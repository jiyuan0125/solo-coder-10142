package goatcounter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"zgo.at/goatcounter/v2/pkg/log"
	"zgo.at/json"
	"zgo.at/zdb"
	"zgo.at/zstd/zbool"
	"zgo.at/zstd/zint"
	"zgo.at/zstd/ztime"
	"zgo.at/zvalidate"
)

var (
	// Valid UUID for testing: 00112233-4455-6677-8899-aabbccddeeff
	TestSession    = zint.Uint128{0x11223344556677, 0x8899aabbccddeeff}
	TestSeqSession = zint.Uint128{TestSession[0], TestSession[1] + 1}
)

var (
	memlog     = log.Module("memstore")
	sesslog    = log.Module("session")
	refspamlog = log.Module("refspam")
)

type sessionKey string

type session struct {
	key      sessionKey
	id       zint.Uint128
	paths    map[PathID]struct{}
	lastSeen int64
}

type ms struct {
	hitMu sync.RWMutex
	hits  []Hit

	sessionMu sync.RWMutex
	sessions  map[sessionKey]*session // sessionKey → session
	byID      map[zint.Uint128]*session // sessionID → session

	sessionTime time.Duration
	testHook    bool
	testSeqMu   sync.Mutex
}

// SessionTime is the maximum length of sessions.
// Deprecated: Use Memstore.SessionTime() and Memstore.SetSessionTime() instead.
var SessionTime = 8 * time.Hour

var Memstore = ms{
	sessionTime: 8 * time.Hour,
}

type storedSession struct {
	Sessions map[sessionKey]zint.Uint128          `json:"sessions"`
	Hashes   map[zint.Uint128]sessionKey          `json:"hashes"`
	Paths    map[zint.Uint128]map[PathID]struct{} `json:"paths"`
	Seen     map[zint.Uint128]int64               `json:"seen"`
}

// SetSessionTime sets the maximum session duration.
func (m *ms) SetSessionTime(d time.Duration) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	m.sessionTime = d
	SessionTime = d
}

// SessionTime returns the current maximum session duration.
func (m *ms) SessionTime() time.Duration {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()
	return m.sessionTime
}

func (m *ms) Reset() {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	m.sessions = make(map[sessionKey]*session)
	m.byID = make(map[zint.Uint128]*session)
	m.testSeqMu.Lock()
	TestSeqSession = zint.Uint128{TestSession[0], TestSession[1] + 1}
	m.testSeqMu.Unlock()
}

// TestInit is like Init(), but enables the test hook to return sequential UUIDs
// instead of random ones.
func (m *ms) TestInit(db zdb.DB) error {
	m.testHook = true
	return m.Init(db)
}

func (m *ms) Init(db zdb.DB) error {
	m.hitMu.Lock()
	defer m.hitMu.Unlock()

	m.Reset()
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	var s []byte
	err := db.Get(context.Background(), &s, `select value from store where key='session'`)
	if err != nil {
		if zdb.ErrNoRows(err) {
			memlog.Debugf(context.Background(), "no sessions stored in DB")
			return nil
		}
		memlog.Errorf(context.Background(), "load from DB store: %s", err)
		return nil
	}

	var stored storedSession
	err = json.Unmarshal(s, &stored)
	if err != nil {
		memlog.Errorf(context.Background(), "unmarshal from DB store: %s", err)
		return nil
	}

	for id, sk := range stored.Hashes {
		s := &session{
			key:      sk,
			id:       id,
			paths:    make(map[PathID]struct{}),
			lastSeen: 0,
		}
		if p, ok := stored.Paths[id]; ok {
			s.paths = p
		}
		if t, ok := stored.Seen[id]; ok {
			s.lastSeen = t
		}
		m.sessions[sk] = s
		m.byID[id] = s
	}
	for sk, id := range stored.Sessions {
		if _, ok := m.sessions[sk]; !ok {
			s := &session{
				key:      sk,
				id:       id,
				paths:    make(map[PathID]struct{}),
				lastSeen: 0,
			}
			if p, ok := stored.Paths[id]; ok {
				s.paths = p
			}
			if t, ok := stored.Seen[id]; ok {
				s.lastSeen = t
			}
			m.sessions[sk] = s
			m.byID[id] = s
		}
	}

	memlog.Debug(context.Background(), "restored sessions from DB",
		"sessions", len(m.sessions),
		"byID", len(m.byID))
	return nil
}

func (m *ms) StoreSessions(db zdb.DB) {
	m.storeSessions(context.Background(), db)
}

func (m *ms) storeSessions(ctx context.Context, db zdb.DB) {
	m.sessionMu.RLock()
	sessions := make(map[sessionKey]zint.Uint128, len(m.sessions))
	hashes := make(map[zint.Uint128]sessionKey, len(m.byID))
	paths := make(map[zint.Uint128]map[PathID]struct{}, len(m.byID))
	seen := make(map[zint.Uint128]int64, len(m.byID))
	for sk, s := range m.sessions {
		sessions[sk] = s.id
		hashes[s.id] = sk
		paths[s.id] = s.paths
		seen[s.id] = s.lastSeen
	}
	m.sessionMu.RUnlock()

	d, err := json.Marshal(storedSession{
		Sessions: sessions,
		Paths:    paths,
		Seen:     seen,
		Hashes:   hashes,
	})
	if err != nil {
		memlog.Error(ctx, err)
		return
	}

	err = db.Exec(ctx,
		`insert into store (key, value) values ('session', $1)
		 on conflict(key) do update set value = excluded.value`, d)
	if err != nil {
		memlog.Error(ctx, err)
	}

	memlog.Debug(ctx, "stored sessions in DB",
		"bytesize", len(d),
		"sessions", len(sessions))
}

// PersistSessions persists the current sessions to the database, using the DB
// from the given context.
func (m *ms) PersistSessions(ctx context.Context) {
	m.storeSessions(ctx, zdb.MustGetDB(ctx))
}

func (m *ms) Append(hits ...Hit) {
	m.hitMu.Lock()
	m.hits = append(m.hits, hits...)
	m.hitMu.Unlock()
}

func (m *ms) SessionsLen() int {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()
	return len(m.sessions)
}

func (m *ms) Len() int {
	m.hitMu.RLock()
	defer m.hitMu.RUnlock()
	return len(m.hits)
}

var (
	refspamSubdomains []string
	refspamOnce       sync.Once
)

func isRefspam(host string) bool {
	if _, ok := refspam[host]; ok {
		return true
	}

	refspamOnce.Do(func() {
		refspamSubdomains = make([]string, 0, len(refspam))
		for v := range refspam {
			refspamSubdomains = append(refspamSubdomains, "."+v)
		}
	})

	for _, v := range refspamSubdomains {
		if strings.HasSuffix(host, v) {
			return true
		}
	}
	return false
}

func (m *ms) Persist(ctx context.Context) ([]Hit, error) {
	if m.Len() == 0 {
		return nil, nil
	}

	m.hitMu.Lock()
	hits := make([]Hit, len(m.hits))
	copy(hits, m.hits)
	m.hits = make([]Hit, 0, 16)
	m.hitMu.Unlock()

	bot, err := zdb.NewBulkInsert(ctx, "bots", []string{"site_id", "path", "bot", "user_agent", "created_at"})
	if err != nil {
		return nil, err
	}
	ins, err := zdb.NewBulkInsert(ctx, "hits", []string{"site_id", "path_id", "ref_id", "browser_id", "system_id",
		"width", "location", "language", "created_at", "session", "first_visit", "campaign"})
	if err != nil {
		return nil, err
	}

	newHits := make([]Hit, 0, len(hits))
	for _, h := range hits {
		if h.Bot > 0 {
			bot.Values(h.Site, h.Path, h.Bot, h.UserAgentHeader, h.CreatedAt)
			continue
		}
		if m.processHit(ctx, &h) {
			// Don't return hits that failed validation; otherwise cron will try to
			// insert them.
			newHits = append(newHits, h)

			if !h.NoStore {
				var w *float64
				if len(h.Size) > 0 {
					w = &h.Size[0]
				}
				ins.Values(h.Site, h.PathID, h.RefID, h.BrowserID, h.SystemID, w, h.Location,
					h.Language, h.CreatedAt.Round(time.Second), h.Session, h.FirstVisit, h.CampaignID)
			}
		}
	}

	// Just log errors on inserting bots; not that important.
	if err := bot.Finish(); err != nil {
		memlog.Errorf(ctx, "storing bots: %s", err)
	}
	return newHits, ins.Finish()
}

func (m *ms) processHit(ctx context.Context, h *Hit) bool {
	defer log.Recover(ctx, func(err error) { memlog.Error(ctx, err, "hit", h) })

	if h.noProcess {
		return true
	}

	// Ignore spammers.
	h.RefURL, _ = url.Parse(h.Ref)
	if h.RefURL != nil {
		if isRefspam(h.RefURL.Host) {
			refspamlog.Debugf(ctx, "refspam ignored: %q", h.RefURL.Host)
			return false
		}
	}

	var site Site
	err := site.ByID(ctx, h.Site)
	if err != nil {
		// This happens if the site gets deleted before the persist runs. We
		// don't really need to log that as an error.
		if !zdb.ErrNoRows(err) {
			memlog.Error(ctx, err, "hit", h)
		}
		return false
	}
	ctx = WithSite(ctx, &site)
	if !site.Settings.Collect.Has(CollectHits) {
		h.NoStore = true
	}

	if !site.Settings.Collect.Has(CollectReferrer) {
		h.Query, h.Ref, h.RefScheme, h.RefURL = "", "", "", nil
	}

	err = h.Defaults(ctx, false)
	if err != nil {
		if errors.As(err, new(&zvalidate.Validator{})) {
			memlog.Debug(ctx, err.Error(), "hit", h)
		} else {
			memlog.Error(ctx, err, "hit", h)
		}
		return false
	}

	if h.Session.IsZero() && site.Settings.Collect.Has(CollectSession) && !h.NoSession.Bool() {
		h.Session, h.FirstVisit = m.session(ctx, site.ID, h.PathID, h.UserSessionID, h.UserAgentHeader, h.RemoteAddr)
	}

	if !site.Settings.Collect.Has(CollectSession) || h.NoSession.Bool() {
		h.Session, h.FirstVisit = zint.Uint128{}, true
	}
	if !site.Settings.Collect.Has(CollectScreenSize) {
		h.Size = nil
	}
	if !site.Settings.Collect.Has(CollectUserAgent) {
		h.UserAgentHeader, h.BrowserID, h.SystemID = "", 0, 0
	}
	if !site.Settings.Collect.Has(CollectLanguage) {
		h.Language = nil
	}
	if !site.Settings.Collect.Has(CollectLocation) {
		h.Location = ""
	}
	if strings.ContainsRune(h.Location, '-') {
		trim := !site.Settings.Collect.Has(CollectLocationRegion)
		if !trim && len(site.Settings.CollectRegions) > 0 {
			trim = !slices.Contains(site.Settings.CollectRegions, h.Location[:2])
		}
		if trim {
			var loc Location
			err := loc.ByCode(ctx, h.Location[:2])
			if err != nil {
				memlog.Errorf(ctx, "lookup %q: %s", h.Location[:2], err)
			}
			h.Location = loc.ISO3166_2
		}
	}

	if h.Ignore() {
		return false
	}

	err = h.Validate(ctx, false)
	if err != nil {
		memlog.Error(ctx, err, "hit", h)
		return false
	}
	return true
}

// For 10k sessions this takes about 5ms on my laptop; that's a small enough
// delay to not overly worry about (there are rarely more than a few hundred
// sessions at a time).
func (m *ms) EvictSessions(ctx context.Context) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	ev := ztime.Now(ctx).Add(-SessionTime).Unix()

	for id, s := range m.byID {
		if s.lastSeen > ev {
			continue
		}

		sesslog.Debug(context.Background(), "evicting session",
			"session-id", id,
			"last-seen", s.lastSeen,
			"session-key", s.key)

		delete(m.sessions, s.key)
		delete(m.byID, id)
	}
}

// SessionID gets a new UUID4 session ID.
func (m *ms) SessionID() zint.Uint128 {
	if m.testHook {
		m.testSeqMu.Lock()
		defer m.testSeqMu.Unlock()
		TestSeqSession[1]++
		return TestSeqSession
	}
	return UUID()
}

func (m *ms) session(ctx context.Context, siteID SiteID, pathID PathID, userSessionID, ua, remoteAddr string) (zint.Uint128, zbool.Bool) {
	sk := sessionKey(userSessionID)
	if userSessionID == "" {
		sk = sessionKey(fmt.Sprintf("%s-%s-%d", ua, remoteAddr, siteID))
	}

	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	s, ok := m.sessions[sk]
	if ok { // Existing session
		s.lastSeen = ztime.Now(ctx).Unix()
		_, seenPath := s.paths[pathID]
		if !seenPath {
			s.paths[pathID] = struct{}{}
		}

		sesslog.Debug(ctx, "HIT",
			"session-key", sk,
			"session-id", s.id,
			"path", pathID,
			"seen-path", seenPath)
		return s.id, zbool.Bool(!seenPath)
	}

	// New session
	id := m.SessionID()
	ns := &session{
		key:      sk,
		id:       id,
		paths:    map[PathID]struct{}{pathID: {}},
		lastSeen: ztime.Now(ctx).Unix(),
	}
	m.sessions[sk] = ns
	m.byID[id] = ns

	sesslog.Debug(ctx, "MISS: created new",
		"session-key", sk,
		"session-id", id,
		"path", pathID)
	return id, true
}

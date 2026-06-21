package goatcounter

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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
	TestSession    = zint.Uint128{0x11223344556677, 0x8899aabbccddeeff}
	TestSeqSession = zint.Uint128{TestSession[0], TestSession[1] + 1}
	testSeqCounter uint64
)

var (
	memlog     = log.Module("memstore")
	sesslog    = log.Module("session")
	refspamlog = log.Module("refspam")
)

type sessionKey string

type sessionEntry struct {
	ID       zint.Uint128
	Key      sessionKey
	Paths    map[PathID]struct{}
	LastSeen int64
}

type storedSession struct {
	Sessions map[sessionKey]*sessionEntry `json:"sessions"`
}

type ms struct {
	hitMu sync.RWMutex
	hits  []Hit

	sessionMu    sync.RWMutex
	sessions     map[sessionKey]*sessionEntry
	sessionsByID map[zint.Uint128]*sessionEntry

	sessionTime time.Duration
	testHook    bool
}

var Memstore = ms{
	sessionTime: 8 * time.Hour,
}

func (m *ms) Reset() {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	m.sessions = make(map[sessionKey]*sessionEntry)
	m.sessionsByID = make(map[zint.Uint128]*sessionEntry)
	atomic.StoreUint64(&testSeqCounter, 1)
}

func (m *ms) SetSessionTime(d time.Duration) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	m.sessionTime = d
}

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

	if stored.Sessions != nil {
		m.sessions = stored.Sessions
		m.sessionsByID = make(map[zint.Uint128]*sessionEntry, len(stored.Sessions))
		for _, entry := range stored.Sessions {
			m.sessionsByID[entry.ID] = entry
		}
	}
	memlog.Debug(context.Background(), "restored sessions from DB",
		"sessions", len(m.sessions),
		"sessionsByID", len(m.sessionsByID))
	return nil
}

func (m *ms) StoreSessions(db zdb.DB) {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()

	d, err := json.Marshal(storedSession{
		Sessions: m.sessions,
	})
	if err != nil {
		memlog.Error(context.Background(), err)
		return
	}

	err = db.Exec(context.Background(),
		`insert into store (key, value) values ('session', $1)
		 on conflict (key) do update set value = excluded.value`, d)
	if err != nil {
		memlog.Error(context.Background(), err)
		return
	}

	memlog.Debug(context.Background(), "stored sessions in DB",
		"bytesize", len(d),
		"sessions", len(m.sessions))
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

func (m *ms) EvictSessions(ctx context.Context) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	ev := ztime.Now(ctx).Add(-m.sessionTime).Unix()
	for id, entry := range m.sessionsByID {
		if entry.LastSeen > ev {
			continue
		}

		sesslog.Debug(context.Background(), "evicting session",
			"session-id", id,
			"last-seen", entry.LastSeen,
			"session-key", entry.Key)

		delete(m.sessions, entry.Key)
		delete(m.sessionsByID, id)
	}
}

func (m *ms) SessionID() zint.Uint128 {
	if m.testHook {
		return zint.Uint128{TestSession[0], TestSession[1] + atomic.AddUint64(&testSeqCounter, 1)}
	}
	return UUID()
}

func (m *ms) newSessionID() zint.Uint128 {
	for {
		id := m.SessionID()
		if _, exists := m.sessionsByID[id]; !exists {
			return id
		}
	}
}

func (m *ms) session(ctx context.Context, siteID SiteID, pathID PathID, userSessionID, ua, remoteAddr string) (zint.Uint128, zbool.Bool) {
	sk := sessionKey(userSessionID)
	if userSessionID == "" {
		sk = sessionKey(fmt.Sprintf("%s-%s-%d", ua, remoteAddr, siteID))
	}

	m.sessionMu.RLock()
	entry, ok := m.sessions[sk]
	if ok {
		id := entry.ID
		_, seenPath := entry.Paths[pathID]
		m.sessionMu.RUnlock()

		m.sessionMu.Lock()
		defer m.sessionMu.Unlock()

		entry, ok = m.sessions[sk]
		if ok {
			entry.LastSeen = ztime.Now(ctx).Unix()
			_, seenPath = entry.Paths[pathID]
			if !seenPath {
				entry.Paths[pathID] = struct{}{}
			}

			sesslog.Debug(ctx, "HIT",
				"session-key", sk,
				"session-id", id,
				"path", pathID,
				"seen-path", seenPath)
			return id, zbool.Bool(!seenPath)
		}

		id = m.newSessionID()
		entry = &sessionEntry{
			ID:       id,
			Key:      sk,
			Paths:    map[PathID]struct{}{pathID: {}},
			LastSeen: ztime.Now(ctx).Unix(),
		}
		m.sessions[sk] = entry
		m.sessionsByID[id] = entry

		sesslog.Debug(ctx, "MISS: created new (after race)",
			"session-key", sk,
			"session-id", id,
			"path", pathID)
		return id, true
	}
	m.sessionMu.RUnlock()

	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	entry, ok = m.sessions[sk]
	if ok {
		entry.LastSeen = ztime.Now(ctx).Unix()
		_, seenPath := entry.Paths[pathID]
		if !seenPath {
			entry.Paths[pathID] = struct{}{}
		}

		sesslog.Debug(ctx, "HIT (after upgrade)",
			"session-key", sk,
			"session-id", entry.ID,
			"path", pathID,
			"seen-path", seenPath)
		return entry.ID, zbool.Bool(!seenPath)
	}

	id := m.newSessionID()
	entry = &sessionEntry{
		ID:       id,
		Key:      sk,
		Paths:    map[PathID]struct{}{pathID: {}},
		LastSeen: ztime.Now(ctx).Unix(),
	}
	m.sessions[sk] = entry
	m.sessionsByID[id] = entry

	sesslog.Debug(ctx, "MISS: created new",
		"session-key", sk,
		"session-id", id,
		"path", pathID)
	return id, true
}

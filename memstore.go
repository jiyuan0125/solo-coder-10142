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
	key   sessionKey
	paths map[PathID]struct{}
	seen  int64
}

type ms struct {
	hitMu sync.RWMutex
	hits  []Hit

	sessionMu    sync.RWMutex
	sessionsByKey map[sessionKey]zint.Uint128
	sessionsByID  map[zint.Uint128]*session

	sessionTime time.Duration

	testHook     bool
	testSeqMu    sync.Mutex
	testSeqID    zint.Uint128
}

var Memstore ms

type storedSession struct {
	Sessions map[sessionKey]zint.Uint128          `json:"sessions"`
	Hashes   map[zint.Uint128]sessionKey          `json:"hashes"`
	Paths    map[zint.Uint128]map[PathID]struct{} `json:"paths"`
	Seen     map[zint.Uint128]int64               `json:"seen"`
}

func (m *ms) Reset() {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	m.sessionsByKey = make(map[sessionKey]zint.Uint128)
	m.sessionsByID = make(map[zint.Uint128]*session)
	m.sessionTime = 8 * time.Hour

	m.testSeqMu.Lock()
	m.testSeqID = zint.Uint128{TestSession[0], TestSession[1] + 1}
	m.testSeqMu.Unlock()

	TestSeqSession = zint.Uint128{TestSession[0], TestSession[1] + 1}
}

func (m *ms) TestInit(db zdb.DB) error {
	m.testHook = true
	return m.Init(db)
}

func (m *ms) Init(db zdb.DB) error {
	m.hitMu.Lock()
	defer m.hitMu.Unlock()

	m.Reset()

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

	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	if stored.Sessions != nil {
		m.sessionsByKey = stored.Sessions
	}
	if stored.Hashes != nil && stored.Paths != nil && stored.Seen != nil {
		for id, sk := range stored.Hashes {
			s := &session{
				key:   sk,
				paths: stored.Paths[id],
				seen:  stored.Seen[id],
			}
			if s.paths == nil {
				s.paths = make(map[PathID]struct{})
			}
			m.sessionsByID[id] = s
		}
	}

	memlog.Debug(context.Background(), "restored sessions from DB",
		"sessions", len(m.sessionsByKey),
		"sessionsByID", len(m.sessionsByID))
	return nil
}

func (m *ms) StoreSessions(db zdb.DB) {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()

	sessions := make(map[sessionKey]zint.Uint128, len(m.sessionsByKey))
	hashes := make(map[zint.Uint128]sessionKey, len(m.sessionsByID))
	paths := make(map[zint.Uint128]map[PathID]struct{}, len(m.sessionsByID))
	seen := make(map[zint.Uint128]int64, len(m.sessionsByID))

	for k, id := range m.sessionsByKey {
		sessions[k] = id
	}
	for id, s := range m.sessionsByID {
		hashes[id] = s.key
		paths[id] = s.paths
		seen[id] = s.seen
	}

	d, err := json.Marshal(storedSession{
		Sessions: sessions,
		Paths:    paths,
		Seen:     seen,
		Hashes:   hashes,
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
	}

	memlog.Debug(context.Background(), "stored sessions in DB",
		"bytesize", len(d),
		"sessions", len(sessions),
		"hashes", len(hashes),
		"paths", len(paths),
		"seen", len(seen))
}

func (m *ms) Append(hits ...Hit) {
	m.hitMu.Lock()
	m.hits = append(m.hits, hits...)
	m.hitMu.Unlock()
}

func (m *ms) SessionsLen() int {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()
	return len(m.sessionsByKey)
}

func (m *ms) Len() int {
	m.hitMu.Lock()
	defer m.hitMu.Unlock()
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

var SessionTime = 8 * time.Hour

func (m *ms) SetSessionTime(d time.Duration) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()
	m.sessionTime = d
}

func (m *ms) EvictSessions(ctx context.Context) {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	ev := ztime.Now(ctx).Add(-m.sessionTime).Unix()
	for id, s := range m.sessionsByID {
		if s.seen > ev {
			continue
		}

		sesslog.Debug(context.Background(), "evicting session",
			"session-id", id,
			"last-seen", s.seen,
			"session-key", s.key)

		delete(m.sessionsByKey, s.key)
		delete(m.sessionsByID, id)
	}
}

func (m *ms) SessionID() zint.Uint128 {
	if m.testHook {
		m.testSeqMu.Lock()
		defer m.testSeqMu.Unlock()
		m.testSeqID[1]++
		TestSeqSession = m.testSeqID
		return m.testSeqID
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

	id, ok := m.sessionsByKey[sk]
	if ok {
		s := m.sessionsByID[id]
		s.seen = ztime.Now(ctx).Unix()
		_, seenPath := s.paths[pathID]
		if !seenPath {
			s.paths[pathID] = struct{}{}
		}

		sesslog.Debug(ctx, "HIT",
			"session-key", sk,
			"session-id", id,
			"path", pathID,
			"seen-path", seenPath)
		return id, zbool.Bool(!seenPath)
	}

	id = m.SessionID()
	m.sessionsByKey[sk] = id
	m.sessionsByID[id] = &session{
		key:   sk,
		paths: map[PathID]struct{}{pathID: {}},
		seen:  ztime.Now(ctx).Unix(),
	}

	sesslog.Debug(ctx, "MISS: created new",
		"session-key", sk,
		"session-id", id,
		"path", pathID)
	return id, true
}

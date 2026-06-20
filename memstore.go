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

// session 存储单次浏览器会话的数据。
//
// 字段并发安全约定：
//   - key、id 只在构造时写入，之后只读，无需额外保护；
//   - lastSeen 是原子字段，用 Load/Store 直接操作；
//   - paths 通过 pathsMu 保护，修改或深拷贝时先加锁。
type session struct {
	key      sessionKey
	id       zint.Uint128
	pathsMu  sync.Mutex
	paths    map[PathID]struct{}
	lastSeen atomic.Int64
}

// storedSessionEntry 是写入数据库时单条会话的序列化结构。
type storedSessionEntry struct {
	ID       zint.Uint128            `json:"id"`
	Paths    map[PathID]struct{} `json:"paths"`
	LastSeen int64                  `json:"last_seen"`
}

// storedSession 是写入数据库的整体结构。
// 只保留一张以 sessionKey 为键的表，加载时从 entry 重建 byID 索引。
type storedSession struct {
	Sessions map[sessionKey]storedSessionEntry `json:"sessions"`
}

type ms struct {
	hitMu sync.RWMutex
	hits  []Hit

	sessionMu   sync.RWMutex                // 保护 sessions、byID、sessionTime 三个字段
	sessions    map[sessionKey]*session     // sessionKey → session
	byID        map[zint.Uint128]*session   // sessionID  → session
	sessionTime time.Duration

	testHook  bool
	testSeqMu sync.Mutex
}

// SessionTime is the maximum length of sessions.
// Deprecated: Use Memstore.SessionTime() and Memstore.SetSessionTime() instead.
//
// 保留此全局变量仅用于向后兼容（旧版本测试或第三方代码可能仍引用）；
// 内部驱逐逻辑统一使用 ms.sessionTime。
var SessionTime = 8 * time.Hour

var Memstore = ms{
	sessionTime: 8 * time.Hour,
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
	m.sessions = make(map[sessionKey]*session)
	m.byID = make(map[zint.Uint128]*session)
	m.sessionMu.Unlock()

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

	// 只初始化必要的空结构，不再悄悄清空——如果后面加载出错，
	// 调用者能感知到错误并决定是否继续，不会因为已经 Reset 导致下一次
	// 持久化把空集合写回库里。
	m.sessionMu.Lock()
	if m.sessions == nil {
		m.sessions = make(map[sessionKey]*session)
	}
	if m.byID == nil {
		m.byID = make(map[zint.Uint128]*session)
	}
	m.sessionMu.Unlock()

	var s []byte
	err := db.Get(context.Background(), &s, `select value from store where key='session'`)
	if err != nil {
		if zdb.ErrNoRows(err) {
			memlog.Debugf(context.Background(), "no sessions stored in DB")
			return nil
		}
		memlog.Errorf(context.Background(), "load from DB store: %s", err)
		return fmt.Errorf("load sessions from DB store: %w", err)
	}

	var stored storedSession
	err = json.Unmarshal(s, &stored)
	if err != nil {
		memlog.Errorf(context.Background(), "unmarshal from DB store: %s", err)
		return fmt.Errorf("unmarshal sessions from DB store: %w", err)
	}

	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	// 以新的结构加载，sessionKey → entry 是唯一真源，byID 从 entry 重建。
	m.sessions = make(map[sessionKey]*session, len(stored.Sessions))
	m.byID = make(map[zint.Uint128]*session, len(stored.Sessions))
	for sk, entry := range stored.Sessions {
		if entry.Paths == nil {
			entry.Paths = make(map[PathID]struct{})
		}
		s := &session{
			key:   sk,
			id:    entry.ID,
			paths: entry.Paths,
		}
		s.lastSeen.Store(entry.LastSeen)
		m.sessions[sk] = s
		m.byID[entry.ID] = s
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
	stored := m.snapshotSessions()

	d, err := json.Marshal(storedSession{Sessions: stored})
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
		"sessions", len(stored))
}

// snapshotSessions 在持锁的情况下安全地拷贝出一份用于落盘的数据。
func (m *ms) snapshotSessions() map[sessionKey]storedSessionEntry {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()

	stored := make(map[sessionKey]storedSessionEntry, len(m.sessions))
	for sk, s := range m.sessions {
		s.pathsMu.Lock()
		paths := make(map[PathID]struct{}, len(s.paths))
		for p, v := range s.paths {
			paths[p] = v
		}
		s.pathsMu.Unlock()

		stored[sk] = storedSessionEntry{
			ID:       s.id,
			Paths:    paths,
			LastSeen: s.lastSeen.Load(),
		}
	}
	return stored
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

// EvictSessions 驱逐过期会话。
//
// 过期时长统一从 ms.sessionTime 读取，不再依赖可变的全局 SessionTime；
// 删除时 sessions 和 byID 两个索引同步操作，确保两张表始终一致。
func (m *ms) EvictSessions(ctx context.Context) {
	m.sessionMu.RLock()
	expireAfter := m.sessionTime
	m.sessionMu.RUnlock()

	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	ev := ztime.Now(ctx).Add(-expireAfter).Unix()

	for id, s := range m.byID {
		if s.lastSeen.Load() > ev {
			continue
		}

		sesslog.Debug(context.Background(), "evicting session",
			"session-id", id,
			"last-seen", s.lastSeen.Load(),
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

	// 读多写少：先用读锁走快路径，命中已有会话时直接在会话级粒度下更新字段。
	m.sessionMu.RLock()
	if s, ok := m.sessions[sk]; ok {
		s.lastSeen.Store(ztime.Now(ctx).Unix())

		_, seenPath := s.paths[pathID]
		if !seenPath {
			s.pathsMu.Lock()
			_, seenPath = s.paths[pathID]
			if !seenPath {
				s.paths[pathID] = struct{}{}
			}
			s.pathsMu.Unlock()
		}

		id := s.id
		m.sessionMu.RUnlock()

		sesslog.Debug(ctx, "HIT",
			"session-key", sk,
			"session-id", id,
			"path", pathID,
			"seen-path", seenPath)
		return id, zbool.Bool(!seenPath)
	}
	m.sessionMu.RUnlock()

	// 慢路径：升级为写锁创建新会话，带双重检查避免同 key 在锁升级窗口被重复创建。
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	if s, ok := m.sessions[sk]; ok {
		s.lastSeen.Store(ztime.Now(ctx).Unix())

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

	// 新会话：生成 ID 并做唯一检查，彻底消除极端情况下的 ID 碰撞。
	id := m.SessionID()
	for {
		if _, exists := m.byID[id]; !exists {
			break
		}
		id = m.SessionID()
	}

	ns := &session{
		key:   sk,
		id:    id,
		paths: map[PathID]struct{}{pathID: {}},
	}
	ns.lastSeen.Store(ztime.Now(ctx).Unix())
	m.sessions[sk] = ns
	m.byID[id] = ns

	sesslog.Debug(ctx, "MISS: created new",
		"session-key", sk,
		"session-id", id,
		"path", pathID)
	return id, true
}

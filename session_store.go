package goatcounter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"zgo.at/json"
	"zgo.at/zdb"
	"zgo.at/zstd/zbool"
	"zgo.at/zstd/zint"
	"zgo.at/zstd/ztime"
)

type sessionKey string

type session struct {
	key      sessionKey
	id       zint.Uint128
	paths    map[PathID]struct{}
	lastSeen int64
}

type storedSession struct {
	Sessions map[sessionKey]zint.Uint128          `json:"sessions"`
	Hashes   map[zint.Uint128]sessionKey          `json:"hashes"`
	Paths    map[zint.Uint128]map[PathID]struct{} `json:"paths"`
	Seen     map[zint.Uint128]int64               `json:"seen"`
}

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[sessionKey]*session
	byID     map[zint.Uint128]*session

	sessionTime time.Duration
	idMu        sync.Mutex
	testHook    bool
}

var Sessions = SessionStore{
	sessionTime: 8 * time.Hour,
	sessions:    make(map[sessionKey]*session),
	byID:        make(map[zint.Uint128]*session),
}

func (s *SessionStore) SetSessionTime(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionTime = d
}

func (s *SessionStore) GetSessionTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionTime
}

func (s *SessionStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = make(map[sessionKey]*session)
	s.byID = make(map[zint.Uint128]*session)
	s.idMu.Lock()
	TestSeqSession = zint.Uint128{TestSession[0], TestSession[1] + 1}
	s.idMu.Unlock()
}

func (s *SessionStore) TestInit(db zdb.DB) error {
	s.testHook = true
	return s.Init(db)
}

func (s *SessionStore) Init(db zdb.DB) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessions = make(map[sessionKey]*session)
	s.byID = make(map[zint.Uint128]*session)

	var data []byte
	err := db.Get(context.Background(), &data, `select value from store where key='session'`)
	if err != nil {
		if zdb.ErrNoRows(err) {
			sesslog.Debugf(context.Background(), "no sessions stored in DB")
			return nil
		}
		sesslog.Errorf(context.Background(), "load from DB store: %s", err)
		return nil
	}

	var stored storedSession
	err = json.Unmarshal(data, &stored)
	if err != nil {
		sesslog.Errorf(context.Background(), "unmarshal from DB store: %s", err)
		return nil
	}

	for id, sk := range stored.Hashes {
		sess := &session{
			key:      sk,
			id:       id,
			paths:    make(map[PathID]struct{}),
			lastSeen: 0,
		}
		if p, ok := stored.Paths[id]; ok {
			sess.paths = p
		}
		if t, ok := stored.Seen[id]; ok {
			sess.lastSeen = t
		}
		s.sessions[sk] = sess
		s.byID[id] = sess
	}
	for sk, id := range stored.Sessions {
		if _, ok := s.sessions[sk]; !ok {
			sess := &session{
				key:      sk,
				id:       id,
				paths:    make(map[PathID]struct{}),
				lastSeen: 0,
			}
			if p, ok := stored.Paths[id]; ok {
				sess.paths = p
			}
			if t, ok := stored.Seen[id]; ok {
				sess.lastSeen = t
			}
			s.sessions[sk] = sess
			s.byID[id] = sess
		}
	}

	sesslog.Debug(context.Background(), "restored sessions from DB",
		"sessions", len(s.sessions),
		"byID", len(s.byID))
	return nil
}

func (s *SessionStore) StoreSessions(db zdb.DB) {
	s.storeSessions(context.Background(), db)
}

func (s *SessionStore) storeSessions(ctx context.Context, db zdb.DB) {
	s.mu.RLock()
	sessions := make(map[sessionKey]zint.Uint128, len(s.sessions))
	hashes := make(map[zint.Uint128]sessionKey, len(s.byID))
	paths := make(map[zint.Uint128]map[PathID]struct{}, len(s.byID))
	seen := make(map[zint.Uint128]int64, len(s.byID))
	for sk, sess := range s.sessions {
		sessions[sk] = sess.id
		hashes[sess.id] = sk
		paths[sess.id] = sess.paths
		seen[sess.id] = sess.lastSeen
	}
	s.mu.RUnlock()

	d, err := json.Marshal(storedSession{
		Sessions: sessions,
		Paths:    paths,
		Seen:     seen,
		Hashes:   hashes,
	})
	if err != nil {
		sesslog.Error(ctx, err)
		return
	}

	err = db.Exec(ctx,
		`insert into store (key, value) values ('session', $1)
		 on conflict(key) do update set value = excluded.value`, d)
	if err != nil {
		sesslog.Error(ctx, err)
		return
	}

	sesslog.Debug(ctx, "stored sessions in DB",
		"bytesize", len(d),
		"sessions", len(sessions))
}

func (s *SessionStore) PersistSessions(ctx context.Context) {
	s.storeSessions(ctx, zdb.MustGetDB(ctx))
}

func (s *SessionStore) SessionsLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *SessionStore) SessionID() zint.Uint128 {
	s.idMu.Lock()
	defer s.idMu.Unlock()
	if s.testHook {
		TestSeqSession[1]++
		return TestSeqSession
	}
	return UUID()
}

func (s *SessionStore) EvictSessions(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry := s.sessionTime
	ev := ztime.Now(ctx).Add(-expiry).Unix()

	for id, sess := range s.byID {
		if sess.lastSeen > ev {
			continue
		}

		sesslog.Debug(context.Background(), "evicting session",
			"session-id", id,
			"last-seen", sess.lastSeen,
			"session-key", sess.key)

		delete(s.sessions, sess.key)
		delete(s.byID, id)
	}
}

func (s *SessionStore) Session(ctx context.Context, siteID SiteID, pathID PathID, userSessionID, ua, remoteAddr string) (zint.Uint128, zbool.Bool) {
	sk := sessionKey(userSessionID)
	if userSessionID == "" {
		sk = sessionKey(fmt.Sprintf("%s-%s-%d", ua, remoteAddr, siteID))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sk]
	if ok {
		sess.lastSeen = ztime.Now(ctx).Unix()
		_, seenPath := sess.paths[pathID]
		if !seenPath {
			sess.paths[pathID] = struct{}{}
		}

		sesslog.Debug(ctx, "HIT",
			"session-key", sk,
			"session-id", sess.id,
			"path", pathID,
			"seen-path", seenPath)
		return sess.id, zbool.Bool(!seenPath)
	}

	id := s.SessionID()
	ns := &session{
		key:      sk,
		id:       id,
		paths:    map[PathID]struct{}{pathID: {}},
		lastSeen: ztime.Now(ctx).Unix(),
	}
	s.sessions[sk] = ns
	s.byID[id] = ns

	sesslog.Debug(ctx, "MISS: created new",
		"session-key", sk,
		"session-id", id,
		"path", pathID)
	return id, true
}



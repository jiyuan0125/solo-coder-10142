package goatcounter

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"zgo.at/json"
	"zgo.at/zdb"
	"zgo.at/zstd/zbool"
	"zgo.at/zstd/zint"
	"zgo.at/zstd/ztime"
)

type sessionKey string

type sessionEntry struct {
	ID    zint.Uint128
	Paths map[PathID]struct{}
	Seen  int64
}

type SessionStore struct {
	mu sync.RWMutex

	byKey   map[sessionKey]*sessionEntry
	byID    map[zint.Uint128]*sessionEntry
	keyOf   map[zint.Uint128]sessionKey
	seenOrd map[zint.Uint128]int64

	sessionTime  time.Duration
	testHook     bool
	nextID       atomic.Uint64
	initialized  bool
}

var Sessions = &SessionStore{
	sessionTime: 8 * time.Hour,
}

type storedSession struct {
	ByKey map[sessionKey]zint.Uint128          `json:"sessions"`
	Paths map[zint.Uint128]map[PathID]struct{} `json:"paths"`
	Seen  map[zint.Uint128]int64               `json:"seen"`
	ByKeyReverse map[zint.Uint128]sessionKey   `json:"hashes"`
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
	s.resetLocked()
}

func (s *SessionStore) resetLocked() {
	s.byKey = make(map[sessionKey]*sessionEntry)
	s.byID = make(map[zint.Uint128]*sessionEntry)
	s.keyOf = make(map[zint.Uint128]sessionKey)
	s.seenOrd = make(map[zint.Uint128]int64)
	s.nextID.Store(1)
}

func (s *SessionStore) TestInit(db zdb.DB) error {
	s.testHook = true
	return s.Init(db)
}

func (s *SessionStore) Init(db zdb.DB) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.resetLocked()
	s.initialized = true

	var data []byte
	err := db.Get(context.Background(), &data, `select value from store where key='session'`)
	if err != nil {
		if zdb.ErrNoRows(err) {
			sesslog.Debug(context.Background(), "no sessions stored in DB")
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

	if stored.ByKey != nil {
		for sk, id := range stored.ByKey {
			e := &sessionEntry{ID: id}
			if stored.Paths != nil {
				e.Paths = stored.Paths[id]
			}
			if e.Paths == nil {
				e.Paths = make(map[PathID]struct{})
			}
			if stored.Seen != nil {
				e.Seen = stored.Seen[id]
			}
			s.byKey[sk] = e
			s.byID[id] = e
			s.seenOrd[id] = e.Seen
		}
	}
	if stored.ByKeyReverse != nil {
		for id, sk := range stored.ByKeyReverse {
			s.keyOf[id] = sk
		}
	}

	sesslog.Debug(context.Background(), "restored sessions from DB",
		"sessions", len(s.byKey),
		"byID", len(s.byID),
		"paths", countPaths(s.byID),
		"seen", len(s.seenOrd))
	return nil
}

func countPaths(m map[zint.Uint128]*sessionEntry) int {
	n := 0
	for _, e := range m {
		n += len(e.Paths)
	}
	return n
}

func (s *SessionStore) StoreSessions(db zdb.DB) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored := storedSession{
		ByKey:        make(map[sessionKey]zint.Uint128, len(s.byKey)),
		ByKeyReverse: make(map[zint.Uint128]sessionKey, len(s.keyOf)),
		Paths:        make(map[zint.Uint128]map[PathID]struct{}, len(s.byID)),
		Seen:         make(map[zint.Uint128]int64, len(s.seenOrd)),
	}
	for sk, e := range s.byKey {
		stored.ByKey[sk] = e.ID
		stored.Paths[e.ID] = e.Paths
		stored.Seen[e.ID] = e.Seen
	}
	for id, sk := range s.keyOf {
		stored.ByKeyReverse[id] = sk
	}

	d, err := json.Marshal(stored)
	if err != nil {
		sesslog.Error(context.Background(), err)
		return
	}

	err = db.Exec(context.Background(), `
		insert into store (key, value) values ('session', $1)
		on conflict (key) do update set value=excluded.value`, d)
	if err != nil {
		sesslog.Error(context.Background(), err)
		return
	}

	sesslog.Debug(context.Background(), "stored sessions in DB",
		"bytesize", len(d),
		"sessions", len(s.byKey),
		"byID", len(s.byID),
		"paths", countPaths(s.byID),
		"seen", len(s.seenOrd))
}

func (s *SessionStore) SessionID() zint.Uint128 {
	if s.testHook {
		seq := s.nextID.Add(1)
		id := zint.Uint128{TestSession[0], TestSession[1] + seq}
		TestSeqSession = id
		return id
	}
	return UUID()
}

func (s *SessionStore) Session(ctx context.Context, siteID SiteID, pathID PathID, userSessionID, ua, remoteAddr string) (zint.Uint128, zbool.Bool) {
	sk := sessionKey(userSessionID)
	if userSessionID == "" {
		sk = sessionKey(fmt.Sprintf("%s-%s-%d", ua, remoteAddr, siteID))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.byKey[sk]; ok {
		e.Seen = ztime.Now(ctx).Unix()
		s.seenOrd[e.ID] = e.Seen
		_, seenPath := e.Paths[pathID]
		if !seenPath {
			e.Paths[pathID] = struct{}{}
		}

		sesslog.Debug(ctx, "HIT",
			"session-key", sk,
			"session-id", e.ID,
			"path", pathID,
			"seen-path", seenPath)
		return e.ID, zbool.Bool(!seenPath)
	}

	id := s.SessionID()
	e := &sessionEntry{
		ID:    id,
		Paths: map[PathID]struct{}{pathID: struct{}{}},
		Seen:  ztime.Now(ctx).Unix(),
	}
	s.byKey[sk] = e
	s.byID[id] = e
	s.keyOf[id] = sk
	s.seenOrd[id] = e.Seen

	sesslog.Debug(ctx, "MISS: created new",
		"session-key", sk,
		"session-id", id,
		"path", pathID)
	return id, true
}

func (s *SessionStore) EvictSessions(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ev := ztime.Now(ctx).Add(-s.sessionTime).Unix()
	for id, seen := range s.seenOrd {
		if seen > ev {
			continue
		}

		sk := s.keyOf[id]
		sesslog.Debug(context.Background(), "evicting session",
			"session-id", id,
			"last-seen", seen,
			"session-key", sk)

		delete(s.byKey, sk)
		delete(s.byID, id)
		delete(s.keyOf, id)
		delete(s.seenOrd, id)
	}
}

func (s *SessionStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byKey)
}

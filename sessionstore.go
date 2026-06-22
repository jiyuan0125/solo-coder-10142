package goatcounter

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"zgo.at/goatcounter/v2/pkg/log"
	"zgo.at/json"
	"zgo.at/zdb"
	"zgo.at/zstd/zint"
	"zgo.at/zstd/ztime"
)

var sesslog = log.Module("session")

type sessionKey string

type sessionEntry struct {
	id       zint.Uint128
	key      sessionKey
	paths    map[PathID]struct{}
	lastSeen int64
}

type storedSessionEntry struct {
	Key      sessionKey              `json:"key"`
	Paths    map[PathID]struct{}     `json:"paths"`
	LastSeen int64                   `json:"last_seen"`
}

type storedSessionStore struct {
	Sessions map[zint.Uint128]storedSessionEntry `json:"sessions"`
}

type SessionStore struct {
	mu          sync.RWMutex
	byKey       map[sessionKey]*sessionEntry
	byID        map[zint.Uint128]*sessionEntry
	sessionTime time.Duration

	testHook    bool
	testSeq     atomic.Uint64
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessionTime: 8 * time.Hour,
		byKey:       make(map[sessionKey]*sessionEntry),
		byID:        make(map[zint.Uint128]*sessionEntry),
	}
}

func (s *SessionStore) SetSessionTime(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionTime = d
}

func (s *SessionStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.byKey = make(map[sessionKey]*sessionEntry)
	s.byID = make(map[zint.Uint128]*sessionEntry)
	s.testSeq.Store(1)
}

func (s *SessionStore) TestInit(db zdb.DB) error {
	s.testHook = true
	return s.Init(db)
}

func (s *SessionStore) Init(db zdb.DB) error {
	s.Reset()

	var data []byte
	err := db.Get(context.Background(), &data, `select value from store where key='session'`)
	if err != nil {
		if zdb.ErrNoRows(err) {
			memlog.Debugf(context.Background(), "no sessions stored in DB")
			return nil
		}
		memlog.Errorf(context.Background(), "load from DB store: %s", err)
		return nil
	}

	var stored storedSessionStore
	err = json.Unmarshal(data, &stored)
	if err != nil {
		memlog.Errorf(context.Background(), "unmarshal from DB store: %s", err)
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, entry := range stored.Sessions {
		e := &sessionEntry{
			id:       id,
			key:      entry.Key,
			paths:    entry.Paths,
			lastSeen: entry.LastSeen,
		}
		s.byKey[entry.Key] = e
		s.byID[id] = e
	}

	memlog.Debug(context.Background(), "restored sessions from DB",
		"sessions", len(s.byID))
	return nil
}

func (s *SessionStore) StoreSessions(db zdb.DB) {
	s.mu.RLock()
	stored := storedSessionStore{
		Sessions: make(map[zint.Uint128]storedSessionEntry, len(s.byID)),
	}
	for id, e := range s.byID {
		stored.Sessions[id] = storedSessionEntry{
			Key:      e.key,
			Paths:    e.paths,
			LastSeen: e.lastSeen,
		}
	}
	s.mu.RUnlock()

	d, err := json.Marshal(stored)
	if err != nil {
		memlog.Error(context.Background(), err)
		return
	}

	err = db.Exec(context.Background(), `
		insert into store (key, value) values ('session', $1)
		on conflict (key) do update set value = excluded.value
	`, d)
	if err != nil {
		memlog.Error(context.Background(), err)
	}

	memlog.Debug(context.Background(), "stored sessions in DB",
		"bytesize", len(d),
		"sessions", len(stored.Sessions))
}

func (s *SessionStore) SessionID() zint.Uint128 {
	if s.testHook {
		seq := s.testSeq.Add(1)
		return zint.Uint128{TestSession[0], TestSession[1] + seq}
	}
	return UUID()
}

func (s *SessionStore) SessionsLen() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byID)
}

func (s *SessionStore) EvictSessions(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()

	evictBefore := ztime.Now(ctx).Add(-s.sessionTime).Unix()
	for id, e := range s.byID {
		if e.lastSeen > evictBefore {
			continue
		}

		sesslog.Debug(context.Background(), "evicting session",
			"session-id", id,
			"last-seen", e.lastSeen,
			"session-key", e.key)

		delete(s.byKey, e.key)
		delete(s.byID, id)
	}
}

func (s *SessionStore) GetOrCreate(ctx context.Context, siteID SiteID, pathID PathID, userSessionID, ua, remoteAddr string) (zint.Uint128, bool) {
	sk := sessionKey(userSessionID)
	if userSessionID == "" {
		sk = sessionKey(fmt.Sprintf("%s-%s-%d", ua, remoteAddr, siteID))
	}

	s.mu.RLock()
	e, ok := s.byKey[sk]
	if ok {
		now := ztime.Now(ctx).Unix()
		_, seenPath := e.paths[pathID]
		if !seenPath {
			s.mu.RUnlock()
			s.mu.Lock()
			e, ok = s.byKey[sk]
			if ok {
				e.lastSeen = now
				e.paths[pathID] = struct{}{}
			}
			s.mu.Unlock()
			if ok {
				sesslog.Debug(ctx, "HIT: new path",
					"session-key", sk,
					"session-id", e.id,
					"path", pathID)
				return e.id, true
			}
			s.mu.RLock()
			e, ok = s.byKey[sk]
			if ok {
				s.mu.RUnlock()
				sesslog.Debug(ctx, "HIT",
					"session-key", sk,
					"session-id", e.id,
					"path", pathID,
					"seen-path", true)
				return e.id, false
			}
		} else {
			e.lastSeen = now
			s.mu.RUnlock()
			sesslog.Debug(ctx, "HIT",
				"session-key", sk,
				"session-id", e.id,
				"path", pathID,
				"seen-path", true)
			return e.id, false
		}
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok = s.byKey[sk]
	if ok {
		now := ztime.Now(ctx).Unix()
		_, seenPath := e.paths[pathID]
		e.lastSeen = now
		if !seenPath {
			e.paths[pathID] = struct{}{}
		}
		sesslog.Debug(ctx, "HIT (after upgrade)",
			"session-key", sk,
			"session-id", e.id,
			"path", pathID,
			"seen-path", seenPath)
		return e.id, !seenPath
	}

	id := s.SessionID()
	e = &sessionEntry{
		id:       id,
		key:      sk,
		paths:    map[PathID]struct{}{pathID: {}},
		lastSeen: ztime.Now(ctx).Unix(),
	}
	s.byKey[sk] = e
	s.byID[id] = e

	sesslog.Debug(ctx, "MISS: created new",
		"session-key", sk,
		"session-id", id,
		"path", pathID)
	return id, true
}

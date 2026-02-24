package server

import (
	"sync"
	"time"
)

// ChallengeStore is the interface for nonce→User-Agent storage used by the Client Hints
// behavioral challenge (Appendix K). When REDIS_URL is set, the server uses a Redis-backed
// implementation; otherwise the in-memory implementation is used. See METHODOLOGY.md Appendix K.
type ChallengeStore interface {
	Set(nonce, userAgent string)
	Get(nonce string) (userAgent string, ok bool)
	GetDebug(nonce string) (userAgent string, inStore bool, createdAt time.Time, expired bool)
}

// challengeEntry holds the stored User-Agent and creation time for a nonce.
type challengeEntry struct {
	UserAgent string
	CreatedAt time.Time
}

// memoryChallengeStore is the in-memory implementation of ChallengeStore. Entries expire after TTL;
// expiry is checked lazily on Get. Used when Redis is not configured.
type memoryChallengeStore struct {
	mu  sync.Map // map[string]*challengeEntry
	ttl time.Duration
	now func() time.Time // for tests
}

// NewChallengeStore creates an in-memory challenge store with the given TTL. Entries older than TTL
// are treated as missing on Get. When Redis is configured (REDIS_URL), the server uses a Redis-backed
// store instead; see NewRedisChallengeStore.
func NewChallengeStore(ttl time.Duration) ChallengeStore {
	return &memoryChallengeStore{ttl: ttl, now: time.Now}
}

// Set stores nonce -> userAgent with the current timestamp. Overwrites any existing entry for nonce.
func (s *memoryChallengeStore) Set(nonce, userAgent string) {
	s.mu.Store(nonce, &challengeEntry{UserAgent: userAgent, CreatedAt: s.now()})
}

// Get returns the User-Agent stored for nonce and true if the entry exists and has not expired.
// If the entry is older than TTL, it is deleted and Get returns "", false.
func (s *memoryChallengeStore) Get(nonce string) (userAgent string, ok bool) {
	v, loaded := s.mu.Load(nonce)
	if !loaded {
		return "", false
	}
	ent := v.(*challengeEntry)
	if s.now().Sub(ent.CreatedAt) > s.ttl {
		s.mu.Delete(nonce)
		return "", false
	}
	return ent.UserAgent, true
}

// GetDebug returns stored User-Agent, whether the nonce is in the store, creation time, and whether the entry has expired.
// Does not delete expired entries (read-only for /debug). Use Get for normal lookup.
func (s *memoryChallengeStore) GetDebug(nonce string) (userAgent string, inStore bool, createdAt time.Time, expired bool) {
	v, loaded := s.mu.Load(nonce)
	if !loaded {
		return "", false, time.Time{}, false
	}
	ent := v.(*challengeEntry)
	expired = s.now().Sub(ent.CreatedAt) > s.ttl
	return ent.UserAgent, true, ent.CreatedAt, expired
}

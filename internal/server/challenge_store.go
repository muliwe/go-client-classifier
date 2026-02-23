package server

import (
	"sync"
	"time"
)

// challengeEntry holds the stored User-Agent and creation time for a nonce.
type challengeEntry struct {
	UserAgent string
	CreatedAt time.Time
}

// ChallengeStore is a concurrent store mapping nonce (JA4H parts C_D) to the raw User-Agent
// seen on the first request. Used for the Client Hints behavioral challenge (Appendix K).
// Entries expire after TTL; expiry is checked lazily on Get.
type ChallengeStore struct {
	mu  sync.Map // map[string]*challengeEntry
	ttl time.Duration
	now func() time.Time // for tests
}

// NewChallengeStore creates a store with the given TTL. Entries older than TTL are treated as missing on Get.
func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{ttl: ttl, now: time.Now}
}

// Set stores nonce -> userAgent with the current timestamp. Overwrites any existing entry for nonce.
func (s *ChallengeStore) Set(nonce, userAgent string) {
	s.mu.Store(nonce, &challengeEntry{UserAgent: userAgent, CreatedAt: s.now()})
}

// Get returns the User-Agent stored for nonce and true if the entry exists and has not expired.
// If the entry is older than TTL, it is deleted and Get returns "", false.
func (s *ChallengeStore) Get(nonce string) (userAgent string, ok bool) {
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

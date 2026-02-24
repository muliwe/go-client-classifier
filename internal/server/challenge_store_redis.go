package server

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisChallengeEntry is stored as JSON in Redis for nonce keys. Creation time enables GetDebug
// and optional TTL refresh on Get (per in-memory semantics). Key schema: {prefix}:nonce:{nonce}.
// References: Redis.io key design; Client Hints challenge (METHODOLOGY.md Appendix K).
type redisChallengeEntry struct {
	UA string `json:"ua"` // User-Agent
	At int64  `json:"at"` // Unix seconds when stored
}

// redisChallengeStore is the Redis-backed implementation of ChallengeStore. When REDIS_URL is set,
// the server uses this instead of in-memory store so that all instances share the same nonce state.
type redisChallengeStore struct {
	client *redis.Client
	prefix string // e.g. "ch"
	ttl    time.Duration
}

// NewRedisChallengeStore creates a ChallengeStore backed by Redis. Key pattern: {prefix}:nonce:{nonce}.
// TTL is applied on Set and optionally refreshed on Get to match in-memory behavior.
func NewRedisChallengeStore(client *redis.Client, prefix string, ttl time.Duration) ChallengeStore {
	if prefix == "" {
		prefix = "ch"
	}
	return &redisChallengeStore{client: client, prefix: prefix, ttl: ttl}
}

func (s *redisChallengeStore) key(nonce string) string {
	return fmt.Sprintf("%s:nonce:%s", s.prefix, nonce)
}

// Set stores nonce→userAgent in Redis with TTL. Overwrites any existing entry (SET with EX).
func (s *redisChallengeStore) Set(nonce, userAgent string) {
	ctx := context.Background()
	ent := redisChallengeEntry{UA: userAgent, At: time.Now().Unix()}
	val, _ := json.Marshal(ent)
	k := s.key(nonce)
	s.client.Set(ctx, k, val, s.ttl)
}

// Get returns the User-Agent for nonce and true if the key exists and has not expired.
// On success, TTL is refreshed to match in-memory semantics (optional; we refresh for consistency).
func (s *redisChallengeStore) Get(nonce string) (userAgent string, ok bool) {
	ctx := context.Background()
	k := s.key(nonce)
	val, err := s.client.Get(ctx, k).Result()
	if err == redis.Nil {
		return "", false
	}
	if err != nil {
		return "", false
	}
	var ent redisChallengeEntry
	if err := json.Unmarshal([]byte(val), &ent); err != nil {
		return "", false
	}
	// Refresh TTL on read (as in-memory store does not expire mid-ttl)
	_ = s.client.Expire(ctx, k, s.ttl)
	return ent.UA, true
}

// GetDebug returns stored User-Agent, presence, creation time, and expiry. Uses GET and PTTL.
// Does not delete or refresh; read-only for /debug.
func (s *redisChallengeStore) GetDebug(nonce string) (userAgent string, inStore bool, createdAt time.Time, expired bool) {
	ctx := context.Background()
	k := s.key(nonce)
	val, err := s.client.Get(ctx, k).Result()
	if err == redis.Nil {
		return "", false, time.Time{}, false
	}
	if err != nil {
		return "", false, time.Time{}, false
	}
	var ent redisChallengeEntry
	if err := json.Unmarshal([]byte(val), &ent); err != nil {
		return "", true, time.Time{}, true
	}
	pttl, err := s.client.PTTL(ctx, k).Result()
	if err != nil {
		return ent.UA, true, time.Unix(ent.At, 0), true
	}
	expired = pttl < 0
	return ent.UA, true, time.Unix(ent.At, 0), expired
}

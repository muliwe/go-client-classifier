package server

import (
	"sync"
	"testing"
	"time"
)

func TestChallengeStore_SetGet(t *testing.T) {
	store := NewChallengeStore(2 * time.Second)
	store.Set("nonce1", "Mozilla/5.0")
	ua, ok := store.Get("nonce1")
	if !ok || ua != "Mozilla/5.0" {
		t.Errorf("Get(nonce1) = (%q, %v), want (Mozilla/5.0, true)", ua, ok)
	}
	_, ok = store.Get("unknown")
	if ok {
		t.Error("Get(unknown) should return ok=false")
	}
}

func TestChallengeStore_Overwrite(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	store.Set("n", "UA1")
	store.Set("n", "UA2")
	ua, ok := store.Get("n")
	if !ok || ua != "UA2" {
		t.Errorf("Get(n) after overwrite = (%q, %v), want (UA2, true)", ua, ok)
	}
}

func TestChallengeStore_TTLExpiry(t *testing.T) {
	now := time.Now()
	store := &ChallengeStore{ttl: 100 * time.Millisecond, now: func() time.Time { return now }}
	store.Set("n", "UA")
	ua, ok := store.Get("n")
	if !ok || ua != "UA" {
		t.Fatalf("Get(n) before expiry = (%q, %v), want (UA, true)", ua, ok)
	}
	// Advance past TTL
	store.now = func() time.Time { return now.Add(200 * time.Millisecond) }
	_, ok = store.Get("n")
	if ok {
		t.Error("Get(n) after TTL should return ok=false")
	}
	_, ok = store.Get("n")
	if ok {
		t.Error("second Get(n) after expiry should still return ok=false")
	}
}

func TestChallengeStore_Concurrent(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(j int) {
			defer wg.Done()
			store.Set("key", "UA")
			store.Get("key")
		}(i)
	}
	wg.Wait()
}

package server

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisChallengeStore_SetGet(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store := NewRedisChallengeStore(client, "ch", 2*time.Second).(*redisChallengeStore)

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

func TestRedisChallengeStore_Overwrite(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store := NewRedisChallengeStore(client, "ch", time.Minute).(*redisChallengeStore)

	store.Set("n", "UA1")
	store.Set("n", "UA2")
	ua, ok := store.Get("n")
	if !ok || ua != "UA2" {
		t.Errorf("Get(n) after overwrite = (%q, %v), want (UA2, true)", ua, ok)
	}
}

func TestRedisChallengeStore_TTLExpiry(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	// miniredis enforces minimum 1s TTL; use 2s and fast-forward 3s
	store := NewRedisChallengeStore(client, "ch", 2*time.Second).(*redisChallengeStore)

	store.Set("n", "UA")
	ua, ok := store.Get("n")
	if !ok || ua != "UA" {
		t.Fatalf("Get(n) before expiry = (%q, %v), want (UA, true)", ua, ok)
	}
	mr.FastForward(3 * time.Second)
	_, ok = store.Get("n")
	if ok {
		t.Error("Get(n) after TTL should return ok=false")
	}
}

func TestRedisChallengeStore_GetDebug(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store := NewRedisChallengeStore(client, "ch", time.Minute).(*redisChallengeStore)

	store.Set("n", "UA-debug")
	ua, inStore, createdAt, expired := store.GetDebug("n")
	if !inStore || ua != "UA-debug" || expired {
		t.Errorf("GetDebug(n) = ua=%q inStore=%v expired=%v createdAt=%v", ua, inStore, expired, createdAt)
	}
	if createdAt.IsZero() {
		t.Error("GetDebug: createdAt should be set")
	}
	_, inStore2, _, expired2 := store.GetDebug("missing")
	if inStore2 || expired2 {
		t.Errorf("GetDebug(missing) should be inStore=false: inStore=%v expired=%v", inStore2, expired2)
	}
}

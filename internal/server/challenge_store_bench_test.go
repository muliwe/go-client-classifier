package server

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func BenchmarkMemoryChallengeStore_SetGet(b *testing.B) {
	store := NewChallengeStore(2 * time.Minute).(*memoryChallengeStore)
	nonce := "bench_nonce"
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(nonce, ua)
		store.Get(nonce)
	}
}

func BenchmarkRedisChallengeStore_SetGet(b *testing.B) {
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	store := NewRedisChallengeStore(client, "ch", 2*time.Minute).(*redisChallengeStore)
	nonce := "bench_nonce"
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Set(nonce, ua)
		store.Get(nonce)
	}
}

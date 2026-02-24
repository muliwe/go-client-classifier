package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestCollector_RecordRequest_NilClient(t *testing.T) {
	c := NewCollector(nil, CollectorConfig{})
	c.RecordRequest("1.2.3.4", "") // must not panic
	c.RecordRequest("1.2.3.4", "nonce1")
}

func TestCollector_RecordRequest_Integration(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	c := NewCollector(client, CollectorConfig{
		Prefix:    "m",
		WindowSec: 60,
		IPTTL:     time.Hour,
		NonceTTL:  10 * time.Minute,
	})
	c.RecordRequest("192.168.1.1", "abc_nonce")
	// Allow goroutine to run
	time.Sleep(50 * time.Millisecond)
	ctx := context.Background()
	keyIP := "m:ip:192.168.1.1:req"
	n, _ := client.ZCard(ctx, keyIP).Result()
	if n != 1 {
		t.Errorf("expected 1 member in %s, got %d", keyIP, n)
	}
	keyNonce := "m:nonce:abc_nonce:req"
	n2, _ := client.ZCard(ctx, keyNonce).Result()
	if n2 != 1 {
		t.Errorf("expected 1 member in %s, got %d", keyNonce, n2)
	}
}

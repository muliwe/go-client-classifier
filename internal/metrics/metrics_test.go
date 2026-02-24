package metrics

import (
	"context"
	"fmt"
	"math"
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

// TestGetRequestMetrics_WithMockRedis seeds Redis with known timestamps and asserts GetRequestMetrics
// returns correct ago_sec, derived stats, and that all floats are rounded to 3 decimals.
// Ensures changes to metrics logic (e.g. rounding, removal of raw timestamps) are caught.
func TestGetRequestMetrics_WithMockRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	prefix := "m"
	windowSec := 300
	nowMs := time.Now().UnixMilli()
	ctx := context.Background()

	// IP: 3 requests at now, now-1s, now-3s (newest first after ZREVRANGE)
	keyIP := prefix + ":ip:10.0.0.1:req"
	for i, deltaMs := range []int64{0, 1000, 3000} {
		score := float64(nowMs - deltaMs)
		if err := client.ZAdd(ctx, keyIP, redis.Z{Score: score, Member: fmt.Sprintf("ip_%d_%d", i, nowMs)}).Err(); err != nil {
			t.Fatalf("ZAdd IP: %v", err)
		}
	}
	// Nonce: 2 requests at now, now-2s
	keyNonce := prefix + ":nonce:abc_nonce:req"
	for i, deltaMs := range []int64{0, 2000} {
		score := float64(nowMs - deltaMs)
		if err := client.ZAdd(ctx, keyNonce, redis.Z{Score: score, Member: fmt.Sprintf("n_%d_%d", i, nowMs)}).Err(); err != nil {
			t.Fatalf("ZAdd nonce: %v", err)
		}
	}

	c := NewCollector(client, CollectorConfig{
		Prefix:    prefix,
		WindowSec: windowSec,
		IPTTL:     time.Hour,
		NonceTTL:  10 * time.Minute,
	})
	m, err := c.GetRequestMetrics(ctx, "10.0.0.1", "abc_nonce")
	if err != nil {
		t.Fatalf("GetRequestMetrics: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil RequestMetrics")
	}

	// Counts
	if m.IPRequestCount != 3 {
		t.Errorf("ip_request_count: got %d, want 3", m.IPRequestCount)
	}
	if m.NonceRequestCount != 2 {
		t.Errorf("nonce_request_count: got %d, want 2", m.NonceRequestCount)
	}

	// Human-readable ago (seconds ago); order newest first → [0, ~1, ~3]
	if len(m.IPRequestAgoSec) != 3 {
		t.Fatalf("ip_request_ago_sec: len = %d, want 3", len(m.IPRequestAgoSec))
	}
	if m.IPRequestAgoSec[0] > 0.5 {
		t.Errorf("ip_request_ago_sec[0] (newest) want ~0, got %f", m.IPRequestAgoSec[0])
	}
	assertRoundedTo3(t, "ip_request_ago_sec[0]", m.IPRequestAgoSec[0])
	assertRoundedTo3(t, "ip_request_ago_sec[1]", m.IPRequestAgoSec[1])
	assertRoundedTo3(t, "ip_request_ago_sec[2]", m.IPRequestAgoSec[2])
	// ~1s and ~3s ago (allow 0.5s tolerance)
	if math.Abs(m.IPRequestAgoSec[1]-1) > 0.5 {
		t.Errorf("ip_request_ago_sec[1] want ~1, got %f", m.IPRequestAgoSec[1])
	}
	if math.Abs(m.IPRequestAgoSec[2]-3) > 0.5 {
		t.Errorf("ip_request_ago_sec[2] want ~3, got %f", m.IPRequestAgoSec[2])
	}

	if len(m.NonceRequestAgoSec) != 2 {
		t.Fatalf("nonce_request_ago_sec: len = %d, want 2", len(m.NonceRequestAgoSec))
	}
	if m.NonceRequestAgoSec[0] > 0.5 {
		t.Errorf("nonce_request_ago_sec[0] (newest) want ~0, got %f", m.NonceRequestAgoSec[0])
	}
	assertRoundedTo3(t, "nonce_request_ago_sec[0]", m.NonceRequestAgoSec[0])
	assertRoundedTo3(t, "nonce_request_ago_sec[1]", m.NonceRequestAgoSec[1])
	if math.Abs(m.NonceRequestAgoSec[1]-2) > 0.5 {
		t.Errorf("nonce_request_ago_sec[1] want ~2, got %f", m.NonceRequestAgoSec[1])
	}

	// Derived: must be present and rounded
	if m.IPDerived == nil {
		t.Fatal("ip_derived must be non-nil")
	}
	if m.IPDerived.RequestRatePerMin <= 0 {
		t.Errorf("ip_derived.request_rate_per_min: got %f", m.IPDerived.RequestRatePerMin)
	}
	assertRoundedTo3(t, "request_rate_per_min", m.IPDerived.RequestRatePerMin)
	assertRoundedTo3(t, "inter_arrival_median_sec", m.IPDerived.InterArrivalMedianSec)
	assertRoundedTo3(t, "inter_arrival_mean_sec", m.IPDerived.InterArrivalMeanSec)
	assertRoundedTo3(t, "inter_arrival_std_sec", m.IPDerived.InterArrivalStdSec)
	assertRoundedTo3(t, "inter_arrival_min_sec", m.IPDerived.InterArrivalMinSec)
	assertRoundedTo3(t, "inter_arrival_max_sec", m.IPDerived.InterArrivalMaxSec)
	// 3 timestamps → 2 gaps: 1s and 2s → min=1, max=2
	if m.IPDerived.InterArrivalMinSec < 0.9 || m.IPDerived.InterArrivalMinSec > 1.1 {
		t.Errorf("ip_derived.inter_arrival_min_sec: got %f, want ~1", m.IPDerived.InterArrivalMinSec)
	}
	if m.IPDerived.InterArrivalMaxSec < 1.9 || m.IPDerived.InterArrivalMaxSec > 2.1 {
		t.Errorf("ip_derived.inter_arrival_max_sec: got %f, want ~2", m.IPDerived.InterArrivalMaxSec)
	}

	if m.NonceDerived == nil {
		t.Fatal("nonce_derived must be non-nil")
	}
	if m.NonceDerived.RequestRatePerMin <= 0 {
		t.Errorf("nonce_derived.request_rate_per_min: got %f", m.NonceDerived.RequestRatePerMin)
	}
	assertRoundedTo3(t, "nonce request_rate_per_min", m.NonceDerived.RequestRatePerMin)
	// 2 timestamps → 1 gap = 2s; median/mean/min/max all 2
	if math.Abs(m.NonceDerived.InterArrivalMeanSec-2) > 0.5 {
		t.Errorf("nonce_derived.inter_arrival_mean_sec: got %f, want ~2", m.NonceDerived.InterArrivalMeanSec)
	}
}

// assertRoundedTo3 fails if f is not rounded to 3 decimal places (round3(f) == f).
func assertRoundedTo3(t *testing.T, label string, f float64) {
	t.Helper()
	r := math.Round(f*1000) / 1000
	if math.Abs(f-r) > 1e-9 {
		t.Errorf("%s: %f is not rounded to 3 decimals (expected %f)", label, f, r)
	}
}

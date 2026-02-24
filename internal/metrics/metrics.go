// Package metrics provides behavioral metrics collection for bot detection research.
// Metrics are stored in Redis per client IP and per __ch_nonce (when present). No scoring
// is performed in this package; collection only. See METHODOLOGY.md Appendix L.
// References: Redis rate-limiting patterns (Redis.io); Cresci et al., Knowledge-Based Systems, 2021;
// BOTracle (Kadel et al., arXiv:2412.02266).
package metrics

import (
	"context"
	"fmt"
	"log"
	"math"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
)

// Collector records request timestamps per entity (IP, nonce) in Redis sorted sets.
// Key schema: {prefix}:ip:{ip}:req, {prefix}:nonce:{nonce}:req (score = unix ms, member = unique id).
// Sliding-window count is obtained by ZREMRANGEBYSCORE then ZADD then ZCARD (Redis.io rate-limiting pattern).
type Collector struct {
	client    *redis.Client
	prefix    string
	windowSec int           // sliding-window length in seconds
	ipTTL     time.Duration // TTL for IP keys (e.g. 24h)
	nonceTTL  time.Duration // TTL for nonce keys (e.g. 2× challenge TTL)
}

// CollectorConfig configures the metrics collector.
type CollectorConfig struct {
	Prefix    string
	WindowSec int           // REDIS_METRICS_WINDOW_SEC
	IPTTL     time.Duration // e.g. 24h
	NonceTTL  time.Duration // e.g. 2× challenge TTL
}

// NewCollector creates a metrics collector. If client is nil, RecordRequest is a no-op.
func NewCollector(client *redis.Client, cfg CollectorConfig) *Collector {
	if client == nil {
		return &Collector{}
	}
	if cfg.WindowSec <= 0 {
		cfg.WindowSec = 300
	}
	return &Collector{
		client:    client,
		prefix:    cfg.Prefix,
		windowSec: cfg.WindowSec,
		ipTTL:     cfg.IPTTL,
		nonceTTL:  cfg.NonceTTL,
	}
}

// RecordRequest records a request for the given IP and optional nonce (__ch_nonce cookie value).
// It is non-blocking: runs in a goroutine. Failures are logged; request/classification are unaffected.
func (c *Collector) RecordRequest(ip, nonce string) {
	if c.client == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		now := time.Now()
		nowMs := now.UnixMilli()
		cutoff := nowMs - int64(c.windowSec)*1000
		member := fmt.Sprintf("%d", now.UnixNano())

		if ip != "" {
			key := fmt.Sprintf("%s:ip:%s:req", c.prefix, ip)
			if err := c.recordOne(ctx, key, cutoff, nowMs, member, c.ipTTL); err != nil {
				log.Printf("metrics: record IP %q: %v", ip, err)
			}
		}
		if nonce != "" {
			key := fmt.Sprintf("%s:nonce:%s:req", c.prefix, nonce)
			if err := c.recordOne(ctx, key, cutoff, nowMs, member, c.nonceTTL); err != nil {
				log.Printf("metrics: record nonce: %v", err)
			}
		}
	}()
}

// recordOne runs ZREMRANGEBYSCORE (trim), ZADD (add current), EXPIRE for one key.
func (c *Collector) recordOne(ctx context.Context, key string, cutoff, nowMs int64, member string, ttl time.Duration) error {
	pipe := c.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", cutoff))
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(nowMs), Member: member})
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// MaxRequestTimestampsInDebug is the max number of request timestamps returned in /debug request_metrics (history).
const MaxRequestTimestampsInDebug = 30

// DerivedStats holds inter-arrival and rate metrics used in bot-detection research (Cresci et al. 2021; BOTracle 2024; F5/Cloudflare heuristics 2025).
// Low inter-arrival variance can indicate automation; high request rate density is a bot signal.
type DerivedStats struct {
	RequestRatePerMin     float64 `json:"request_rate_per_min,omitempty"`     // requests per minute in window (density)
	InterArrivalMedianSec float64 `json:"inter_arrival_median_sec,omitempty"` // median time between consecutive requests (sec)
	InterArrivalMeanSec   float64 `json:"inter_arrival_mean_sec,omitempty"`   // mean inter-arrival (sec)
	InterArrivalStdSec    float64 `json:"inter_arrival_std_sec,omitempty"`    // std dev of inter-arrival; low = regular timing (bot-like)
	InterArrivalMinSec    float64 `json:"inter_arrival_min_sec,omitempty"`    // min gap (sec)
	InterArrivalMaxSec    float64 `json:"inter_arrival_max_sec,omitempty"`    // max gap (sec); with min indicates burstiness
}

// RequestMetrics holds current sliding-window counts, human-readable ago deltas, and derived stats for the request's IP and (if present) nonce.
// Raw timestamps are not exposed; only ip_request_ago_sec / nonce_request_ago_sec and ip_derived / nonce_derived. See Appendix L.
type RequestMetrics struct {
	WindowSec          int           `json:"window_sec"`                      // sliding-window length in seconds
	IP                 string        `json:"ip,omitempty"`                    // client IP for which counts are shown
	IPRequestCount     int64         `json:"ip_request_count,omitempty"`      // requests from this IP in the window
	IPRequestAgoSec    []float64     `json:"ip_request_ago_sec,omitempty"`    // human-readable: seconds ago from this request (0 = newest)
	IPDerived          *DerivedStats `json:"ip_derived,omitempty"`            // request rate density, inter-arrival stats (median, mean, std, min, max)
	Nonce              string        `json:"nonce,omitempty"`                 // __ch_nonce value if present (C_D only, not full cookie)
	NonceRequestCount  int64         `json:"nonce_request_count,omitempty"`   // requests with this nonce in the window (0 if no nonce)
	NonceRequestAgoSec []float64     `json:"nonce_request_ago_sec,omitempty"` // human-readable: seconds ago from this request (0 = newest)
	NonceDerived       *DerivedStats `json:"nonce_derived,omitempty"`         // same derived stats for nonce
}

// GetRequestMetrics returns current request counts and last N timestamps in the sliding window for the given IP and nonce.
// Read-only (ZCOUNT + ZREVRANGEBYSCORE). If client is nil, returns metrics with zero counts and nil timestamps. On Redis error, returns (nil, err).
// Used by /debug to expose metrics and request history for this request.
func (c *Collector) GetRequestMetrics(ctx context.Context, ip, nonce string) (*RequestMetrics, error) {
	if c.client == nil {
		return &RequestMetrics{WindowSec: c.windowSec, IP: ip, Nonce: nonce}, nil
	}
	nowMs := time.Now().UnixMilli()
	minScore := fmt.Sprintf("%d", nowMs-int64(c.windowSec)*1000)
	zRange := &redis.ZRangeBy{Min: minScore, Max: "+inf", Count: MaxRequestTimestampsInDebug}

	out := &RequestMetrics{WindowSec: c.windowSec, IP: ip, Nonce: nonce}

	if ip != "" {
		key := fmt.Sprintf("%s:ip:%s:req", c.prefix, ip)
		n, err := c.client.ZCount(ctx, key, minScore, "+inf").Result()
		if err != nil {
			return nil, err
		}
		out.IPRequestCount = n
		zs, err := c.client.ZRevRangeByScoreWithScores(ctx, key, zRange).Result()
		if err != nil {
			return nil, err
		}
		ipTs := zScoresToInt64(zs)
		out.IPRequestAgoSec = timestampsToAgoSec(nowMs, ipTs)
		out.IPDerived = derivedStats(c.windowSec, out.IPRequestCount, ipTs)
	}
	if nonce != "" {
		key := fmt.Sprintf("%s:nonce:%s:req", c.prefix, nonce)
		n, err := c.client.ZCount(ctx, key, minScore, "+inf").Result()
		if err != nil {
			return nil, err
		}
		out.NonceRequestCount = n
		zs, err := c.client.ZRevRangeByScoreWithScores(ctx, key, zRange).Result()
		if err != nil {
			return nil, err
		}
		nonceTs := zScoresToInt64(zs)
		out.NonceRequestAgoSec = timestampsToAgoSec(nowMs, nonceTs)
		out.NonceDerived = derivedStats(c.windowSec, out.NonceRequestCount, nonceTs)
	}

	return out, nil
}

// round3 rounds to 3 decimal places for readable JSON output.
func round3(f float64) float64 {
	return math.Round(f*1000) / 1000
}

// derivedStats computes request rate per minute and inter-arrival stats (median, mean, std, min, max) from timestamps (newest first, unix ms).
// Used for bot-detection heuristics: request density and inter-arrival regularity (Cresci et al. 2021; Cloudflare/F5 2025).
// All float outputs are rounded to 3 decimal places.
func derivedStats(windowSec int, count int64, timestamps []int64) *DerivedStats {
	if windowSec <= 0 {
		return nil
	}
	d := &DerivedStats{}
	d.RequestRatePerMin = round3(float64(count) / (float64(windowSec) / 60.0))
	if len(timestamps) < 2 {
		return d
	}
	gapsSec := make([]float64, 0, len(timestamps)-1)
	for i := 0; i < len(timestamps)-1; i++ {
		gapMs := timestamps[i] - timestamps[i+1]
		if gapMs < 0 {
			gapMs = -gapMs
		}
		gapsSec = append(gapsSec, float64(gapMs)/1000.0)
	}
	sort.Float64s(gapsSec)
	n := len(gapsSec)
	d.InterArrivalMinSec = round3(gapsSec[0])
	d.InterArrivalMaxSec = round3(gapsSec[n-1])
	sum := 0.0
	for _, g := range gapsSec {
		sum += g
	}
	d.InterArrivalMeanSec = round3(sum / float64(n))
	var variance float64
	for _, g := range gapsSec {
		variance += (g - d.InterArrivalMeanSec) * (g - d.InterArrivalMeanSec)
	}
	if n > 1 {
		variance /= float64(n - 1)
	}
	d.InterArrivalStdSec = round3(math.Sqrt(variance))
	if n%2 == 1 {
		d.InterArrivalMedianSec = round3(gapsSec[n/2])
	} else {
		d.InterArrivalMedianSec = round3((gapsSec[n/2-1] + gapsSec[n/2]) / 2)
	}
	return d
}

// timestampsToAgoSec returns seconds ago from nowMs for each timestamp (newest first). 0 = this request / most recent. Rounded to 3 decimals.
func timestampsToAgoSec(nowMs int64, timestamps []int64) []float64 {
	if len(timestamps) == 0 {
		return nil
	}
	out := make([]float64, len(timestamps))
	for i, ts := range timestamps {
		out[i] = round3(float64(nowMs-ts) / 1000.0)
	}
	return out
}

func zScoresToInt64(zs []redis.Z) []int64 {
	if len(zs) == 0 {
		return nil
	}
	out := make([]int64, len(zs))
	for i, z := range zs {
		out[i] = int64(z.Score)
	}
	return out
}

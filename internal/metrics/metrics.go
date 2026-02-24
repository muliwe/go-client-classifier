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

// RequestMetrics holds current sliding-window counts for the request's IP and (if present) nonce.
// Used in /debug to show metrics pertaining to this request. See Appendix L.
type RequestMetrics struct {
	WindowSec         int    `json:"window_sec"`                    // sliding-window length in seconds
	IP                string `json:"ip,omitempty"`                  // client IP for which counts are shown
	IPRequestCount    int64  `json:"ip_request_count,omitempty"`    // requests from this IP in the window
	Nonce             string `json:"nonce,omitempty"`               // __ch_nonce value if present (C_D only, not full cookie)
	NonceRequestCount int64  `json:"nonce_request_count,omitempty"` // requests with this nonce in the window (0 if no nonce)
}

// GetRequestMetrics returns current request counts in the sliding window for the given IP and nonce.
// Read-only (ZCOUNT). If client is nil, returns metrics with zero counts. On Redis error, returns (nil, err).
// Used by /debug to expose metrics for this request.
func (c *Collector) GetRequestMetrics(ctx context.Context, ip, nonce string) (*RequestMetrics, error) {
	if c.client == nil {
		return &RequestMetrics{WindowSec: c.windowSec, IP: ip, Nonce: nonce}, nil
	}
	nowMs := time.Now().UnixMilli()
	minScore := fmt.Sprintf("%d", nowMs-int64(c.windowSec)*1000)

	out := &RequestMetrics{WindowSec: c.windowSec, IP: ip, Nonce: nonce}

	if ip != "" {
		key := fmt.Sprintf("%s:ip:%s:req", c.prefix, ip)
		n, err := c.client.ZCount(ctx, key, minScore, "+inf").Result()
		if err != nil {
			return nil, err
		}
		out.IPRequestCount = n
	}
	if nonce != "" {
		key := fmt.Sprintf("%s:nonce:%s:req", c.prefix, nonce)
		n, err := c.client.ZCount(ctx, key, minScore, "+inf").Result()
		if err != nil {
			return nil, err
		}
		out.NonceRequestCount = n
	}

	return out, nil
}

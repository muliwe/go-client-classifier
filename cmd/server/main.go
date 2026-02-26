package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/config"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/server"
)

func main() {
	// Load scoring config (points, thresholds, classifier); fallback to defaults on error
	scoringPath := os.Getenv("SCORING_CONFIG")
	if scoringPath == "" {
		scoringPath = "config/scoring.json"
	}
	scoringCfg, err := config.Load(scoringPath)
	if err != nil {
		log.Printf("Scoring config load failed, using defaults: %v", err)
		scoringCfg = config.DefaultScoringConfig()
	} else {
		log.Printf("Scoring config loaded from %s", scoringPath)
	}
	fpScoring := config.ToFingerprintScoringConfig(scoringCfg)
	fingerprint.SetScoringConfig(&fpScoring)

	cfg := server.DefaultConfig()
	cfg.ClassifierCfg = config.ToClassifierConfig(scoringCfg)
	if scoringCfg.BehavioralEdges != nil {
		cfg.BehavioralEdges = &classifier.BehavioralEdges{
			RequestRatePerMinAbove:      scoringCfg.BehavioralEdges.RequestRatePerMinAbove,
			InterArrivalMedianSecBelow:  scoringCfg.BehavioralEdges.InterArrivalMedianSecBelow,
			InterArrivalStdPerMeanAbove: scoringCfg.BehavioralEdges.InterArrivalStdPerMeanAbove,
			MeanMedianRatioAbove:        scoringCfg.BehavioralEdges.InterArrivalMeanMedianRatioAbove,
		}
	}
	if len(scoringCfg.BotScores) > 0 {
		cfg.BotScores = scoringCfg.BotScores
	}
	// Default TTL for challenge nonce store from main config (challenge_ttl_sec)
	if scoringCfg.ChallengeTTLSec > 0 {
		cfg.ChallengeTTL = time.Duration(scoringCfg.ChallengeTTLSec) * time.Second
	} else {
		cfg.ChallengeTTL = 120 * time.Second
	}

	// Port overrides from environment
	if port := os.Getenv("PORT"); port != "" {
		cfg.Addr = ":" + port
	}
	if tlsPort := os.Getenv("TLS_PORT"); tlsPort != "" {
		cfg.TLSAddr = ":" + tlsPort
	}

	// Enable debug endpoint in development
	if os.Getenv("DEBUG") == "true" {
		cfg.EnableDebug = true
	}

	// TLS configuration from environment
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	if tlsCert != "" && tlsKey != "" {
		cfg.TLSEnabled = true
		cfg.TLSCertFile = tlsCert
		cfg.TLSKeyFile = tlsKey
	}

	// PROXY protocol on TLS listener (for nginx stream with proxy_protocol on → real client IP in logs)
	if v := os.Getenv("PROXY_PROTOCOL"); v == "1" || v == "true" {
		cfg.ProxyProtocol = true
	}

	// Client Hints challenge (Appendix K): disable or set TTL via env
	if v := os.Getenv("CHALLENGE_ENABLED"); v == "0" || v == "false" {
		cfg.ChallengeEnabled = false
	}
	if s := os.Getenv("CHALLENGE_TTL_SEC"); s != "" {
		if sec, err := strconv.Atoi(s); err == nil && sec > 0 {
			cfg.ChallengeTTL = time.Duration(sec) * time.Second
		}
	}

	// Redis: when REDIS_URL is set, challenge store and metrics use Redis (see METHODOLOGY.md Appendix L).
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			log.Fatalf("Invalid REDIS_URL: %v", err)
		}
		cfg.Redis = &server.RedisConfig{
			Client:           redis.NewClient(opts),
			ChallengePrefix:  envOrDefault("REDIS_CHALLENGE_PREFIX", "ch"),
			MetricsPrefix:    envOrDefault("REDIS_METRICS_PREFIX", "metrics"),
			MetricsTTLSec:    envIntOrDefault("REDIS_METRICS_TTL_SEC", 86400),
			MetricsWindowSec: envIntOrDefault("REDIS_METRICS_WINDOW_SEC", 300),
		}
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envIntOrDefault(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}

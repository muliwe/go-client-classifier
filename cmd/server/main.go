package main

import (
	"log"
	"os"
	"strconv"
	"time"

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

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

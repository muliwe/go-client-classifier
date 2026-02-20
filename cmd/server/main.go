package main

import (
	"log"
	"os"

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

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

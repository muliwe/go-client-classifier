package main

import (
	"log"
	"os"

	"github.com/muliwe/go-client-classifier/internal/server"
)

func main() {
	cfg := server.DefaultConfig()

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

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

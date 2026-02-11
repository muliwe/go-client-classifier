package main

import (
	"log"
	"os"

	"github.com/muliwe/go-client-slassifier/internal/server"
)

func main() {
	cfg := server.DefaultConfig()

	// Allow port override from environment
	if port := os.Getenv("PORT"); port != "" {
		cfg.Addr = ":" + port
	}

	// Enable debug endpoint in development
	if os.Getenv("DEBUG") == "true" {
		cfg.EnableDebug = true
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// Response represents the classification result
type Response struct {
	Classification string    `json:"classification"`
	Message        string    `json:"message"`
	Timestamp      time.Time `json:"timestamp"`
	Version        string    `json:"version"`
}

func main() {
	// Simple sanity check handler
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/health", handleHealth)

	addr := ":8080"
	log.Printf("🚀 Bot Detector Server starting on %s", addr)
	log.Printf("📊 Sanity check mode - basic classification")
	log.Printf("🔗 Test with: curl http://localhost:8080/")
	
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	// Basic sanity check: detect if request looks like curl
	classification := "browser"
	message := "You appear to be using a browser"

	userAgent := r.Header.Get("User-Agent")
	
	// Simple heuristic for sanity check
	if containsAny(userAgent, []string{"curl", "wget", "python", "go-http-client"}) {
		classification = "bot"
		message = "You appear to be using an automated client"
	}

	// Log request info
	log.Printf("[%s] %s %s - UA: %s - Classification: %s", 
		r.RemoteAddr, r.Method, r.URL.Path, userAgent, classification)

	// Send JSON response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Classification: classification,
		Message:        message,
		Timestamp:      time.Now(),
		Version:        "0.1.0-sanity",
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"version": "0.1.0-sanity",
	})
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}

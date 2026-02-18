package server

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/logger"
)

// ClientIP returns the client IP for logging. When the request is from a trusted proxy (localhost
// or X-Internal-Proxy: 1, e.g. nginx http→http or TLS termination→http), it uses X-Real-IP or the
// first (leftmost) IP in X-Forwarded-For; otherwise r.RemoteAddr.
func ClientIP(r *http.Request) string {
	trustProxy := r.Header.Get("X-Internal-Proxy") == "1"
	if !trustProxy {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		if host != "127.0.0.1" && host != "::1" {
			return r.RemoteAddr
		}
	}
	if s := strings.TrimSpace(r.Header.Get("X-Real-IP")); s != "" {
		return s
	}
	if s := r.Header.Get("X-Forwarded-For"); s != "" {
		if i := strings.Index(s, ","); i >= 0 {
			s = s[:i]
		}
		return strings.TrimSpace(s)
	}
	return r.RemoteAddr
}

const version = "0.7.0"

// Response represents the API response
type Response struct {
	Classification string    `json:"classification"`
	Confidence     string    `json:"confidence"` // e.g. "0.95" — string to avoid float instability in JSON
	Message        string    `json:"message"`
	RequestID      string    `json:"request_id"`
	Timestamp      time.Time `json:"timestamp"`
	Version        string    `json:"version"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// Handler holds dependencies for HTTP handlers
type Handler struct {
	collector  *fingerprint.Collector
	classifier *classifier.Classifier
	logger     *logger.Logger
	quiet      bool // suppress console logging (useful for tests)
}

// NewHandler creates a new handler with dependencies
func NewHandler(c *fingerprint.Collector, cl *classifier.Classifier, l *logger.Logger) *Handler {
	return &Handler{
		collector:  c,
		classifier: cl,
		logger:     l,
		quiet:      false,
	}
}

// SetQuiet enables or disables console logging
func (h *Handler) SetQuiet(quiet bool) {
	h.quiet = quiet
}

// formatConfidence returns confidence as a string with n decimal places for the API (avoids float instability in JSON).
func formatConfidence(c float64, decimals int) string {
	if decimals <= 0 {
		return fmt.Sprintf("%.0f", math.Round(c))
	}
	pow := math.Pow(10, float64(decimals))
	rounded := math.Round(c*pow) / pow
	return fmt.Sprintf("%.*f", decimals, rounded)
}

// HandleClassify handles the main classification endpoint.
// Classification and logging are done for every request; only GET / returns 200 JSON, other paths return 404.
func (h *Handler) HandleClassify(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Collect fingerprint and classify regardless of path
	fp := h.collector.Collect(r)
	result := h.classifier.Classify(fp)
	responseTime := time.Since(startTime).Milliseconds()

	addr := ClientIP(r)
	// Always log to JSONL and console
	if h.logger != nil {
		if err := h.logger.LogResult(result, addr, responseTime); err != nil {
			log.Printf("Error logging result: %v", err)
		}
	}
	if !h.quiet {
		log.Printf("[%s] %s %s - UA: %s - %s (%.2f) - %dms",
			addr,
			r.Method,
			r.URL.Path,
			fp.HTTP.UserAgent,
			result.Classification,
			result.Confidence,
			responseTime,
		)
	}

	// Only exact root path gets 200 JSON; everything else gets 404
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	message := "You appear to be using a browser"
	if result.Classification == classifier.ClassificationBot {
		message = "You appear to be using an automated client"
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(Response{
		Classification: result.Classification,
		Confidence:     formatConfidence(result.Confidence, 2),
		Message:        message,
		RequestID:      result.RequestID,
		Timestamp:      result.Timestamp,
		Version:        version,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// HandleHealth handles the health check endpoint
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(HealthResponse{
		Status:  "ok",
		Version: version,
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

// HandleDebug returns detailed fingerprint for debugging (optional endpoint)
func (h *Handler) HandleDebug(w http.ResponseWriter, r *http.Request) {
	fp := h.collector.Collect(r)
	result := h.classifier.Classify(fp)

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		log.Printf("Error encoding debug response: %v", err)
	}
}

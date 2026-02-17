package server

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/logger"
)

const version = "0.6.0"

// Response represents the API response
type Response struct {
	Classification string    `json:"classification"`
	Confidence     float64   `json:"confidence"`
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

// HandleClassify handles the main classification endpoint.
// Classification and logging are done for every request; only GET / returns 200 JSON, other paths return 404.
func (h *Handler) HandleClassify(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Collect fingerprint and classify regardless of path
	fp := h.collector.Collect(r)
	result := h.classifier.Classify(fp)
	responseTime := time.Since(startTime).Milliseconds()

	// Always log to JSONL and console
	if h.logger != nil {
		if err := h.logger.LogResult(result, r.RemoteAddr, responseTime); err != nil {
			log.Printf("Error logging result: %v", err)
		}
	}
	if !h.quiet {
		log.Printf("[%s] %s %s - UA: %s - %s (%.2f) - %dms",
			r.RemoteAddr,
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
		Confidence:     result.Confidence,
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

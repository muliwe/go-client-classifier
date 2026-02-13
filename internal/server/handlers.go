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

const version = "0.4.0"

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

// HandleClassify handles the main classification endpoint
func (h *Handler) HandleClassify(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Only handle exact root path
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Collect fingerprint
	fp := h.collector.Collect(r)

	// Classify request
	result := h.classifier.Classify(fp)

	// Calculate response time
	responseTime := time.Since(startTime).Milliseconds()

	// Log the result
	if h.logger != nil {
		if err := h.logger.LogResult(result, r.RemoteAddr, responseTime); err != nil {
			log.Printf("Error logging result: %v", err)
		}
	}

	// Generate message based on classification
	message := "You appear to be using a browser"
	if result.Classification == classifier.ClassificationBot {
		message = "You appear to be using an automated client"
	}

	// Log to console (unless quiet mode)
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

	// Send response
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

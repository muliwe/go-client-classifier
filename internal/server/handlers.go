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

// Client Hints behavioral challenge (Appendix K): cookie and header constants
const (
	challengeCookieName = "__ch_nonce"
	challengeAcceptCH   = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version"
	challengeCriticalCH = "Sec-CH-UA-Full-Version-List"
	challengeVary       = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version"
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

const version = "0.10.0"

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
	collector      *fingerprint.Collector
	classifier     *classifier.Classifier
	logger         *logger.Logger
	challengeStore *ChallengeStore // nil = Client Hints challenge disabled
	quiet          bool            // suppress console logging (useful for tests)
}

// NewHandler creates a new handler with dependencies
func NewHandler(c *fingerprint.Collector, cl *classifier.Classifier, l *logger.Logger, challengeStore *ChallengeStore) *Handler {
	return &Handler{
		collector:      c,
		classifier:     cl,
		logger:         l,
		challengeStore: challengeStore,
		quiet:          false,
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
// When the Client Hints challenge is enabled, response may include Accept-CH, Critical-CH, Vary, and Set-Cookie (Appendix K).
func (h *Handler) HandleClassify(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Collect fingerprint and classify regardless of path
	fp := h.collector.Collect(r)
	result := h.classifier.Classify(fp)

	// Client Hints behavioral challenge (Appendix K): only for root path and when store is configured
	if r.URL.Path == "/" && h.challengeStore != nil {
		nonce, nonceOK := fingerprint.JA4HPartsCD(fp.HTTP.JA4HHash)
		if nonceOK && !fingerprint.IsJA4HNonceEmpty(nonce) {
			cookieNonce := getChallengeCookie(r)
			currentUA := r.Header.Get("User-Agent")

			if cookieNonce != "" {
				// Second request: cookie present — check store, UA, hints, and that Full-Version-List matches stored UA version
				if storedUA, found := h.challengeStore.Get(cookieNonce); found {
					fullList := r.Header.Get("Sec-CH-UA-Full-Version-List")
					hasHints := fullList != "" && r.Header.Get("Sec-CH-UA-Platform-Version") != ""
					versionMatch := fullVersionListMatchesUA(storedUA, fullList)
					passed := currentUA == storedUA && hasHints && versionMatch
					h.classifier.ApplyChallengeSignal(&result, passed, true)
				}
			} else {
				// No cookie in request
				if _, found := h.challengeStore.Get(nonce); found {
					// Nonce already in store: client should have sent cookie — challenge failed
					h.classifier.ApplyChallengeSignal(&result, false, true)
				} else {
					// First request with this nonce: store and send challenge headers
					h.challengeStore.Set(nonce, currentUA)
					w.Header().Set("Accept-CH", challengeAcceptCH)
					w.Header().Set("Critical-CH", challengeCriticalCH)
					w.Header().Set("Vary", challengeVary)
					w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=30; Secure; HttpOnly; SameSite=Lax", challengeCookieName, nonce))
				}
			}
		}
	}

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

// getChallengeCookie returns the value of the __ch_nonce cookie if present.
func getChallengeCookie(r *http.Request) string {
	for _, c := range r.Cookies() {
		if c.Name == challengeCookieName {
			return c.Value
		}
	}
	return ""
}

// chromeVersionFromUA extracts the browser version from a User-Agent string (Chrome, Chromium, or Edg).
// Returns the version substring (e.g. "120.0.0.0") or empty if not found.
func chromeVersionFromUA(ua string) string {
	for _, prefix := range []string{"Chrome/", "Chromium/", "Edg/"} {
		if i := strings.Index(ua, prefix); i >= 0 {
			ver := ua[i+len(prefix):]
			if end := strings.IndexAny(ver, " \t"); end >= 0 {
				ver = ver[:end]
			}
			return ver
		}
	}
	return ""
}

// fullVersionListMatchesUA checks that Sec-CH-UA-Full-Version-List contains the same version as in the stored User-Agent.
// Header format: "Chromium";v="120.0.6099.109", "Google Chrome";v="120.0.6099.109". We require v="<versionFromUA>" to appear.
func fullVersionListMatchesUA(storedUA, fullVersionListHeader string) bool {
	ver := chromeVersionFromUA(storedUA)
	if ver == "" {
		return true // non-Chrome UA: do not require version match
	}
	return strings.Contains(fullVersionListHeader, `v="`+ver+`"`)
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

// DebugResponse is the /debug payload: summary first, then full result for details
type DebugResponse struct {
	Classification string  `json:"classification"`
	Score          int     `json:"score"`  // weighted net (browser - 4*bot)
	Reason         string  `json:"reason"` // text summary
	Confidence     float64 `json:"confidence"`
	RequestID      string  `json:"request_id"`
	Timestamp      string  `json:"timestamp"`
	Fingerprint    any     `json:"fingerprint,omitempty"`
	Signals        any     `json:"signals,omitempty"`
}

// HandleDebug returns detailed fingerprint for debugging (optional endpoint).
// Top-level fields (classification, score, reason) give the outcome without a second request to /.
func (h *Handler) HandleDebug(w http.ResponseWriter, r *http.Request) {
	fp := h.collector.Collect(r)
	result := h.classifier.Classify(fp)

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	payload := DebugResponse{
		Classification: result.Classification,
		Score:          result.Score,
		Reason:         result.Reason,
		Confidence:     result.Confidence,
		RequestID:      result.RequestID,
		Timestamp:      result.Timestamp.UTC().Format(time.RFC3339Nano),
		Fingerprint:    result.Fingerprint,
		Signals:        result.Signals,
	}
	if err := encoder.Encode(payload); err != nil {
		log.Printf("Error encoding debug response: %v", err)
	}
}

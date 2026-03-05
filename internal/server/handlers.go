package server

import (
	"context"
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
	"github.com/muliwe/go-client-classifier/internal/metrics"
)

// Client Hints behavioral challenge (Appendix K): cookie and header constants
const (
	challengeCookieName = "__ch_nonce"
	challengeAcceptCH   = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version"
	challengeCriticalCH = "Sec-CH-UA-Full-Version-List"
	challengeVary       = "Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version"
)

// ClientIP returns the client IP (host only, no port) for logging and metrics. When the request is
// from a trusted proxy (localhost or X-Internal-Proxy: 1, e.g. nginx http→http or TLS termination→http),
// it uses X-Real-IP or the first (leftmost) IP in X-Forwarded-For; otherwise the host part of r.RemoteAddr.
// The result is always normalized: if the value is "host:port", the port is stripped so logs and request_metrics show the IP only.
func ClientIP(r *http.Request) string {
	var addr string
	trustProxy := r.Header.Get("X-Internal-Proxy") == "1"
	if !trustProxy {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			addr = r.RemoteAddr
			return stripHostPort(addr)
		}
		if host != "127.0.0.1" && host != "::1" {
			return host
		}
		addr = r.RemoteAddr
	}
	if s := strings.TrimSpace(r.Header.Get("X-Real-IP")); s != "" {
		return stripHostPort(s)
	}
	if s := r.Header.Get("X-Forwarded-For"); s != "" {
		if i := strings.Index(s, ","); i >= 0 {
			s = s[:i]
		}
		return stripHostPort(strings.TrimSpace(s))
	}
	if addr == "" {
		addr = r.RemoteAddr
	}
	return stripHostPort(addr)
}

// stripHostPort returns the host part of hostport; if hostport is not "host:port", returns hostport unchanged.
func stripHostPort(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

const version = "1.4.0"

// Response represents the API response
type Response struct {
	Classification string    `json:"classification"`
	Confidence     string    `json:"confidence"` // e.g. "0.95" — string to avoid float instability in JSON
	Message        string    `json:"message"`
	RequestID      string    `json:"request_id"`
	Timestamp      time.Time `json:"timestamp"`
	Version        string    `json:"version"`
}

// HealthResponse represents the health check response.
// When Redis is configured, RedisStatus is set to "ok" or "unavailable" (startup does not fail if Redis is down).
type HealthResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	RedisStatus string `json:"redis,omitempty"` // present only when Redis is configured
}

// Handler holds dependencies for HTTP handlers
type Handler struct {
	collector                *fingerprint.Collector
	classifier               *classifier.Classifier
	logger                   *logger.Logger
	challengeStore           ChallengeStore     // nil = Client Hints challenge disabled (in-memory or Redis when REDIS_URL set)
	redisClient              RedisPinger        // optional; for /health Redis PING when configured
	metricsCollector         *metrics.Collector // optional; when Redis configured, records behavioral metrics (Appendix L)
	challengeCookieMaxAgeSec int                // Max-Age for __ch_nonce cookie; synced with challenge TTL and nonce metrics window (Appendix L)
	behavioralEdges          *classifier.BehavioralEdges
	botScores                map[string]int
	quiet                    bool
}

// RedisPinger is used for optional Redis connectivity check in /health. Implemented by the server when Redis is configured.
type RedisPinger interface {
	Ping(ctx context.Context) error
}

// HandlerOptions configures Handler dependencies. Only Collector and Classifier are required; the rest are optional (nil/zero).
type HandlerOptions struct {
	Collector                *fingerprint.Collector
	Classifier               *classifier.Classifier
	Logger                   *logger.Logger
	ChallengeStore           ChallengeStore
	RedisPinger              RedisPinger
	MetricsCollector         *metrics.Collector
	ChallengeCookieMaxAgeSec int                         // Max-Age (seconds) for __ch_nonce cookie; should match ChallengeTTL. If <= 0, 120 is used when setting the cookie.
	BehavioralEdges          *classifier.BehavioralEdges // optional; when set with BotScores, ApplyBehavioralSignals is used (Appendix M)
	BotScores                map[string]int
}

// NewHandler creates a new handler from options. Collector and Classifier must be set; other fields may be nil/zero.
func NewHandler(opts HandlerOptions) *Handler {
	return &Handler{
		collector:                opts.Collector,
		classifier:               opts.Classifier,
		logger:                   opts.Logger,
		challengeStore:           opts.ChallengeStore,
		redisClient:              opts.RedisPinger,
		metricsCollector:         opts.MetricsCollector,
		challengeCookieMaxAgeSec: opts.ChallengeCookieMaxAgeSec,
		behavioralEdges:          opts.BehavioralEdges,
		botScores:                opts.BotScores,
		quiet:                    false,
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

// recordAndLogRequest records the request in metrics, writes full payload to JSONL (parity with /debug), and logs one line to console.
// If requestMetrics is non-nil it is used (e.g. from HandleClassify after ApplyBehavioralSignals); otherwise builds when metricsCollector is set. Appendix J (log), Appendix L (metrics).
func (h *Handler) recordAndLogRequest(r *http.Request, result fingerprint.ClassificationResult, addr string, responseTime int64, userAgent string, ja4hHash string, requestMetrics *metrics.RequestMetrics) (*metrics.RequestMetrics, *ChallengeState) {
	if h.metricsCollector != nil && requestMetrics == nil {
		requestMetrics = h.buildRequestMetrics(r)
	}
	challengeState := h.buildChallengeState(ja4hHash)
	if h.logger != nil {
		if err := h.logger.LogResult(result, addr, responseTime, challengeState, requestMetrics); err != nil {
			log.Printf("Error logging result: %v", err)
		}
	}
	if !h.quiet {
		log.Printf("[%s] %s %s - UA: %s - %s (%.2f) - %dms",
			addr, r.Method, r.URL.Path, userAgent, result.Classification, result.Confidence, responseTime)
	}
	return requestMetrics, challengeState
}

// HandleClassify handles the main classification endpoint.
// Classification and logging are done for every request; only GET / returns 200 JSON, other paths return 404.
// When the Client Hints challenge is enabled, response may include Accept-CH, Critical-CH, Vary, and Set-Cookie (Appendix K).
// When Redis and behavioral edges are configured, request_metrics are applied (Appendix M) before the challenge.
func (h *Handler) HandleClassify(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	fp := h.collector.Collect(r)
	result := h.classifier.Classify(fp)

	var requestMetrics *metrics.RequestMetrics
	if h.metricsCollector != nil {
		addr := ClientIP(r)
		nonce := getChallengeCookie(r)
		h.metricsCollector.RecordRequest(addr, nonce)
		requestMetrics = h.buildRequestMetrics(r)
		if requestMetrics != nil && h.behavioralEdges != nil && len(h.botScores) > 0 {
			h.classifier.ApplyBehavioralSignals(&result, requestMetrics, *h.behavioralEdges, h.botScores)
		}
	}

	h.applyChallenge(w, r, "/", fp.HTTP.JA4HHash, &result)
	result.Confidence = h.classifier.ConfidenceFromSignals(result.Signals, result.Score)

	responseTime := time.Since(startTime).Milliseconds()
	addr := ClientIP(r)
	h.recordAndLogRequest(r, result, addr, responseTime, fp.HTTP.UserAgent, fp.HTTP.JA4HHash, requestMetrics)

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

// applyChallenge runs the Client Hints challenge (Appendix K) for the given path when the store is configured.
// Path must be "/" or "/debug". Mutates result (ApplyChallengeSignal) and may set Accept-CH, Critical-CH, Vary, Set-Cookie on w.
func (h *Handler) applyChallenge(w http.ResponseWriter, r *http.Request, path, ja4hHash string, result *fingerprint.ClassificationResult) {
	if r.URL.Path != path || h.challengeStore == nil {
		return
	}
	nonce, nonceOK := fingerprint.JA4HPartsCD(ja4hHash)
	if !nonceOK || fingerprint.IsJA4HNonceEmpty(nonce) {
		return
	}
	cookieNonce := getChallengeCookie(r)
	currentUA := r.Header.Get("User-Agent")

	if cookieNonce != "" {
		// Second request: cookie present — check store, UA, hints, and that Full-Version-List matches stored UA version
		if storedUA, found := h.challengeStore.Get(cookieNonce); found {
			fullList := r.Header.Get("Sec-CH-UA-Full-Version-List")
			hasHints := fullList != "" && r.Header.Get("Sec-CH-UA-Platform-Version") != ""
			versionMatch := fullVersionListMatchesUA(storedUA, fullList)
			passed := currentUA == storedUA && hasHints && versionMatch
			h.classifier.ApplyChallengeSignal(result, passed, true)
		}
	} else {
		// No cookie in request
		maxAge := h.challengeCookieMaxAgeSec
		if maxAge <= 0 {
			maxAge = 120
		}
		if storedUA, found := h.challengeStore.Get(nonce); found {
			// Nonce already in store: if same UA, treat as same client that lost the cookie — do not fail; re-issue cookie
			if currentUA == storedUA {
				h.challengeStore.Set(nonce, currentUA) // refresh TTL
				w.Header().Set("Accept-CH", challengeAcceptCH)
				w.Header().Set("Critical-CH", challengeCriticalCH)
				w.Header().Set("Vary", challengeVary)
				w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Secure; HttpOnly; SameSite=Lax", challengeCookieName, nonce, maxAge))
				// Do not apply challenge signal: same client, cookie was lost (e.g. new tab, refresh)
			} else {
				// Different UA with same nonce — different client, challenge failed
				h.classifier.ApplyChallengeSignal(result, false, true)
			}
		} else {
			// First request with this nonce: store and send challenge headers
			h.challengeStore.Set(nonce, currentUA)
			w.Header().Set("Accept-CH", challengeAcceptCH)
			w.Header().Set("Critical-CH", challengeCriticalCH)
			w.Header().Set("Vary", challengeVary)
			w.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s; Max-Age=%d; Secure; HttpOnly; SameSite=Lax", challengeCookieName, nonce, maxAge))
		}
	}
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
// Header format: "Chromium";v="120.0.6099.109", "Google Chrome";v="120.0.6099.109".
// We accept exact match (v="<versionFromUA>") or, when UA has simplified major (e.g. 145.0.0.0), any full version with same major (e.g. v="145.0.7632.75").
func fullVersionListMatchesUA(storedUA, fullVersionListHeader string) bool {
	ver := chromeVersionFromUA(storedUA)
	if ver == "" {
		return true // non-Chrome UA: do not require version match
	}
	if strings.Contains(fullVersionListHeader, `v="`+ver+`"`) {
		return true
	}
	// Real Chrome often sends UA with major.0.0.0 and hint with full build (e.g. 145.0.7632.75)
	if strings.HasSuffix(ver, ".0.0.0") {
		major := ver[:len(ver)-len(".0.0.0")]
		return strings.Contains(fullVersionListHeader, `v="`+major+`.`)
	}
	return false
}

// HandleHealth handles the health check endpoint. When Redis is configured, reports Redis connectivity (PING).
func (h *Handler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{Status: "ok", Version: version}
	if h.redisClient != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := h.redisClient.Ping(ctx); err != nil {
			resp.RedisStatus = "unavailable"
		} else {
			resp.RedisStatus = "ok"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

// DebugResponse is the /debug payload: summary first, then full result for details
type DebugResponse struct {
	Classification string                  `json:"classification"`
	Score          int                     `json:"score"`  // weighted net (browser - 4*bot)
	Reason         string                  `json:"reason"` // text summary
	Confidence     float64                 `json:"confidence"`
	RequestID      string                  `json:"request_id"`
	Timestamp      string                  `json:"timestamp"`
	Fingerprint    any                     `json:"fingerprint,omitempty"`
	Signals        any                     `json:"signals,omitempty"`
	ChallengeState *ChallengeState         `json:"challenge_state,omitempty"` // Client Hints challenge: nonce (C_D), store state
	RequestMetrics *metrics.RequestMetrics `json:"request_metrics,omitempty"` // behavioral metrics for this request (IP + __ch_nonce); Appendix L
}

// ChallengeState is the Client Hints challenge store state for this request: nonce (C_D), in_store, stored UA, created_at.
type ChallengeState struct {
	JA4HHash   string `json:"ja4h_hash,omitempty"` // full JA4H from request (or X-FP-JA4H)
	NonceCD    string `json:"nonce_c_d,omitempty"` // C_D (nonce) extracted from JA4H
	EmptyNonce bool   `json:"empty_nonce"`         // true when C/D are zeros (no cookies) — challenge skipped
	InStore    bool   `json:"in_store"`            // nonce is in the challenge store (and not expired)
	StoredUA   string `json:"stored_ua,omitempty"` // User-Agent stored for this nonce (if in_store)
	StoredAt   string `json:"stored_at,omitempty"` // when the nonce was stored (RFC3339)
	Expired    bool   `json:"expired"`             // entry exists but TTL exceeded (will be removed on next Get)
	Enabled    bool   `json:"enabled"`             // challenge store is configured (enabled)
}

// HandleDebug returns detailed fingerprint for debugging (optional endpoint).
// Same collect/classify/challenge/log path as HandleClassify; only the response body differs (full debug JSON).
// When Redis metrics are configured, request_metrics contains sliding-window counts and request history (Appendix L).
// The current request is recorded before building request_metrics so /debug traffic accumulates in the window.
func (h *Handler) HandleDebug(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	fp := h.collector.Collect(r)
	result := h.classifier.Classify(fp)

	h.applyChallenge(w, r, "/debug", fp.HTTP.JA4HHash, &result)
	result.Confidence = h.classifier.ConfidenceFromSignals(result.Signals, result.Score)

	responseTime := time.Since(startTime).Milliseconds()
	addr := ClientIP(r)
	var requestMetrics *metrics.RequestMetrics
	if h.metricsCollector != nil {
		h.metricsCollector.RecordRequest(addr, getChallengeCookie(r))
		requestMetrics = h.buildRequestMetrics(r)
		if requestMetrics != nil && h.behavioralEdges != nil && len(h.botScores) > 0 {
			h.classifier.ApplyBehavioralSignals(&result, requestMetrics, *h.behavioralEdges, h.botScores)
		}
	}
	result.Confidence = h.classifier.ConfidenceFromSignals(result.Signals, result.Score)
	requestMetrics, challengeState := h.recordAndLogRequest(r, result, addr, responseTime, fp.HTTP.UserAgent, fp.HTTP.JA4HHash, requestMetrics)

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
		ChallengeState: challengeState,
		RequestMetrics: requestMetrics,
	}
	if err := encoder.Encode(payload); err != nil {
		log.Printf("Error encoding debug response: %v", err)
	}
}

// buildChallengeState returns challenge store state for the given JA4H hash (for /debug and JSONL).
func (h *Handler) buildChallengeState(ja4hHash string) *ChallengeState {
	out := &ChallengeState{Enabled: h.challengeStore != nil}
	if ja4hHash != "" {
		out.JA4HHash = ja4hHash
	}
	if h.challengeStore == nil {
		return out
	}
	nonce, ok := fingerprint.JA4HPartsCD(ja4hHash)
	if !ok {
		return out
	}
	out.NonceCD = nonce
	out.EmptyNonce = fingerprint.IsJA4HNonceEmpty(nonce)
	if out.EmptyNonce {
		return out
	}
	storedUA, inStore, createdAt, expired := h.challengeStore.GetDebug(nonce)
	out.InStore = inStore && !expired
	out.StoredUA = storedUA
	if !createdAt.IsZero() {
		out.StoredAt = createdAt.UTC().Format(time.RFC3339)
	}
	out.Expired = expired
	return out
}

// buildRequestMetrics returns sliding-window request counts for this request's IP and __ch_nonce (Appendix L).
// Returns nil if metrics collector is not configured or Redis is unavailable.
func (h *Handler) buildRequestMetrics(r *http.Request) *metrics.RequestMetrics {
	if h.metricsCollector == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	ip := ClientIP(r)
	nonce := getChallengeCookie(r)
	m, err := h.metricsCollector.GetRequestMetrics(ctx, ip, nonce)
	if err != nil {
		log.Printf("debug: request_metrics: %v", err)
		return nil
	}
	return m
}

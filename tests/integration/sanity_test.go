package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/server"
)

// Response matches the server response structure
type Response struct {
	Classification string `json:"classification"`
	Confidence     string `json:"confidence"` // e.g. "0.95" — string for stability
	Message        string `json:"message"`
	RequestID      string `json:"request_id"`
}

// HealthResponse matches the health endpoint response
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// createTestHandler creates a handler for testing without file logging
func createTestHandler() *server.Handler {
	return createTestHandlerWithLogging(false)
}

// createTestHandlerWithLogging creates a handler with optional console logging
func createTestHandlerWithLogging(enableConsoleLog bool) *server.Handler {
	collector := fingerprint.NewCollector()
	clf := classifier.New(classifier.DefaultConfig())
	handler := server.NewHandler(collector, clf, nil, nil) // nil file logger
	if !enableConsoleLog {
		handler.SetQuiet(true)
	}
	return handler
}

// createTestHandlerWithChallenge creates a handler with the Client Hints challenge store enabled (TTL 2m for tests).
func createTestHandlerWithChallenge() *server.Handler {
	collector := fingerprint.NewCollector()
	clf := classifier.New(classifier.DefaultConfig())
	store := server.NewChallengeStore(2 * time.Minute)
	handler := server.NewHandler(collector, clf, nil, store)
	handler.SetQuiet(true)
	return handler
}

func TestClassify_CurlDetection(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/8.0.1")

	w := httptest.NewRecorder()
	handler.HandleClassify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Classification != "bot" {
		t.Errorf("Expected 'bot' for curl, got '%s'", resp.Classification)
	}

	if resp.RequestID == "" {
		t.Error("Expected request_id to be set")
	}
}

func TestClassify_BrowserDetection(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-CH-UA", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
	// Cookie present so JA4H C/D are non-zero; avoids ja4h-no-cookies(+3) (smoking-gun for browser UA + no cookies).
	req.Header.Set("Cookie", "session=test")

	w := httptest.NewRecorder()
	handler.HandleClassify(w, req)

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Classification != "browser" {
		t.Errorf("Expected 'browser' for Chrome, got '%s'", resp.Classification)
	}
}

func TestClassify_PythonRequestsDetection(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "python-requests/2.31.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")

	w := httptest.NewRecorder()
	handler.HandleClassify(w, req)

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Classification != "bot" {
		t.Errorf("Expected 'bot' for python-requests, got '%s'", resp.Classification)
	}
}

func TestClassify_GoHTTPClientDetection(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Go-http-client/1.1")

	w := httptest.NewRecorder()
	handler.HandleClassify(w, req)

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Classification != "bot" {
		t.Errorf("Expected 'bot' for Go-http-client, got '%s'", resp.Classification)
	}
}

func TestClassify_NoUserAgent(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	// No User-Agent header

	w := httptest.NewRecorder()
	handler.HandleClassify(w, req)

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Should be classified as bot due to missing headers
	if resp.Classification != "bot" {
		t.Errorf("Expected 'bot' for request with no User-Agent, got '%s'", resp.Classification)
	}
}

func TestClassify_NotFoundForOtherPaths(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/nonexistent", nil)

	w := httptest.NewRecorder()
	handler.HandleClassify(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for /nonexistent, got %d", w.Code)
	}
}

func TestHealthEndpoint(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/health", nil)

	w := httptest.NewRecorder()
	handler.HandleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", resp.Status)
	}

	if resp.Version == "" {
		t.Error("Expected version to be set")
	}
}

func TestDebugEndpoint(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/debug", nil)
	req.Header.Set("User-Agent", "curl/8.0.1")

	w := httptest.NewRecorder()
	handler.HandleDebug(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result fingerprint.ClassificationResult
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode debug response: %v", err)
	}

	if result.Classification == "" {
		t.Error("Expected classification in debug response")
	}

	if result.Fingerprint.HTTP.UserAgent != "curl/8.0.1" {
		t.Errorf("Expected User-Agent 'curl/8.0.1', got '%s'", result.Fingerprint.HTTP.UserAgent)
	}
}

// Unit tests for fingerprint package
func TestExtractSignals_BotPatterns(t *testing.T) {
	testCases := []struct {
		name      string
		userAgent string
		expectBot bool
	}{
		{"curl", "curl/8.0.1", true},
		{"wget", "Wget/1.21", true},
		{"python", "python-requests/2.31.0", true},
		{"httpie", "HTTPie/3.2.1", true},
		{"go-http-client", "Go-http-client/1.1", true},
		{"chrome", "Mozilla/5.0 Chrome/120.0.0.0", false},
		{"firefox", "Mozilla/5.0 Firefox/121.0", false},
	}

	collector := fingerprint.NewCollector()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tc.userAgent)

			fp := collector.Collect(req)
			signals := fingerprint.ExtractSignals(fp)

			if signals.UserAgentIsBot != tc.expectBot {
				t.Errorf("Expected UserAgentIsBot=%v for %s, got %v", tc.expectBot, tc.userAgent, signals.UserAgentIsBot)
			}
		})
	}
}

func TestClassifier_ScoreCalculation(t *testing.T) {
	clf := classifier.New(classifier.DefaultConfig())

	// Browser-like fingerprint with TLS from proxy, GREASE, no bot signals → positive weighted net
	browserFp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available:  true,
			FromProxy:  true,
			Version:    "TLS 1.3",
			SSLGreased: "1",
			JA3Hash:    "d476cd86acfd7e8c059537eb357d1135", // not in knownLibraryJA3
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
			AcceptLang:    "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6",
			AcceptEnc:     "gzip, deflate, br",
			SecFetchSite:  "none",
			SecFetchMode:  "navigate",
			SecFetchDest:  "document",
			SecChUA:       `"Chromium";v="120"`,
			HeaderCount:   14,
			JA4HHash:      "ge11nn14enus_abc_000_000",
			H2Fingerprint: "1:65536;4:6291456;2:0|1|1:1:0:256|m,a,s,p",
			H2Parsed:      fingerprint.ParseH2Fingerprint("1:65536;4:6291456;2:0|1|1:1:0:256|m,a,s,p"),
		},
	}
	browserResult := clf.Classify(browserFp)
	if browserResult.Score <= 0 {
		t.Errorf("Expected positive score for browser-like fingerprint, got %d (browser=%d bot=%d)",
			browserResult.Score, browserResult.Signals.BrowserScore, browserResult.Signals.BotScore)
	}

	// Bot-like request should have negative weighted net
	collector := fingerprint.NewCollector()
	botReq := httptest.NewRequest("GET", "/", nil)
	botReq.Header.Set("User-Agent", "curl/8.0.1")
	botFp := collector.Collect(botReq)
	botResult := clf.Classify(botFp)
	if botResult.Score >= 0 {
		t.Errorf("Expected negative score for bot-like request, got %d", botResult.Score)
	}
}

// Test AI/LLM crawler detection
func TestExtractSignals_AICrawlerPatterns(t *testing.T) {
	testCases := []struct {
		name      string
		userAgent string
		expectBot bool
		expectAI  bool
	}{
		{"GPTBot", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)", true, true},
		{"ChatGPT-User", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ChatGPT-User/1.0; +https://openai.com/bot)", true, true},
		{"ClaudeBot", "Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", true, true},
		{"PerplexityBot", "Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)", true, true},
		{"Google-Extended", "Mozilla/5.0 (compatible; Google-Extended)", true, true},
		{"CCBot", "CCBot/2.0 (https://commoncrawl.org/faq/)", true, true},
		{"Bytespider", "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko; compatible; Bytespider)", true, true},
		{"Meta-ExternalAgent", "Mozilla/5.0 (compatible; Meta-ExternalAgent/1.0)", true, true},
		// Non-AI bots
		{"curl", "curl/8.0.1", true, false},
		{"Googlebot", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true, false},
		// Browsers
		{"Chrome", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0", false, false},
	}

	collector := fingerprint.NewCollector()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tc.userAgent)

			fp := collector.Collect(req)
			signals := fingerprint.ExtractSignals(fp)

			if signals.UserAgentIsBot != tc.expectBot {
				t.Errorf("Expected UserAgentIsBot=%v for %s, got %v", tc.expectBot, tc.name, signals.UserAgentIsBot)
			}

			if signals.UserAgentIsAICrawler != tc.expectAI {
				t.Errorf("Expected UserAgentIsAICrawler=%v for %s, got %v", tc.expectAI, tc.name, signals.UserAgentIsAICrawler)
			}
		})
	}
}

func TestClassify_AICrawlerDetection(t *testing.T) {
	handler := createTestHandler()

	testCases := []struct {
		name      string
		userAgent string
		expectBot bool
	}{
		{"GPTBot", "Mozilla/5.0 (compatible; GPTBot/1.0)", true},
		{"ClaudeBot", "ClaudeBot/1.0", true},
		{"PerplexityBot", "PerplexityBot/1.0", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.Header.Set("User-Agent", tc.userAgent)

			w := httptest.NewRecorder()
			handler.HandleClassify(w, req)

			var resp Response
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			expectedClass := "browser"
			if tc.expectBot {
				expectedClass = "bot"
			}

			if resp.Classification != expectedClass {
				t.Errorf("Expected '%s' for %s, got '%s'", expectedClass, tc.name, resp.Classification)
			}
		})
	}
}

// TestClassificationTiming measures request processing latency
func TestClassificationTiming(t *testing.T) {
	handler := createTestHandler()

	testCases := []struct {
		name    string
		setup   func(*http.Request)
		maxTime time.Duration
	}{
		{
			name: "minimal_request",
			setup: func(req *http.Request) {
				// No headers - minimal processing
			},
			maxTime: 5 * time.Millisecond,
		},
		{
			name: "curl_request",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "curl/8.0.1")
				req.Header.Set("Accept", "*/*")
			},
			maxTime: 5 * time.Millisecond,
		},
		{
			name: "browser_request",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
				req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
				req.Header.Set("Accept-Language", "en-US,en;q=0.5")
				req.Header.Set("Accept-Encoding", "gzip, deflate, br")
				req.Header.Set("Sec-Fetch-Dest", "document")
				req.Header.Set("Sec-Fetch-Mode", "navigate")
				req.Header.Set("Sec-Fetch-Site", "none")
				req.Header.Set("Sec-Fetch-User", "?1")
				req.Header.Set("Sec-CH-UA", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
				req.Header.Set("Sec-CH-UA-Mobile", "?0")
				req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
				req.Header.Set("Cookie", "session=abc123; prefs=dark")
				req.Header.Set("Referer", "https://example.com/")
			},
			maxTime: 5 * time.Millisecond,
		},
		{
			name: "ai_crawler_request",
			setup: func(req *http.Request) {
				req.Header.Set("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.0; +https://openai.com/gptbot)")
				req.Header.Set("Accept", "*/*")
				req.Header.Set("Accept-Encoding", "gzip, deflate")
			},
			maxTime: 5 * time.Millisecond,
		},
	}

	// Warm-up run
	warmupReq := httptest.NewRequest("GET", "/", nil)
	warmupW := httptest.NewRecorder()
	handler.HandleClassify(warmupW, warmupReq)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Run multiple iterations for more accurate timing
			const iterations = 100
			var totalDuration time.Duration

			for i := 0; i < iterations; i++ {
				req := httptest.NewRequest("GET", "/", nil)
				tc.setup(req)
				w := httptest.NewRecorder()

				start := time.Now()
				handler.HandleClassify(w, req)
				totalDuration += time.Since(start)

				if w.Code != http.StatusOK {
					t.Fatalf("Expected status 200, got %d", w.Code)
				}
			}

			avgDuration := totalDuration / iterations
			t.Logf("%s: avg=%v (total=%v over %d iterations)", tc.name, avgDuration, totalDuration, iterations)

			if avgDuration > tc.maxTime {
				t.Errorf("Average latency %v exceeds max %v", avgDuration, tc.maxTime)
			}
		})
	}
}

// TestDebugEndpointTiming measures debug endpoint latency (more data to serialize)
func TestDebugEndpointTiming(t *testing.T) {
	handler := createTestHandler()

	req := httptest.NewRequest("GET", "/debug", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Cookie", "session=test123")

	// Warm-up
	warmupW := httptest.NewRecorder()
	handler.HandleDebug(warmupW, req)

	const iterations = 100
	var totalDuration time.Duration

	for i := 0; i < iterations; i++ {
		w := httptest.NewRecorder()

		start := time.Now()
		handler.HandleDebug(w, req)
		totalDuration += time.Since(start)

		if w.Code != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", w.Code)
		}
	}

	avgDuration := totalDuration / iterations
	t.Logf("debug endpoint: avg=%v (total=%v over %d iterations)", avgDuration, totalDuration, iterations)

	// Debug endpoint has more JSON to serialize, allow 10ms
	maxTime := 10 * time.Millisecond
	if avgDuration > maxTime {
		t.Errorf("Average latency %v exceeds max %v", avgDuration, maxTime)
	}
}

// TestOverallTimingBenchmark provides summary timing stats
func TestOverallTimingBenchmark(t *testing.T) {
	handler := createTestHandler()

	scenarios := []struct {
		name  string
		setup func(*http.Request)
	}{
		{"empty", func(r *http.Request) {}},
		{"curl", func(r *http.Request) {
			r.Header.Set("User-Agent", "curl/8.0.1")
		}},
		{"python", func(r *http.Request) {
			r.Header.Set("User-Agent", "python-requests/2.31.0")
			r.Header.Set("Accept", "*/*")
		}},
		{"browser_minimal", func(r *http.Request) {
			r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
			r.Header.Set("Accept-Language", "en-US")
		}},
		{"browser_full", func(r *http.Request) {
			r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0")
			r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			r.Header.Set("Accept-Language", "en-US,en;q=0.9,ru;q=0.8")
			r.Header.Set("Accept-Encoding", "gzip, deflate, br")
			r.Header.Set("Sec-Fetch-Dest", "document")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header.Set("Sec-CH-UA", `"Chrome";v="120"`)
			r.Header.Set("Cookie", "sid=abc; pref=1; track=xyz")
			r.Header.Set("Referer", "https://example.com/page")
		}},
		{"gptbot", func(r *http.Request) {
			r.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GPTBot/1.0)")
		}},
	}

	const iterations = 500

	t.Logf("\n=== Classification Timing Summary (%d iterations each) ===", iterations)

	var overallTotal time.Duration
	var overallCount int

	for _, s := range scenarios {
		var total time.Duration
		var min, max time.Duration = time.Hour, 0

		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest("GET", "/", nil)
			s.setup(req)
			w := httptest.NewRecorder()

			start := time.Now()
			handler.HandleClassify(w, req)
			elapsed := time.Since(start)

			total += elapsed
			if elapsed < min {
				min = elapsed
			}
			if elapsed > max {
				max = elapsed
			}
		}

		avg := total / iterations
		overallTotal += total
		overallCount += iterations

		t.Logf("%-20s avg=%-10v min=%-10v max=%-10v", s.name, avg, min, max)
	}

	overallAvg := overallTotal / time.Duration(overallCount)
	t.Logf("\n%-20s avg=%v (total requests: %d)", "OVERALL", overallAvg, overallCount)

	// Overall p99 target from methodology: <5ms
	if overallAvg > 5*time.Millisecond {
		t.Errorf("Overall average %v exceeds target 5ms", overallAvg)
	}
}

// TestChallenge_FirstRequest_SetsCookieAndHeaders verifies that a first request with cookies (non-empty JA4H C/D)
// receives Accept-CH, Critical-CH, Vary, and Set-Cookie in the response.
func TestChallenge_FirstRequest_SetsCookieAndHeaders(t *testing.T) {
	handler := createTestHandlerWithChallenge()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	req.Header.Set("Cookie", "session=abc") // so JA4H C/D are non-zero

	w := httptest.NewRecorder()
	handler.HandleClassify(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("Accept-CH") == "" {
		t.Error("expected Accept-CH header")
	}
	if w.Header().Get("Critical-CH") == "" {
		t.Error("expected Critical-CH header")
	}
	if w.Header().Get("Vary") == "" {
		t.Error("expected Vary header")
	}
	setCookie := w.Header().Get("Set-Cookie")
	if setCookie == "" || len(setCookie) < 20 {
		t.Errorf("expected Set-Cookie with __ch_nonce value, got %q", setCookie)
	}
}

// TestChallenge_SecondRequest_SameUAAndHints_Passed verifies that a second request with the cookie from the first
// response, same User-Agent, and required Sec-CH-* hints is classified with challenge passed (no bot penalty).
func TestChallenge_SecondRequest_SameUAAndHints_Passed(t *testing.T) {
	handler := createTestHandlerWithChallenge()

	// Use browser-like headers so base classification is browser; then challenge passed keeps it browser
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	browserHeaders := func(r *http.Request) {
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		r.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6")
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
		r.Header.Set("Sec-Fetch-Dest", "document")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Site", "none")
		r.Header.Set("Sec-Fetch-User", "?1")
		r.Header.Set("Sec-CH-UA", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)
		r.Header.Set("Cookie", "session=xyz")
	}
	req1 := httptest.NewRequest("GET", "/", nil)
	browserHeaders(req1)

	w1 := httptest.NewRecorder()
	handler.HandleClassify(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", w1.Code)
	}
	setCookie := w1.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("first request: expected Set-Cookie")
	}
	nonceVal := parseNonceFromSetCookie(setCookie)
	if nonceVal == "" {
		t.Fatalf("could not parse nonce from Set-Cookie %q", setCookie)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	browserHeaders(req2)
	req2.Header.Set("Cookie", "session=xyz; __ch_nonce="+nonceVal)
	// Same version as in User-Agent (Chrome/120.0.0.0) so challenge passes
	req2.Header.Set("Sec-CH-UA-Full-Version-List", `"Chromium";v="120.0.0.0", "Google Chrome";v="120.0.0.0"`)
	req2.Header.Set("Sec-CH-UA-Platform-Version", `"15.0.0"`)

	w2 := httptest.NewRecorder()
	handler.HandleClassify(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("second request: expected 200, got %d", w2.Code)
	}
	var resp Response
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Classification == "bot" {
		t.Errorf("expected browser (challenge passed), got %s", resp.Classification)
	}
}

// parseNonceFromSetCookie extracts the __ch_nonce value from a Set-Cookie header like "__ch_nonce=abc_def; Max-Age=30; ...".
func parseNonceFromSetCookie(setCookie string) string {
	const prefix = "__ch_nonce="
	for _, part := range strings.Split(setCookie, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, prefix) {
			return strings.TrimSpace(part[len(prefix):])
		}
	}
	return ""
}

// TestChallenge_SecondRequest_DifferentUA_Failed verifies that a second request with the same cookie but different
// User-Agent gets challenge failed (bot signal).
func TestChallenge_SecondRequest_DifferentUA_Failed(t *testing.T) {
	handler := createTestHandlerWithChallenge()

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0")
	req1.Header.Set("Cookie", "s=1")

	w1 := httptest.NewRecorder()
	handler.HandleClassify(w1, req1)
	setCookie := w1.Header().Get("Set-Cookie")
	if setCookie == "" {
		t.Fatal("expected Set-Cookie on first request")
	}
	nonceVal := parseNonceFromSetCookie(setCookie)
	if nonceVal == "" {
		t.Fatalf("could not parse nonce from %q", setCookie)
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", "OtherUA/1.0") // different UA
	req2.Header.Set("Cookie", "s=1; __ch_nonce="+nonceVal)
	req2.Header.Set("Sec-CH-UA-Full-Version-List", `"120.0"`)
	req2.Header.Set("Sec-CH-UA-Platform-Version", `"15.0.0"`)

	w2 := httptest.NewRecorder()
	handler.HandleClassify(w2, req2)
	var resp Response
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Classification != "bot" {
		t.Errorf("expected bot (challenge failed: UA mismatch), got %s", resp.Classification)
	}
}

// TestChallenge_SecondRequest_WrongVersionInHint_Failed verifies that when Sec-CH-UA-Full-Version-List
// does not match the version from the stored User-Agent (Chrome/120.0.0.0), the challenge fails.
func TestChallenge_SecondRequest_WrongVersionInHint_Failed(t *testing.T) {
	handler := createTestHandlerWithChallenge()

	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("User-Agent", ua)
	req1.Header.Set("Cookie", "s=1")

	w1 := httptest.NewRecorder()
	handler.HandleClassify(w1, req1)
	nonceVal := parseNonceFromSetCookie(w1.Header().Get("Set-Cookie"))
	if nonceVal == "" {
		t.Fatal("expected Set-Cookie on first request")
	}

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", ua)
	req2.Header.Set("Cookie", "s=1; __ch_nonce="+nonceVal)
	// Version in hint (119.0.0.0) does not match UA (Chrome/120.0.0.0)
	req2.Header.Set("Sec-CH-UA-Full-Version-List", `"Chromium";v="119.0.0.0", "Google Chrome";v="119.0.0.0"`)
	req2.Header.Set("Sec-CH-UA-Platform-Version", `"15.0.0"`)

	w2 := httptest.NewRecorder()
	handler.HandleClassify(w2, req2)
	var resp Response
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Classification != "bot" {
		t.Errorf("expected bot (challenge failed: version in hint does not match UA), got %s", resp.Classification)
	}
}

// TestChallenge_SecondRequestNoCookie_NonceInStore_Failed verifies that when the same JA4H (same nonce) appears
// again without the __ch_nonce cookie, the server treats it as challenge failed (impersonator not sending cookie).
func TestChallenge_SecondRequestNoCookie_NonceInStore_Failed(t *testing.T) {
	handler := createTestHandlerWithChallenge()

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0")
	req1.Header.Set("Cookie", "sid=abc")

	w1 := httptest.NewRecorder()
	handler.HandleClassify(w1, req1)
	if w1.Header().Get("Set-Cookie") == "" {
		t.Fatal("first request must set cookie")
	}

	// Second request: same cookies (same JA4H nonce) but no __ch_nonce cookie
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	req2.Header.Set("Cookie", "sid=abc")

	w2 := httptest.NewRecorder()
	handler.HandleClassify(w2, req2)
	var resp Response
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Classification != "bot" {
		t.Errorf("expected bot (challenge failed: no cookie sent), got %s", resp.Classification)
	}
}

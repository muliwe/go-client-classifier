package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/muliwe/go-client-slassifier/internal/classifier"
	"github.com/muliwe/go-client-slassifier/internal/fingerprint"
	"github.com/muliwe/go-client-slassifier/internal/server"
)

// Response matches the server response structure
type Response struct {
	Classification string  `json:"classification"`
	Confidence     float64 `json:"confidence"`
	Message        string  `json:"message"`
	RequestID      string  `json:"request_id"`
}

// HealthResponse matches the health endpoint response
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// createTestHandler creates a handler for testing without file logging
func createTestHandler() *server.Handler {
	collector := fingerprint.NewCollector()
	clf := classifier.New(classifier.DefaultConfig())
	return server.NewHandler(collector, clf, nil) // nil logger for tests
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
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-CH-UA", `"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"`)

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
	collector := fingerprint.NewCollector()
	clf := classifier.New(classifier.DefaultConfig())

	// Browser-like request should have positive score
	browserReq := httptest.NewRequest("GET", "/", nil)
	browserReq.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	browserReq.Header.Set("Accept-Language", "en-US")
	browserReq.Header.Set("Accept-Encoding", "gzip")
	browserReq.Header.Set("Sec-Fetch-Site", "none")

	browserFp := collector.Collect(browserReq)
	browserResult := clf.Classify(browserFp)

	if browserResult.Score < 0 {
		t.Errorf("Expected positive score for browser-like request, got %d", browserResult.Score)
	}

	// Bot-like request should have negative score
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

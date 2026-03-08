package unit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/logger"
	"github.com/muliwe/go-client-classifier/internal/server"
)

func createTestHandler() *server.Handler {
	collector := fingerprint.NewCollector()
	cls := classifier.New(classifier.DefaultConfig())
	return server.NewHandler(server.HandlerOptions{Collector: collector, Classifier: cls})
}

func TestServerNewHandler(t *testing.T) {
	h := createTestHandler()
	if h == nil {
		t.Fatal("NewHandler() returned nil")
	}
}

func TestServerHandleHealth(t *testing.T) {
	h := createTestHandler()

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	h.HandleHealth(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleHealth() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("HandleHealth() Content-Type = %q, want %q", contentType, "application/json")
	}

	var health struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if health.Status != "ok" {
		t.Errorf("HandleHealth() status = %q, want %q", health.Status, "ok")
	}
	if health.Version == "" {
		t.Error("HandleHealth() version should not be empty")
	}
}

func TestServerHandleClassify(t *testing.T) {
	h := createTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("Accept", "*/*")
	w := httptest.NewRecorder()

	h.HandleClassify(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleClassify() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var response struct {
		Classification string `json:"classification"`
		RequestID      string `json:"request_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Classification != "bot" {
		t.Errorf("HandleClassify(curl) classification = %q, want %q", response.Classification, "bot")
	}
	if response.RequestID == "" {
		t.Error("HandleClassify() RequestID should not be empty")
	}
}

func TestServerHandleClassify_NotFound(t *testing.T) {
	h := createTestHandler()

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()

	h.HandleClassify(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("HandleClassify(/nonexistent) status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestServerHandleClassify_NotFoundStillLogs verifies that a 404 response for a non-root path
// still performs classification and writes one entry to the JSONL log.
func TestServerHandleClassify_NotFoundStillLogs(t *testing.T) {
	tmpDir := t.TempDir()
	logCfg := logger.Config{LogDir: tmpDir, FileName: "test.jsonl", Daily: false}
	l, err := logger.New(logCfg)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	defer func() { _ = l.Close() }()

	collector := fingerprint.NewCollector()
	cls := classifier.New(classifier.DefaultConfig())
	h := server.NewHandler(server.HandlerOptions{Collector: collector, Classifier: cls, Logger: l})
	h.SetQuiet(true)

	req := httptest.NewRequest("GET", "/123", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	w := httptest.NewRecorder()

	h.HandleClassify(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("HandleClassify(/123) status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	logPath := filepath.Join(tmpDir, "test.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Errorf("log file should have exactly one line, got %d lines", len(lines))
	}
	var entry struct {
		Classification string `json:"classification"`
		RequestID      string `json:"request_id"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("log entry is not valid JSON: %v", err)
	}
	if entry.Classification == "" {
		t.Error("log entry should contain classification")
	}
	if entry.RequestID == "" {
		t.Error("log entry should contain request_id")
	}
}

// TestServerHandleClassify_FaviconNoLog verifies that /favicon.ico returns 404 and is not logged (no JSONL, no metrics).
func TestServerHandleClassify_FaviconNoLog(t *testing.T) {
	tmpDir := t.TempDir()
	logCfg := logger.Config{LogDir: tmpDir, FileName: "test.jsonl", Daily: false}
	l, err := logger.New(logCfg)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	defer func() { _ = l.Close() }()

	collector := fingerprint.NewCollector()
	cls := classifier.New(classifier.DefaultConfig())
	h := server.NewHandler(server.HandlerOptions{Collector: collector, Classifier: cls, Logger: l})
	h.SetQuiet(true)

	req := httptest.NewRequest("GET", "/favicon.ico", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	w := httptest.NewRecorder()

	h.HandleClassify(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("HandleClassify(/favicon.ico) status = %d, want %d", w.Code, http.StatusNotFound)
	}
	logPath := filepath.Join(tmpDir, "test.jsonl")
	data, _ := os.ReadFile(logPath)
	if len(data) != 0 {
		t.Errorf("favicon.ico must not be logged: log file has %d bytes", len(data))
	}
}

func TestServerHandleClassify_LogsRealIPWhenProxied(t *testing.T) {
	tmpDir := t.TempDir()
	logCfg := logger.Config{LogDir: tmpDir, FileName: "test.jsonl", Daily: false}
	l, err := logger.New(logCfg)
	if err != nil {
		t.Fatalf("logger.New: %v", err)
	}
	defer func() { _ = l.Close() }()

	collector := fingerprint.NewCollector()
	cls := classifier.New(classifier.DefaultConfig())
	h := server.NewHandler(server.HandlerOptions{Collector: collector, Classifier: cls, Logger: l})
	h.SetQuiet(true)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "127.0.0.1:51954"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("User-Agent", "curl/8.0")
	w := httptest.NewRecorder()

	h.HandleClassify(w, req)

	logPath := filepath.Join(tmpDir, "test.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	var entry struct {
		RemoteAddr string `json:"remote_addr"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatalf("log entry JSON: %v", err)
	}
	if entry.RemoteAddr != "203.0.113.10" {
		t.Errorf("remote_addr in log = %q, want 203.0.113.10 (real client IP when proxied)", entry.RemoteAddr)
	}
}

func TestServerHandleDebug(t *testing.T) {
	h := createTestHandler()

	req := httptest.NewRequest("GET", "/debug", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120")
	req.Header.Set("Accept-Language", "en-US")
	w := httptest.NewRecorder()

	h.HandleDebug(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HandleDebug() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result fingerprint.ClassificationResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if result.Fingerprint.HTTP.UserAgent == "" {
		t.Error("HandleDebug() should include fingerprint data")
	}
}

func TestServerHandleClassify_BrowserHeaders(t *testing.T) {
	h := createTestHandler()

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Ch-UA", `"Chromium";v="120"`)
	req.Header.Set("Cookie", "session=test") // so fingerprint has cookies and JA4H C/D non-zero; avoids ja4h-no-cookies
	w := httptest.NewRecorder()

	h.HandleClassify(w, req)

	var response struct {
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Classification != "browser" {
		t.Errorf("HandleClassify(browser headers) classification = %q, want %q", response.Classification, "browser")
	}
}

// TestServerHandleClassify_ConfidenceAsString verifies the API returns confidence as a string with 2 decimal places (stable, no float).
func TestServerHandleClassify_ConfidenceAsString(t *testing.T) {
	h := createTestHandler()
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Site", "none")
	w := httptest.NewRecorder()
	h.HandleClassify(w, req)

	var response struct {
		Confidence string `json:"confidence"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Confidence == "" {
		t.Error("confidence should not be empty")
	}
	// Must look like "0.95" (at most 2 decimal places): e.g. "0", "0.5", "0.77", "0.99"
	if len(response.Confidence) > 5 {
		t.Errorf("confidence %q should be short (e.g. 0.95)", response.Confidence)
	}
	// Sanity: parse as float and ensure it's in [0, 1]
	var v float64
	if _, err := fmt.Sscanf(response.Confidence, "%f", &v); err != nil {
		t.Errorf("confidence %q should be a number: %v", response.Confidence, err)
	}
	if v < 0 || v > 1 {
		t.Errorf("confidence %q parses to %v, want in [0, 1]", response.Confidence, v)
	}
}

func TestServerClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{"direct connection", "192.168.1.100:45678", nil, "192.168.1.100"},
		{"proxy X-Forwarded-For", "127.0.0.1:8080", map[string]string{"X-Forwarded-For": "203.0.113.50"}, "203.0.113.50"},
		{"proxy X-Forwarded-For first", "127.0.0.1:8080", map[string]string{"X-Forwarded-For": "203.0.113.50, 10.0.0.1"}, "203.0.113.50"},
		{"proxy X-Real-IP", "127.0.0.1:8080", map[string]string{"X-Real-IP": "198.51.100.1"}, "198.51.100.1"},
		{"proxy X-Real-IP overrides X-Forwarded-For", "127.0.0.1:8080", map[string]string{"X-Real-IP": "198.51.100.1", "X-Forwarded-For": "203.0.113.50"}, "198.51.100.1"},
		{"localhost no headers", "127.0.0.1:8080", nil, "127.0.0.1"},
		{"::1 with X-Forwarded-For", "[::1]:8080", map[string]string{"X-Forwarded-For": "2001:db8::1"}, "2001:db8::1"},
		{"X-Internal-Proxy http->http", "10.0.0.5:12345", map[string]string{"X-Internal-Proxy": "1", "X-Forwarded-For": "203.0.113.20"}, "203.0.113.20"},
		{"non-localhost no proxy header", "192.168.1.1:80", nil, "192.168.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			got := server.ClientIP(req)
			if got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

package unit

import (
	"encoding/json"
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
	return server.NewHandler(collector, cls, nil)
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
	h := server.NewHandler(collector, cls, l)
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
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
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

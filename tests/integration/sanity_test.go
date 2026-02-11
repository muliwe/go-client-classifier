package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Response matches the server response structure
type Response struct {
	Classification string `json:"classification"`
	Message        string `json:"message"`
}

// Simple handler for testing (copy from main for now)
func testHandler(w http.ResponseWriter, r *http.Request) {
	classification := "browser"
	userAgent := r.Header.Get("User-Agent")

	if containsAny(userAgent, []string{"curl", "wget", "python", "go-http-client"}) {
		classification = "bot"
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(Response{
		Classification: classification,
		Message:        "test",
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

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": "0.1.0-sanity",
	})
}

func TestSanityCheck_CurlDetection(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "curl/8.0.1")

	w := httptest.NewRecorder()
	testHandler(w, req)

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Classification != "bot" {
		t.Errorf("Expected 'bot', got '%s'", resp.Classification)
	}
}

func TestSanityCheck_BrowserDetection(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	w := httptest.NewRecorder()
	testHandler(w, req)

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Classification != "browser" {
		t.Errorf("Expected 'browser', got '%s'", resp.Classification)
	}
}

func TestSanityCheck_PythonRequestsDetection(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "python-requests/2.31.0")

	w := httptest.NewRecorder()
	testHandler(w, req)

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Classification != "bot" {
		t.Errorf("Expected 'bot', got '%s'", resp.Classification)
	}
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)

	w := httptest.NewRecorder()
	healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", resp["status"])
	}

	if resp["version"] == "" {
		t.Error("Expected version to be set")
	}
}

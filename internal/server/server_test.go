package server

import (
	"testing"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

// Tests are in tests/unit/server_test.go
// This file exists to satisfy go test ./... discovery

func TestServerPackage(t *testing.T) {
	// Verify package is testable
	collector := fingerprint.NewCollector()
	cls := classifier.New(classifier.DefaultConfig())
	h := NewHandler(HandlerOptions{Collector: collector, Classifier: cls})
	if h == nil {
		t.Error("NewHandler should not return nil")
	}
}

func TestChromeVersionFromUA(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "120.0.0.0"},
		{"Mozilla/5.0 Chrome/120.0.6099.109", "120.0.6099.109"},
		{"Something Chromium/119.0.0.0 Other", "119.0.0.0"},
		{"Edg/121.0.0.0", "121.0.0.0"},
		{"curl/8.0", ""},
		{"", ""},
	}
	for _, tt := range tests {
		got := chromeVersionFromUA(tt.ua)
		if got != tt.want {
			t.Errorf("chromeVersionFromUA(%q) = %q, want %q", tt.ua, got, tt.want)
		}
	}
}

func TestFullVersionListMatchesUA(t *testing.T) {
	tests := []struct {
		storedUA string
		header   string
		want     bool
	}{
		{"Mozilla/5.0 Chrome/120.0.0.0", `"Chromium";v="120.0.0.0", "Google Chrome";v="120.0.0.0"`, true},
		{"Chrome/120.0.6099.109", `"Google Chrome";v="120.0.6099.109"`, true},
		{"Chrome/120.0.0.0", `"Google Chrome";v="120.0.6099.109"`, true},                                                                                                                             // UA simplified major; hint has full version (same major)
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36", `"Google Chrome";v="145.0.7632.75", "Chromium";v="145.0.7632.75"`, true}, // real Chrome: UA major.0.0.0, hint full build
		{"curl/8.0", `"Chrome";v="120"`, true},                                                                                                                                                       // non-Chrome UA: no version check
		{"Chrome/120.0.0.0", "", false},
	}
	for _, tt := range tests {
		got := fullVersionListMatchesUA(tt.storedUA, tt.header)
		if got != tt.want {
			t.Errorf("fullVersionListMatchesUA(%q, %q) = %v, want %v", tt.storedUA, tt.header, got, tt.want)
		}
	}
}

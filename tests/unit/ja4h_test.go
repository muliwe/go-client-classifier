package unit

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

func TestJA4H_FullFingerprint(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Proto = "HTTP/1.1"
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("Accept", "*/*")

	collector := fingerprint.NewCollector()
	fp := collector.Collect(req)

	// Should have JA4H hash
	if fp.HTTP.JA4HHash == "" {
		t.Error("JA4H hash should not be empty")
	}

	// Should have format: a_b_c_d (4 parts separated by underscore)
	parts := strings.Split(fp.HTTP.JA4HHash, "_")
	if len(parts) != 4 {
		t.Errorf("JA4H = %q, want 4 parts separated by underscore", fp.HTTP.JA4HHash)
	}

	// JA4H_a should start with method+version
	if !strings.HasPrefix(parts[0], "ge11") {
		t.Errorf("JA4H_a part = %q, want prefix 'ge11'", parts[0])
	}

	// JA4H_b should be 12 hex chars
	if len(parts[1]) != 12 {
		t.Errorf("JA4H_b part length = %d, want 12", len(parts[1]))
	}

	// JA4H_c and JA4H_d should be zeros (no cookies)
	if parts[2] != "000000000000" {
		t.Errorf("JA4H_c part = %q, want '000000000000'", parts[2])
	}
	if parts[3] != "000000000000" {
		t.Errorf("JA4H_d part = %q, want '000000000000'", parts[3])
	}
}

func TestJA4H_Consistency(t *testing.T) {
	collector := fingerprint.NewCollector()

	// Same request should produce same fingerprint
	makeRequest := func() *fingerprint.Fingerprint {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Proto = "HTTP/2.0"
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("Accept-Language", "en-US")
		fp := collector.Collect(req)
		return &fp
	}

	fp1 := makeRequest()
	fp2 := makeRequest()

	if fp1.HTTP.JA4HHash != fp2.HTTP.JA4HHash {
		t.Errorf("JA4H not consistent: %q != %q", fp1.HTTP.JA4HHash, fp2.HTTP.JA4HHash)
	}
}

func TestJA4H_DifferentClients(t *testing.T) {
	collector := fingerprint.NewCollector()

	// curl request
	curlReq := httptest.NewRequest("GET", "/test", nil)
	curlReq.Proto = "HTTP/1.1"
	curlReq.Header.Set("User-Agent", "curl/8.0")
	curlReq.Header.Set("Accept", "*/*")
	curlFP := collector.Collect(curlReq)

	// browser request
	browserReq := httptest.NewRequest("GET", "/test", nil)
	browserReq.Proto = "HTTP/2.0"
	browserReq.Header.Set("User-Agent", "Mozilla/5.0")
	browserReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	browserReq.Header.Set("Accept-Language", "en-US,en;q=0.9")
	browserReq.Header.Set("Accept-Encoding", "gzip, deflate, br")
	browserReq.Header.Set("Sec-Fetch-Site", "none")
	browserReq.Header.Set("Sec-Fetch-Mode", "navigate")
	browserFP := collector.Collect(browserReq)

	if curlFP.HTTP.JA4HHash == browserFP.HTTP.JA4HHash {
		t.Error("curl and browser should have different JA4H fingerprints")
	}

	// Verify curl has HTTP/1.1 marker
	if !strings.HasPrefix(curlFP.HTTP.JA4HHash, "ge11") {
		t.Errorf("curl JA4H should start with 'ge11', got %q", curlFP.HTTP.JA4HHash)
	}

	// Verify browser has HTTP/2 marker
	if !strings.HasPrefix(browserFP.HTTP.JA4HHash, "ge20") {
		t.Errorf("browser JA4H should start with 'ge20', got %q", browserFP.HTTP.JA4HHash)
	}
}

func TestJA4H_WithCookies(t *testing.T) {
	collector := fingerprint.NewCollector()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Proto = "HTTP/1.1"
	req.Header.Set("User-Agent", "test")
	req.Header.Set("Cookie", "session=abc123")

	fp := collector.Collect(req)

	// Should have cookie flag 'c' in position 4
	if len(fp.HTTP.JA4HHash) > 4 && fp.HTTP.JA4HHash[4] != 'c' {
		t.Errorf("JA4H should have cookie flag 'c', got %q", fp.HTTP.JA4HHash)
	}
}

func TestJA4H_WithReferer(t *testing.T) {
	collector := fingerprint.NewCollector()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Proto = "HTTP/1.1"
	req.Header.Set("User-Agent", "test")
	req.Header.Set("Referer", "http://example.com")

	fp := collector.Collect(req)

	// Should have referer flag 'r' in position 5
	if len(fp.HTTP.JA4HHash) > 5 && fp.HTTP.JA4HHash[5] != 'r' {
		t.Errorf("JA4H should have referer flag 'r', got %q", fp.HTTP.JA4HHash)
	}
}

func TestJA4H_LanguageCode(t *testing.T) {
	collector := fingerprint.NewCollector()

	tests := []struct {
		name     string
		lang     string
		wantCode string
	}{
		{"en-US", "en-US,en;q=0.9", "enus"},
		{"de-DE", "de-DE", "dede"},
		{"no language", "", "0000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Proto = "HTTP/1.1"
			req.Header.Set("User-Agent", "test")
			if tt.lang != "" {
				req.Header.Set("Accept-Language", tt.lang)
			}

			fp := collector.Collect(req)

			// Language code is at positions 8-11 in JA4H_a
			if len(fp.HTTP.JA4HHash) >= 12 {
				langCode := fp.HTTP.JA4HHash[8:12]
				if langCode != tt.wantCode {
					t.Errorf("JA4H language code = %q, want %q", langCode, tt.wantCode)
				}
			}
		})
	}
}

package unit

import (
	"net/http"
	"testing"

	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

func TestCollect_TrustedProxy_ReusesNginxHeaders(t *testing.T) {
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-FP-TLS-Version", "TLSv1.3")
	req.Header.Set("X-FP-TLS-Cipher", "TLS_AES_128_GCM_SHA256")
	req.Header.Set("X-FP-TLS-ALPN", "h2")
	req.Header.Set("X-FP-TLS-SNI", "example.com")
	req.Header.Set("X-FP-JA3", "abcd1234")
	req.Header.Set("X-FP-H2", "settings:a:b:c")

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	if !fp.TLS.Available {
		t.Error("TLS should be available when from proxy")
	}
	if !fp.TLS.FromProxy {
		t.Error("TLS.FromProxy should be true")
	}
	if fp.TLS.Version != "TLS 1.3" {
		t.Errorf("TLS version = %q, want TLS 1.3", fp.TLS.Version)
	}
	if fp.TLS.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("TLS cipher = %q", fp.TLS.CipherSuite)
	}
	if fp.TLS.ALPN != "h2" {
		t.Errorf("ALPN = %q, want h2", fp.TLS.ALPN)
	}
	if fp.TLS.ServerName != "example.com" {
		t.Errorf("SNI = %q", fp.TLS.ServerName)
	}
	if fp.TLS.JA3Hash != "abcd1234" {
		t.Errorf("JA3 = %q", fp.TLS.JA3Hash)
	}
	if fp.HTTP.H2Fingerprint != "settings:a:b:c" {
		t.Errorf("H2Fingerprint = %q, want settings:a:b:c", fp.HTTP.H2Fingerprint)
	}

	s := fingerprint.ExtractSignals(fp)
	if !s.TLSFromProxy {
		t.Error("TLSFromProxy signal should be true")
	}
	if !s.HasHTTP2Fingerprint {
		t.Error("HasHTTP2Fingerprint should be true")
	}
	if !s.HasHTTP2FingerprintFromProxy {
		t.Error("HasHTTP2FingerprintFromProxy should be true")
	}
	if !s.IsHTTP2 {
		t.Error("IsHTTP2 should be true (ALPN h2)")
	}
	if !s.HasTLSFingerprint {
		t.Error("HasTLSFingerprint should be true (JA3 from proxy)")
	}
}

func TestCollect_TrustedProxy_NormalizesTLSVersion(t *testing.T) {
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-FP-TLS-Version", "TLSv1.2")

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	if fp.TLS.Version != "TLS 1.2" {
		t.Errorf("TLS version = %q, want TLS 1.2", fp.TLS.Version)
	}
}

func TestCollect_NoProxy_IgnoresXFPHeaders(t *testing.T) {
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-FP-TLS-Version", "TLSv1.3")
	req.Header.Set("X-FP-H2", "fake")
	// Do NOT set X-Internal-Proxy

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	if fp.TLS.FromProxy {
		t.Error("TLS.FromProxy should be false when X-Internal-Proxy not set")
	}
	if fp.HTTP.H2Fingerprint != "" {
		t.Error("H2Fingerprint should be empty when not from trusted proxy")
	}
	s := fingerprint.ExtractSignals(fp)
	if s.TLSFromProxy {
		t.Error("TLSFromProxy signal should be false")
	}
	if s.HasHTTP2FingerprintFromProxy {
		t.Error("HasHTTP2FingerprintFromProxy should be false")
	}
}

func TestCollect_TrustedProxy_NoH2Header_LeavesH2FingerprintEmpty(t *testing.T) {
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-FP-TLS-Version", "TLSv1.3")
	// No X-FP-H2

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	if fp.HTTP.H2Fingerprint != "" {
		t.Errorf("H2Fingerprint = %q, want empty", fp.HTTP.H2Fingerprint)
	}
	s := fingerprint.ExtractSignals(fp)
	if s.HasHTTP2Fingerprint {
		t.Error("HasHTTP2Fingerprint should be false when X-FP-H2 not set")
	}
}

func mustRequest(method, url string, body interface{}) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

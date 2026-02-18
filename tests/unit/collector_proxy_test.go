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
	req.Header.Set("X-FP-JA3-HASH", "abcd1234abcd1234abcd1234abcd1234")
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
	if fp.TLS.JA3Hash != "abcd1234abcd1234abcd1234abcd1234" {
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
	// Raw X-FP-* headers captured for ML / post-hoc analysis
	if fp.ProxyHeaders == nil {
		t.Fatal("ProxyHeaders should be set when from trusted proxy")
	}
	if fp.ProxyHeaders["X-FP-TLS-Version"] != "TLSv1.3" {
		t.Errorf("ProxyHeaders[X-FP-TLS-Version] = %q", fp.ProxyHeaders["X-FP-TLS-Version"])
	}
	if fp.ProxyHeaders["X-FP-JA3-HASH"] != "abcd1234abcd1234abcd1234abcd1234" {
		t.Errorf("ProxyHeaders[X-FP-JA3-HASH] = %q", fp.ProxyHeaders["X-FP-JA3-HASH"])
	}
	if fp.ProxyHeaders["X-FP-H2"] != "settings:a:b:c" {
		t.Errorf("ProxyHeaders[X-FP-H2] = %q", fp.ProxyHeaders["X-FP-H2"])
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
	if fp.ProxyHeaders != nil {
		t.Error("ProxyHeaders should be nil when not from trusted proxy")
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

func TestCollect_TrustedProxy_JA3HashPreference(t *testing.T) {
	// X-FP-JA3-HASH preferred when present (32 hex)
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-FP-TLS-Version", "TLSv1.3")
	req.Header.Set("X-FP-JA3-HASH", "599ccb0563b7bbae9962ca7e634cc462")
	req.Header.Set("X-FP-JA3", "772,4865-4866-...,0-23-65281,...") // raw would hash to something else

	c := fingerprint.NewCollector()
	fp := c.Collect(req)
	if fp.TLS.JA3Hash != "599ccb0563b7bbae9962ca7e634cc462" {
		t.Errorf("JA3Hash = %q, want 599ccb0563b7bbae9962ca7e634cc462 (X-FP-JA3-HASH preferred)", fp.TLS.JA3Hash)
	}
}

func TestCollect_TrustedProxy_JA3RawHashedWhenNotMD5(t *testing.T) {
	// X-FP-JA3 as raw string (not 32 hex) → MD5 computed
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-FP-TLS-Version", "TLSv1.3")
	req.Header.Set("X-FP-JA3", "771,4866-4867-4865,0-11-10-35-22-23-13,29-23-24,0") // raw JA3

	c := fingerprint.NewCollector()
	fp := c.Collect(req)
	if len(fp.TLS.JA3Hash) != 32 {
		t.Errorf("JA3Hash len = %d, want 32 (MD5 of raw)", len(fp.TLS.JA3Hash))
	}
	// MD5 of that string is deterministic
	for _, c := range fp.TLS.JA3Hash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			t.Errorf("JA3Hash = %q, want 32 hex chars", fp.TLS.JA3Hash)
			break
		}
	}
}

func mustRequest(method, url string, body interface{}) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

package unit

import (
	"net/http"
	"strings"
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

func TestCollect_TrustedProxy_UsesOriginalHeaderOrder(t *testing.T) {
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-Original-Header-Order", "host:user-agent:accept:accept-language:sec-fetch-site")
	req.Header.Set("Host", "example.com")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Accept", "text/html")

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	want := []string{"host", "user-agent", "accept", "accept-language", "sec-fetch-site"}
	if len(fp.HTTP.HeaderOrder) != len(want) {
		t.Errorf("HeaderOrder len = %d, want %d", len(fp.HTTP.HeaderOrder), len(want))
	}
	for i, name := range want {
		if i >= len(fp.HTTP.HeaderOrder) || fp.HTTP.HeaderOrder[i] != name {
			t.Errorf("HeaderOrder[%d] = %v, want %q", i, fp.HTTP.HeaderOrder, name)
			break
		}
	}
}

func TestCollect_NoProxy_IgnoresOriginalHeaderOrder(t *testing.T) {
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Original-Header-Order", "host:user-agent:accept")
	// No X-Internal-Proxy

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	// Order should come from Go's r.Header iteration, not from the header (we don't trust it)
	if len(fp.HTTP.HeaderOrder) != 1 {
		t.Errorf("HeaderOrder should have one entry (x-original-header-order), got %d", len(fp.HTTP.HeaderOrder))
	}
	if len(fp.HTTP.HeaderOrder) > 0 && fp.HTTP.HeaderOrder[0] != "x-original-header-order" {
		t.Errorf("HeaderOrder = %v (expected Go order, not parsed from header)", fp.HTTP.HeaderOrder)
	}
}

// TestCollect_TrustedProxy_TLSSignalsForScoring verifies that when TLS is proxied via X-FP-*
// (real browser payload like reference_bot_curl_cffi.json), the signals used for scoring
// (TLSFromProxy, HasModernTLS, HasSSLGreased) are set so that modern-tls and ssl-greased
// browser points are awarded correctly.
func TestCollect_TrustedProxy_TLSSignalsForScoring(t *testing.T) {
	req := mustRequest("GET", "https://antibot.invent.sale/debug", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-FP-TLS-Version", "TLSv1.3")
	req.Header.Set("X-FP-TLS-Cipher", "TLS_AES_128_GCM_SHA256")
	req.Header.Set("X-FP-TLS-ALPN", "h2")
	req.Header.Set("X-FP-TLS-SNI", "antibot.invent.sale")
	req.Header.Set("X-FP-JA3-HASH", "e13cd90b3b270ccbe2c76b767d55d991")
	req.Header.Set("X-FP-SSL-GREASED", "1")
	req.Header.Set("X-FP-H2", "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	if !fp.TLS.Available || !fp.TLS.FromProxy {
		t.Error("TLS must be available and FromProxy when X-FP-* headers are set with X-Internal-Proxy: 1")
	}
	if fp.TLS.Version != "TLS 1.3" {
		t.Errorf("TLS version = %q, want TLS 1.3 (normalized from X-FP-TLS-Version)", fp.TLS.Version)
	}
	if fp.TLS.SSLGreased != "1" {
		t.Errorf("SSLGreased = %q, want 1 (from X-FP-SSL-GREASED)", fp.TLS.SSLGreased)
	}

	s := fingerprint.ExtractSignals(fp)
	if !s.TLSFromProxy {
		t.Error("TLSFromProxy must be true for correct proxy scoring path")
	}
	if !s.HasModernTLS {
		t.Error("HasModernTLS must be true when X-FP-TLS-Version is TLSv1.3")
	}
	if !s.HasSSLGreased {
		t.Error("HasSSLGreased must be true when X-FP-SSL-GREASED is non-zero (e.g. \"1\")")
	}
	if !strings.Contains(s.ScoreBreakdown, "modern-tls(+1)") {
		t.Errorf("score_breakdown must award modern-tls(+1) when TLS from proxy has modern version; got %q", s.ScoreBreakdown)
	}
	if !strings.Contains(s.ScoreBreakdown, "ssl-greased(+1)") {
		t.Errorf("score_breakdown must award ssl-greased(+1) when TLS from proxy has GREASE; got %q", s.ScoreBreakdown)
	}
}

// TestCollect_TrustedProxy_JA3FillsCountsAndGroups verifies that when TLS is from proxy,
// CipherSuitesCount, ExtensionsCount and SupportedGroups are derived from raw X-FP-JA3
// so that scoring (high-ciphers, tls-ext>=10, multi-groups) can apply.
func TestCollect_TrustedProxy_JA3FillsCountsAndGroups(t *testing.T) {
	// JA3 from reference_bot_curl_cffi.json: 15 ciphers, 14 extensions, 4 groups
	ja3 := "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,65281-35-0-43-18-45-10-27-5-13-11-16-51-23,4588-29-23-24,0"
	req := mustRequest("GET", "https://example.com/", nil)
	req.Header.Set("X-Internal-Proxy", "1")
	req.Header.Set("X-FP-TLS-Version", "TLSv1.3")
	req.Header.Set("X-FP-JA3", ja3)
	req.Header.Set("X-FP-JA3-HASH", "e13cd90b3b270ccbe2c76b767d55d991")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

	c := fingerprint.NewCollector()
	fp := c.Collect(req)

	if !fp.TLS.FromProxy {
		t.Fatal("TLS must be from proxy")
	}
	if fp.TLS.CipherSuitesCount != 15 {
		t.Errorf("CipherSuitesCount = %d, want 15 (from JA3 field 2)", fp.TLS.CipherSuitesCount)
	}
	if fp.TLS.ExtensionsCount != 14 {
		t.Errorf("ExtensionsCount = %d, want 14 (from JA3 field 3)", fp.TLS.ExtensionsCount)
	}
	if len(fp.TLS.SupportedGroups) != 4 {
		t.Errorf("len(SupportedGroups) = %d, want 4 (from JA3 field 4)", len(fp.TLS.SupportedGroups))
	}
	if fp.TLS.SupportedGroups != nil {
		expected := []string{"4588", "29", "23", "24"}
		for i, g := range expected {
			if i >= len(fp.TLS.SupportedGroups) || fp.TLS.SupportedGroups[i] != g {
				t.Errorf("SupportedGroups = %v, want %v", fp.TLS.SupportedGroups, expected)
				break
			}
		}
	}

	s := fingerprint.ExtractSignals(fp)
	if !s.HighCipherCount {
		t.Error("HighCipherCount should be true when CipherSuitesCount > 10 from proxy JA3")
	}
	if !s.HasMultipleGroups {
		t.Error("HasMultipleGroups should be true when SupportedGroups >= 3 from proxy JA3")
	}
	if !strings.Contains(s.ScoreBreakdown, "high-ciphers") {
		t.Errorf("score_breakdown should award high-ciphers when from proxy with JA3; got %q", s.ScoreBreakdown)
	}
	if !strings.Contains(s.ScoreBreakdown, "multi-groups") {
		t.Errorf("score_breakdown should award multi-groups when from proxy with JA3; got %q", s.ScoreBreakdown)
	}
	if !strings.Contains(s.ScoreBreakdown, "tls-ext>=10") {
		t.Errorf("score_breakdown should award tls-ext>=10 when ExtensionsCount >= 10 from proxy JA3; got %q", s.ScoreBreakdown)
	}
}

func mustRequest(method, url string, body interface{}) *http.Request {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		panic(err)
	}
	return req
}

package fingerprint

import (
	"crypto/tls"
	"net/http"
	"strings"
)

// Collector extracts fingerprint data from HTTP requests
type Collector struct{}

// NewCollector creates a new fingerprint collector
func NewCollector() *Collector {
	return &Collector{}
}

// Collect extracts fingerprint from an HTTP request
func (c *Collector) Collect(r *http.Request) Fingerprint {
	return Fingerprint{
		TLS:  c.collectTLS(r),
		HTTP: c.collectHTTP(r),
	}
}

// collectTLS extracts TLS-level fingerprint
func (c *Collector) collectTLS(r *http.Request) TLSFingerprint {
	fp := TLSFingerprint{
		Available: false,
	}

	if r.TLS == nil {
		return fp
	}

	fp.Available = true
	fp.Version = tlsVersionName(r.TLS.Version)
	fp.CipherSuite = tls.CipherSuiteName(r.TLS.CipherSuite)
	fp.ServerName = r.TLS.ServerName
	fp.ALPN = r.TLS.NegotiatedProtocol

	// Note: Some fields like CipherSuitesCount require custom TLS listener
	// to capture ClientHello. For now, we use what's available from std lib.

	return fp
}

// collectHTTP extracts HTTP-level fingerprint
func (c *Collector) collectHTTP(r *http.Request) HTTPFingerprint {
	fp := HTTPFingerprint{
		Version:     r.Proto,
		Method:      r.Method,
		Path:        r.URL.Path,
		Headers:     make(map[string]string),
		HeaderOrder: make([]string, 0, len(r.Header)),
		HeaderCount: len(r.Header),
	}

	// Collect headers in order (Go 1.21+ preserves order)
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		fp.HeaderOrder = append(fp.HeaderOrder, lowerKey)
		if len(values) > 0 {
			fp.Headers[lowerKey] = values[0]
		}
	}

	// Extract specific headers
	fp.UserAgent = r.Header.Get("User-Agent")
	fp.Accept = r.Header.Get("Accept")
	fp.AcceptLang = r.Header.Get("Accept-Language")
	fp.AcceptEnc = r.Header.Get("Accept-Encoding")
	fp.Connection = r.Header.Get("Connection")
	fp.ContentType = r.Header.Get("Content-Type")
	fp.ContentLength = r.ContentLength

	// Browser-specific headers
	fp.SecFetchSite = r.Header.Get("Sec-Fetch-Site")
	fp.SecFetchMode = r.Header.Get("Sec-Fetch-Mode")
	fp.SecFetchDest = r.Header.Get("Sec-Fetch-Dest")
	fp.SecFetchUser = r.Header.Get("Sec-Fetch-User")
	fp.SecChUA = r.Header.Get("Sec-CH-UA")

	// Boolean checks
	fp.HasCookies = r.Header.Get("Cookie") != ""
	fp.HasReferer = r.Header.Get("Referer") != ""

	return fp
}

// tlsVersionName converts TLS version to human-readable name
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

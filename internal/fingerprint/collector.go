package fingerprint

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/psanford/tlsfingerprint"
)

// TLSFingerprintContextKey is the context key type for TLS fingerprint
type TLSFingerprintContextKey string

const (
	// ContextKeyTLSFingerprint is the key for storing TLS fingerprint in context
	ContextKeyTLSFingerprint TLSFingerprintContextKey = "tls_fingerprint"
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

	// Try to get ClientHello fingerprint from context (set by fingerprintlistener)
	if clientHelloFP := c.getClientHelloFingerprint(r); clientHelloFP != nil {
		// Populate fields from ClientHello
		fp.CipherSuitesCount = len(clientHelloFP.CipherSuites)
		fp.ExtensionsCount = len(clientHelloFP.Extensions)
		fp.HasSessionTicket = containsExtension(clientHelloFP.Extensions, 35) // session_ticket extension

		// Supported versions from ClientHello
		fp.SupportedVersions = formatTLSVersions(clientHelloFP.Version, clientHelloFP.RawVersion)

		// Signature schemes
		fp.SignatureSchemes = formatSignatureSchemes(clientHelloFP.SignatureAlgorithms)

		// Supported groups (elliptic curves)
		fp.SupportedGroups = formatSupportedGroups(clientHelloFP.SupportedGroups)

		// JA3/JA4 fingerprints
		fp.JA3Hash = clientHelloFP.JA3Hash()
		fp.JA4Hash = clientHelloFP.JA4String()

		// Check for early data extension (0-RTT)
		fp.HasEarlyData = containsExtension(clientHelloFP.Extensions, 42) // early_data extension
	}

	return fp
}

// getClientHelloFingerprint retrieves the ClientHello fingerprint from request context
func (c *Collector) getClientHelloFingerprint(r *http.Request) *tlsfingerprint.Fingerprint {
	// The fingerprint is stored by the server's ConnContext callback
	val := r.Context().Value(ContextKeyTLSFingerprint)
	if val == nil {
		return nil
	}
	if fp, ok := val.(*tlsfingerprint.Fingerprint); ok {
		return fp
	}
	return nil
}

// containsExtension checks if extension list contains a specific extension type
func containsExtension(extensions []uint16, extType uint16) bool {
	for _, ext := range extensions {
		if ext == extType {
			return true
		}
	}
	return false
}

// formatTLSVersions formats TLS versions for display
func formatTLSVersions(negotiated, raw uint16) []string {
	versions := []string{}

	// Add negotiated version (from supported_versions extension if TLS 1.3)
	if negotiated > 0 {
		versions = append(versions, tlsVersionName(negotiated))
	}

	// If raw version differs (for TLS 1.3, raw is always 0x0303 = TLS 1.2)
	if raw > 0 && raw != negotiated {
		versions = append(versions, fmt.Sprintf("raw: %s", tlsVersionName(raw)))
	}

	return versions
}

// formatSignatureSchemes converts signature scheme IDs to names
func formatSignatureSchemes(schemes []uint16) []string {
	names := make([]string, 0, len(schemes))
	for _, scheme := range schemes {
		names = append(names, signatureSchemeName(scheme))
	}
	return names
}

// formatSupportedGroups converts supported group IDs to names
func formatSupportedGroups(groups []uint16) []string {
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, supportedGroupName(group))
	}
	return names
}

// signatureSchemeName returns human-readable name for signature scheme
func signatureSchemeName(scheme uint16) string {
	// Common signature schemes
	names := map[uint16]string{
		0x0201: "rsa_pkcs1_sha1",
		0x0203: "ecdsa_sha1",
		0x0401: "rsa_pkcs1_sha256",
		0x0403: "ecdsa_secp256r1_sha256",
		0x0501: "rsa_pkcs1_sha384",
		0x0503: "ecdsa_secp384r1_sha384",
		0x0601: "rsa_pkcs1_sha512",
		0x0603: "ecdsa_secp521r1_sha512",
		0x0804: "rsa_pss_rsae_sha256",
		0x0805: "rsa_pss_rsae_sha384",
		0x0806: "rsa_pss_rsae_sha512",
		0x0807: "ed25519",
		0x0808: "ed448",
		0x0809: "rsa_pss_pss_sha256",
		0x080a: "rsa_pss_pss_sha384",
		0x080b: "rsa_pss_pss_sha512",
	}
	if name, ok := names[scheme]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", scheme)
}

// supportedGroupName returns human-readable name for supported group
func supportedGroupName(group uint16) string {
	names := map[uint16]string{
		0x0017: "secp256r1",
		0x0018: "secp384r1",
		0x0019: "secp521r1",
		0x001d: "x25519",
		0x001e: "x448",
		0x0100: "ffdhe2048",
		0x0101: "ffdhe3072",
		0x0102: "ffdhe4096",
		0x0103: "ffdhe6144",
		0x0104: "ffdhe8192",
	}
	if name, ok := names[group]; ok {
		return name
	}
	// Check for GREASE values
	if isGREASE(group) {
		return "GREASE"
	}
	return fmt.Sprintf("0x%04x", group)
}

// isGREASE checks if value is a GREASE value (RFC 8701)
func isGREASE(val uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
	return (val & 0x0f0f) == 0x0a0a
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

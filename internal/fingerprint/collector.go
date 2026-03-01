package fingerprint

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
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

// Collect extracts fingerprint from an HTTP request.
// When the request comes from a trusted proxy (X-Internal-Proxy: 1), TLS and
// HTTP/2 data are taken from X-FP-* headers instead of r.TLS / context.
// Raw X-FP-* header values are stored in fp.ProxyHeaders for ML and post-hoc analysis.
func (c *Collector) Collect(r *http.Request) Fingerprint {
	fp := Fingerprint{
		TLS:  c.collectTLS(r),
		HTTP: c.collectHTTP(r),
	}

	// HTTP/2 fingerprint from proxy (e.g. nginx X-FP-H2); parse for structured signals
	if IsTrustedProxy(r) {
		if h2 := r.Header.Get(HeaderFPH2); h2 != "" {
			fp.HTTP.H2Fingerprint = h2
			fp.HTTP.H2Parsed = ParseH2Fingerprint(h2)
		}
		// Capture all X-FP-* headers for logging (ML training and post-hoc analysis)
		fp.ProxyHeaders = make(map[string]string, len(ProxyHeaderNames))
		for _, name := range ProxyHeaderNames {
			if v := r.Header.Get(name); v != "" {
				fp.ProxyHeaders[name] = v
			}
		}
	}

	// JA4H: from trusted proxy header X-FP-JA4H when present, else compute from request
	if IsTrustedProxy(r) {
		if h := r.Header.Get(HeaderFPJA4H); h != "" {
			fp.HTTP.JA4HHash = h
		} else {
			fp.HTTP.JA4HHash = JA4H(r)
		}
	} else {
		fp.HTTP.JA4HHash = JA4H(r)
	}

	return fp
}

// collectTLS extracts TLS-level fingerprint.
// When X-Internal-Proxy is "1", TLS data is read from X-FP-* headers (nginx
// TLS termination); otherwise from r.TLS and ConnContext.
func (c *Collector) collectTLS(r *http.Request) TLSFingerprint {
	fp := TLSFingerprint{
		Available: false,
	}

	if IsTrustedProxy(r) {
		return c.collectTLSFromProxy(r)
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

// collectTLSFromProxy builds TLS fingerprint from trusted proxy headers
// (e.g. nginx with ssl_ja3 and proxy_set_header X-FP-*).
// JA3 hash: prefer X-FP-JA3-HASH (32-char MD5); else X-FP-JA3 if it looks like MD5; else compute MD5 from raw JA3 string.
// CipherSuitesCount, ExtensionsCount, SupportedGroups are derived from raw X-FP-JA3 when present,
// so that scoring (high-ciphers, tls-ext>=10, multi-groups / low-ciphers, few-tls-ext) applies correctly.
func (c *Collector) collectTLSFromProxy(r *http.Request) TLSFingerprint {
	fp := TLSFingerprint{
		Available: true,
		FromProxy: true,
	}
	v := r.Header.Get(HeaderFPTLSVersion)
	if v != "" {
		fp.Version = normalizeTLSVersionFromProxy(v)
		// Supported versions: we only have negotiated version from proxy; set it as minimal inferred list.
		fp.SupportedVersions = []string{fp.Version}
	}
	fp.CipherSuite = r.Header.Get(HeaderFPTLSCipher)
	fp.ALPN = r.Header.Get(HeaderFPTLSALPN)
	fp.ServerName = r.Header.Get(HeaderFPTLSSNI)
	fp.JA3Hash = resolveJA3HashFromProxy(r.Header.Get(HeaderFPJA3Hash), r.Header.Get(HeaderFPJA3))
	fp.JA4Hash = r.Header.Get(HeaderFPJA4)
	fp.SSLGreased = r.Header.Get(HeaderFPSSLGreased)

	// Derive counts, cipher names, and group names from raw JA3 (IANA ID dictionaries in code)
	if ja3Raw := strings.TrimSpace(r.Header.Get(HeaderFPJA3)); ja3Raw != "" {
		cipherIDs, extN, groupIDs := parseJA3Counts(ja3Raw)
		fp.CipherSuitesCount = len(cipherIDs)
		fp.ExtensionsCount = extN
		fp.OfferedCipherSuites = ja3CipherIDsToNames(cipherIDs)
		fp.SupportedGroups = ja3SupportedGroupIDsToNames(groupIDs)
	}
	return fp
}

// parseJA3Counts parses the raw JA3 string (format: Version,Ciphers,Extensions,EllipticCurves,PointFormats)
// and returns cipher IDs, extension count, and supported group IDs for use in scoring and name lookup.
func parseJA3Counts(ja3Raw string) (cipherIDs []string, extCount int, groupIDs []string) {
	parts := strings.Split(ja3Raw, ",")
	if len(parts) < 4 {
		return nil, 0, nil
	}
	if parts[1] != "" {
		cipherIDs = strings.Split(parts[1], "-")
	}
	if len(parts) > 2 && parts[2] != "" {
		extCount = len(strings.Split(parts[2], "-"))
	}
	if len(parts) > 3 && parts[3] != "" {
		groupIDs = strings.Split(parts[3], "-")
	}
	return cipherIDs, extCount, groupIDs
}

// ja3CipherIDsToNames converts JA3 field-2 cipher suite IDs (decimal) to IANA names. Unknown IDs stay as decimal string.
var cipherSuiteIDToName = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x2f:   "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x35:   "TLS_RSA_WITH_AES_256_CBC_SHA",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
	0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
	0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
}

func ja3CipherIDsToNames(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	names := make([]string, 0, len(ids))
	for _, s := range ids {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		id, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			names = append(names, s)
			continue
		}
		if name, ok := cipherSuiteIDToName[uint16(id)]; ok {
			names = append(names, name)
		} else if isGREASE(uint16(id)) {
			names = append(names, "GREASE")
		} else {
			names = append(names, fmt.Sprintf("%d", id))
		}
	}
	return names
}

// ja3SupportedGroupIDsToNames converts JA3 field-4 IDs (decimal strings) to IANA names using supportedGroupName.
func ja3SupportedGroupIDsToNames(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	names := make([]string, 0, len(ids))
	for _, s := range ids {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		id, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			names = append(names, s)
			continue
		}
		names = append(names, supportedGroupName(uint16(id)))
	}
	return names
}

// resolveJA3HashFromProxy returns the 32-char JA3 MD5 hash for use in known-library/browser lookups.
// Prefer hashHeader (X-FP-JA3-HASH); else if ja3Raw looks like MD5 use it; else compute MD5(ja3Raw).
func resolveJA3HashFromProxy(hashHeader, ja3Raw string) string {
	hashHeader = strings.TrimSpace(strings.ToLower(hashHeader))
	ja3Raw = strings.TrimSpace(ja3Raw)
	if hashHeader != "" && isMD5Hex(hashHeader) {
		return hashHeader
	}
	if ja3Raw != "" {
		ja3Lower := strings.ToLower(ja3Raw)
		if isMD5Hex(ja3Lower) {
			return ja3Lower
		}
		return ja3RawToMD5Hash(ja3Raw)
	}
	return ""
}

// isMD5Hex returns true if s is exactly 32 lowercase hex characters (MD5 hash).
func isMD5Hex(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ja3RawToMD5Hash returns MD5 hash of the raw JA3 string (comma-separated), as 32 lowercase hex chars.
func ja3RawToMD5Hash(raw string) string {
	h := md5.Sum([]byte(raw))
	return hex.EncodeToString(h[:])
}

// normalizeTLSVersionFromProxy maps proxy TLS version strings to our format
// (e.g. "TLSv1.3" -> "TLS 1.3").
func normalizeTLSVersionFromProxy(s string) string {
	switch s {
	case "TLSv1.0":
		return "TLS 1.0"
	case "TLSv1.1":
		return "TLS 1.1"
	case "TLSv1.2":
		return "TLS 1.2"
	case "TLSv1.3":
		return "TLS 1.3"
	default:
		return s
	}
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

// signatureSchemeName returns human-readable name for signature scheme.
// IDs from IANA TLS SignatureScheme registry: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml (section TLS SignatureScheme), CSV: tls-signaturescheme.csv
func signatureSchemeName(scheme uint16) string {
	// Common signature schemes (IANA TLS SignatureScheme)
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

// supportedGroupName returns human-readable name for supported group (elliptic curve / FFDHE).
// IDs from IANA TLS Supported Groups: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml (section TLS Supported Groups), CSV: tls-parameters-8.csv
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

	// Populate fp.Headers from request
	for key, values := range r.Header {
		lowerKey := strings.ToLower(key)
		if len(values) > 0 {
			fp.Headers[lowerKey] = values[0]
		}
	}
	// Header order: when from trusted proxy, use X-Original-Header-Order (set by nginx Lua) so we use
	// the client's real order instead of nginx's reordered headers
	if IsTrustedProxy(r) {
		if raw := r.Header.Get(HeaderOriginalHeaderOrder); raw != "" {
			for _, name := range strings.Split(raw, ":") {
				name = strings.TrimSpace(strings.ToLower(name))
				if name != "" {
					fp.HeaderOrder = append(fp.HeaderOrder, name)
				}
			}
			fp.HeaderOrderFromProxy = true
		}
	}
	// When not from proxy (e.g. TLS terminated by Go): net/http stores Header as a map, so order is not preserved.
	// We only have meaningful order when X-Original-Header-Order is set (nginx with Lua). Otherwise we fill order
	// from map iteration (unpredictable) so header-order signals are not applied (HeaderOrderFromProxy stays false).
	if len(fp.HeaderOrder) == 0 {
		for key := range r.Header {
			fp.HeaderOrder = append(fp.HeaderOrder, strings.ToLower(key))
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

	// H2Fingerprint is set in Collect() when IsTrustedProxy and X-FP-H2 present
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

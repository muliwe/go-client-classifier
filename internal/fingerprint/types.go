package fingerprint

import "time"

// Fingerprint contains all collected signals from a request
type Fingerprint struct {
	TLS  TLSFingerprint  `json:"tls"`
	HTTP HTTPFingerprint `json:"http"`
}

// TLSFingerprint contains TLS-level signals
type TLSFingerprint struct {
	Version            string   `json:"version"`             // TLS version (e.g., "TLS 1.3")
	CipherSuite        string   `json:"cipher_suite"`        // Negotiated cipher suite
	ALPN               string   `json:"alpn"`                // Negotiated protocol (h2, http/1.1)
	ServerName         string   `json:"server_name"`         // SNI hostname
	CipherSuitesCount  int      `json:"cipher_suites_count"` // Number of offered cipher suites
	ExtensionsCount    int      `json:"extensions_count"`    // Number of TLS extensions
	SupportedVersions  []string `json:"supported_versions"`  // Client-offered TLS versions
	SignatureSchemes   []string `json:"signature_schemes"`   // Supported signature algorithms
	SupportedGroups    []string `json:"supported_groups"`    // Supported elliptic curves
	HasSessionTicket   bool     `json:"has_session_ticket"`  // Session resumption support
	HasEarlyData       bool     `json:"has_early_data"`      // 0-RTT support
	JA3Hash            string   `json:"ja3_hash,omitempty"`  // JA3 fingerprint hash
	JA4Hash            string   `json:"ja4_hash,omitempty"`  // JA4 fingerprint hash
	CertificateRequest bool     `json:"certificate_request"` // Client cert requested
	Available          bool     `json:"available"`           // TLS info was available
}

// HTTPFingerprint contains HTTP-level signals
type HTTPFingerprint struct {
	Version       string            `json:"version"`        // HTTP version (HTTP/1.1, HTTP/2)
	Method        string            `json:"method"`         // Request method
	Path          string            `json:"path"`           // Request path
	Headers       map[string]string `json:"headers"`        // All headers (lowercased keys)
	HeaderOrder   []string          `json:"header_order"`   // Order of headers as received
	HeaderCount   int               `json:"header_count"`   // Total header count
	UserAgent     string            `json:"user_agent"`     // User-Agent header
	Accept        string            `json:"accept"`         // Accept header
	AcceptLang    string            `json:"accept_lang"`    // Accept-Language header
	AcceptEnc     string            `json:"accept_enc"`     // Accept-Encoding header
	Connection    string            `json:"connection"`     // Connection header
	SecFetchSite  string            `json:"sec_fetch_site"` // Sec-Fetch-Site header
	SecFetchMode  string            `json:"sec_fetch_mode"` // Sec-Fetch-Mode header
	SecFetchDest  string            `json:"sec_fetch_dest"` // Sec-Fetch-Dest header
	SecFetchUser  string            `json:"sec_fetch_user"` // Sec-Fetch-User header
	SecChUA       string            `json:"sec_ch_ua"`      // Sec-CH-UA header
	HasCookies    bool              `json:"has_cookies"`    // Has Cookie header
	HasReferer    bool              `json:"has_referer"`    // Has Referer header
	ContentType   string            `json:"content_type"`   // Content-Type header
	ContentLength int64             `json:"content_length"` // Content-Length value
}

// Signals contains extracted classification signals
type Signals struct {
	// TLS signals
	IsHTTP2           bool `json:"is_http2"`
	HasModernTLS      bool `json:"has_modern_tls"`      // TLS 1.2+
	HasALPN           bool `json:"has_alpn"`            // ALPN negotiated
	HighCipherCount   bool `json:"high_cipher_count"`   // > 10 cipher suites
	HasSessionSupport bool `json:"has_session_support"` // Session tickets

	// HTTP signals
	HasSecFetchHeaders bool `json:"has_sec_fetch_headers"` // Has Sec-Fetch-* headers
	HasAcceptLanguage  bool `json:"has_accept_language"`   // Has Accept-Language
	HasUserAgent       bool `json:"has_user_agent"`        // Has User-Agent
	HasAccept          bool `json:"has_accept"`            // Has Accept header
	HasAcceptEncoding  bool `json:"has_accept_encoding"`   // Has Accept-Encoding

	// Heuristic signals
	UserAgentIsBot       bool `json:"ua_is_bot"`        // UA contains bot indicators
	UserAgentIsAICrawler bool `json:"ua_is_ai_crawler"` // UA contains AI/LLM crawler indicators
	UserAgentIsBrowser   bool `json:"ua_is_browser"`    // UA looks like a browser
	LowHeaderCount       bool `json:"low_header_count"` // < 5 headers (suspicious)
	HasBrowserHeaders    bool `json:"has_browser_headers"`
	MissingTypicalHeader bool `json:"missing_typical_header"` // Missing expected headers

	// Computed
	BrowserScore int `json:"browser_score"` // Score towards browser classification
	BotScore     int `json:"bot_score"`     // Score towards bot classification
}

// ClassificationResult contains the final classification
type ClassificationResult struct {
	RequestID      string      `json:"request_id"`
	Timestamp      time.Time   `json:"timestamp"`
	Classification string      `json:"classification"` // "browser" or "bot"
	Confidence     float64     `json:"confidence"`     // 0.0 to 1.0
	Fingerprint    Fingerprint `json:"fingerprint"`
	Signals        Signals     `json:"signals"`
	Score          int         `json:"score"` // Net score (positive = browser, negative = bot)
	Reason         string      `json:"reason"`
}

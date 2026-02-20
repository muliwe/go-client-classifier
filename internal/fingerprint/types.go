package fingerprint

import "time"

// Fingerprint contains all collected signals from a request
type Fingerprint struct {
	TLS          TLSFingerprint    `json:"tls"`
	HTTP         HTTPFingerprint   `json:"http"`
	ProxyHeaders map[string]string `json:"proxy_headers,omitempty"` // Raw X-FP-* header values when from trusted proxy (for ML and post-hoc analysis)
}

// TLSFingerprint contains TLS-level signals
type TLSFingerprint struct {
	Version            string   `json:"version"`               // TLS version (e.g., "TLS 1.3")
	CipherSuite        string   `json:"cipher_suite"`          // Negotiated cipher suite
	ALPN               string   `json:"alpn"`                  // Negotiated protocol (h2, http/1.1)
	ServerName         string   `json:"server_name"`           // SNI hostname
	CipherSuitesCount  int      `json:"cipher_suites_count"`   // Number of offered cipher suites
	ExtensionsCount    int      `json:"extensions_count"`      // Number of TLS extensions
	SupportedVersions  []string `json:"supported_versions"`    // Client-offered TLS versions
	SignatureSchemes   []string `json:"signature_schemes"`     // Supported signature algorithms
	SupportedGroups    []string `json:"supported_groups"`      // Supported elliptic curves
	HasSessionTicket   bool     `json:"has_session_ticket"`    // Session resumption support
	HasEarlyData       bool     `json:"has_early_data"`        // 0-RTT support
	JA3Hash            string   `json:"ja3_hash,omitempty"`    // JA3 fingerprint hash (32-char MD5)
	JA4Hash            string   `json:"ja4_hash,omitempty"`    // JA4 fingerprint hash
	SSLGreased         string   `json:"ssl_greased,omitempty"` // GREASE values from proxy (X-FP-SSL-GREASED); format depends on nginx module
	CertificateRequest bool     `json:"certificate_request"`   // Client cert requested
	Available          bool     `json:"available"`             // TLS info was available
	FromProxy          bool     `json:"from_proxy"`            // TLS data came from trusted proxy headers (e.g. nginx)
}

// HTTPFingerprint contains HTTP-level signals
type HTTPFingerprint struct {
	Version              string               `json:"version"`                  // HTTP version (HTTP/1.1, HTTP/2)
	Method               string               `json:"method"`                   // Request method
	Path                 string               `json:"path"`                     // Request path
	Headers              map[string]string    `json:"headers"`                  // All headers (lowercased keys)
	HeaderOrder          []string             `json:"header_order"`             // Order of headers as received
	HeaderOrderFromProxy bool                 `json:"header_order_from_proxy"`  // True when order came from X-Original-Header-Order (nginx Lua)
	HeaderCount          int                  `json:"header_count"`             // Total header count
	UserAgent            string               `json:"user_agent"`               // User-Agent header
	Accept               string               `json:"accept"`                   // Accept header
	AcceptLang           string               `json:"accept_lang"`              // Accept-Language header
	AcceptEnc            string               `json:"accept_enc"`               // Accept-Encoding header
	Connection           string               `json:"connection"`               // Connection header
	SecFetchSite         string               `json:"sec_fetch_site"`           // Sec-Fetch-Site header
	SecFetchMode         string               `json:"sec_fetch_mode"`           // Sec-Fetch-Mode header
	SecFetchDest         string               `json:"sec_fetch_dest"`           // Sec-Fetch-Dest header
	SecFetchUser         string               `json:"sec_fetch_user"`           // Sec-Fetch-User header
	SecChUA              string               `json:"sec_ch_ua"`                // Sec-CH-UA header
	HasCookies           bool                 `json:"has_cookies"`              // Has Cookie header
	HasReferer           bool                 `json:"has_referer"`              // Has Referer header
	ContentType          string               `json:"content_type"`             // Content-Type header
	ContentLength        int64                `json:"content_length"`           // Content-Length value
	JA4HHash             string               `json:"ja4h_hash,omitempty"`      // JA4H HTTP fingerprint hash
	H2Fingerprint        string               `json:"h2_fingerprint,omitempty"` // HTTP/2 fingerprint (e.g. from nginx X-FP-H2)
	H2Parsed             *H2FingerprintParsed `json:"h2_parsed,omitempty"`      // Parsed H2 fingerprint (SETTINGS, window, priority)
}

// Signals contains extracted classification signals
type Signals struct {
	// TLS signals (from ClientHello)
	IsHTTP2           bool `json:"is_http2"`
	HasModernTLS      bool `json:"has_modern_tls"`      // TLS 1.2+
	HasALPN           bool `json:"has_alpn"`            // ALPN negotiated
	HighCipherCount   bool `json:"high_cipher_count"`   // > 10 cipher suites (browsers typically have 15-20)
	HasSessionSupport bool `json:"has_session_support"` // Session tickets support
	HasTLSFingerprint bool `json:"has_tls_fingerprint"` // JA3/JA4 fingerprint available
	TLSKnownLibrary   bool `json:"tls_known_library"`   // JA3/JA4 matches known library/bot list (for TLS vs UA consistency)
	TLSKnownBrowser   bool `json:"tls_known_browser"`   // JA3/JA4 matches known browser list (for TLS vs UA consistency)
	HasMultipleGroups bool `json:"has_multiple_groups"` // Multiple elliptic curve groups (browsers)
	HasModernCiphers  bool `json:"has_modern_ciphers"`  // Has TLS 1.3 cipher suites

	// HTTP signals
	HasSecFetchHeaders bool `json:"has_sec_fetch_headers"` // Has Sec-Fetch-* headers
	HasAcceptLanguage  bool `json:"has_accept_language"`   // Has Accept-Language
	HasUserAgent       bool `json:"has_user_agent"`        // Has User-Agent
	HasAccept          bool `json:"has_accept"`            // Has Accept header
	HasAcceptEncoding  bool `json:"has_accept_encoding"`   // Has Accept-Encoding
	HasSecClientHints  bool `json:"has_sec_ch_ua"`         // Has Sec-CH-UA headers

	// JA4H signals (HTTP fingerprint)
	HasJA4HFingerprint     bool   `json:"has_ja4h_fingerprint"`      // JA4H fingerprint available
	JA4HLanguageCode       string `json:"ja4h_language_code"`        // Language code from JA4H (e.g., "enus", "0000")
	JA4HMissingLanguage    bool   `json:"ja4h_missing_language"`     // Language code is "0000" (no Accept-Language)
	JA4HLowHeaderCount     bool   `json:"ja4h_low_header_count"`     // Header count from JA4H < 5
	JA4HHighHeaderCount    bool   `json:"ja4h_high_header_count"`    // Header count from JA4H >= 10
	JA4HHasCookies         bool   `json:"ja4h_has_cookies"`          // JA4H indicates cookies present
	JA4HHasReferer         bool   `json:"ja4h_has_referer"`          // JA4H indicates referer present
	JA4HIsHTTP2            bool   `json:"ja4h_is_http2"`             // JA4H indicates HTTP/2
	JA4HConsistentSignal   bool   `json:"ja4h_consistent_signal"`    // JA4H signals match HTTP signals
	JA4HZeroedCookieHashes bool   `json:"ja4h_zeroed_cookie_hashes"` // JA4H parts C and D are 000000000000 (no cookies)
	BrowserLikeHeaderOrder bool   `json:"browser_like_header_order"` // Accept and Accept-Language in first N positions
	SecChUAModernOrder     bool   `json:"sec_ch_ua_modern_order"`    // First brand in Sec-CH-UA is Not:A-Brand or Not_A Brand (Chrome 109+)
	HasCacheControl        bool   `json:"has_cache_control"`         // Request has Cache-Control header (browser often sends max-age=0 on navigation)
	AcceptLangRich         bool   `json:"accept_lang_rich"`          // Accept-Language has multiple locales (>=3 parts or length > 40) and varied q-values
	HasSecPurpose          bool   `json:"has_sec_purpose"`           // Sec-Purpose header present (prefetch/prerender; forbidden for JS)
	SecPurposeValid        bool   `json:"sec_purpose_valid"`         // Sec-Purpose value is prefetch or prefetch;prerender (W3C nav-speculation)

	// Proxy / HTTP/2 fingerprint (e.g. from nginx TLS termination)
	TLSFromProxy                 bool   `json:"tls_from_proxy"`                   // TLS data from trusted proxy headers
	TLSObsolete                  bool   `json:"tls_obsolete"`                     // TLS 1.0 or 1.1 (outdated client)
	TLSExoticALPN                bool   `json:"tls_exotic_alpn"`                  // ALPN is legacy/exotic (http/0.9, spdy, h2c, hq) — often bots/scanners
	NoSNI                        bool   `json:"no_sni"`                           // TLS available but no Server Name Indication (browsers send SNI for HTTPS)
	NoALPN                       bool   `json:"no_alpn"`                          // TLS available but no ALPN (modern browsers send ALPN)
	HasSSLGreased                bool   `json:"has_ssl_greased"`                  // GREASE present from proxy (X-FP-SSL-GREASED)
	HasHTTP2Fingerprint          bool   `json:"has_http2_fingerprint"`            // HTTP/2 fingerprint present
	HasHTTP2FingerprintFromProxy bool   `json:"has_http2_fingerprint_from_proxy"` // HTTP/2 fingerprint from X-FP-H2
	H2SettingsParsed             bool   `json:"h2_settings_parsed"`               // H2 fingerprint string parsed (SETTINGS, window, priority)
	H2InitialWindowSize          uint32 `json:"h2_initial_window_size"`           // SETTINGS INITIAL_WINDOW_SIZE (0 if not parsed)
	H2PriorityPresent            bool   `json:"h2_priority_present"`              // PRIORITY segment non-empty (browsers send, libs often omit)
	H2WindowUpdatePresent        bool   `json:"h2_window_update_present"`         // WINDOW_UPDATE segment non-zero (flow control; real clients send)
	H2MaxFrameSizeBrowserLike    bool   `json:"h2_max_frame_size_browser_like"`   // SETTINGS MAX_FRAME_SIZE (id 5) is 16384 or 16777215
	H2PseudoHeaderOrderPresent   bool   `json:"h2_pseudo_header_order_present"`   // fourth segment non-empty (pseudo-header order/flags; full fingerprint)
	H2JA4Inconsistent            bool   `json:"h2_ja4_inconsistent"`              // JA4 ALPN (h2/h1) disagrees with actual HTTP/2 (Appendix G)
	TLSALPNVsHTTPInconsistent    bool   `json:"tls_alpn_vs_http_inconsistent"`    // ALPN (h2/http/1.1) disagrees with request HTTP version (direct TLS only; Appendix G)

	// Request context (path/method — blind probe detection)
	RequestIsProbe bool `json:"request_is_probe"` // Path != "/" or method != "GET"; bots often probe blindly

	// Heuristic signals
	UserAgentIsBot       bool `json:"ua_is_bot"`        // UA contains bot indicators
	UserAgentIsAICrawler bool `json:"ua_is_ai_crawler"` // UA contains AI/LLM crawler indicators
	UserAgentIsBrowser   bool `json:"ua_is_browser"`    // UA looks like a browser
	LowHeaderCount       bool `json:"low_header_count"` // < 5 headers (suspicious)
	HasBrowserHeaders    bool `json:"has_browser_headers"`
	MissingTypicalHeader bool `json:"missing_typical_header"` // Missing expected headers

	// Computed
	BrowserScore   int    `json:"browser_score"`   // Score towards browser classification
	BotScore       int    `json:"bot_score"`       // Score towards bot classification
	ScoreBreakdown string `json:"score_breakdown"` // Detailed scoring explanation
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

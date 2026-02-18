package fingerprint

import "strings"

// Header-order thresholds from real browser observations (e.g. Chrome: accept-language ~9, accept ~10; bablosoft, JA4H).
const (
	browserLikeHeaderOrderMaxIdx = 12 // Accept and Accept-Language both before this index → browser-like
	headerOrderLateMinIdx        = 12 // Either at or after this index → "late" (impersonator signal)
)

// Known bot User-Agent patterns
var botPatterns = []string{
	// HTTP libraries
	"curl",
	"wget",
	"python",
	"go-http-client",
	"httpie",
	"postman",
	"insomnia",
	"axios",
	"node-fetch",
	"undici",
	"got",
	"request",
	"scrapy",
	"httpx",
	"aiohttp",
	"okhttp",
	"apache-httpclient",

	// Automation frameworks
	"puppeteer",
	"playwright",
	"selenium",
	"phantomjs",
	"headless",

	// Generic bot indicators
	"bot",
	"crawler",
	"spider",
	"scraper",

	// AI/LLM Crawlers - Training
	"gptbot",
	"chatgpt",
	"claudebot",
	"claude-web",
	"anthropic",
	"google-extended",
	"googleother",
	"ccbot",
	"cohere-ai",
	"diffbot",

	// AI/LLM Crawlers - Search/Fetcher
	"perplexitybot",
	"youbot",
	"ai2bot",
	"bytespider",
	"amazonbot",
	"applebot",
	"iaskspider",
	"phind",

	// Meta AI
	"meta-externalagent",
	"meta-externalfetcher",
	"facebookbot",

	// Microsoft AI
	"bingpreview",
}

// AI-specific patterns (subset for detailed classification)
var aiCrawlerPatterns = []string{
	"gptbot",
	"chatgpt",
	"claudebot",
	"claude-web",
	"anthropic",
	"google-extended",
	"perplexitybot",
	"cohere",
	"meta-external",
	"bytespider",
	"ccbot",
	"ai2bot",
	"youbot",
	"amazonbot",
}

// Known browser User-Agent patterns
var browserPatterns = []string{
	"mozilla",
	"chrome",
	"safari",
	"firefox",
	"edge",
	"opera",
}

// ExtractSignals analyzes fingerprint and extracts classification signals
func ExtractSignals(fp Fingerprint) Signals {
	s := Signals{}

	// Proxy / HTTP/2 fingerprint (e.g. nginx TLS termination)
	s.TLSFromProxy = fp.TLS.FromProxy
	s.TLSObsolete = fp.TLS.Version == "TLS 1.0" || fp.TLS.Version == "TLS 1.1"
	// X-FP-SSL-GREASED: nginx may send "0" when no GREASE; only non-empty and not "0"/"false" count as present
	s.HasSSLGreased = isSSLGreasedPresent(fp.TLS.SSLGreased)
	s.HasHTTP2Fingerprint = fp.HTTP.H2Fingerprint != ""
	s.HasHTTP2FingerprintFromProxy = fp.TLS.FromProxy && fp.HTTP.H2Fingerprint != ""
	if fp.HTTP.H2Parsed != nil && fp.HTTP.H2Parsed.ParsedOK {
		s.H2SettingsParsed = true
		s.H2InitialWindowSize = fp.HTTP.H2Parsed.InitialWindow
		s.H2PriorityPresent = strings.TrimSpace(fp.HTTP.H2Parsed.Priority) != ""
		s.H2WindowUpdatePresent = fp.HTTP.H2Parsed.WindowUpdate > 0
		s.H2MaxFrameSizeBrowserLike = IsBrowserLikeH2MaxFrameSize(fp.HTTP.H2Parsed.MaxFrameSize)
		s.H2PseudoHeaderOrderPresent = strings.TrimSpace(fp.HTTP.H2Parsed.PseudoHeaderOrder) != ""
	}

	// TLS/HTTP/2: needed for H2 vs JA4 check below
	s.IsHTTP2 = fp.HTTP.Version == "HTTP/2.0" || fp.TLS.ALPN == "h2" || fp.HTTP.H2Fingerprint != ""

	// H2 vs JA4: JA4 Part A contains ALPN (h2/h1); must agree with actual protocol (Appendix G)
	if fp.TLS.JA4Hash != "" {
		alpn := JA4ALPN(fp.TLS.JA4Hash)
		if alpn == "h2" && !s.IsHTTP2 {
			s.H2JA4Inconsistent = true
		}
		if alpn == "h1" && s.IsHTTP2 {
			s.H2JA4Inconsistent = true
		}
	}

	// TLS/HTTP version mismatch (Appendix G): with direct TLS, ALPN must match observed HTTP version
	if !fp.TLS.FromProxy && fp.TLS.ALPN != "" {
		switch fp.TLS.ALPN {
		case "h2":
			if fp.HTTP.Version != "HTTP/2.0" {
				s.TLSALPNVsHTTPInconsistent = true
			}
		case "http/1.1":
			if fp.HTTP.Version == "HTTP/2.0" {
				s.TLSALPNVsHTTPInconsistent = true
			}
		}
	}

	// TLS signals (from ClientHello or from proxy headers)
	s.HasModernTLS = fp.TLS.Version == "TLS 1.2" || fp.TLS.Version == "TLS 1.3"
	s.HasALPN = fp.TLS.ALPN != ""
	s.HighCipherCount = fp.TLS.CipherSuitesCount > 10 // Browsers typically have 15-20
	s.HasSessionSupport = fp.TLS.HasSessionTicket     // Session resumption
	s.HasTLSFingerprint = fp.TLS.JA3Hash != "" || fp.TLS.JA4Hash != ""
	s.TLSKnownLibrary = IsKnownLibraryTLS(fp.TLS.JA3Hash, fp.TLS.JA4Hash)
	s.TLSKnownBrowser = IsKnownBrowserTLS(fp.TLS.JA3Hash, fp.TLS.JA4Hash)
	s.HasMultipleGroups = len(fp.TLS.SupportedGroups) >= 3 // Browsers support multiple curves
	s.HasModernCiphers = fp.TLS.Version == "TLS 1.3" && fp.TLS.CipherSuitesCount > 0

	// HTTP signals
	s.HasSecFetchHeaders = fp.HTTP.SecFetchSite != "" ||
		fp.HTTP.SecFetchMode != "" ||
		fp.HTTP.SecFetchDest != ""
	s.HasAcceptLanguage = fp.HTTP.AcceptLang != ""
	s.HasUserAgent = fp.HTTP.UserAgent != ""
	s.HasAccept = fp.HTTP.Accept != ""
	s.HasAcceptEncoding = fp.HTTP.AcceptEnc != ""
	s.HasSecClientHints = fp.HTTP.SecChUA != ""

	// JA4H signals (HTTP fingerprint)
	s.HasJA4HFingerprint = fp.HTTP.JA4HHash != ""
	if s.HasJA4HFingerprint {
		extractJA4HSignals(&s, fp.HTTP.JA4HHash, fp)
	}

	// Header order: Accept and Accept-Language in first N positions (browser-like). See browserLikeHeaderOrderMaxIdx.
	s.BrowserLikeHeaderOrder = isBrowserLikeHeaderOrder(fp.HTTP.HeaderOrder, browserLikeHeaderOrderMaxIdx)

	// Sec-CH-UA: Chrome 109+ sends Not:A-Brand or Not_A Brand first; automation often sends Chromium first.
	s.SecChUAModernOrder = isSecChUAModernOrder(fp.HTTP.SecChUA)

	// Cache-Control: real Chrome often sends on document navigation; curl_cffi often omits.
	if v, ok := fp.HTTP.Headers["cache-control"]; ok && strings.TrimSpace(v) != "" {
		s.HasCacheControl = true
	}
	// Accept-Language richness: multiple locales typical for real browsers; automation often short/single locale.
	s.AcceptLangRich = acceptLangRich(fp.HTTP.AcceptLang)

	// User-Agent analysis
	uaLower := strings.ToLower(fp.HTTP.UserAgent)
	s.UserAgentIsBot = containsAny(uaLower, botPatterns)
	s.UserAgentIsAICrawler = containsAny(uaLower, aiCrawlerPatterns)
	s.UserAgentIsBrowser = containsAny(uaLower, browserPatterns) && !s.UserAgentIsBot

	// Header analysis
	s.LowHeaderCount = fp.HTTP.HeaderCount < 5
	s.HasBrowserHeaders = s.HasSecFetchHeaders || s.HasAcceptLanguage
	s.MissingTypicalHeader = !s.HasAccept || !s.HasAcceptEncoding

	// Calculate scores with breakdown
	s.BrowserScore, s.BotScore, s.ScoreBreakdown = calculateScores(s, fp)

	return s
}

// extractJA4HSignals parses JA4H fingerprint and extracts signals
// JA4H format: {method}{version}{cookie}{referer}{header_count}{language}_{hash_b}_{hash_c}_{hash_d}
// Example: ge20cn14enus_7cf2b917f4b0_000000000000_000000000000
func extractJA4HSignals(s *Signals, ja4h string, fp Fingerprint) {
	// Split by underscore to get parts
	parts := strings.Split(ja4h, "_")
	if len(parts) < 1 || len(parts[0]) < 12 {
		return
	}

	ja4hA := parts[0]

	// Extract version (positions 2-3): "11", "20", "30"
	if len(ja4hA) >= 4 {
		version := ja4hA[2:4]
		s.JA4HIsHTTP2 = version == "20" || version == "30"
	}

	// Extract cookie flag (position 4): "c" or "n"
	if len(ja4hA) >= 5 {
		s.JA4HHasCookies = ja4hA[4:5] == "c"
	}

	// Extract referer flag (position 5): "r" or "n"
	if len(ja4hA) >= 6 {
		s.JA4HHasReferer = ja4hA[5:6] == "r"
	}

	// Extract header count (positions 6-7)
	if len(ja4hA) >= 8 {
		headerCountStr := ja4hA[6:8]
		var headerCount int
		if _, err := parseHeaderCount(headerCountStr, &headerCount); err == nil {
			s.JA4HLowHeaderCount = headerCount < 5
			s.JA4HHighHeaderCount = headerCount >= 10
		}
	}

	// Extract language code (positions 8-11)
	if len(ja4hA) >= 12 {
		s.JA4HLanguageCode = ja4hA[8:12]
		s.JA4HMissingLanguage = s.JA4HLanguageCode == "0000"
	}

	// JA4H parts C and D: 12 zeros when no cookies (FoxIO spec). Used for ja4h-no-cookies bot signal.
	if len(parts) >= 4 && parts[2] == "000000000000" && parts[3] == "000000000000" {
		s.JA4HZeroedCookieHashes = true
	}

	// Check consistency between JA4H signals and HTTP signals
	// Inconsistencies may indicate fingerprint manipulation
	s.JA4HConsistentSignal = checkJA4HConsistency(s, fp)
}

// parseHeaderCount parses 2-digit header count string
func parseHeaderCount(s string, result *int) (int, error) {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	*result = n
	return n, nil
}

// checkJA4HConsistency verifies JA4H signals match HTTP signals
// Returns true if signals are consistent, false if there are discrepancies.
// When TLS is from proxy, backend sees HTTP/1.x so JA4H version is "11"/"10"; is_http2 comes from ALPN.
// We do not compare JA4H version vs is_http2 when from_proxy to avoid false inconsistency.
func checkJA4HConsistency(s *Signals, fp Fingerprint) bool {
	consistent := true

	// HTTP/2 consistency (skip when from proxy: JA4H reflects backend HTTP/1.x, not client protocol)
	if !fp.TLS.FromProxy && s.JA4HIsHTTP2 != s.IsHTTP2 {
		consistent = false
	}

	// Cookie consistency
	if s.JA4HHasCookies != fp.HTTP.HasCookies {
		consistent = false
	}

	// Referer consistency
	if s.JA4HHasReferer != fp.HTTP.HasReferer {
		consistent = false
	}

	// Accept-Language consistency
	// If JA4H says "0000" (no language), HasAcceptLanguage should be false
	if s.JA4HMissingLanguage && s.HasAcceptLanguage {
		consistent = false
	}

	return consistent
}

// calculateScores computes browser and bot scores based on signals
func calculateScores(s Signals, fp Fingerprint) (browserScore, botScore int, breakdown string) {
	var browserReasons, botReasons []string

	// ==========================================
	// Browser-positive signals
	// ==========================================

	// HTTP/2 - browsers prefer HTTP/2
	if s.IsHTTP2 {
		browserScore += 2
		browserReasons = append(browserReasons, "http2(+2)")
	}

	// HTTP/2 fingerprint present (from proxy or future native) - correlates with real clients
	if s.HasHTTP2Fingerprint {
		browserScore++
		browserReasons = append(browserReasons, "h2-fp(+1)")
	}

	// Parsed H2 fingerprint with browser-like INITIAL_WINDOW_SIZE (SETTINGS id 4)
	if s.H2SettingsParsed && IsBrowserLikeH2InitialWindow(s.H2InitialWindowSize) {
		browserScore++
		browserReasons = append(browserReasons, "h2-init-window(+1)")
	}

	// PRIORITY segment present: browsers send PRIORITY frames, many HTTP/2 libraries omit them
	if s.H2SettingsParsed && s.H2PriorityPresent {
		browserScore++
		browserReasons = append(browserReasons, "h2-priority(+1)")
	}

	// WINDOW_UPDATE present (connection-level): real clients use flow control; correlates with browser behavior
	if s.H2SettingsParsed && s.H2WindowUpdatePresent {
		browserScore++
		browserReasons = append(browserReasons, "h2-window-update(+1)")
	}

	// MAX_FRAME_SIZE (SETTINGS id 5) browser-like (16384 default or 16777215 max)
	if s.H2SettingsParsed && s.H2MaxFrameSizeBrowserLike {
		browserScore++
		browserReasons = append(browserReasons, "h2-max-frame(+1)")
	}

	// Fourth segment (pseudo-header order / flags) present: full fingerprint typical of browsers
	if s.H2SettingsParsed && s.H2PseudoHeaderOrderPresent {
		browserScore++
		browserReasons = append(browserReasons, "h2-pseudo-headers(+1)")
	}

	// Sec-Fetch-* headers — easily spoofable; reduced weight
	if s.HasSecFetchHeaders {
		browserScore++
		browserReasons = append(browserReasons, "sec-fetch(+1)")
	}

	// Accept-Language — trivial to spoof; no browser points
	_ = s.HasAcceptLanguage

	// Browser headers combination — trivial to spoof; no browser points
	_ = s.HasBrowserHeaders

	// User-Agent looks like browser — easily spoofable; reduced weight
	if s.UserAgentIsBrowser && !s.UserAgentIsBot {
		browserScore++
		browserReasons = append(browserReasons, "browser-ua(+1)")
	}

	// Sec-CH-UA client hints — easily spoofable; reduced weight
	if s.HasSecClientHints {
		browserScore++
		browserReasons = append(browserReasons, "sec-ch-ua(+1)")
	}

	// Browser-like header order: +1 only when order came from proxy (X-Original-Header-Order), else 0 (nginx reorders)
	if fp.HTTP.HeaderOrderFromProxy && s.BrowserLikeHeaderOrder {
		browserScore++
		browserReasons = append(browserReasons, "header-order(+1)")
	}

	// Sec-CH-UA modern order — easily spoofable; no browser points
	_ = s.SecChUAModernOrder

	// Cache-Control present: real Chrome often sends max-age=0 on navigation; impersonators often omit. Appendix I.
	if s.HasCacheControl {
		browserScore++
		browserReasons = append(browserReasons, "cache-control(+1)")
	}

	// Accept-Language rich — easily spoofable; no browser points
	_ = s.AcceptLangRich

	// Cookies present
	if fp.HTTP.HasCookies {
		browserScore++
		browserReasons = append(browserReasons, "cookies(+1)")
	}

	// High header count — trivial to spoof; no browser points (fp.HTTP.HeaderCount still used elsewhere)

	// Modern TLS - only count as browser signal when UA is not already a known bot (curl, etc. have modern TLS too)
	if !s.UserAgentIsBot && s.HasModernTLS {
		browserScore++
		browserReasons = append(browserReasons, "modern-tls(+1)")
	}

	// GREASE present (from proxy X-FP-SSL-GREASED) - real browsers send GREASE; optional +1 browser when TLS is modern
	if s.HasSSLGreased && s.HasModernTLS && !s.UserAgentIsBot {
		browserScore++
		browserReasons = append(browserReasons, "ssl-greased(+1)")
	}

	// TLS fingerprint signals (from ClientHello) - only when UA is not bot; CLI libraries also have rich TLS
	if !s.UserAgentIsBot && s.HasTLSFingerprint {
		// High cipher suite count - browsers offer 15-20 cipher suites
		if s.HighCipherCount {
			browserScore += 2
			browserReasons = append(browserReasons, "high-ciphers(+2)")
		}

		// Session ticket support - browsers support session resumption
		if s.HasSessionSupport {
			browserScore++
			browserReasons = append(browserReasons, "session-ticket(+1)")
		}

		// Multiple elliptic curve groups - browsers support several
		if s.HasMultipleGroups {
			browserScore++
			browserReasons = append(browserReasons, "multi-groups(+1)")
		}

		// Extensions count - browsers have many TLS extensions
		if fp.TLS.ExtensionsCount >= 10 {
			browserScore++
			browserReasons = append(browserReasons, "tls-ext>=10(+1)")
		}
	}

	// JA4H fingerprint signals (browser-positive)
	if s.HasJA4HFingerprint {
		// High header count from JA4H - browsers send many headers
		if s.JA4HHighHeaderCount {
			browserScore++
			browserReasons = append(browserReasons, "ja4h-headers>=10(+1)")
		}

		// Has referer - often present in browser navigation
		if s.JA4HHasReferer {
			browserScore++
			browserReasons = append(browserReasons, "ja4h-referer(+1)")
		}

		// Consistent signals - no fingerprint manipulation detected; skip for bot UA (minimal headers can be "consistent" too)
		if !s.UserAgentIsBot && s.JA4HConsistentSignal {
			browserScore++
			browserReasons = append(browserReasons, "ja4h-consistent(+1)")
		}
	}

	// ==========================================
	// Bot-positive signals
	// ==========================================

	// Obsolete TLS (1.0/1.1) - outdated clients, often automation or legacy
	if s.TLSObsolete {
		botScore++
		botReasons = append(botReasons, "obsolete-tls(+1)")
	}

	// Known bot User-Agent pattern
	if s.UserAgentIsBot {
		botScore += 3
		botReasons = append(botReasons, "bot-ua(+3)")
	}

	// AI/LLM crawler - extra penalty
	if s.UserAgentIsAICrawler {
		botScore += 2
		botReasons = append(botReasons, "ai-crawler(+2)")
	}

	// Low header count - bots send minimal headers
	if s.LowHeaderCount {
		botScore += 2
		botReasons = append(botReasons, "low-headers(+2)")
	}

	// Missing typical headers (Accept or Accept-Encoding) and no Sec-Fetch - strong library signal
	if s.MissingTypicalHeader && !s.HasSecFetchHeaders {
		botScore += 2
		botReasons = append(botReasons, "missing-typical(+2)")
	}

	// Missing User-Agent - smoking gun (legitimate clients always send it)
	if !s.HasUserAgent {
		botScore += 3
		botReasons = append(botReasons, "no-ua(+3)")
	}

	// HTTP/1.1 without H2 when TLS was available - many bots don't support HTTP/2.
	// Skip when TLS is not available (e.g. raw HTTP pipeline without nginx): HTTP/2 wasn't an option.
	if fp.TLS.Available && !s.IsHTTP2 && fp.HTTP.Version == "HTTP/1.1" {
		botScore++
		botReasons = append(botReasons, "http1.1(+1)")
	}

	// Generic Accept header (*/*) - typical for HTTP libraries
	if fp.HTTP.Accept == "*/*" {
		botScore++
		botReasons = append(botReasons, "accept-*/*-(+1)")
	}

	// Missing Accept-Language without Sec-Fetch
	if !s.HasAcceptLanguage && !s.HasSecFetchHeaders {
		botScore++
		botReasons = append(botReasons, "no-accept-lang(+1)")
	}

	// TLS fingerprint signals indicating bot
	if s.HasTLSFingerprint {
		// Low cipher suite count - simple HTTP clients
		if fp.TLS.CipherSuitesCount > 0 && fp.TLS.CipherSuitesCount < 10 {
			botScore++
			botReasons = append(botReasons, "low-ciphers(+1)")
		}

		// Few or no TLS extensions
		if fp.TLS.ExtensionsCount > 0 && fp.TLS.ExtensionsCount < 8 {
			botScore++
			botReasons = append(botReasons, "few-tls-ext(+1)")
		}

		// No session ticket support (skip when from proxy: session ticket not passed in X-FP-*)
		if !s.HasSessionSupport && fp.TLS.Available && !fp.TLS.FromProxy {
			botScore++
			botReasons = append(botReasons, "no-session(+1)")
		}
	}

	// JA4H fingerprint signals (bot-positive)
	// When TLS is from proxy, JA4H is computed from the request as seen by the backend (after nginx);
	// header set can differ from what the client sent, so these penalties are skipped to avoid false bot points for real browsers.
	if s.HasJA4HFingerprint && !fp.TLS.FromProxy {
		// Missing language in JA4H - bots often don't send Accept-Language
		if s.JA4HMissingLanguage {
			botScore++
			botReasons = append(botReasons, "ja4h-no-lang(+1)")
		}

		// Low header count from JA4H
		if s.JA4HLowHeaderCount {
			botScore++
			botReasons = append(botReasons, "ja4h-low-headers(+1)")
		}

		// Inconsistent signals - possible fingerprint manipulation/evasion
		if !s.JA4HConsistentSignal {
			botScore += 2
			botReasons = append(botReasons, "ja4h-inconsistent(+2)")
		}
	}

	// When TLS is from proxy but no client TLS was forwarded (HTTP→HTTP), we skip cookie/grease bot penalties.
	proxyHasClientTLS := fp.TLS.ALPN != "" || fp.TLS.JA3Hash != "" || fp.TLS.CipherSuite != ""

	// JA4H zeroed C/D with browser UA and no cookies: smoking gun for automation (e.g. curl_cffi). Strong penalty.
	// Skip when HTTP→HTTP proxy: no client TLS visible; no cookies on first request or over HTTP is normal.
	if s.UserAgentIsBrowser && !s.UserAgentIsBot && !fp.HTTP.HasCookies && s.JA4HZeroedCookieHashes &&
		!(fp.TLS.FromProxy && !proxyHasClientTLS) {
		botScore += 3
		botReasons = append(botReasons, "ja4h-no-cookies(+3)")
	}

	// Browser UA but header order not browser-like (Accept or Accept-Language late). Only when order from proxy (X-Original-Header-Order).
	if fp.HTTP.HeaderOrderFromProxy && s.UserAgentIsBrowser && !s.UserAgentIsBot && !s.BrowserLikeHeaderOrder && s.HasAcceptLanguage && s.HasAccept {
		idxAccept, idxLang := indexOfHeader(fp.HTTP.HeaderOrder, "accept"), indexOfHeader(fp.HTTP.HeaderOrder, "accept-language")
		if idxAccept >= headerOrderLateMinIdx || idxLang >= headerOrderLateMinIdx {
			botScore += 2
			botReasons = append(botReasons, "header-order-late(+2)")
		}
	}

	// H2 vs User-Agent inconsistency (Appendix G): UA claims browser but H2 fingerprint looks library-like.
	// Skip when from proxy: X-FP-H2 may omit some SETTINGS (e.g. MAX_FRAME_SIZE id 5), so isH2LibraryLike can false-positive on real browsers.
	if !fp.TLS.FromProxy && s.UserAgentIsBrowser && !s.UserAgentIsBot && s.HasHTTP2Fingerprint && isH2LibraryLike(s) {
		botScore += 2
		botReasons = append(botReasons, "h2-ua-inconsistent(+2)")
	}

	// TLS vs User-Agent inconsistency (Appendix G): UA claims browser but JA3/JA4 is known library (curl, Go, Python, etc.). Smoking gun.
	if s.UserAgentIsBrowser && !s.UserAgentIsBot && s.TLSKnownLibrary && !s.TLSKnownBrowser {
		botScore += 3
		botReasons = append(botReasons, "tls-ua-inconsistent(+3)")
	}

	// Browser UA but no GREASE when TLS from proxy: real browsers send GREASE; curl/libraries typically do not. Smoking gun.
	// Only apply when proxy actually forwarded client TLS. For HTTP→HTTP proxy, no GREASE is expected — do not penalize.
	if s.TLSFromProxy && proxyHasClientTLS && s.UserAgentIsBrowser && !s.UserAgentIsBot && !s.HasSSLGreased {
		botScore += 3
		botReasons = append(botReasons, "ua-browser-no-grease(+3)")
	}

	// TLS vs User-Agent: browser UA + known browser TLS → consistency bonus
	if s.UserAgentIsBrowser && !s.UserAgentIsBot && s.TLSKnownBrowser {
		browserScore++
		browserReasons = append(browserReasons, "tls-ua-consistent(+1)")
	}

	// TLS vs User-Agent: bot UA but JA3/JA4 is known browser (e.g. spoofed UA, real browser TLS). Smoking gun.
	if s.UserAgentIsBot && s.TLSKnownBrowser {
		botScore += 3
		botReasons = append(botReasons, "tls-ua-inconsistent(+3)")
	}

	// H2 vs JA4 inconsistency (Appendix G): JA4 says h2 but request is HTTP/1.1, or JA4 says h1 but we have HTTP/2
	if s.H2JA4Inconsistent {
		botScore += 2
		botReasons = append(botReasons, "h2-ja4-inconsistent(+2)")
	}

	// TLS/HTTP version mismatch (Appendix G): ALPN (h2/http/1.1) disagrees with request HTTP version (direct TLS only)
	if s.TLSALPNVsHTTPInconsistent {
		botScore += 2
		botReasons = append(botReasons, "tls-alpn-http-inconsistent(+2)")
	}

	// Build breakdown string
	breakdown = "BROWSER[" + strings.Join(browserReasons, " ") + "] "
	breakdown += "BOT[" + strings.Join(botReasons, " ") + "]"

	return browserScore, botScore, breakdown
}

// isH2LibraryLike returns true when H2 fingerprint is parsed but lacks key browser-like traits
// (e.g. no PRIORITY, non-browser window size). Used for H2 vs UA cross-validation (Appendix G).
func isH2LibraryLike(s Signals) bool {
	if !s.H2SettingsParsed {
		return false
	}
	// Library-like if any key browser indicator is missing
	if !s.H2PriorityPresent {
		return true
	}
	if !IsBrowserLikeH2InitialWindow(s.H2InitialWindowSize) {
		return true
	}
	if !s.H2WindowUpdatePresent {
		return true
	}
	if !s.H2MaxFrameSizeBrowserLike {
		return true
	}
	return false
}

// isSSLGreasedPresent returns true when X-FP-SSL-GREASED indicates GREASE is present.
// Nginx may send "0" when there is no GREASE; we treat empty, "0", and "false" as absent.
func isSSLGreasedPresent(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" {
		return false
	}
	if v == "0" {
		return false
	}
	if strings.EqualFold(v, "false") {
		return false
	}
	return true
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

// isBrowserLikeHeaderOrder returns true when both "accept" and "accept-language" appear in the first maxIdx positions of order (case-insensitive).
func isBrowserLikeHeaderOrder(order []string, maxIdx int) bool {
	idxAccept := indexOfHeader(order, "accept")
	idxLang := indexOfHeader(order, "accept-language")
	if idxAccept < 0 || idxLang < 0 {
		return false
	}
	return idxAccept < maxIdx && idxLang < maxIdx
}

// indexOfHeader returns the first index of name in order (lowercase comparison), or -1 if not found.
func indexOfHeader(order []string, name string) int {
	lower := strings.ToLower(name)
	for i, h := range order {
		if strings.ToLower(h) == lower {
			return i
		}
	}
	return -1
}

// isSecChUAModernOrder returns true when the first quoted brand in Sec-CH-UA is "Not:A-Brand" or "Not_A Brand" (Chrome 109+).
func isSecChUAModernOrder(secChUA string) bool {
	s := strings.TrimSpace(secChUA)
	if s == "" {
		return false
	}
	// First token: up to first comma or end; then extract quoted value.
	if idx := strings.Index(s, ","); idx >= 0 {
		s = strings.TrimSpace(s[:idx])
	}
	s = strings.TrimSpace(s)
	if len(s) < 2 || (s[0] != '"' && s[0] != '\'') {
		return false
	}
	quote := s[0]
	end := 1
	for end < len(s) && s[end] != quote {
		end++
	}
	if end >= len(s) {
		return false
	}
	first := strings.TrimSpace(s[1:end])
	firstNorm := strings.ToLower(strings.ReplaceAll(first, " ", ""))
	return firstNorm == "not:a-brand" || firstNorm == "not_abrand" || firstNorm == "not_a_brand"
}

// acceptLangRich returns true when Accept-Language has multiple locales (>= 3 comma-separated parts) or length > 40.
// Real browsers often send several locales with q-values; automation and curl_cffi often send a short single-locale value.
func acceptLangRich(acceptLang string) bool {
	s := strings.TrimSpace(acceptLang)
	if s == "" {
		return false
	}
	if len(s) > 40 {
		return true
	}
	parts := strings.Split(s, ",")
	count := 0
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			count++
		}
	}
	return count >= 3
}

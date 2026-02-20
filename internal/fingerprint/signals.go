package fingerprint

import (
	"fmt"
	"strings"
	"sync"
)

// ScoringThresholds holds numeric thresholds used in signal extraction (from scoring config).
type ScoringThresholds struct {
	BrowserLikeHeaderOrderMaxIdx int
	HeaderOrderLateMinIdx        int
	HighCipherCountMin           int
	LowCipherCountMax            int
	TLSExtBrowserMin             int
	FewTLSExtMax                 int
	SupportedGroupsMin           int
	LowHeaderCountMax            int
	JA4HLowHeaderCountMax        int
	JA4HHighHeaderCountMin       int
	AcceptLangMinLocaleParts     int
	AcceptLangMinLength          int
}

// ScoringConfig holds points and thresholds for scoring (set at startup, no dependency on config package).
type ScoringConfig struct {
	Thresholds    ScoringThresholds
	BrowserScores map[string]int
	BotScores     map[string]int
}

// defaultScoringConfig returns the same values as original hardcoded constants (fallback).
func defaultScoringConfig() ScoringConfig {
	return ScoringConfig{
		Thresholds: ScoringThresholds{
			BrowserLikeHeaderOrderMaxIdx: 12,
			HeaderOrderLateMinIdx:        12,
			HighCipherCountMin:           10,
			LowCipherCountMax:            10,
			TLSExtBrowserMin:             10,
			FewTLSExtMax:                 8,
			SupportedGroupsMin:           3,
			LowHeaderCountMax:            5,
			JA4HLowHeaderCountMax:        5,
			JA4HHighHeaderCountMin:       10,
			AcceptLangMinLocaleParts:     3,
			AcceptLangMinLength:          40,
		},
		BrowserScores: defaultBrowserScoresMap(),
		BotScores:     defaultBotScoresMap(),
	}
}

func defaultBrowserScoresMap() map[string]int {
	m := map[string]int{
		"http2": 2, "h2-fp": 1, "h2-init-window": 1, "h2-priority": 1, "h2-window-update": 1,
		"h2-max-frame": 1, "h2-pseudo-headers": 1, "sec-fetch": 1, "browser-ua": 1, "sec-ch-ua": 1,
		"header-order": 1, "cache-control": 1, "cookies": 1, "modern-tls": 1, "ssl-greased": 1,
		"high-ciphers": 2, "session-ticket": 1, "multi-groups": 1, "tls-ext>=10": 1,
		"ja4h-headers>=10": 1, "ja4h-referer": 1, "ja4h-consistent": 1, "tls-ua-consistent": 1,
		"accept-language": 0, "browser-headers": 0, "sec-ch-ua-modern": 0, "accept-lang-rich": 0, "high-header-count": 0,
		"no-bot-red-flags": 0,
	}
	return m
}

func defaultBotScoresMap() map[string]int {
	m := map[string]int{
		"obsolete-tls": 3, "exotic-alpn": 3, "blind-probe": 3, "bot-ua": 3, "ai-crawler": 2,
		"low-headers": 1, "missing-typical": 2, "no-ua": 3, "http1.1": 1, "accept-*/*": 1,
		"no-accept-lang": 1, "low-ciphers": 1, "few-tls-ext": 1, "no-session": 1,
		"ja4h-no-lang": 1, "ja4h-low-headers": 1, "ja4h-inconsistent": 2, "ja4h-no-cookies": 2,
		"header-order-late": 2, "h2-ua-inconsistent": 2, "tls-ua-inconsistent": 3,
		"ua-browser-no-grease": 3, "h2-ja4-inconsistent": 2, "tls-alpn-http-inconsistent": 2,
		"no-sni": 1, "no-alpn": 1,
	}
	return m
}

var (
	scoringConfigMu sync.RWMutex
	scoringConfig   *ScoringConfig
	defaultScoring  = defaultScoringConfig()
)

// SetScoringConfig sets the scoring config (called at server startup). If cfg is nil, defaults are used.
func SetScoringConfig(cfg *ScoringConfig) {
	scoringConfigMu.Lock()
	defer scoringConfigMu.Unlock()
	if cfg != nil {
		scoringConfig = cfg
	} else {
		scoringConfig = &defaultScoring
	}
}

func getScoringConfig() *ScoringConfig {
	scoringConfigMu.RLock()
	defer scoringConfigMu.RUnlock()
	if scoringConfig != nil {
		return scoringConfig
	}
	return &defaultScoring
}

func getThresholds() ScoringThresholds {
	return getScoringConfig().Thresholds
}

func browserScore(key string) int {
	if n, ok := getScoringConfig().BrowserScores[key]; ok {
		return n
	}
	return 0
}

func botScore(key string) int {
	if n, ok := getScoringConfig().BotScores[key]; ok {
		return n
	}
	return 0
}

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
	s.TLSExoticALPN = isExoticALPN(fp.TLS.ALPN)
	// Absence of SNI/ALPN: only when TLS is direct (not from proxy), to avoid penalizing when proxy omits headers.
	if fp.TLS.Available && !fp.TLS.FromProxy {
		s.NoSNI = strings.TrimSpace(fp.TLS.ServerName) == ""
		s.NoALPN = fp.TLS.ALPN == ""
	}
	t := getThresholds()
	highCipherMin := t.HighCipherCountMin
	if highCipherMin <= 0 {
		highCipherMin = 10
	}
	s.HighCipherCount = fp.TLS.CipherSuitesCount > highCipherMin
	s.HasSessionSupport = fp.TLS.HasSessionTicket
	s.HasTLSFingerprint = fp.TLS.JA3Hash != "" || fp.TLS.JA4Hash != ""
	s.TLSKnownLibrary = IsKnownLibraryTLS(fp.TLS.JA3Hash, fp.TLS.JA4Hash)
	s.TLSKnownBrowser = IsKnownBrowserTLS(fp.TLS.JA3Hash, fp.TLS.JA4Hash)
	groupsMin := t.SupportedGroupsMin
	if groupsMin <= 0 {
		groupsMin = 3
	}
	s.HasMultipleGroups = len(fp.TLS.SupportedGroups) >= groupsMin
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

	// Header order: Accept and Accept-Language in first N positions (browser-like).
	headerOrderMax := t.BrowserLikeHeaderOrderMaxIdx
	if headerOrderMax <= 0 {
		headerOrderMax = 12
	}
	s.BrowserLikeHeaderOrder = isBrowserLikeHeaderOrder(fp.HTTP.HeaderOrder, headerOrderMax)

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
	lowHeaderMax := t.LowHeaderCountMax
	if lowHeaderMax <= 0 {
		lowHeaderMax = 5
	}
	s.LowHeaderCount = fp.HTTP.HeaderCount < lowHeaderMax
	s.HasBrowserHeaders = s.HasSecFetchHeaders || s.HasAcceptLanguage
	s.MissingTypicalHeader = !s.HasAccept || !s.HasAcceptEncoding

	// Blind probe: path not in allowed list (/, /debug) or non-GET. /health is not scored. See server mux: /, /health, /debug.
	s.RequestIsProbe = !isAllowedPathForScoring(fp.HTTP.Path) || strings.TrimSpace(strings.ToUpper(fp.HTTP.Method)) != "GET"

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
			t := getThresholds()
			lowMax := t.JA4HLowHeaderCountMax
			if lowMax <= 0 {
				lowMax = 5
			}
			highMin := t.JA4HHighHeaderCountMin
			if highMin <= 0 {
				highMin = 10
			}
			s.JA4HLowHeaderCount = headerCount < lowMax
			s.JA4HHighHeaderCount = headerCount >= highMin
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

// addBrowser adds points for a browser signal key and appends to reasons if points > 0.
func addBrowser(reasons *[]string, key string) int {
	n := browserScore(key)
	if n > 0 {
		*reasons = append(*reasons, fmt.Sprintf("%s(+%d)", key, n))
	}
	return n
}

// addBot adds points for a bot signal key and appends to reasons if points > 0.
func addBot(reasons *[]string, key string) int {
	n := botScore(key)
	if n > 0 {
		*reasons = append(*reasons, fmt.Sprintf("%s(+%d)", key, n))
	}
	return n
}

// calculateScores computes browser and bot scores based on signals
func calculateScores(s Signals, fp Fingerprint) (browserScore, botScore int, breakdown string) {
	var browserReasons, botReasons []string
	t := getThresholds()
	tlsExtMin := t.TLSExtBrowserMin
	if tlsExtMin <= 0 {
		tlsExtMin = 10
	}
	lateIdx := t.HeaderOrderLateMinIdx
	if lateIdx <= 0 {
		lateIdx = 12
	}
	lowCipherMax := t.LowCipherCountMax
	if lowCipherMax <= 0 {
		lowCipherMax = 10
	}
	fewExtMax := t.FewTLSExtMax
	if fewExtMax <= 0 {
		fewExtMax = 8
	}

	// ==========================================
	// Browser-positive signals
	// ==========================================

	if s.IsHTTP2 {
		browserScore += addBrowser(&browserReasons, "http2")
	}
	if s.HasHTTP2Fingerprint {
		browserScore += addBrowser(&browserReasons, "h2-fp")
	}
	if s.H2SettingsParsed && IsBrowserLikeH2InitialWindow(s.H2InitialWindowSize) {
		browserScore += addBrowser(&browserReasons, "h2-init-window")
	}
	if s.H2SettingsParsed && s.H2PriorityPresent {
		browserScore += addBrowser(&browserReasons, "h2-priority")
	}
	if s.H2SettingsParsed && s.H2WindowUpdatePresent {
		browserScore += addBrowser(&browserReasons, "h2-window-update")
	}
	if s.H2SettingsParsed && s.H2MaxFrameSizeBrowserLike {
		browserScore += addBrowser(&browserReasons, "h2-max-frame")
	}
	if s.H2SettingsParsed && s.H2PseudoHeaderOrderPresent {
		browserScore += addBrowser(&browserReasons, "h2-pseudo-headers")
	}
	if s.HasSecFetchHeaders {
		browserScore += addBrowser(&browserReasons, "sec-fetch")
	}
	if s.HasAcceptLanguage {
		browserScore += addBrowser(&browserReasons, "accept-language")
	}
	if s.HasBrowserHeaders {
		browserScore += addBrowser(&browserReasons, "browser-headers")
	}
	if s.UserAgentIsBrowser && !s.UserAgentIsBot {
		browserScore += addBrowser(&browserReasons, "browser-ua")
	}
	if s.HasSecClientHints {
		browserScore += addBrowser(&browserReasons, "sec-ch-ua")
	}
	if fp.HTTP.HeaderOrderFromProxy && s.BrowserLikeHeaderOrder {
		browserScore += addBrowser(&browserReasons, "header-order")
	}
	if s.SecChUAModernOrder {
		browserScore += addBrowser(&browserReasons, "sec-ch-ua-modern")
	}
	if s.HasCacheControl {
		browserScore += addBrowser(&browserReasons, "cache-control")
	}
	if s.AcceptLangRich {
		browserScore += addBrowser(&browserReasons, "accept-lang-rich")
	}
	if fp.HTTP.HasCookies {
		browserScore += addBrowser(&browserReasons, "cookies")
	}
	if !s.UserAgentIsBot && s.HasModernTLS {
		browserScore += addBrowser(&browserReasons, "modern-tls")
	}
	if s.HasSSLGreased && s.HasModernTLS && !s.UserAgentIsBot {
		browserScore += addBrowser(&browserReasons, "ssl-greased")
	}
	if !s.UserAgentIsBot && s.HasTLSFingerprint {
		if s.HighCipherCount {
			browserScore += addBrowser(&browserReasons, "high-ciphers")
		}
		if s.HasSessionSupport {
			browserScore += addBrowser(&browserReasons, "session-ticket")
		}
		if s.HasMultipleGroups {
			browserScore += addBrowser(&browserReasons, "multi-groups")
		}
		if fp.TLS.ExtensionsCount >= tlsExtMin {
			browserScore += addBrowser(&browserReasons, "tls-ext>=10")
		}
	}
	if s.HasJA4HFingerprint {
		if s.JA4HHighHeaderCount {
			browserScore += addBrowser(&browserReasons, "ja4h-headers>=10")
		}
		if s.JA4HHasReferer {
			browserScore += addBrowser(&browserReasons, "ja4h-referer")
		}
		if !s.UserAgentIsBot && s.JA4HConsistentSignal {
			browserScore += addBrowser(&browserReasons, "ja4h-consistent")
		}
	}

	// ==========================================
	// Bot-positive signals
	// ==========================================

	if s.TLSObsolete {
		botScore += addBot(&botReasons, "obsolete-tls")
	}
	if s.TLSExoticALPN {
		botScore += addBot(&botReasons, "exotic-alpn")
	}
	if s.RequestIsProbe {
		botScore += addBot(&botReasons, "blind-probe")
	}
	if s.UserAgentIsBot {
		botScore += addBot(&botReasons, "bot-ua")
	}
	if s.UserAgentIsAICrawler {
		botScore += addBot(&botReasons, "ai-crawler")
	}
	if s.LowHeaderCount {
		botScore += addBot(&botReasons, "low-headers")
	}
	if s.MissingTypicalHeader && !s.HasSecFetchHeaders {
		botScore += addBot(&botReasons, "missing-typical")
	}
	if !s.HasUserAgent {
		botScore += addBot(&botReasons, "no-ua")
	}
	if fp.TLS.Available && !s.IsHTTP2 && fp.HTTP.Version == "HTTP/1.1" {
		botScore += addBot(&botReasons, "http1.1")
	}
	if fp.HTTP.Accept == "*/*" {
		botScore += addBot(&botReasons, "accept-*/*")
	}
	if !s.HasAcceptLanguage && !s.HasSecFetchHeaders {
		botScore += addBot(&botReasons, "no-accept-lang")
	}
	if s.HasTLSFingerprint {
		if fp.TLS.CipherSuitesCount > 0 && fp.TLS.CipherSuitesCount < lowCipherMax {
			botScore += addBot(&botReasons, "low-ciphers")
		}
		if fp.TLS.ExtensionsCount > 0 && fp.TLS.ExtensionsCount < fewExtMax {
			botScore += addBot(&botReasons, "few-tls-ext")
		}
		if !s.HasSessionSupport && fp.TLS.Available && !fp.TLS.FromProxy {
			botScore += addBot(&botReasons, "no-session")
		}
	}
	if s.HasJA4HFingerprint && !fp.TLS.FromProxy {
		if s.JA4HMissingLanguage {
			botScore += addBot(&botReasons, "ja4h-no-lang")
		}
		if s.JA4HLowHeaderCount {
			botScore += addBot(&botReasons, "ja4h-low-headers")
		}
		if !s.JA4HConsistentSignal {
			botScore += addBot(&botReasons, "ja4h-inconsistent")
		}
	}

	proxyHasClientTLS := fp.TLS.ALPN != "" || fp.TLS.JA3Hash != "" || fp.TLS.CipherSuite != ""
	if s.UserAgentIsBrowser && !s.UserAgentIsBot && !fp.HTTP.HasCookies && s.JA4HZeroedCookieHashes &&
		!(fp.TLS.FromProxy && !proxyHasClientTLS) {
		botScore += addBot(&botReasons, "ja4h-no-cookies")
	}

	if fp.HTTP.HeaderOrderFromProxy && s.UserAgentIsBrowser && !s.UserAgentIsBot && !s.BrowserLikeHeaderOrder && s.HasAcceptLanguage && s.HasAccept {
		idxAccept, idxLang := indexOfHeader(fp.HTTP.HeaderOrder, "accept"), indexOfHeader(fp.HTTP.HeaderOrder, "accept-language")
		if idxAccept >= lateIdx || idxLang >= lateIdx {
			botScore += addBot(&botReasons, "header-order-late")
		}
	}

	if !fp.TLS.FromProxy && s.UserAgentIsBrowser && !s.UserAgentIsBot && s.HasHTTP2Fingerprint && isH2LibraryLike(s) {
		botScore += addBot(&botReasons, "h2-ua-inconsistent")
	}
	if s.UserAgentIsBrowser && !s.UserAgentIsBot && s.TLSKnownLibrary && !s.TLSKnownBrowser {
		botScore += addBot(&botReasons, "tls-ua-inconsistent")
	}
	if s.TLSFromProxy && proxyHasClientTLS && s.UserAgentIsBrowser && !s.UserAgentIsBot && !s.HasSSLGreased {
		botScore += addBot(&botReasons, "ua-browser-no-grease")
	}

	if s.UserAgentIsBrowser && !s.UserAgentIsBot && s.TLSKnownBrowser {
		browserScore += addBrowser(&browserReasons, "tls-ua-consistent")
	}
	if s.UserAgentIsBot && s.TLSKnownBrowser {
		botScore += addBot(&botReasons, "tls-ua-inconsistent")
	}
	if s.H2JA4Inconsistent {
		botScore += addBot(&botReasons, "h2-ja4-inconsistent")
	}
	if s.TLSALPNVsHTTPInconsistent {
		botScore += addBot(&botReasons, "tls-alpn-http-inconsistent")
	}
	if s.NoSNI {
		botScore += addBot(&botReasons, "no-sni")
	}
	if s.NoALPN {
		botScore += addBot(&botReasons, "no-alpn")
	}

	// No smoking-gun bot signals → optional small browser bonus (tunable, default 0).
	noSmokingGun := !s.TLSObsolete && !s.TLSExoticALPN && !s.RequestIsProbe &&
		!s.UserAgentIsBot && s.HasUserAgent &&
		!(s.UserAgentIsBrowser && !s.UserAgentIsBot && s.TLSKnownLibrary && !s.TLSKnownBrowser) &&
		!(s.UserAgentIsBot && s.TLSKnownBrowser) &&
		!(s.TLSFromProxy && proxyHasClientTLS && s.UserAgentIsBrowser && !s.UserAgentIsBot && !s.HasSSLGreased)
	if noSmokingGun {
		browserScore += addBrowser(&browserReasons, "no-bot-red-flags")
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

// exoticALPNProtocols are ALPN values we accept for handshake but treat as bot signal.
var exoticALPNProtocols = map[string]bool{
	"http/0.9": true, "http/1.0": true,
	"spdy/1": true, "spdy/2": true, "spdy/3": true,
	"h2c": true, "hq": true,
}

func isExoticALPN(alpn string) bool {
	return exoticALPNProtocols[alpn]
}

// allowedPathsForScoring are paths that return 200 and run the classifier (server mux: / → HandleClassify, /debug → HandleDebug). /health is not in the list (HandleHealth does not call classifier).
var allowedPathsForScoring = map[string]bool{
	"/":      true,
	"/debug": true,
}

func isAllowedPathForScoring(path string) bool {
	return allowedPathsForScoring[path]
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

// acceptLangRich returns true when Accept-Language has multiple locales or long string (thresholds from config).
func acceptLangRich(acceptLang string) bool {
	s := strings.TrimSpace(acceptLang)
	if s == "" {
		return false
	}
	t := getThresholds()
	minLen := t.AcceptLangMinLength
	if minLen <= 0 {
		minLen = 40
	}
	if len(s) > minLen {
		return true
	}
	minParts := t.AcceptLangMinLocaleParts
	if minParts <= 0 {
		minParts = 3
	}
	parts := strings.Split(s, ",")
	count := 0
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			count++
		}
	}
	return count >= minParts
}

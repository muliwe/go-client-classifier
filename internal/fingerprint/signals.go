package fingerprint

import "strings"

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

	// TLS signals (from ClientHello fingerprint)
	s.IsHTTP2 = fp.HTTP.Version == "HTTP/2.0" || fp.TLS.ALPN == "h2"
	s.HasModernTLS = fp.TLS.Version == "TLS 1.2" || fp.TLS.Version == "TLS 1.3"
	s.HasALPN = fp.TLS.ALPN != ""
	s.HighCipherCount = fp.TLS.CipherSuitesCount > 10 // Browsers typically have 15-20
	s.HasSessionSupport = fp.TLS.HasSessionTicket     // Session resumption
	s.HasTLSFingerprint = fp.TLS.JA3Hash != "" || fp.TLS.JA4Hash != ""
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
// Returns true if signals are consistent, false if there are discrepancies
func checkJA4HConsistency(s *Signals, fp Fingerprint) bool {
	consistent := true

	// HTTP/2 consistency
	if s.JA4HIsHTTP2 != s.IsHTTP2 {
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

	// Sec-Fetch-* headers - strong browser indicator (cannot be spoofed via JS)
	if s.HasSecFetchHeaders {
		browserScore += 3
		browserReasons = append(browserReasons, "sec-fetch(+3)")
	}

	// Accept-Language - browsers always send this
	if s.HasAcceptLanguage {
		browserScore++
		browserReasons = append(browserReasons, "accept-lang(+1)")
	}

	// Browser headers combination
	if s.HasBrowserHeaders {
		browserScore++
		browserReasons = append(browserReasons, "browser-headers(+1)")
	}

	// User-Agent looks like browser (without bot patterns)
	if s.UserAgentIsBrowser && !s.UserAgentIsBot {
		browserScore += 2
		browserReasons = append(browserReasons, "browser-ua(+2)")
	}

	// Sec-CH-UA client hints - browser-specific
	if s.HasSecClientHints {
		browserScore += 2
		browserReasons = append(browserReasons, "sec-ch-ua(+2)")
	}

	// Cookies present
	if fp.HTTP.HasCookies {
		browserScore++
		browserReasons = append(browserReasons, "cookies(+1)")
	}

	// High header count - browsers send many headers
	if fp.HTTP.HeaderCount >= 10 {
		browserScore++
		browserReasons = append(browserReasons, "headers>=10(+1)")
	}

	// Modern TLS
	if s.HasModernTLS {
		browserScore++
		browserReasons = append(browserReasons, "modern-tls(+1)")
	}

	// TLS fingerprint signals (from ClientHello)
	if s.HasTLSFingerprint {
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

		// Consistent signals - no fingerprint manipulation detected
		if s.JA4HConsistentSignal {
			browserScore++
			browserReasons = append(browserReasons, "ja4h-consistent(+1)")
		}
	}

	// ==========================================
	// Bot-positive signals
	// ==========================================

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

	// Missing typical headers (without Sec-Fetch)
	if s.MissingTypicalHeader && !s.HasSecFetchHeaders {
		botScore++
		botReasons = append(botReasons, "missing-typical(+1)")
	}

	// Missing User-Agent - very suspicious
	if !s.HasUserAgent {
		botScore += 2
		botReasons = append(botReasons, "no-ua(+2)")
	}

	// HTTP/1.1 without H2 - many bots don't support HTTP/2
	if !s.IsHTTP2 && fp.HTTP.Version == "HTTP/1.1" {
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

		// No session ticket support
		if !s.HasSessionSupport && fp.TLS.Available {
			botScore++
			botReasons = append(botReasons, "no-session(+1)")
		}
	}

	// JA4H fingerprint signals (bot-positive)
	if s.HasJA4HFingerprint {
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

	// Build breakdown string
	breakdown = "BROWSER[" + strings.Join(browserReasons, " ") + "] "
	breakdown += "BOT[" + strings.Join(botReasons, " ") + "]"

	return browserScore, botScore, breakdown
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

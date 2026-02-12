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

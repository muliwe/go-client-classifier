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

	// TLS signals
	s.IsHTTP2 = fp.HTTP.Version == "HTTP/2.0" || fp.TLS.ALPN == "h2"
	s.HasModernTLS = fp.TLS.Version == "TLS 1.2" || fp.TLS.Version == "TLS 1.3"
	s.HasALPN = fp.TLS.ALPN != ""
	s.HighCipherCount = fp.TLS.CipherSuitesCount > 10
	s.HasSessionSupport = fp.TLS.HasSessionTicket

	// HTTP signals
	s.HasSecFetchHeaders = fp.HTTP.SecFetchSite != "" ||
		fp.HTTP.SecFetchMode != "" ||
		fp.HTTP.SecFetchDest != ""
	s.HasAcceptLanguage = fp.HTTP.AcceptLang != ""
	s.HasUserAgent = fp.HTTP.UserAgent != ""
	s.HasAccept = fp.HTTP.Accept != ""
	s.HasAcceptEncoding = fp.HTTP.AcceptEnc != ""

	// User-Agent analysis
	uaLower := strings.ToLower(fp.HTTP.UserAgent)
	s.UserAgentIsBot = containsAny(uaLower, botPatterns)
	s.UserAgentIsAICrawler = containsAny(uaLower, aiCrawlerPatterns)
	s.UserAgentIsBrowser = containsAny(uaLower, browserPatterns) && !s.UserAgentIsBot

	// Header analysis
	s.LowHeaderCount = fp.HTTP.HeaderCount < 5
	s.HasBrowserHeaders = s.HasSecFetchHeaders || s.HasAcceptLanguage
	s.MissingTypicalHeader = !s.HasAccept || !s.HasAcceptEncoding

	// Calculate scores
	s.BrowserScore, s.BotScore = calculateScores(s, fp)

	return s
}

// calculateScores computes browser and bot scores based on signals
func calculateScores(s Signals, fp Fingerprint) (browserScore, botScore int) {
	// Browser-positive signals
	if s.IsHTTP2 {
		browserScore += 2
	}
	if s.HasSecFetchHeaders {
		browserScore += 3 // Strong browser indicator
	}
	if s.HasAcceptLanguage {
		browserScore++
	}
	if s.HasBrowserHeaders {
		browserScore++
	}
	if s.UserAgentIsBrowser && !s.UserAgentIsBot {
		browserScore += 2
	}
	if fp.HTTP.SecChUA != "" {
		browserScore += 2 // Client hints are browser-specific
	}
	if fp.HTTP.HasCookies {
		browserScore++
	}
	if fp.HTTP.HeaderCount >= 10 {
		browserScore++ // Browsers typically send many headers
	}
	if s.HasModernTLS {
		browserScore++
	}

	// Bot-positive signals
	if s.UserAgentIsBot {
		botScore += 3
	}
	if s.LowHeaderCount {
		botScore += 2
	}
	if s.MissingTypicalHeader && !s.HasSecFetchHeaders {
		botScore++
	}
	if !s.HasUserAgent {
		botScore += 2 // Missing UA is suspicious
	}
	if !s.IsHTTP2 && fp.HTTP.Version == "HTTP/1.1" {
		botScore++ // Many bots use HTTP/1.1
	}
	if fp.HTTP.Accept == "*/*" {
		botScore++ // Generic accept header
	}
	if !s.HasAcceptLanguage && !s.HasSecFetchHeaders {
		botScore++ // Browsers always send Accept-Language
	}

	return browserScore, botScore
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

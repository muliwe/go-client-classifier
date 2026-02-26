package unit

import (
	"strings"
	"testing"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
	"github.com/muliwe/go-client-classifier/internal/metrics"
)

func TestClassifierDefaultConfig(t *testing.T) {
	cfg := classifier.DefaultConfig()
	if cfg.Threshold != 4 {
		t.Errorf("DefaultConfig().Threshold = %d, want 4", cfg.Threshold)
	}
}

func TestClassifierNew(t *testing.T) {
	cfg := classifier.Config{Threshold: 5}
	c := classifier.New(cfg)
	if c == nil {
		t.Fatal("New() returned nil")
	}
}

func TestClassify_CurlBot(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())

	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version:     "HTTP/1.1",
			UserAgent:   "curl/8.0.1",
			Accept:      "*/*",
			HeaderCount: 3,
			JA4HHash:    "ge11nn030000_abc123def456_000000000000_000000000000",
		},
	}

	result := c.Classify(fp)

	if result.Classification != classifier.ClassificationBot {
		t.Errorf("Classify(curl) = %s, want %s", result.Classification, classifier.ClassificationBot)
	}
	if result.Score >= 0 {
		t.Errorf("Classify(curl) score = %d, want negative", result.Score)
	}
	if result.RequestID == "" {
		t.Error("Classify() should generate RequestID")
	}
}

func TestClassify_Browser(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())

	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Method:       "GET",
			Path:         "/",
			Version:      "HTTP/2.0",
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
			Accept:       "text/html,application/xhtml+xml",
			AcceptLang:   "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6",
			AcceptEnc:    "gzip, deflate, br",
			SecFetchSite: "none",
			SecFetchMode: "navigate",
			SecFetchDest: "document",
			SecChUA:      `"Chromium";v="120"`,
			HeaderCount:  14,
			HasCookies:   true, // avoid ja4h-no-cookies(+3) so real-browser-like fp stays browser
			JA4HHash:     "ge20nn14enus_abc123def456_000000000000_000000000000",
		},
		TLS: fingerprint.TLSFingerprint{
			Version:           "TLS 1.3",
			ALPN:              "h2",
			ServerName:        "example.com",
			CipherSuitesCount: 16,
			ExtensionsCount:   18,
			HasSessionTicket:  true,
			SupportedGroups:   []string{"x25519", "secp256r1", "secp384r1"},
			JA3Hash:           "abc123",
			JA4Hash:           "def456",
			Available:         true,
		},
	}

	result := c.Classify(fp)

	if result.Classification != classifier.ClassificationBrowser {
		t.Errorf("Classify(browser) = %s, want %s", result.Classification, classifier.ClassificationBrowser)
	}
	if result.Score <= 0 {
		t.Errorf("Classify(browser) score = %d, want positive", result.Score)
	}
}

func TestClassify_AICrawler(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())

	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version:     "HTTP/1.1",
			UserAgent:   "Mozilla/5.0 compatible; GPTBot/1.0",
			Accept:      "*/*",
			HeaderCount: 4,
			JA4HHash:    "ge11nn040000_abc123def456_000000000000_000000000000",
		},
	}

	result := c.Classify(fp)

	if result.Classification != classifier.ClassificationBot {
		t.Errorf("Classify(GPTBot) = %s, want %s", result.Classification, classifier.ClassificationBot)
	}
	if !result.Signals.UserAgentIsAICrawler {
		t.Error("Classify(GPTBot) should detect AI crawler")
	}
}

func TestClassify_JA4HSignals(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())

	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version:     "HTTP/1.1",
			UserAgent:   "test",
			HeaderCount: 3,
			JA4HHash:    "ge20nn14enus_abc123def456_000000000000_000000000000",
		},
	}

	result := c.Classify(fp)

	if !result.Signals.HasJA4HFingerprint {
		t.Error("Should have JA4H fingerprint")
	}
}

func TestClassify_ReturnsValidResult(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())

	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version: "HTTP/1.1",
		},
	}

	result := c.Classify(fp)

	if result.RequestID == "" {
		t.Error("RequestID should not be empty")
	}
	if result.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
	if result.Classification != classifier.ClassificationBrowser && result.Classification != classifier.ClassificationBot {
		t.Errorf("Classification should be browser or bot, got %s", result.Classification)
	}
	if result.Confidence < 0.5 || result.Confidence > 0.99 {
		t.Errorf("Confidence should be 0.5-0.99, got %f", result.Confidence)
	}
	if result.Reason == "" {
		t.Error("Reason should not be empty")
	}
}

func TestClassify_ReasonContainsJA4H(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())

	// Bot with JA4H inconsistency
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version:    "HTTP/2.0",
			HasCookies: true,
			AcceptLang: "en-US",
			JA4HHash:   "ge11nr050000_abc123def456_000000000000_000000000000", // Says HTTP/1.1, referer, no cookies
		},
	}

	result := c.Classify(fp)

	// Should mention JA4H in breakdown
	if !strings.Contains(result.Signals.ScoreBreakdown, "ja4h") {
		t.Errorf("Score breakdown should mention JA4H, got: %s", result.Signals.ScoreBreakdown)
	}
}

func TestClassify_ImpersonateLikeFingerprint_ClassifiedAsBot(t *testing.T) {
	// Fingerprint similar to curl_cffi impersonating Chrome: browser UA, Sec-Fetch, H2 from proxy,
	// no cookies, JA4H zeroed C/D, late accept/accept-language order. With signals (ja4h-no-cookies +3,
	// header-order-late, ua-browser-no-grease) net score should be <= threshold → bot.
	c := classifier.New(classifier.DefaultConfig())
	order := make([]string, 26)
	for i := range order {
		order[i] = "x"
	}
	order[10] = "accept"
	order[24] = "accept-language"
	order[0] = "x-forwarded-for"
	order[1] = "x-fp-ja3-hash"
	order[2] = "sec-fetch-site"
	order[3] = "sec-fetch-mode"
	order[4] = "sec-fetch-dest"
	order[5] = "user-agent"
	order[6] = "accept-encoding"
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Version:    "TLS 1.3",
			ALPN:       "h2",
			FromProxy:  true,
			JA3Hash:    "88ddb7c9e8f79ce9a304f01221a4e3a3", // curl_cffi Chrome profile (reference_bot_curl_cffi.json); in knownLibraryJA3 → tls-ua-inconsistent
			SSLGreased: "",                                 // no GREASE → ua-browser-no-grease(+3) so net drops below threshold
		},
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder:   order,
			HeaderCount:   len(order),
			UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/142.0.0.0 Safari/537.36",
			Accept:        "text/html,application/xhtml+xml",
			AcceptLang:    "en-US,en;q=0.9",
			AcceptEnc:     "gzip, deflate, br, zstd",
			SecFetchSite:  "none",
			SecFetchMode:  "navigate",
			SecFetchDest:  "document",
			HasCookies:    false,
			JA4HHash:      "ge11nn25enus_fc343ccb8320_000000000000_000000000000",
			H2Fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p",
		},
	}
	fp.HTTP.H2Parsed = fingerprint.ParseH2Fingerprint(fp.HTTP.H2Fingerprint)
	result := c.Classify(fp)
	if result.Classification != classifier.ClassificationBot {
		t.Errorf("Impersonate-like fingerprint (no cookies, zeroed JA4H C/D, late header order, no GREASE) should be classified bot, got %s (net score %d)", result.Classification, result.Score)
	}
	if result.Score > 8 {
		t.Errorf("Impersonate-like fingerprint net score should be <= 8 for bot classification, got %d", result.Score)
	}
}

var defaultBehavioralEdges = classifier.BehavioralEdges{
	RequestRatePerMinAbove:      1.2,
	InterArrivalMedianSecBelow:  3.0,
	InterArrivalStdPerMeanAbove: 1.4,
	MeanMedianRatioAbove:        1.15,
}

var defaultBehavioralBotScores = map[string]int{
	"high-request-rate":           1,
	"low-inter-arrival-median":    1,
	"high-inter-arrival-variance": 1,
	"mean-above-median":           1,
}

func TestApplyBehavioralSignals_nilMetrics_noChange(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())
	fp := fingerprint.Fingerprint{HTTP: fingerprint.HTTPFingerprint{UserAgent: "curl/7.0", HeaderCount: 2}}
	result := c.Classify(fp)
	beforeScore := result.Score
	beforeClass := result.Classification
	c.ApplyBehavioralSignals(&result, nil, defaultBehavioralEdges, defaultBehavioralBotScores)
	if result.Score != beforeScore || result.Classification != beforeClass {
		t.Errorf("ApplyBehavioralSignals(nil metrics) should not change result; got score %d (was %d), class %s (was %s)", result.Score, beforeScore, result.Classification, beforeClass)
	}
}

func TestApplyBehavioralSignals_nilBotScores_noChange(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())
	fp := fingerprint.Fingerprint{HTTP: fingerprint.HTTPFingerprint{UserAgent: "curl/7.0", HeaderCount: 2}}
	result := c.Classify(fp)
	beforeScore := result.Score
	metrics := &metrics.RequestMetrics{IPDerived: &metrics.DerivedStats{RequestRatePerMin: 5.0}}
	c.ApplyBehavioralSignals(&result, metrics, defaultBehavioralEdges, nil)
	if result.Score != beforeScore {
		t.Errorf("ApplyBehavioralSignals(nil botScores) should not change result; got score %d (was %d)", result.Score, beforeScore)
	}
}

func TestApplyBehavioralSignals_highRequestRate_addsBotScore(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())
	fp := fingerprint.Fingerprint{HTTP: fingerprint.HTTPFingerprint{UserAgent: "curl/7.0", HeaderCount: 2}}
	result := c.Classify(fp)
	beforeScore := result.Score
	metrics := &metrics.RequestMetrics{
		IPRequestCount: 10,
		IPDerived: &metrics.DerivedStats{
			RequestRatePerMin:     2.0,
			InterArrivalMedianSec: 1.0,
			InterArrivalMeanSec:   1.0,
			InterArrivalStdSec:    0.5,
		},
	}
	c.ApplyBehavioralSignals(&result, metrics, defaultBehavioralEdges, defaultBehavioralBotScores)
	if result.Score >= beforeScore {
		t.Errorf("ApplyBehavioralSignals(rate 2.0 > 1.2) should add bot score; before %d after %d", beforeScore, result.Score)
	}
	if !strings.Contains(result.Reason, "behavioral: high-request-rate") {
		t.Errorf("Reason should mention behavioral: high-request-rate, got %q", result.Reason)
	}
}

func TestApplyBehavioralSignals_lowInterArrivalMedian_addsBotScore(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())
	fp := fingerprint.Fingerprint{HTTP: fingerprint.HTTPFingerprint{UserAgent: "curl/7.0", HeaderCount: 2}}
	result := c.Classify(fp)
	beforeScore := result.Score
	metrics := &metrics.RequestMetrics{
		IPRequestCount: 2,
		IPDerived: &metrics.DerivedStats{
			RequestRatePerMin:     0.5,
			InterArrivalMedianSec: 1.5,
			InterArrivalMeanSec:   1.5,
			InterArrivalStdSec:    0.3,
		},
	}
	c.ApplyBehavioralSignals(&result, metrics, defaultBehavioralEdges, defaultBehavioralBotScores)
	if result.Score >= beforeScore {
		t.Errorf("ApplyBehavioralSignals(median 1.5 < 3.0) should add bot score; before %d after %d", beforeScore, result.Score)
	}
	if !strings.Contains(result.Reason, "behavioral: low-inter-arrival-median") {
		t.Errorf("Reason should mention low-inter-arrival-median, got %q", result.Reason)
	}
}

func TestApplyBehavioralSignals_highVariance_addsBotScore(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())
	fp := fingerprint.Fingerprint{HTTP: fingerprint.HTTPFingerprint{UserAgent: "curl/7.0", HeaderCount: 2}}
	result := c.Classify(fp)
	beforeScore := result.Score
	// std/mean = 2.0/1.0 = 2.0 > 1.4
	metrics := &metrics.RequestMetrics{
		IPRequestCount: 2,
		IPDerived: &metrics.DerivedStats{
			RequestRatePerMin:     0.5,
			InterArrivalMedianSec: 2.0,
			InterArrivalMeanSec:   1.0,
			InterArrivalStdSec:    2.0,
		},
	}
	c.ApplyBehavioralSignals(&result, metrics, defaultBehavioralEdges, defaultBehavioralBotScores)
	if result.Score >= beforeScore {
		t.Errorf("ApplyBehavioralSignals(std/mean 2.0 > 1.4) should add bot score; before %d after %d", beforeScore, result.Score)
	}
	if !strings.Contains(result.Reason, "behavioral: high-inter-arrival-variance") {
		t.Errorf("Reason should mention high-inter-arrival-variance, got %q", result.Reason)
	}
}

func TestApplyBehavioralSignals_meanAboveMedian_addsBotScore(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())
	fp := fingerprint.Fingerprint{HTTP: fingerprint.HTTPFingerprint{UserAgent: "curl/7.0", HeaderCount: 2}}
	result := c.Classify(fp)
	beforeScore := result.Score
	// mean/median = 2.0/1.0 = 2.0 > 1.15
	metrics := &metrics.RequestMetrics{
		IPRequestCount: 2,
		IPDerived: &metrics.DerivedStats{
			RequestRatePerMin:     0.5,
			InterArrivalMedianSec: 1.0,
			InterArrivalMeanSec:   2.0,
			InterArrivalStdSec:    0.5,
		},
	}
	c.ApplyBehavioralSignals(&result, metrics, defaultBehavioralEdges, defaultBehavioralBotScores)
	if result.Score >= beforeScore {
		t.Errorf("ApplyBehavioralSignals(mean/median 2.0 > 1.15) should add bot score; before %d after %d", beforeScore, result.Score)
	}
	if !strings.Contains(result.Reason, "behavioral: mean-above-median") {
		t.Errorf("Reason should mention mean-above-median, got %q", result.Reason)
	}
}

func TestApplyBehavioralSignals_singleRequest_noInterArrivalSignals(t *testing.T) {
	c := classifier.New(classifier.DefaultConfig())
	fp := fingerprint.Fingerprint{HTTP: fingerprint.HTTPFingerprint{UserAgent: "curl/7.0", HeaderCount: 2}}
	result := c.Classify(fp)
	beforeScore := result.Score
	metrics := &metrics.RequestMetrics{
		IPRequestCount: 1,
		IPDerived: &metrics.DerivedStats{
			RequestRatePerMin:     0.5,
			InterArrivalMedianSec: 1.0,
			InterArrivalMeanSec:   1.0,
		},
	}
	c.ApplyBehavioralSignals(&result, metrics, defaultBehavioralEdges, defaultBehavioralBotScores)
	if result.Score != beforeScore {
		t.Errorf("ApplyBehavioralSignals(IPRequestCount=1) should not add inter-arrival signals; before %d after %d", beforeScore, result.Score)
	}
}

package unit

import (
	"strings"
	"testing"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

func TestClassifierDefaultConfig(t *testing.T) {
	cfg := classifier.DefaultConfig()
	if cfg.Threshold != 0 {
		t.Errorf("DefaultConfig().Threshold = %d, want 0", cfg.Threshold)
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
			Version:      "HTTP/2.0",
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
			Accept:       "text/html,application/xhtml+xml",
			AcceptLang:   "en-US,en;q=0.9",
			AcceptEnc:    "gzip, deflate, br",
			SecFetchSite: "none",
			SecFetchMode: "navigate",
			SecFetchDest: "document",
			SecChUA:      `"Chromium";v="120"`,
			HeaderCount:  14,
			JA4HHash:     "ge20nn14enus_abc123def456_000000000000_000000000000",
		},
		TLS: fingerprint.TLSFingerprint{
			Version:           "TLS 1.3",
			ALPN:              "h2",
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

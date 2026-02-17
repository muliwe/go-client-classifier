package classifier

import (
	"time"

	"github.com/muliwe/go-client-classifier/internal/fingerprint"

	"github.com/google/uuid"
)

const (
	ClassificationBrowser = "browser"
	ClassificationBot     = "bot"
)

// Classifier performs client classification based on fingerprint signals
type Classifier struct {
	threshold int // Score threshold for classification
}

// Config holds classifier configuration
type Config struct {
	// Threshold determines the cutoff for classification
	// Net score (browser - bot) >= threshold = browser; otherwise = bot.
	// Real browsers typically yield net score >= 8; raising threshold reduces false browser classification (e.g. curl with many headers).
	Threshold int
}

// DefaultConfig returns default classifier configuration
func DefaultConfig() Config {
	return Config{
		Threshold: 8, // Require clear browser lead; real browsers typically score >= 8 net
	}
}

// New creates a new classifier
func New(cfg Config) *Classifier {
	return &Classifier{
		threshold: cfg.Threshold,
	}
}

// Classify analyzes a fingerprint and returns classification result
func (c *Classifier) Classify(fp fingerprint.Fingerprint) fingerprint.ClassificationResult {
	signals := fingerprint.ExtractSignals(fp)
	netScore := signals.BrowserScore - signals.BotScore

	classification := ClassificationBot
	var reason string
	switch {
	case netScore > c.threshold:
		classification = ClassificationBrowser
		reason = c.browserReason(signals)
	case netScore < c.threshold:
		reason = c.botReason(signals)
	default:
		// netScore == threshold: use User-Agent so that curl/python etc. with many headers stay bot
		if signals.UserAgentIsBot {
			reason = c.botReason(signals)
		} else {
			classification = ClassificationBrowser
			reason = c.browserReason(signals)
		}
	}

	confidence := c.calculateConfidence(signals, netScore)

	return fingerprint.ClassificationResult{
		RequestID:      uuid.New().String(),
		Timestamp:      time.Now().UTC(),
		Classification: classification,
		Confidence:     confidence,
		Fingerprint:    fp,
		Signals:        signals,
		Score:          netScore,
		Reason:         reason,
	}
}

// browserReason generates explanation for browser classification
func (c *Classifier) browserReason(s fingerprint.Signals) string {
	reasons := []string{}

	if s.HasSecFetchHeaders {
		reasons = append(reasons, "has Sec-Fetch headers")
	}
	if s.IsHTTP2 {
		reasons = append(reasons, "uses HTTP/2")
	}
	if s.UserAgentIsBrowser {
		reasons = append(reasons, "browser User-Agent")
	}
	if s.HasBrowserHeaders {
		reasons = append(reasons, "has browser-specific headers")
	}
	if s.HasJA4HFingerprint && s.JA4HConsistentSignal {
		reasons = append(reasons, "consistent JA4H fingerprint")
	}
	if s.JA4HHighHeaderCount {
		reasons = append(reasons, "high header count (JA4H)")
	}
	if s.HasHTTP2Fingerprint {
		reasons = append(reasons, "HTTP/2 fingerprint present")
	}

	if len(reasons) == 0 {
		return "Classified as browser based on overall signal score"
	}

	result := "Browser indicators: "
	for i, r := range reasons {
		if i > 0 {
			result += ", "
		}
		result += r
	}
	return result
}

// botReason generates explanation for bot classification
func (c *Classifier) botReason(s fingerprint.Signals) string {
	reasons := []string{}

	if s.UserAgentIsBot {
		reasons = append(reasons, "bot User-Agent pattern")
	}
	if s.UserAgentIsAICrawler {
		reasons = append(reasons, "AI/LLM crawler pattern")
	}
	if s.LowHeaderCount {
		reasons = append(reasons, "low header count")
	}
	if !s.HasUserAgent {
		reasons = append(reasons, "missing User-Agent")
	}
	if !s.HasSecFetchHeaders && !s.HasAcceptLanguage {
		reasons = append(reasons, "missing browser headers")
	}
	if s.MissingTypicalHeader {
		reasons = append(reasons, "missing typical headers")
	}
	if s.HasJA4HFingerprint && !s.JA4HConsistentSignal {
		reasons = append(reasons, "inconsistent JA4H fingerprint")
	}
	if s.TLSKnownLibrary && s.UserAgentIsBrowser {
		reasons = append(reasons, "TLS fingerprint matches known library (TLS vs UA inconsistent)")
	}
	if s.TLSKnownBrowser && s.UserAgentIsBot {
		reasons = append(reasons, "TLS fingerprint matches browser but UA claims bot (TLS vs UA inconsistent)")
	}
	if s.H2JA4Inconsistent {
		reasons = append(reasons, "HTTP/2 vs JA4 ALPN inconsistent")
	}
	if s.TLSALPNVsHTTPInconsistent {
		reasons = append(reasons, "TLS ALPN vs HTTP version mismatch")
	}
	if s.JA4HMissingLanguage {
		reasons = append(reasons, "no Accept-Language (JA4H)")
	}
	if s.JA4HLowHeaderCount {
		reasons = append(reasons, "low header count (JA4H)")
	}

	if len(reasons) == 0 {
		return "Classified as bot based on overall signal score"
	}

	result := "Bot indicators: "
	for i, r := range reasons {
		if i > 0 {
			result += ", "
		}
		result += r
	}
	return result
}

// calculateConfidence computes confidence score based on signal strength
func (c *Classifier) calculateConfidence(s fingerprint.Signals, netScore int) float64 {
	totalSignals := s.BrowserScore + s.BotScore
	if totalSignals == 0 {
		return 0.5 // No signals, uncertain
	}

	// Calculate confidence based on score magnitude and signal count
	absScore := netScore
	if absScore < 0 {
		absScore = -absScore
	}

	// Base confidence from score ratio
	confidence := float64(absScore) / float64(totalSignals)

	// Adjust for total signal count (more signals = more confident)
	if totalSignals >= 5 {
		confidence = min(confidence*1.2, 1.0)
	} else if totalSignals < 3 {
		confidence *= 0.8
	}

	// Clamp to 0.5-0.99 range
	confidence = max(0.5, min(0.99, 0.5+confidence*0.49))

	return confidence
}

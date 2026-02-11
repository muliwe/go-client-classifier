package classifier

import (
	"time"

	"github.com/muliwe/go-client-slassifier/internal/fingerprint"

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
	// Positive net score (browser - bot) >= threshold = browser
	// Otherwise = bot
	Threshold int
}

// DefaultConfig returns default classifier configuration
func DefaultConfig() Config {
	return Config{
		Threshold: 0, // If browser score > bot score, classify as browser
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
	if netScore >= c.threshold {
		classification = ClassificationBrowser
		reason = c.browserReason(signals)
	} else {
		reason = c.botReason(signals)
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

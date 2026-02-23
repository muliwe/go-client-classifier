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

// ConfidenceParams holds parameters for confidence calculation (from scoring config).
type ConfidenceParams struct {
	NoSignal              float64
	HighSignalsThreshold  int
	HighSignalsMultiplier float64
	LowSignalsThreshold   int
	LowSignalsMultiplier  float64
	Min, Max              float64
}

// Classifier performs client classification based on fingerprint signals
type Classifier struct {
	cfg Config
}

// Config holds classifier configuration (from scoring config or defaults).
type Config struct {
	// BotScoreWeight multiplies bot_score; net = browser - BotScoreWeight*bot.
	BotScoreWeight int
	// Threshold: net score must be > threshold for browser.
	Threshold int
	// Confidence params for calculateConfidence (optional; zero value uses built-in defaults).
	Confidence ConfidenceParams
	// Client Hints challenge (Appendix K): bot score added when challenge failed; 0 = no challenge scoring.
	ChallengeFailedBotScore int
	// Client Hints challenge: browser score added when challenge passed; 0 = no bonus.
	ChallengePassedBrowserScore int
}

// DefaultConfig returns default classifier configuration (fallback when config load fails).
func DefaultConfig() Config {
	return Config{
		BotScoreWeight:              4,
		Threshold:                   4,
		ChallengeFailedBotScore:     2,
		ChallengePassedBrowserScore: 1,
		Confidence: ConfidenceParams{
			NoSignal:              0.5,
			HighSignalsThreshold:  5,
			HighSignalsMultiplier: 1.2,
			LowSignalsThreshold:   3,
			LowSignalsMultiplier:  0.8,
			Min:                   0.5,
			Max:                   0.99,
		},
	}
}

// New creates a new classifier
func New(cfg Config) *Classifier {
	return &Classifier{cfg: cfg}
}

// Classify analyzes a fingerprint and returns classification result
func (c *Classifier) Classify(fp fingerprint.Fingerprint) fingerprint.ClassificationResult {
	signals := fingerprint.ExtractSignals(fp)
	weight := c.cfg.BotScoreWeight
	if weight <= 0 {
		weight = 4
	}
	netScore := signals.BrowserScore - weight*signals.BotScore

	threshold := c.cfg.Threshold
	classification := ClassificationBot
	var reason string
	switch {
	case netScore > threshold:
		classification = ClassificationBrowser
		reason = c.browserReason(signals)
	case netScore < threshold:
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
	if s.RequestIsProbe {
		reasons = append(reasons, "blind probe (non-GET or non-root path)")
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

// ApplyChallengeSignal applies the Client Hints behavioral challenge outcome to the classification result.
// When applicable is true and passed is false, bot score is increased and classification may flip to bot.
// When applicable is true and passed is true, a small browser score may be added (see scoring config).
func (c *Classifier) ApplyChallengeSignal(result *fingerprint.ClassificationResult, passed, applicable bool) {
	result.Signals.CHChallengePassed = applicable && passed
	result.Signals.CHChallengeFailed = applicable && !passed
	if !applicable {
		return
	}
	weight := c.cfg.BotScoreWeight
	if weight <= 0 {
		weight = 4
	}
	if !passed {
		add := c.cfg.ChallengeFailedBotScore
		if add <= 0 {
			add = 2
		}
		result.Signals.BotScore += add
		result.Score = result.Signals.BrowserScore - weight*result.Signals.BotScore
		if result.Score <= c.cfg.Threshold && result.Classification == ClassificationBrowser {
			result.Classification = ClassificationBot
			result.Reason += "; Client Hints challenge failed (cookie/hints mismatch or not sent)"
		} else if result.Classification == ClassificationBot {
			result.Reason += "; Client Hints challenge failed"
		}
	} else {
		if c.cfg.ChallengePassedBrowserScore > 0 {
			result.Signals.BrowserScore += c.cfg.ChallengePassedBrowserScore
		}
		result.Score = result.Signals.BrowserScore - weight*result.Signals.BotScore
	}
}

// calculateConfidence computes confidence score based on signal strength
func (c *Classifier) calculateConfidence(s fingerprint.Signals, netScore int) float64 {
	p := c.cfg.Confidence
	noSig := p.NoSignal
	if noSig == 0 {
		noSig = 0.5
	}
	highThr := p.HighSignalsThreshold
	if highThr <= 0 {
		highThr = 5
	}
	highMul := p.HighSignalsMultiplier
	if highMul == 0 {
		highMul = 1.2
	}
	lowThr := p.LowSignalsThreshold
	if lowThr <= 0 {
		lowThr = 3
	}
	lowMul := p.LowSignalsMultiplier
	if lowMul == 0 {
		lowMul = 0.8
	}
	minC, maxC := p.Min, p.Max
	if minC == 0 {
		minC = 0.5
	}
	if maxC == 0 {
		maxC = 0.99
	}

	totalSignals := s.BrowserScore + s.BotScore
	if totalSignals == 0 {
		return noSig
	}

	absScore := netScore
	if absScore < 0 {
		absScore = -absScore
	}
	confidence := float64(absScore) / float64(totalSignals)
	if totalSignals >= highThr {
		confidence = min(confidence*highMul, 1.0)
	} else if totalSignals < lowThr {
		confidence *= lowMul
	}
	confidence = minC + confidence*(maxC-minC)
	return max(minC, min(maxC, confidence))
}

package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/muliwe/go-client-classifier/internal/classifier"
	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

// ScoringConfig is the root of the scoring JSON config (points, thresholds, classifier).
type ScoringConfig struct {
	Classifier    ClassifierConfig `json:"classifier"`
	Confidence    ConfidenceConfig `json:"confidence"`
	Thresholds    ThresholdsConfig `json:"thresholds"`
	BrowserScores map[string]int   `json:"browser_scores"`
	BotScores     map[string]int   `json:"bot_scores"`
}

// ClassifierConfig holds classifier weights and threshold.
type ClassifierConfig struct {
	BotScoreWeight int `json:"bot_score_weight"`
	Threshold      int `json:"threshold"`
}

// ConfidenceConfig holds confidence calculation parameters.
type ConfidenceConfig struct {
	NoSignal              float64 `json:"no_signal"`
	HighSignalsThreshold  int     `json:"high_signals_threshold"`
	HighSignalsMultiplier float64 `json:"high_signals_multiplier"`
	LowSignalsThreshold   int     `json:"low_signals_threshold"`
	LowSignalsMultiplier  float64 `json:"low_signals_multiplier"`
	Min                   float64 `json:"min"`
	Max                   float64 `json:"max"`
}

// ThresholdsConfig holds all numeric thresholds used in signal extraction and scoring.
type ThresholdsConfig struct {
	BrowserLikeHeaderOrderMaxIdx int `json:"browser_like_header_order_max_idx"`
	HeaderOrderLateMinIdx        int `json:"header_order_late_min_idx"`
	HighCipherCountMin           int `json:"high_cipher_count_min"`
	LowCipherCountMax            int `json:"low_cipher_count_max"`
	TLSExtBrowserMin             int `json:"tls_ext_browser_min"`
	FewTLSExtMax                 int `json:"few_tls_ext_max"`
	SupportedGroupsMin           int `json:"supported_groups_min"`
	LowHeaderCountMax            int `json:"low_header_count_max"`
	JA4HLowHeaderCountMax        int `json:"ja4h_low_header_count_max"`
	JA4HHighHeaderCountMin       int `json:"ja4h_high_header_count_min"`
	AcceptLangMinLocaleParts     int `json:"accept_lang_min_locale_parts"`
	AcceptLangMinLength          int `json:"accept_lang_min_length"`
}

// DefaultScoringConfig returns the same values as current hardcoded constants (fallback).
func DefaultScoringConfig() ScoringConfig {
	return ScoringConfig{
		Classifier: ClassifierConfig{
			BotScoreWeight: 4,
			Threshold:      4,
		},
		Confidence: ConfidenceConfig{
			NoSignal:              0.5,
			HighSignalsThreshold:  5,
			HighSignalsMultiplier: 1.2,
			LowSignalsThreshold:   3,
			LowSignalsMultiplier:  0.8,
			Min:                   0.5,
			Max:                   0.99,
		},
		Thresholds: ThresholdsConfig{
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
		BrowserScores: defaultBrowserScores(),
		BotScores:     defaultBotScores(),
	}
}

func defaultBrowserScores() map[string]int {
	return map[string]int{
		"http2":             2,
		"h2-fp":             1,
		"h2-init-window":    1,
		"h2-priority":       1,
		"h2-window-update":  1,
		"h2-max-frame":      1,
		"h2-pseudo-headers": 1,
		"sec-fetch":         1,
		"browser-ua":        1,
		"sec-ch-ua":         1,
		"header-order":      1,
		"cache-control":     1,
		"cookies":           1,
		"modern-tls":        1,
		"ssl-greased":       1,
		"high-ciphers":      2,
		"session-ticket":    1,
		"multi-groups":      1,
		"tls-ext>=10":       1,
		"ja4h-headers>=10":  1,
		"ja4h-referer":      1,
		"ja4h-consistent":   1,
		"tls-ua-consistent": 1,
		// zero points (documented in config, tunable later)
		"accept-language":   0,
		"browser-headers":   0,
		"sec-ch-ua-modern":  0,
		"accept-lang-rich":  0,
		"high-header-count": 0,
		"no-bot-red-flags":  0,
	}
}

func defaultBotScores() map[string]int {
	return map[string]int{
		"obsolete-tls":               3,
		"exotic-alpn":                3,
		"blind-probe":                3,
		"bot-ua":                     3,
		"ai-crawler":                 2,
		"low-headers":                1,
		"missing-typical":            2,
		"no-ua":                      3,
		"http1.1":                    1,
		"accept-*/*":                 1,
		"no-accept-lang":             1,
		"low-ciphers":                1,
		"few-tls-ext":                1,
		"no-session":                 1,
		"ja4h-no-lang":               1,
		"ja4h-low-headers":           1,
		"ja4h-inconsistent":          2,
		"ja4h-no-cookies":            2,
		"header-order-late":          2,
		"h2-ua-inconsistent":         2,
		"tls-ua-inconsistent":        3,
		"ua-browser-no-grease":       3,
		"h2-ja4-inconsistent":        2,
		"tls-alpn-http-inconsistent": 2,
		"no-sni":                     1,
		"no-alpn":                    1,
	}
}

// Load reads scoring config from path. If path is empty, uses default path.
// On any error (file missing, invalid JSON), returns DefaultScoringConfig() and the error.
func Load(path string) (ScoringConfig, error) {
	if path == "" {
		path = "config/scoring.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return DefaultScoringConfig(), fmt.Errorf("scoring config read: %w", err)
	}
	var cfg ScoringConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return DefaultScoringConfig(), fmt.Errorf("scoring config parse: %w", err)
	}
	// Merge with defaults so missing keys get fallbacks
	merged := DefaultScoringConfig()
	merged.Classifier = cfg.Classifier
	merged.Confidence = cfg.Confidence
	merged.Thresholds = cfg.Thresholds
	if len(cfg.BrowserScores) > 0 {
		for k, v := range cfg.BrowserScores {
			merged.BrowserScores[k] = v
		}
	}
	if len(cfg.BotScores) > 0 {
		for k, v := range cfg.BotScores {
			merged.BotScores[k] = v
		}
	}
	return merged, nil
}

// ToClassifierConfig converts scoring config to classifier.Config.
func ToClassifierConfig(cfg ScoringConfig) classifier.Config {
	return classifier.Config{
		BotScoreWeight: cfg.Classifier.BotScoreWeight,
		Threshold:      cfg.Classifier.Threshold,
		Confidence: classifier.ConfidenceParams{
			NoSignal:              cfg.Confidence.NoSignal,
			HighSignalsThreshold:  cfg.Confidence.HighSignalsThreshold,
			HighSignalsMultiplier: cfg.Confidence.HighSignalsMultiplier,
			LowSignalsThreshold:   cfg.Confidence.LowSignalsThreshold,
			LowSignalsMultiplier:  cfg.Confidence.LowSignalsMultiplier,
			Min:                   cfg.Confidence.Min,
			Max:                   cfg.Confidence.Max,
		},
	}
}

// ToFingerprintScoringConfig converts scoring config to fingerprint.ScoringConfig (copies maps).
func ToFingerprintScoringConfig(cfg ScoringConfig) fingerprint.ScoringConfig {
	t := cfg.Thresholds
	out := fingerprint.ScoringConfig{
		Thresholds: fingerprint.ScoringThresholds{
			BrowserLikeHeaderOrderMaxIdx: t.BrowserLikeHeaderOrderMaxIdx,
			HeaderOrderLateMinIdx:        t.HeaderOrderLateMinIdx,
			HighCipherCountMin:           t.HighCipherCountMin,
			LowCipherCountMax:            t.LowCipherCountMax,
			TLSExtBrowserMin:             t.TLSExtBrowserMin,
			FewTLSExtMax:                 t.FewTLSExtMax,
			SupportedGroupsMin:           t.SupportedGroupsMin,
			LowHeaderCountMax:            t.LowHeaderCountMax,
			JA4HLowHeaderCountMax:        t.JA4HLowHeaderCountMax,
			JA4HHighHeaderCountMin:       t.JA4HHighHeaderCountMin,
			AcceptLangMinLocaleParts:     t.AcceptLangMinLocaleParts,
			AcceptLangMinLength:          t.AcceptLangMinLength,
		},
		BrowserScores: copyMap(cfg.BrowserScores),
		BotScores:     copyMap(cfg.BotScores),
	}
	return out
}

func copyMap(m map[string]int) map[string]int {
	if m == nil {
		return nil
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

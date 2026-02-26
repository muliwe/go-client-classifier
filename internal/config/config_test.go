package config

import (
	"testing"
)

func TestDefaultScoringConfig_fullStructure(t *testing.T) {
	cfg := DefaultScoringConfig()

	// Classifier
	if cfg.Classifier.BotScoreWeight != 4 {
		t.Errorf("Classifier.BotScoreWeight = %d, want 4", cfg.Classifier.BotScoreWeight)
	}
	if cfg.Classifier.Threshold != 4 {
		t.Errorf("Classifier.Threshold = %d, want 4", cfg.Classifier.Threshold)
	}
	if cfg.ChallengeTTLSec != 120 {
		t.Errorf("ChallengeTTLSec = %d, want 120", cfg.ChallengeTTLSec)
	}

	// Confidence
	if cfg.Confidence.NoSignal != 0.5 {
		t.Errorf("Confidence.NoSignal = %v, want 0.5", cfg.Confidence.NoSignal)
	}
	if cfg.Confidence.HighSignalsThreshold != 5 {
		t.Errorf("Confidence.HighSignalsThreshold = %d, want 5", cfg.Confidence.HighSignalsThreshold)
	}
	if cfg.Confidence.HighSignalsMultiplier != 1.2 {
		t.Errorf("Confidence.HighSignalsMultiplier = %v, want 1.2", cfg.Confidence.HighSignalsMultiplier)
	}
	if cfg.Confidence.LowSignalsThreshold != 3 {
		t.Errorf("Confidence.LowSignalsThreshold = %d, want 3", cfg.Confidence.LowSignalsThreshold)
	}
	if cfg.Confidence.LowSignalsMultiplier != 0.8 {
		t.Errorf("Confidence.LowSignalsMultiplier = %v, want 0.8", cfg.Confidence.LowSignalsMultiplier)
	}
	if cfg.Confidence.Min != 0.5 {
		t.Errorf("Confidence.Min = %v, want 0.5", cfg.Confidence.Min)
	}
	if cfg.Confidence.Max != 0.99 {
		t.Errorf("Confidence.Max = %v, want 0.99", cfg.Confidence.Max)
	}

	// Thresholds
	wantThresholds := ThresholdsConfig{
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
	}
	if cfg.Thresholds != wantThresholds {
		t.Errorf("Thresholds:\n got  %+v\n want %+v", cfg.Thresholds, wantThresholds)
	}

	// Browser scores: required keys and expected values (full set from default)
	wantBrowserScores := map[string]int{
		"http2": 2, "h2-fp": 1, "h2-init-window": 1, "h2-priority": 1, "h2-window-update": 1,
		"h2-max-frame": 1, "h2-pseudo-headers": 1, "sec-fetch": 1, "browser-ua": 1, "sec-ch-ua": 1,
		"header-order": 1, "cache-control": 1, "cookies": 1, "modern-tls": 1, "ssl-greased": 1,
		"high-ciphers": 2, "session-ticket": 1, "multi-groups": 1, "tls-ext>=10": 1,
		"ja4h-headers>=10": 1, "ja4h-referer": 1, "ja4h-consistent": 1, "tls-ua-consistent": 1,
		"accept-language": 0, "browser-headers": 0, "sec-ch-ua-modern": 0, "accept-lang-rich": 1, "sec-purpose": 2,
		"challenge-passed": 1, "high-header-count": 0, "no-bot-red-flags": 0,
	}
	for key, want := range wantBrowserScores {
		got, ok := cfg.BrowserScores[key]
		if !ok {
			t.Errorf("BrowserScores: missing key %q", key)
			continue
		}
		if got != want {
			t.Errorf("BrowserScores[%q] = %d, want %d", key, got, want)
		}
	}
	if len(cfg.BrowserScores) != len(wantBrowserScores) {
		t.Errorf("BrowserScores: got %d keys, want %d (extra or missing)", len(cfg.BrowserScores), len(wantBrowserScores))
	}

	// Bot scores: required keys and expected values (full set from default)
	wantBotScores := map[string]int{
		"obsolete-tls": 3, "exotic-alpn": 3, "blind-probe": 3, "bot-ua": 3, "ai-crawler": 2,
		"low-headers": 1, "missing-typical": 2, "no-ua": 3, "http1.1": 1, "accept-*/*": 1,
		"no-accept-lang": 1, "low-ciphers": 1, "few-tls-ext": 1, "no-session": 1,
		"ja4h-no-lang": 1, "ja4h-low-headers": 1, "ja4h-inconsistent": 2, "ja4h-no-cookies": 2,
		"header-order-late": 2, "h2-ua-inconsistent": 2, "tls-ua-inconsistent": 3,
		"ua-browser-no-grease": 3, "h2-ja4-inconsistent": 2, "tls-alpn-http-inconsistent": 2,
		"no-sni": 1, "no-alpn": 1, "accept-lang-simple": 1,
		"sec-purpose-invalid": 1, "sec-purpose-no-sec-fetch": 2, "challenge-failed": 3,
		"high-request-rate": 1, "low-inter-arrival-median": 1, "high-inter-arrival-variance": 1, "mean-above-median": 1,
	}
	for key, want := range wantBotScores {
		got, ok := cfg.BotScores[key]
		if !ok {
			t.Errorf("BotScores: missing key %q", key)
			continue
		}
		if got != want {
			t.Errorf("BotScores[%q] = %d, want %d", key, got, want)
		}
	}
	if len(cfg.BotScores) != len(wantBotScores) {
		t.Errorf("BotScores: got %d keys, want %d (extra or missing)", len(cfg.BotScores), len(wantBotScores))
	}
}

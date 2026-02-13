package unit

import (
	"strings"
	"testing"

	"github.com/muliwe/go-client-classifier/internal/fingerprint"
)

func TestExtractSignals_CurlBot(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version:     "HTTP/1.1",
			UserAgent:   "curl/8.0.1",
			Accept:      "*/*",
			HeaderCount: 3,
			JA4HHash:    "ge11nn030000_abc123def456_000000000000_000000000000",
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.UserAgentIsBot {
		t.Error("curl should be detected as bot")
	}
	if s.UserAgentIsBrowser {
		t.Error("curl should not be detected as browser")
	}
	if s.IsHTTP2 {
		t.Error("HTTP/1.1 should not be HTTP/2")
	}
	if !s.LowHeaderCount {
		t.Error("3 headers should be low header count")
	}
	if s.BotScore <= 0 {
		t.Error("curl should have positive bot score")
	}
}

func TestExtractSignals_Browser(t *testing.T) {
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

	s := fingerprint.ExtractSignals(fp)

	if s.UserAgentIsBot {
		t.Error("Chrome should not be detected as bot")
	}
	if !s.UserAgentIsBrowser {
		t.Error("Chrome should be detected as browser")
	}
	if !s.IsHTTP2 {
		t.Error("HTTP/2.0 should be HTTP/2")
	}
	if !s.HasSecFetchHeaders {
		t.Error("Should have Sec-Fetch headers")
	}
	if !s.HasAcceptLanguage {
		t.Error("Should have Accept-Language")
	}
	if s.BrowserScore <= 0 {
		t.Error("Browser should have positive browser score")
	}
}

func TestExtractSignals_AICrawler(t *testing.T) {
	aiCrawlers := []struct {
		name string
		ua   string
	}{
		{"GPTBot", "Mozilla/5.0 compatible; GPTBot/1.0"},
		{"ClaudeBot", "ClaudeBot/1.0"},
		{"PerplexityBot", "Mozilla/5.0 PerplexityBot"},
		{"CCBot", "CCBot/2.0"},
	}

	for _, tc := range aiCrawlers {
		t.Run(tc.name, func(t *testing.T) {
			fp := fingerprint.Fingerprint{
				HTTP: fingerprint.HTTPFingerprint{
					UserAgent: tc.ua,
				},
			}

			s := fingerprint.ExtractSignals(fp)

			if !s.UserAgentIsAICrawler {
				t.Errorf("%s should be detected as AI crawler", tc.name)
			}
			if !s.UserAgentIsBot {
				t.Errorf("%s should also be detected as bot", tc.name)
			}
		})
	}
}

func TestExtractSignals_JA4H(t *testing.T) {
	tests := []struct {
		name                string
		ja4h                string
		wantHasJA4H         bool
		wantIsHTTP2         bool
		wantMissingLanguage bool
		wantLowHeaderCount  bool
		wantHighHeaderCount bool
	}{
		{
			name:                "browser with all features",
			ja4h:                "ge20cr14enus_abc123def456_abc123def456_abc123def456",
			wantHasJA4H:         true,
			wantIsHTTP2:         true,
			wantMissingLanguage: false,
			wantLowHeaderCount:  false,
			wantHighHeaderCount: true,
		},
		{
			name:                "curl minimal",
			ja4h:                "ge11nn020000_abc123def456_000000000000_000000000000",
			wantHasJA4H:         true,
			wantIsHTTP2:         false,
			wantMissingLanguage: true,
			wantLowHeaderCount:  true,
			wantHighHeaderCount: false,
		},
		{
			name:        "empty JA4H",
			ja4h:        "",
			wantHasJA4H: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := fingerprint.Fingerprint{
				HTTP: fingerprint.HTTPFingerprint{
					JA4HHash: tt.ja4h,
				},
			}

			s := fingerprint.ExtractSignals(fp)

			if s.HasJA4HFingerprint != tt.wantHasJA4H {
				t.Errorf("HasJA4HFingerprint = %v, want %v", s.HasJA4HFingerprint, tt.wantHasJA4H)
			}

			if !tt.wantHasJA4H {
				return
			}

			if s.JA4HIsHTTP2 != tt.wantIsHTTP2 {
				t.Errorf("JA4HIsHTTP2 = %v, want %v", s.JA4HIsHTTP2, tt.wantIsHTTP2)
			}
			if s.JA4HMissingLanguage != tt.wantMissingLanguage {
				t.Errorf("JA4HMissingLanguage = %v, want %v", s.JA4HMissingLanguage, tt.wantMissingLanguage)
			}
			if s.JA4HLowHeaderCount != tt.wantLowHeaderCount {
				t.Errorf("JA4HLowHeaderCount = %v, want %v", s.JA4HLowHeaderCount, tt.wantLowHeaderCount)
			}
			if s.JA4HHighHeaderCount != tt.wantHighHeaderCount {
				t.Errorf("JA4HHighHeaderCount = %v, want %v", s.JA4HHighHeaderCount, tt.wantHighHeaderCount)
			}
		})
	}
}

func TestExtractSignals_TLSSignals(t *testing.T) {
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Version:           "TLS 1.3",
			CipherSuitesCount: 16,
			ExtensionsCount:   15,
			HasSessionTicket:  true,
			SupportedGroups:   []string{"x25519", "secp256r1", "secp384r1"},
			JA3Hash:           "abc123",
			JA4Hash:           "def456",
			Available:         true,
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.HasModernTLS {
		t.Error("TLS 1.3 should be modern TLS")
	}
	if !s.HasTLSFingerprint {
		t.Error("Should have TLS fingerprint")
	}
	if !s.HighCipherCount {
		t.Error("16 ciphers should be high count")
	}
	if !s.HasSessionSupport {
		t.Error("Should have session support")
	}
	if !s.HasMultipleGroups {
		t.Error("3 groups should be multiple groups")
	}
}

func TestCalculateScores_Breakdown(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version:      "HTTP/2.0",
			SecFetchSite: "none",
			AcceptLang:   "en-US",
			HeaderCount:  12,
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !strings.Contains(s.ScoreBreakdown, "BROWSER[") {
		t.Error("Breakdown should contain BROWSER section")
	}
	if !strings.Contains(s.ScoreBreakdown, "BOT[") {
		t.Error("Breakdown should contain BOT section")
	}
	if !strings.Contains(s.ScoreBreakdown, "http2") {
		t.Error("Breakdown should mention http2")
	}
	if !strings.Contains(s.ScoreBreakdown, "sec-fetch") {
		t.Error("Breakdown should mention sec-fetch")
	}
}

func TestCalculateScores_JA4HInconsistent(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			Version:    "HTTP/2.0",
			HasCookies: true,
			HasReferer: false,
			AcceptLang: "en-US",
			JA4HHash:   "ge11nr050000_abc123def456_000000000000_000000000000",
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if s.JA4HConsistentSignal {
		t.Error("Should detect inconsistent JA4H signals")
	}

	if !strings.Contains(s.ScoreBreakdown, "ja4h-inconsistent") {
		t.Error("Breakdown should mention JA4H inconsistency")
	}
}

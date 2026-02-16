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

func TestCalculateScores_H2Parsed_BrowserLikeWindow(t *testing.T) {
	// Parsed H2 fingerprint with browser-like INITIAL_WINDOW_SIZE (131072) gets +1 (h2-init-window)
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			H2Fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201",
			H2Parsed:      fingerprint.ParseH2Fingerprint("1:65536;4:131072;5:16384|12517377|3:0:0:201"),
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.HasHTTP2Fingerprint {
		t.Error("Should have HTTP/2 fingerprint")
	}
	if !s.H2SettingsParsed {
		t.Error("Should have parsed H2 settings")
	}
	if s.H2InitialWindowSize != 131072 {
		t.Errorf("H2InitialWindowSize = %d, want 131072", s.H2InitialWindowSize)
	}
	if !s.H2WindowUpdatePresent {
		t.Error("Should have H2 WINDOW_UPDATE present (12517377)")
	}
	if !s.H2MaxFrameSizeBrowserLike {
		t.Error("Should have browser-like MAX_FRAME_SIZE (16384)")
	}
	for _, sub := range []string{"h2-fp(+1)", "h2-init-window(+1)", "h2-priority(+1)", "h2-window-update(+1)", "h2-max-frame(+1)"} {
		if !strings.Contains(s.ScoreBreakdown, sub) {
			t.Errorf("Breakdown should contain %s", sub)
		}
	}
	// Should have at least 5 browser points from H2 (h2-fp + h2-init-window + h2-priority + h2-window-update + h2-max-frame)
	if s.BrowserScore < 5 {
		t.Errorf("BrowserScore should be >= 5 (H2 signals), got %d", s.BrowserScore)
	}
}

func TestCalculateScores_H2Parsed_FullFingerprintWithPseudoHeaders(t *testing.T) {
	// Full nginx-style fingerprint with 4 segments (SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order)
	raw := "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			H2Fingerprint: raw,
			H2Parsed:      fingerprint.ParseH2Fingerprint(raw),
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.H2PseudoHeaderOrderPresent {
		t.Error("Should have pseudo-header order (fourth segment)")
	}
	if !strings.Contains(s.ScoreBreakdown, "h2-pseudo-headers(+1)") {
		t.Error("Breakdown should contain h2-pseudo-headers(+1)")
	}
	// All H2 browser signals: h2-fp, h2-init-window, h2-priority, h2-window-update, h2-max-frame, h2-pseudo-headers = 6
	if s.BrowserScore < 6 {
		t.Errorf("BrowserScore should be >= 6 (full H2 fingerprint), got %d", s.BrowserScore)
	}
}

func TestCalculateScores_H2Parsed_NonBrowserLikeWindow(t *testing.T) {
	// Parsed H2 with unusual INITIAL_WINDOW_SIZE (e.g. 99999) — no h2-init-window bonus
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			H2Fingerprint: "1:65536;4:99999;5:16384|0|",
			H2Parsed:      fingerprint.ParseH2Fingerprint("1:65536;4:99999;5:16384|0|"),
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.H2SettingsParsed {
		t.Error("Should have parsed H2 settings")
	}
	if s.H2InitialWindowSize != 99999 {
		t.Errorf("H2InitialWindowSize = %d, want 99999", s.H2InitialWindowSize)
	}
	if strings.Contains(s.ScoreBreakdown, "h2-init-window") {
		t.Error("Breakdown should NOT contain h2-init-window for non-browser-like window 99999")
	}
	// Still has h2-fp(+1)
	if !strings.Contains(s.ScoreBreakdown, "h2-fp(+1)") {
		t.Error("Breakdown should still contain h2-fp(+1)")
	}
}

func TestCalculateScores_H2Parsed_NoPriority(t *testing.T) {
	// Parsed H2 with empty PRIORITY segment (third segment empty) — no h2-priority bonus
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			H2Fingerprint: "1:65536;4:131072;5:16384|12517377|",
			H2Parsed:      fingerprint.ParseH2Fingerprint("1:65536;4:131072;5:16384|12517377|"),
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.H2SettingsParsed {
		t.Error("Should have parsed H2 settings")
	}
	if s.H2PriorityPresent {
		t.Error("H2PriorityPresent should be false when PRIORITY segment is empty")
	}
	if strings.Contains(s.ScoreBreakdown, "h2-priority") {
		t.Error("Breakdown should NOT contain h2-priority when PRIORITY segment empty")
	}
	// Should still have h2-fp and h2-init-window
	if !strings.Contains(s.ScoreBreakdown, "h2-fp(+1)") {
		t.Error("Breakdown should contain h2-fp(+1)")
	}
	if !strings.Contains(s.ScoreBreakdown, "h2-init-window(+1)") {
		t.Error("Breakdown should contain h2-init-window(+1)")
	}
}

func TestCalculateScores_H2Fingerprint_Unparseable(t *testing.T) {
	// H2 fingerprint string present but not in Akamai format — no parse, no h2-init-window
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			H2Fingerprint: "not-a-valid-format",
			H2Parsed:      fingerprint.ParseH2Fingerprint("not-a-valid-format"),
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.HasHTTP2Fingerprint {
		t.Error("Should have HTTP/2 fingerprint (raw string)")
	}
	// Parser returns struct but ParsedOK false when no SETTINGS
	if s.H2SettingsParsed {
		t.Error("H2SettingsParsed should be false when format has no SETTINGS segment")
	}
	if strings.Contains(s.ScoreBreakdown, "h2-init-window") {
		t.Error("Breakdown should NOT contain h2-init-window when unparseable")
	}
}

func TestCalculateScores_H2UAInconsistent(t *testing.T) {
	// Browser-like UA but H2 fingerprint is library-like (no PRIORITY) → h2-ua-inconsistent +2 bot (Appendix G)
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{Available: true},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
			H2Fingerprint: "1:65536;4:131072;5:16384|12517377|", // no PRIORITY segment (third empty)
			H2Parsed:      fingerprint.ParseH2Fingerprint("1:65536;4:131072;5:16384|12517377|"),
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.UserAgentIsBrowser {
		t.Error("UA should be classified as browser")
	}
	if !s.HasHTTP2Fingerprint || !s.H2SettingsParsed {
		t.Error("Should have parsed H2 fingerprint")
	}
	if s.H2PriorityPresent {
		t.Error("PRIORITY segment empty → library-like H2")
	}
	if !strings.Contains(s.ScoreBreakdown, "h2-ua-inconsistent(+2)") {
		t.Error("Breakdown should contain h2-ua-inconsistent(+2) when browser UA + library-like H2")
	}
	if s.BotScore < 2 {
		t.Errorf("BotScore should be at least 2 from h2-ua-inconsistent, got %d", s.BotScore)
	}
}

func TestCalculateScores_TLSUAInconsistent(t *testing.T) {
	// Browser-like UA but JA3 is known library (e.g. Python requests) → tls-ua-inconsistent +2 bot (Appendix G)
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available: true,
			JA3Hash:   "599ccb0563b7bbae9962ca7e634cc462", // Python requests
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.UserAgentIsBrowser {
		t.Error("UA should be classified as browser")
	}
	if !s.TLSKnownLibrary {
		t.Error("JA3 should be in known-library set")
	}
	if !strings.Contains(s.ScoreBreakdown, "tls-ua-inconsistent(+2)") {
		t.Error("Breakdown should contain tls-ua-inconsistent(+2) when browser UA + known library JA3")
	}
	if s.BotScore < 2 {
		t.Errorf("BotScore should be at least 2 from tls-ua-inconsistent, got %d", s.BotScore)
	}
}

func TestCalculateScores_TLSUAConsistent_BrowserBonus(t *testing.T) {
	// Browser UA + known browser JA3 (Chrome) → tls-ua-consistent +1 browser
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available: true,
			JA3Hash:   "579ccef312d18482fc42e2b822ca2430", // Chrome (in knownBrowserJA3)
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.UserAgentIsBrowser || !s.TLSKnownBrowser {
		t.Error("UA is browser and JA3 should be in known-browser set")
	}
	if !strings.Contains(s.ScoreBreakdown, "tls-ua-consistent(+1)") {
		t.Error("Breakdown should contain tls-ua-consistent(+1) when browser UA + known browser TLS")
	}
	if strings.Contains(s.ScoreBreakdown, "tls-ua-inconsistent") {
		t.Error("Breakdown should NOT contain tls-ua-inconsistent when browser UA + browser TLS")
	}
}

func TestCalculateScores_TLSUA_BotUA_BrowserTLS(t *testing.T) {
	// Bot UA (e.g. curl) but JA3 is known browser → tls-ua-inconsistent +2 bot
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available: true,
			JA3Hash:   "579ccef312d18482fc42e2b822ca2430", // Chrome
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent: "curl/7.68.0",
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.UserAgentIsBot || !s.TLSKnownBrowser {
		t.Error("UA is bot and JA3 should be in known-browser set")
	}
	if !strings.Contains(s.ScoreBreakdown, "tls-ua-inconsistent(+2)") {
		t.Error("Breakdown should contain tls-ua-inconsistent(+2) when bot UA + known browser TLS")
	}
	if s.BotScore < 2 {
		t.Errorf("BotScore should include tls-ua-inconsistent, got %d", s.BotScore)
	}
}

func TestCalculateScores_TLSALPNVsHTTPInconsistent(t *testing.T) {
	// Direct TLS: ALPN h2 but request is HTTP/1.1 → tls-alpn-http-inconsistent +2 bot
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			ALPN:      "h2",
			FromProxy: false,
		},
		HTTP: fingerprint.HTTPFingerprint{
			Version: "HTTP/1.1",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.TLSALPNVsHTTPInconsistent {
		t.Error("ALPN h2 with HTTP/1.1 (direct TLS) should set TLSALPNVsHTTPInconsistent")
	}
	if !strings.Contains(s.ScoreBreakdown, "tls-alpn-http-inconsistent(+2)") {
		t.Error("Breakdown should contain tls-alpn-http-inconsistent(+2)")
	}

	// Direct TLS: ALPN http/1.1 but request is HTTP/2.0 → inconsistent
	fp2 := fingerprint.Fingerprint{
		TLS:  fingerprint.TLSFingerprint{ALPN: "http/1.1", FromProxy: false},
		HTTP: fingerprint.HTTPFingerprint{Version: "HTTP/2.0"},
	}
	s2 := fingerprint.ExtractSignals(fp2)
	if !s2.TLSALPNVsHTTPInconsistent {
		t.Error("ALPN http/1.1 with HTTP/2.0 (direct TLS) should set TLSALPNVsHTTPInconsistent")
	}
}

func TestCalculateScores_TLSALPNVsHTTP_FromProxy_NoPenalty(t *testing.T) {
	// From proxy: ALPN h2 but request to backend is HTTP/1.1 — normal, no inconsistency
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			ALPN:      "h2",
			FromProxy: true,
		},
		HTTP: fingerprint.HTTPFingerprint{
			Version: "HTTP/1.1",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.TLSALPNVsHTTPInconsistent {
		t.Error("From proxy: ALPN h2 + HTTP/1.1 to backend is normal, should not set TLSALPNVsHTTPInconsistent")
	}
}

func TestCalculateScores_H2JA4Inconsistent(t *testing.T) {
	// JA4 says h2 but request is HTTP/1.1 (no ALPN h2, no H2 fingerprint) → h2-ja4-inconsistent +2 bot
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			JA4Hash: "t13d1516h2_8daaf6152771_02713d6af862", // Part A ends with h2
		},
		HTTP: fingerprint.HTTPFingerprint{
			Version: "HTTP/1.1", // not HTTP/2
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.H2JA4Inconsistent {
		t.Error("JA4 ALPN h2 but IsHTTP2 false should set H2JA4Inconsistent")
	}
	if !strings.Contains(s.ScoreBreakdown, "h2-ja4-inconsistent(+2)") {
		t.Error("Breakdown should contain h2-ja4-inconsistent(+2)")
	}
	if s.BotScore < 2 {
		t.Errorf("BotScore should include h2-ja4-inconsistent, got %d", s.BotScore)
	}
}

func TestCalculateScores_H2UAConsistent_NoPenalty(t *testing.T) {
	// Browser-like UA and browser-like H2 (PRIORITY present, browser-like window) → no h2-ua-inconsistent
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{Available: true},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
			H2Fingerprint: "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s",
			H2Parsed:      fingerprint.ParseH2Fingerprint("1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"),
		},
	}

	s := fingerprint.ExtractSignals(fp)

	if !s.UserAgentIsBrowser || !s.H2PriorityPresent {
		t.Error("UA browser and H2 should have PRIORITY")
	}
	if strings.Contains(s.ScoreBreakdown, "h2-ua-inconsistent") {
		t.Error("Breakdown should NOT contain h2-ua-inconsistent when H2 is browser-like")
	}
}

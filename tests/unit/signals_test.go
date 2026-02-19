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
	// Browser-like UA but JA3 is known library (e.g. Python requests) → tls-ua-inconsistent +3 bot (Appendix G)
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
	if !strings.Contains(s.ScoreBreakdown, "tls-ua-inconsistent(+3)") {
		t.Error("Breakdown should contain tls-ua-inconsistent(+3) when browser UA + known library JA3")
	}
	if s.BotScore < 3 {
		t.Errorf("BotScore should be at least 3 from tls-ua-inconsistent, got %d", s.BotScore)
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
	// Bot UA (e.g. curl) but JA3 is known browser → tls-ua-inconsistent +3 bot
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
	if !strings.Contains(s.ScoreBreakdown, "tls-ua-inconsistent(+3)") {
		t.Error("Breakdown should contain tls-ua-inconsistent(+3) when bot UA + known browser TLS")
	}
	if s.BotScore < 3 {
		t.Errorf("BotScore should include tls-ua-inconsistent, got %d", s.BotScore)
	}
}

func TestCalculateScores_ObsoleteTLS(t *testing.T) {
	// TLS 1.0 or 1.1 from proxy → obsolete-tls +3 bot (smoking gun)
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available: true,
			Version:   "TLS 1.0",
		},
		HTTP: fingerprint.HTTPFingerprint{UserAgent: "Mozilla/5.0"},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.TLSObsolete {
		t.Error("TLSObsolete should be true for TLS 1.0")
	}
	if !strings.Contains(s.ScoreBreakdown, "obsolete-tls(+3)") {
		t.Error("Breakdown should contain obsolete-tls(+3)")
	}
}

func TestCalculateScores_ExoticALPN(t *testing.T) {
	// Exotic ALPN (spdy, h2c, hq, http/0.9) → exotic-alpn +1 bot
	for _, alpn := range []string{"h2c", "hq", "http/0.9", "http/1.0", "spdy/3"} {
		fp := fingerprint.Fingerprint{
			TLS: fingerprint.TLSFingerprint{
				Available: true,
				Version:   "TLS 1.2",
				ALPN:      alpn,
			},
			HTTP: fingerprint.HTTPFingerprint{UserAgent: "Mozilla/5.0"},
		}
		s := fingerprint.ExtractSignals(fp)
		if !s.TLSExoticALPN {
			t.Errorf("TLSExoticALPN should be true for ALPN %q", alpn)
		}
		if !strings.Contains(s.ScoreBreakdown, "exotic-alpn(+3)") {
			t.Errorf("Breakdown should contain exotic-alpn(+3) for ALPN %q, got: %s", alpn, s.ScoreBreakdown)
		}
	}
}

func TestCalculateScores_SSLGreased_BrowserBonus(t *testing.T) {
	// GREASE present + modern TLS + non-bot UA → ssl-greased +1 browser
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available:  true,
			Version:    "TLS 1.3",
			SSLGreased: "0x1a1a,0x2a2a",
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.HasSSLGreased {
		t.Error("HasSSLGreased should be true")
	}
	if !s.HasModernTLS {
		t.Error("HasModernTLS should be true")
	}
	if !strings.Contains(s.ScoreBreakdown, "ssl-greased(+1)") {
		t.Error("Breakdown should contain ssl-greased(+1) when GREASE present and modern TLS and browser UA")
	}
}

func TestCalculateScores_SSLGreased_ZeroIsAbsent(t *testing.T) {
	// X-FP-SSL-GREASED "0" means no GREASE (nginx convention) → HasSSLGreased false, no ssl-greased bonus
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available:  true,
			Version:    "TLS 1.3",
			SSLGreased: "0",
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.HasSSLGreased {
		t.Error("HasSSLGreased should be false when X-FP-SSL-GREASED is \"0\"")
	}
	if strings.Contains(s.ScoreBreakdown, "ssl-greased(+1)") {
		t.Error("Breakdown should NOT contain ssl-greased when value is \"0\"")
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

func TestCalculateScores_FromProxy_NoSession_NoPenalty(t *testing.T) {
	// From proxy: HasSessionTicket is never set (X-FP-* does not pass it) → do not add no-session(+1) bot
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available: true,
			Version:   "TLS 1.3",
			FromProxy: true,
			JA3Hash:   "0149f47eabf9a20d0893e2a44e5a6323",
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.TLSFromProxy != true {
		t.Error("TLS should be from proxy")
	}
	if strings.Contains(s.ScoreBreakdown, "no-session(+1)") {
		t.Error("From proxy: should NOT add no-session(+1) (session ticket not in X-FP-*)")
	}
}

func TestCalculateScores_FromProxy_JA4HVersion_Consistent(t *testing.T) {
	// From proxy: backend sees HTTP/1.1 so JA4H version is "11"; is_http2 from ALPN. Do not treat as ja4h-inconsistent
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			ALPN:      "h2",
			FromProxy: true,
		},
		HTTP: fingerprint.HTTPFingerprint{
			Version:     "HTTP/1.1",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
			JA4HHash:    "ge11nn14enus_abc123def456_000000000000_000000000000", // version 11
			HeaderCount: 14,
			AcceptLang:  "en-US,en;q=0.9",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.IsHTTP2 {
		t.Error("ALPN h2 should set IsHTTP2")
	}
	if s.JA4HConsistentSignal != true {
		t.Error("From proxy: JA4H version vs is_http2 should be ignored, so signals stay consistent")
	}
	if strings.Contains(s.ScoreBreakdown, "ja4h-inconsistent(+2)") {
		t.Error("From proxy: should NOT add ja4h-inconsistent from version mismatch (backend sees HTTP/1.x)")
	}
}

func TestCalculateScores_FromProxy_JA4HBotPenalties_Skipped(t *testing.T) {
	// From proxy: JA4H bot penalties (ja4h-no-lang, ja4h-low-headers, ja4h-inconsistent) are skipped
	// because JA4H is computed from the request as seen by the backend (header set can differ from client).
	// Use a JA4H that would normally trigger all three: 0000 lang, low header count (03), and request has Accept-Language → inconsistent.
	// HasCookies true and JA4H parts C/D non-zero so the new ja4h-no-cookies penalty does not apply (that one is for impersonate detection).
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			ALPN:       "h2",
			Version:    "TLS 1.3",
			FromProxy:  true,
			SSLGreased: "1",
		},
		HTTP: fingerprint.HTTPFingerprint{
			Version:      "HTTP/1.1",
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36",
			JA4HHash:     "ge11cn030000_abc123def456_111111111111_222222222222", // c=cookies, 03 headers, 0000 lang; C/D non-zero so no ja4h-no-cookies
			HeaderCount:  26,
			HasCookies:   true,
			AcceptLang:   "ru-RU,ru;q=0.9", // present → inconsistent with JA4H 0000
			Accept:       "text/html,application/xhtml+xml",
			AcceptEnc:    "gzip, deflate, br",
			SecFetchSite: "none",
			SecFetchMode: "navigate",
			SecFetchDest: "document",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.HasJA4HFingerprint || !s.TLSFromProxy {
		t.Fatal("Setup: need JA4H and FromProxy")
	}
	if !s.JA4HMissingLanguage || !s.JA4HLowHeaderCount {
		t.Error("JA4H fingerprint should parse as missing lang and low headers (for direct would trigger penalties)")
	}
	if s.JA4HConsistentSignal {
		t.Error("JA4H 0000 with HasAcceptLanguage should be inconsistent (for direct would trigger penalty)")
	}
	// When from proxy we must NOT add any JA4H bot penalties
	if strings.Contains(s.ScoreBreakdown, "ja4h-no-lang(+1)") {
		t.Error("From proxy: should NOT add ja4h-no-lang")
	}
	if strings.Contains(s.ScoreBreakdown, "ja4h-low-headers(+1)") {
		t.Error("From proxy: should NOT add ja4h-low-headers")
	}
	if strings.Contains(s.ScoreBreakdown, "ja4h-inconsistent(+2)") {
		t.Error("From proxy: should NOT add ja4h-inconsistent")
	}
	// With browser-like request and from proxy, no other bot signals → BotScore 0
	if s.BotScore != 0 {
		t.Errorf("From proxy + browser-like request: BotScore want 0, got %d (breakdown: %s)", s.BotScore, s.ScoreBreakdown)
	}
}

func TestCalculateScores_BrowserUA_NoGrease_FromProxy_BotPenalty(t *testing.T) {
	// From proxy + browser UA + no GREASE (curl/libraries) → ua-browser-no-grease(+3) bot
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available:  true,
			Version:    "TLS 1.3",
			FromProxy:  true,
			SSLGreased: "",                                 // no GREASE
			JA3Hash:    "0149f47eabf9a20d0893e2a44e5a6323", // curl
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/133.0.0.0 Safari/537.36",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.TLSFromProxy || !s.UserAgentIsBrowser || s.HasSSLGreased {
		t.Error("Setup: from proxy, browser UA, no GREASE")
	}
	if !strings.Contains(s.ScoreBreakdown, "ua-browser-no-grease(+3)") {
		t.Error("Breakdown should contain ua-browser-no-grease(+3) when browser UA + from proxy + no GREASE")
	}
	if s.BotScore < 3 {
		t.Errorf("BotScore should include ua-browser-no-grease, got %d", s.BotScore)
	}
}

func TestCalculateScores_BrowserUA_NoGrease_FromProxy_HTTPToHTTP_NoPenalty(t *testing.T) {
	// HTTP→HTTP proxy: client did no TLS to us; TLS from proxy but no ALPN/JA3/cipher. Do NOT add ua-browser-no-grease.
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available:   true,
			FromProxy:   true,
			Version:     "",
			ALPN:        "",
			JA3Hash:     "",
			CipherSuite: "",
			SSLGreased:  "",
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			AcceptEnc:  "gzip, deflate",
			AcceptLang: "ru-RU,ru;q=0.9,en;q=0.8",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.TLSFromProxy || !s.UserAgentIsBrowser {
		t.Error("Setup: from proxy, browser UA")
	}
	if strings.Contains(s.ScoreBreakdown, "ua-browser-no-grease(+3)") {
		t.Errorf("HTTP→HTTP proxy must NOT get ua-browser-no-grease (no client TLS), got breakdown: %s", s.ScoreBreakdown)
	}
}

func TestCalculateScores_JA4HNoCookies_HTTPToHTTP_NoPenalty(t *testing.T) {
	// HTTP→HTTP proxy: no client TLS; no cookies is normal (first visit). Do NOT add ja4h-no-cookies.
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available:   true,
			FromProxy:   true,
			Version:     "",
			ALPN:        "",
			JA3Hash:     "",
			CipherSuite: "",
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36",
			Accept:     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			AcceptEnc:  "gzip, deflate",
			AcceptLang: "ru-RU,ru;q=0.9,en;q=0.8",
			HasCookies: false,
			JA4HHash:   "ge11nn11ruru_365e380d999b_000000000000_000000000000",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.TLSFromProxy || !s.UserAgentIsBrowser || !s.JA4HZeroedCookieHashes {
		t.Error("Setup: from proxy, browser UA, no cookies, zeroed C/D")
	}
	if strings.Contains(s.ScoreBreakdown, "ja4h-no-cookies(+3)") {
		t.Errorf("HTTP→HTTP proxy must NOT get ja4h-no-cookies (no client TLS; cookies rare), got %s", s.ScoreBreakdown)
	}
}

func TestCalculateScores_FromProxy_H2UAInconsistent_Skipped(t *testing.T) {
	// From proxy: H2 fingerprint may omit SETTINGS (e.g. id 5 MAX_FRAME_SIZE) so isH2LibraryLike can be true for real Chrome.
	// We must NOT add h2-ua-inconsistent when from proxy.
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			ALPN:       "h2",
			FromProxy:  true,
			SSLGreased: "1",
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/145.0.0.0 Safari/537.36",
			H2Fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p", // no id 5 → MaxFrameSize 0 → library-like
			H2Parsed:      fingerprint.ParseH2Fingerprint("1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p"),
			HeaderCount:   28,
			Accept:        "text/html,application/xhtml+xml",
			AcceptEnc:     "gzip, deflate, br",
			AcceptLang:    "ru-RU,ru;q=0.9",
			SecFetchSite:  "none",
			SecFetchMode:  "navigate",
			SecFetchDest:  "document",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.TLSFromProxy || !s.UserAgentIsBrowser || !s.HasHTTP2Fingerprint {
		t.Fatal("Setup: from proxy, browser UA, H2 fingerprint")
	}
	if s.H2MaxFrameSizeBrowserLike {
		t.Error("H2 fingerprint has no SETTINGS id 5, so H2MaxFrameSizeBrowserLike should be false")
	}
	if strings.Contains(s.ScoreBreakdown, "h2-ua-inconsistent(+2)") {
		t.Error("From proxy: should NOT add h2-ua-inconsistent (X-FP-H2 may omit MAX_FRAME_SIZE)")
	}
	if s.BotScore != 0 {
		t.Errorf("From proxy + browser-like request, H2 without id 5: BotScore want 0, got %d (breakdown: %s)", s.BotScore, s.ScoreBreakdown)
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

// TestCalculateScores_HTTP11_NoTLS_NoPenalty: raw HTTP pipeline (no TLS) + HTTP/1.1 → no http1.1(+1) penalty
func TestCalculateScores_HTTP11_NoTLS_NoPenalty(t *testing.T) {
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{Available: false},
		HTTP: fingerprint.HTTPFingerprint{
			Version:      "HTTP/1.1",
			UserAgent:    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/144.0.0.0 Safari/537.36",
			Accept:       "text/html,application/xhtml+xml",
			AcceptLang:   "ru-RU,ru;q=0.9",
			AcceptEnc:    "gzip, deflate, br",
			SecFetchSite: "none",
			SecFetchMode: "navigate",
			SecFetchDest: "document",
			SecChUA:      `"Chromium";v="144"`,
			HeaderCount:  12,
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.ScoreBreakdown != "" && strings.Contains(s.ScoreBreakdown, "http1.1(+1)") {
		t.Error("Raw HTTP (no TLS) + HTTP/1.1 should NOT get http1.1(+1) penalty")
	}
}

// TestCalculateScores_HTTP11_TLSAvailable_Penalty: TLS available + HTTP/1.1 (e.g. curl) → http1.1(+1)
func TestCalculateScores_HTTP11_TLSAvailable_Penalty(t *testing.T) {
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available: true,
			JA3Hash:   "e7d705a3286e19ea42f587b344ee6865", // cURL
		},
		HTTP: fingerprint.HTTPFingerprint{
			Version:   "HTTP/1.1",
			UserAgent: "curl/7.68.0",
			Accept:    "*/*",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !strings.Contains(s.ScoreBreakdown, "http1.1(+1)") {
		t.Error("TLS available + HTTP/1.1 should get http1.1(+1) in breakdown")
	}
}

// TestCalculateScores_BotUA_NoTLSBrowserPoints: bot UA (curl) with rich TLS → no browser points for TLS/ja4h-consistent
func TestCalculateScores_BotUA_NoTLSBrowserPoints(t *testing.T) {
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available:         true,
			Version:           "TLS 1.3",
			CipherSuitesCount: 16,
			ExtensionsCount:   18,
			HasSessionTicket:  true,
			SupportedGroups:   []string{"x25519", "secp256r1", "secp384r1"},
			JA3Hash:           "e7d705a3286e19ea42f587b344ee6865",
		},
		HTTP: fingerprint.HTTPFingerprint{
			Version:     "HTTP/1.1",
			UserAgent:   "curl/8.0.1",
			Accept:      "*/*",
			HeaderCount: 5,
			JA4HHash:    "ge11nn050000_abc123_000000000000_000000000000",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.UserAgentIsBot {
		t.Fatal("curl must be detected as bot")
	}
	// Bot UA must not receive browser points for TLS or ja4h-consistent
	if strings.Contains(s.ScoreBreakdown, "modern-tls(+1)") ||
		strings.Contains(s.ScoreBreakdown, "high-ciphers(+2)") ||
		strings.Contains(s.ScoreBreakdown, "session-ticket(+1)") ||
		strings.Contains(s.ScoreBreakdown, "multi-groups(+1)") ||
		strings.Contains(s.ScoreBreakdown, "tls-ext>=10(+1)") ||
		strings.Contains(s.ScoreBreakdown, "ja4h-consistent(+1)") {
		t.Errorf("Bot UA (curl) must not get TLS/ja4h browser points; breakdown: %s", s.ScoreBreakdown)
	}
	if s.BrowserScore > 0 {
		t.Errorf("Bot UA with rich TLS should have 0 browser score, got %d", s.BrowserScore)
	}
}

// TestCalculateScores_TLSUA_BothSets_NoPenalty: browser UA + JA4 in both library and browser set (e.g. real Chrome in ja4db) → no tls-ua-inconsistent
func TestCalculateScores_TLSUA_BothSets_NoPenalty(t *testing.T) {
	// JA4 from fixture: Chrome + python-requests → same hash in knownLibraryJA4 and knownBrowserJA4
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Available: true,
			JA4Hash:   "t13d1516h2_8daaf6152771_d8a2da3f94cd",
		},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/144.0.0.0 Safari/537.36",
			Accept:      "text/html",
			AcceptLang:  "ru-RU,ru;q=0.9",
			HeaderCount: 10,
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.UserAgentIsBrowser {
		t.Fatal("UA should be classified as browser")
	}
	if !s.TLSKnownLibrary || !s.TLSKnownBrowser {
		t.Fatalf("Fixture JA4 should be in both sets (library=%v browser=%v); ensure ja4db_fixture has Chrome+python-requests entry", s.TLSKnownLibrary, s.TLSKnownBrowser)
	}
	if strings.Contains(s.ScoreBreakdown, "tls-ua-inconsistent") {
		t.Errorf("Browser UA + TLS in both library and browser set must NOT get tls-ua-inconsistent; breakdown: %s", s.ScoreBreakdown)
	}
}

func TestExtractSignals_HeaderOrder_BrowserLike(t *testing.T) {
	// Accept and accept-language at indices 1 and 2 (both < 8) → BrowserLikeHeaderOrder true
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder: []string{"x-fp-h2", "accept", "accept-language", "priority", "user-agent"},
			HeaderCount: 5,
			UserAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
			Accept:      "text/html",
			AcceptLang:  "en-US,en;q=0.9",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.BrowserLikeHeaderOrder {
		t.Error("Accept and accept-language in first 8 positions should set BrowserLikeHeaderOrder true")
	}
	// Without HeaderOrderFromProxy we don't give header-order points (order may be from nginx)
	if strings.Contains(s.ScoreBreakdown, "header-order(+1)") {
		t.Errorf("without HeaderOrderFromProxy breakdown should not contain header-order(+1), got %s", s.ScoreBreakdown)
	}
}

func TestExtractSignals_HeaderOrder_FromProxy_BrowserLike_GetsPoint(t *testing.T) {
	// When order came from X-Original-Header-Order (nginx Lua), we give +1 for browser-like order
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder:          []string{"x-fp-h2", "accept", "accept-language", "user-agent"},
			HeaderOrderFromProxy: true,
			HeaderCount:          4,
			UserAgent:            "Mozilla/5.0 Chrome/120.0.0.0",
			Accept:               "text/html",
			AcceptLang:           "en-US,en;q=0.9",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !strings.Contains(s.ScoreBreakdown, "header-order(+1)") {
		t.Errorf("with HeaderOrderFromProxy and browser-like order should get header-order(+1), got %s", s.ScoreBreakdown)
	}
}

func TestExtractSignals_HeaderOrder_ChromeLike_FromProxy_BrowserLike_NoLate(t *testing.T) {
	// Real Chrome order (e.g. bablosoft): accept-language ~9, accept ~10; both < 12 → browser-like, no header-order-late
	order := make([]string, 16)
	for i := range order {
		order[i] = "x"
	}
	order[0] = "host"
	order[1] = "connection"
	order[2] = "pragma"
	order[3] = "cache-control"
	order[4] = "sec-ch-ua"
	order[5] = "sec-ch-ua-mobile"
	order[6] = "sec-ch-ua-platform"
	order[7] = "upgrade-insecure-requests"
	order[8] = "user-agent"
	order[9] = "accept-language"
	order[10] = "accept"
	order[11] = "sec-fetch-site"
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder:          order,
			HeaderOrderFromProxy: true,
			HeaderCount:          len(order),
			UserAgent:            "Mozilla/5.0 Chrome/138.0.0.0 Safari/537.36",
			Accept:               "text/html",
			AcceptLang:           "en-US,en;q=0.9",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.BrowserLikeHeaderOrder {
		t.Error("Chrome-like order (accept 10, accept-language 9) should be browser-like with threshold 12")
	}
	if !strings.Contains(s.ScoreBreakdown, "header-order(+1)") {
		t.Errorf("Chrome-like order from proxy should get header-order(+1), got %s", s.ScoreBreakdown)
	}
	if strings.Contains(s.ScoreBreakdown, "header-order-late") {
		t.Errorf("Chrome-like order should NOT get header-order-late, got %s", s.ScoreBreakdown)
	}
}

func TestExtractSignals_HeaderOrder_NotBrowserLike(t *testing.T) {
	// Accept at 10, accept-language at 24 → BrowserLikeHeaderOrder false
	order := make([]string, 30)
	for i := range order {
		order[i] = "x"
	}
	order[10] = "accept"
	order[24] = "accept-language"
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{FromProxy: true},
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder:  order,
			HeaderCount:  30,
			UserAgent:    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/142.0.0.0 Safari/537.36",
			Accept:       "text/html",
			AcceptLang:   "en-US,en;q=0.9",
			SecFetchSite: "none",
			SecFetchMode: "navigate",
			SecFetchDest: "document",
			JA4HHash:     "ge11nn25enus_fc343ccb8320_000000000000_000000000000",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.BrowserLikeHeaderOrder {
		t.Error("Accept or accept-language at index >= 8 should set BrowserLikeHeaderOrder false")
	}
	// Without HeaderOrderFromProxy we don't apply header-order-late (order may be from nginx)
	if strings.Contains(s.ScoreBreakdown, "header-order-late") {
		t.Errorf("without HeaderOrderFromProxy breakdown should not contain header-order-late, got %s", s.ScoreBreakdown)
	}
}

func TestExtractSignals_HeaderOrder_FromProxy_Late_GetsBotPoint(t *testing.T) {
	// When order from proxy and late → header-order-late(+2)
	order := make([]string, 30)
	for i := range order {
		order[i] = "x"
	}
	order[10] = "accept"
	order[24] = "accept-language"
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{FromProxy: true},
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder:          order,
			HeaderOrderFromProxy: true,
			HeaderCount:          30,
			UserAgent:            "Mozilla/5.0 Chrome/142.0.0.0 Safari/537.36",
			Accept:               "text/html",
			AcceptLang:           "en-US,en;q=0.9",
			SecFetchSite:         "none",
			SecFetchMode:         "navigate",
			SecFetchDest:         "document",
			JA4HHash:             "ge11nn25enus_fc343ccb8320_000000000000_000000000000",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !strings.Contains(s.ScoreBreakdown, "header-order-late(+2)") {
		t.Errorf("with HeaderOrderFromProxy and late order should get header-order-late(+2), got %s", s.ScoreBreakdown)
	}
}

func TestExtractSignals_HeaderOrder_EmptyOrMissing(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder: []string{},
			UserAgent:   "Mozilla/5.0 Chrome/120.0.0.0",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.BrowserLikeHeaderOrder {
		t.Error("Empty HeaderOrder should set BrowserLikeHeaderOrder false")
	}
	fp.HTTP.HeaderOrder = []string{"user-agent", "accept-encoding"}
	s = fingerprint.ExtractSignals(fp)
	if s.BrowserLikeHeaderOrder {
		t.Error("Missing accept or accept-language should set BrowserLikeHeaderOrder false")
	}
}

func TestExtractSignals_JA4H_ZeroedCookieHashes(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			JA4HHash: "ge11nn25enus_fc343ccb8320_000000000000_000000000000",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.JA4HZeroedCookieHashes {
		t.Error("JA4H with parts C and D 000000000000 should set JA4HZeroedCookieHashes true")
	}
}

func TestExtractSignals_JA4H_NonZeroedCookieHashes(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			JA4HHash: "ge11cn26ruru_e9eb613b7ad4_68abb940d098_7b022c4b1588",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.JA4HZeroedCookieHashes {
		t.Error("JA4H with non-zero C/D should set JA4HZeroedCookieHashes false")
	}
}

func TestCalculateScores_JA4HZeroedCookieHashes_BotPenalty(t *testing.T) {
	// Proxy forwarded client TLS (ALPN) + no cookies + zeroed C/D → ja4h-no-cookies(+3)
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{FromProxy: true, SSLGreased: "1", Version: "TLS 1.3", ALPN: "h2"},
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:    "Mozilla/5.0 Chrome/142.0.0.0 Safari/537.36",
			Accept:       "text/html",
			AcceptLang:   "en-US,en;q=0.9",
			SecFetchSite: "none",
			SecFetchMode: "navigate",
			SecFetchDest: "document",
			HeaderCount:  25,
			HasCookies:   false,
			JA4HHash:     "ge11nn25enus_abc123_000000000000_000000000000",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !strings.Contains(s.ScoreBreakdown, "ja4h-no-cookies(+3)") {
		t.Errorf("Browser UA + no cookies + zeroed C/D (proxy with client TLS) should get ja4h-no-cookies(+3), got %s", s.ScoreBreakdown)
	}
	// With cookies present, no penalty
	fp.HTTP.HasCookies = true
	fp.HTTP.JA4HHash = "ge11cn25enus_abc123_a1b2c3d4e5f6_f6e5d4c3b2a1"
	s = fingerprint.ExtractSignals(fp)
	if strings.Contains(s.ScoreBreakdown, "ja4h-no-cookies(+3)") {
		t.Error("HasCookies true should not get ja4h-no-cookies penalty")
	}
}

func TestExtractSignals_SecChUA_ModernOrder(t *testing.T) {
	for _, secChUA := range []string{`"Not:A-Brand";v="99"`, `"Not_A Brand";v="99"`, `"Not:A-Brand";v="99", "Chromium";v="120"`} {
		fp := fingerprint.Fingerprint{
			HTTP: fingerprint.HTTPFingerprint{SecChUA: secChUA},
		}
		s := fingerprint.ExtractSignals(fp)
		if !s.SecChUAModernOrder {
			t.Errorf("SecChUA %q should set SecChUAModernOrder true", secChUA)
		}
	}
}

func TestExtractSignals_SecChUA_ChromiumFirst(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			SecChUA: `"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"`,
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if s.SecChUAModernOrder {
		t.Error("Chromium first should set SecChUAModernOrder false")
	}
}

func TestCalculateScores_SecChUAModernOrder_BrowserBonus(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:  "Mozilla/5.0 Chrome/120.0.0.0",
			SecChUA:    `"Not:A-Brand";v="99", "Google Chrome";v="120"`,
			Accept:     "text/html",
			AcceptLang: "en-US",
		},
	}
	s := fingerprint.ExtractSignals(fp)
	// sec-ch-ua-modern gives 0 points (easily spoofable); signal still computed
	if strings.Contains(s.ScoreBreakdown, "sec-ch-ua-modern(+1)") {
		t.Errorf("sec-ch-ua-modern is disabled for scoring; breakdown should not contain it, got %s", s.ScoreBreakdown)
	}
}

func TestCalculateScores_RealBrowserLike_KeepsBrowserScore(t *testing.T) {
	// Fingerprint similar to reference_browser: early accept/accept-language, cookies, optional Sec-CH-UA modern
	order := []string{"x-fp-h2", "accept", "accept-language", "priority", "user-agent", "sec-ch-ua", "cookie", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "accept-encoding"}
	fp := fingerprint.Fingerprint{
		TLS: fingerprint.TLSFingerprint{
			Version:    "TLS 1.3",
			ALPN:       "h2",
			FromProxy:  true,
			SSLGreased: "1",
		},
		HTTP: fingerprint.HTTPFingerprint{
			HeaderOrder:   order,
			HeaderCount:   len(order),
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/145.0.0.0 Safari/537.36",
			Accept:        "text/html,application/xhtml+xml",
			AcceptLang:    "ru-RU,ru;q=0.9",
			AcceptEnc:     "gzip, deflate, br, zstd",
			SecFetchSite:  "none",
			SecFetchMode:  "navigate",
			SecFetchDest:  "document",
			SecChUA:       `"Not:A-Brand";v="99", "Google Chrome";v="145"`,
			HasCookies:    true,
			JA4HHash:      "ge11cn26ruru_e9eb613b7ad4_68abb940d098_7b022c4b1588",
			H2Fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p",
		},
	}
	fp.HTTP.H2Parsed = fingerprint.ParseH2Fingerprint(fp.HTTP.H2Fingerprint)
	s := fingerprint.ExtractSignals(fp)
	if !s.BrowserLikeHeaderOrder {
		t.Error("Real browser-like order should have BrowserLikeHeaderOrder true")
	}
	if s.JA4HZeroedCookieHashes {
		t.Error("Real browser with cookies should not have JA4HZeroedCookieHashes")
	}
	if strings.Contains(s.ScoreBreakdown, "ja4h-no-cookies(+3)") {
		t.Error("Real browser-like fingerprint should not get ja4h-no-cookies in breakdown")
	}
	if s.BrowserScore < 15 {
		t.Errorf("Real browser-like should have browser score >= 15, got %d", s.BrowserScore)
	}
}

func TestExtractSignals_HasCacheControl(t *testing.T) {
	t.Run("present", func(t *testing.T) {
		fp := fingerprint.Fingerprint{
			HTTP: fingerprint.HTTPFingerprint{
				Headers: map[string]string{"cache-control": "max-age=0"},
			},
		}
		s := fingerprint.ExtractSignals(fp)
		if !s.HasCacheControl {
			t.Error("HasCacheControl should be true when cache-control header is present")
		}
	})
	t.Run("absent", func(t *testing.T) {
		fp := fingerprint.Fingerprint{
			HTTP: fingerprint.HTTPFingerprint{
				Headers: map[string]string{"accept": "text/html"},
			},
		}
		s := fingerprint.ExtractSignals(fp)
		if s.HasCacheControl {
			t.Error("HasCacheControl should be false when cache-control header is absent")
		}
	})
	t.Run("empty_value", func(t *testing.T) {
		fp := fingerprint.Fingerprint{
			HTTP: fingerprint.HTTPFingerprint{
				Headers: map[string]string{"cache-control": "   "},
			},
		}
		s := fingerprint.ExtractSignals(fp)
		if s.HasCacheControl {
			t.Error("HasCacheControl should be false when cache-control value is empty/whitespace")
		}
	})
}

func TestExtractSignals_AcceptLangRich(t *testing.T) {
	tests := []struct {
		name       string
		acceptLang string
		wantRich   bool
	}{
		{"rich_three_parts", "ru-RU,ru;q=0.9,en-GB;q=0.8", true},
		{"rich_long", "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6", true},
		{"short_two_parts", "en-US,en;q=0.9", false},
		{"single", "en-US", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := fingerprint.Fingerprint{
				HTTP: fingerprint.HTTPFingerprint{
					AcceptLang: tt.acceptLang,
				},
			}
			s := fingerprint.ExtractSignals(fp)
			if s.AcceptLangRich != tt.wantRich {
				t.Errorf("AcceptLangRich: accept_lang %q => got %v, want %v", tt.acceptLang, s.AcceptLangRich, tt.wantRich)
			}
		})
	}
}

func TestCalculateScores_CacheControlAndAcceptLangRich_BrowserBonus(t *testing.T) {
	fp := fingerprint.Fingerprint{
		HTTP: fingerprint.HTTPFingerprint{
			UserAgent:  "Mozilla/5.0 Chrome/120.0.0.0",
			Accept:     "text/html",
			AcceptLang: "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7",
			Headers:    map[string]string{"cache-control": "max-age=0"},
		},
	}
	s := fingerprint.ExtractSignals(fp)
	if !s.HasCacheControl {
		t.Error("test fingerprint should have HasCacheControl true")
	}
	if !s.AcceptLangRich {
		t.Error("test fingerprint should have AcceptLangRich true")
	}
	if !strings.Contains(s.ScoreBreakdown, "cache-control(+1)") {
		t.Errorf("breakdown should contain cache-control(+1), got %s", s.ScoreBreakdown)
	}
	// accept-lang-rich gives 0 points (easily spoofable); signal still computed
	if strings.Contains(s.ScoreBreakdown, "accept-lang-rich(+1)") {
		t.Errorf("accept-lang-rich is disabled for scoring; breakdown should not contain it, got %s", s.ScoreBreakdown)
	}
}

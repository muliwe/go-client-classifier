package fingerprint

import "testing"

func TestParseH2Fingerprint(t *testing.T) {
	// Example from nginx-http2-fingerprint README
	raw := "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"
	p := ParseH2Fingerprint(raw)
	if p == nil {
		t.Fatal("ParseH2Fingerprint should not return nil for valid input")
	}
	if !p.ParsedOK {
		t.Error("ParsedOK should be true when SETTINGS are present")
	}
	if len(p.Settings) < 3 {
		t.Errorf("expected at least 3 settings, got %d", len(p.Settings))
	}
	// SETTINGS 4 = INITIAL_WINDOW_SIZE
	if p.InitialWindow != 131072 {
		t.Errorf("InitialWindow = %d, want 131072", p.InitialWindow)
	}
	if p.WindowUpdate != 12517377 {
		t.Errorf("WindowUpdate = %d, want 12517377", p.WindowUpdate)
	}
	if p.Priority != "3:0:0:201" {
		t.Errorf("Priority = %q, want 3:0:0:201", p.Priority)
	}
	if len(p.RawSegments) != 4 {
		t.Errorf("RawSegments = %d, want 4", len(p.RawSegments))
	}
}

func TestParseH2Fingerprint_Empty(t *testing.T) {
	if ParseH2Fingerprint("") != nil {
		t.Error("empty string should return nil")
	}
	if ParseH2Fingerprint("   ") != nil {
		t.Error("whitespace-only should return nil")
	}
}

func TestParseH2Fingerprint_NoSettings(t *testing.T) {
	p := ParseH2Fingerprint("|12345|1:0:0:0")
	if p == nil {
		t.Fatal("should return struct for segments without SETTINGS")
	}
	if p.ParsedOK {
		t.Error("ParsedOK should be false when no SETTINGS segment")
	}
	if p.WindowUpdate != 12345 {
		t.Errorf("WindowUpdate = %d, want 12345", p.WindowUpdate)
	}
}

func TestIsBrowserLikeH2InitialWindow(t *testing.T) {
	browserLike := []uint32{65535, 65536, 131072, 1048576, 2097152}
	for _, size := range browserLike {
		if !IsBrowserLikeH2InitialWindow(size) {
			t.Errorf("IsBrowserLikeH2InitialWindow(%d) should be true", size)
		}
	}
	notBrowserLike := []uint32{0, 1, 99999, 100000, 123456}
	for _, size := range notBrowserLike {
		if IsBrowserLikeH2InitialWindow(size) {
			t.Errorf("IsBrowserLikeH2InitialWindow(%d) should be false", size)
		}
	}
}

func TestParseH2Fingerprint_MaxFrameSizeAndFourthSegment(t *testing.T) {
	raw := "1:65536;4:131072;5:16384|12517377|3:0:0:201|m,p,a,s"
	p := ParseH2Fingerprint(raw)
	if p == nil || !p.ParsedOK {
		t.Fatal("expected parsed fingerprint")
	}
	if p.MaxFrameSize != 16384 {
		t.Errorf("MaxFrameSize = %d, want 16384", p.MaxFrameSize)
	}
	if p.PseudoHeaderOrder != "m,p,a,s" {
		t.Errorf("PseudoHeaderOrder = %q, want m,p,a,s", p.PseudoHeaderOrder)
	}
}

func TestIsBrowserLikeH2MaxFrameSize(t *testing.T) {
	for _, size := range []uint32{16384, 16777215} {
		if !IsBrowserLikeH2MaxFrameSize(size) {
			t.Errorf("IsBrowserLikeH2MaxFrameSize(%d) should be true", size)
		}
	}
	for _, size := range []uint32{0, 8192, 1000000} {
		if IsBrowserLikeH2MaxFrameSize(size) {
			t.Errorf("IsBrowserLikeH2MaxFrameSize(%d) should be false", size)
		}
	}
}

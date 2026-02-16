package fingerprint

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	// Stub path and forbid download so tests never hit the network
	_ = os.Setenv("JA4DB_SKIP_DOWNLOAD", "1")
	dir, _ := os.Getwd()
	for dir != "" && dir != string(filepath.Separator) {
		stub := filepath.Join(dir, "testdata", "ja4db_fixture.json")
		if _, err := os.Stat(stub); err == nil {
			_ = os.Setenv("JA4DB_PATH", stub)
			break
		}
		dir = filepath.Dir(dir)
	}
	os.Exit(m.Run())
}

func TestIsKnownLibraryTLS(t *testing.T) {
	tests := []struct {
		ja3, ja4 string
		want     bool
	}{
		{"599ccb0563b7bbae9962ca7e634cc462", "", true}, // Python requests
		{"e7d705a3286e19ea42f587b344ee6865", "", true}, // cURL
		{"E7D705A3286E19EA42F587B344EE6865", "", true}, // cURL uppercase normalized
		{"", "unknown_ja4", false},
		{"abc123def456", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got := IsKnownLibraryTLS(tt.ja3, tt.ja4)
		if got != tt.want {
			t.Errorf("IsKnownLibraryTLS(%q, %q) = %v, want %v", tt.ja3, tt.ja4, got, tt.want)
		}
	}
}

func TestIsKnownLibraryTLS_JA4(t *testing.T) {
	// Synthetic JA4 that is not in ja4db → not in library set
	if got := IsKnownLibraryTLS("", "x00x00x00_000000000000_000000000000"); got {
		t.Error("synthetic JA4 should not be in library set")
	}
	// Python JA4 from ja4db should be in knownLibraryJA4 after init
	if !IsKnownLibraryTLS("", "t13i181000_85036bcba153_d41ae481755e") {
		t.Error("Python JA4 from ja4db should be in knownLibraryJA4")
	}
}

func TestIsKnownBrowserTLS(t *testing.T) {
	tests := []struct {
		ja3, ja4 string
		want     bool
	}{
		{"579ccef312d18482fc42e2b822ca2430", "", true},  // Chrome (Scrapfly)
		{"579CCEF312D18482FC42E2B822CA2430", "", true},  // uppercase normalized
		{"599ccb0563b7bbae9962ca7e634cc462", "", false}, // Python requests (library)
		{"", "", false},
	}
	for _, tt := range tests {
		got := IsKnownBrowserTLS(tt.ja3, tt.ja4)
		if got != tt.want {
			t.Errorf("IsKnownBrowserTLS(%q, %q) = %v, want %v", tt.ja3, tt.ja4, got, tt.want)
		}
	}
	// JA4 from ja4db (Chromium) should be in knownBrowserJA4 after init
	if !IsKnownBrowserTLS("", "t13d1516h2_8daaf6152771_02713d6af862") {
		t.Error("Chromium JA4 from ja4db should be in knownBrowserJA4")
	}
}

func TestJA4ALPN(t *testing.T) {
	tests := []struct {
		ja4  string
		want string
	}{
		{"t13d1516h2_8daaf6152771_02713d6af862", "h2"},
		{"t13i181000_85036bcba153_d41ae481755e", ""},
		{"q13d0312h3_55b375c5d22e_06cda9e17597", "h3"},
		{"", ""},
		{"nounderscore", ""},
	}
	for _, tt := range tests {
		got := JA4ALPN(tt.ja4)
		if got != tt.want {
			t.Errorf("JA4ALPN(%q) = %q, want %q", tt.ja4, got, tt.want)
		}
	}
	// h1: Part A can end with h1 (HTTP/1.1)
	got := JA4ALPN("t12d1010h1_abc_def")
	if got != "h1" {
		t.Errorf("JA4ALPN(t12d1010h1_...) = %q, want h1", got)
	}
}

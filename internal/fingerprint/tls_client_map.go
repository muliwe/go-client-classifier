package fingerprint

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const ja4dbURL = "https://ja4db.com/api/read/"

var (
	ja4dbLoadOnce sync.Once
)

func getJA4DBPath() string {
	if p := os.Getenv("JA4DB_PATH"); p != "" {
		return p
	}
	return filepath.Join("internal", "fingerprint", "data", "ja4db.json")
}

// ensureJA4DBLoaded loads JA4 DB from file (downloads if missing). Called on first use.
// In tests, set JA4DB_PATH to a stub and/or JA4DB_SKIP_DOWNLOAD=1 so nothing is downloaded.
func ensureJA4DBLoaded() {
	ja4dbLoadOnce.Do(func() {
		path := getJA4DBPath()
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				if os.Getenv("JA4DB_SKIP_DOWNLOAD") == "1" {
					return
				}
				if err := downloadJA4DB(path); err != nil {
					log.Printf("[fingerprint] ja4db: download failed (%v), JA4 maps empty", err)
					return
				}
				data, err = os.ReadFile(path)
			}
			if err != nil {
				log.Printf("[fingerprint] ja4db: read failed (%v), JA4 maps empty", err)
				return
			}
		}
		parseAndFillJA4DB(data)
	})
}

func downloadJA4DB(path string) error {
	resp, err := http.Get(ja4dbURL)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ja4db: GET %s: %s", ja4dbURL, resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(f, resp.Body)
	return err
}

func parseAndFillJA4DB(data []byte) {
	var list []ja4dbRecord
	if err := json.Unmarshal(data, &list); err != nil {
		return
	}
	libraryKeywords := []string{"python", "curl", "go ", "nmap", "node", "java", "perl", "ruby", "php", "wget", "httpie", "scrapy", "requests", "urllib", "okhttp", "axios", "bot", "crawler", "semrush", "semrushbot"}
	browserKeywords := []string{"chrome", "chromium", "firefox", "safari", "edge", "opera", "mozilla", "browser"}
	for _, r := range list {
		if r.JA4 == nil || *r.JA4 == "" {
			continue
		}
		ja4 := strings.TrimSpace(*r.JA4)
		app := ""
		if r.Application != nil {
			app = strings.ToLower(*r.Application)
		}
		lib := ""
		if r.Library != nil {
			lib = strings.ToLower(*r.Library)
		}
		ua := ""
		if r.UserAgent != nil {
			ua = strings.ToLower(*r.UserAgent)
		}
		isLibrary := false
		for _, k := range libraryKeywords {
			if strings.Contains(app, k) || strings.Contains(lib, k) || strings.Contains(ua, k) {
				isLibrary = true
				break
			}
		}
		isBrowser := false
		for _, k := range browserKeywords {
			if strings.Contains(app, k) || strings.Contains(ua, k) {
				isBrowser = true
				break
			}
		}
		if isLibrary {
			knownLibraryJA4[ja4] = true
		}
		if isBrowser {
			knownBrowserJA4[ja4] = true
		}
	}
}

// Known library/bot JA3 hashes (32-char MD5). Used for TLS vs User-Agent consistency:
// if UA claims a browser but JA3 is in this set → tls-ua-inconsistent (+bot).
// Sources: Scrapfly (ja3-fingerprint), ja3.me API, curl (daniel.haxx.se), reference payloads
// (tests/testdata), curl-impersonate/curl_cffi measured per profile. See METHODOLOGY Appendix I
// "Collecting JA3 hashes". JA3 may change with library/version; this is a conservative blocklist.
var knownLibraryJA3 = map[string]bool{
	// Python requests / urllib3 (Scrapfly, Cloudflare bot DB)
	"599ccb0563b7bbae9962ca7e634cc462": true,
	// cURL 7.x (Scrapfly, daniel.haxx.se)
	"e7d705a3286e19ea42f587b344ee6865": true,
	// cURL / OpenSSL (observed JA3 from curl with HTTP/2, e.g. Linux deploy)
	"0149f47eabf9a20d0893e2a44e5a6323": true,
	// Go default http.Client (Scrapfly: b32309a26951...; may vary by Go/openssl)
	"b32309a26951c0191840ad2b48942e64": true,
	// Node.js https (Scrapfly: 8f1c5a3428db...; full hash may vary by Node/OpenSSL version)
	"8f1c5a3428db0a2a88c6d34d730c0f2e": true,
	// PowerShell / .NET HttpClient (Windows; observed from Invoke-WebRequest)
	"68b3ecfaf0034bb9fcbecd518b5ab8d4": true,
	// cURL on Windows (curl.exe; ALPN http/1.1, observed from PowerShell)
	"fae0e5d973c96ae1888b99538efa0363": true,
	// curl_cffi / curl-impersonate (Chrome profile; from reference_bot_curl_cffi.json)
	"88ddb7c9e8f79ce9a304f01221a4e3a3": true,
}

// Known library/bot JA4 hashes (full string). Filled from ja4db.com in init().
var knownLibraryJA4 = make(map[string]bool)

// Known browser JA3 hashes (32-char MD5). Static list (ja4db has JA4 only). Scrapfly, ja3.me.
var knownBrowserJA3 = map[string]bool{
	"579ccef312d18482fc42e2b822ca2430": true, // Chrome / curl_cffi
}

// Known browser JA4 hashes (full string). Filled from ja4db.com in init().
var knownBrowserJA4 = make(map[string]bool)

// IsKnownLibraryTLS returns true if the given JA3 or JA4 is in the known-library set.
// Used to detect "browser" User-Agent with library TLS fingerprint (Appendix G).
// Hashes should be normalized (lowercase, no spaces); empty strings are ignored.
func IsKnownLibraryTLS(ja3Hash, ja4Hash string) bool {
	ensureJA4DBLoaded()
	if ja3Hash != "" && knownLibraryJA3[normalizeTLSHash(ja3Hash)] {
		return true
	}
	if ja4Hash != "" && knownLibraryJA4[ja4Hash] {
		return true
	}
	return false
}

// IsKnownBrowserTLS returns true if the given JA3 or JA4 is in the known-browser set.
// Used for consistency: browser UA + browser TLS → +1; bot UA + browser TLS → +2 bot (Appendix G).
func IsKnownBrowserTLS(ja3Hash, ja4Hash string) bool {
	ensureJA4DBLoaded()
	if ja3Hash != "" && knownBrowserJA3[normalizeTLSHash(ja3Hash)] {
		return true
	}
	if ja4Hash != "" && knownBrowserJA4[ja4Hash] {
		return true
	}
	return false
}

func normalizeTLSHash(h string) string {
	return strings.ToLower(strings.TrimSpace(h))
}

// JA4ALPN extracts ALPN from JA4 fingerprint Part A (e.g. t13d1516h2_... → "h2").
// Returns "h2", "h1", "h3" or "" if not present. Used for H2 vs JA4 consistency (Appendix G).
func JA4ALPN(ja4 string) string {
	ja4 = strings.TrimSpace(ja4)
	if ja4 == "" {
		return ""
	}
	partA := ja4
	if idx := strings.Index(ja4, "_"); idx > 0 {
		partA = ja4[:idx]
	}
	// Part A ends with ALPN: h2, h1, h3 (FoxIO JA4 spec)
	if strings.HasSuffix(partA, "h2") {
		return "h2"
	}
	if strings.HasSuffix(partA, "h3") {
		return "h3"
	}
	if strings.HasSuffix(partA, "h1") {
		return "h1"
	}
	return ""
}

// ja4dbRecord matches one entry from https://ja4db.com/api/read/
type ja4dbRecord struct {
	Application *string `json:"application"`
	Library     *string `json:"library"`
	UserAgent   *string `json:"user_agent_string"`
	JA4         *string `json:"ja4_fingerprint"`
}

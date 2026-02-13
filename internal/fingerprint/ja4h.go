package fingerprint

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// JA4H computes the full JA4H fingerprint from an HTTP request.
// Format: JA4H_a_JA4H_b_JA4H_c_JA4H_d
//
// Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md
func JA4H(req *http.Request) string {
	a := JA4H_a(req)
	b := JA4H_b(req)
	c := JA4H_c(req)
	d := JA4H_d(req)

	return fmt.Sprintf("%s_%s_%s_%s", a, b, c, d)
}

// JA4H_a computes the human-readable part of JA4H fingerprint.
// Format: {method}{version}{cookie}{referer}{header_count}{language}
//
// Example: ge20nn14enus (GET, HTTP/2, no cookie, no referer, 14 headers, en-US)
func JA4H_a(req *http.Request) string {
	method := httpMethodCode(req.Method)
	version := httpVersionCode(req.Proto)
	cookie := cookieFlag(req)
	referer := refererFlag(req)
	headerCount := countHeaders(req.Header)
	language := languageCode(req.Header)

	return fmt.Sprintf("%s%s%s%s%02d%s", method, version, cookie, referer, headerCount, language)
}

// JA4H_b computes the header fingerprint.
// SHA256 hash of sorted header names + sorted header values, truncated to 12 hex chars.
//
// Note: Official spec uses original header order, but Go's http.Header is a map
// and doesn't preserve order reliably. We use sorted headers for consistency.
func JA4H_b(req *http.Request) string {
	if len(req.Header) == 0 {
		return strings.Repeat("0", 12)
	}

	// Collect header names (excluding Cookie and Referer for consistency)
	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		lower := strings.ToLower(name)
		if lower != "cookie" && lower != "referer" {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	// Collect header values in sorted name order
	values := make([]string, 0, len(names))
	for _, name := range names {
		if v := req.Header.Get(name); v != "" {
			values = append(values, v)
		}
	}

	// Concatenate sorted names + values
	data := strings.Join(names, ",") + strings.Join(values, ",")

	return truncatedSHA256(data)
}

// JA4H_c computes the cookie names fingerprint.
// SHA256 hash of sorted cookie names, truncated to 12 hex chars.
// Returns "000000000000" if no cookies present.
func JA4H_c(req *http.Request) string {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return strings.Repeat("0", 12)
	}

	names := make([]string, 0, len(cookies))
	for _, c := range cookies {
		names = append(names, c.Name)
	}
	sort.Strings(names)

	data := strings.Join(names, ",")
	return truncatedSHA256(data)
}

// JA4H_d computes the cookie names+values fingerprint.
// SHA256 hash of sorted "name=value" pairs, truncated to 12 hex chars.
// Returns "000000000000" if no cookies present.
func JA4H_d(req *http.Request) string {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return strings.Repeat("0", 12)
	}

	pairs := make([]string, 0, len(cookies))
	for _, c := range cookies {
		pairs = append(pairs, c.Name+"="+c.Value)
	}
	sort.Strings(pairs)

	data := strings.Join(pairs, ",")
	return truncatedSHA256(data)
}

// httpMethodCode returns first 2 lowercase characters of HTTP method.
// GET -> "ge", POST -> "po", DELETE -> "de", etc.
func httpMethodCode(method string) string {
	m := strings.ToLower(method)
	if len(m) < 2 {
		return m + strings.Repeat("0", 2-len(m))
	}
	return m[:2]
}

// httpVersionCode returns HTTP version code.
// HTTP/1.0, HTTP/1.1 -> "11"
// HTTP/2, HTTP/2.0 -> "20"
// HTTP/3, HTTP/3.0 -> "30"
func httpVersionCode(proto string) string {
	parts := strings.Split(proto, "/")
	if len(parts) != 2 {
		return "11"
	}

	version := parts[1]
	switch {
	case strings.HasPrefix(version, "3"):
		return "30"
	case strings.HasPrefix(version, "2"):
		return "20"
	default:
		return "11"
	}
}

// cookieFlag returns "c" if request has cookies, "n" otherwise.
func cookieFlag(req *http.Request) string {
	if len(req.Cookies()) > 0 {
		return "c"
	}
	return "n"
}

// refererFlag returns "r" if request has Referer header, "n" otherwise.
func refererFlag(req *http.Request) string {
	if req.Referer() != "" {
		return "r"
	}
	return "n"
}

// countHeaders returns the number of headers, excluding Cookie and Referer.
// Capped at 99 per JA4H spec.
func countHeaders(headers http.Header) int {
	count := len(headers)

	// Exclude Cookie and Referer from count
	if headers.Get("Cookie") != "" {
		count--
	}
	if headers.Get("Referer") != "" {
		count--
	}

	if count > 99 {
		return 99
	}
	if count < 0 {
		return 0
	}
	return count
}

// languageCode extracts first 4 characters from Accept-Language header.
// Removes hyphens and converts to lowercase.
// Returns "0000" if header is missing or empty.
//
// Examples:
//   - "en-US,en;q=0.9" -> "enus"
//   - "de-DE" -> "dede"
//   - "" -> "0000"
func languageCode(headers http.Header) string {
	lang := headers.Get("Accept-Language")
	if lang == "" {
		return "0000"
	}

	// Take first language (before comma)
	if idx := strings.Index(lang, ","); idx > 0 {
		lang = lang[:idx]
	}

	// Remove quality value (;q=...)
	if idx := strings.Index(lang, ";"); idx > 0 {
		lang = lang[:idx]
	}

	// Remove hyphens, lowercase
	lang = strings.ReplaceAll(lang, "-", "")
	lang = strings.ToLower(lang)

	// Pad or truncate to 4 characters
	if len(lang) < 4 {
		lang += strings.Repeat("0", 4-len(lang))
	}
	return lang[:4]
}

// truncatedSHA256 computes SHA256 hash and returns first 12 hex characters.
func truncatedSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:12]
}

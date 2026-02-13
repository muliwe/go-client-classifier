# Changelog

All notable changes to this project are documented in this file.

## v0.4.0 (2026-02-13)

### JA4H HTTP Fingerprinting Implementation

Core implementation:
- Added JA4H (HTTP fingerprint) computation from JA4+ family
- Custom implementation using existing `HeaderOrder` from collector
- Full JA4H format: `{method}{version}{cookie}{referer}{headers}{lang}_{hash_b}_{hash_c}_{hash_d}`

JA4H components:
- **JA4H_a**: Human-readable part (method, HTTP version, cookie/referer flags, header count, language)
- **JA4H_b**: SHA256 hash of sorted header names and values (12 hex chars)
- **JA4H_c**: SHA256 hash of sorted cookie names (12 hex chars)
- **JA4H_d**: SHA256 hash of sorted cookie name=value pairs (12 hex chars)

New classification signals from JA4H:
- `has_ja4h_fingerprint` - JA4H computed successfully
- `ja4h_language_code` - extracted language (e.g., "enus", "0000")
- `ja4h_missing_language` - language code is "0000" (bot indicator)
- `ja4h_low_header_count` - header count < 5 (bot indicator)
- `ja4h_high_header_count` - header count >= 10 (browser indicator)
- `ja4h_has_cookies` - cookies present in request
- `ja4h_has_referer` - referer header present
- `ja4h_is_http2` - HTTP/2 detected from JA4H
- `ja4h_consistent_signal` - JA4H signals match HTTP signals (inconsistency = evasion)

Scoring integration:
- Browser: +1 for high header count, +1 for referer, +1 for consistent signals
- Bot: +1 for missing language, +1 for low header count, +2 for inconsistent signals

Classifier updates:
- Updated `browserReason()` and `botReason()` to include JA4H indicators
- AI crawler detection now included in bot reasons

Testing:
- Comprehensive unit tests for JA4H computation (`tests/unit/ja4h_test.go`)
- Signal extraction tests (`tests/unit/signals_test.go`)
- Classifier tests with JA4H scenarios (`tests/unit/classifier_test.go`)
- Server and logger tests (`tests/unit/server_test.go`, `tests/unit/logger_test.go`)
- Stub tests in internal packages for `go test ./...` discovery

Project structure:
- Tests moved to `tests/unit/` directory
- Taskfile updated to exclude `cmd/server` from test runs
- All linter errors fixed

Example JA4H fingerprints:
- curl: `ge11nn020000_a00508f53a24_000000000000_000000000000`
- Chrome: `ge20nn14enus_7cf2b917f4b0_000000000000_000000000000`

## v0.3.0 (2026-02-12)

### HTTPS Server with TLS Fingerprinting

Server infrastructure:
- Added HTTPS mode to Go server with configurable TLS certificates
- Environment variables `TLS_CERT` and `TLS_KEY` for certificate configuration
- New `task run:tls` command to start server in HTTPS mode (port 8443)
- Graceful fallback to HTTP mode when certificates not provided
- Added `certs/` directory to `.gitignore` for local development certificates

### TLS Fingerprinting Implementation (Phase 1 Complete)

Core implementation:
- Integrated `github.com/psanford/tlsfingerprint` library for full ClientHello capture
- Implemented custom `fingerprintlistener` wrapper that intercepts TLS handshake
- TLS fingerprint injection into request context via `http.Server.ConnContext`
- Connection unwrapping: `*tls.Conn` -> `fingerprintlistener.Conn` -> fingerprint extraction

Fingerprint data captured:
- `cipher_suites_count`, `extensions_count` - raw counts from ClientHello
- `supported_versions` - TLS versions offered (1.2, 1.3)
- `signature_schemes` - signature algorithms (ecdsa_secp256r1_sha256, rsa_pss_*, etc.)
- `supported_groups` - elliptic curves including GREASE detection
- `has_session_ticket`, `has_early_data` - TLS session features
- `ja3_hash`, `ja4_hash` - computed fingerprint hashes

New classification signals:
- `has_tls_fingerprint` - ClientHello successfully captured
- `has_multiple_groups` - 3+ elliptic curve groups offered
- `has_modern_ciphers` - modern cipher suite detected
- `high_cipher_count` - 15+ cipher suites offered

Scoring and debugging:
- Updated scoring algorithm with TLS-based weights (+2 for high cipher count, +1 for session ticket, etc.)
- Added `score_breakdown` field to debug output with detailed point-by-point explanation
- Format: `BROWSER[signal(+N) ...] BOT[signal(+N) ...]`

Testing:
- New `task integration:tls` for HTTPS integration tests
- Updated test scripts with `--insecure`/`-SkipCertCheck` flags for self-signed certificates
- README updated with TLS certificate setup instructions

Example detection results:
- Chrome 144: browser_score=18, bot_score=0, confidence=0.99
- curl 8.16: browser_score=6, bot_score=9, classification=bot

## v0.2.0 (2026-02-11)

- Initial methodology documentation
- Rule-based classifier implementation
- HTTP signal extraction
- JSON logging for analysis

## v0.1.0 (2026-02-10)

- Project setup
- Basic User-Agent classification (sanity check)

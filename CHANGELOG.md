# Changelog

All notable changes to this project are documented in this file.

## v0.6.0 (2026-02-17)

### Daily request log files

Request logs are now written **by day** to files named `requests_YYYYMMDD.jsonl` (e.g. `logs/requests_20260217.jsonl`) instead of a single `requests.jsonl`.

- **Default behaviour**: `logger.Config.Daily` is `true`; path is `logs/requests_<date>.jsonl` in UTC.
- **Rotation**: When the date changes (e.g. after midnight UTC), the logger closes the current file and opens a new one for the new day without restarting the process.
- **Single-file mode**: Set `Daily: false` in logger config to keep the previous behaviour and use `FileName` (e.g. `requests.jsonl`) as before.

### Test fixtures moved to tests/testdata

- Fixture folder `testdata/` (e.g. `ja4db_fixture.json`) moved to `tests/testdata/`. All TestMain and docs updated to use `tests/testdata/ja4db_fixture.json`.

## v0.5.0 (2026-02-16)

### Nginx TLS termination: proxy header reuse in signal collector

When TLS is terminated at nginx and the Go server receives requests via `proxy_pass`, the collector now reuses fingerprint data from trusted proxy headers instead of requiring a direct TLS connection.

**Trusted proxy detection**
- If `X-Internal-Proxy` is `"1"`, the request is treated as coming from a trusted TLS-terminating proxy (e.g. nginx with fingerprint modules).
- TLS and HTTP/2 data are read from the `X-FP-*` headers; other sources (e.g. `r.TLS`, ConnContext) are ignored for TLS when proxy mode is active.

**Headers consumed (when trusted proxy)**
- `X-FP-TLS-Version` → TLS version (e.g. TLSv1.3)
- `X-FP-TLS-Cipher` → cipher suite name
- `X-FP-TLS-ALPN` → negotiated protocol (h2, http/1.1)
- `X-FP-TLS-SNI` → server name
- `X-FP-JA3` → JA3 hash (from nginx-ssl-ja3 or similar)
- `X-FP-H2` → HTTP/2 fingerprint (from nginx-http2-fingerprint or similar)

**New fingerprint fields**
- `TLS.FromProxy`: true when TLS data came from proxy headers.
- `HTTP.H2Fingerprint`: HTTP/2 fingerprint value when provided by proxy (X-FP-H2).

**New classification signals**
- `tls_from_proxy`: TLS info came from trusted proxy headers (no ClientHello in Go).
- `has_http2_fingerprint`: HTTP/2 fingerprint present (from proxy or future native H2).
- `has_http2_fingerprint_from_proxy`: HTTP/2 fingerprint was supplied via X-FP-H2.

**Scoring**
- When `has_http2_fingerprint` is true, +1 browser score (H2 fingerprint correlates with real clients; see Methodology Appendix F).
- TLS signals (modern TLS, ALPN h2) still apply when populated from proxy headers; JA3 from proxy is used for `has_tls_fingerprint` where applicable. Full JA4/cipher counts are not available from nginx in the current setup.

**Security**
- Proxy headers are only used when `X-Internal-Proxy` is exactly `"1"`. Backends must be deployed so that only the trusted proxy can set this header (e.g. internal network, stripped from external traffic). See [METHODOLOGY.md](docs/METHODOLOGY.md) Appendix F and RFC 9440 / trusted header practices.

**Documentation**
- [docs/nginx.md](docs/nginx.md) — nginx configuration and header usage.
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) Appendix F — Nginx TLS termination and proxy header reuse (rationale, references 2025–2026).

### Cross-validation: TLS vs UA, H2 vs JA4, ALPN vs HTTP version (Appendix G)

**TLS vs User-Agent**
- Known library JA3/JA4 (curl, Python requests, Go, Node.js) and known browser JA3/JA4 (Chrome, etc.) in `internal/fingerprint/tls_client_map.go`. Browser UA + library TLS → +2 bot (`tls-ua-inconsistent`); browser UA + browser TLS → +1 browser (`tls-ua-consistent`); bot UA + browser TLS → +2 bot.
- JA4 set loaded from file (default `internal/fingerprint/data/ja4db.json`); if file missing on first use, downloaded from ja4db.com. Env: `JA4DB_PATH`, `JA4DB_SKIP_DOWNLOAD` (tests never download).

**H2 vs JA4**
- ALPN parsed from JA4 Part A (h2/h1/h3). If JA4 says h2 but request is not HTTP/2 (or h1 but HTTP/2) → +2 bot (`h2-ja4-inconsistent`).

**TLS ALPN vs HTTP version**
- With direct TLS (not from proxy): ALPN must match observed HTTP version (h2 ↔ HTTP/2.0, http/1.1 ↔ non‑HTTP/2). Mismatch → +2 bot (`tls-alpn-http-inconsistent`). Skipped when TLS is from proxy.

**Testing**
- Stub `tests/testdata/ja4db_fixture.json` for unit/integration; `JA4DB_SKIP_DOWNLOAD=1` and `JA4DB_PATH` set in TestMain so no network in tests. Removed large ja4db.json from test trees.

### Scoring fixes: TLS/UA overlap, raw HTTP/1.1, bot UA TLS weights

**TLS vs User-Agent (tls-ua-inconsistent)**
- We only add +2 bot when the fingerprint is in the known-library set *and* not in the known-browser set. The same JA4 can appear in both ja4db categories (e.g. real Chrome); in that case we do not penalize, so real browsers are no longer falsely scored as inconsistent.

**HTTP/1.1 without H2**
- +1 bot is applied only when TLS was available (client could have negotiated HTTP/2). For raw HTTP pipelines (no TLS, e.g. direct to app without nginx) we do not add `http1.1(+1)`.

**Bot User-Agent and TLS/JA4H browser points**
- When the User-Agent is already classified as bot (curl, Python, etc.), we no longer award browser points for TLS (modern-tls, high-ciphers, session-ticket, multi-groups, tls-ext≥10) or for ja4h-consistent. Primitive CLI clients have modern TLS stacks too; without this, curl received 6–7 browser points and the net score was only slightly negative.

**Tests and docs**
- New unit tests: `TestCalculateScores_HTTP11_NoTLS_NoPenalty`, `TestCalculateScores_HTTP11_TLSAvailable_Penalty`, `TestCalculateScores_BotUA_NoTLSBrowserPoints`, `TestCalculateScores_TLSUA_BothSets_NoPenalty`.
- `tests/testdata/ja4db_fixture.json`: added entry with JA4 in both library and browser set (Chrome + python-requests) for the “both sets, no penalty” test.
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) Appendix G “Our current implementation”: updated TLS vs UA (4), added HTTP/1.1 and bot-UA TLS/ja4h bullets; table “HTTP/1.1 without H2” clarified.

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

Performance testing:
- New `tools/benchmark/` HTTP benchmark tool
- New `task bench` and `task bench:tls` commands
- Integration timing tests in `tests/integration/sanity_test.go`
- Handler `SetQuiet()` method to suppress console logging in tests

Benchmark results (localhost, HTTPS with TLS fingerprinting):
- 10 concurrent: ~9,600 RPS (~576K RPM), avg latency 1.0ms
- 50 concurrent: ~14,500 RPS (~870K RPM), avg latency 3.4ms
- Classification logic only: ~7µs avg (~8M theoretical RPM)

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

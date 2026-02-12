# Changelog

All notable changes to this project are documented in this file.

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

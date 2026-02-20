# Changelog

All notable changes to this project are documented in this file.

## v0.8.0 (2026-02-20)

### Absence signals (no-sni, no-alpn, no-bot-red-flags)

- **Bot signals (absence of TLS traits):** When TLS is observed **directly** (not from proxy), missing Server Name Indication or ALPN is now scored as a bot signal. Real browsers send SNI and ALPN for HTTPS; many libraries and scanners do not.
  - **no-sni** (+1): TLS available but no SNI (direct TLS only). Not applied when TLS comes from proxy (X-FP-*), to avoid penalizing deployments where the proxy does not forward X-FP-TLS-SNI.
  - **no-alpn** (+1): TLS available but no ALPN (direct TLS only). Same proxy caveat as no-sni.
- **Optional browser signal:** **no-bot-red-flags** (default **0** points, tunable in config): small browser bonus when none of the smoking-gun bot signals fire (obsolete-tls, exotic-alpn, blind-probe, bot-ua, no-ua, tls-ua-inconsistent, ua-browser-no-grease). Intended for experiments; can be set to +1 in `browser_scores` if desired.
- **Config and docs:** New keys in `bot_scores` (no-sni, no-alpn) and `browser_scores` (no-bot-red-flags). [config/README.md](config/README.md) documents the signals. [docs/METHODOLOGY.md](docs/METHODOLOGY.md) updated: TLS-level signal table, bot/browser weight lists, new subsection "Absence signals (2025–2026 practice)", and default threshold 4 in the formula example. [README.md](README.md) Classification Signals section mentions absence signals.
- **Tests and fixtures:** Unit tests for NoSNI/NoALPN (direct vs proxy) and no-bot-red-flags path; classifier test browser fingerprint now sets `ServerName` so it is not penalized by no-sni; config test expects 29 browser and 26 bot score keys. Reference fixtures `reference_bot_curl_cffi.json` and `reference_browser.json` include `no_sni` and `no_alpn` in the signals object.

### Scoring config (JSON)

- **Externalized scoring** — All scoring points, thresholds, classifier weight and confidence parameters are loaded from a single JSON file at startup (`SCORING_CONFIG` or `config/scoring.json`). Missing or invalid file falls back to built-in defaults. No code changes needed to tune weights or thresholds.
- **config/scoring.json** — Default config with current values (pretty-printed). **config/scoring.default.json** — Reference copy for diff/restore.
- **config/README.md** — Documentation: JSON structure; smoking guns (+3); strong (+2) and weak (+1) bot signals; zero-point (easily spoofable) browser signals; thresholds table; classifier formula.
- **Internal** — `internal/config` loads and merges JSON with defaults; `ToClassifierConfig` / `ToFingerprintScoringConfig` feed classifier and fingerprint. Fallback defaults in `internal/config/scoring.go` and `internal/fingerprint/signals.go`.

### Incognito / first-visit tuning

- **ja4h-no-cookies**: +3 → **+2** so browsers in incognito or first visit (no cookies, JA4H C/D zeroed) are not over-penalized; signal remains strong but no longer smoking-gun level.
- **low-headers**: +2 → **+1** so fewer headers (common in incognito) add less bot score.
- **Tests and reference** — Unit tests and `tests/testdata/reference_bot_curl_cffi.json` updated for new scores. README and config/README.md describe the change.

## v0.7.0 (2026-02-19)

### Benchmark: URL for routing tests

- **`task bench`** and **`task bench:tls`** accept a target URL so you can test different routes (e.g. `/`, `/health`, `/debug`). Pass via variable: `task bench URL=http://localhost:8080/path`, or positionally: `task bench -- http://localhost:8080/path`. Defaults remain `http://localhost:8080/` and `https://localhost:8443/` respectively.
- README Benchmark section updated with URL examples.

### Benchmark: tests

- **`tools/benchmark`**: Logic extracted into `runBenchmark()` for testability. Tests added: `TestRunBenchmark_usesGivenURL` (benchmark hits the given URL/path), `TestRunBenchmark_differentPaths` (e.g. `/health`). Benchmark tool now covered by `go test ./...`.

### Test tasks and coverage

- **`task test`** and **`task test:short`** now run **`go test ./...`** so all packages are tested (internal, tests, tools, cmd). Previously only `./internal/...` and `./tests/...` were listed; `./tools/...` was added, then replaced with `./...` for future-proofing.
- **`cmd/server`**: Dummy test (`TestDummy`) added so the package is no longer reported as `[no test files]` when running `go test ./...`.

### Permissive TLS and smoking-gun signals (obsolete TLS, exotic ALPN)

**Server (direct TLS termination):** Accept all TLS versions and ALPN protocols we can handle instead of rejecting at handshake. Goal: accept connections and classify as bot from fingerprint.
- **MinVersion** TLS 1.0 (was 1.2); **NextProtos** include `h2`, `http/1.1`, `http/1.0`, `http/0.9`, `spdy/3`, `spdy/2`, `spdy/1`, `h2c`, `hq`. Eliminates "client offered only unsupported versions" and "unsupported application protocols" handshake errors so scanners/bots are scored rather than dropped.

**Bot signals (smoking gun, +3 each):**
- **obsolete-tls**: TLS 1.0 or 1.1 → +3 bot (was +1). Outdated clients are often automation or legacy.
- **exotic-alpn**: Negotiated ALPN is legacy/exotic (http/0.9, http/1.0, spdy/*, h2c, hq) → +3 bot. Scanners and bots often send these; real browsers use h2 or http/1.1.
- **blind-probe**: Path not in allowed list (`/`, `/debug`) or method ≠ GET → +3 bot. Bots often probe blindly (e.g. GET /actuator/gateway/routes, POST /cgi-bin/...). Allowed paths match server mux; `/health` is not scored (no classifier). Signal `RequestIsProbe`.

**Tests:** `TestCalculateScores_ObsoleteTLS`, `TestCalculateScores_ExoticALPN`, `TestCalculateScores_BlindProbe` (expect +3 in breakdown; GET `/` and GET `/debug` no probe).

### Spoofable signals and header-order

**header-order-late disabled:** The bot signal `header-order-late` (+2) is no longer applied (0 points). Vanilla nginx does not preserve HTTP header order when proxying; late Accept/Accept-Language can be a proxy artifact. Logic remains in code for possible future use (e.g. when order is passed via a dedicated header from OpenResty).

**Reduced browser weights for easily spoofable signals:** Trivial-to-forge headers no longer carry full weight:
- **sec-fetch**: +3 → +1
- **browser-ua**: +2 → +1
- **sec-ch-ua**: +2 → +1
- **0 points** (not added to breakdown): accept-lang, browser-headers, header-order, sec-ch-ua-modern, accept-lang-rich, headers>=10

**Classifier threshold:** Default threshold 8 → 4 so that real browsers (with fewer spoofable points) still classify as browser when net = browser_score − 4×bot_score > 4.

**Reference data and tests:** `reference_browser.json` (browser_score 25→16), `reference_bot_curl_cffi.json` (browser 21→15, bot 5→3); unit tests and default threshold assertions updated.

### Classifier: browser vs curl (proxy path)

Improves separation of real browsers from curl (or similar) when requests arrive via TLS-terminating proxy. See [Appendix G](docs/METHODOLOGY.md#appendix-g-cross-validation-of-transport-vs-application-fingerprints), [Phase 2](docs/METHODOLOGY.md#phase-2-http2-deep-inspection), [Phase 3](docs/METHODOLOGY.md#phase-3-fingerprint-inconsistency-detection).

**Proxy-path scoring adjustments (fewer false bot points for real browser):**
- **no-session**: Bot penalty for missing session ticket is not applied when TLS is from proxy (X-FP-* does not convey session ticket presence).
- **JA4H consistency**: When TLS is from proxy, JA4H version (11/10) is not compared with `is_http2` in the consistency check; the backend sees HTTP/1.x from the proxy, so the version mismatch is not treated as inconsistency.
- **JA4H bot penalties**: When TLS is from proxy, the three JA4H-based bot penalties are not applied (`ja4h-no-lang`, `ja4h-low-headers`, `ja4h-inconsistent`). JA4H is computed from the request as seen by the backend (after nginx); the header set can differ from what the client sent, so these penalties are skipped to avoid false bot points for real browsers.
- **h2-ua-inconsistent**: When TLS is from proxy, the H2 vs User-Agent inconsistency penalty is not applied. X-FP-H2 may omit some SETTINGS (e.g. id 5 MAX_FRAME_SIZE); with missing MAX_FRAME_SIZE the fingerprint is treated as library-like and would otherwise add +2 bot for real browsers (e.g. Chrome).

**Browser-like H2 and TLS:**
- **INITIAL_WINDOW_SIZE 6291456** (Chrome 6 MiB) is now treated as browser-like (`h2-init-window`). Value 10485760 (typical for curl/libraries) remains non–browser-like.
- **knownLibraryJA3** extended with additional curl/OpenSSL JA3 hashes (e.g. `0149f47eabf9a20d0893e2a44e5a6323`) so that browser UA with library TLS is reliably detected as `tls-ua-inconsistent`.

**New bot signal (stronger detection of spoofed headers):**
- **ua-browser-no-grease**: When TLS is from proxy, User-Agent looks like a browser, and X-FP-SSL-GREASED is empty, +3 bot. Real browsers send GREASE; curl and many HTTP libraries do not.

**HTTP→HTTP proxy (fewer false bots):** When the request arrives via HTTP→HTTP proxy (TLS from proxy but no client TLS forwarded: ALPN, JA3, cipher all empty), two bot penalties are now skipped so normal browsers are not classified as bot:
- **ua-browser-no-grease**: Applied only when the proxy actually forwarded client TLS (ALPN or JA3 or cipher non-empty). For HTTP→HTTP we never see client GREASE, so the penalty is skipped.
- **ja4h-no-cookies**: Skipped when TLS is from proxy and no client TLS was forwarded. No cookies on first request or over HTTP is common; the +3 bot penalty is reserved for the HTTPS path where we have other signals (e.g. TLS vs UA).

**Strengthened bot signals (smoking guns):** Several high-confidence bot indicators now carry stronger weight so automation is classified more reliably: **ua-browser-no-grease** +3, **tls-ua-inconsistent** +3 (browser UA + library TLS or bot UA + browser TLS), **no-ua** +3 (missing User-Agent), **missing-typical** +2 (no Sec-Fetch and missing Accept or Accept-Encoding). **header-order-late** was +2 but is now disabled (0 points) because vanilla nginx does not preserve header order. See METHODOLOGY Appendix I and H.

**Weighted bot score (classification):**
- **net_score = browser_score − 4×bot_score** (constant `BotScoreWeight = 4` in classifier). A few bot points now strongly reduce net so that curl with spoofed headers is classified as bot; real browser with 1–2 bot points stays browser. Default threshold was 8; see subsection *Spoofable signals and header-order* for reduction to 4. See [Scoring Algorithm](docs/METHODOLOGY.md#scoring-algorithm).

**Tests:**
- `TestCalculateScores_FromProxy_NoSession_NoPenalty`, `TestCalculateScores_FromProxy_JA4HVersion_Consistent`, `TestCalculateScores_FromProxy_JA4HBotPenalties_Skipped`, `TestCalculateScores_FromProxy_H2UAInconsistent_Skipped`, `TestCalculateScores_BrowserUA_NoGrease_FromProxy_BotPenalty`, `TestCalculateScores_BrowserUA_NoGrease_FromProxy_HTTPToHTTP_NoPenalty`, `TestCalculateScores_JA4HNoCookies_HTTPToHTTP_NoPenalty`.
- `TestIsBrowserLikeH2InitialWindow`: 6291456 browser-like, 10485760 not browser-like.
- `TestIsKnownLibraryTLS`: curl JA3 `0149f47eabf9a20d0893e2a44e5a6323` in known-library set.

### Classifier: impersonate / curl_cffi detection

Improves separation of real browsers from impersonators (e.g. curl_cffi, curl-impersonate) that send browser-like TLS/H2 and Sec-Fetch headers but differ in header order, absence of cookies, and Sec-CH-UA brand order. See [Appendix I](docs/METHODOLOGY.md#appendix-i-impersonate-and-header-order-detection).

**New signals:**
- **BrowserLikeHeaderOrder**: Accept and Accept-Language in the first 8 positions of `HeaderOrder` → +1 browser (`header-order`). Browser UA but Accept or Accept-Language at index ≥ 10 → +2 bot (`header-order-late`) to separate impersonators.
- **JA4HZeroedCookieHashes**: JA4H parts C and D are `000000000000`. When User-Agent is browser-like and request has no Cookie header → **+3 bot** (`ja4h-no-cookies`). Strong (smoking-gun) signal for automation; applied when TLS is direct or proxy forwarded client TLS; skipped for HTTP→HTTP proxy (see above).
- **SecChUAModernOrder**: First brand in Sec-CH-UA is `Not:A-Brand` or `Not_A Brand` (Chrome 109+) → +1 browser (`sec-ch-ua-modern`). No bot penalty for Chromium-first to avoid false positives on older browsers.
- **HasCacheControl**: Request has Cache-Control header (e.g. `max-age=0` on document navigation) → +1 browser (`cache-control`). Real Chrome often sends it; curl_cffi often omits. No bot penalty when absent.
- **AcceptLangRich**: Accept-Language has ≥3 comma-separated locales or length &gt; 40 → +1 browser (`accept-lang-rich`). Real browsers often send multiple locales; automation often short/single locale. No bot penalty for short value.

**Reference payloads:**
- `tests/testdata/reference_browser.json` and `tests/testdata/reference_bot_curl_cffi.json`: canonical fixtures from real browser and curl_cffi /debug responses for implementation and tests.

**Tests:**
- `TestExtractSignals_HeaderOrder_BrowserLike`, `TestExtractSignals_HeaderOrder_NotBrowserLike`, `TestExtractSignals_HeaderOrder_EmptyOrMissing`.
- `TestExtractSignals_JA4H_ZeroedCookieHashes`, `TestExtractSignals_JA4H_NonZeroedCookieHashes`, `TestCalculateScores_JA4HZeroedCookieHashes_BotPenalty`.
- `TestExtractSignals_SecChUA_ModernOrder`, `TestExtractSignals_SecChUA_ChromiumFirst`, `TestCalculateScores_SecChUAModernOrder_BrowserBonus`.
- `TestExtractSignals_HasCacheControl`, `TestExtractSignals_AcceptLangRich`, `TestCalculateScores_CacheControlAndAcceptLangRich_BrowserBonus`.
- `TestClassify_ImpersonateLikeFingerprint_ClassifiedAsBot`, `TestCalculateScores_RealBrowserLike_KeepsBrowserScore`.

**Documentation:**
- **METHODOLOGY.md**: New [Appendix I — Impersonate and header-order detection](docs/METHODOLOGY.md#appendix-i-impersonate-and-header-order-detection) (purpose, signals, scoring table, risks and mitigations, references). Appendix I extended with “Additional signals”: HasCacheControl, AcceptLangRich (implemented); optional “Known impersonator JA3” (operational list). Appendix D: added `ja4h_zeroed_cookie_hashes` to Signal Extraction table; Example Fingerprints note for zeroed C/D. Background Header Order: short cross-reference to Appendix I.

### X-FP-* proxy headers: JA3 hash, GREASE, obsolete TLS, JA4 ([Appendix H](docs/METHODOLOGY.md#appendix-h-ja3-ja4-and-x-fp-for-bot-detection))

**JA3 hash from proxy**
- **X-FP-JA3-HASH** is now preferred for classification: when present (32-char MD5), it is used as `fingerprint.tls.ja3_hash`; otherwise the backend uses X-FP-JA3 (as hash if it looks like MD5, else computes MD5 of the raw JA3 string). Ensures TLS vs User-Agent checks work regardless of whether nginx sends raw JA3 or hash. Constants: `HeaderFPJA3Hash`, `HeaderFPSSLGreased`, `HeaderFPJA4` in `internal/fingerprint/proxy_headers.go`.
- New helpers: `resolveJA3HashFromProxy`, `isMD5Hex`, `ja3RawToMD5Hash` in collector.

**New proxy headers consumed**
- **X-FP-SSL-GREASED**: stored in `fingerprint.tls.ssl_greased`; when non-empty with modern TLS and non-bot UA → +1 browser (`ssl-greased`).
- **X-FP-JA4**: read when set (e.g. from foxio-llc/ja4-nginx); used for known-library/browser checks and H2 vs ALPN consistency.
- **X-FP-TLS-Version** (obsolete): when TLS 1.0 or 1.1 → +3 bot (`obsolete-tls`). New signals: `TLSObsolete`, `HasSSLGreased`, `TLSExoticALPN`, `RequestIsProbe` (blind-probe).

**Scoring**
- Obsolete TLS (1.0/1.1) → +3 bot (`obsolete-tls(+3)`), smoking gun.
- Exotic ALPN (http/0.9, http/1.0, spdy/*, h2c, hq) → +3 bot (`exotic-alpn(+3)`), smoking gun.
- Blind probe (path ≠ `/` and ≠ `/debug`, or method ≠ GET) → +3 bot (`blind-probe(+3)`), smoking gun.
- GREASE present (X-FP-SSL-GREASED non-empty) + modern TLS + non-bot UA → +1 browser (`ssl-greased(+1)`).
- JA3 hash resolution and JA4 from proxy integrated into existing TLS vs UA and H2 vs JA4 rules.

**Logging for ML and post-hoc analysis**
- **`fingerprint.proxy_headers`**: when the request is from a trusted proxy, the log now includes a map of all raw X-FP-* header values (X-FP-TLS-Version, X-FP-TLS-Cipher, X-FP-TLS-ALPN, X-FP-TLS-SNI, X-FP-JA3, X-FP-JA3-HASH, X-FP-SSL-GREASED, X-FP-JA4, X-FP-H2). Only non-empty values are present. Supports ML training and post-hoc analysis (recomputing hashes, feature engineering). List of header names: `ProxyHeaderNames` in `proxy_headers.go`.

**Documentation**
- **METHODOLOGY.md**: New **Appendix H — JA3, JA4 and X-FP-* for bot detection**: scope of headers, best practices (prefer JA3-HASH, JA3 limitation, multi-layer detection, GREASE, obsolete TLS, trust), scoring summary, references (publications/sources), future TODOs (temporal inconsistency, JA4 at edge, GREASE format, validation dataset).
- Appendix G “Our current implementation”: added Done items for obsolete TLS, GREASE, JA3 hash from proxy.
- Phase 2 table: X-FP-* proxy headers (JA3-HASH, GREASE, obsolete TLS) and X-FP-JA4 consumption marked Done; implementation details block for X-FP-* best practices.
- Phase 3 table: TLS/HTTP version mismatch marked Done (direct TLS only); temporal inconsistency marked Planned with TODO.
- Log Format (JSONL): described `fingerprint.proxy_headers` and derived fields for proxy path.
- **docs/nginx.md**: Example config with X-FP-JA3-HASH, X-FP-SSL-GREASED, optional X-FP-JA4; “Best practices” subsection; JA4 options (nginx module / Fingerproxy).

**Tests**
- `TestCollect_TrustedProxy_JA3HashPreference`, `TestCollect_TrustedProxy_JA3RawHashedWhenNotMD5`; proxy test updated to use X-FP-JA3-HASH (32 chars).
- `TestCalculateScores_ObsoleteTLS`, `TestCalculateScores_SSLGreased_BrowserBonus`.
- `TestCollect_TrustedProxy_ReusesNginxHeaders`: asserts `ProxyHeaders` contains X-FP-TLS-Version, X-FP-JA3-HASH, X-FP-H2.
- `TestCollect_NoProxy_IgnoresXFPHeaders`: asserts `ProxyHeaders` is nil when not from proxy.

**API**
- **Confidence**: the classify response JSON now returns `confidence` as a **string** with 2 decimal places (e.g. `"0.95"`) to avoid float instability in JSON. Internal classification and logs keep full precision (float). Test: `TestServerHandleClassify_ConfidenceAsString`.
- **Debug endpoint** (`/debug`): response now includes top-level `classification`, `score` (weighted net), and `reason` (text summary) so one request gives both the verdict and full fingerprint/signals without calling `/` separately.

### Python tools (antibot testing)

- **tools/python**: New Python tooling with Poetry for scripts that hit the classifier/antibot service.
- **pyproject.toml**: Poetry project (Python ^3.12, dependency `curl-cffi`).
- **antibot_test.py**: Script using curl_cffi to test antibot bypass (browser TLS/HTTP2 impersonation): single-request test and multi-profile run (chrome, chrome110, chrome116, safari, safari_ios).
- **README**: Install (`poetry install`), run (`poetry run python antibot_test.py`), and dependency management.

## v0.6.0 (2026-02-17)

### Daily request log files

Request logs are now written **by day** to files named `requests_YYYYMMDD.jsonl` (e.g. `logs/requests_20260217.jsonl`) instead of a single `requests.jsonl`.

- **Default behaviour**: `logger.Config.Daily` is `true`; path is `logs/requests_<date>.jsonl` in UTC.
- **Rotation**: When the date changes (e.g. after midnight UTC), the logger closes the current file and opens a new one for the new day without restarting the process.
- **Single-file mode**: Set `Daily: false` in logger config to keep the previous behaviour and use `FileName` (e.g. `requests.jsonl`) as before.

### Test fixtures moved to tests/testdata

- Fixture folder `testdata/` (e.g. `ja4db_fixture.json`) moved to `tests/testdata/`. All TestMain and docs updated to use `tests/testdata/ja4db_fixture.json`.

### Dual HTTP + HTTPS listeners

- Server can listen on **both** HTTP and HTTPS at once: set `TLS_PORT` (e.g. `8443`) together with `TLS_CERT`/`TLS_KEY`; HTTP stays on `PORT` (e.g. `8080`), HTTPS on `TLS_PORT` with TLS fingerprinting (JA3/JA4).
- New config: `Config.TLSAddr`; env vars `PORT` and `TLS_PORT` in `cmd/server/main.go`.
- New tasks: `task run:dual` (local HTTP :8080 + HTTPS :8443), `task build:prod` (Linux binary for deploy), `task deploy:build` (alias).
- **TLS Accept retry (no listener exit on single connection error)**: The TLS listener uses `fingerprintlistener`, which reads the ClientHello inside `Accept()`. If that read returns an error (e.g. EOF when the client closes before or during the handshake), the error was being returned from `Accept()` and `net/http.Serve()` would exit. The server now wraps the fingerprint listener in `acceptRetryListener`: on transient errors (`io.EOF` or connection reset / broken pipe from the fingerprint read) it logs and retries `Accept()` instead of propagating the error, so one bad connection no longer stops the HTTPS listener. Compatible with Go 1.22+ (no dependency on Go 1.23+ `net.ErrRetryableAcceptError`).

### Production deploy (systemd)

- README section **Production deploy**: build with `task build:prod`, copy binary and certs to server, install systemd unit with `Restart=always` and `RestartSec=5`, expose HTTP and HTTPS via `PORT` and `TLS_PORT`. Service survives crashes and reboots (`WantedBy=multi-user.target`).

### Go version and tooling

- `go.mod` and `.golangci.yml` require **Go 1.22** (was 1.26) for compatibility with older deploy environments where the 1.26 toolchain is not available.
- README: Go install instructions, explicit `$HOME/go/bin` in PATH (avoids `go` in bad cwd), make PATH permanent (e.g. `~/.bashrc`).

### Classify and log for all paths; 404 for non-root

- **Classify handler**: For every request (any path), the server now collects the fingerprint, classifies, and writes to both the JSONL log and the console; only **GET /** returns 200 JSON, all other paths return **404** (body unchanged). So requests to e.g. `/not-known` are still classified and logged for analysis.
- **Logger**: `file.Sync()` after each log line so entries appear immediately (e.g. when tailing or on NFS).
- **Test**: `TestServerHandleClassify_NotFoundStillLogs` asserts that a request to `/not-known` returns 404 and writes one entry to the JSONL log.

### Classifier threshold and tie-break

- **Default threshold 8**: `Config.Threshold` default is now **8** (was 0). Classification as browser requires net score (browser − bot) ≥ 8; real browsers typically yield net ≥ 8, reducing false browser classification (e.g. curl with many headers).
- **Tie-break by User-Agent**: When net score equals the threshold, classification uses the User-Agent: if `UserAgentIsBot` then bot, else browser (so curl/python with many headers stay bot).
- Tests updated for `Threshold == 8`.

### Real client IP in logs

- **ClientIP**: Console and JSONL logs now show the real client IP when behind a trusted proxy. The server uses `X-Real-IP` or the first IP in `X-Forwarded-For` when the request is from localhost (127.0.0.1 / ::1) or when `X-Internal-Proxy` is `"1"` (e.g. nginx http→http or TLS termination→http). Exported as `ClientIP(r *http.Request)` for tests.
- **Tests**: `TestServerClientIP` (direct, X-Forwarded-For, X-Real-IP, localhost, X-Internal-Proxy); `TestServerHandleClassify_LogsRealIPWhenProxied` (JSONL `remote_addr` from header).
- **PROXY protocol (stream)**: When nginx stream uses `proxy_protocol on`, the TLS listener can parse the PROXY header so that `RemoteAddr` (and logs) show the real client IP. Set `PROXY_PROTOCOL=1` (or `true`) for the Go service and add `proxy_protocol on` to the stream server in nginx. Optional; omit both when not using PROXY protocol. Dependency: `github.com/pires/go-proxyproto`.

### Docs and deploy

- README: Production deploy with **User=** and **Group=** in the systemd unit; **LimitNOFILE=65535** in the unit to avoid connection/SSL errors under load; **viewing logs** (real-time: `journalctl -u go-client-classifier -f`, `tail -f logs/requests_*.jsonl`); certbot **webroot** and **nginx** options when port 80 is in use; troubleshooting empty log (only classify requests are logged).
- docs/nginx.md: Main config and **site file** in `/etc/nginx/sites-available/`; **TLS passthrough** in a separate file included from `stream { }`; **adding fingerprint modules when nginx is already installed** (rebuild with same configure args + modules, replace binary).
- docs/nginx.md: **Stream on port 443** — section on SNI-based routing so that Go terminates TLS on 443 (stream `listen 443` + `ssl_preread`, domain → Go :8443, default → nginx http on :8440); other HTTPS servers must use `listen 8440 ssl`; command `grep -rl "listen.*443"` to list configs; optional **proxy_protocol on** and Go `PROXY_PROTOCOL=1` for real client IP in stream path; **HTTP (port 80)** proxy to Go :8080 with `X-Forwarded-For` and `X-Internal-Proxy "1"` for real client IP; Notes: real IP requires X-Forwarded-For (or X-Real-IP), and X-Internal-Proxy when proxy is not on localhost.
- README: **PROXY_PROTOCOL** env var and optional `Environment=PROXY_PROTOCOL=1` in systemd; env table entry for `PROXY_PROTOCOL`.

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

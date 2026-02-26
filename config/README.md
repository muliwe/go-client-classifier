# Scoring configuration

The scoring config is loaded at service startup (`SCORING_CONFIG` or `config/scoring.json`). On read error, built-in defaults are used (same values as in `scoring.default.json`).

## JSON structure

| Section | Description |
|--------|-------------|
| `classifier` | Bot score weight and threshold: `net = browser_score - bot_score_weight * bot_score`; class **browser** if `net > threshold`. |
| `confidence` | Confidence calculation parameters (no_signal, thresholds and multipliers by signal count, min/max). |
| `thresholds` | Numeric thresholds for signal extraction (header order, cipher count, TLS extensions, JA4H, Accept-Language). |
| `behavioral_edges` | Optional thresholds for request_metrics-based bot signals (Appendix M). When set with Redis, ApplyBehavioralSignals adds bot score per condition. |
| `browser_scores` | Points per browser signal (toward "browser" classification). |
| `bot_scores` | Points per bot signal (toward "bot" classification), including optional behavioural keys (high-request-rate, low-inter-arrival-median, high-inter-arrival-variance, mean-above-median). |

File **scoring.default.json** is the reference default with current values for commit and comparison.

---

## Smoking guns (bot, +3)

Strong automation indicators; a single such signal already strongly pulls toward bot (with weight 4: +3 → +12 toward negative net).

| Key | When it fires |
|-----|----------------|
| `obsolete-tls` | TLS 1.0 / 1.1. Real browsers do not use these. |
| `exotic-alpn` | ALPN like `http/0.9`, `spdy`, `h2c`, `hq` — typical for scanners/bots. |
| `blind-probe` | Request is not GET or path is not `/` or `/debug` (probing disallowed paths). |
| `bot-ua` | User-Agent matches a known bot (curl, python, go-http-client, puppeteer, etc.). |
| `no-ua` | No User-Agent header (legitimate clients always send it). |
| `tls-ua-inconsistent` | UA "browser" but JA3/JA4 is a known library (curl, Go, Python, etc.); or UA bot and TLS browser-like. |
| `ua-browser-no-grease` | Behind nginx: UA browser-like but no GREASE in TLS (real browsers send GREASE). |
| `challenge-failed` | Client Hints challenge failed (UA mismatch, missing cookie/hints, or version mismatch). See [Appendix K](../docs/METHODOLOGY.md#appendix-k-client-hints-behavioural-challenge). |

---

## Strong bot signals (+2)

| Key | When it fires |
|-----|----------------|
| `ai-crawler` | User-Agent matches AI/LLM crawler (gptbot, perplexity, etc.). |
| `ja4h-no-cookies` | Browser UA, no cookies, JA4H C/D zero (incognito/first visit; lowered from +3 so incognito is not classified as bot). |
| `missing-typical` | Missing typical headers (Accept or Accept-Encoding) and no Sec-Fetch. |
| `ja4h-inconsistent` | JA4H inconsistent with HTTP signals (cookies, referer, language, version). |
| `header-order-late` | Header order from proxy: Accept or Accept-Language "late" (index ≥ 12). |
| `h2-ua-inconsistent` | UA browser-like but H2 fingerprint looks like a library (no PRIORITY, non-browser window, etc.). |
| `h2-ja4-inconsistent` | JA4 says h2, request is HTTP/1.1, or vice versa. |
| `tls-alpn-http-inconsistent` | ALPN (h2/http/1.1) does not match actual HTTP version of the request. |

---

## Weak bot signals (+1)

| Key | When it fires |
|-----|----------------|
| `http1.1` | TLS was available but request is HTTP/1.1 without H2 (many bots do not use H2). |
| `accept-*/*` | Accept = `*/*` (typical for libraries). |
| `no-accept-lang` | No Accept-Language and no Sec-Fetch. |
| `low-headers` | Few headers (`header_count < low_header_count_max`); lowered to +1 (incognito may send fewer). |
| `low-ciphers` | Few cipher suites (0 < count < 10). |
| `few-tls-ext` | Few TLS extensions (0 < count < 8). |
| `no-session` | No session ticket (with direct TLS, not behind proxy). |
| `ja4h-no-lang` | No language code in JA4H (0000). |
| `ja4h-low-headers` | Few headers in JA4H (< 5). |
| `no-sni` | TLS available (direct connection) but client did not send SNI (real browsers send SNI for HTTPS). Only applied with direct TLS, not behind proxy. |
| `no-alpn` | TLS available (direct connection) but client did not send ALPN (modern browsers send h2/http/1.1). Only applied with direct TLS, not behind proxy. |
| `high-request-rate` | Request rate (from Redis metrics) above threshold; see [Behavioural metrics](#behavioural-metrics-optional-appendix-m) below. |
| `low-inter-arrival-median` | Median inter-arrival time below threshold (when ≥2 requests in window). |
| `high-inter-arrival-variance` | Inter-arrival std/mean above threshold (when ≥2 requests). |
| `mean-above-median` | Mean/median inter-arrival ratio above threshold (when ≥2 requests, median > 0). |

---

## Behavioural metrics (optional, Appendix M)

When **Redis** is configured and scoring config includes **`behavioral_edges`** and the corresponding **`bot_scores`** keys, the classifier applies request-metrics-based signals before the Client Hints challenge. See [METHODOLOGY.md Appendix M](../docs/METHODOLOGY.md#appendix-m-behavioural-metrics-edge-values-for-bot-scoring).

| Config key / bot_scores key | Default | Description |
|-----------------------------|---------|-------------|
| `behavioral_edges.request_rate_per_min_above` | 1.2 | Add `high-request-rate` bot point when request rate (req/min in window) exceeds this. |
| `behavioral_edges.inter_arrival_median_sec_below` | 3.0 | Add `low-inter-arrival-median` when median inter-arrival (s) is below this (requires ≥2 requests in window). |
| `behavioral_edges.inter_arrival_std_per_mean_above` | 1.4 | Add `high-inter-arrival-variance` when std/mean of inter-arrival times exceeds this. |
| `behavioral_edges.inter_arrival_mean_median_ratio_above` | 1.15 | Add `mean-above-median` when mean/median inter-arrival ratio exceeds this (right-skewed gaps → bot-like). |

The four **bot_scores** keys (`high-request-rate`, `low-inter-arrival-median`, `high-inter-arrival-variance`, `mean-above-median`) default to **1** point each. Exact recall and false positive rate for a cohort can be computed by running **request_log_stats_by_class.py** on the same JSONL; see Appendix M.

---

## Browser score points

- **+2:** `http2` (HTTP/2 used), `high-ciphers` (many cipher suites, typical for browser).
- **+1:** all other keys in `browser_scores`, except those listed below with zero.

---

## Weak / zero-point signals (0 points)

These signals are **easy to spoof** (headers, single header, etc.), so they are explicitly set to 0. They participate in logic (e.g. JA4H consistency) but do not add points.

| Key | Description |
|-----|-------------|
| `accept-language` | Presence of Accept-Language — trivial to spoof. |
| `browser-headers` | Combination of "browser" headers (Sec-Fetch or Accept-Language) — trivial. |
| `sec-ch-ua-modern` | Modern order in Sec-CH-UA (Not:A-Brand etc.) — easy to spoof. |
| `accept-lang-rich` | "Rich" Accept-Language (multiple locales, long string) — easy to spoof. |
| `high-header-count` | High header count — trivial to spoof; count is still used in other checks. |
| `no-bot-red-flags` | None of the smoking-gun bot signals fired (obsolete-tls, exotic-alpn, blind-probe, bot-ua, no-ua, tls-ua-inconsistent, ua-browser-no-grease). Default 0 points (optionally +1 for experiments). |

You can set non-zero values in config if needed (e.g. for experiments).

---

## Thresholds (`thresholds`)

| Key | Default | Purpose |
|-----|---------|---------|
| `browser_like_header_order_max_idx` | 12 | Accept and Accept-Language both before this index → "browser-like" order. |
| `header_order_late_min_idx` | 12 | Index ≥ this → header is considered "late" (impersonator signal). |
| `high_cipher_count_min` | 10 | Cipher suites > this → high-ciphers (browser). |
| `low_cipher_count_max` | 10 | Cipher suites < this (and > 0) → low-ciphers (bot). |
| `tls_ext_browser_min` | 10 | TLS extensions ≥ this → tls-ext>=10 (browser). |
| `few_tls_ext_max` | 8 | TLS extensions < this (and > 0) → few-tls-ext (bot). |
| `supported_groups_min` | 3 | Groups ≥ this → multi-groups (browser). |
| `low_header_count_max` | 5 | Headers < this → low-headers (bot). |
| `ja4h_low_header_count_max` | 5 | Headers in JA4H < this → ja4h-low-headers. |
| `ja4h_high_header_count_min` | 10 | Headers in JA4H ≥ this → ja4h-headers>=10. |
| `accept_lang_min_locale_parts` | 3 | Minimum parts in Accept-Language for "rich" (or length). |
| `accept_lang_min_length` | 40 | Minimum Accept-Language length for "rich". |

---

## Classifier

- **bot_score_weight** (4): multiplier for bot points in the net formula. A few strong bot signals quickly outweigh spoofed browser headers.
- **threshold** (4): decision boundary. `net > threshold` → browser; on equality User-Agent decides (bot UA stays bot).

Formula: **net = browser_score − bot_score_weight × bot_score**.

---

## Client Hints behavioural challenge (Appendix K)

The server can run a behavioural challenge using HTTP Client Hints (Accept-CH, Critical-CH) and a cookie `__ch_nonce` bound to the JA4H fingerprint (parts C and D). See [METHODOLOGY.md Appendix K](../docs/METHODOLOGY.md#appendix-k-client-hints-behavioural-challenge).

**Main config (scoring JSON root):**

| Key | Default | Description |
|-----|---------|-------------|
| `challenge_ttl_sec` | 120 | Default TTL (seconds) for the nonce→User-Agent store. Also sets the `__ch_nonce` cookie **Max-Age** and (when Redis is used) the TTL for nonce behavioural metrics keys, so cookie lifetime and nonce analysis window are synchronized. |

**Server / environment:**

| Env | Description |
|-----|-------------|
| `CHALLENGE_ENABLED` | Set to `0` or `false` to disable the challenge. Default: enabled. |
| `CHALLENGE_TTL_SEC` | Overrides `challenge_ttl_sec` from config (e.g. `120`). |

**Signals (in API/debug output):** `ch_challenge_passed`, `ch_challenge_failed` — set when the challenge was applicable (non-empty JA4H C/D and store configured).

---

## Redis (challenge store and behavioural metrics)

When **`REDIS_URL`** is set (e.g. `redis://localhost:6379/0`), the server uses Redis for both the challenge (nonce) store and behavioural metrics collection. **The in-memory nonce store is not used** in this case; the single source of truth is Redis. This design supports load-balanced deployments where all instances share the same nonce state. References: [METHODOLOGY.md Appendix L](../docs/METHODOLOGY.md#appendix-l-behavioural-monitoring); Redis rate-limiting patterns (Redis.io); BOTracle (Kadel et al., arXiv:2412.02266).

1. **Challenge (nonce) store** — The nonce → User-Agent mapping is stored in Redis. Key pattern: `{REDIS_CHALLENGE_PREFIX}:nonce:<nonce>` (default prefix `ch`). TTL follows `CHALLENGE_TTL_SEC` / `challenge_ttl_sec`.
2. **Behavioural metrics** — Per client IP and per `__ch_nonce` (when present), request timestamps are recorded in Redis sorted sets. When `behavioral_edges` are set in scoring config, the classifier adds bot score points for rate and inter-arrival conditions (see [Appendix M](../docs/METHODOLOGY.md#appendix-m-behavioural-metrics-edge-values-for-bot-scoring)). See [METHODOLOGY.md Appendix L](../docs/METHODOLOGY.md#appendix-l-behavioural-monitoring) and [docs/deploy/README.md](../docs/deploy/README.md).

**Environment:**

| Env | Description |
|-----|-------------|
| `REDIS_URL` | Redis connection URL. If unset, challenge store is in-memory and behavioural metrics are not collected. |
| `REDIS_CHALLENGE_PREFIX` | Key prefix for nonce keys (default `ch`). Example: `ch:nonce:<nonce>`. |
| `REDIS_METRICS_PREFIX` | Key prefix for behavioural metrics keys (default `metrics`). Example: `metrics:ip:<ip>:req`. |
| `REDIS_METRICS_TTL_SEC` | TTL in seconds for metrics keys (e.g. 86400 for 24h for IP keys). Default 86400. |
| `REDIS_METRICS_WINDOW_SEC` | Sliding-window length in seconds for request-count aggregation (e.g. 60 or 300). Default 300. Aligns with session/window used for rate and inter-arrival features. |

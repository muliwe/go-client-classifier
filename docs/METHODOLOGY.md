# Bot Detection Methodology

Research documentation for transport-level HTTP client classification.

## Table of Contents

1. [Research Overview](#research-overview)
2. [Background & Related Work](#background--related-work)
3. [Classification Signals](#classification-signals)
4. [Scoring Algorithm](#scoring-algorithm)
5. [Implementation Details](#implementation-details)
6. [Limitations & Future Work](#limitations--future-work)
7. [References](#references)

**Appendices**
- [Appendix A: Bot User-Agent Patterns](#appendix-a-bot-user-agent-patterns)
- [Appendix B: Browser Header Patterns](#appendix-b-browser-header-patterns)
- [Appendix C: TLS Fingerprinting Implementation](#appendix-c-tls-fingerprinting-implementation)
- [Appendix D: JA4H HTTP Fingerprinting Implementation](#appendix-d-ja4h-http-fingerprinting-implementation)
- [Appendix E: Performance Benchmarks](#appendix-e-performance-benchmarks)
- [Appendix F: Nginx TLS Termination and Proxy Header Reuse](#appendix-f-nginx-tls-termination-and-proxy-header-reuse)
- [Appendix G: Cross-validation of transport vs application fingerprints](#appendix-g-cross-validation-of-transport-vs-application-fingerprints)
- [Appendix H: JA3, JA4 and X-FP-* for bot detection](#appendix-h-ja3-ja4-and-x-fp-for-bot-detection)
- [Appendix I: Impersonate and header-order detection](#appendix-i-impersonate-and-header-order-detection)
- [Appendix J: Request log statistics and collection methodology](#appendix-j-request-log-statistics-and-collection-methodology)
- [Appendix K: Client Hints behavioural challenge](#appendix-k-client-hints-behavioural-challenge)
- [Appendix L: Behavioural monitoring](#appendix-l-behavioural-monitoring)

---

## Research Overview

### Problem Statement

Distinguishing automated HTTP clients (bots, scrapers, LLM agents, headless browsers) from legitimate browsers using **transport-level signals only** — without JavaScript challenges, CAPTCHAs, or behavioral analysis.

### Research Questions

1. **RQ1**: Can transport-level signals (TLS handshake, HTTP/2 negotiation, header structure) reliably distinguish browsers from automation?
2. **RQ2**: Which signals are most predictive for classification?
3. **RQ3**: How do sophisticated bots (headless Chrome, stealth plugins) behave compared to real browsers?
4. **RQ4**: What are the false positive/negative rates for different client types?

### Approach

Rule-based classification using weighted signals extracted from:
- TLS handshake metadata
- HTTP protocol negotiation
- Request header structure and semantics

---

## Background & Related Work

### TLS Fingerprinting

#### JA3 (2017)
Original TLS fingerprinting method that hashes ClientHello parameters:
- SSL/TLS version
- Cipher suites (in order)
- Extensions (in order)
- Elliptic curves
- EC point formats

**Limitation**: Chrome randomized extension order in 2023, breaking JA3 stability.

#### JA4/JA4+ (2023-2024)
Updated fingerprinting addressing JA3 limitations:
- Sorts extensions before hashing (order-independent)
- Three-part structure: `protocol_cipher-hash_extension-hash`
- Extended family: JA4S (server), JA4H (HTTP), JA4L (latency), JA4X (X.509)

**Current status**: Adopted by Cloudflare, Akamai, and major CDNs for bot detection.

#### Key Research

- **FoxIO JA4+ Network Fingerprinting** (2023): Comprehensive JA4 specification and implementation
- **Akamai HTTP/2 Fingerprinting** (2017): Passive fingerprinting via HTTP/2 SETTINGS frames
- **FP-Inconsistent** (2024): Detection of fingerprint inconsistencies in evasive bot traffic (arXiv:2406.07647)

### HTTP-Level Signals

#### Fetch Metadata Headers (Sec-Fetch-*)

Browser-only headers introduced to communicate request context:
- `Sec-Fetch-Site`: Origin relationship (same-origin, cross-site, none)
- `Sec-Fetch-Mode`: Request mode (navigate, cors, no-cors)
- `Sec-Fetch-Dest`: Resource destination (document, image, script)
- `Sec-Fetch-User`: User activation indicator (?1 if user-initiated)

**Important**: These headers have the `Sec-` prefix, making them **forbidden headers** — they cannot be set or modified via JavaScript, making them reliable browser indicators.

#### Client Hints (Sec-CH-UA-*)

Modern replacement for User-Agent providing structured client information:
- `Sec-CH-UA`: Browser brand and version
- `Sec-CH-UA-Mobile`: Mobile indicator
- `Sec-CH-UA-Platform`: Operating system

**Note**: Client hints are opt-in and require server policy headers.

#### Header Order

HTTP clients emit headers in characteristic sequences based on implementation. While not reliable as a sole identifier, header order provides supplementary signal. Header order can also distinguish real browsers from impersonators (e.g. curl_cffi): Accept and Accept-Language tend to appear early in real Chrome; automation often sends a different order. See [Appendix I: Impersonate and header-order detection](#appendix-i-impersonate-and-header-order-detection) for the signals we use.

**Research findings**: Header order is highly variable across middleware and implementations, best used as one feature among many (Radware, 2023).

### AI/LLM Crawler Landscape (2025-2026)

The rise of Large Language Models has created a new category of web crawlers with distinct characteristics and detection challenges.

#### Traffic Volume & Composition

Per Fastly Q2 2025 data:
- AI crawlers constitute ~80% of AI bot traffic
- Meta generates ~52% of AI crawler traffic, Google ~23%, OpenAI ~20%
- "Fetcher" bots (ChatGPT, Perplexity) produce peaks >39,000 requests/minute
- North America receives ~90% of observed AI crawler traffic

Per Imperva 2025 Bad Bot Report:
- Automated traffic surpassed human traffic in 2024 (~51% of web)
- Bad bots account for ~37% of internet traffic
- AI tooling has lowered the barrier for sophisticated bot attacks

#### Types of AI Crawlers

| Type | Purpose | Examples | Behavior |
|------|---------|----------|----------|
| **Training Crawlers** | Collect data for model training | GPTBot, ClaudeBot, CCBot | Bulk crawling, respect robots.txt (sometimes) |
| **Search Crawlers** | Index for AI-powered search | Google-Extended, BingBot | Similar to traditional search crawlers |
| **Fetcher Bots** | Real-time content for RAG | ChatGPT-User, PerplexityBot | High-frequency, real-time requests |
| **Agent Crawlers** | Autonomous AI agents | Various | Unpredictable patterns, tool use |

#### Detection Challenges

1. **User-Agent Spoofing**: AI crawlers can easily spoof browser User-Agents
2. **Distributed Infrastructure**: Use of cloud providers (AWS, GCP, Azure) makes IP blocking difficult
3. **Legitimate Use Cases**: Some AI crawling is beneficial (accessibility, search)
4. **Evolving Landscape**: New crawlers appear frequently; User-Agent strings change
5. **Robots.txt Non-Compliance**: Studies show many AI crawlers selectively ignore robots.txt

#### Key Detection Signals for AI Crawlers

| Signal | Rationale |
|--------|-----------|
| Known AI User-Agent patterns | Direct identification (when not spoofed) |
| Missing Sec-Fetch-* headers | AI crawlers don't send browser-only headers |
| Missing Accept-Language | Browsers always include, crawlers often omit |
| Generic Accept header (`*/*`) | Browsers send specific MIME preferences |
| Low header count | Minimal headers typical of HTTP libraries |
| HTTP/1.1 without H2 (when TLS was available) | Many crawlers don't negotiate HTTP/2; raw HTTP pipeline has no H2 option, so we do not penalize. |
| Missing Client Hints | Sec-CH-UA-* absent |
| Request patterns | High frequency, systematic paths (behavioral) |

#### Recommendations for AI Crawler Detection

1. **Don't rely solely on User-Agent**: Easily spoofed
2. **Use Sec-Fetch-* headers as strong signal**: Cannot be forged via JavaScript
3. **Combine multiple signals**: No single signal is definitive
4. **Consider behavioral patterns**: Request timing, path access patterns
5. **Maintain updated crawler database**: AI landscape changes rapidly
6. **Log everything**: Enable post-hoc analysis and pattern discovery

---

## Classification Signals

### Signal Categories

#### TLS-Level Signals

| Signal | Description | Browser Indicator |
|--------|-------------|-------------------|
| `is_http2` | HTTP/2 protocol negotiated | ✓ (most browsers prefer H2) |
| `has_modern_tls` | TLS 1.2 or 1.3 | ✓ |
| `has_alpn` | ALPN negotiated | ✓ |
| `cipher_suites_count` | Number of offered ciphers | High count (≥15) suggests browser |
| `extensions_count` | Number of TLS extensions | High count (≥10) suggests browser |
| `has_session_ticket` | Session resumption support | ✓ |
| `has_multiple_groups` | ≥3 supported elliptic curve groups | ✓ |
| `has_tls_fingerprint` | Full ClientHello captured | ✓ (required for JA3/JA4) |
| `ja3_hash` | JA3 fingerprint hash | Client identification |
| `ja4_hash` | JA4 fingerprint hash | Client identification (stable) |
| `supported_versions` | TLS versions offered by client | Modern clients offer TLS 1.2+ |
| `signature_schemes` | Signature algorithms supported | Variety suggests browser |
| `supported_groups` | Elliptic curves (incl. GREASE) | GREASE presence suggests browser |
| `no_sni` | TLS available but no Server Name Indication (direct TLS only) | Bot indicator: real browsers send SNI for HTTPS |
| `no_alpn` | TLS available but no ALPN (direct TLS only) | Bot indicator: modern browsers send ALPN (h2, http/1.1) |

**Note on absence signals:** When TLS is observed **directly** (not from proxy), missing SNI or ALPN is scored as a bot signal (+1 each). When TLS comes from a proxy (X-FP-*), we do not set `no_sni`/`no_alpn` because the proxy may omit those headers and we cannot infer whether the client sent them.

#### HTTP-Level Signals

| Signal | Description | Browser Indicator |
|--------|-------------|-------------------|
| `has_sec_fetch_headers` | Sec-Fetch-* headers present | ✓✓ (strong indicator) |
| `has_accept_language` | Accept-Language header | ✓ |
| `has_sec_ch_ua` | Client hints present | ✓✓ |
| `header_count` | Total header count | High (≥10) suggests browser |
| `accept_header` | Accept header value | `*/*` suggests bot |
| `ja4h_hash` | JA4H HTTP fingerprint | Client identification |
| `ja4h_missing_language` | JA4H language code is "0000" | Bot indicator |
| `ja4h_low_header_count` | JA4H header count < 5 | Bot indicator |
| `ja4h_high_header_count` | JA4H header count >= 10 | ✓ |
| `ja4h_has_referer` | JA4H referer flag is 'r' | ✓ |
| `ja4h_consistent_signal` | JA4H matches HTTP signals | ✓ (inconsistency = evasion) |

#### User-Agent Analysis

| Pattern | Classification |
|---------|----------------|
| `curl`, `wget`, `httpie` | Bot |
| `python-requests`, `python-urllib` | Bot |
| `go-http-client`, `axios`, `node-fetch` | Bot |
| `bot`, `crawler`, `spider` | Bot |
| `Mozilla/5.0` + browser tokens | Browser candidate |

### Signal Weights

Current implementation uses the following weights:

**Browser-positive signals:**
```
+3: has_sec_fetch_headers (strong indicator)
+2: is_http2
+2: ua_is_browser (without bot patterns)
+2: has_sec_ch_ua (client hints)
+2: high_cipher_count (>= 15 cipher suites)
+1: has_accept_language
+1: has_browser_headers
+1: has_cookies
+1: header_count >= 10
+1: has_modern_tls
+1: has_session_ticket (TLS session resumption)
+1: has_multiple_groups (>= 3 supported groups)
+1: tls_extensions >= 10
+1: ja4h_high_header_count (>= 10 headers from JA4H)
+1: ja4h_has_referer (referer present from JA4H)
+1: ja4h_consistent_signal (JA4H matches HTTP signals)
+1: has_http2_fingerprint (H2 fingerprint present, e.g. from proxy X-FP-H2)
+1: h2_settings_parsed + browser-like INITIAL_WINDOW_SIZE (parsed H2 fingerprint with common browser window size)
+1: h2_settings_parsed + h2_priority_present (PRIORITY segment non-empty; browsers send, libs often omit)
+1: h2_settings_parsed + h2_window_update_present (WINDOW_UPDATE segment non-zero; flow control, real clients)
+1: h2_settings_parsed + h2_max_frame_size_browser_like (SETTINGS MAX_FRAME_SIZE 16384 or 16777215)
+1: h2_settings_parsed + h2_pseudo_header_order_present (fourth segment non-empty; full fingerprint)
```

**Bot-positive signals:**
```
+3: ua_is_bot (known bot patterns)
+2: low_header_count (< 5 headers)
+2: missing_user_agent
+2: ja4h_inconsistent (JA4H signals don't match HTTP — evasion indicator)
+1: missing_typical_headers
+1: http/1.1 (without H2)
+1: accept = "*/*" (generic)
+1: missing_accept_language (without sec-fetch)
+1: ja4h_missing_language (language code "0000" from JA4H)
+1: ja4h_low_header_count (< 5 headers from JA4H)
+1: no_sni (direct TLS, no Server Name Indication; browsers send SNI for HTTPS)
+1: no_alpn (direct TLS, no ALPN; modern browsers send h2/http/1.1)
```

**Optional browser signal (tunable, default 0):** `no_bot_red_flags` — small bonus when none of the smoking-gun bot signals fire (obsolete-tls, exotic-alpn, blind-probe, bot-ua, no-ua, tls-ua-inconsistent, ua-browser-no-grease). Used for experiments; advanced bots could avoid these and gain the bonus, so default weight is 0.

### Absence signals (2025–2026 practice)

Current scoring uses **presence** of traits (e.g. Sec-Fetch → +browser; bot UA → +bot). Best practice is to also treat **absence** of expected traits as a signal in the opposite direction:

- **Absence of TLS traits → bot:** Real browsers send SNI and ALPN for HTTPS; scanners and many libraries omit or send a minimal set. We therefore add bot points for `no_sni` and `no_alpn` when TLS is observed **directly** (not from proxy), to avoid penalizing deployments where the proxy does not forward SNI/ALPN headers.
- **Absence of smoking-gun bot signals → optional browser:** The `no_bot_red_flags` signal (default 0 points) gives a small browser bonus when none of the strongest bot indicators fire. This is optional and tunable; see [config/README.md](../config/README.md).

Signals such as `no-ua`, `missing-typical`, `ja4h-no-cookies` already implement “absence of browser trait → +bot”. The above extend this to TLS (no SNI/ALPN) and, optionally, to “no red flags → +browser”.

---

## Scoring Algorithm

### Classification Logic

Bot points are **weighted** so that a few strong bot signals (e.g. TLS known library + no GREASE + library-like H2) can outweigh many spoofable browser headers. Real browsers may occasionally get 1–2 bot points; curl with spoofed headers gets several.

```
net_score = browser_score - BotScoreWeight * bot_score   // BotScoreWeight = 4

if net_score > threshold:
    classification = "browser"
else:
    classification = "bot"
```

Default threshold: `4`. With weight 4: e.g. browser 19, bot 6 → net 19−24 = −5 → bot; browser 20, bot 2 → net 20−8 = 12 → browser.

### Confidence Calculation

Confidence is computed from the **final** signals and net score (after the Client Hints challenge, if applied), so that challenge-failed and other post-classify adjustments lower confidence.

```
raw = |net_score| / total_signals   // total_signals = browser_score + bot_score
If total_signals >= 5:  raw *= 1.2  (capped at 1.0)
If total_signals < 3:  raw *= 0.8
confidence = 0.5 + raw * (0.99 - 0.5)   // map into [0.50, 0.99]
```

Parameters (high/low thresholds and multipliers, min/max) are configurable in scoring config.

### Example Classifications

**curl request:**
```
Headers: User-Agent: curl/8.0.1, Accept: */*
Browser score: 0
Bot score: 3 (ua_bot) + 2 (low_headers) + 1 (generic_accept) = 6
Net score: -6
Classification: bot (confidence: 0.99)
```

**Chrome browser:**
```
Headers: Full browser header set with Sec-Fetch-*, Accept-Language, etc.
Browser score: 3 + 2 + 2 + 2 + 1 + 1 + 1 + 1 = 13
Bot score: 0
Net score: +13
Classification: browser (confidence: 0.97)
```

---

## Implementation Details

### Deployment: two data-flow variants

**A) Direct TLS (Go terminates HTTPS)**  
`client → Go TLS listener (:8443) → ConnContext + r.TLS → collector → signals → classifier → response`  
TLS and HTTP/2 are observed directly; JA3/JA4 from ClientHello, H2 from the same connection when implemented.

**B) Via nginx (TLS termination at edge)**  
`client → nginx (443, TLS + JA3 module + H2 fingerprint module) → proxy_pass HTTP → Go (:8080) → collector reads X-FP-* + X-Internal-Proxy: 1 → same signals/classifier → response`  
TLS and H2 fingerprint are taken from trusted proxy headers (X-FP-TLS-*, X-FP-JA3, X-FP-H2); no ClientHello in Go. See [Appendix F](#appendix-f-nginx-tls-termination-and-proxy-header-reuse) and [docs/nginx.md](nginx.md).

### Architecture (collector internals)

```
┌─────────────────────────────────────────────────────────┐
│                   HTTP Request                          │
│        (direct TLS conn or from proxy with X-FP-*)      │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│              Fingerprint Collector                      │
│  ┌──────────────┐  ┌──────────────────────────────────┐ │
│  │ TLS Signals  │  │        HTTP Signals              │ │
│  │ - Version    │  │ - Headers (order, count)         │ │
│  │ - Cipher     │  │ - User-Agent                     │ │
│  │ - ALPN       │  │ - Sec-Fetch-*                    │ │
│  │ - SNI        │  │ - Accept-*                       │ │
│  │ - JA3/JA4    │  │ - JA4H (HTTP fingerprint)        │ │
│  │ or X-FP-*    │  │ - H2 fingerprint (X-FP-H2, v0.5) │ │
│  └──────────────┘  └──────────────────────────────────┘ │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│               Signal Extractor                          │
│  - Pattern matching (bot UA patterns)                   │
│  - Boolean signal extraction                            │
│  - JA4H signal parsing                                  │
│  - Consistency checking (JA4H vs HTTP)                  │
│  - Score calculation                                    │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                 Classifier                              │
│  - Net score calculation                                │
│  - Threshold comparison                                 │
│  - Confidence estimation                                │
│  - Reason generation                                    │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│                JSON Logger                              │
│  - Full fingerprint (TLS + HTTP + JA4H)                 │
│  - All signals                                          │
│  - Classification result                                │
│  - Response time                                        │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Request received** → TLS connection state captured (direct Go TLS) **or** TLS/H2 from X-FP-* headers (when behind trusted proxy, X-Internal-Proxy: 1).
2. **Fingerprint collection** → Extract TLS and HTTP signals: from ConnContext + r.TLS (direct), or from proxy headers (X-FP-TLS-Version, X-FP-JA3, X-FP-H2, etc.) when proxy path is used.
3. **Signal extraction** → Convert raw data to boolean/numeric signals
4. **Score calculation** → Apply weights, compute net score
5. **Classification** → Compare against threshold
6. **Logging** → Write structured JSON for analysis
7. **Response** → Return classification to client

### Log Format (JSONL)

```json
{
  "timestamp": "2026-02-12T12:40:35.460Z",
  "request_id": "1156b9b3-04a1-4de7-a4bb-8fa4cc9d688b",
  "classification": "browser",
  "confidence": 0.99,
  "fingerprint": {
    "tls": {
      "version": "TLS 1.3",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "alpn": "h2",
      "server_name": "localhost",
      "cipher_suites_count": 16,
      "extensions_count": 18,
      "supported_versions": ["TLS 1.3", "raw: TLS 1.2"],
      "signature_schemes": ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "..."],
      "supported_groups": ["GREASE", "x25519", "secp256r1", "secp384r1"],
      "has_session_ticket": true,
      "has_early_data": false,
      "ja3_hash": "9b0d79d10808bc0e509b4789f870a650",
      "ja4_hash": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
      "available": true
    },
    "http": {
      "version": "HTTP/2.0",
      "method": "GET",
      "path": "/debug",
      "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
      "header_count": 14,
      "header_order": ["accept", "sec-fetch-mode", "sec-fetch-dest", "..."],
      "ja4h_hash": "ge20nr14enus_7cf2b917f4b0_a1b2c3d4e5f6_f6e5d4c3b2a1"
    }
  },
  "signals": {
    "is_http2": true,
    "has_modern_tls": true,
    "has_alpn": true,
    "high_cipher_count": true,
    "has_session_support": true,
    "has_tls_fingerprint": true,
    "has_multiple_groups": true,
    "has_modern_ciphers": true,
    "has_sec_fetch_headers": true,
    "has_accept_language": true,
    "has_sec_ch_ua": true,
    "ua_is_bot": false,
    "ua_is_browser": true,
    "has_ja4h_fingerprint": true,
    "ja4h_language_code": "enus",
    "ja4h_missing_language": false,
    "ja4h_low_header_count": false,
    "ja4h_high_header_count": true,
    "ja4h_has_cookies": false,
    "ja4h_has_referer": true,
    "ja4h_is_http2": true,
    "ja4h_consistent_signal": true,
    "browser_score": 21,
    "bot_score": 0,
    "score_breakdown": "BROWSER[http2(+2) sec-fetch(+3) accept-lang(+1) browser-headers(+1) browser-ua(+2) sec-ch-ua(+2) headers>=10(+1) modern-tls(+1) high-ciphers(+2) session-ticket(+1) multi-groups(+1) tls-ext>=10(+1) ja4h-headers>=10(+1) ja4h-referer(+1) ja4h-consistent(+1)] BOT[]"
  },
  "score": 21,
  "reason": "Browser indicators: has Sec-Fetch headers, uses HTTP/2, browser User-Agent, has browser-specific headers, consistent JA4H signals"
}
```

When the request is from a **trusted proxy** (X-Internal-Proxy: 1), the log also includes **`fingerprint.proxy_headers`**: a map of raw X-FP-* header values as received (X-FP-TLS-Version, X-FP-TLS-Cipher, X-FP-TLS-ALPN, X-FP-TLS-SNI, X-FP-JA3, X-FP-JA3-HASH, X-FP-SSL-GREASED, X-FP-JA4, X-FP-H2). Only non-empty values are present. This supports ML training and post-hoc analysis (recomputing hashes, comparing raw vs derived fields, feature engineering). The derived fields `fingerprint.tls` (e.g. `ja3_hash`, `ja4_hash`, `ssl_greased`, `from_proxy`) and `signals` (e.g. `tls_obsolete`, `has_ssl_greased`) are always present when applicable.

**Request log statistics**: Aggregated statistics over these logs (top-N by path, method, IP, user agent, JA3/JA4/JA4H, headers, and per-signal prevalence from `score_breakdown`) are produced by the `request_log_stats.py` tool. The collection method, statistical significance filtering, and interpretation are described in [Appendix J: Request log statistics and collection methodology](#appendix-j-request-log-statistics-and-collection-methodology).

---

## Limitations & Future Work

### Current Limitations

1. **HTTP/2 frame-level capture**: Not implemented in Go. HTTP/2 fingerprint is **consumed from proxy** (e.g. nginx X-FP-H2) in v0.5.0 and used in classification; SETTINGS/WINDOW_UPDATE/PRIORITY capture is done at nginx via modules. Native Go H2 frame parsing is not planned (see Phase 2, [Appendix F](#appendix-f-nginx-tls-termination-and-proxy-header-reuse)).

2. **Behavioral analysis**: Single-request classification remains the primary decision. **Behavioral metrics are collected** (Redis, per IP and per `__ch_nonce`; sliding-window counts and timestamps) for future use — see [Appendix L: Behavioural monitoring](#appendix-l-behavioural-monitoring). **Scoring** based on these metrics is not yet implemented; `/debug` exposes `request_metrics` for the current request.

3. **Evasion vulnerability**: Sophisticated bots can spoof headers (except Sec-Fetch-*).

4. **No ML model**: Rule-based only. ML could improve accuracy.

### Future Work

Based on recent research (2025-2026), the following development roadmap addresses key gaps and incorporates state-of-the-art techniques.

---

#### Phase 1: TLS Fingerprinting Enhancement [COMPLETED]

**Goal**: Implement JA4+ fingerprinting for robust client identification

| Task | Priority | Reference | Status |
|------|----------|-----------|--------|
| [x] Custom TLS listener to capture ClientHello | High | JA4+ spec [2] | Done |
| [x] JA4 hash computation (sorted extensions) | High | FoxIO JA4 [2] | Done |
| [x] JA3 hash computation (legacy compatibility) | High | JA3 spec [1] | Done |
| [x] JA4H (HTTP fingerprint) integration | Medium | JA4+ family | Done |
| [ ] JA4L (latency fingerprint) for timing analysis | Medium | JA4+ family | Planned |
| [ ] Fingerprint database integration (known JA4 hashes) | Medium | Cloudflare [3] | Planned |

**Implementation details (v0.3.0 - TLS)**:
- Integrated `github.com/psanford/tlsfingerprint` library [28] with custom `fingerprintlistener`
- Full ClientHello capture: cipher suites, extensions, supported versions, signature schemes, supported groups
- JA3 and JA4 hash computation from raw ClientHello data
- TLS fingerprint data injected into request context via `http.Server.ConnContext`
- New TLS-based signals: `has_tls_fingerprint`, `has_multiple_groups`, `has_modern_ciphers`, `high_cipher_count`
- Detailed score breakdown in debug output

**Implementation details (v0.4.0 - JA4H)**:
- JA4H HTTP fingerprinting from JA4+ family (method, version, cookies, referer, headers, language)
- New HTTP-based signals: `ja4h_missing_language`, `ja4h_low_header_count`, `ja4h_high_header_count`, `ja4h_has_referer`, `ja4h_consistent_signal`
- Consistency checking between JA4H and HTTP signals (evasion detection)
- See [Appendix D](#appendix-d-ja4h-http-fingerprinting-implementation) for full details

**Why**: Chrome's 2023 extension randomization broke JA3; JA4 provides stable fingerprints. Industry adoption is universal by 2026 [2].

---

#### Phase 2: HTTP/2 Deep Inspection

**Goal**: Extract HTTP/2 frame-level signals per Akamai methodology.

**Implementation approach — nginx modules, not Go libraries**: HTTP/2 fingerprint data is collected at the **nginx** layer using existing modules (e.g. [Xetera/nginx-http2-fingerprint](https://github.com/Xetera/nginx-http2-fingerprint)) and passed to the Go backend via `X-FP-H2`; **consumption in Go is implemented in v0.5.0** (see [Appendix F](#appendix-f-nginx-tls-termination-and-proxy-header-reuse)). Extended statistics (SETTINGS, WINDOW_UPDATE, PRIORITY) remain a deployment concern on nginx. This avoids implementing low-level HTTP/2 frame parsing in Go: there are no mature, production-ready libraries for passive H2 fingerprinting in the Go ecosystem, while nginx already terminates TLS and parses H2 frames; extending it with fingerprint modules is a well-established approach used in CDNs and described in research (Akamai [4]). The nginx→Go integration is documented in [docs/nginx.md](nginx.md).

| Task | Priority | Reference | Status |
|------|----------|-----------|--------|
| [x] HTTP/2 fingerprint consumption from proxy (X-FP-H2) in Go | High | Appendix F, [29] | Done (v0.5.0) |
| [x] HTTP/2 SETTINGS + PRIORITY in fingerprint at nginx | High | Akamai [4], [29] | Done by module (deploy nginx) |
| [x] Flow control / window in fingerprint | Medium | Akamai [4], [29] | Done by module (in $http2_fingerprint) |
| [x] X-FP-* proxy headers: JA3-HASH preference, X-FP-SSL-GREASED, obsolete TLS (1.0/1.1) in scoring | High | Appendix H, F | Done |
| [x] X-FP-JA4 consumption when provided by JA4-capable module | Medium | Appendix F, H | Done |
| [ ] H2/H3 ratio tracking (per-client behavioral) | Medium | Cloudflare signals | Planned |

*Note*: [nginx-http2-fingerprint](https://github.com/Xetera/nginx-http2-fingerprint) implements Akamai’s method: one variable `$http2_fingerprint` includes SETTINGS (incl. INITIAL_WINDOW_SIZE), PRIORITY, and flow-control/window behaviour (RFC 7540 §10.8). Deploy nginx with the module to use; no separate WINDOW_UPDATE variable — it is part of the combined fingerprint.

**Implementation details (v0.5.0)**:
- Collector reuses `X-FP-H2` when `X-Internal-Proxy: 1`; TLS and H2 from proxy headers (see [Appendix F](#appendix-f-nginx-tls-termination-and-proxy-header-reuse)).
- New signals: `has_http2_fingerprint`, `has_http2_fingerprint_from_proxy`, `tls_from_proxy`; +1 browser score for H2 fingerprint.

**Implementation details (X-FP-* best practices, 2025–2026)**:
- JA3 hash from proxy: prefer **X-FP-JA3-HASH** (32-char MD5); fallback to X-FP-JA3 as hash or MD5(raw). Signals/scoring: `has_tls_fingerprint`, `tls-ua-inconsistent` / `tls-ua-consistent` (Appendix G).
- **X-FP-SSL-GREASED** non-empty + modern TLS + non-bot UA → +1 browser (`ssl-greased`). **X-FP-TLS-Version** TLS 1.0/1.1 → +3 bot (`obsolete-tls`). **Exotic ALPN** (http/0.9, spdy, h2c, hq) → +3 bot (`exotic-alpn`). **Blind probe** (path ≠ `/` and ≠ `/debug`, or method ≠ GET) → +3 bot (`blind-probe`). **X-FP-JA4** read when set; used for known-client and H2 vs ALPN consistency. See [Appendix H](#appendix-h-ja3-ja4-and-x-fp-for-bot-detection).

**Why**: HTTP/2 implementation details (initial window size, max concurrent streams, header table size) create passive fingerprints that are hard to spoof [4]. Using nginx at the edge for H2 fingerprinting is a rational choice when no equivalent Go libraries exist and avoids reimplementing protocol parsing.

---

#### Phase 3: Fingerprint Inconsistency Detection

**Goal**: Detect evasive bots via fingerprint inconsistencies (FP-Inconsistent approach)

| Task | Priority | Reference | Status |
|------|----------|-----------|--------|
| [x] Spatial inconsistency detection (cross-signal) | High | FP-Inconsistent [7] | Done (v0.4.0) |
| [x] TLS/HTTP version mismatch detection (direct TLS only; ALPN vs request HTTP version) | Medium | FP-Inconsistent [7], Appendix G | Done; proxy path intentionally skips (backend may be HTTP/1.1) |
| [ ] Temporal inconsistency tracking (same client, different FPs) | High | FP-Inconsistent [7] | Planned — TODO: Appendix H |
| [ ] Header-UA consistency validation (beyond TLS vs UA) | Medium | Radware [10] | Planned |

**Implementation details (v0.4.0)**:
- JA4H consistency checking compares JA4H-derived signals vs HTTP-extracted signals
- Detects mismatches in: cookies, referer, HTTP version
- Inconsistency adds +2 to bot score (evasion indicator)

**Why**: FP-Inconsistent (2024) reduced evasion rates by 44-48% while maintaining 96.84% true-negative rate. Evasive bots produce inconsistent fingerprints across signals [7].

Methodologies for cross-checking "complex" fingerprints (TLS JA3/JA4, HTTP/2, JA4H) with ordinary HTTP headers are summarized in [Appendix G: Cross-validation of transport vs application fingerprints](#appendix-g-cross-validation-of-transport-vs-application-fingerprints).

---

#### Phase 4: AI/LLM Crawler Specialization

**Goal**: Specialized detection for AI training crawlers and fetcher bots

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] Expanded AI crawler User-Agent database | High | Dark Visitors [27] |
| [ ] Cloud provider IP range detection (AWS/GCP/Azure) | High | Fastly [15] |
| [ ] Fetcher bot request pattern detection (high-frequency bursts) | Medium | Fastly [15] |
| [ ] robots.txt compliance verification | Medium | arXiv:2505.21733 [12] |
| [ ] AI crawler traffic volume metrics | Low | Imperva [16] |

**Why**: AI crawlers constitute ~80% of AI bot traffic (Fastly Q2 2025). Many selectively ignore robots.txt [12]. Fetcher bots produce >39K requests/minute peaks [15].

---

#### Phase 5: LLM Output Fingerprinting (Experimental)

**Goal**: Detect AI-generated content in requests (for agent detection)

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] Inter-token timing analysis for LLM detection | Medium | arXiv:2502.20589 [20] |
| [ ] Lexical/POS fingerprint extraction | Low | ACL GenAIDetect [18] |
| [ ] Zero-shot perplexity-based detection | Low | arXiv:2501.02406 [21] |

**Why**: "LLMs Have Rhythm" (2025) shows inter-token timing patterns can identify LLM models even over encrypted streams [20]. Useful for detecting autonomous AI agents.

---

#### Phase 6: Behavioral Analysis

**Goal**: Session-level analysis for sophisticated bot detection

| Task | Priority | Reference | Status |
|------|----------|-----------|--------|
| [x] Request count/timestamp collection (Redis, per IP and per __ch_nonce); /debug request_metrics | High | Appendix L, Redis rate-limiting patterns | Done (v1.0.0); scoring not yet |
| [ ] Request timing pattern analysis (inter-arrival, rate-based scoring) | High | Cloudflare signals, Cresci et al. | Planned |
| [ ] Path access pattern clustering | Medium | - | Planned |
| [ ] Session fingerprint consistency tracking | Medium | FP-Inconsistent [7] | Planned |
| [ ] Mouse/keyboard event analysis (if JS available) | Low | FP-Inspector [8] | Planned |

**Why**: Single-request classification is vulnerable to evasion. Behavioral patterns over sessions are harder to spoof. Redis-backed metrics (Appendix L) provide the storage for future rate and temporal analysis.

---

#### Phase 7: Machine Learning Integration

**Goal**: ML-based classification trained on collected data

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] Feature engineering from fingerprint signals | High | - |
| [ ] Ensemble classifier (multi-model voting) | High | arXiv:2503.01659 [4*] |
| [ ] LoRA fine-tuning for LLM source detection | Medium | FDLLM [19] |
| [ ] Active learning from classification feedback | Medium | - |
| [ ] Adversarial robustness evaluation | Medium | GenAIDetect [23] |

**Why**: Ensemble classifiers achieve 0.9988 precision with unanimous voting across model families [4*]. ML generalizes better than rules but requires quality training data.

---

#### Phase 8: Research Validation & Publication

**Goal**: Academic validation and community contribution

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] Collect diverse traffic dataset (browsers, bots, AI crawlers) | High | - |
| [ ] Cross-validate with commercial services (Cloudflare, DataDome) | Medium | FP-Inconsistent [7] |
| [ ] Measure false positive/negative rates by client type | High | - |
| [ ] Adversarial testing with evasion tools | Medium | Header mutation fuzzing |
| [ ] Public dataset contribution | Low | ESORICS [9] |
| [ ] Research paper preparation | Low | - |

**Why**: FP-Inconsistent evaluated against DataDome (52.93% evasion) and BotD (44.56% evasion). Our system needs similar validation [7].

---

#### Implementation Priority Matrix

```
                    HIGH IMPACT
                         │
    ┌────────────────────┼────────────────────┐
    │                    │                    │
    │  P1: JA4+          │  P3: FP-Inconsist  │
    │  P2: HTTP/2        │  P4: AI Crawlers   │
    │                    │                    │
LOW ├────────────────────┼────────────────────┤ HIGH
EFFORT                   │                    EFFORT
    │                    │                    │
    │  P8: Validation    │  P7: ML            │
    │                    │  P5: LLM FP        │
    │                    │  P6: Behavioral    │
    │                    │                    │
    └────────────────────┼────────────────────┘
                         │
                    LOW IMPACT
```

**Recommended order**: P1 → P4 → P3 → P2 → P6 → P7 → P8 → P5

---

#### Key Metrics to Track

| Metric | Target | Current |
|--------|--------|---------|
| True Positive Rate (bots) | >95% | TBD |
| True Negative Rate (browsers) | >96% | TBD |
| AI Crawler Detection Rate | >90% | TBD |
| Evasion Rate (vs commercial) | <10% | TBD |
| Classification Latency (p99) | <5ms | **~1ms** (measured) |
| Classification Latency (avg) | <1ms | **~7µs** (unit tests) |
| False Positive Rate | <1% | TBD |
| Throughput (RPS) | >10K | **~14.5K** (localhost TLS) |
| Throughput (RPM) | >600K | **~870K** (localhost TLS) |

**Current assessment**

- **Latency and throughput — targets met.** Classification logic is ~7µs per request (unit tests, no I/O); with full TLS handshake and logging, p99 is ~1ms and average ~1–3.4ms depending on concurrency (see [Appendix E: Performance Benchmarks](#appendix-e-performance-benchmarks)). Throughput reaches ~14.5K RPS and ~870K RPM on localhost with TLS (50 concurrent), above the >10K RPS and >600K RPM targets.
- **Accuracy metrics (TPR, TNR, FPR) — TBD.** True/false positive and negative rates require a **labeled validation set** (ground-truth browser vs bot per request). We do not yet have a curated test set or a controlled experiment with known clients. Production log aggregates (e.g. [Appendix J](#appendix-j-request-log-statistics-and-collection-methodology) sample: ~36% bot / ~64% browser, score medians bot −23 vs browser 0) show clear score separation but do not substitute for labeled evaluation. **Next step:** build a labeled dataset (e.g. known browser sessions + known bot UAs and tools) and report confusion matrix and TPR/TNR/FPR.
- **AI crawler detection — TBD.** We match known AI crawler User-Agents (Appendix A: GPTBot, ClaudeBot, etc.) and score them as bot when `ua_is_bot` fires; we have no dedicated AI-crawler validation (e.g. traffic from labeled AI fetchers). **Next step:** collect or synthesize AI-crawler traffic and measure detection rate.
- **Evasion rate — TBD.** Evasion rate vs commercial solutions would require running the same traffic through this classifier and a commercial anti-bot product and comparing miss rates. Not performed. FP-Inconsistent (2024) reports ~44–48% evasion reduction with consistency rules; our JA4H and TLS-vs-UA checks follow a similar idea but are not benchmarked against a commercial baseline. **Next step:** optional A/B or replay study vs a commercial endpoint.

---

#### Research Questions for Each Phase

**P1 (JA4+)**:
- How stable are JA4 fingerprints across browser updates?
- What's the collision rate for legitimate clients?

**P3 (FP-Inconsistent)**:
- Which signal combinations are most discriminative?
- How do sophisticated bots (headless Chrome) score on inconsistency?

**P4 (AI Crawlers)**:
- Do AI crawlers follow any identifiable behavioral patterns?
- How effective is IP-based detection vs fingerprinting?

**P7 (ML)**:
- What's the minimum training set size for robust classification?
- How quickly do models degrade as bot techniques evolve?

---

## References

### TLS Fingerprinting

1. **JA3 - SSL/TLS Client Fingerprinting** (Salesforce, 2017)
   - GitHub: https://github.com/salesforce/ja3
   - Original JA3 specification and implementation

2. **JA4+ Network Fingerprinting** (FoxIO, 2023-2024)
   - https://github.com/FoxIO-LLC/ja4
   - Medium: https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637
   - JA4H Technical Details: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md
   - Updated fingerprinting addressing Chrome randomization
   - JA4+ family: JA4 (TLS), JA4S (Server), JA4H (HTTP), JA4L (Latency), JA4X (X.509)

3. **Cloudflare JA3/JA4 Documentation**
   - https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/
   - Enterprise bot management integration

### HTTP Fingerprinting

4. **Passive Fingerprinting of HTTP/2 Clients** (Akamai, BlackHat EU 2017)
   - https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
   - HTTP/2 SETTINGS frame fingerprinting; rationale for extracting H2 stats at the proxy (nginx) layer rather than in application code

5. **Fetch Metadata Request Headers** (W3C)
   - https://w3c.github.io/webappsec-fetch-metadata/
   - Sec-Fetch-* header specification

6. **Client Hints** (IETF/W3C)
   - https://developer.mozilla.org/en-US/docs/Web/HTTP/Client_hints
   - Sec-CH-UA-* headers

### Bot Detection Research

7. **FP-Inconsistent: Measurement and Analysis of Fingerprint Inconsistencies in Evasive Bot Traffic** (2024)
   - arXiv: https://arxiv.org/abs/2406.07647
   - Fingerprint inconsistency detection for evasive bots

8. **FP-Inspector: Detecting Browser Fingerprinting** (2020)
   - arXiv: https://arxiv.org/abs/2008.04480
   - ML-based fingerprinting script detection

9. **Fingerprint Surface-based Detection of Web Bot Detectors** (ESORICS 2019)
   - https://bkrumnow.github.io/fpbotdetection/
   - Comparing fingerprint surfaces of browsers vs automation

10. **HTTP Header Anomaly-based Advanced Behavioural Bot Detection** (Radware, 2023)
    - https://www.radware.com/blog/application-protection/http-header-anomaly-based-advanced-behavioural-bot-detection/
    - Header-based detection in practice

### AI/LLM Crawler Research (2025-2026)

11. **Somesite I Used To Crawl: Awareness, Agency and Efficacy in Protecting Content Creators From AI Crawlers** (IMC 2025)
    - https://www.sysnet.ucsd.edu/~voelker/pubs/robots-imc25.pdf
    - UCSD study of 203 professional artists + large-scale measurements
    - Finds robots.txt/NoAI tags widely demanded but limited efficacy; reverse-proxy blocking stronger but underdeployed
    - Key insight: many AI crawlers don't check or selectively ignore robots.txt

12. **Scrapers Selectively Respect robots.txt Directives: Evidence from a Large-Scale Empirical Study** (2025)
    - arXiv: https://arxiv.org/abs/2505.21733
    - Empirical evidence that bots selectively comply with robots.txt
    - AI search crawlers rarely check robots.txt at all
    - Stricter directives less likely to be obeyed

13. **Web Crawler Restrictions, AI Training Datasets & Political Biases** (HAL/2025)
    - https://hal.science/hal-05302425/document
    - Study of robots.txt blocking patterns across news sites
    - 60% of reputable news sites block AI crawlers vs 9.1% of misinformation sites
    - Reputable sites forbid ~15.5 AI user agents on average
    - Raises concerns about AI training data bias toward lower-quality sources

14. **From Googlebot to GPTBot: Who's Crawling Your Site in 2025** (Cloudflare, 2025)
    - https://blog.cloudflare.com/from-googlebot-to-gptbot-whos-crawling-your-site-in-2025
    - Industry overview of AI crawler landscape
    - Documents major LLM crawlers: GPTBot, ClaudeBot, Google-Extended, PerplexityBot

15. **Fastly Q2 2025 Threat Insights: AI Crawler Traffic Analysis**
    - https://www.fastly.com/press/press-releases/new-fastly-threat-research-reveals-ai-crawlers-make-up-almost-80-of-ai-bot
    - AI crawlers ≈80% of AI bot traffic
    - Meta ~52%, Google ~23%, OpenAI ~20% of AI crawler traffic
    - Fetcher bots (ChatGPT/Perplexity) produce >39,000 requests/minute peaks
    - North America receives ~90% of AI crawler traffic

16. **Imperva 2025 Bad Bot Report**
    - https://www.imperva.com/resources/reports/2025-Bad-Bot-Report.pdf
    - Automated traffic surpassed human traffic in 2024 (~51%)
    - Bad bots ≈37% of internet traffic
    - AI tooling lowered attacker barrier; sophistication rising

### LLM Fingerprinting & Detection (2024-2026)

17. **LLMmap: Fingerprinting For Large Language Models** (USENIX 2024)
    - arXiv: https://arxiv.org/abs/2407.15847
    - Active fingerprinting with 8 targeted prompts identifies 42 LLM versions at >95% accuracy
    - Works across system prompts, sampling settings, RAG/CoT pipelines
    - Effective on proprietary and open-source models

18. **Your Large Language Models are Leaving Fingerprints** (ACL GenAIDetect 2025)
    - https://aclanthology.org/2025.genaidetect-1.6/
    - Detection via lexical n-grams and POS features
    - Persistent model-family "fingerprints" but poor cross-family transfer

19. **FDLLM: A Dedicated Detector for Black-Box LLMs Fingerprinting** (2025)
    - arXiv: https://arxiv.org/abs/2501.16029
    - LoRA fine-tuning on FD-Dataset (90k samples from 20 LLMs)
    - Learns separable representations for source LLM identification

20. **LLMs Have Rhythm: Inter-Token Timing for LLM Fingerprinting** (2025)
    - arXiv: https://arxiv.org/abs/2502.20589
    - Passive fingerprinting via inter-token timing patterns
    - Works over encrypted streams, local/remote/VPN scenarios
    - Useful for detecting bot/crawler LLM usage from network traffic

21. **Zero-Shot Statistical Tests for LLM-Generated Text Detection** (2025)
    - arXiv: https://arxiv.org/abs/2501.02406
    - Log-perplexity based statistical tests
    - ~82.5% TPR at 5% FPR; error rates shrink exponentially with text length

22. **Detecting LLM-Generated Text with Performance Guarantees** (2026)
    - arXiv: https://arxiv.org/abs/2601.06586
    - Classifier approach with statistical inference and type-I error control
    - No reliance on watermarks/auxiliary info

23. **Benchmarking AI Text Detection** (ACL GenAIDetect 2025)
    - https://aclanthology.org/2025.genaidetect-1.4/
    - Evaluation of detectors (OpenAI Detector, RADAR, ArguGPT)
    - Finds detectors brittle across domains and vulnerable to evasion

### Tools & Datasets

24. **FingerprintJS**
    - https://fingerprint.com/
    - Browser fingerprinting library and commercial service

25. **CreepJS**
    - https://abrahamjuliot.github.io/creepjs/
    - Advanced fingerprinting and lie detection

26. **BrowserLeaks**
    - https://browserleaks.com/
    - Comprehensive browser fingerprint testing

27. **Dark Visitors - AI Crawler Database**
    - https://darkvisitors.com/
    - Maintained list of known AI crawlers and their User-Agent strings
    - Community-driven updates

28. **psanford/tlsfingerprint** (Go library)
    - https://github.com/psanford/tlsfingerprint
    - Go implementation for TLS ClientHello fingerprinting
    - Used in this project for JA3/JA4 hash computation

29. **nginx-http2-fingerprint** (nginx module)
    - https://github.com/Xetera/nginx-http2-fingerprint
    - Passive HTTP/2 fingerprinting (SETTINGS/priority) as nginx module; used for planned H2 statistics collection at the edge instead of Go-side parsing (no mature H2 fingerprinting libs in Go). See [Phase 2: HTTP/2 Deep Inspection](#phase-2-http2-deep-inspection), [Appendix F](#appendix-f-nginx-tls-termination-and-proxy-header-reuse), and [docs/nginx.md](nginx.md).

30. **Fingerproxy** (Go reverse proxy)
    - https://github.com/wi1dcard/fingerproxy
    - Captures JA3, JA4, and HTTP/2 fingerprints and forwards to backends via headers (X-JA3-Fingerprint, X-JA4-Fingerprint, X-HTTP2-Fingerprint). Production use (e.g. Subscan.io). Rationale for proxy-side fingerprint collection and header forwarding.

31. **Finch** (fingerprint-based actions)
    - https://github.com/0x4D31/finch
    - Real-time actions (block, reroute, tarpit) based on JA3, JA4, QUIC, JA4H, HTTP/2 fingerprints. Alternative to in-app fingerprint parsing.

32. **Scrapfly HTTP/2 Fingerprint**
    - https://scrapfly.io/web-scraping-tools/http2-fingerprint
    - Format SETTINGS|WINDOW_UPDATE|PRIORITY|...; browser vs library differences; used for bot detection. See Appendix F (HTTP/2 scoring).

33. **HTTP/2 fingerprinting** (lwt hiker)
    - https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html
    - Browsers send PRIORITY; libraries often omit; SETTINGS/window differ (e.g. curl). See Appendix F (HTTP/2 scoring).

34. **When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints** (arXiv:2602.09606)
    - https://arxiv.org/abs/2602.09606
    - JA4-based bot detection; 98.63% accuracy, AUC 0.998; TLS vs HTTP correlation. See [Cross-validation of transport vs application fingerprints](#cross-validation-of-transport-vs-application-fingerprints).

---

## Appendix A: Bot User-Agent Patterns

### HTTP Libraries

```
curl/*
wget/*
python-requests/*
python-urllib/*
python-httpx/*
aiohttp/*
go-http-client/*
okhttp/*
apache-httpclient/*
axios/*
node-fetch/*
undici/*
got/*
superagent/*
```

### Automation Frameworks

```
puppeteer/*
playwright/*
selenium/*
phantomjs/*
headlesschrome/*
```

### Crawlers & Bots

```
googlebot/*
bingbot/*
yandexbot/*
baiduspider/*
duckduckbot/*
slackbot/*
twitterbot/*
facebookexternalhit/*
linkedinbot/*
```

### AI/LLM Crawlers & Agents

```
# OpenAI
GPTBot/*
ChatGPT-User/*
OAI-SearchBot/*

# Anthropic
ClaudeBot/*
Claude-Web/*
anthropic-ai/*

# Google
Google-Extended/*
GoogleOther/*

# Meta
Meta-ExternalAgent/*
Meta-ExternalFetcher/*
FacebookBot/*

# Microsoft/Bing
Bingbot/*
BingPreview/*

# Perplexity
PerplexityBot/*

# Other AI Services
Bytespider/*
CCBot/*
cohere-ai/*
Diffbot/*
YouBot/*
AI2Bot/*
Amazonbot/*
AppleBot-Extended/*
iaskspider/*
Scrapy/*
```

### AI Fetcher Bots (Real-time RAG)

These fetch content in real-time for AI responses:

```
ChatGPT-User/*          # ChatGPT browsing/plugins
PerplexityBot/*         # Perplexity search
You.com/*               # You.com search
Phind/*                 # Phind code search
```

---

## Appendix B: Browser Header Patterns

### Typical Chrome Request Headers

```
Host: example.com
Connection: keep-alive
sec-ch-ua: "Chromium";v="120", "Google Chrome";v="120", "Not-A.Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
```

### Typical curl Request Headers

```
Host: example.com
User-Agent: curl/8.0.1
Accept: */*
```

---

## Appendix C: TLS Fingerprinting Implementation

This appendix describes the **direct TLS** path (Go terminates HTTPS). When TLS is terminated at nginx, the collector uses X-FP-* headers instead of ConnContext; see [Appendix F](#appendix-f-nginx-tls-termination-and-proxy-header-reuse).

### Architecture (direct TLS only)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Incoming TLS Connection (to Go)                          │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                     net.Listen("tcp", ":8443")                              │
│                         Raw TCP Listener                                    │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│              fingerprintlistener.NewListener(tcpListener)                   │
│                                                                             │
│   Intercepts ClientHello before TLS handshake completes:                    │
│   - Reads raw ClientHello bytes                                             │
│   - Parses cipher suites, extensions, versions, groups                      │
│   - Computes JA3 and JA4 hashes                                             │
│   - Stores fingerprint in connection wrapper                                │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                   http.Server.ServeTLS(fpListener, "", "")                  │
│                                                                             │
│   TLS handshake completes, HTTP/2 or HTTP/1.1 negotiated                    │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      http.Server.ConnContext                                │
│                                                                             │
│   func(ctx context.Context, c net.Conn) context.Context {                   │
│       // Unwrap *tls.Conn to get underlying fingerprintlistener.Conn        │
│       tlsConn := c.(*tls.Conn)                                              │
│       fpConn := tlsConn.NetConn().(fingerprintlistener.Conn)                │
│       fp := fpConn.Fingerprint()                                            │
│       return context.WithValue(ctx, ContextKeyTLSFingerprint, fp)           │
│   }                                                                         │
└─────────────────────────────┬───────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         HTTP Handler                                        │
│                                                                             │
│   fp := ctx.Value(ContextKeyTLSFingerprint).(*tlsfingerprint.Fingerprint)   │
│   - Access fp.CipherSuites, fp.Extensions, fp.SupportedVersions             │
│   - Access fp.JA3Hash(), fp.JA4Hash()                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Library Used

**github.com/psanford/tlsfingerprint** [28] (v0.0.0-20251111180026-c742e470de9b)

This library provides:
- `fingerprintlistener.NewListener()` - wraps net.Listener to capture ClientHello
- `fingerprintlistener.Conn` - connection interface with `Fingerprint()` method
- `tlsfingerprint.Fingerprint` - struct containing parsed ClientHello data
- Built-in JA3 and JA4 hash computation

### Fingerprint Data Structure

```go
type Fingerprint struct {
    Version           uint16       // Negotiated TLS version
    RawVersion        uint16       // Raw version from ClientHello (0x0303 for TLS 1.2)
    CipherSuites      []uint16     // Offered cipher suites
    Extensions        []uint16     // TLS extension IDs
    SupportedVersions []uint16     // From supported_versions extension
    SupportedGroups   []uint16     // Elliptic curve groups (incl. GREASE)
    SignatureSchemes  []uint16     // Signature algorithms
    ALPNProtocols     []string     // Application layer protocols
    // ... additional fields
}
```

### JA3 Hash Computation

JA3 format: `version,ciphers,extensions,curves,point_formats`

Example for curl:
```
771,4866-4867-4865-49196-49200-159-52393-52392-52394-49195-49199-158-49188-49192-107-49187-49191-103-49162-49172-57-49161-49171-51-157-156-61-60-53-47-255,0-11-10-35-22-23-13-43-45-51,29-23-24,0
```

MD5 hash: `2e6c64f66822fc35b6a7a128b557f1de`

### JA4 Hash Computation

JA4 format: `protocol_version_ciphers_extensions`

Three-part structure:
1. `t13d2012h1` - protocol info (TLS 1.3, 20 ciphers, 12 extensions, HTTP/1.1)
2. `2b729b4bf6f3` - truncated SHA256 of sorted cipher suites
3. `36bf25f296df` - truncated SHA256 of sorted extensions

Example for curl: `t13d2012h1_2b729b4bf6f3_36bf25f296df`

### Scoring Integration

TLS fingerprint signals contribute to browser/bot scoring:

| Signal | Condition | Score |
|--------|-----------|-------|
| `has_modern_tls` | TLS 1.2 or 1.3 | +1 browser |
| `high_cipher_count` | >= 15 cipher suites | +2 browser |
| `has_session_support` | Session ticket extension present | +1 browser |
| `has_multiple_groups` | >= 3 elliptic curve groups | +1 browser |
| `has_tls_fingerprint` | ClientHello captured | (required for above) |
| Extensions >= 10 | Extension count check | +1 browser |

### Example Output

**Chrome 144 (real browser):**
```json
{
  "cipher_suites_count": 16,
  "extensions_count": 18,
  "supported_groups": ["GREASE", "0x11ec", "x25519", "secp256r1", "secp384r1"],
  "ja3_hash": "9b0d79d10808bc0e509b4789f870a650",
  "ja4_hash": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
  "browser_score": 18,
  "bot_score": 0
}
```

**curl 8.16:**
```json
{
  "cipher_suites_count": 20,
  "extensions_count": 12,
  "supported_groups": ["x25519", "secp256r1", "secp384r1"],
  "ja3_hash": "2e6c64f66822fc35b6a7a128b557f1de",
  "ja4_hash": "t13d2012h1_2b729b4bf6f3_36bf25f296df",
  "browser_score": 6,
  "bot_score": 9
}
```

### Key Observations

1. **GREASE detection**: Chrome includes GREASE values (0x0a0a, 0x1a1a, etc.) in supported_groups and extensions. This is a strong browser indicator.

2. **Extension count**: Browsers typically have 15-20 extensions, while HTTP libraries have 10-15.

3. **Cipher suite ordering**: While JA3 is order-dependent, JA4 sorts before hashing for stability across browser updates.

4. **HTTP/2 correlation**: Browsers negotiate HTTP/2 via ALPN (`h2`), while curl defaults to HTTP/1.1.

5. **Session tickets**: Both browsers and modern HTTP clients support session tickets, so this signal is weak alone but contributes to overall scoring.

---

## Appendix D: JA4H HTTP Fingerprinting Implementation

*Added: 2026-02-13 (v0.4.0)*

### Overview

JA4H is part of the JA4+ fingerprinting suite developed by FoxIO [2]. While JA3/JA4 fingerprint TLS connections, JA4H fingerprints HTTP requests themselves — method, version, headers, cookies, and language preferences.

Reference: [FoxIO JA4H Technical Details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md)

### JA4H Format

Full format: `JA4H_a_JA4H_b_JA4H_c_JA4H_d`

**JA4H_a (human-readable):** `{method}{version}{cookie}{referer}{headers}{lang}`
- `method`: ge (GET), po (POST), pu (PUT), de (DELETE), pa (PATCH), he (HEAD), op (OPTIONS), co (CONNECT), tr (TRACE)
- `version`: 10 (HTTP/1.0), 11 (HTTP/1.1), 20 (HTTP/2), 30 (HTTP/3)
- `cookie`: c (has cookies), n (no cookies)
- `referer`: r (has referer), n (no referer)
- `headers`: 2-digit count of headers (00-99)
- `lang`: 4-char language code (e.g., "enus", "engb", "0000" if missing)

**JA4H_b:** First 12 characters of SHA256(sorted header name:value pairs)

**JA4H_c:** First 12 characters of SHA256(sorted cookie names)

**JA4H_d:** First 12 characters of SHA256(sorted cookie name=value pairs)

### Implementation Details

```go
// internal/fingerprint/ja4h.go
func JA4H(req *http.Request) string {
    a := JA4H_a(req)  // Human-readable component
    b := JA4H_b(req)  // Header hash
    c := JA4H_c(req)  // Cookie names hash
    d := JA4H_d(req)  // Cookie values hash
    return fmt.Sprintf("%s_%s_%s_%s", a, b, c, d)
}
```

Key implementation notes:
- Uses `HeaderOrder` from our existing collector to preserve original header order
- Excludes pseudo-headers (`:method`, `:path`, etc.) from hash computation
- Handles missing `Accept-Language` as "0000" (strong bot indicator)
- Cookie hashes return "000000000000" when no cookies present

### Signal Extraction

From JA4H_a component, we extract classification signals:

| Signal | Description | Classification Impact |
|--------|-------------|----------------------|
| `ja4h_missing_language` | Language code is "0000" | +1 bot (bots often omit Accept-Language) |
| `ja4h_low_header_count` | Header count < 5 | +1 bot (minimal request) |
| `ja4h_high_header_count` | Header count >= 10 | +1 browser (rich headers) |
| `ja4h_has_cookies` | Cookie flag is 'c' | +0 (neutral, tracked for analysis) |
| `ja4h_has_referer` | Referer flag is 'r' | +1 browser (navigation context) |
| `ja4h_consistent_signal` | JA4H signals match HTTP signals | +1 browser / +2 bot if inconsistent |
| `ja4h_zeroed_cookie_hashes` | JA4H parts C and D are 000000000000 (no cookies) | +1 bot when browser UA and no Cookie header; see [Appendix I](#appendix-i-impersonate-and-header-order-detection) |

### Consistency Checking

JA4H provides redundant signals that should match our existing HTTP signal extraction:

```go
func checkJA4HConsistency(ja4hHasCookies, httpHasCookies bool,
                          ja4hHasReferer, httpHasReferer bool,
                          ja4hIsHTTP2, httpIsHTTP2 bool) bool {
    return ja4hHasCookies == httpHasCookies &&
           ja4hHasReferer == httpHasReferer &&
           ja4hIsHTTP2 == httpIsHTTP2
}
```

**Inconsistency indicates evasion attempts** — a client manipulating headers to appear more legitimate while actual request characteristics don't match.

### Example Fingerprints

**curl (minimal HTTP client):**
```
ge11nn020000_a00508f53a24_000000000000_000000000000
```
Breakdown:
- `ge` = GET method
- `11` = HTTP/1.1
- `n` = no cookies
- `n` = no referer
- `02` = 2 headers (Host, User-Agent)
- `0000` = no Accept-Language

**Chrome browser:**
```
ge20nr14enus_7cf2b917f4b0_a1b2c3d4e5f6_f6e5d4c3b2a1
```
Breakdown:
- `ge` = GET method
- `20` = HTTP/2
- `n` = no cookies (first visit)
- `r` = has referer (navigation)
- `14` = 14 headers
- `enus` = Accept-Language: en-US

**Python requests:**
```
ge11nn040000_b3c4d5e6f7a8_000000000000_000000000000
```
- 4 headers, no language — typical of HTTP libraries. When JA4H has zeroed C/D and the request has browser UA but no cookies, we add +3 bot (`ja4h-no-cookies`); see [Appendix I](#appendix-i-impersonate-and-header-order-detection).

### Classifier Integration

The classifier now uses JA4H signals in determining browser/bot reasons:

```go
// Browser indicators
if s.JA4HConsistentSignal && s.JA4HHighHeaderCount {
    reasons = append(reasons, "ja4h-browser-profile")
}

// Bot indicators  
if s.JA4HMissingLanguage {
    reasons = append(reasons, "ja4h-no-language")
}
if s.JA4HLowHeaderCount {
    reasons = append(reasons, "ja4h-minimal-headers")
}
if !s.JA4HConsistentSignal {
    reasons = append(reasons, "ja4h-inconsistent")
}
```

### Testing

Unit tests cover:
- JA4H computation for various HTTP methods
- Header hash stability
- Cookie handling (single, multiple, none)
- Language code extraction (en-US, en-GB, missing)
- Edge cases (empty requests, HTTP/2 pseudo-headers)

```bash
# Run JA4H-specific tests
task test -- -run TestJA4H

# All tests including JA4H
task test
```

### Future Work

1. **JA4H database**: Build corpus of known JA4H fingerprints for common clients
2. **JA4H_b clustering**: Group clients by header patterns regardless of values
3. **Cross-correlation**: Compare JA4+JA4H for comprehensive client profiling
4. **Temporal analysis**: Track JA4H changes across requests for session analysis

---

## Appendix E: Performance Benchmarks

*Added: 2026-02-13 (v0.4.0)*

### Unit Test Timing (httptest, no network I/O)

Classification logic timing measured via `go test` with 100-500 iterations per scenario:

| Scenario | Avg Latency | Theoretical RPS | Theoretical RPM |
|----------|-------------|-----------------|-----------------|
| empty request | 5.5 µs | ~182,000 | ~10.9M |
| curl | 5.3 µs | ~189,000 | ~11.3M |
| python-requests | 4.2 µs | ~238,000 | ~14.3M |
| browser (minimal) | 8.4 µs | ~119,000 | ~7.1M |
| browser (full headers) | 14.8 µs | ~67,500 | ~4.0M |
| GPTBot | 6.5 µs | ~154,000 | ~9.2M |
| **OVERALL (3000 reqs)** | **7.4 µs** | **~135,000** | **~8.1M** |

These are theoretical maximums for classification logic only, without network overhead.

### Real HTTP Benchmark (localhost, HTTPS with TLS fingerprinting)

Benchmark using `task bench:tls` against localhost with full TLS handshake and JA3/JA4/JA4H computation:

| Concurrency | RPS | RPM | Avg Latency | Max Latency | Errors |
|-------------|-----|-----|-------------|-------------|--------|
| 10 | 9,600 | 576K | 1.0 ms | 30 ms | 0 |
| 50 | 14,500 | **870K** | 3.4 ms | 53 ms | 0 |

**Peak throughput: ~870K RPM** at 50 concurrent connections with HTTPS/TLS (zero errors).

### What's Included in Benchmark

The benchmark measures full request processing:
- TCP connection establishment
- TLS handshake (with ClientHello capture)
- JA3/JA4 hash computation
- HTTP request parsing
- JA4H fingerprint computation
- Signal extraction and scoring
- JSON response serialization
- File logging (JSONL)

### Bottlenecks

At very high concurrency, errors may appear due to:
- OS-level connection limits
- TLS handshake overhead
- File I/O for logging

Optimal throughput with zero errors: **~870K RPM at c=50**.

### Running Benchmarks

```bash
# Start server
task run:tls

# Default benchmark (10s, 10 concurrent)
task bench:tls

# Higher load
task bench:tls DURATION=30s CONCURRENCY=50

# HTTP mode (no TLS overhead)
task bench URL=http://localhost:8080/ DURATION=10s CONCURRENCY=50
```

### Interpretation

- **Classification is not a bottleneck**: ~7µs per request in pure logic
- **TLS dominates latency**: ~1ms avg with TLS vs ~7µs without
- **Target met**: p99 latency well under 5ms target
- **Scalable**: Can handle ~870K RPM on single node (localhost)

---

## Appendix F: Nginx TLS Termination and Proxy Header Reuse

*Added: 2026-02-16 (v0.5.0)*

### Overview

When TLS is terminated at a reverse proxy (e.g. nginx with SSL and optional fingerprint modules), the Go backend receives plain HTTP from the proxy and has no direct access to the client TLS handshake or HTTP/2 frames. To preserve fingerprint data for classification, the proxy forwards it via trusted HTTP headers; the collector reuses these headers when a trusted-proxy marker is present.

This approach is consistent with industry practice: CDNs and anti-bot services capture TLS and HTTP/2 fingerprints at the edge and pass them to backends for policy enforcement (see References below). Doing the same with nginx allows reusing mature fingerprint modules (JA3, HTTP/2) without reimplementing protocol parsing in Go.

### Trusted proxy detection

The backend treats a request as coming from a trusted TLS-terminating proxy only when:

- The `X-Internal-Proxy` header is exactly `"1"`.
- The proxy is the only component that can set this header (e.g. internal network, or external headers stripped before reaching the app).

**Security**: Fingerprint headers must never be trusted from untrusted clients. RFC 9440 and gateway best practices (e.g. [2]) state that backends should only accept client identity/fingerprint data from configured trusted proxies and should strip or ignore such headers when they originate from the public internet. See [docs/nginx.md](nginx.md) for deployment notes.

### Headers consumed (when trusted proxy)

| Header | Source (nginx) | Used as |
|--------|----------------|--------|
| `X-Internal-Proxy` | Set by proxy to `1` | Trusted-proxy marker |
| `X-FP-TLS-Version` | `$ssl_protocol` | TLS version (e.g. TLSv1.3) |
| `X-FP-TLS-Cipher` | `$ssl_cipher` | Cipher suite name |
| `X-FP-TLS-ALPN` | `$ssl_alpn_protocol` | Negotiated protocol (h2, http/1.1) |
| `X-FP-TLS-SNI` | `$ssl_server_name` | SNI |
| `X-FP-JA3` | phuslu `$http_ssl_ja3` | Raw JA3 string; if not 32-char MD5, backend hashes it |
| `X-FP-JA3-HASH` | phuslu `$http_ssl_ja3_hash` | JA3 MD5 (32 hex) — **preferred** for classification |
| `X-FP-SSL-GREASED` | Module (e.g. phuslu) | GREASE values; non-empty → soft browser signal |
| `X-FP-JA4` | JA4-capable module (e.g. foxio-llc/ja4-nginx) | JA4 fingerprint when available |
| `X-FP-H2` | HTTP/2 fingerprint module (e.g. nginx-http2-fingerprint) | HTTP/2 fingerprint string |

When `X-Internal-Proxy` is not `"1"`, all `X-FP-*` headers are ignored for fingerprint construction; TLS data is taken only from `r.TLS` and ConnContext (direct TLS to Go).

### New fingerprint and signal fields (v0.5.0)

- **TLS**: `FromProxy` — set when TLS was built from proxy headers (no ClientHello in Go). When from proxy: JA3 hash is resolved from **X-FP-JA3-HASH** (preferred) or **X-FP-JA3** (raw string is MD5-hashed if not 32-hex). **X-FP-JA4** is read when set (e.g. from a JA4-capable module); cipher/extension counts remain unavailable from phuslu. **SSLGreased** stores X-FP-SSL-GREASED for optional scoring.
- **HTTP**: `H2Fingerprint` — HTTP/2 fingerprint value when provided by proxy (`X-FP-H2`). **`H2Parsed`** — when present, the backend parses the Akamai/nginx-http2-fingerprint format (`SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-header order`) into structured fields: SETTINGS map (RFC 7540 ids), INITIAL_WINDOW_SIZE (id 4), MAX_FRAME_SIZE (id 5), WINDOW_UPDATE, PRIORITY, PseudoHeaderOrder (fourth segment); see `internal/fingerprint/h2fingerprint.go`.
- **Signals**: `tls_from_proxy`, `has_http2_fingerprint`, `has_http2_fingerprint_from_proxy`, `h2_settings_parsed`, `h2_initial_window_size`, `h2_priority_present`, `h2_window_update_present`, `h2_max_frame_size_browser_like`, `h2_pseudo_header_order_present` — used in scoring, logging, and research.

### Scoring impact

- **HTTP/2 fingerprint**: If `has_http2_fingerprint` is true, the browser score is increased by **+1** (`h2-fp`). HTTP/2 SETTINGS/frame-level fingerprints correlate with real browser and client implementations and are hard to spoof from script (no JS API for raw H2 frames); see Akamai [4], NST Browser [6], and recent anti-bot literature.
- **Parsed H2 + browser-like INITIAL_WINDOW_SIZE**: When the H2 fingerprint string is successfully parsed (`h2_settings_parsed`) and SETTINGS INITIAL_WINDOW_SIZE (id 4) is one of the values commonly seen in real browsers (65535, 65536, 131072, 1048576, 2097152, **6291456** per RFC 7540 and Akamai fingerprinting; Chrome uses 6291456 = 6 MiB), the browser score is increased by **+1** (`h2-init-window`). Unusual or library-typical window sizes do not receive this bonus; **10485760** (10 MiB) is typical for curl and HTTP/2 libraries and is *not* treated as browser-like. See `internal/fingerprint/h2fingerprint.go` (`IsBrowserLikeH2InitialWindow`). curl and many HTTP/2 libraries use different window sizes than browsers (Scrapfly [32], lwt hiker [33]).
- **Parsed H2 + PRIORITY present**: When the fingerprint is parsed and the PRIORITY segment is non-empty (`h2_priority_present`), the browser score is increased by **+1** (`h2-priority`). Browsers typically send PRIORITY frames; many HTTP/2 client libraries omit or handle them differently (lwt hiker [33], Scrapfly format [32]).
- **Parsed H2 + WINDOW_UPDATE present**: When the connection-level WINDOW_UPDATE segment (second segment) is non-zero (`h2_window_update_present`), **+1** (`h2-window-update`). Real clients use flow control; this correlates with browser behavior (Akamai [4], Scrapfly [32]).
- **Parsed H2 + browser-like MAX_FRAME_SIZE**: When SETTINGS id 5 (MAX_FRAME_SIZE) is 16384 (RFC default) or 16777215 (max), **+1** (`h2-max-frame`). Browsers typically use these values (RFC 7540/9113).
- **Parsed H2 + pseudo-header order present**: When the fourth segment (pseudo-header order or flags, e.g. `m,p,a,s` in nginx module) is non-empty (`h2_pseudo_header_order_present`), **+1** (`h2-pseudo-headers`). Full fingerprint format typical of browsers (Scrapfly format [32]).
- **TLS from proxy**: Existing TLS-based signals apply. JA3 hash is taken from X-FP-JA3-HASH (preferred) or derived from X-FP-JA3; JA4 is used when X-FP-JA4 is set (e.g. foxio-llc/ja4-nginx). Cipher/extension counts are not forwarded by phuslu. **Obsolete TLS** (1.0/1.1 from X-FP-TLS-Version) adds +1 bot; **GREASE** (X-FP-SSL-GREASED non-empty) with modern TLS adds +1 browser when UA is not bot.

### HTTP/2 scoring rules and best practices (publications)

Rules above are aligned with the following sources:

| Rule | Source | Note |
|------|--------|------|
| H2 fingerprint presence | Akamai [4], NST Browser [6] | SETTINGS/WINDOW_UPDATE/PRIORITY identify client; no JS API to spoof. |
| Browser-like INITIAL_WINDOW_SIZE | Akamai [4], RFC 7540, Scrapfly [32] | Browsers use characteristic values; curl/libs differ. |
| PRIORITY segment present | lwt hiker [33], Scrapfly [32] | Browsers send PRIORITY; libraries often omit. |
| WINDOW_UPDATE segment non-zero | Akamai [4], Scrapfly [32] | Flow control; real clients send connection-level WINDOW_UPDATE. |
| Browser-like MAX_FRAME_SIZE (id 5) | RFC 7540/9113 | Default 16384, max 16777215; browsers use these. |
| Fourth segment (pseudo-header order) | Scrapfly [32], nginx module | Full fingerprint; browsers send characteristic order. |
| Consistency (spatial/temporal) | FP-Inconsistent [7] | Inconsistent attributes indicate evasion; we use JA4H consistency, H2 fits same idea. |

### Rationale (why proxy headers instead of Go-only)

1. **No mature H2 fingerprinting in Go**: Production-ready libraries for passive HTTP/2 frame fingerprinting (SETTINGS, PRIORITY, etc.) are not available in the Go ecosystem; nginx modules (e.g. [29]) already implement this at the edge.
2. **Reuse of nginx SSL/H2 stack**: nginx already parses TLS and HTTP/2; adding fingerprint modules avoids duplicating protocol logic and keeps a single place for certificate and ALPN handling.
3. **Alignment with CDN/research practice**: Passive HTTP/2 fingerprinting at the proxy is described in Akamai’s work [4]; TLS and HTTP/2 fingerprint forwarding to backends is used by Fingerproxy [30], Finch [31], and similar tools (2024–2025).
4. **Trusted-header pattern**: Forwarding identity/fingerprint from a trusted proxy via headers is a standard pattern (e.g. RFC 9440 Client-Cert, gateway mTLS/header docs [2]).

### References (2024–2026 and foundational)

- **[4] Passive Fingerprinting of HTTP/2 Clients** (Akamai, Black Hat EU 2017) — HTTP/2 SETTINGS/frame fingerprinting at the proxy; basis for nginx-http2-fingerprint and similar modules.  
  https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf

- **[2] Trusted headers for TLS-terminating reverse proxies** (PingIdentity, 2025) — Backends should only trust client identity/certificate headers from configured trusted proxies; strip or ignore from untrusted sources.  
  https://backstage.pingidentity.com/docs/ig/2025.3/gateway-guide/oauth2-rs-introspect-mtls-header.html

- **[29] nginx-http2-fingerprint** — Passive HTTP/2 fingerprinting (SETTINGS/priority) as nginx module; supplies values for variables/headers (e.g. `X-FP-H2`).  
  https://github.com/Xetera/nginx-http2-fingerprint

- **[30] Fingerproxy** — HTTPS reverse proxy that captures JA3, JA4, and HTTP/2 fingerprints and forwards them to backends via headers (X-JA3-Fingerprint, X-JA4-Fingerprint, X-HTTP2-Fingerprint). Production use (e.g. Subscan.io).  
  https://github.com/wi1dcard/fingerproxy

- **[31] Finch** — Real-time fingerprint-based actions (JA3, JA4, QUIC, JA4H, HTTP/2); supports block, reroute, tarpit.  
  https://github.com/0x4D31/finch

- **RFC 9440** — Client-Cert and Client-Cert-Chain HTTP header fields for TLS-terminating reverse proxies (TTRPs); standardizes secure forwarding of client certificate information.  
  https://httpwg.org/specs/rfc9440.html

- **[6] HTTP/2 fingerprinting and bypass** (NST Browser, 2025) — SETTINGS frame and transport-layer fingerprinting; cannot be spoofed via browser APIs; used in anti-bot/scraping.  
  https://www.nstbrowser.io/blog/http-2-bypass

- **TLS fingerprinting in 2026** (proxies.sx, 2026) — JA4+ adoption; inter-request and ML-based detection; fingerprinting at edge/proxy.  
  https://www.proxies.sx/use-cases/privacy/tls-fingerprint

- **[32] Scrapfly HTTP/2 Fingerprint** — Format and components: SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header order; used to detect scrapers/bots; browser vs library differences.  
  https://scrapfly.io/web-scraping-tools/http2-fingerprint

- **[33] HTTP/2 fingerprinting** (lwt hiker) — Browsers send PRIORITY; libraries often omit; SETTINGS/window differ (e.g. curl); impersonation requires matching frame behaviour.  
  https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html

### JA3 behind proxy and JA4 options

Behind a TLS-terminating proxy (e.g. nginx with phuslu), the backend has no access to ClientHello; only headers are available. **phuslu/nginx-ssl-fingerprint** provides JA3 (raw and hash), not JA4. JA3 is weakened by Chrome’s extension-order randomization (2022+), so the same browser can yield many JA3 hashes; this can produce “unknown” fingerprints for real browsers. For more stable detection, JA4 is preferred (industry adoption: Cloudflare, Fastly, 2025–2026). **Options for JA4 when using nginx:** (a) Use a nginx module that computes JA4 (e.g. [foxio-llc/ja4-nginx](https://github.com/foxio-llc/ja4-nginx)) and pass it as **X-FP-JA4**; the Go backend already reads X-FP-JA4 and uses it in known-library/browser checks and ALPN consistency. (b) Put a JA4-capable reverse proxy (e.g. [Fingerproxy](https://github.com/wi1dcard/fingerproxy)) in front of nginx and have it inject JA4 (and optionally JA3/H2) into headers that nginx forwards to Go.

### Configuration and deployment

See [docs/nginx.md](nginx.md) for nginx build, module list, and example `proxy_set_header` configuration. The Go server uses the same header names (`X-FP-*`, `X-Internal-Proxy`) so that a single nginx config can drive both logging and classification.

---

## Appendix G: Cross-validation of transport vs application fingerprints

Methodologies for checking consistency between "complex" fingerprints (TLS JA3/JA4, HTTP/2, JA4H) and ordinary HTTP headers are widely used in anti-bot systems; mismatches indicate spoofing or evasive bots.

### Spatial vs temporal inconsistency

- **Spatial**: Two attributes in the *same* request contradict each other (e.g. User-Agent says Chrome, TLS fingerprint says curl; or JA4H says HTTP/1.1, ALPN says h2).  
- **Temporal**: The *same* attribute changes across requests from the same client (e.g. JA3 differs between requests that should be the same browser).  

FP-Inconsistent [7] uses both: data-driven rules on attribute pairs (spatial) and same-attribute-over-time (temporal). Evasive bots that alter fingerprints often produce invalid combinations; detection targets those combinations. Our project implements **spatial** consistency (JA4H vs HTTP; H2 vs ALPN/version is implicit).

### TLS (JA3/JA4) vs HTTP / User-Agent

| Check | Description | Source |
|-------|-------------|--------|
| TLS fingerprint vs User-Agent | Declared browser (UA) should match TLS ClientHello profile (JA3/JA4). Chrome UA with curl-like JA4 → bot. | DataDome, Cloudflare, mitmproxy [4], proxies.sx [34], JA4 in Action |
| TLS vs HTTP version | ALPN (h2 / http/1.1) should match request protocol; TLS JA4 includes ALPN. Mismatch → impersonation. | FoxIO JA4+, TrueGuard JA4/JA4T |
| JA4T vs claimed OS | TCP fingerprint (JA4T) should match User-Agent OS (e.g. "Windows" vs Linux TCP options). | TrueGuard [34], gen0sec JA4+ |

Cloudflare and others compare TLS fingerprint to the declared User-Agent; mismatches trigger challenges or 403. Multi-layer correlation (TLS + headers + behavior) makes single-signal spoofing insufficient.

### JA4H vs HTTP headers

| Check | Description | Source |
|-------|-------------|--------|
| JA4H vs HTTP cookies/referer/version | JA4H encodes method, version, cookie, referer, header count, language. These must match actual request headers. | FoxIO JA4H [2], ThreatRelay, gen0sec |
| JA4H language vs Accept-Language | JA4H "0000" vs present Accept-Language (or vice versa) → inconsistency. | Our implementation (v0.4.0) |

JA4H is an HTTP *structural* fingerprint (order, presence, counts). Cross-validating JA4H-derived flags with the same facts from raw headers catches header manipulation. We do this in Phase 3 (JA4H consistent signal; inconsistency → +2 bot).

### HTTP/2 fingerprint vs HTTP headers / TLS

| Check | Description | Source |
|-------|-------------|--------|
| H2 fingerprint vs protocol | If request is HTTP/2 (ALPN h2 or H2 fingerprint present), other signals (e.g. JA4H version "20") should agree. | Akamai [4], Scrapfly [32] |
| H2 vs User-Agent | Real browsers send characteristic H2 SETTINGS/PRIORITY; spoofed UA with library-like H2 → mismatch. | lwt hiker [33], curl_cffi impersonation FAQ |
| H2 + TLS + headers | Full signature must be coherent (e.g. Chrome UA + Chrome-like JA4 + Chrome-like H2). | Browserless, curl_cffi |

HTTP/2 fingerprint reflects the real client stack; it cannot be set via JavaScript. We implement H2 vs UA (browser UA + library-like H2 → +2 bot) and H2 vs JA4 (JA4 ALPN vs actual protocol); see Our current implementation below.

### References for this section

- **[7] FP-Inconsistent** (arXiv:2406.07647) — Spatial (pair of attributes in one request) and temporal (same attribute over time) inconsistency; data-driven rules; 44–48% evasion reduction, 96.84% TNR.  
  https://arxiv.org/abs/2406.07647  
- **DataDome** — TLS fingerprinting reinforces protection; TLS vs declared User-Agent.  
  https://datadome.co/engineering/how-tls-fingerprinting-reinforces-datadomes-protection/  
- **JA4 in Action** (Medium) — Detecting bots/fake browsers via JA4; TLS vs UA consistency.  
  https://medium.com/@belghitishakantar/ja4-in-action-detecting-bots-malware-and-fake-browsers-at-the-tls-level-3ccd890fbce9  
- **[34] When Handshakes Tell the Truth** (arXiv:2602.09606) — Bot detection via TLS (JA4) fingerprints; 98.63% accuracy, AUC 0.998; features ja4_b, cipher_count, ext_count.  
  https://arxiv.org/abs/2602.09606  
- **Browser Polygraph** (Kalantari et al., 2024) — Predict whether fingerprint attributes are consistent with *reported User-Agent*; ML-based.  
- **curl_cffi / lwt hiker** — Impersonation requires matching TLS *and* HTTP/2 (and often pseudo-header order); mismatches reveal automation.  
  https://curl-cffi.readthedocs.io/en/latest/impersonate/faq.html  

### Our current implementation

- **Done**: JA4H vs HTTP (cookies, referer, version, language) — spatial consistency; inconsistency → +2 bot.  
- **Done**: H2 vs User-Agent — when UA looks like a browser but the HTTP/2 fingerprint is library-like (e.g. no PRIORITY, non-browser INITIAL_WINDOW_SIZE or WINDOW_UPDATE), we add +2 bot (`h2-ua-inconsistent`). Uses existing H2 parsed signals; no new data collection.  
- **Done**: TLS vs User-Agent — (1) When UA looks like a browser but JA3/JA4 is in a known-library set (curl, Python requests, Go, Node.js), we add +3 bot (`tls-ua-inconsistent`). (2) When UA looks like a browser and JA3/JA4 is in a known-browser set (Chrome, etc.), we add +1 browser (`tls-ua-consistent`). (3) When UA claims bot/library but JA3/JA4 is in the known-browser set, we add +3 bot (`tls-ua-inconsistent`). (4) We only apply (1) when the fingerprint is in the library set and *not* in the browser set—the same JA4 can appear in both ja4db categories (e.g. real Chrome), in which case we do not penalize. JA3 maps are static in `internal/fingerprint/tls_client_map.go`; JA4 set is loaded from file (default `internal/fingerprint/data/ja4db.json`, download from ja4db.com on first start if missing). Env: `JA4DB_PATH`, `JA4DB_SKIP_DOWNLOAD` (tests). Extend from ja3.me, JA3.ZONE, ja4db.com.
- **Done**: HTTP/1.1 without H2 — we add +1 bot only when TLS was available (the client could have negotiated H2). For raw HTTP pipelines (no TLS, e.g. direct to app without nginx), we do not penalize HTTP/1.1.
- **Done**: Bot User-Agent and TLS/JA4H browser points — when the User-Agent is already classified as bot (e.g. curl, Python), we do not award browser points for TLS (modern-tls, high-ciphers, session-ticket, multi-groups, tls-ext≥10) or for ja4h-consistent. Primitive CLI clients have modern TLS stacks too; without this, curl would receive 6–7 browser points and the net score would be only slightly negative.  
- **Done**: H2 vs JA4 — when JA4 is present, we parse ALPN from Part A (h2/h1/h3). If JA4 says h2 but the request is not HTTP/2 (or says h1 but it is HTTP/2), we add +2 bot (`h2-ja4-inconsistent`). See `JA4ALPN()` in `tls_client_map.go`.
- **Done**: TLS/HTTP version mismatch — with direct TLS (not from proxy), we require ALPN to match the observed HTTP version: ALPN `h2` ↔ `HTTP/2.0`, ALPN `http/1.1` ↔ non‑HTTP/2. Mismatch → +2 bot (`tls-alpn-http-inconsistent`). When TLS is from proxy, ALPN reflects client↔proxy; the request to the backend may be HTTP/1.1, so we do not apply this check.
- **Done**: Obsolete TLS (X-FP-TLS-Version) — when version is TLS 1.0 or TLS 1.1 we add +3 bot (`obsolete-tls(+3)`). Source: proxy header `X-FP-TLS-Version` or direct TLS; signal `TLSObsolete`. Smoking gun; outdated clients are often automation or legacy stacks.
- **Done**: Exotic ALPN — when negotiated ALPN is http/0.9, http/1.0, spdy/1, spdy/2, spdy/3, h2c, or hq we add +3 bot (`exotic-alpn(+3)`). Signal `TLSExoticALPN`. Smoking gun; scanners and bots often send these; real browsers use h2 or http/1.1. Server accepts these in ALPN so the connection is established and then scored.
- **Done**: Blind probe — when request path is not in the allowed list (`/`, `/debug`) or method is not GET we add +3 bot (`blind-probe(+3)`). Signal `RequestIsProbe`. Smoking gun; bots often probe blindly (e.g. GET /actuator/gateway/routes, POST /cgi-bin/...). Allowed paths match server mux (`/` → HandleClassify, `/debug` → HandleDebug); `/health` is not scored (HandleHealth does not call classifier).
- **Done**: GREASE (X-FP-SSL-GREASED) — when the header is non-empty, TLS is modern (1.2/1.3), and UA is not bot we add +1 browser (`ssl-greased(+1)`). Real browsers send GREASE; many libraries omit or use it inconsistently (Akamai, Cloudflare). Signal `HasSSLGreased`; format of value is module-dependent (e.g. phuslu).
- **Done**: Browser UA + no GREASE when TLS from proxy — when TLS is from proxy, **proxy forwarded client TLS** (ALPN or JA3 or cipher non-empty), UA looks like a browser, and X-FP-SSL-GREASED is empty we add +3 bot (`ua-browser-no-grease(+3)`). Strong (smoking-gun) signal; typical of curl or HTTP libraries spoofing browser headers; real browsers send GREASE. For **HTTP→HTTP proxy** (client did no TLS to us; ALPN/JA3/cipher all empty) we do *not* apply this penalty, since no GREASE is expected.
- **Done**: From-proxy scoring adjustments — (1) **no-session**: we do *not* add +1 bot for missing session ticket when TLS is from proxy, because X-FP-* does not convey session ticket presence. (2) **JA4H consistency**: when TLS is from proxy, we do *not* compare JA4H version (11/10) with `is_http2` in the consistency check; the backend always sees HTTP/1.x from the proxy, so JA4H version reflects that, while `is_http2` comes from ALPN and is correct for the client.
- **Done**: INITIAL_WINDOW_SIZE 6291456 — Chrome uses 6 MiB; we treat it as browser-like (`h2-init-window`). 10485760 (10 MiB) remains library-typical and is not in the browser-like set.
- **Done**: knownLibraryJA3 — extended with additional curl/OpenSSL JA3 hashes (e.g. `0149f47eabf9a20d0893e2a44e5a6323` from curl with HTTP/2 on Linux) so that browser UA + library TLS is reliably detected as `tls-ua-inconsistent`.
- **Done**: JA3 hash from proxy — we prefer **X-FP-JA3-HASH** (32-char MD5) for classification; if absent we use X-FP-JA3 as hash when it looks like MD5, else we compute MD5 of the raw JA3 string in Go. Ensures TLS vs UA checks work regardless of whether nginx sends raw or hash. See [Appendix H](#appendix-h-ja3-ja4-and-x-fp-for-bot-detection).
- **Planned**: Temporal inconsistency (same attribute changes across requests from same client).

---

<a id="appendix-h-ja3-ja4-and-x-fp-for-bot-detection"></a>

## Appendix H: JA3, JA4 and X-FP-* for bot detection

This appendix summarizes industry practices and our implementation choices for using proxy-forwarded fingerprint headers (X-FP-*) in bot detection when TLS is terminated at nginx (or similar) and the Go backend receives plain HTTP with headers.

### Scope of headers

| Header | Typical source (nginx) | Purpose in classification |
|--------|------------------------|---------------------------|
| `X-FP-TLS-Version` | `$ssl_protocol` | TLS version; obsolete (1.0/1.1) → +3 bot. |
| `X-FP-TLS-Cipher` | `$ssl_cipher` | Negotiated cipher; logged, not currently scored separately. |
| `X-FP-TLS-ALPN` | `$ssl_alpn_protocol` | h2 vs http/1.1; used for H2 vs JA4 consistency and IsHTTP2. Exotic (http/0.9, spdy, h2c, hq) → +3 bot. |
| `X-FP-TLS-SNI` | `$ssl_server_name` | SNI; logged. |
| `X-FP-JA3` | `$http_ssl_ja3` (phuslu) | Raw JA3 string; used when X-FP-JA3-HASH absent (hashed in Go if not 32-hex). |
| `X-FP-JA3-HASH` | `$http_ssl_ja3_hash` | **Preferred** 32-char MD5 for known-library/browser lookups and TLS vs UA. |
| `X-FP-SSL-GREASED` | `$http_ssl_greased` | GREASE presence; non-empty + modern TLS + non-bot UA → +1 browser. |
| `X-FP-JA4` | JA4-capable module | JA4 fingerprint when available; used like direct-TLS JA4 (consistency, known sets). |
| `X-FP-H2` | `$http2_fingerprint` | HTTP/2 fingerprint; parsed and scored (SETTINGS, PRIORITY, WINDOW_UPDATE, etc.). |

### Best practices (2025–2026)

1. **Prefer X-FP-JA3-HASH for classification**  
   The classifier expects a 32-character MD5 for JA3 lookups (`knownLibraryJA3`, `knownBrowserJA3`). If the proxy sends only the raw JA3 string in X-FP-JA3, the backend hashes it; sending X-FP-JA3-HASH avoids ambiguity and matches phuslu’s native output. Configure nginx to set both when possible; the backend uses X-FP-JA3-HASH when present.

2. **JA3 limitation behind proxy**  
   Behind a TLS-terminating proxy only JA3 (not JA4) is available from phuslu. Chrome’s extension-order randomization (2022+) makes JA3 unstable for the same browser (many hashes). Prefer JA4 when feasible (e.g. foxio-llc/ja4-nginx or Fingerproxy) and pass it as X-FP-JA4; the backend already consumes it for consistency and known-client checks.

3. **Multi-layer detection**  
   Combine TLS (JA3/JA4), HTTP/2 fingerprint, and JA4H with consistency checks (TLS vs User-Agent, H2 vs UA, H2 vs JA4 ALPN). Single-signal spoofing is insufficient; spatial consistency is implemented (Appendix G). Temporal inconsistency (same client, changing fingerprints) is planned.

4. **GREASE as a soft signal**  
   Real browsers typically send GREASE; many automation stacks do not or do so inconsistently. We use non-empty X-FP-SSL-GREASED with modern TLS as a +1 browser signal when the User-Agent is not already classified as bot. The exact format of the header value is module-dependent (e.g. phuslu).

5. **Obsolete TLS**  
   TLS 1.0 and 1.1 are deprecated and often associated with legacy or automated clients. We add +3 bot (smoking gun) when X-FP-TLS-Version indicates TLS 1.0 or 1.1.

6. **Exotic ALPN**  
   Negotiated ALPN values such as http/0.9, http/1.0, spdy/*, h2c, hq are typical of scanners or legacy stacks; real browsers use h2 or http/1.1. We add +3 bot (smoking gun) when ALPN is one of these. The server (direct TLS) accepts them in NextProtos so the handshake succeeds and we can score the request.

7. **Trust and stripping**  
   X-FP-* and X-Internal-Proxy must only be trusted when the request comes from a controlled proxy (e.g. internal network). Strip or ignore these headers from untrusted/external traffic to prevent spoofing.

8. **Blind probe (path/method)**  
   Requests to non-existent paths or with non-GET method (we return 404 for these) are treated as a smoking-gun bot signal (`blind-probe` +3). Allowed paths are `/` and `/debug` (match server mux); `/health` is not scored (no classifier). Bots often probe blindly (e.g. GET /actuator/gateway/routes, POST /cgi-bin/...).

### Scoring summary (proxy path)

Signals derived from the above headers and used in `calculateScores` (see [Appendix F](#appendix-f-nginx-tls-termination-and-proxy-header-reuse) and `internal/fingerprint/signals.go`):

| Signal | Condition | Score |
|--------|-----------|-------|
| `obsolete-tls` | X-FP-TLS-Version is TLS 1.0 or 1.1 | +3 bot (smoking gun) |
| `exotic-alpn` | Negotiated ALPN is http/0.9, http/1.0, spdy/*, h2c, hq | +3 bot (smoking gun) |
| `blind-probe` | Request path not in allowed list (`/`, `/debug`) or method ≠ GET | +3 bot (smoking gun) |
| `ssl-greased` | X-FP-SSL-GREASED non-empty, modern TLS, non-bot UA | +1 browser |
| `ua-browser-no-grease` | TLS from proxy **and** proxy forwarded client TLS (ALPN/JA3/cipher), browser UA, X-FP-SSL-GREASED empty | +3 bot; skipped for HTTP→HTTP (no client TLS) |
| `has_tls_fingerprint` | JA3 or JA4 present (JA3 from X-FP-JA3-HASH or X-FP-JA3) | Enables TLS-based scoring |
| `tls-ua-inconsistent` / `tls-ua-consistent` | JA3/JA4 vs User-Agent (known library/browser sets) | +3 bot / +1 browser |
| H2 fingerprint rules | X-FP-H2 parsed (SETTINGS, PRIORITY, etc.); INITIAL_WINDOW_SIZE 6291456 = browser-like | Multiple browser/bot points |
| `h2-ja4-inconsistent` | JA4 ALPN vs actual HTTP/2 when JA4 from X-FP-JA4 | +2 bot |

### References (publications and sources)

The practices in this appendix align with the following publications and documentation (numbering from the main [References](#references) section):

| Topic | Source | URL / note |
|-------|--------|------------|
| JA3 specification and MD5 hash | **[1] JA3 - SSL/TLS Client Fingerprinting** (Salesforce, 2017) | https://github.com/salesforce/ja3 |
| JA4+ and Chrome randomization; JA4 at edge | **[2] JA4+ Network Fingerprinting** (FoxIO, 2023-2024) | https://github.com/FoxIO-LLC/ja4 |
| JA3/JA4 in bot management | **[3] Cloudflare JA3/JA4 Documentation** | https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/ |
| HTTP/2 fingerprint at proxy; SETTINGS/PRIORITY | **[4] Passive Fingerprinting of HTTP/2 Clients** (Akamai, Black Hat EU 2017) | https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf |
| Spatial/temporal inconsistency; evasion detection | **[7] FP-Inconsistent** (2024, arXiv:2406.07647) | https://arxiv.org/abs/2406.07647 |
| TLS fingerprint vs User-Agent; JA4 bot detection | **[34] When Handshakes Tell the Truth** (arXiv:2602.09606) | https://arxiv.org/abs/2602.09606 |
| JA3/JA4/H2 via headers to backend | **[30] Fingerproxy** | https://github.com/wi1dcard/fingerproxy |
| Fingerprint-based actions (JA3, JA4, JA4H, H2) | **[31] Finch** | https://github.com/0x4D31/finch |
| TLS fingerprinting 2026; JA4+ adoption at proxy | **TLS fingerprinting in 2026** (proxies.sx) | https://www.proxies.sx/use-cases/privacy/tls-fingerprint |
| GREASE and TLS extensibility | **RFC 8701 (GREASE)** | https://datatracker.ietf.org/doc/html/rfc8701 |
| Bots tampering with TLS to avoid detection | **Akamai: Bots Tampering With TLS** | https://www.akamai.com/blog/security/bots-tampering-with-tls-to-avoid-detection |
| phuslu nginx JA3 + HTTP/2 fingerprint module | **phuslu/nginx-ssl-fingerprint** | https://github.com/phuslu/nginx-ssl-fingerprint |

### Future work (TODOs)

- **Temporal inconsistency**: Track the same client (e.g. by IP or session) across requests; flag when JA3/JA4 or H2 fingerprint changes in an implausible way (Phase 3 in roadmap). Redis metrics (Appendix L) can support session-keyed analysis when scoring from behavioral data is added.
- **JA4 at edge**: Evaluate production use of a JA4-capable nginx module or Fingerproxy and extend JA4-based rules when X-FP-JA4 is widely available.
- **GREASE format**: Document the exact format of X-FP-SSL-GREASED per nginx module (phuslu and others) for optional stricter parsing or anomaly detection (e.g. TLS 1.3 with empty GREASE as soft bot signal).
- **Validation dataset**: Collect labeled traffic (browser vs bot) with X-FP-* present and measure precision/recall for the above rules; compare with commercial solutions (e.g. FP-Inconsistent-style evaluation).

---

## Appendix I: Impersonate and header-order detection

*Added: 2026-02-18*

### Purpose

Clients that impersonate browsers (e.g. curl_cffi, curl-impersonate) can match TLS and HTTP/2 fingerprints and send Sec-Fetch-* and Sec-CH-UA headers, and previously scored only one point below a real browser (e.g. 21 vs 22) because they often send no cookies. To separate them from real browsers without raising the classification threshold, we added signals based on header order, JA4H cookie-hash segments, and Sec-CH-UA brand order.

### Signals

#### BrowserLikeHeaderOrder

**Definition**: Accept and Accept-Language appear in the first N positions of the request header order (as received by the backend). We use **N=12** so that real Chrome and similar browsers pass: observed Chrome order (e.g. [fingerprints.bablosoft.com](https://fingerprints.bablosoft.com/headersorder)) has host, connection, pragma, cache-control, sec-ch-ua*, user-agent, **accept-language (9)**, **accept (10)**, sec-fetch-*, accept-encoding. Firefox and Safari differ but typically send Accept/Accept-Language in the first dozen positions; libraries often put them much later.

**Computation**: From `fingerprint.http.header_order` (lowercase), we take the first index of `"accept"` and `"accept-language"`. If both are present and both indices are &lt; 12 (`browserLikeHeaderOrderMaxIdx`), the signal is true. When order is from proxy (X-Original-Header-Order) and not browser-like, we check if either index ≥ 12 (`headerOrderLateMinIdx`) for the late penalty.

**Scoring**: +1 browser (`header-order(+1)`) only when `header_order_from_proxy` is true. When User-Agent is browser-like but the order is not browser-like (either index ≥ 12), we add +2 bot (`header-order-late(+2)`) to separate impersonators (only when order from proxy).

**Dependency**: Meaningful header order is only available when the proxy passes it explicitly: nginx with Lua sets `X-Original-Header-Order`. When TLS is terminated by Go (stream → Go :8443), `net/http` parses the request and stores headers in a map, so order is **not** preserved; we only have order when it comes from that header.

**References**: JA4H uses header structure and order; ThreatRelay JA4H, WebDecoy headless detection; internal comparison of real browser vs curl_cffi payloads (see reference fixtures in `tests/testdata/reference_browser.json`, `reference_bot_curl_cffi.json`).

#### JA4HZeroedCookieHashes

**Definition**: JA4H parts C and D (cookie-name hash and cookie name=value hash per FoxIO spec) are both `000000000000`. Per [2] FoxIO JA4H, when no cookies are present, C and D are output as 12 zeros.

**Computation**: In `extractJA4HSignals`, after splitting JA4H by `_`, we set the signal when `len(parts) >= 4` and `parts[2] == "000000000000"` and `parts[3] == "000000000000"`.

**Scoring**: When User-Agent is browser-like, the request has no Cookie header, and this signal is true, we add a bot score (default **+2** in config: `ja4h-no-cookies`). Strong signal for automation that mimics browser but sends no cookies; default is lowered from smoking-gun (+3) to reduce false positives for incognito/first visit. **Skipped for HTTP→HTTP proxy** (TLS from proxy but no ALPN/JA3/cipher): no client TLS is visible and no cookies on first request or over HTTP is common, so we do not penalize.

**References**: [2] FoxIO JA4+ Network Fingerprinting, JA4H technical details (https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md).

#### SecChUAModernOrder

**Definition**: The first quoted brand in the Sec-CH-UA header is `Not:A-Brand` or `Not_A Brand` (Chrome 109+). Automation and older Chrome often send `Chromium` first.

**Computation**: We take the first token (up to the first comma), extract the quoted value, normalize spaces and case, and compare to `not:a-brand`, `not_abrand`, `not_a_brand`.

**Scoring**: +1 browser (`sec-ch-ua-modern(+1)`). We do not add a bot penalty when the first brand is Chromium, to avoid false positives on older browsers.

**References**: MDN Sec-CH-UA (https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA), Chrome User-Agent Client Hints; GREASE behaviour (Stack Overflow, Chrome 109).

#### HasCacheControl

**Observation**: Real Chrome often sends `Cache-Control: max-age=0` on document navigation (Fetch “no-cache” mode). curl_cffi requests in the reference payload do not send Cache-Control.

**Computation**: `fingerprint.http.headers["cache-control"]` non-empty (collector stores all headers; use lowercase key).

**Scoring**: +1 browser when present (`cache-control(+1)`). No bot penalty when missing (many valid requests omit it).

**References**: MDN Cache-Control; Fetch standard (max-age=0 for no-cache).

#### AcceptLangRich and accept-lang-simple

**Observation**: Real browsers often send multiple locales in Accept-Language with **varied** q-values (canonical example: `ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6` — 5 parts, four distinct explicit weights). Impersonators (curl_cffi, undici, playwright-stealth) typically send 1–2 languages and a single weight (e.g. `en-US,en;q=0.9`). This is one of the most stable transport-signals in 2025 practice.

**Computation**: **Rich** = (≥3 comma-separated parts or length &gt; 40) **and** at least 2 distinct explicit q-values (after `;q=`). If all explicit weights are the same (e.g. only 0.9), the profile is not rich. Thresholds from config (`accept_lang_min_locale_parts`, `accept_lang_min_length`). Reference browser payload uses the canonical header above; reference bot uses `en-US,en;q=0.9`.

**Scoring**: +1 browser when rich (`accept-lang-rich(+1)`). +1 bot when Accept-Language is present but not rich (`accept-lang-simple(+1)`). **Missing Accept-Language** → +1 bot (`no-accept-lang`) whenever the header is absent, including when Sec-Fetch-* is present (per Radware: browser-like requests should include accept-language; missing header = anomaly). Incognito or first visit with a simple profile receives the bot point by design to improve separation from impersonators.

**References (specs and docs)**: [MDN Accept-Language](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language) (q-values, Chrome/Safari add fallbacks e.g. `en-US,en;q=0.9,zh-CN;q=0.8`; Safari/Chrome incognito send one language). [HTTP Semantics (RFC 9110) field.accept-language](https://httpwg.org/specs/rfc9110.html#field.accept-language). [WICG Reduce Accept-Language fingerprinting](https://discourse.wicg.io/t/proposal-reduce-fingerprinting-in-the-accept-language-header/5835/).

**References (bot detection and fingerprinting)**:
- **Radware Bot Manager** — [HTTP Header Anomaly-based Bot Detection](https://www.radware.com/blog/application-protection/http-header-anomaly-based-advanced-behavioural-bot-detection/): lists **Accept-Language Spoofing** as a common bot technique (bots set the header to common values to blend in); detection correlates User-Agent with expected Accept headers (accept-language, accept-encoding, etc.); deviations are treated as anomalous.
- **FP-Inconsistent** (Venugopalan et al., IMC 2024) — [arXiv:2406.07647](https://arxiv.org/abs/2406.07647): evasive bots alter fingerprint attributes but struggle to maintain **consistency** across attributes; rules that detect spatial/temporal inconsistencies reduce evasion by ~44–48%. Our rich-vs-simple Accept-Language is a spatial consistency signal (browser UA vs. simplistic language profile).
- **JA4H (FoxIO)** — [JA4H technical details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md): HTTP client fingerprint includes **Accept-Language** (method, version, header order, cookie, referer, language). Used in bot/C2 detection and threat hunting.
- **curl_cffi / Playwright** — [Impersonation FAQ](https://curl-cffi.readthedocs.io/en/latest/impersonate/faq.html) (other fields detectable beyond TLS/HTTP2); [Playwright #23732](https://github.com/microsoft/playwright/issues/23732) (Firefox/WebKit ignore custom Accept-Language in automation; automation often sends wrong or simplistic values). Internal payload comparison: real Chrome vs curl_cffi reference.

### Scoring table

| Signal | Condition | Effect | Source |
|--------|-----------|--------|--------|
| `header-order` | Accept and Accept-Language in first 8 positions of HeaderOrder | +1 browser | JA4H header structure; WebDecoy/ThreatRelay; internal payload comparison |
| `header-order-late` | Browser UA but Accept or Accept-Language at index ≥ 12 | +2 bot | Same |
| `ja4h-no-cookies` | JA4H parts C and D are 000000000000, browser UA, no Cookie header | +2 bot (default; tunable); skipped for HTTP→HTTP proxy (no client TLS) | [2] FoxIO JA4H |
| `sec-ch-ua-modern` | First brand in Sec-CH-UA is Not:A-Brand or Not_A Brand | +1 browser | Chrome 109+ Client Hints; no bot penalty for Chromium-first |
| `no-accept-lang` | Accept-Language header missing | +1 bot | Radware: missing standard Accept header = anomaly; applies even when Sec-Fetch-* present |
| `accept-lang-rich` | Accept-Language has ≥3 parts or length &gt; 40 and ≥2 distinct explicit q-values | +1 browser | Canonical: ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6 |
| `accept-lang-simple` | Accept-Language present but not rich (1–2 parts or single q-value) | +1 bot | Impersonators often send en-US,en;q=0.9 |
| `sec-purpose` | Sec-Purpose header present and value is `prefetch` or `prefetch;prerender` | +2 browser | W3C nav-speculation; forbidden header (JS cannot set it) |
| `sec-purpose-invalid` | Sec-Purpose present but value not in allowed set | +1 bot | Spoofed or broken header |
| `sec-purpose-no-sec-fetch` | Sec-Purpose present but no Sec-Fetch-* headers | +2 bot | Prefetch in spec always sends fetch metadata |

#### Sec-Purpose (prefetch / prerender)

**Observation**: The `Sec-Purpose` request header is a fetch metadata header (W3C nav-speculation prefetch/prerender). It is a **forbidden** request header (`Sec-` prefix), so JavaScript cannot set it; only the browser engine sends it for prefetch/prerender requests. curl_cffi, undici, and Playwright do not send it by default. When present with a valid value and with Sec-Fetch-* headers, it is a strong browser signal; when present with an invalid value or without Sec-Fetch-*, it indicates spoofing or a broken client.

**Computation**: Read from request headers (e.g. `Headers["sec-purpose"]`). **HasSecPurpose**: header present and non-empty after trim. **SecPurposeValid**: normalized value (trim, lowercase, collapse space after `;`) is `prefetch` or `prefetch;prerender` (per spec, the token is `prefetch` with optional `prerender` parameter).

**Scoring**: +2 browser when `HasSecPurpose && SecPurposeValid` (`sec-purpose`). +1 bot when `HasSecPurpose && !SecPurposeValid` (`sec-purpose-invalid`). +2 bot when `HasSecPurpose && !HasSecFetchHeaders` (`sec-purpose-no-sec-fetch`); in the spec, prefetch requests always include fetch metadata (Sec-Fetch-*). No penalty when the header is absent (normal navigation does not send Sec-Purpose). No penalty for missing cookies when Sec-Purpose is present (cross-origin prefetch may legitimately have no cookies).

**References**: [W3C nav-speculation Prefetch](https://wicg.github.io/nav-speculation/prefetch.html#sec-purpose-header), [MDN Sec-Purpose](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Purpose).

### Risks and mitigations

- **Header order altered by proxy**: If a proxy or CDN reorders headers, a real browser may lose the browser-like order. We use a N=12 (see Appendix I) and do not rely on header order alone; we only add a bot point for “late” order when both Accept and Accept-Language are present and at least one is at index ≥ 12 (only when order from X-Original-Header-Order).
- **Real users without cookies**: Incognito or first visit can yield zeroed JA4H C/D and no Cookie header. We add the +3 bot penalty only when User-Agent is browser-like; a typical real browser with cookies and browser-like order still classifies as browser; first-visit/incognito may need other browser signals to outweigh the penalty.
- **Older browsers**: Browsers that do not send Not:A-Brand first simply do not get the sec-ch-ua-modern bonus; we do not penalize them.

### Additional signals (from updated payloads and curl_cffi best practices)

Comparison of full reference payloads (real Chrome vs curl_cffi) and curl_cffi/curl-impersonate docs shows further discriminators. Proposed (not yet implemented):

#### Known impersonator JA3 (optional, operational)

**Observation**: When TLS is from proxy, JA3 is available (e.g. X-FP-JA3-HASH). curl-impersonate uses a fixed JA3 per browser profile; the reference bot payload has a distinct JA3 (e.g. Chrome 142 profile) vs the real browser (Chrome 145). A list of JA3 hashes observed from curl-impersonate/curl_cffi builds can be maintained and checked when UA claims browser.

**Computation**: When `tls.from_proxy` and `tls.ja3_hash` is in a configured or hardcoded set of “known impersonator” JA3 hashes and User-Agent is browser-like → treat as impersonator hint.

**Scoring**: +1 bot when JA3 in list and browser UA (`ja3-known-impersonator(+1)`). List should be updated from operational data or curl-impersonate release notes; risk of false positives if a real browser build shares the same JA3.

**References**: curl_cffi impersonate FAQ (JA3 and HTTP/2 not comprehensive; other fields detectable); curl-impersonate Chrome profiles per version.

#### Collecting JA3 hashes (sources for known-library / impersonator list)

We add JA3 hashes to `knownLibraryJA3` (and optionally keep a separate impersonator set) from:

- **Reference payloads**: e.g. `tests/testdata/reference_bot_curl_cffi.json` — capture real request with X-FP-JA3-HASH from your proxy; hash is in `fingerprint.tls.ja3_hash`.
- **Public JA3 databases and tools** (no single “impersonator” list; use to look up or verify hashes):
  - **ja3.me** — free JA3+User-Agent database; API: `https://api.ja3.me/v1/ja3/{hash}`, `https://api.ja3.me/v1/user_agent/{query}` (see [ja3.me](https://ja3.me/)).
  - **Scrapfly JA3 tool** — [Scrapfly JA3/JA4 fingerprint](https://scrapfly.io/web-scraping-tools/ja3-fingerprint) (compare against 125k+ fingerprints).
  - **Live capture**: [tls.browserleaks.com/json](https://tls.browserleaks.com/json), [tls.peet.ws/api/all](https://tls.peet.ws/api/all) — hit with the client (e.g. curl_cffi) and read JA3 from the response.
- **curl-impersonate / curl_cffi**: The [curl-impersonate](https://github.com/lwthiker/curl-impersonate) repo does **not** publish a ready list of JA3 hashes. It provides:
  - **tests/signatures/** — YAML with full TLS Client Hello (ciphers, extensions, etc.) per browser version; JA3 can be **derived** from these or **measured** by running the binary.
  - **curl_cffi** supports targets like chrome99..chrome136, safari153..safari260, firefox133, etc. (see [curl_cffi impersonate targets](https://curl-cffi.readthedocs.io/en/latest/impersonate/targets.html)). Each target has a fixed JA3 per build; to collect hashes, run e.g. `curl_cffi` with `impersonate="chrome124"` against tls.browserleaks.com or your `/debug` endpoint and record the JA3 hash, then add it to `knownLibraryJA3` in `internal/fingerprint/tls_client_map.go`.
- **Operational data**: Logs with `fingerprint.tls.ja3_hash` and `fingerprint.proxy_headers` (X-FP-JA3-HASH) for requests classified or confirmed as bots; add recurring hashes to the blocklist after review.

There is no single public "all curl-impersonate JA3" list; we maintain the list from reference payloads, from measuring each curl_cffi/curl-impersonate profile, from ja3.me/Scrapfly for lookup/verification, and from operational logs.

### References (Appendix I)

- [2] FoxIO JA4+ Network Fingerprinting — https://github.com/FoxIO-LLC/ja4 (JA4H technical_details/JA4H.md). JA4H includes Accept-Language in HTTP client fingerprint.
- ThreatRelay JA4H Quick Labs — https://www.threatrelay.com/Quick-Labs/JA4/JA4H (HTTP client fingerprinting).
- WebDecoy headless/impersonate detection — headless browser detection (Playwright, Puppeteer, Selenium); JA4/JA4H for scrapers.
- MDN Sec-CH-UA — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-CH-UA.
- MDN Accept-Language — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language (q-values, browser behavior, incognito single-language).
- Radware Bot Manager — HTTP Header Anomaly-based Bot Detection: Accept-Language spoofing; correlation of User-Agent with Accept headers — https://www.radware.com/blog/application-protection/http-header-anomaly-based-advanced-behavioural-bot-detection/.
- FP-Inconsistent (Venugopalan et al., IMC 2024) — fingerprint inconsistencies in evasive bot traffic; spatial/temporal consistency rules — https://arxiv.org/abs/2406.07647.
- curl_cffi impersonate — https://curl-cffi.readthedocs.io/en/latest/impersonate.html (what is mimicked: TLS, H2, headers).
- curl_cffi Impersonation FAQ — JA3/akamai not comprehensive; other fields detectable — https://curl-cffi.readthedocs.io/en/latest/impersonate/faq.html.
- W3C nav-speculation Prefetch (Sec-Purpose) — https://wicg.github.io/nav-speculation/prefetch.html#sec-purpose-header. MDN Sec-Purpose — https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Sec-Purpose.

---

## Appendix J: Request log statistics and collection methodology

*Added: 2026-02*

### Purpose

This appendix describes how we collect and aggregate statistics from request logs produced by the classifier. The goal is to support methodology validation, tuning of scoring weights, and operational insight into bot vs browser traffic composition. The implementation is the `request_log_stats.py` tool (see `tools/python/README.md` and the script docstring).

### Data source and filters

- **Input**: JSONL files; each line is one JSON object with `classification`, `score`, `fingerprint`, `signals`, and optionally `remote_addr`. Format matches `tests/testdata/reference_browser.json` and the log structure in [Implementation Details](#implementation-details) above.
- **Optional filters**:
  - **Stress-test exclusion** (`--exclude-stress-tests`): Records with User-Agent normalised to `go-http-client` *and* path in `/`, `/health`, `/debug` are excluded so that load-test traffic (which hits only these endpoints) does not dominate aggregates. Other go-http-client traffic is retained.
  - **Localhost as empty**: `remote_addr` equal to `127.0.0.1` or `127.0.0.1:port` is normalised to `(empty)` so that local/proxy-forwarded traffic is grouped and excluded from “unique IP” and “top IP” counts when desired.
- **Canonical interpretation**: When TLS/HTTP data comes from a trusted proxy (X-FP-*), we do not use backend-only fields (e.g. `fingerprint.http.version`) for client protocol; we use `signals.is_http2` and fingerprint data already unified from proxy headers (see [Appendix F](METHODOLOGY.md#appendix-f-nginx-tls-termination-and-proxy-header-reuse)).

### Aggregation design

1. **Global summary**  
   Total requests (after filters), unique IPs, unique URLs (paths), bot/browser counts and percentages, score percentiles (median, P50, P95) and header-count percentiles, prevalence of boolean signals (e.g. `ua_is_bot`, `has_sec_fetch_headers`, `has_accept_language`, `sec_ch_ua_modern_order`), HTTP/2 ratio, and share of requests with TLS from proxy.

2. **Top-N by dimension**  
   For each of path, method, remote_addr (IP), user_agent (normalised family), user_agent_raw, accept, accept_lang_category, ja3_hash, ja4_hash, ja4h_hash, http_version, alpn, header_count_bucket, sec_ch_ua_prefix, and boolean signals (sec_ch_ua_present, has_sec_fetch, is_http2), we output the top-N values by total count (or by discriminativity |bot − browser|). Each row gives total, bot count, browser count, and bot%. For JA3/JA4/JA4H we also report distinct user-agents, paths, and IPs per fingerprint value (Signals Intelligence style). For *non-empty* fingerprint values only, we add per-hash lists with request counts: **top_user_agents** (raw User-Agent strings), **top_paths** (URL paths), **top_ips** (remote_addr); each list is `[{ "value": "...", "count": N }, ...]` sorted by count descending. The `(empty)` fingerprint value does not receive these breakdowns.

3. **Scoring-signal prevalence**  
   For every signal ID present in the scoring config (browser and bot, including zero-point signals), we parse the per-request `signals.score_breakdown` string and count how many requests had that signal in their breakdown. We output total, bot, browser, and bot%/browser% per signal.

4. **Statistical significance (optional)**  
   To avoid over-interpreting rare categories, we optionally apply a per-block significance filter: within each grouping (e.g. method, path, user_agent), we set N = max total among values in that block, excluding the value `(empty)`. We then keep only rows with total ≥ √N. This threshold can be disabled via `--no-significance-filter` for full enumeration.

**Output**: Text (default) or JSON (`--format json`). Progress bars: *Reading* (counting lines across files), *Processing* (parsing JSONL and aggregating). A reference JSON report is produced under `tests/testdata/report.json` (see [Brief interpretation](#brief-interpretation-of-a-sample-run) below).

### References (statistics and bot traffic measurement)

- **Cloudflare Signals Intelligence** — [Bots and JA3/JA4](https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/), [Signals Intelligence](https://developers.cloudflare.com/bots/concepts/signals-intelligence/). Use of JA4 and related metrics (browser ratio, UA/path/IP diversity per fingerprint, HTTP/2 ratio) for bot management; aligns with our top-N and diversity metrics.
- **Radware** — [HTTP Header Anomaly-based Advanced Behavioural Bot Detection](https://www.radware.com/blog/application-protection/http-header-anomaly-based-advanced-behavioural-bot-detection/) (2023). Header and Accept-Language anomalies; correlation of User-Agent with headers; supports our focus on accept, accept_lang_category, and header-order signals in aggregates.
- **FP-Inconsistent** (Venugopalan et al., IMC 2024) — [arXiv:2406.07647](https://arxiv.org/abs/2406.07647). Fingerprint inconsistencies in evasive bot traffic; spatial/temporal consistency. Our scoring-signal prevalence (e.g. `ja4h-inconsistent`, `tls-ua-inconsistent`) and per-signal bot% help validate which inconsistency signals fire in production.
- **Imperva Bad Bot Report** — [2025 Bad Bot Report](https://www.imperva.com/resources/reports/2025-Bad-Bot-Report.pdf). Automated vs human traffic share; bad bot trends; contextualises aggregate bot/browser ratios and path/method mixes.
- **FoxIO JA4+ / JA4H** — [JA4](https://github.com/FoxIO-LLC/ja4), [JA4H technical details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md). JA4H as HTTP client fingerprint; we aggregate ja4h_hash and JA4H-derived signals (e.g. ja4h-headers≥10, ja4h-consistent) in both top-N and scoring-signal tables.
- **When Handshakes Tell the Truth** (2025) — [Detecting Web Bad Bots via TLS Fingerprints](https://arxiv.org/html/2602.09606v1). TLS fingerprint (JA4) as protocol-level signal; ML-based bot detection; reinforces that one hash with many UAs is a bot indicator.

### Fingerprint–client diversity as a bot signal (2024–2025 methodology)

A well-established pattern in modern bot detection is **one TLS fingerprint (JA3/JA4/JA4H) associated with many different User-Agent strings, paths, or IPs**. TLS operates at the protocol layer; the ClientHello (cipher suites, extensions, order) reflects the actual TLS stack. User-Agent and other HTTP headers are trivial to spoof. So when a single fingerprint appears with a large diversity of claimed clients (e.g. "Chrome", "Firefox", "curl", "python-requests", scanners), it indicates one underlying stack pretending to be many — a strong signal of automation or evasive bots.

- **Cloudflare Signals Intelligence** (2024) explicitly uses per-fingerprint diversity: `uas_rank_1h` (diversity of user agents), `paths_rank_1h` (diversity of request paths), `ips_rank_1h` (diversity of client IPs), and `browser_ratio_1h` (share of browser-like UAs). Lower rank = higher diversity; high UA/path diversity with low browser ratio is indicative of non-browser traffic.
- **FP-Inconsistent** (Venugopalan et al., IMC 2024) shows that evasive bots exhibit *inconsistent* fingerprint attributes across space (different attributes in one fingerprint) and time; multiple user agents or identities under one fingerprint is a typical evasion pattern, and consistency checks (e.g. TLS vs UA, JA4H vs headers) reduce evasion.
- **JA4 in bot detection** (2024–2025): JA4’s structured format and sorting reduce cipher/extension randomization used by bots; the same “one hash, many clients” logic applies — a single JA4 with many distinct UAs is a fingerprint-level bot indicator.

**Application to our report**: In `tests/testdata/report.json`, the `(empty)` JA3 bucket (requests without TLS fingerprint from proxy) aggregates a very high diversity of raw User-Agents in `top_user_agents`: curl, CensysInspect, Go-http-client, python-requests, zgrab, Palo Alto Cortex, Let’s Encrypt, HeadlessChrome, bingbot, and many spoofed “Mozilla/…” strings. That is exactly the “one profile, many claimed identities” pattern. For non-empty hashes, the same view holds: `distinct_user_agents`, `distinct_paths`, `distinct_ips` plus the per-hash lists `top_user_agents`, `top_paths`, `top_ips` (with counts) let us spot fingerprints that are shared by many different claimed clients and paths — supporting methodology validation and tuning (e.g. down-ranking or flagging high-diversity, low-browser-ratio fingerprints).

### Brief interpretation of a sample run

The following is a short reading of the reference run in `tests/testdata/report.json` (after excluding go-http-client stress traffic on `/`, `/health`, `/debug`; significance filter can be disabled for that file with `--no-significance-filter`):

- **Volume**: 4 066 requests; 412 unique IPs; 1 319 unique paths — consistent with a mixed production-like sample where many requests share paths (e.g. `/`, `/favicon.ico`) and a subset of IPs account for most traffic.
- **Classification**: 36.89% bot, 63.11% browser. Score medians: bot −24, browser 0; P95 bot 2, browser 14 — clear separation; low header count and missing browser signals drive negative bot scores.
- **Paths**: Top path `/` has high bot% (66.58%); `/geoserver/wfs`, `/cgi-bin/ViewLog.asp`, `/.env` are almost entirely bot; `/login` is mixed. These reflect *breach attempts* against our classification: advanced bots probing or evading detection; login shows mixed use by both humans and automation.
- **Methods**: GET dominates; POST is more browser-heavy; HEAD and others (PROPFIND, OPTIONS, CONNECT) are almost all bot — consistent with crawlers and scanners.
- **User agents**: curl is numerous but mostly classified browser (many benign tools use curl); Chrome/Firefox show higher bot%; `(empty)` and python are almost all bot.
- **Fingerprint breakdown (JA3/JA4/JA4H)**: For each non-empty hash, the report includes `top_user_agents`, `top_paths`, and `top_ips` with request counts, so one can see which raw clients, URLs, and IPs contributed to that fingerprint (e.g. for a given JA3 hash, the list of User-Agent strings and their counts).
- **Scoring signals**: High-prevalence browser signals (e.g. `ja4h-headers>=10`, `browser-headers`) and bot signals (`no-accept-lang`, `ja4h-no-lang`, `low-headers`, `ja4h-low-headers`, `missing-typical`, `ja4h-inconsistent`) match the rule set; per-signal bot%/browser% helps prioritise which signals to tune or monitor.

This kind of output supports methodology review (e.g. Appendix I signals), scoring calibration, and operational dashboards (top paths/methods/IPs, TLS-from-proxy share, HTTP/2 ratio).

### References (Appendix J)

- Cloudflare Signals Intelligence — https://developers.cloudflare.com/bots/concepts/signals-intelligence/
- Cloudflare JA3/JA4 — https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/
- Radware HTTP Header Anomaly-based Bot Detection — https://www.radware.com/blog/application-protection/http-header-anomaly-based-advanced-behavioural-bot-detection/
- FP-Inconsistent (arXiv:2406.07647) — https://arxiv.org/abs/2406.07647
- Imperva 2025 Bad Bot Report — https://www.imperva.com/resources/reports/2025-Bad-Bot-Report.pdf
- FoxIO JA4+ (JA4, JA4H) — https://github.com/FoxIO-LLC/ja4
- When Handshakes Tell the Truth: Detecting Web Bad Bots via TLS Fingerprints (2025) — https://arxiv.org/html/2602.09606v1

---

## Appendix K: Client Hints behavioural challenge

*Added: 2026-02*

### Purpose

This appendix specifies a **behavioural classifier** that uses HTTP Client Hints (Accept-CH, Critical-CH) and a server-issued cookie (`__ch_nonce`) bound to the JA4H fingerprint. In JA4H, **C and D** are the cookie hash (cookie names and name=value). The **nonce** is **C_D** only: one nonce per cookie set, so that when two different clients use the same cookies (same C,D), they share one nonce and the second fails (no cookie or wrong User-Agent). The challenge runs only when C and D are non-zero. The goal is to detect impersonators that either do not persist cookies, do not send the requested Sec-CH-UA-* headers on subsequent requests, or reuse a single cookie jar across many clients (or one jar for all traffic). Real browsers that honour Accept-CH will store the cookie and send the requested hints on the next request; automation and shared-jar setups frequently fail one or more of these checks.

### Specification references

- **RFC 8942** — *HTTP Client Hints* (February 2021). Defines the `Accept-CH` response header by which a server advertises which client hint headers it accepts; clients may then send those headers in subsequent requests. Experimental; IETF. <https://www.rfc-editor.org/info/rfc8942>.
- **WICG Client Hints Infrastructure** — Draft Community Group Report. Integrates Client Hints with the web platform; defines how clients process `Accept-CH` and the **Critical-CH** header. Critical-CH instructs the client to retry the request with the indicated hints if they were missing, ensuring reliable content adaptation. <https://wicg.github.io/client-hints-infrastructure/>.
- **Critical-CH** (MDN) — Each header listed in Critical-CH must also appear in Accept-CH and Vary; the client retries the request with the critical hints. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Critical-CH>.
- **User-Agent Client Hints** (Chrome, MDN) — Sec-CH-UA, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version, etc. Low-entropy hints are sent by default; high-entropy hints are sent only after the server requests them via Accept-CH. <https://developer.chrome.com/docs/privacy-security/user-agent-client-hints>; <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Client_hints>.

### Flow

1. **First request (no `__ch_nonce` cookie, or cookie value unknown to the server)**  
   The server computes the **nonce** from the request’s JA4H hash: nonce = **C_D** (parts 3 and 4 — the cookie hash). Example: `ge11cn25ruru_30e4f3a786b6_68abb940d098_7b022c4b1588` → nonce = `68abb940d098_7b022c4b1588`. Two different clients with the same cookies (same C,D) thus share one nonce; the second fails (no cookie or UA mismatch).  
   - **Empty nonce**: If parts C and D are all zeros (no cookies present, e.g. `000000000000_000000000000`), the server **does not** store the nonce, **does not** send Set-Cookie, and **does not** apply the challenge; classification proceeds using existing fingerprint and scoring signals only.  
   - **Nonce already in store, but no cookie in request**: If the computed nonce is already in the server’s store (from a prior response) and the request does not contain the `__ch_nonce` cookie, the client is treated as having failed the challenge (impersonator that does not send back the cookie).  
   - **Same nonce, different clients:** For any same non-zero JA4H (same nonce), the challenge must fire: the first request gets the cookie; any subsequent request with that nonce either has no cookie (→ fail) or has the cookie but a different User-Agent or wrong hints (→ fail). Only the same client returning with the same UA and correct hints passes.  
   - **Otherwise**: The server stores `nonce → raw User-Agent` with a TTL (e.g. 60–120 s), and responds with:
     - `Accept-CH: Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version`
     - `Critical-CH: Sec-CH-UA-Full-Version-List` (and optionally both hints; each must also appear in Vary)
     - `Vary: Sec-CH-UA-Full-Version-List, Sec-CH-UA-Platform-Version`
     - `Set-Cookie: __ch_nonce=<nonce>; Max-Age=<challenge_ttl_sec>; Secure; HttpOnly; SameSite=Lax` — cookie lifetime is **synchronized** with the challenge store TTL and with the behavioural metrics window for this nonce (Appendix L), so the client sends the nonce for the same period the server retains it.

2. **Second request (Cookie: `__ch_nonce=<nonce>` and nonce known in store)**  
   The server retrieves the stored User-Agent for that nonce. It then checks: (1) the request’s User-Agent matches the stored value; (2) the request includes the requested Client Hint headers (e.g. `Sec-CH-UA-Full-Version-List`, `Sec-CH-UA-Platform-Version`); (3) when the stored User-Agent identifies a Chrome-, Chromium-, or Edg-based browser, the `Sec-CH-UA-Full-Version-List` header must contain the same version as in that User-Agent: exact match (e.g. `v="120.0.0.0"`) or, when the UA has a simplified major (e.g. `Chrome/145.0.0.0`), any full version with the same major (e.g. `v="145.0.7632.75"`); a different or generic version fails the check. For non–Chrome/Chromium/Edg User-Agents, the version check is skipped. If all applicable checks hold, the challenge is **passed**; otherwise (wrong UA, missing hints, version mismatch, or nonce not in store / expired) the challenge is **failed** and the result is used as a bot signal in scoring.

### Signals and scoring

- **challenge-passed**: Second request with matching UA, required Sec-CH-* headers present, and (for Chrome/Chromium/Edg UAs) the full-version list containing the same version as in the stored User-Agent; may contribute a small positive (browser) weight.  
- **challenge-failed**: Second request with mismatched UA, missing hints, or version mismatch in `Sec-CH-UA-Full-Version-List`; or first-request path with nonce already in store but no cookie sent; or second request with unknown/expired nonce. **+3 bot** (smoking gun); same weight as obsolete-tls, exotic-alpn, blind-probe, bot-ua, no-ua, ua-browser-no-grease.

Classification and logging remain unchanged except for the addition of these challenge signals and the corresponding response headers when the challenge is applied.

### Impersonator patterns detected

- **Shared cookie jar**: One cookie jar (same `__ch_nonce` value) used for many different clients. The store maps nonce → one User-Agent; when another request arrives with the same nonce but a different User-Agent, the mismatch is detected and the challenge fails.  
- **One jar reused for all traffic**: A single jar reused across many requests or identities; again, the same nonce may appear with different User-Agents or without the cookie on a “repeat” visit, both of which are flagged.  
- **Wrong or generic version in Client Hints**: An impersonator may send a fixed or arbitrary `Sec-CH-UA-Full-Version-List` (e.g. a single common version). The server requires the version in that header to match the stored User-Agent: exact match or, when UA has simplified major (e.g. 145.0.0.0), same major in the hint (e.g. v="145.0.7632.75"). A mismatch fails the challenge. These behaviours are common in scripts and proxies; binding the nonce to the stored User-Agent and to the declared version exposes them.

### References (Appendix K)

- IETF RFC 8942 — HTTP Client Hints (February 2021). <https://www.rfc-editor.org/info/rfc8942>.
- WICG Client Hints Infrastructure. <https://wicg.github.io/client-hints-infrastructure/>.
- MDN Critical-CH. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Critical-CH>.
- MDN Accept-CH. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-CH>.
- Chrome: User-Agent Client Hints. <https://developer.chrome.com/docs/privacy-security/user-agent-client-hints>.
- MDN: Client hints. <https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Client_hints>.

---

## Appendix L: Behavioural monitoring

*Added: 2026-02*

### Purpose

This appendix describes the **behavioural monitoring** subsystem that collects request-level metrics by client identifier (IP address and, when present, the `__ch_nonce` cookie value) for use in future bot-detection research. The subsystem does **not** perform scoring or classification in the current specification; it only persists metrics in a shared store (Redis). The design aligns with established literature on behavioural and session-based bot detection (request rate, inter-arrival times, and session characteristics) and with Redis-based patterns for sliding-window aggregation.

### Rationale and related work

Bot detection increasingly combines transport and application fingerprints with **behavioural signals**. Bots tend to exhibit distinct request patterns: high request rates, regular inter-arrival times, and navigation that deviates from typical human session structure. Passive collection of such metrics allows later use in rule-based or learning-based classifiers without requiring JavaScript or active challenges.

- **Request rate and volume**: Automated clients often generate high request volumes and navigate many pages in short periods; human users typically show moderate pacing (Human Security, 2025; Imperva Bad Bot Report). Rate limiting and volumetric baselines are standard in production systems (e.g. AWS WAF rate-based rules, Redis rate-limiting patterns).
- **Inter-arrival and session structure**: On-the-fly bot detection research uses inter-arrival times and request sequences as discriminative features for real-time classification (Cresci et al., Knowledge-Based Systems, 2021). Session duration and traversal patterns are central in graph-based and hybrid approaches (BOTracle: Kadel et al., arXiv:2412.02266, 2024; BotGraph-style traversal graphs).
- **Fingerprint consistency over time**: Evasive bots may alter fingerprints inconsistently across requests; temporal consistency of IP, nonce, and fingerprint is a useful signal (FP-Inconsistent, arXiv:2406.07647, 2024).
- **Storage**: Redis is widely used for rate limiting and sliding-window counters (e.g. ZADD, ZREMRANGEBYSCORE, ZCARD) and provides a natural backend for shared state across multiple server instances (Redis.io rate-limiting patterns; antirez fundamental rate-limiting).

By collecting metrics keyed by **IP** and by **`__ch_nonce`** (when present), we support both IP-based rate and session analysis and nonce-based consistency checks (e.g. one nonce used by many distinct IPs or many User-Agents), without committing to a specific scoring model in this appendix.

### Metrics collected

Metrics are updated asynchronously (non-blocking) on each classified request when Redis is configured. No metrics are collected when Redis is not in use.

**Essence of the collected metrics.** The subsystem records, for each *entity* (a client IP or a `__ch_nonce` cookie value), a **time series of request timestamps** within a configurable sliding window. Each stored value is the time of one classified request; no payload, path, or header content is stored. From this series one can derive: (1) **request rate** (e.g. requests per minute) as the count of timestamps in the window; (2) **inter-arrival statistics** (gaps between consecutive requests), which discriminate regular or bursty patterns typical of automation (Cresci et al., 2021); (3) **session-like scope** when keyed by nonce, tying multiple requests to the same client hint binding. Thus the metrics are purely **behavioural and volumetric**: they describe *when* and *how often* requests occur per identifier, not *what* was requested. This design supports future use in rate-based rules, inter-arrival features, and consistency checks (e.g. one nonce used from many IPs) without storing sensitive or application-level data.

| Dimension | Description |
|-----------|-------------|
| **Per client IP** | Client IP is taken from the same logic as logging (X-Real-IP, first element of X-Forwarded-For when trusted proxy, else RemoteAddr). |
| **Per `__ch_nonce`** | When the request includes a `__ch_nonce` cookie, the same metrics are also keyed by that cookie value. |

**Stored quantities (conceptual):**

- **Request count in a sliding window**: For each entity (IP or nonce), a sorted set of request timestamps (score = Unix time in milliseconds) is maintained. Old entries are removed outside the window (e.g. 60 s or 300 s); the cardinality after trim gives the request count in that window. This supports rate-based and volumetric features used in the literature.
- **Last-N timestamps**: The same or a separate structure retains the last K request times per entity to allow computation of inter-arrival statistics (e.g. min/mean/std of gaps between requests) for future use in classifiers that exploit timing regularity (Cresci et al., 2021).
- **TTL**: Keys are given an expiration (e.g. 24 h for IP, 2× challenge TTL for nonce) to bound memory and focus on recent behaviour.

Exact key names, window lengths, and TTLs are implementation-defined and documented in the deployment and configuration guides (e.g. `docs/deploy/README.md`, `config/README.md`). The session/window length for sliding-window request counts is configurable via `REDIS_METRICS_WINDOW_SEC` (default 300 seconds).

### Storage (Redis)

- **Backend**: Redis 6+ (single instance or managed/Sentinel as provided).
- **Key schema (example)**: `metrics:ip:<ip>:req`, `metrics:nonce:<nonce>:req` — sorted sets with score = timestamp, member = request id or timestamp string. Optional keys for “last K” or secondary windows may be added by implementation.
- **Operations**: For each request, pipeline or Lua: ZREMRANGEBYSCORE (trim old), ZADD (current time), EXPIRE. Failures are logged; request classification is unaffected.
- **Challenge (nonce) store**: The same Redis instance may be used for the Client Hints challenge store (nonce → User-Agent with TTL). Key pattern e.g. `ch:nonce:<nonce>`. See deployment README and Appendix K.

### Scope and limitations

- **No scoring**: This appendix defines only collection and storage. Integration of these metrics into the classifier (e.g. score weights or thresholds) is out of scope here.
- **Best-effort**: Metric updates are best-effort; backpressure or Redis unavailability must not change classification or response.
- **Privacy and retention**: Operators should configure TTLs and key scope in line with data retention and privacy policy.

### References (Appendix L)

- BOTracle: J. Kadel, R. A. See, R. Sinha, M. Fischer, “BOTracle: A framework for Discriminating Bots and Humans,” arXiv:2412.02266, 2024. <https://arxiv.org/abs/2412.02266>.
- S. Cresci et al., “Efficient on-the-fly Web bot detection,” Knowledge-Based Systems, 2021. <https://www.sciencedirect.com/science/article/pii/S0950705121003373>.
- FP-Inconsistent: “Measurement and Analysis of Fingerprint Inconsistencies in Evasive Bot Traffic,” arXiv:2406.07647, 2024. <https://arxiv.org/abs/2406.07647>.
- Data-driven human and bot recognition from web activity logs (hybrid learning), ScienceDirect, 2023. <https://www.sciencedirect.com/science/article/pii/S2352864823000330>.
- Redis rate limiting: “How to Implement Rate Limiting in Redis,” Redis.io. Sliding window log (ZADD, ZREMRANGEBYSCORE, ZCARD). <https://redis.io/docs/manual/patterns/rate-limiting/>.
- Human Security, “Bot Detection Guide,” 2025. <https://humansecurity.com/learn/topics/what-is-bot-detection>.
- Imperva, “Bad Bot Report,” 2025. <https://www.imperva.com/resources/reports/2025-Bad-Bot-Report.pdf>.

---

See [CHANGELOG.md](../CHANGELOG.md) for version history.

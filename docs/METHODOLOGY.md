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

HTTP clients emit headers in characteristic sequences based on implementation. While not reliable as a sole identifier, header order provides supplementary signal.

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
| HTTP/1.1 without H2 | Many crawlers don't negotiate HTTP/2 |
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
| `cipher_suites_count` | Number of offered ciphers | High count suggests browser |
| `has_session_ticket` | Session resumption support | ✓ |

#### HTTP-Level Signals

| Signal | Description | Browser Indicator |
|--------|-------------|-------------------|
| `has_sec_fetch_headers` | Sec-Fetch-* headers present | ✓✓ (strong indicator) |
| `has_accept_language` | Accept-Language header | ✓ |
| `has_sec_ch_ua` | Client hints present | ✓✓ |
| `header_count` | Total header count | High (≥10) suggests browser |
| `accept_header` | Accept header value | `*/*` suggests bot |

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
+1: has_accept_language
+1: has_browser_headers
+1: has_cookies
+1: header_count >= 10
+1: has_modern_tls
```

**Bot-positive signals:**
```
+3: ua_is_bot (known bot patterns)
+2: low_header_count (< 5 headers)
+2: missing_user_agent
+1: missing_typical_headers
+1: http/1.1 (without H2)
+1: accept = "*/*" (generic)
+1: missing_accept_language (without sec-fetch)
```

---

## Scoring Algorithm

### Classification Logic

```
net_score = browser_score - bot_score

if net_score >= threshold:
    classification = "browser"
else:
    classification = "bot"
```

Default threshold: `0` (browser score must exceed bot score)

### Confidence Calculation

```
confidence = base_confidence + signal_strength_adjustment

Where:
- base_confidence = |net_score| / total_signals
- Boosted by 20% if total_signals >= 5
- Reduced by 20% if total_signals < 3
- Clamped to [0.50, 0.99]
```

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

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    HTTP Request                         │
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
│  └──────────────┘  └──────────────────────────────────┘ │
└─────────────────────┬───────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────┐
│               Signal Extractor                          │
│  - Pattern matching (bot UA patterns)                   │
│  - Boolean signal extraction                            │
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
│  - Full fingerprint                                     │
│  - All signals                                          │
│  - Classification result                                │
│  - Response time                                        │
└─────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Request received** → TLS connection state captured
2. **Fingerprint collection** → Extract TLS and HTTP signals
3. **Signal extraction** → Convert raw data to boolean/numeric signals
4. **Score calculation** → Apply weights, compute net score
5. **Classification** → Compare against threshold
6. **Logging** → Write structured JSON for analysis
7. **Response** → Return classification to client

### Log Format (JSONL)

```json
{
  "timestamp": "2026-02-11T15:30:45.123Z",
  "request_id": "550e8400-e29b-41d4-a716-446655440000",
  "remote_addr": "192.168.1.100:54321",
  "classification": "bot",
  "confidence": 0.95,
  "fingerprint": {
    "tls": {
      "version": "TLS 1.3",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "alpn": "h2",
      "available": true
    },
    "http": {
      "version": "HTTP/2.0",
      "method": "GET",
      "path": "/",
      "user_agent": "curl/8.0.1",
      "header_count": 3,
      "header_order": ["user-agent", "accept", "host"]
    }
  },
  "signals": {
    "is_http2": true,
    "has_sec_fetch_headers": false,
    "ua_is_bot": true,
    "browser_score": 2,
    "bot_score": 6
  },
  "score": -4,
  "reason": "Bot indicators: bot User-Agent pattern, missing browser headers",
  "response_time_ms": 1
}
```

---

## Limitations & Future Work

### Current Limitations

1. **No TLS ClientHello parsing**: Standard Go TLS doesn't expose full ClientHello data needed for JA3/JA4 computation. Requires custom TLS listener.

2. **HTTP/2 frame analysis**: Not implemented. Could extract SETTINGS, WINDOW_UPDATE, PRIORITY frame patterns.

3. **No behavioral analysis**: Single-request classification only. No session/temporal patterns.

4. **Evasion vulnerability**: Sophisticated bots can spoof headers (except Sec-Fetch-*).

5. **No ML model**: Rule-based only. ML could improve accuracy.

### Future Work

Based on recent research (2025-2026), the following development roadmap addresses key gaps and incorporates state-of-the-art techniques.

---

#### Phase 1: TLS Fingerprinting Enhancement

**Goal**: Implement JA4+ fingerprinting for robust client identification

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] Custom TLS listener to capture ClientHello | High | JA4+ spec [2] |
| [ ] JA4 hash computation (sorted extensions) | High | FoxIO JA4 [2] |
| [ ] JA4H (HTTP fingerprint) integration | Medium | JA4+ family |
| [ ] JA4L (latency fingerprint) for timing analysis | Medium | JA4+ family |
| [ ] Fingerprint database integration (known JA4 hashes) | Medium | Cloudflare [3] |

**Why**: Chrome's 2023 extension randomization broke JA3; JA4 provides stable fingerprints. Industry adoption is universal by 2026 [2].

---

#### Phase 2: HTTP/2 Deep Inspection

**Goal**: Extract HTTP/2 frame-level signals per Akamai methodology

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] HTTP/2 SETTINGS frame capture | High | Akamai [4] |
| [ ] WINDOW_UPDATE pattern analysis | Medium | Akamai [4] |
| [ ] PRIORITY frame fingerprinting | Medium | Akamai [4] |
| [ ] H2/H3 ratio tracking (per-client behavioral) | Medium | Cloudflare signals |

**Why**: HTTP/2 implementation details (initial window size, max concurrent streams, header table size) create passive fingerprints that are hard to spoof [4].

---

#### Phase 3: Fingerprint Inconsistency Detection

**Goal**: Detect evasive bots via fingerprint inconsistencies (FP-Inconsistent approach)

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] Spatial inconsistency detection (cross-signal) | High | FP-Inconsistent [7] |
| [ ] Temporal inconsistency tracking (same client, different FPs) | High | FP-Inconsistent [7] |
| [ ] TLS/HTTP version mismatch detection | Medium | FP-Inconsistent [7] |
| [ ] Header-UA consistency validation | Medium | Radware [10] |

**Why**: FP-Inconsistent (2024) reduced evasion rates by 44-48% while maintaining 96.84% true-negative rate. Evasive bots produce inconsistent fingerprints across signals [7].

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

| Task | Priority | Reference |
|------|----------|-----------|
| [ ] Request timing pattern analysis | High | Cloudflare signals |
| [ ] Path access pattern clustering | Medium | - |
| [ ] Session fingerprint consistency tracking | Medium | FP-Inconsistent [7] |
| [ ] Mouse/keyboard event analysis (if JS available) | Low | FP-Inspector [8] |

**Why**: Single-request classification is vulnerable to evasion. Behavioral patterns over sessions are harder to spoof.

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
| Classification Latency (p99) | <5ms | ~1ms |
| False Positive Rate | <1% | TBD |

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

2. **JA4+ Network Fingerprinting** (FoxIO, 2023)
   - https://github.com/FoxIO-LLC/ja4
   - Medium: https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637
   - Updated fingerprinting addressing Chrome randomization

3. **Cloudflare JA3/JA4 Documentation**
   - https://developers.cloudflare.com/bots/concepts/ja3-ja4-fingerprint/
   - Enterprise bot management integration

### HTTP Fingerprinting

4. **Passive Fingerprinting of HTTP/2 Clients** (Akamai, BlackHat EU 2017)
   - https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf
   - HTTP/2 SETTINGS frame fingerprinting

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

## Changelog

### v0.2.0 (2026-02-11)
- Initial methodology documentation
- Rule-based classifier implementation
- HTTP signal extraction
- JSON logging for analysis

### v0.1.0 (2026-02-10)
- Project setup
- Basic User-Agent classification (sanity check)

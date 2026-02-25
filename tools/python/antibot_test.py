"""
Antibot detection bypass test using curl_cffi.

curl_cffi uses a patched curl (curl-impersonate) under the hood, which mimics
real browser TLS fingerprints (JA3/JA4), HTTP/2 frame ordering, and header signatures.

Results summary (https://antibot.invent.sale/):
  - Plain curl:                         bot  (confidence: 0.99)
  - curl + browser headers:             bot  (confidence: 0.60)
  - curl-impersonate (patched binary):  browser (confidence: 0.83)
  - curl_cffi (chrome + cookie jar):    browser (confidence: 0.99)
  - Playwright (real Chromium):         browser (confidence: 0.99)

Key factors the antibot checks:
  1. TLS fingerprint (JA3/JA4) — cipher suites order, extensions, curves
  2. HTTP/2 fingerprint — SETTINGS frame, WINDOW_UPDATE, HEADERS frame flags
  3. Header order and presence of Sec-CH-UA / Sec-Fetch-* headers
  4. ALPS (Application-Layer Protocol Settings) TLS extension
  5. Certificate compression (brotli)
  6. TLS extension permutation

Standard curl cannot fake items 1,2,4,5,6 — it requires either:
  - curl-impersonate (patched curl binary)
  - curl_cffi (Python library wrapping curl-impersonate)
  - A real browser engine (Playwright, Puppeteer, Selenium)

Dependencies:
  pip install curl-cffi
"""

import json
from curl_cffi import requests

# Cookie jar: cookies for domain .invent.sale (used in requests to antibot)
INVENT_COOKIES = [
    {
        "name": "__Secure-authjs.callback-url",
        "value": "https%3A%2F%2Finvent.sale",
        "domain": ".invent.sale",
        "path": "/",
        "httpOnly": True,
        "secure": True,
        "expires": -1,
        "sameSite": "Lax",
    }
]


def _cookies_jar() -> dict[str, str]:
    """Builds a name->value dict for passing to requests."""
    return {c["name"]: c["value"] for c in INVENT_COOKIES}


def _session_with_initial_cookies() -> requests.Session:
    """Session with a shared cookie jar; initial cookies from INVENT_COOKIES; response Set-Cookie is stored in the jar automatically."""
    session = requests.Session()
    for c in INVENT_COOKIES:
        session.cookies.set(
            c["name"],
            c["value"],
            domain=c.get("domain", ""),
            path=c.get("path", "/"),
        )
    return session


# Canonical "rich" Accept-Language (≥3 parts, ≥2 distinct q-values) — better browser signal
ACCEPT_LANGUAGE_RICH = "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6"


def test_antibot(
    url: str = "https://antibot.invent.sale/debug",
    session: requests.Session | None = None,
) -> dict:
    """Send a request impersonating Chrome and return the antibot verdict. Uses session's cookie jar; response Set-Cookie is stored in it."""
    if session is None:
        session = _session_with_initial_cookies()
    headers = {"Accept-Language": ACCEPT_LANGUAGE_RICH}
    response = session.get(url, impersonate="chrome", headers=headers)
    return response.json()


def _ja3_hash_from_result(data: dict) -> str:
    """Extract JA3 hash from antibot response (tls.ja3_hash or x-fp-ja3-hash header)."""
    fp = data.get("fingerprint") or {}
    tls = fp.get("tls") or {}
    if tls.get("ja3_hash"):
        return tls["ja3_hash"]
    headers = (fp.get("http") or {}).get("headers") or {}
    return headers.get("x-fp-ja3-hash") or (fp.get("proxy_headers") or {}).get("X-FP-JA3-HASH") or "—"


def _ja4h_hash_from_result(data: dict) -> str:
    """Extract JA4H hash from antibot response (fingerprint.http.ja4h_hash)."""
    return ((data.get("fingerprint") or {}).get("http") or {}).get("ja4h_hash") or "—"


def _challenge_state_line(data: dict) -> str:
    """Format challenge_state for one-line output: nonce_c_d, in_store, stored_ua."""
    cd = data.get("challenge_state") or {}
    if not cd:
        return ""
    parts = []
    if cd.get("nonce_c_d"):
        parts.append(f"nonce_c_d={cd['nonce_c_d']}")
    parts.append(f"in_store={cd.get('in_store', False)}")
    if cd.get("stored_ua"):
        ua_short = cd["stored_ua"][:60] + "…" if len(cd["stored_ua"]) > 60 else cd["stored_ua"]
        parts.append(f"stored_ua={ua_short!r}")
    return " | " + " ".join(parts) if parts else ""


def _current_ua_from_result(data: dict) -> str:
    """Extract current request User-Agent from debug response."""
    return ((data.get("fingerprint") or {}).get("http") or {}).get("user_agent") or ""


def test_antibot_with_profiles(
    url: str = "https://antibot.invent.sale/debug",
    session: requests.Session | None = None,
) -> None:
    """Test multiple browser profiles against the antibot service. One session = one cookie jar; Set-Cookie from each response is stored and sent on the next request."""
    profiles = [
        "chrome",       # Latest Chrome
        "chrome110",    # Chrome 110
        "chrome116",    # Chrome 116
        "safari",       # Safari
        "safari_ios",   # Safari iOS
    ]
    if session is None:
        session = _session_with_initial_cookies()

    headers = {"Accept-Language": ACCEPT_LANGUAGE_RICH}
    multi_instance_hint = False
    for profile in profiles:
        try:
            response = session.get(url, impersonate=profile, headers=headers)
            data = response.json()
            status = "PASS" if data["classification"] == "browser" else "FAIL"
            ja3 = _ja3_hash_from_result(data)
            ja4h = _ja4h_hash_from_result(data)
            sig = data.get("signals") or {}
            score = data.get("score", "—")
            bot_score = sig.get("bot_score", "—")
            browser_score = sig.get("browser_score", "—")
            ch_line = _challenge_state_line(data)
            print(f"[{status}] {profile:20s} -> {data['classification']} "
                  f"(confidence: {data['confidence']}) score={score} browser={browser_score} bot={bot_score} | ja4h_hash: {ja4h}{ch_line}")
            # If challenge says in_store with a stored_ua that doesn't match current profile UA, we're likely hitting different backends (each has its own store)
            cd = data.get("challenge_state") or {}
            if cd.get("in_store") and cd.get("stored_ua"):
                current_ua = _current_ua_from_result(data)
                if current_ua and cd["stored_ua"] != current_ua and data["classification"] == "browser":
                    multi_instance_hint = True
        except Exception as e:
            print(f"[ERR]  {profile:20s} -> {e}")
    if multi_instance_hint:
        print("\nNote: stored_ua differs from current UA but classification=browser — likely load-balanced: each request hit a different instance (challenge store is per-process). For same C_D to fail, all requests must hit the same instance or use a shared store (e.g. Redis).")


if __name__ == "__main__":
    # One cookie jar for the whole run: response Set-Cookie (e.g. __ch_nonce) is stored in the session and sent on subsequent requests.
    session = _session_with_initial_cookies()

    print("=== Single test (chrome profile) ===")
    result = test_antibot(session=session)
    print(json.dumps(result, indent=2))
    ja3 = _ja3_hash_from_result(result)
    ja4h = _ja4h_hash_from_result(result)
    sig = result.get("signals") or {}
    print(f"\nSummary: {result['classification']} (confidence: {result['confidence']}), "
          f"score={result.get('score')} browser={sig.get('browser_score')} bot={sig.get('bot_score')}, "
          f"ja3: {ja3}, ja4h: {ja4h}")

    print("\n=== Multi-profile test (same cookie jar, incl. from first request) ===")
    test_antibot_with_profiles(session=session)

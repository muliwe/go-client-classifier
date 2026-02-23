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

# Cookie jar: куки для домена .invent.sale (используются в запросах к antibot)
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
    """Собирает dict name->value для передачи в requests."""
    return {c["name"]: c["value"] for c in INVENT_COOKIES}


# Canonical "rich" Accept-Language (≥3 parts, ≥2 distinct q-values) — better browser signal
ACCEPT_LANGUAGE_RICH = "ru-RU,ru;q=0.9,en-GB;q=0.8,en;q=0.7,en-US;q=0.6"


def test_antibot(url: str = "https://antibot.invent.sale/debug") -> dict:
    """Send a request impersonating Chrome and return the antibot verdict."""
    headers = {"Accept-Language": ACCEPT_LANGUAGE_RICH}
    response = requests.get(url, impersonate="chrome", cookies=_cookies_jar(), headers=headers)
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


def test_antibot_with_profiles(url: str = "https://antibot.invent.sale/debug") -> None:
    """Test multiple browser profiles against the antibot service."""
    profiles = [
        "chrome",       # Latest Chrome
        "chrome110",    # Chrome 110
        "chrome116",    # Chrome 116
        "safari",       # Safari
        "safari_ios",   # Safari iOS
    ]
    cookies = _cookies_jar()

    headers = {"Accept-Language": ACCEPT_LANGUAGE_RICH}
    for profile in profiles:
        try:
            response = requests.get(url, impersonate=profile, cookies=cookies, headers=headers)
            data = response.json()
            status = "PASS" if data["classification"] == "browser" else "FAIL"
            ja3 = _ja3_hash_from_result(data)
            ja4h = _ja4h_hash_from_result(data)
            print(f"[{status}] {profile:20s} -> {data['classification']} "
                  f"(confidence: {data['confidence']}) ja4h_hash: {ja4h}")
        except Exception as e:
            print(f"[ERR]  {profile:20s} -> {e}")


if __name__ == "__main__":
    print("=== Single test (chrome profile) ===")
    result = test_antibot()
    print(json.dumps(result, indent=2))
    ja3 = _ja3_hash_from_result(result)
    ja4h = _ja4h_hash_from_result(result)
    print(f"\nSummary: {result['classification']} (confidence: {result['confidence']}), "
          f"x-fp-ja3-hash: {ja3}, ja4h_hash: {ja4h}")

    print("\n=== Multi-profile test ===")
    test_antibot_with_profiles()

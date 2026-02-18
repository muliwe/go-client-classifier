"""
Antibot detection bypass test using curl_cffi.

curl_cffi uses a patched curl (curl-impersonate) under the hood, which mimics
real browser TLS fingerprints (JA3/JA4), HTTP/2 frame ordering, and header signatures.

Results summary (https://antibot.invent.sale/):
  - Plain curl:                         bot  (confidence: 0.99)
  - curl + browser headers:             bot  (confidence: 0.60)
  - curl-impersonate (patched binary):  browser (confidence: 0.83)
  - curl_cffi (Python, chrome profile): browser (confidence: 0.83)
  - Playwright (real Chromium):         browser (confidence: 0.83)

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


def test_antibot(url: str = "https://antibot.invent.sale/debug") -> dict:
    """Send a request impersonating Chrome and return the antibot verdict."""
    response = requests.get(url, impersonate="chrome")
    return response.json()


def test_antibot_with_profiles(url: str = "https://antibot.invent.sale/debug") -> None:
    """Test multiple browser profiles against the antibot service."""
    profiles = [
        "chrome",       # Latest Chrome
        "chrome110",    # Chrome 110
        "chrome116",    # Chrome 116
        "safari",       # Safari
        "safari_ios",   # Safari iOS
    ]

    for profile in profiles:
        try:
            response = requests.get(url, impersonate=profile)
            data = response.json()
            status = "PASS" if data["classification"] == "browser" else "FAIL"
            print(f"[{status}] {profile:20s} -> {data['classification']} "
                  f"(confidence: {data['confidence']})")
        except Exception as e:
            print(f"[ERR]  {profile:20s} -> {e}")


if __name__ == "__main__":
    print("=== Single test (chrome profile) ===")
    result = test_antibot()
    print(json.dumps(result, indent=2))

    print("\n=== Multi-profile test ===")
    test_antibot_with_profiles()

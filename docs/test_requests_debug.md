# Test requests to /debug

To verify the classifier: a request from a **real browser** should yield `classification: browser`, 0 bot points; **three console requests** (curl, curl.exe, Invoke-WebRequest) with Chrome-like headers should yield **bot**.

Endpoint: `https://antibot.invent.sale/debug` (or your instance behind nginx with X-FP-*).

---

## Test: Real browser (manual request)

**Purpose:** Open the URL in a normal browser (Chrome, Firefox, etc.). The classifier should recognise the client as a browser with no false bot points.

**How to reproduce:** In the browser, go to `https://antibot.invent.sale/debug`. No scripts or header spoofing.

**Expected result (after v0.8.0 changes):** `classification: "browser"`, `bot_score: 0`, high `browser_score` (~20–21). In fingerprint: TLS from proxy, `ssl_greased` not "0", H2 fingerprint with browser-like window (e.g. 6291456), JA3 not in knownLibraryJA3. Breakdown must not include: `no-session(+1)`, `ja4h-inconsistent(+2)`, `h2-ua-inconsistent(+2)`.

---

## Three console requests

All three use Chrome-like headers; **bot** is expected (TLS/stack is not browser-like).

### Request 1 — curl (Bash)

```bash
curl -s "https://antibot.invent.sale/debug" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br, zstd" \
  -H "Cache-Control: max-age=0" \
  -H "Connection: keep-alive" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1" \
  -H "Sec-CH-UA: \"Chromium\";v=\"133\", \"Not(A:Brand\";v=\"99\", \"Google Chrome\";v=\"133\"" \
  -H "Sec-CH-UA-Mobile: ?0" \
  -H "Sec-CH-UA-Platform: \"Windows\"" \
  --compressed
```

Expected: `classification: bot`, JA3 from knownLibraryJA3 (e.g. `0149f47e...`), `ssl_greased: "0"`, H2 library-like (10485760).

---

### Request 2 — curl.exe (PowerShell)

```powershell
curl.exe -s "https://antibot.invent.sale/debug" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate, br, zstd" -H "Cache-Control: max-age=0" -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Sec-Fetch-User: ?1" -H 'Sec-CH-UA: "Chromium";v="133", "Not(A:Brand";v="99", "Google Chrome";v="133"' -H "Sec-CH-UA-Mobile: ?0" -H 'Sec-CH-UA-Platform: "Windows"' --compressed
```

Expected: `classification: bot`, JA3 e.g. `fae0e5d973c96ae1888b99538efa0363`, `ssl_greased: "0"`.

---

### Request 3 — Invoke-WebRequest (PowerShell)

(No Connection header — PowerShell does not allow setting it.)

```powershell
(Invoke-WebRequest -Uri "https://antibot.invent.sale/debug" -Headers @{"User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"; "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"; "Accept-Language"="en-US,en;q=0.9"; "Accept-Encoding"="gzip, deflate, br, zstd"; "Cache-Control"="max-age=0"; "Upgrade-Insecure-Requests"="1"; "Sec-Fetch-Dest"="document"; "Sec-Fetch-Mode"="navigate"; "Sec-Fetch-Site"="none"; "Sec-Fetch-User"="?1"; "Sec-CH-UA"='"Chromium";v="133", "Not(A:Brand";v="99", "Google Chrome";v="133"'; "Sec-CH-UA-Mobile"="?0"; "Sec-CH-UA-Platform"='"Windows"'}).Content
```

Expected: `classification: bot`, JA3 e.g. `68b3ecfaf0034bb9fcbecd518b5ab8d4` (.NET), `ssl_greased: "0"`.

---

| Test / request | How to run | Expected |
|----------------|------------|----------|
| Real browser | Open URL in browser | browser |
| 1. curl | Bash | bot |
| 2. curl.exe | PowerShell | bot |
| 3. Invoke-WebRequest | PowerShell | bot |

See [METHODOLOGY.md](METHODOLOGY.md), [CHANGELOG.md](../CHANGELOG.md) v0.8.0.

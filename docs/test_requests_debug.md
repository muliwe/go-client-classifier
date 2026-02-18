# Тестовые запросы к /debug

Для проверки классификатора: запрос из **реального браузера** должен давать `classification: browser`, 0 bot-баллов; **три консольных запроса** (curl, curl.exe, Invoke-WebRequest) с заголовками «под Chrome» — классификацию **bot**.

Endpoint: `https://antibot.invent.sale/debug` (или ваш инстанс за nginx с X-FP-*).

---

## Тест: Реальный браузер (ручной запрос)

**Суть:** Открыть URL в обычном браузере (Chrome, Firefox и т.д.). Классификатор должен распознать клиента как браузер без ложных bot-баллов.

**Как воспроизвести:** В браузере перейти на `https://antibot.invent.sale/debug`. Никаких скриптов и подмены заголовков.

**Ожидаемый результат (после правок v0.7.0):** `classification: "browser"`, `bot_score: 0`, `browser_score` высокий (~20–21). В fingerprint: TLS от proxy, `ssl_greased` не "0", H2 fingerprint с browser-like окном (напр. 6291456), JA3 не из knownLibraryJA3. В breakdown не должно быть: `no-session(+1)`, `ja4h-inconsistent(+2)`, `h2-ua-inconsistent(+2)`.

---

## Три консольных запроса

Все три — с заголовками под Chrome; ожидается **bot** (TLS/стек не браузерный).

### Запрос 1 — curl (Bash)

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

Ожидается: `classification: bot`, JA3 из knownLibraryJA3 (напр. `0149f47e...`), `ssl_greased: "0"`, H2 library-like (10485760).

---

### Запрос 2 — curl.exe (PowerShell)

```powershell
curl.exe -s "https://antibot.invent.sale/debug" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate, br, zstd" -H "Cache-Control: max-age=0" -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-Site: none" -H "Sec-Fetch-User: ?1" -H 'Sec-CH-UA: "Chromium";v="133", "Not(A:Brand";v="99", "Google Chrome";v="133"' -H "Sec-CH-UA-Mobile: ?0" -H 'Sec-CH-UA-Platform: "Windows"' --compressed
```

Ожидается: `classification: bot`, JA3 напр. `fae0e5d973c96ae1888b99538efa0363`, `ssl_greased: "0"`.

---

### Запрос 3 — Invoke-WebRequest (PowerShell)

(Без заголовка Connection — PowerShell не даёт его задавать.)

```powershell
(Invoke-WebRequest -Uri "https://antibot.invent.sale/debug" -Headers @{"User-Agent"="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"; "Accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"; "Accept-Language"="en-US,en;q=0.9"; "Accept-Encoding"="gzip, deflate, br, zstd"; "Cache-Control"="max-age=0"; "Upgrade-Insecure-Requests"="1"; "Sec-Fetch-Dest"="document"; "Sec-Fetch-Mode"="navigate"; "Sec-Fetch-Site"="none"; "Sec-Fetch-User"="?1"; "Sec-CH-UA"='"Chromium";v="133", "Not(A:Brand";v="99", "Google Chrome";v="133"'; "Sec-CH-UA-Mobile"="?0"; "Sec-CH-UA-Platform"='"Windows"'}).Content
```

Ожидается: `classification: bot`, JA3 напр. `68b3ecfaf0034bb9fcbecd518b5ab8d4` (.NET), `ssl_greased: "0"`.

---

| Тест / запрос | Как сделать | Ожидание |
|---------------|-------------|----------|
| Реальный браузер | Открыть URL в браузере | browser |
| 1. curl | Bash | bot |
| 2. curl.exe | PowerShell | bot |
| 3. Invoke-WebRequest | PowerShell | bot |

См. [METHODOLOGY.md](METHODOLOGY.md), [CHANGELOG.md](../CHANGELOG.md) v0.7.0.

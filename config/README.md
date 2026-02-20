# Scoring configuration

Конфиг скоринга загружается при старте сервиса (`SCORING_CONFIG` или `config/scoring.json`). При ошибке чтения используются встроенные дефолты (те же значения, что в `scoring.default.json`).

## Структура JSON

| Секция | Описание |
|--------|----------|
| `classifier` | Вес бот-баллов и порог: `net = browser_score - bot_score_weight * bot_score`; класс **browser**, если `net > threshold`. |
| `confidence` | Параметры расчёта уверенности (no_signal, пороги и множители по числу сигналов, min/max). |
| `thresholds` | Числовые пороги для извлечения сигналов (порядок заголовков, число cipher suites, TLS extensions, JA4H, Accept-Language). |
| `browser_scores` | Баллы за каждый browser-сигнал (положительные к классификации «браузер»). |
| `bot_scores` | Баллы за каждый bot-сигнал (положительные к классификации «бот»). |

Файл **scoring.default.json** — эталонный дефолт с текущими значениями для коммита и сравнения.

---

## Smoking guns (бот, +3)

Сильные индикаторы автоматизации; один такой сигнал уже сильно тянет в сторону бота (с учётом веса 4: +3 → +12 к отрицательному net).

| Ключ | Когда срабатывает |
|------|-------------------|
| `obsolete-tls` | TLS 1.0 / 1.1. Реальные браузеры не используют. |
| `exotic-alpn` | ALPN вроде `http/0.9`, `spdy`, `h2c`, `hq` — типично сканеры/боты. |
| `blind-probe` | Запрос не GET или путь не `/`/`/debug` (зонд по неразрешённым путям). |
| `bot-ua` | User-Agent совпадает с известным ботом (curl, python, go-http-client, puppeteer, и т.д.). |
| `no-ua` | Нет заголовка User-Agent (легитимные клиенты всегда шлют). |
| `tls-ua-inconsistent` | UA «браузер», но JA3/JA4 — известная библиотека (curl, Go, Python и т.п.); или UA бот, а TLS — браузерный. |
| `ua-browser-no-grease` | За nginx: UA браузерный, но GREASE в TLS нет (реальные браузеры шлют GREASE). |

---

## Сильные бот-сигналы (+2)

| Ключ | Когда срабатывает |
|------|-------------------|
| `ai-crawler` | User-Agent совпадает с AI/LLM краулером (gptbot, perplexity, и т.д.). |
| `ja4h-no-cookies` | Browser UA, нет cookies, JA4H C/D нулевые (инкогнито/первый заход; понижено с +3, чтобы не считать инкогнито ботом). |
| `missing-typical` | Нет типичных заголовков (Accept или Accept-Encoding) и нет Sec-Fetch. |
| `ja4h-inconsistent` | JA4H не согласован с HTTP-сигналами (cookies, referer, language, версия). |
| `header-order-late` | Порядок заголовков от прокси: Accept или Accept-Language «поздно» (индекс ≥ 12). |
| `h2-ua-inconsistent` | UA браузерный, но H2 fingerprint выглядит как библиотека (нет PRIORITY, небраузерное окно и т.д.). |
| `h2-ja4-inconsistent` | JA4 говорит h2, запрос HTTP/1.1, или наоборот. |
| `tls-alpn-http-inconsistent` | ALPN (h2/http/1.1) не совпадает с фактической версией HTTP запроса. |

---

## Слабые бот-сигналы (+1)

| Ключ | Когда срабатывает |
|------|-------------------|
| `http1.1` | TLS был доступен, но запрос HTTP/1.1 без H2 (многие боты не поднимают H2). |
| `accept-*/*` | Accept = `*/*` (типично для библиотек). |
| `no-accept-lang` | Нет Accept-Language и нет Sec-Fetch. |
| `low-headers` | Мало заголовков (`header_count < low_header_count_max`); понижено до +1 (инкогнито может слать меньше). |
| `low-ciphers` | Мало cipher suites (0 < count < 10). |
| `few-tls-ext` | Мало TLS extensions (0 < count < 8). |
| `no-session` | Нет session ticket (при прямом TLS, не от прокси). |
| `ja4h-no-lang` | В JA4H нет кода языка (0000). |
| `ja4h-low-headers` | В JA4H мало заголовков (< 5). |

---

## Браузерные баллы

- **+2:** `http2` (используется HTTP/2), `high-ciphers` (много cipher suites, типично для браузера).
- **+1:** все остальные ключи в `browser_scores`, кроме перечисленных ниже с нулём.

---

## Слабые / нулевые сигналы (0 баллов)

Эти сигналы **легко подделать** (заголовки, один заголовок и т.д.), поэтому им явно выставлен 0. Они участвуют в логике (например, для консистентности JA4H), но не дают баллов.

| Ключ | Описание |
|------|----------|
| `accept-language` | Наличие Accept-Language — тривиально подделать. |
| `browser-headers` | Комбинация «браузерных» заголовков (Sec-Fetch или Accept-Language) — тривиально. |
| `sec-ch-ua-modern` | Современный порядок в Sec-CH-UA (Not:A-Brand и т.п.) — легко подделать. |
| `accept-lang-rich` | «Богатый» Accept-Language (несколько локалей, длинная строка) — легко подделать. |
| `high-header-count` | Большое число заголовков — тривиально подделать; число всё ещё используется в других проверках. |

При необходимости можно выставить им ненулевые значения в конфиге (например, для экспериментов).

---

## Пороги (`thresholds`)

| Ключ | По умолчанию | Назначение |
|------|--------------|------------|
| `browser_like_header_order_max_idx` | 12 | Accept и Accept-Language оба до этого индекса → «браузерный» порядок. |
| `header_order_late_min_idx` | 12 | Индекс ≥ этого → заголовок считается «поздним» (сигнал имитатора). |
| `high_cipher_count_min` | 10 | Cipher suites > этого → high-ciphers (браузер). |
| `low_cipher_count_max` | 10 | Cipher suites < этого (и > 0) → low-ciphers (бот). |
| `tls_ext_browser_min` | 10 | TLS extensions ≥ этого → tls-ext>=10 (браузер). |
| `few_tls_ext_max` | 8 | TLS extensions < этого (и > 0) → few-tls-ext (бот). |
| `supported_groups_min` | 3 | Групп ≥ этого → multi-groups (браузер). |
| `low_header_count_max` | 5 | Заголовков < этого → low-headers (бот). |
| `ja4h_low_header_count_max` | 5 | В JA4H заголовков < этого → ja4h-low-headers. |
| `ja4h_high_header_count_min` | 10 | В JA4H заголовков ≥ этого → ja4h-headers>=10. |
| `accept_lang_min_locale_parts` | 3 | Минимум частей в Accept-Language для «богатого» (или длина). |
| `accept_lang_min_length` | 40 | Минимальная длина Accept-Language для «богатого». |

---

## Классификатор

- **bot_score_weight** (4): множитель бот-баллов в формуле net. Несколько сильных бот-сигналов быстро перевешивают подделываемые браузерные заголовки.
- **threshold** (4): граница решения. `net > threshold` → browser; при равенстве решает User-Agent (бот-UA остаётся ботом).

Формула: **net = browser_score − bot_score_weight × bot_score**.

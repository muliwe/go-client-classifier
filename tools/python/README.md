# Python tools

Вспомогательные скрипты на Python для проекта go-client-classifier (тесты антибот-обхода и др.).

## Требования

- Python 3.12+
- [Poetry](https://python-poetry.org/docs/#installation)

## Установка (деплой окружения)

Из корня репозитория:

```bash
cd tools/python
poetry install
```

Или из любой директории:

```bash
poetry install --directory tools/python
```

После этого окружение с зависимостями готово к использованию.

## Запуск скриптов

Все команды выполняйте из `tools/python` после `poetry install`, либо через `poetry run`:

```bash
cd tools/python
poetry run python antibot_test.py
```

Или активируйте shell и запускайте скрипты как обычно:

```bash
cd tools/python
poetry shell
python antibot_test.py
```

## Что внутри

- **antibot_test.py** — проверка обхода антибот-детекции через [curl_cffi](https://github.com/yifeikong/curl_cffi) (TLS/HTTP2 fingerprint под Chrome/Safari). Зависимость: `curl-cffi`.

- **request_log_stats.py** — сбор статистики по request-logs (JSONL) для методологии детекции ботов: топ-N по полям (path, method, IP, user_agent, accept, JA3/JA4/JA4H, заголовки), разбивка bot/browser, превалентность сигналов скоринга, глобальная сводка (уникальные IP/URL). Метрики в духе [Cloudflare Signals Intelligence](https://developers.cloudflare.com/bots/concepts/signals-intelligence/); опциональный фильтр по статзначимости (√N). Учитывает каналы доставки (**docs/nginx.md**); единая интерпретация при прокси (signals.is_http2, fingerprint.tls). Подробно: **docs/METHODOLOGY.md**, Appendix J (Request log statistics and collection methodology).

  Запуск (из `tools/python` или из корня репо):

  ```bash
  poetry run python request_log_stats.py -n 20 "logs/**/requests_*.jsonl"
  poetry run python request_log_stats.py -n 10 -o report.txt --format text "logs/**/*.jsonl"
  poetry run python request_log_stats.py --format json -o stats.json "logs/**/requests_*.jsonl"
  ```

  Опции: `-n` / `--top` — число топ-значений по каждому полю (по умолчанию 15); `-o` — файл вывода; `--format text|json`; `--sort count|discriminative`; `--exclude-stress-tests` — исключить go-http-client; `--no-significance-filter` — отключить фильтр по статзначимости (√N). Формат записей — один JSON на строку (`tests/testdata/reference_browser.json`).

## Зависимости

Управляются через Poetry, см. `pyproject.toml`. Основные: `curl-cffi`, `pandas`, `numpy`.

Добавление новой зависимости:

```bash
cd tools/python
poetry add <package>
```

Обновление lock-файла после правок `pyproject.toml`:

```bash
poetry lock
poetry install
```

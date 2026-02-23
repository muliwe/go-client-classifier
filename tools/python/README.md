# Python tools

Helper Python scripts for the go-client-classifier project (antibot bypass tests and more).

## Requirements

- Python 3.12+
- [Poetry](https://python-poetry.org/docs/#installation)

## Setup (deploy environment)

From the repo root:

```bash
cd tools/python
poetry install
```

Or from any directory:

```bash
poetry install --directory tools/python
```

After that the environment with dependencies is ready to use.

## Running scripts

Run all commands from `tools/python` after `poetry install`, or via `poetry run`:

```bash
cd tools/python
poetry run python antibot_test.py
```

Or activate the shell and run scripts as usual:

```bash
cd tools/python
poetry shell
python antibot_test.py
```

## Contents

- **antibot_test.py** — antibot detection bypass check via [curl_cffi](https://github.com/yifeikong/curl_cffi) (TLS/HTTP2 fingerprint as Chrome/Safari). Dependency: `curl-cffi`.

- **request_log_stats.py** — statistics over request logs (JSONL) for bot detection methodology: top-N by fields (path, method, IP, user_agent, accept, JA3/JA4/JA4H, headers), bot/browser split, scoring signal prevalence, global summary (unique IPs/URLs). Metrics in the spirit of [Cloudflare Signals Intelligence](https://developers.cloudflare.com/bots/concepts/signals-intelligence/); optional significance filter (√N). Accounts for delivery channels (**docs/nginx.md**); unified interpretation behind proxy (signals.is_http2, fingerprint.tls). Details: **docs/METHODOLOGY.md**, Appendix J (Request log statistics and collection methodology).

  Run (from `tools/python` or repo root):

  ```bash
  poetry run python request_log_stats.py -n 20 "logs/**/requests_*.jsonl"
  poetry run python request_log_stats.py -n 10 -o report.txt --format text "logs/**/*.jsonl"
  poetry run python request_log_stats.py --format json -o stats.json "logs/**/requests_*.jsonl"
  ```

  Options: `-n` / `--top` — number of top values per field (default 15); `-o` — output file; `--format text|json`; `--sort count|discriminative`; `--exclude-stress-tests` — exclude go-http-client; `--no-significance-filter` — disable significance filter (√N). Record format: one JSON per line (`tests/testdata/reference_browser.json`).

## Dependencies

Managed via Poetry, see `pyproject.toml`. Main ones: `curl-cffi`, `pandas`, `numpy`.

Adding a new dependency:

```bash
cd tools/python
poetry add <package>
```

Updating the lock file after editing `pyproject.toml`:

```bash
poetry lock
poetry install
```

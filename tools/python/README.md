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

- **build_dashboard_payload.py** — builds the **dashboard JSON** consumed by the TS dashboard (`tools/ts/dashboard`). Reads JSONL request logs (same format as `request_log_stats.py`: `classification`, `timestamp`, `signals.score_breakdown`, optional `request_metrics` for behavioural signals). Output: `windows` (hour, day, week, month, all), `timeline` (fixed 60 bars; granularity 10 s → 10 min, 1 min → 1 h, 10 min → 10 h when many empty bars), `signals` (transport signals from score_breakdown + behavioural: `req_per_min`, `gap_median`, `gap_std_mean`, `gap_mean_median`), plus `timeline_bucket_sec` and `timeline_window_sec` for the UI. Records without `timestamp` are skipped.

  ```bash
  poetry run python build_dashboard_payload.py "logs/**/requests_*.jsonl"
  poetry run python build_dashboard_payload.py -o dashboard.json "logs/**/*.jsonl"
  poetry run python build_dashboard_payload.py --timeline-minutes 10 "logs/**/requests_*.jsonl"
  poetry run python build_dashboard_payload.py --progress "logs/**/requests_*.jsonl"
  ```

  Options: `-o` / `--output` — output file (default: stdout); `--timeline-minutes` — timeline window in minutes for the initial 10 s granularity (default: 10); `--progress` — show tqdm progress bar (default: simple stderr log “Reading N file(s)…” / “Read M records.”).

- **request_log_stats.py** — statistics over request logs (JSONL) for bot detection methodology: top-N by fields (path, method, IP, user_agent, accept, JA3/JA4/JA4H, headers), bot/browser split, scoring signal prevalence, global summary (unique IPs/URLs). Metrics in the spirit of [Cloudflare Signals Intelligence](https://developers.cloudflare.com/bots/concepts/signals-intelligence/); optional significance filter (√N). Accounts for delivery channels (**docs/nginx.md**); unified interpretation behind proxy (signals.is_http2, fingerprint.tls). Details: **docs/METHODOLOGY.md**, Appendix J (Request log statistics and collection methodology).

  Run (from `tools/python` or repo root):

  ```bash
  poetry run python request_log_stats.py -n 20 "logs/**/requests_*.jsonl"
  poetry run python request_log_stats.py -n 10 -o report.txt --format text "logs/**/*.jsonl"
  poetry run python request_log_stats.py --format json -o stats.json "logs/**/requests_*.jsonl"
  ```

  Options: `-n` / `--top` — number of top values per field (default 15); `-o` — output file; `--format text|json`; `--sort count|discriminative`; `--exclude-stress-tests` — exclude go-http-client; `--no-significance-filter` — disable significance filter (√N). Record format: one JSON per line (`tests/testdata/reference_browser.json`).

- **request_log_stats_by_class.py** — same statistics as above but **by group**: **all** (optionally excluding stress tests), **bot**, **browser**. Input: one or more globs for **JSON** (single array of objects) or **JSONL** (one object per line). Output: file or stdout, text or JSON. Reuses aggregation and formatting from `request_log_stats.py`.

  ```bash
  poetry run python request_log_stats_by_class.py -n 15 "logs/**/requests_*.jsonl"
  poetry run python request_log_stats_by_class.py -o report.txt "logs/**/*.json" "logs/**/*.jsonl"
  poetry run python request_log_stats_by_class.py --format json -o stats.json "logs/requests.jsonl"
  poetry run python request_log_stats_by_class.py --exclude-stress-tests "logs/**/requests_*.jsonl"
  ```

  Options: same as `request_log_stats.py` plus `--no-progress`. Text output: three sections (ALL, BOT, BROWSER). JSON output: `{"all": {...}, "bot": {...}, "browser": {...}}`.

- **behavioral_bars.py** — splits values of four behavioural metrics (request_rate_per_min, inter_arrival_median_sec, inter_arrival_std_per_mean, inter_arrival_mean_median_ratio) from `request_metrics.ip_derived` into 99 percentile bars (p01–p99). For each bar it outputs: total row count, rows classified as browser, as bot, bot−browser, and (bot−browser)/(bot+browser). Optionally generates and saves charts per parameter with the current edge threshold marked (METHODOLOGY Appendix M).

  ```bash
  poetry run python behavioral_bars.py "logs/requests.jsonl"
  poetry run python behavioral_bars.py -o report.json --charts-dir ./charts "logs/**/*.jsonl"
  poetry run python behavioral_bars.py --p-from 5 --p-to 95 "logs/requests.jsonl"
  poetry run python behavioral_bars.py --req-per-min 2.0 --gap-median-sec 4.0 "logs/**/requests_*.jsonl"
  ```

  Options: `-o` — output JSON (default: stdout); `--charts-dir` — directory for PNG charts; `--p-from`, `--p-to` — percentile bar range, 1-based (default: 1 and 99, i.e. p01–p99); `--no-progress`; `--req-per-min`, `--gap-median-sec`, `--gap-std-mean`, `--gap-mean-median` — edge thresholds for display on charts.

## Dashboard payload (build_dashboard_payload.py)

The script is the recommended way to produce `dashboard.json` for the TS dashboard. Place the output in `tools/ts/dashboard/public/dashboard.json` for local dev, or serve it from the same origin (or set `VITE_DASHBOARD_JSON_URL` at build time). Cron example:

```bash
cd tools/python
poetry run python build_dashboard_payload.py -o /var/www/dashboard.json "logs/**/requests_*.jsonl"
```

## Dependencies

Managed via Poetry, see `pyproject.toml`. Main ones: `curl-cffi`, `pandas`, `numpy`, `matplotlib` (for behavioral_bars.py charts).

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

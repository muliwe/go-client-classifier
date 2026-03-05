# Bot Detector Dashboard

A terminal-style React dashboard that displays bot-detection metrics from a statically served JSON payload. It shows aggregate counts and shares (bot vs browser) over time windows (hour, day, week, month, all), a **timeline** with fixed 60 bars (granularity 10 s / 1 min / 10 min depending on data density), and **signal activation statistics** (transport + behavioural). The dashboard **auto-refreshes** at half the timeline bar length (e.g. every 5 s for 10 s bars). Table headers are **sortable** (click to sort).

## Requirements

- Node.js 18+
- npm

## Setup

From the repository root or this directory:

```bash
cd tools/ts/dashboard
npm install
```

## Scripts

| Command            | Description                                              |
| ------------------ | -------------------------------------------------------- |
| `npm run dev`      | Start the development server.                            |
| `npm run build`    | Type-check and build for production (output in `dist/`). |
| `npm run preview`  | Serve the production build locally.                      |
| `npm run lint`     | Run ESLint on the project.                               |
| `npm run lint:fix` | Run ESLint and apply auto-fixes where possible.          |
| `npm run prettier` | Format source and config files with Prettier (writes).   |

## Development

```bash
npm run dev
```

The app loads dashboard data from `/dashboard.json` by default (e.g. from `public/dashboard.json` during dev). After load it schedules the next fetch at half the timeline bar length (from `timeline_bucket_sec`); the header shows “Auto-refresh every X sec/min”.

## Build

```bash
npm run build
```

Output is written to `dist/`. Serve the contents with any static file server. The dashboard will request the JSON from `/dashboard.json` relative to the deployment origin unless overridden (see **Environment variables**).

At build time Vite loads `.env` and `.env.production` (in production mode) from this directory, so you can put `VITE_BASE` and `VITE_DASHBOARD_JSON_URL` in a file instead of the command line. Variables set in the shell still override file values.

## Environment variables

| Variable                  | Description                                                                                                                                                                                         |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VITE_BASE`               | Base public path when served in production. Use a subpath when the app is under a folder (e.g. `VITE_BASE=/dashboard/` or `https://example.com/dashboard/`). If unset, `/` is used. Read from `.env` / `.env.production` or set at build time. |
| `VITE_DASHBOARD_JSON_URL` | URL from which to fetch the dashboard JSON. If unset, the app uses `/dashboard.json`. Set at **build time** (in `.env.production` or e.g. `VITE_DASHBOARD_JSON_URL=https://example.com/dashboard/data.json npm run build`). |

## Dashboard JSON contract

The dashboard expects a single JSON object with the following shape.

- **`windows`** — Object with keys `hour`, `day`, `week`, `month`, `all`. Each value is an object:
  - `total` (number): total request count in that window
  - `bot` (number): count classified as bot
  - `browser` (number): count classified as browser
  - `bot_pct` (number, optional): percentage of requests classified as bot
  - `browser_pct` (number, optional): percentage of requests classified as browser

- **`timeline`** — Array of **exactly 60** points (fixed bar count). Granularity is chosen by the generator (e.g. 10 s → 10 min window, 1 min → 1 h, 10 min → 10 h). Each object:
  - `t` (number or string): bucket start (Unix seconds or ISO 8601)
  - `total` (number): request count in that bucket
  - `bot` (number): bot count
  - `browser` (number): browser count

- **`timeline_bucket_sec`** (number, optional): bucket size in seconds (e.g. 10, 60, 600). Used for the section title and auto-refresh interval (refresh every `bucket_sec / 2`).

- **`timeline_window_sec`** (number, optional): timeline window in seconds. Used for the section title (e.g. “last 10 minutes”, “last 1 hour, by minute”).

- **`signals`** — Array of signal statistics (transport + behavioural). Each object:
  - `signal_id` (string): identifier (e.g. from `config/scoring.json` or behavioural: `req_per_min`, `gap_median`, …)
  - `total` (number): number of requests where this signal fired
  - `bot` (number): bot count among those
  - `browser` (number): browser count among those
  - `bot_pct` (number): percentage bot
  - `browser_pct` (number): percentage browser

- **`behavioral_edges`** (optional) — Object with edge thresholds (e.g. `request_rate_per_min_above`, `inter_arrival_median_sec_below`, …). When present, the UI shows them in the behavioural edges block.

Example minimal structure:

```json
{
  "windows": {
    "hour": { "total": 100, "bot": 20, "browser": 80 },
    "day": { "total": 2000, "bot": 400, "browser": 1600 },
    "week": { "total": 14000, "bot": 2800, "browser": 11200 },
    "month": { "total": 60000, "bot": 12000, "browser": 48000 },
    "all": { "total": 60000, "bot": 12000, "browser": 48000 }
  },
  "timeline": [{ "t": 1700000000, "total": 5, "bot": 1, "browser": 4 }],
  "timeline_bucket_sec": 10,
  "timeline_window_sec": 600,
  "signals": [
    {
      "signal_id": "http2",
      "total": 5000,
      "bot": 200,
      "browser": 4800,
      "bot_pct": 4.0,
      "browser_pct": 96.0
    }
  ]
}
```

This JSON is intended to be produced by a generator such as **tools/python/build_dashboard_payload.py**, which reads JSONL request logs and outputs the payload (see Python tools README).

## UI behaviour

- **Timeline**: Bars are ordered **newest first** (most recent bucket at the top). Section title reflects window and granularity (e.g. “last 10 minutes, by 10 sec”). Empty buckets are drawn as a dark bar with no numbers.
- **Signals table**: Click a column header to sort. Default sort is `signal_id` ascending; other columns sort descending on first click; click again to toggle direction. Indicator ▲/▼ shows current column and direction.
- **Auto-refresh**: After each successful load, the next fetch is scheduled in `timeline_bucket_sec / 2` seconds (e.g. 5 s for 10 s bars, 30 min for 1 h bars). The header line shows “Auto-refresh every X sec/min”.

## Styling

The UI uses **terminal.css** for base terminal aesthetics and **JetBrains Mono** for typography. Bot-related values are in red and browser-related in green. Favicon is a terminal-style icon (dark window, green prompt). Layout uses CSS Grid and Flexbox; section borders use Unicode box-drawing characters where appropriate.

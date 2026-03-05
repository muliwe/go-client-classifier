"""
Build dashboard JSON payload from request log files.

Reads JSONL request logs (same format as request_log_stats.py: classification,
timestamp, signals.score_breakdown). Aggregates:
  - windows: hour, day, week, month, all — total/bot/browser and pcts
  - timeline: last N minutes, one point per second — t, total, bot, browser
  - signals: per-signal activation stats (signal_id, total, bot, browser, bot_pct, browser_pct)

Behavioral edges (req_per_min, gap_median, etc.) are read from config/scoring.json
(behavioral_edges) so they match production. Use --config to point to another file.

Output conforms to tools/ts/dashboard src/types/dashboard.ts DashboardData.

Usage:
  poetry run python build_dashboard_payload.py "logs/**/requests_*.jsonl"
  poetry run python build_dashboard_payload.py -o dashboard.json "logs/**/*.jsonl"
  poetry run python build_dashboard_payload.py --config ../../config/scoring.json "logs/**/requests_*.jsonl"
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tqdm import tqdm

from request_log_stats import (
    ALL_SCORING_SIGNAL_IDS,
    _count_lines_in_files,
    _parse_score_breakdown,
    iter_jsonl_files,
    read_jsonl_stream,
)
from request_log_stats_by_class import SIGNAL_NAMES as _BEHAVIORAL_SIGNAL_NAMES
from request_log_stats_by_class import _behavioural_signal_flags, _get_edges

# Display IDs for behavioural signals (prefixed for dashboard; same order as _BEHAVIORAL_SIGNAL_NAMES)
BEHAVIORAL_SIGNAL_IDS = tuple("behavioral_" + s for s in _BEHAVIORAL_SIGNAL_NAMES)

# Keys expected in config behavioral_edges (must match config/scoring.json and classifier)
BEHAVIORAL_EDGE_KEYS = (
    "request_rate_per_min_above",
    "inter_arrival_median_sec_below",
    "inter_arrival_std_per_mean_above",
    "inter_arrival_mean_median_ratio_above",
)

# Time window sizes in seconds
WINDOW_SEC: dict[str, int | float] = {
    "hour": 3600,
    "day": 86400,
    "week": 604800,
    "month": 30 * 86400,
    "all": float("inf"),
}
TIMELINE_DEFAULT_SEC = 600  # 10 minutes (baseline window)
# Fixed number of bars for all granularities: 10 min with 10 sec step = 60 bars
TIMELINE_BAR_COUNT = 60
# If median of (total = bot+browser) per bar is below this, cluster to next granularity (1min, then 10min).
TIMELINE_MEDIAN_TOTAL_THRESHOLD = 10
# Bucket sizes: 10s (baseline), 1min, 10min. Window = TIMELINE_BAR_COUNT * bucket_sec.
BUCKET_SEC_10SEC = 10
BUCKET_SEC_MINUTE = 60
BUCKET_SEC_10MIN = 600


def load_behavioral_edges_from_config(
    config_path: Path | None = None,
) -> dict[str, float]:
    """Load behavioral_edges from config/scoring.json (same as production). Tries config_path, then cwd/config/scoring.json, then repo_root/config/scoring.json. Falls back to _get_edges() if missing."""
    candidates: list[Path] = []
    if config_path is not None:
        candidates.append(config_path.resolve())
    candidates.append(Path.cwd() / "config" / "scoring.json")
    repo_root = Path(__file__).resolve().parent.parent
    candidates.append(repo_root / "config" / "scoring.json")
    for path in candidates:
        if not path.is_file():
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        be = data.get("behavioral_edges")
        if not isinstance(be, dict):
            continue
        if all(
            k in be and isinstance(be[k], (int, float)) for k in BEHAVIORAL_EDGE_KEYS
        ):
            return {k: float(be[k]) for k in BEHAVIORAL_EDGE_KEYS}
    print(
        "Warning: behavioral_edges not found in config, using script defaults.",
        file=sys.stderr,
    )
    return _get_edges()


def _parse_timestamp(ts: Any) -> float | None:
    """Parse timestamp to Unix seconds. Accepts ISO 8601 string or number."""
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        if ts > 1e12:  # milliseconds
            return float(ts) / 1000.0
        return float(ts)
    if isinstance(ts, str):
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except (ValueError, TypeError):
            return None
    return None


def extract_dashboard_record(
    rec: Any, edges: dict[str, float] | None = None
) -> dict[str, Any] | None:
    """Extract classification, timestamp (unix sec), score_signal_ids, behavioral_signal_ids. Skip if no timestamp or invalid classification. Uses edges for behavioural flags (defaults from _get_edges() if None)."""
    if not isinstance(rec, dict):
        return None
    classification = (rec.get("classification") or "").strip().lower()
    if classification not in ("bot", "browser"):
        return None
    ts = _parse_timestamp(rec.get("timestamp"))
    if ts is None:
        return None
    sig = rec.get("signals")
    if not isinstance(sig, dict):
        sig = {}
    breakdown = sig.get("score_breakdown") or ""
    score_signal_ids = _parse_score_breakdown(breakdown)
    # Behavioral signals from request_metrics.ip_derived (METHODOLOGY Appendix M), computed with current edges
    effective_edges = edges if edges is not None else _get_edges()
    flags = _behavioural_signal_flags(rec.get("request_metrics"), effective_edges)
    behavioral_signal_ids = {
        BEHAVIORAL_SIGNAL_IDS[i] for i in range(4) if flags[i]
    }  # behavioral_req_per_min, etc.
    return {
        "classification": classification,
        "ts": ts,
        "score_signal_ids": score_signal_ids,
        "behavioral_signal_ids": behavioral_signal_ids,
    }


def _count_window(
    records: list[dict[str, Any]], now: float, window_sec: int | float
) -> dict[str, Any]:
    """Aggregate total/bot/browser for records with ts >= now - window_sec."""
    if window_sec == float("inf"):
        subset = records
    else:
        cutoff = now - window_sec
        subset = [r for r in records if r["ts"] >= cutoff]
    total = len(subset)
    bot = sum(1 for r in subset if r["classification"] == "bot")
    browser = total - bot
    bot_pct = round(100.0 * bot / total, 1) if total else 0.0
    browser_pct = round(100.0 * browser / total, 1) if total else 0.0
    return {
        "total": total,
        "bot": bot,
        "browser": browser,
        "bot_pct": bot_pct,
        "browser_pct": browser_pct,
    }


def _aggregate_timeline_by_bucket(
    points: list[dict[str, Any]],
    bucket_sec: int,
) -> list[dict[str, Any]]:
    """Merge timeline points by time bucket; each output point has t = bucket start, total/bot/browser summed."""
    merged: dict[int, dict[str, Any]] = {}
    for p in points:
        t_sec = int(p["t"]) if isinstance(p["t"], (int, float)) else int(float(p["t"]))
        key = (t_sec // bucket_sec) * bucket_sec
        if key not in merged:
            merged[key] = {"t": key, "total": 0, "bot": 0, "browser": 0}
        merged[key]["total"] += p.get("total", 0)
        merged[key]["bot"] += p.get("bot", 0)
        merged[key]["browser"] += p.get("browser", 0)
    return sorted(merged.values(), key=lambda x: x["t"])


def _build_timeline_for_window(
    records: list[dict[str, Any]],
    now: float,
    bucket_sec: int,
    bar_count: int = TIMELINE_BAR_COUNT,
) -> list[dict[str, Any]]:
    """Build timeline with exactly bar_count bars; window_sec = bar_count * bucket_sec. Returns list of { t, total, bot, browser }."""
    window_sec = bar_count * bucket_sec
    cutoff = now - window_sec
    subset = [r for r in records if r["ts"] >= cutoff]
    buckets: dict[int, list[dict[str, Any]]] = {}
    for r in subset:
        s = int(r["ts"])
        key = (s // bucket_sec) * bucket_sec
        buckets.setdefault(key, []).append(r)
    start = (int(now) - window_sec) // bucket_sec * bucket_sec
    timeline: list[dict[str, Any]] = []
    for i in range(bar_count):
        t = start + i * bucket_sec
        group = buckets.get(t, [])
        total = len(group)
        bot = sum(1 for r in group if r["classification"] == "bot")
        browser = total - bot
        timeline.append({"t": t, "total": total, "bot": bot, "browser": browser})
    return timeline


def _median_total(timeline: list[dict[str, Any]]) -> float:
    """Median of total (bot+browser) over timeline points. Returns 0 if empty."""
    totals = [p["total"] for p in timeline]
    if not totals:
        return 0.0
    totals_sorted = sorted(totals)
    n = len(totals_sorted)
    mid = (n - 1) / 2
    lo, hi = int(mid), (n - 1) - int(mid)
    return (totals_sorted[lo] + totals_sorted[hi]) / 2.0


def _build_timeline(
    records: list[dict[str, Any]],
    now: float,
    last_sec: int,
) -> tuple[list[dict[str, Any]], int, int]:
    """Build timeline with fixed bar count (60). Baseline: 10 min, 10 sec step. If median total per bar < threshold, cluster to 1-min (1h window), then to 10-min (10h window). Returns (timeline, bucket_sec, window_sec)."""
    bucket_sec = BUCKET_SEC_10SEC
    timeline = _build_timeline_for_window(records, now, bucket_sec)
    window_sec = TIMELINE_BAR_COUNT * bucket_sec

    median = _median_total(timeline)
    if median < TIMELINE_MEDIAN_TOTAL_THRESHOLD:
        bucket_sec = BUCKET_SEC_MINUTE
        window_sec = TIMELINE_BAR_COUNT * bucket_sec
        timeline = _build_timeline_for_window(records, now, bucket_sec)
        median = _median_total(timeline)
        if median < TIMELINE_MEDIAN_TOTAL_THRESHOLD:
            bucket_sec = BUCKET_SEC_10MIN
            window_sec = TIMELINE_BAR_COUNT * bucket_sec
            timeline = _build_timeline_for_window(records, now, bucket_sec)

    return (timeline, bucket_sec, window_sec)


def _build_signals(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per-signal stats: transport (score_breakdown) + behavioral (request_metrics), same shape: total, bot, browser, bot_pct, browser_pct."""

    def count_for_signal(
        recs: list[dict[str, Any]],
        ids_key: str,
        signal_ids_iter: tuple[str, ...] | list[str],
    ) -> list[dict[str, Any]]:
        """For each signal_id in signal_ids_iter, count records where signal_id in record[ids_key]. Returns list of { signal_id, total, bot, browser, bot_pct, browser_pct }."""
        result_list: list[dict[str, Any]] = []
        for signal_id in signal_ids_iter:
            total_s = 0
            bot_s = 0
            browser_s = 0
            for r in recs:
                ids = r.get(ids_key)
                if ids is None:
                    ids = set()
                elif not isinstance(ids, set):
                    ids = set(ids) if ids else set()
                if signal_id not in ids:
                    continue
                total_s += 1
                if r.get("classification") == "bot":
                    bot_s += 1
                else:
                    browser_s += 1
            bot_pct = round(100.0 * bot_s / total_s, 1) if total_s else 0.0
            browser_pct = round(100.0 * browser_s / total_s, 1) if total_s else 0.0
            result_list.append(
                {
                    "signal_id": signal_id,
                    "total": total_s,
                    "bot": bot_s,
                    "browser": browser_s,
                    "bot_pct": bot_pct,
                    "browser_pct": browser_pct,
                }
            )
        return result_list

    # Transport-level signals (from score_breakdown)
    result = count_for_signal(records, "score_signal_ids", ALL_SCORING_SIGNAL_IDS)
    # Behavioral signals (from request_metrics.ip_derived, METHODOLOGY Appendix M)
    result += count_for_signal(records, "behavioral_signal_ids", BEHAVIORAL_SIGNAL_IDS)
    return result


def build_payload(
    records: list[dict[str, Any]],
    *,
    timeline_sec: int = TIMELINE_DEFAULT_SEC,
    behavioral_edges: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Build DashboardData-shaped payload from extracted records. If behavioral_edges is provided, include it for the dashboard UI."""
    edges = behavioral_edges if behavioral_edges is not None else _get_edges()
    if not records:
        now = 0.0
    else:
        now = max(r["ts"] for r in records)

    windows: dict[str, dict[str, Any]] = {}
    for key, sec in WINDOW_SEC.items():
        windows[key] = _count_window(records, now, sec)

    if records:
        timeline, timeline_bucket_sec, timeline_window_sec = _build_timeline(
            records, now, timeline_sec
        )
    else:
        timeline = []
        timeline_bucket_sec = BUCKET_SEC_10SEC
        timeline_window_sec = TIMELINE_BAR_COUNT * timeline_bucket_sec

    signals = _build_signals(records)

    out: dict[str, Any] = {
        "windows": windows,
        "timeline": timeline,
        "timeline_bucket_sec": timeline_bucket_sec,
        "timeline_window_sec": timeline_window_sec,
        "signals": signals,
    }
    out["behavioral_edges"] = edges
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build dashboard JSON payload from request log files (JSONL by glob).",
    )
    parser.add_argument(
        "globs",
        nargs="+",
        help="Glob mask(s) for JSONL files, e.g. logs/**/requests_*.jsonl",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--timeline-minutes",
        type=int,
        default=TIMELINE_DEFAULT_SEC // 60,
        metavar="N",
        help="Timeline length in minutes (default: 10)",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show progress bar on stderr (default: simple log messages)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to scoring.json (default: config/scoring.json from cwd or repo root). Behavioral edges are read from here to match production.",
    )
    args = parser.parse_args()

    edges = load_behavioral_edges_from_config(args.config)

    file_paths = iter_jsonl_files(args.globs)
    if file_paths is None:
        print("Use file glob(s), not stdin.", file=sys.stderr)
        return 1
    if not file_paths:
        print("No files matched the given glob(s).", file=sys.stderr)
        return 1

    use_pbar = args.progress
    pbar: tqdm | None = None
    if use_pbar:
        total_lines = _count_lines_in_files(file_paths)
        pbar = tqdm(
            total=total_lines,
            unit=" lines",
            desc="Reading",
            file=sys.stderr,
            mininterval=0.5,
        )
    else:
        n_files = len(file_paths)
        print(f"Reading {n_files} file(s)...", file=sys.stderr)

    def on_progress(delta: int, _path: Path | None) -> None:
        if pbar is not None:
            pbar.update(delta)

    records: list[dict[str, Any]] = []
    skipped = 0
    no_ts = 0
    for rec, _ in read_jsonl_stream(
        file_paths, progress_callback=on_progress if pbar else None
    ):
        if rec is None:
            break
        row = extract_dashboard_record(rec, edges)
        if row is not None:
            records.append(row)
        else:
            if (rec.get("classification") or "").strip().lower() in ("bot", "browser"):
                no_ts += 1
            else:
                skipped += 1

    if pbar is not None:
        pbar.close()
    elif not use_pbar:
        print(f"Read {len(records)} records.", file=sys.stderr)

    if no_ts:
        print(
            f"Warning: {no_ts} record(s) with valid classification had no timestamp and were skipped.",
            file=sys.stderr,
        )
    if skipped:
        print(
            f"Warning: {skipped} record(s) with classification not bot/browser were skipped.",
            file=sys.stderr,
        )

    timeline_sec = args.timeline_minutes * 60
    payload = build_payload(records, timeline_sec=timeline_sec, behavioral_edges=edges)
    text = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

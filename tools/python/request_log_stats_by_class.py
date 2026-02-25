"""
Request metrics (IP only) by cohort: all / bot / browser.

Reads request logs from JSON or JSONL. Outputs three cohorts (all, bot, browser;
optionally exclude stress tests from "all") and for each the distribution of
request_metrics from logs: ip_request_count, ip_derived.* (min/max/mean/median/p50/p95).
Nonce is not used.

Usage:
  poetry run python request_log_stats_by_class.py "../../logs/requests.jsonl"
  poetry run python request_log_stats_by_class.py --format json -o stats.json "../../logs/**/*.jsonl"
  poetry run python request_log_stats_by_class.py --exclude-stress-tests "../../logs/**/requests_*.jsonl"
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path
from typing import Any, Iterator

from tqdm import tqdm

from request_log_stats import aggregate, extract_record


def iter_files_by_globs(globs: list[str]) -> list[Path]:
    """Expand globs to sorted list of existing files."""
    seen: set[Path] = set()
    for g in globs:
        for p in glob.glob(g):
            path = Path(p).resolve()
            if path.is_file():
                seen.add(path)
    return sorted(seen)


def load_records_from_file(path: Path) -> Iterator[dict[str, Any]]:
    """Yield parsed JSON objects from a file. Supports JSON array or JSONL (one object per line)."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first_ch = f.read(1)
        f.seek(0)
        if first_ch == "[":
            data = json.load(f)
            if isinstance(data, list):
                for obj in data:
                    yield obj
            else:
                yield data
        else:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue


def load_all_records(
    file_paths: list[Path],
    progress: bool = True,
) -> list[dict[str, Any]]:
    """Load and extract valid records from all files. Returns list of extracted records (same format as request_log_stats)."""
    records: list[dict[str, Any]] = []
    skipped_invalid = 0
    skipped_class = 0
    iterator = file_paths
    if progress:
        iterator = tqdm(file_paths, desc="Files", unit=" file", file=sys.stderr, mininterval=0.5)
    for path in iterator:
        for rec in load_records_from_file(path):
            extracted = extract_record(rec)
            if extracted is not None:
                records.append(extracted)
            else:
                skipped_class += 1
    if skipped_class:
        print(f"Warning: skipped {skipped_class} record(s) with classification not bot/browser.", file=sys.stderr)
    return records


STRESS_PATHS = ("/", "/health", "/debug")


def _format_ip_metrics_text(im: dict[str, Any] | None) -> str:
    """Format ip_metrics_stats as short text (only distributions)."""
    if not im:
        return "  Records with request_metrics: 0"
    lines = [f"  Records with request_metrics: {im.get('records_with_ip_metrics', 0)}"]
    for key, val in im.items():
        if key == "records_with_ip_metrics" or not isinstance(val, dict):
            continue
        lines.append(
            f"  {key}: min={val.get('min')} max={val.get('max')} mean={val.get('mean')} "
            f"median={val.get('median')} p05={val.get('p05')} p50={val.get('p50')} p95={val.get('p95')}"
        )
    return "\n".join(lines) if len(lines) > 1 else lines[0]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request metrics (IP only) by cohort: all, bot, browser. Output: distributions only."
    )
    parser.add_argument(
        "globs",
        nargs="+",
        help="Glob mask(s) for JSON or JSONL files",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format: text or json (default: text)",
    )
    parser.add_argument(
        "--exclude-stress-tests",
        action="store_true",
        help="Exclude go-http-client requests only for paths /, /health, /debug (stress-test traffic) from 'all' group",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar on stderr",
    )
    args = parser.parse_args()

    file_paths = iter_files_by_globs(args.globs)
    if not file_paths:
        print("No files matched the given glob(s).", file=sys.stderr)
        return 1

    records = load_all_records(file_paths, progress=not args.no_progress)

    if args.exclude_stress_tests:
        before = len(records)
        records_all = [
            r
            for r in records
            if not (r.get("user_agent") == "go-http-client" and r.get("path") in STRESS_PATHS)
        ]
        excluded = before - len(records_all)
        if excluded:
            print(
                f"Excluded {excluded} go-http-client record(s) for {', '.join(STRESS_PATHS)} (stress tests) from 'all'.",
                file=sys.stderr,
            )
    else:
        records_all = list(records)

    records_bot = [r for r in records_all if r.get("classification") == "bot"]
    records_browser = [r for r in records_all if r.get("classification") == "browser"]

    stats_all = aggregate(records_all, sort_by="count", filter_significance=True)
    stats_bot = aggregate(records_bot, sort_by="count", filter_significance=True)
    stats_browser = aggregate(records_browser, sort_by="count", filter_significance=True)

    if args.format == "text":
        lines = []
        for label, stats in [
            ("ALL" + (" (excluding stress tests)" if args.exclude_stress_tests else ""), stats_all),
            ("BOT", stats_bot),
            ("BROWSER", stats_browser),
        ]:
            lines.append(f"=== {label} ===")
            lines.append(f"  total: {stats['summary']['total']}")
            lines.append(_format_ip_metrics_text(stats.get("ip_metrics_stats")))
            lines.append("")
        text = "\n".join(lines).rstrip()
    else:
        out = {
            "all": {"total": stats_all["summary"]["total"], "ip_metrics_stats": stats_all.get("ip_metrics_stats")},
            "bot": {"total": stats_bot["summary"]["total"], "ip_metrics_stats": stats_bot.get("ip_metrics_stats")},
            "browser": {"total": stats_browser["summary"]["total"], "ip_metrics_stats": stats_browser.get("ip_metrics_stats")},
        }
        text = json.dumps(out, indent=2, ensure_ascii=False)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

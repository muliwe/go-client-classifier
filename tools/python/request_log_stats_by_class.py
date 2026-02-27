"""
Request metrics (IP only) by cohort: all / bot / browser.

Reads request logs from JSON or JSONL. Outputs three cohorts (all, bot, browser;
optionally exclude stress tests from "all") and for each the distribution of
request_metrics from logs: ip_request_count, ip_derived.* (min/max/mean/median/p05/p20/p50/p80/p95).
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
import math
import sys
from pathlib import Path
from typing import Any, Iterator

from tqdm import tqdm


def extract_record(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Extract classification, path, user_agent and request_metrics from one log record. Standalone extractor."""
    classification = (rec.get("classification") or "").strip().lower()
    if classification not in ("bot", "browser"):
        return None
    http = (rec.get("fingerprint") or {}).get("http") or {}
    path = (http.get("path") or "").strip() or "/"
    user_agent = (http.get("user_agent") or "").strip()
    request_metrics = rec.get("request_metrics")
    return {
        "classification": classification,
        "path": path,
        "user_agent": user_agent,
        "request_metrics": request_metrics,
    }


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
    """Load and extract valid records from all files. Uses local extract_record."""
    records: list[dict[str, Any]] = []
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


def _percentile(sorted_values: list[float], p: float) -> float | None:
    """Return percentile p (0..100) of sorted_values, or None if empty."""
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * p / 100.0
    lo = int(math.floor(k))
    hi = int(math.ceil(k))
    if lo == hi:
        return sorted_values[lo]
    return sorted_values[lo] * (1 - (k - lo)) + sorted_values[hi] * (k - lo)


def _has_any_ip_metric(rm: dict[str, Any]) -> bool:
    """True if request_metrics has at least one numeric metric (ip_request_count or any value in ip_derived)."""
    if "ip_request_count" in rm and isinstance(rm.get("ip_request_count"), (int, float)):
        return True
    ipd = rm.get("ip_derived")
    if isinstance(ipd, dict):
        for v in ipd.values():
            if isinstance(v, (int, float)):
                return True
    return False


def compute_ip_metrics_stats(
    records: list[dict[str, Any]],
    *,
    debug_reject: bool = False,
) -> dict[str, Any] | None:
    """Build ip_metrics_stats from records that have request_metrics with at least one ip metric."""
    values_by_key: dict[str, list[float]] = {}
    n_with_metrics = 0
    for i, r in enumerate(records):
        rm = r.get("request_metrics")
        if not rm or not isinstance(rm, dict):
            if debug_reject and r.get("request_metrics") is not None:
                print(
                    f"[debug] record {i}: request_metrics is not a dict: {type(rm).__name__!r}",
                    file=sys.stderr,
                )
            continue
        if not _has_any_ip_metric(rm):
            if debug_reject:
                ip_count = rm.get("ip_request_count")
                ipd = rm.get("ip_derived")
                print(
                    f"[debug] record {i}: rejected (no numeric ip metric). "
                    f"ip_request_count={ip_count!r} (type={type(ip_count).__name__}), "
                    f"ip_derived={ipd!r} (type={type(ipd).__name__}); "
                    f"ip_derived values types={[type(v).__name__ for v in (ipd or {}).values()]!r}",
                    file=sys.stderr,
                )
            continue
        n_with_metrics += 1
        if "ip_request_count" in rm and isinstance(rm["ip_request_count"], (int, float)):
            values_by_key.setdefault("ip_request_count", []).append(float(rm["ip_request_count"]))
        ipd = rm.get("ip_derived")
        if isinstance(ipd, dict):
            for k, v in ipd.items():
                if isinstance(v, (int, float)):
                    values_by_key.setdefault(k, []).append(float(v))
            # Derived: inter_arrival_std_sec / inter_arrival_mean_sec (per record)
            std_s = ipd.get("inter_arrival_std_sec")
            mean_s = ipd.get("inter_arrival_mean_sec")
            if (
                isinstance(std_s, (int, float))
                and isinstance(mean_s, (int, float))
                and float(mean_s) != 0
            ):
                values_by_key.setdefault("inter_arrival_std_per_mean", []).append(
                    float(std_s) / float(mean_s)
                )
    if n_with_metrics == 0:
        return None
    out: dict[str, Any] = {"records_with_ip_metrics": n_with_metrics}
    for key, vals in values_by_key.items():
        if not vals:
            continue
        sorted_vals = sorted(vals)
        n = len(sorted_vals)
        out[key] = {
            "min": round(min(vals), 3),
            "max": round(max(vals), 3),
            "mean": round(sum(vals) / n, 3),
            "median": round(_percentile(sorted_vals, 50) or 0, 3),
            "p05": round(_percentile(sorted_vals, 5) or 0, 3),
            "p20": round(_percentile(sorted_vals, 20) or 0, 3),
            "p50": round(_percentile(sorted_vals, 50) or 0, 3),
            "p80": round(_percentile(sorted_vals, 80) or 0, 3),
            "p95": round(_percentile(sorted_vals, 95) or 0, 3),
        }
    return out


STRESS_PATHS = ("/", "/health", "/debug")

# Behavioural edge thresholds (METHODOLOGY Appendix M; configurable in classifier).
# Default behavioural edges (METHODOLOGY Appendix M). Overridable via CLI (--req-per-min, --gap-*, etc.).
# Must match config/scoring.json behavioral_edges and classifier bot_scores (2 pts each).
EDGE_REQUEST_RATE_PER_MIN = 2.0
EDGE_INTER_ARRIVAL_MEDIAN_SEC = 4.0
EDGE_INTER_ARRIVAL_STD_PER_MEAN = 1.35
EDGE_MEAN_MEDIAN_RATIO = 1.2


def _get_edges(
    edge_rate: float | None = None,
    edge_median_sec: float | None = None,
    edge_std_per_mean: float | None = None,
    edge_ratio: float | None = None,
) -> dict[str, float]:
    """Return effective edge values (CLI overrides or module defaults)."""
    return {
        "request_rate_per_min_above": edge_rate if edge_rate is not None else EDGE_REQUEST_RATE_PER_MIN,
        "inter_arrival_median_sec_below": edge_median_sec if edge_median_sec is not None else EDGE_INTER_ARRIVAL_MEDIAN_SEC,
        "inter_arrival_std_per_mean_above": edge_std_per_mean if edge_std_per_mean is not None else EDGE_INTER_ARRIVAL_STD_PER_MEAN,
        "inter_arrival_mean_median_ratio_above": edge_ratio if edge_ratio is not None else EDGE_MEAN_MEDIAN_RATIO,
    }


def _behavioural_signal_flags(
    rm: dict[str, Any] | None,
    edges: dict[str, float] | None = None,
) -> tuple[bool, bool, bool, bool]:
    """
    Return (req_per_min, gap_median, gap_std_mean, gap_mean_median) for this record.
    Uses ip_derived only. Inter-arrival flags require at least two requests in the window.
    """
    if not rm or not isinstance(rm, dict):
        return (False, False, False, False)
    ipd = rm.get("ip_derived")
    if not isinstance(ipd, dict):
        return (False, False, False, False)
    e = edges or _get_edges()
    rate = ipd.get("request_rate_per_min")
    flag_rate = isinstance(rate, (int, float)) and float(rate) > e["request_rate_per_min_above"]
    median_s = ipd.get("inter_arrival_median_sec")
    mean_s = ipd.get("inter_arrival_mean_sec")
    has_inter_arrival = (
        isinstance(median_s, (int, float))
        and isinstance(mean_s, (int, float))
    )
    flag_median = bool(
        has_inter_arrival and isinstance(median_s, (int, float)) and float(median_s) < e["inter_arrival_median_sec_below"]
    )
    std_per_mean = ipd.get("inter_arrival_std_per_mean")
    if has_inter_arrival and std_per_mean is None and isinstance(mean_s, (int, float)) and float(mean_s) != 0:
        std_s = ipd.get("inter_arrival_std_sec")
        if isinstance(std_s, (int, float)):
            std_per_mean = float(std_s) / float(mean_s)
    flag_std_mean = bool(
        has_inter_arrival and isinstance(std_per_mean, (int, float)) and float(std_per_mean) > e["inter_arrival_std_per_mean_above"]
    )
    flag_ratio = False
    if (
        has_inter_arrival
        and isinstance(median_s, (int, float))
        and isinstance(mean_s, (int, float))
        and float(median_s) > 0
    ):
        ratio = float(mean_s) / float(median_s)
        flag_ratio = ratio > e["inter_arrival_mean_median_ratio_above"]
    return (flag_rate, flag_median, flag_std_mean, flag_ratio)


def _count_behavioural_signals(
    rm: dict[str, Any] | None,
    edges: dict[str, float] | None = None,
) -> int:
    """Return number of behavioural-edge signals (0–4) for this record."""
    return sum(_behavioural_signal_flags(rm, edges))


def compute_behavioral_edges_stats(
    records: list[dict[str, Any]],
    cohort: str,
    edges: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    For records with request_metrics, count how many have 0, 1, 2, 3, 4 behavioural signals
    and how many triggered each of the four criteria (req_per_min, gap_median, gap_std_mean, gap_mean_median).
    """
    count_by_signals: dict[int, int] = {0: 0, 1: 0, 2: 0, 3: 0, 4: 0}
    count_per_signal: dict[str, int] = {"req_per_min": 0, "gap_median": 0, "gap_std_mean": 0, "gap_mean_median": 0}
    for r in records:
        rm = r.get("request_metrics")
        flags = _behavioural_signal_flags(rm, edges)
        n = sum(flags)
        count_by_signals[n] = count_by_signals.get(n, 0) + 1
        if flags[0]:
            count_per_signal["req_per_min"] += 1
        if flags[1]:
            count_per_signal["gap_median"] += 1
        if flags[2]:
            count_per_signal["gap_std_mean"] += 1
        if flags[3]:
            count_per_signal["gap_mean_median"] += 1
    n_total = len(records)
    n_with_at_least_one = sum(count_by_signals.get(k, 0) for k in range(1, 5))
    pct = round(100.0 * n_with_at_least_one / n_total, 2) if n_total else 0.0
    out: dict[str, Any] = {
        "count_by_signals": count_by_signals,
        "count_per_signal": count_per_signal,
        "n_total": n_total,
    }
    if cohort == "bot":
        out["recall_pct"] = pct
    elif cohort == "browser":
        out["fp_rate_pct"] = pct
    return out


def compute_mean_median_ratio_stats(
    records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Compute distribution of mean/median inter-arrival ratio per cohort (median vs mean comparison)."""
    ratios: list[float] = []
    for r in records:
        rm = r.get("request_metrics")
        if not rm or not isinstance(rm, dict):
            continue
        ipd = rm.get("ip_derived")
        if not isinstance(ipd, dict):
            continue
        median_s = ipd.get("inter_arrival_median_sec")
        mean_s = ipd.get("inter_arrival_mean_sec")
        if (
            isinstance(median_s, (int, float))
            and isinstance(mean_s, (int, float))
            and float(median_s) > 0
        ):
            ratios.append(float(mean_s) / float(median_s))
    if not ratios:
        return None
    sorted_ratios = sorted(ratios)
    return {
        "min": round(min(ratios), 3),
        "max": round(max(ratios), 3),
        "mean": round(sum(ratios) / len(ratios), 3),
        "median": round(_percentile(sorted_ratios, 50) or 0, 3),
        "p05": round(_percentile(sorted_ratios, 5) or 0, 3),
        "p20": round(_percentile(sorted_ratios, 20) or 0, 3),
        "p50": round(_percentile(sorted_ratios, 50) or 0, 3),
        "p80": round(_percentile(sorted_ratios, 80) or 0, 3),
        "p95": round(_percentile(sorted_ratios, 95) or 0, 3),
        "n": len(ratios),
    }


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
            f"median={val.get('median')} p05={val.get('p05')} p20={val.get('p20')} p50={val.get('p50')} p80={val.get('p80')} p95={val.get('p95')}"
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
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print to stderr request_metrics that are rejected (no numeric ip metric)",
    )
    parser.add_argument("--req-per-min", type=float, default=None, metavar="N",
        help="Requests per minute threshold (signal if >). Default: %.1f" % EDGE_REQUEST_RATE_PER_MIN)
    parser.add_argument("--gap-median-sec", type=float, default=None, metavar="N",
        help="Gap between requests, median (sec); signal if <. Default: %.1f" % EDGE_INTER_ARRIVAL_MEDIAN_SEC)
    parser.add_argument("--gap-std-mean", type=float, default=None, metavar="N",
        help="Gap between requests, std/mean; signal if >. Default: %.2f" % EDGE_INTER_ARRIVAL_STD_PER_MEAN)
    parser.add_argument("--gap-mean-median", type=float, default=None, metavar="N",
        help="Gap between requests, mean/median; signal if >. Default: %.2f" % EDGE_MEAN_MEDIAN_RATIO)
    args = parser.parse_args()

    edges = _get_edges(
        edge_rate=args.req_per_min,
        edge_median_sec=args.gap_median_sec,
        edge_std_per_mean=args.gap_std_mean,
        edge_ratio=args.gap_mean_median,
    )
    print(
        "Behavioral edges: request_rate_per_min_above=%.2f inter_arrival_median_sec_below=%.2f "
        "inter_arrival_std_per_mean_above=%.2f inter_arrival_mean_median_ratio_above=%.2f" % (
            edges["request_rate_per_min_above"],
            edges["inter_arrival_median_sec_below"],
            edges["inter_arrival_std_per_mean_above"],
            edges["inter_arrival_mean_median_ratio_above"],
        ),
        file=sys.stderr,
    )

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
            if not (
                "go-http-client" in (r.get("user_agent") or "").lower()
                and r.get("path") in STRESS_PATHS
            )
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

    debug_reject = args.debug
    stats_all = {"total": len(records_all), "ip_metrics_stats": compute_ip_metrics_stats(records_all, debug_reject=debug_reject)}
    if debug_reject:
        print("[debug] --- ALL cohort done ---", file=sys.stderr)
    stats_bot = {"total": len(records_bot), "ip_metrics_stats": compute_ip_metrics_stats(records_bot, debug_reject=debug_reject)}
    if debug_reject:
        print("[debug] --- BOT cohort done ---", file=sys.stderr)
    stats_browser = {"total": len(records_browser), "ip_metrics_stats": compute_ip_metrics_stats(records_browser, debug_reject=debug_reject)}

    # Behavioural-edge recall/FPR (METHODOLOGY Appendix M).
    behavioral_bot = compute_behavioral_edges_stats(records_bot, cohort="bot", edges=edges)
    behavioral_browser = compute_behavioral_edges_stats(records_browser, cohort="browser", edges=edges)
    mean_median_bot = compute_mean_median_ratio_stats(records_bot)
    mean_median_browser = compute_mean_median_ratio_stats(records_browser)

    if args.format == "text":
        lines = []
        for label, stats in [
            ("ALL" + (" (excluding stress tests)" if args.exclude_stress_tests else ""), stats_all),
            ("BOT", stats_bot),
            ("BROWSER", stats_browser),
        ]:
            lines.append(f"=== {label} ===")
            lines.append(f"  total: {stats['total']}")
            lines.append(_format_ip_metrics_text(stats.get("ip_metrics_stats")))
            lines.append("")
        # Behavioural edges (BOT and BROWSER).
        lines.append("=== Behavioural edges (bot) ===")
        lines.append(f"  count_by_signals: {behavioral_bot['count_by_signals']}")
        lines.append(f"  count_per_signal: {behavioral_bot['count_per_signal']}")
        lines.append(f"  bot recall (% with >=1 signal): {behavioral_bot.get('recall_pct', 'N/A')}%")
        if mean_median_bot:
            lines.append(f"  mean/median ratio: min={mean_median_bot['min']} max={mean_median_bot['max']} mean={mean_median_bot['mean']} median={mean_median_bot['median']} p05={mean_median_bot['p05']} p20={mean_median_bot['p20']} p50={mean_median_bot['p50']} p80={mean_median_bot['p80']} p95={mean_median_bot['p95']} n={mean_median_bot['n']}")
        lines.append("")
        lines.append("=== Behavioural edges (browser) ===")
        lines.append(f"  count_by_signals: {behavioral_browser['count_by_signals']}")
        lines.append(f"  count_per_signal: {behavioral_browser['count_per_signal']}")
        lines.append(f"  browser FP rate (% with >=1 signal): {behavioral_browser.get('fp_rate_pct', 'N/A')}%")
        if mean_median_browser:
            lines.append(f"  mean/median ratio: min={mean_median_browser['min']} max={mean_median_browser['max']} mean={mean_median_browser['mean']} median={mean_median_browser['median']} p05={mean_median_browser['p05']} p20={mean_median_browser['p20']} p50={mean_median_browser['p50']} p80={mean_median_browser['p80']} p95={mean_median_browser['p95']} n={mean_median_browser['n']}")
        text = "\n".join(lines).rstrip()
    else:
        out = {
            "all": {"total": stats_all["total"], "ip_metrics_stats": stats_all.get("ip_metrics_stats")},
            "bot": {
                "total": stats_bot["total"],
                "ip_metrics_stats": stats_bot.get("ip_metrics_stats"),
                "behavioral_edges": behavioral_bot,
                "mean_median_ratio": mean_median_bot,
            },
            "browser": {
                "total": stats_browser["total"],
                "ip_metrics_stats": stats_browser.get("ip_metrics_stats"),
                "behavioral_edges": behavioral_browser,
                "mean_median_ratio": mean_median_browser,
            },
        }
        text = json.dumps(out, indent=2, ensure_ascii=False)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

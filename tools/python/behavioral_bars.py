"""
Behavioral metrics bar analysis: p01–p99 bins per parameter.

Reads request logs (JSON/JSONL), extracts four behavioral metrics from
request_metrics.ip_derived, splits values into 99 percentile bars (p01–p99),
and for each bar outputs: total rows, browser count, bot count, bot−browser,
(bot−browser)/(bot+browser). Generates charts per parameter with current
edge value marked. Aligns with request_log_stats_by_class.py (METHODOLOGY Appendix M).

Usage:
  poetry run python behavioral_bars.py "logs/requests.jsonl"
  poetry run python behavioral_bars.py -o report.json --charts-dir ./charts "logs/**/*.jsonl"
  poetry run python behavioral_bars.py --req-per-min 2.0 --gap-median-sec 4.0 "logs/**/requests_*.jsonl"
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Any

# Reuse loading and extraction from request_log_stats_by_class
from request_log_stats_by_class import (
    EDGE_INTER_ARRIVAL_MEDIAN_SEC,
    EDGE_INTER_ARRIVAL_STD_PER_MEAN,
    EDGE_MEAN_MEDIAN_RATIO,
    EDGE_REQUEST_RATE_PER_MIN,
    _percentile,
    iter_files_by_globs,
    load_all_records,
)

# Four behavioral parameters: key in ip_derived or derived formula
PARAM_KEYS = (
    "request_rate_per_min",
    "inter_arrival_median_sec",
    "inter_arrival_std_per_mean",
    "inter_arrival_mean_median_ratio",
)

# Edge thresholds (signal direction: above = bot signal if value > edge; below = bot signal if value < edge)
EDGES: dict[str, tuple[float, str]] = {
    "request_rate_per_min": (EDGE_REQUEST_RATE_PER_MIN, "above"),
    "inter_arrival_median_sec": (EDGE_INTER_ARRIVAL_MEDIAN_SEC, "below"),
    "inter_arrival_std_per_mean": (EDGE_INTER_ARRIVAL_STD_PER_MEAN, "above"),
    "inter_arrival_mean_median_ratio": (EDGE_MEAN_MEDIAN_RATIO, "above"),
}

NUM_PERCENTILE_BARS = 99


def get_metric_value(record: dict[str, Any], param: str) -> float | None:
    """Extract the numeric value for one behavioral parameter from record.request_metrics."""
    rm = record.get("request_metrics")
    if not rm or not isinstance(rm, dict):
        return None
    ipd = rm.get("ip_derived")
    if not isinstance(ipd, dict):
        return None

    if param == "request_rate_per_min":
        v = ipd.get("request_rate_per_min")
        return float(v) if isinstance(v, (int, float)) else None
    if param == "inter_arrival_median_sec":
        v = ipd.get("inter_arrival_median_sec")
        return float(v) if isinstance(v, (int, float)) else None
    if param == "inter_arrival_std_per_mean":
        v = ipd.get("inter_arrival_std_per_mean")
        if isinstance(v, (int, float)):
            return float(v)
        std_s = ipd.get("inter_arrival_std_sec")
        mean_s = ipd.get("inter_arrival_mean_sec")
        if (
            isinstance(std_s, (int, float))
            and isinstance(mean_s, (int, float))
            and float(mean_s) != 0
        ):
            return float(std_s) / float(mean_s)
        return None
    if param == "inter_arrival_mean_median_ratio":
        median_s = ipd.get("inter_arrival_median_sec")
        mean_s = ipd.get("inter_arrival_mean_sec")
        if (
            isinstance(median_s, (int, float))
            and isinstance(mean_s, (int, float))
            and float(median_s) > 0
        ):
            return float(mean_s) / float(median_s)
        return None
    return None


def compute_bars(
    records: list[dict[str, Any]],
    param: str,
    p_from: int = 1,
    p_to: int = 99,
) -> tuple[list[dict[str, Any]], list[float], float | None, int, int]:
    """
    Build percentile bars for one parameter.
    Always uses 99 percentile bins (p01–p99); returns bars from percentile p_from to p_to (1-based).
    Returns (list of bar stats, bin_edges for plotting, edge value or None, bar_offset, num_bars_displayed).
    """
    values: list[tuple[float, str]] = []  # (value, classification)
    for r in records:
        v = get_metric_value(r, param)
        if v is not None and math.isfinite(v):
            values.append((v, r.get("classification", "")))
    if not values:
        return [], [], EDGES.get(param, (None, ""))[0] if param in EDGES else None, 0, 0

    sorted_vals = sorted(v[0] for v in values)
    # Percentiles 0, 1, ..., 99 -> 100 edges, 99 bars
    bin_edges: list[float] = []
    for p in range(100):
        q = _percentile(sorted_vals, p)
        bin_edges.append(q if q is not None else sorted_vals[0])
    edge_val, _ = EDGES.get(param, (None, ""))

    # Assign each (value, classification) to one of 99 bars (0..98)
    n_total_bars = NUM_PERCENTILE_BARS
    bars_full: list[dict[str, int]] = [
        {"total": 0, "browser": 0, "bot": 0} for _ in range(n_total_bars)
    ]
    for val, cl in values:
        i = 0
        while i < n_total_bars - 1 and val > bin_edges[i + 1]:
            i += 1
        if i >= n_total_bars:
            i = n_total_bars - 1
        bars_full[i]["total"] += 1
        if cl == "browser":
            bars_full[i]["browser"] += 1
        elif cl == "bot":
            bars_full[i]["bot"] += 1

    # Slice to percentile range [p_from, p_to] (1-based); bar i corresponds to (p_{i+1}, p_{i+2}]
    start = max(0, p_from - 1)
    end = min(n_total_bars, p_to)
    bars_full = bars_full[start:end]
    bar_offset = start

    out: list[dict[str, Any]] = []
    for i, b in enumerate(bars_full):
        total = b["total"]
        if total == 0:
            continue
        idx = bar_offset + i
        bot = b["bot"]
        browser = b["browser"]
        bot_minus_browser = bot - browser
        sum_bot_browser = bot + browser
        ratio = (bot_minus_browser / sum_bot_browser) if sum_bot_browser else 0.0
        p_lo_val = bin_edges[idx]
        p_hi_val = bin_edges[idx + 1]
        out.append(
            {
                "bar": len(out) + 1,
                "p_lo": p_lo_val,
                "p_hi": p_hi_val,
                "value": p_hi_val,
                "total": total,
                "browser": browser,
                "bot": bot,
                "bot_minus_browser": bot_minus_browser,
                "bot_minus_browser_over_sum": round(ratio, 4),
            }
        )
    return out, bin_edges, edge_val, bar_offset, len(out)


def build_all_bars(
    records: list[dict[str, Any]],
    p_from: int = 1,
    p_to: int = 99,
) -> dict[str, Any]:
    """Compute bars for all four parameters in percentile range [p_from, p_to]."""
    result: dict[str, Any] = {}
    for param in PARAM_KEYS:
        bars, edges, edge_val, bar_offset, n_displayed = compute_bars(
            records, param, p_from=p_from, p_to=p_to
        )
        result[param] = {
            "bars": bars,
            "bin_edges": edges,
            "edge_value": edge_val,
            "edge_direction": EDGES.get(param, (None, ""))[1],
            "bar_offset": bar_offset,
            "num_bars_displayed": n_displayed,
        }
    return result


def generate_charts(
    data: dict[str, Any],
    output_dir: Path,
) -> None:
    """Save one chart per parameter: bar metrics + vertical line at edge."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as e:
        print(f"Charts skipped: matplotlib not available ({e}).", file=sys.stderr)
        return

    output_dir.mkdir(parents=True, exist_ok=True)

    for param in PARAM_KEYS:
        block = data.get(param)
        if not block or not block.get("bars"):
            continue
        bars_list = block["bars"]
        block.get("bin_edges") or []
        edge_val = block.get("edge_value")

        # x-axis = metric values (center of each bar), width = interval length
        all_lo = [b["p_lo"] for b in bars_list]
        all_hi = [b["p_hi"] for b in bars_list]
        x_centers = [(b["p_lo"] + b["p_hi"]) / 2 for b in bars_list]
        x_range = (max(all_hi) - min(all_lo)) if bars_list else 1.0
        if x_range <= 0:
            x_range = 1.0
        widths = []
        for b in bars_list:
            w = b["p_hi"] - b["p_lo"]
            if w <= 0:
                w = x_range * 0.01
            widths.append(w)
        [b["total"] for b in bars_list]
        browser = [b["browser"] for b in bars_list]
        bot = [b["bot"] for b in bars_list]
        bot_minus_browser = [b["bot_minus_browser"] for b in bars_list]
        ratio = [b["bot_minus_browser_over_sum"] for b in bars_list]

        x_min = min(all_lo)
        x_max = max(all_hi)
        edge_val_x = edge_val

        fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
        fig.suptitle(f"Behavioral parameter: {param}\n(edge = {edge_val})", fontsize=11)

        for ax in axes:
            ax.set_xlim(x_min, x_max)

        ax1 = axes[0]
        ax1.bar(
            x_centers,
            browser,
            width=widths,
            align="center",
            label="browser",
            color="steelblue",
            alpha=0.8,
        )
        ax1.bar(
            x_centers,
            bot,
            width=widths,
            align="center",
            bottom=browser,
            label="bot",
            color="coral",
            alpha=0.8,
        )
        ax1.set_ylabel("count")
        ax1.legend(loc="upper right")
        ax1.set_title("Total / Browser / Bot per bar")
        if edge_val_x is not None:
            ax1.axvline(
                x=edge_val_x, color="red", linestyle="--", linewidth=1.5, label="edge"
            )

        ax2 = axes[1]
        ax2.bar(
            x_centers,
            bot_minus_browser,
            width=widths,
            align="center",
            color="purple",
            alpha=0.7,
        )
        ax2.axhline(y=0, color="gray", linestyle="-", linewidth=0.5)
        ax2.set_ylabel("bot − browser")
        ax2.set_title("Bot minus browser per bar")
        if edge_val_x is not None:
            ax2.axvline(x=edge_val_x, color="red", linestyle="--", linewidth=1.5)

        ax3 = axes[2]
        ax3.bar(
            x_centers, ratio, width=widths, align="center", color="green", alpha=0.6
        )
        ax3.axhline(y=0, color="gray", linestyle="-", linewidth=0.5)
        ax3.set_ylabel("(bot−browser)/(bot+browser)")
        ax3.set_xlabel(param)
        ax3.set_title("(Bot − browser) / (bot + browser) per bar")
        if edge_val_x is not None:
            ax3.axvline(x=edge_val_x, color="red", linestyle="--", linewidth=1.5)

        plt.tight_layout()
        out_path = output_dir / f"behavioral_bars_{param}.png"
        plt.savefig(out_path, dpi=120, bbox_inches="tight")
        plt.close()
        print(f"Saved: {out_path}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Behavioral metrics bar analysis (p01–p99) and charts with edge line."
    )
    parser.add_argument(
        "globs",
        nargs="+",
        help="Glob mask(s) for JSON or JSONL files",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output JSON file (default: stdout)",
    )
    parser.add_argument(
        "--charts-dir",
        type=Path,
        default=None,
        help="Directory to save PNG charts (one per parameter); omit to skip charts",
    )
    parser.add_argument(
        "--p-from",
        type=int,
        default=1,
        metavar="P",
        help="First percentile bar to include, 1-based (default: 1, i.e. p01)",
    )
    parser.add_argument(
        "--p-to",
        type=int,
        default=99,
        metavar="P",
        help="Last percentile bar to include, 1-based (default: 99, i.e. p99)",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bar",
    )
    parser.add_argument(
        "--req-per-min",
        type=float,
        default=None,
        metavar="V",
        help="Edge for request_rate_per_min (default: %.2f)"
        % EDGE_REQUEST_RATE_PER_MIN,
    )
    parser.add_argument(
        "--gap-median-sec",
        type=float,
        default=None,
        metavar="V",
        help="Edge for inter_arrival_median_sec (default: %.2f)"
        % EDGE_INTER_ARRIVAL_MEDIAN_SEC,
    )
    parser.add_argument(
        "--gap-std-mean",
        type=float,
        default=None,
        metavar="V",
        help="Edge for inter_arrival_std_per_mean (default: %.2f)"
        % EDGE_INTER_ARRIVAL_STD_PER_MEAN,
    )
    parser.add_argument(
        "--gap-mean-median",
        type=float,
        default=None,
        metavar="V",
        help="Edge for inter_arrival_mean_median_ratio (default: %.2f)"
        % EDGE_MEAN_MEDIAN_RATIO,
    )
    args = parser.parse_args()

    # Override edges if passed (for display; compute_bars uses module-level EDGES)
    if args.req_per_min is not None:
        EDGES["request_rate_per_min"] = (args.req_per_min, "above")
    if args.gap_median_sec is not None:
        EDGES["inter_arrival_median_sec"] = (args.gap_median_sec, "below")
    if args.gap_std_mean is not None:
        EDGES["inter_arrival_std_per_mean"] = (args.gap_std_mean, "above")
    if args.gap_mean_median is not None:
        EDGES["inter_arrival_mean_median_ratio"] = (args.gap_mean_median, "above")

    p_from = args.p_from
    p_to = args.p_to
    if not (1 <= p_from <= p_to <= NUM_PERCENTILE_BARS):
        print(
            f"Error: require 1 <= --p-from ({p_from}) <= --p-to ({p_to}) <= {NUM_PERCENTILE_BARS}.",
            file=sys.stderr,
        )
        return 1

    file_paths = iter_files_by_globs(args.globs)
    if not file_paths:
        print("No files matched the given glob(s).", file=sys.stderr)
        return 1

    records = load_all_records(file_paths, progress=not args.no_progress)
    if not records:
        print("No records loaded.", file=sys.stderr)
        return 1

    data = build_all_bars(records, p_from=p_from, p_to=p_to)
    data["n_records"] = len(records)
    data["p_from"] = p_from
    data["p_to"] = p_to
    data["edges"] = {k: v[0] for k, v in EDGES.items()}

    text = json.dumps(data, indent=2, ensure_ascii=False)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(text)

    if args.charts_dir:
        generate_charts(data, args.charts_dir)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

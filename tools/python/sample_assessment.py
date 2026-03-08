"""
Random representative sample from request JSONL for manual FP/FN assessment.

Reads JSONL request logs, selects random IPs that are NOT in top-10 or bottom-10
by request count; 100 IPs from those with at least one bot-labeled request,
100 from those with at least one browser-labeled request. For each selected IP
outputs the first 10 requests by time (time, classification, url, client,
cookies, referrer). In JSON output mode writes the full result to file.

Usage:
  poetry run python sample_assessment.py "logs/requests.jsonl"
  poetry run python sample_assessment.py -o sample.json --json "logs/requests.jsonl"
  poetry run python sample_assessment.py "logs/**/requests_*.jsonl"
  poetry run python sample_assessment.py --bot-n 50 --browser-n 50 --seed 42 "logs/requests.jsonl"
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tqdm import tqdm

from request_log_stats import iter_jsonl_files, read_jsonl_stream

# Number of IPs to exclude from each end when selecting "middle" by request count
TOP_BOTTOM_N = 10
DEFAULT_BOT_IPS = 100
DEFAULT_BROWSER_IPS = 100
REQUESTS_PER_IP = 10
MIN_REQUESTS_PER_IP = 2


def _print_human_readable(
    result: list[dict[str, Any]],
    output_file: Path | None,
) -> None:
    """Print samples to stdout in human-readable format."""
    total_rows = sum(len(s["requests"]) for s in result)
    print("=" * 72)
    print(
        f"  Sample: {len(result)} IPs, {total_rows} requests (first {REQUESTS_PER_IP} by time per IP)"
    )
    print("=" * 72)

    for idx, entry in enumerate(result, 1):
        ip = entry["ip"]
        label = entry["sample_label"]
        total = entry["request_count_total"]
        requests = entry["requests"]

        print()
        print("-" * 72)
        print(
            f"  [{idx}] IP: {ip}  |  sample: {label}  |  total requests for this IP: {total}"
        )
        print("-" * 72)

        for i, req in enumerate(requests, 1):
            time_ = req.get("time") or ""
            classification = req.get("classification") or ""
            url = req.get("url") or ""
            client = (req.get("client") or "").strip()
            cookies = (req.get("cookies") or "").strip()
            referrer = (req.get("referrer") or "").strip()

            delta_ms = req.get("delta_ms")
            delta_str = f"{delta_ms} ms" if delta_ms is not None else "—"

            print(f"\n  Request {i}:")
            print(f"    Time:         {time_}")
            print(f"    Delta:        {delta_str}")
            print(f"    Classification: {classification}")
            print(f"    URL:         {url}")
            client_display = (
                f"{client[:100]}..." if len(client) > 100 else (client or "(empty)")
            )
            print(f"    Client:      {client_display}")
            if cookies:
                print(
                    f"    Cookies:     {cookies[:70]}{'...' if len(cookies) > 70 else ''}"
                )
            else:
                print("    Cookies:     (none)")
            if referrer:
                print(
                    f"    Referrer:    {referrer[:70]}{'...' if len(referrer) > 70 else ''}"
                )
            else:
                print("    Referrer:    (none)")

    print()
    print("=" * 72)
    print(f"  Total: {len(result)} IPs, {total_rows} request rows shown.")
    if output_file:
        print(f"  Full JSON saved to: {output_file}")
    print("=" * 72)


def _parse_iso_time(s: str) -> datetime | None:
    """Parse ISO timestamp (e.g. 2026-02-25T12:11:51.384034113Z) to naive UTC datetime for diff."""
    if not s or not s.strip():
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _delta_ms(prev_iso: str, curr_iso: str) -> int | None:
    """Return milliseconds from prev_iso to curr_iso, or None if unparseable."""
    t1 = _parse_iso_time(prev_iso)
    t2 = _parse_iso_time(curr_iso)
    if t1 is None or t2 is None:
        return None
    delta = (t2 - t1).total_seconds() * 1000
    return int(round(delta))


def _normalize_ip(addr: str) -> str:
    """Strip port from remote_addr (e.g. 1.2.3.4:56789 -> 1.2.3.4)."""
    if not addr or not addr.strip():
        return ""
    s = addr.strip()
    if re.match(r".*:\d+$", s):
        s = re.sub(r":\d+$", "", s)
    return s


def extract_request_row(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Extract one row for assessment: time, classification, url, client, cookies, referrer."""
    classification = (rec.get("classification") or "").strip().lower()
    if classification not in ("bot", "browser"):
        return None
    http = (rec.get("fingerprint") or {}).get("http") or {}
    headers = http.get("headers") or {}
    path = (http.get("path") or "").strip() or "/"
    user_agent = (http.get("user_agent") or "").strip()
    cookie = (headers.get("cookie") or headers.get("Cookie") or "").strip()
    referrer = (headers.get("referer") or headers.get("Referer") or "").strip()
    return {
        "time": (rec.get("timestamp") or "").strip(),
        "classification": classification,
        "url": path,
        "client": user_agent,
        "cookies": cookie,
        "referrer": referrer,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sample random IPs from request JSONL for manual FP/FN assessment (excludes top/bottom 10 by count)."
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
        help="Write full result to this file (JSON array).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print result as JSON to stdout (and to -o if set).",
    )
    parser.add_argument(
        "--bot-n",
        type=int,
        default=DEFAULT_BOT_IPS,
        metavar="N",
        help=f"Number of random bot IPs to sample (default: {DEFAULT_BOT_IPS}).",
    )
    parser.add_argument(
        "--browser-n",
        type=int,
        default=DEFAULT_BROWSER_IPS,
        metavar="N",
        help=f"Number of random browser IPs to sample (default: {DEFAULT_BROWSER_IPS}).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible sampling.",
    )
    args = parser.parse_args()

    file_paths = iter_jsonl_files(args.globs)
    if file_paths is not None and not file_paths:
        print("No files matched the given glob(s).", file=sys.stderr)
        return 1

    # 1) Read all records and group by IP; keep full row for selected IPs later
    ip_to_rows: dict[str, list[dict[str, Any]]] = {}
    ip_request_count: dict[str, int] = {}
    skipped = 0

    def on_progress(delta: int, _path: Path | None) -> None:
        pbar.update(delta)

    pbar = tqdm(
        total=None,
        unit=" lines",
        desc="Reading",
        file=sys.stderr,
        mininterval=0.5,
    )
    for rec, skip_count in read_jsonl_stream(file_paths, progress_callback=on_progress):
        if rec is None:
            skipped = skip_count
            break
        row = extract_request_row(rec)
        if row is None:
            continue
        ip = _normalize_ip(rec.get("remote_addr") or "")
        if not ip or ip in ("127.0.0.1", "::1"):
            continue
        ip_to_rows.setdefault(ip, []).append(row)
        ip_request_count[ip] = ip_request_count.get(ip, 0) + 1
    pbar.close()

    if skipped:
        print(f"Warning: skipped {skipped} invalid JSON line(s).", file=sys.stderr)

    if not ip_request_count:
        print(
            "No valid records with bot/browser classification and non-local IP.",
            file=sys.stderr,
        )
        return 1

    # 2) Sort IPs by request count; exclude IPs with < MIN_REQUESTS_PER_IP, then exclude top-10 and bottom-10
    sorted_ips = sorted(
        [ip for ip in ip_request_count if ip_request_count[ip] >= MIN_REQUESTS_PER_IP],
        key=lambda x: ip_request_count[x],
        reverse=True,
    )
    n = len(sorted_ips)
    if n <= 2 * TOP_BOTTOM_N:
        print(
            f"Warning: only {n} IPs; cannot exclude top/bottom {TOP_BOTTOM_N}. Using all.",
            file=sys.stderr,
        )
        middle_ips = set(sorted_ips)
    else:
        excluded_top = set(sorted_ips[:TOP_BOTTOM_N])
        excluded_bottom = set(sorted_ips[-TOP_BOTTOM_N:])
        middle_ips = set(sorted_ips) - excluded_top - excluded_bottom

    # 3) Middle IPs that have at least one bot (browser) record
    bot_candidate_ips = [
        ip
        for ip in middle_ips
        if any(r["classification"] == "bot" for r in ip_to_rows[ip])
    ]
    browser_candidate_ips = [
        ip
        for ip in middle_ips
        if any(r["classification"] == "browser" for r in ip_to_rows[ip])
    ]

    rng = __import__("random").Random(args.seed)
    n_bot = min(args.bot_n, len(bot_candidate_ips))
    n_browser = min(args.browser_n, len(browser_candidate_ips))
    chosen_bot_ips = set(rng.sample(bot_candidate_ips, n_bot))
    chosen_browser_ips = set(rng.sample(browser_candidate_ips, n_browser))

    # 4) For each chosen IP: sort requests by time, take first REQUESTS_PER_IP, add delta_ms
    def first_10_for_ip(ip: str, sample_label: str) -> dict[str, Any]:
        rows = ip_to_rows[ip]
        by_time = sorted(rows, key=lambda r: r["time"] or "")
        first = by_time[:REQUESTS_PER_IP]
        requests_with_delta: list[dict[str, Any]] = []
        prev_time = ""
        for r in first:
            row = dict(r)
            if prev_time:
                row["delta_ms"] = _delta_ms(prev_time, r.get("time") or "")
            else:
                row["delta_ms"] = None
            prev_time = r.get("time") or ""
            requests_with_delta.append(row)
        return {
            "ip": ip,
            "sample_label": sample_label,
            "request_count_total": len(rows),
            "requests": requests_with_delta,
        }

    result: list[dict[str, Any]] = []
    for ip in chosen_bot_ips:
        result.append(first_10_for_ip(ip, "bot"))
    for ip in chosen_browser_ips:
        result.append(first_10_for_ip(ip, "browser"))

    # 5) Output
    out_data: dict[str, Any] = {
        "meta": {
            "bot_ips_sampled": n_bot,
            "browser_ips_sampled": n_browser,
            "requests_per_ip_shown": REQUESTS_PER_IP,
            "total_ips_in_logs": n,
            "middle_ips_after_excluding_top_bottom_10": len(middle_ips),
        },
        "samples": result,
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2, ensure_ascii=False)
        print(f"Wrote full result to {args.output}", file=sys.stderr)

    if args.json:
        print(json.dumps(out_data, indent=2, ensure_ascii=False))
    else:
        _print_human_readable(result, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())

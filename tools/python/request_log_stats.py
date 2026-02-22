"""
Request log statistics for bot-detection methodology.

Reads JSONL request logs (one JSON object per line, format as in
tests/testdata/reference_browser.json), aggregates by fingerprint and
signals, outputs top-N values per field with bot/browser breakdown.

Channels (see docs/nginx.md): requests may reach the classifier (1) via *trusted proxy*
(X-Internal-Proxy: 1) — nginx terminates TLS, sets X-FP-* (TLS, JA3, JA4, H2, etc.),
proxies HTTP to Go; or (2) *direct* — Go terminates TLS. All fingerprint data is
delivered in a unified way: when from proxy, fingerprint.tls/http are filled from
X-FP-* and X-Original-Header-Order; when direct, from r.TLS and the request. For
*statistics we must not use "direct" request fields when that record came from proxy*
(e.g. fingerprint.http.version is backend view "HTTP/1.0" when from proxy, not client
protocol). We use a single canonical interpretation: TLS/JA3/JA4 from fingerprint.tls
(already unified); client HTTP version from signals.is_http2 (not fingerprint.http.version);
header order/count from fingerprint.http (order from proxy = X-Original-Header-Order when applicable).

Methodology aligned with Cloudflare Signals Intelligence (JA4 per-fingerprint metrics:
browser_ratio, user-agent/path/IP diversity, HTTP/2 ratio) and JA4/JA4H fingerprinting
(FoxIO JA4+). Full statistics collection method, significance filtering, and references
are in docs/METHODOLOGY.md Appendix J (Request log statistics and collection methodology).

Usage:
  poetry run python request_log_stats.py -n 20 "logs/**/requests_*.jsonl"
  poetry run python request_log_stats.py -n 10 -o report.txt --format text "logs/**/*.jsonl"
  poetry run python request_log_stats.py --format json -o stats.json "logs/**/requests_*.jsonl"

Examples of glob masks:
  logs/**/requests_*.jsonl
  logs/**/*.jsonl
  /path/to/requests_20260217.jsonl

Test run on two reference payloads (Windows):
  Get-Content ../../tests/testdata/reference_browser.json, ../../tests/testdata/reference_bot_curl_cffi.json | poetry run python request_log_stats.py -n 10 -
  Or: poetry run python request_log_stats.py -n 10 "../../tests/testdata/reference_browser.json" "../../tests/testdata/reference_bot_curl_cffi.json"
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd
from tqdm import tqdm


# All signal IDs from scoring config (browser_scores + bot_scores), including 0-point ones, for stats.
# Must match internal/config/scoring.go defaultBrowserScores + defaultBotScores.
ALL_SCORING_SIGNAL_IDS: list[str] = sorted({
    "http2", "h2-fp", "h2-init-window", "h2-priority", "h2-window-update", "h2-max-frame", "h2-pseudo-headers",
    "sec-fetch", "browser-ua", "sec-ch-ua", "header-order", "cache-control", "cookies", "modern-tls", "ssl-greased",
    "high-ciphers", "session-ticket", "multi-groups", "tls-ext>=10", "ja4h-headers>=10", "ja4h-referer", "ja4h-consistent",
    "tls-ua-consistent", "accept-lang-rich", "sec-purpose", "accept-language", "browser-headers", "sec-ch-ua-modern",
    "high-header-count", "no-bot-red-flags",
    "obsolete-tls", "exotic-alpn", "blind-probe", "bot-ua", "ai-crawler", "low-headers", "missing-typical", "no-ua",
    "http1.1", "accept-*/*", "no-accept-lang", "low-ciphers", "few-tls-ext", "no-session", "ja4h-no-lang",
    "ja4h-low-headers", "ja4h-inconsistent", "ja4h-no-cookies", "header-order-late", "h2-ua-inconsistent",
    "tls-ua-inconsistent", "ua-browser-no-grease", "h2-ja4-inconsistent", "tls-alpn-http-inconsistent", "no-sni", "no-alpn",
    "accept-lang-simple", "sec-purpose-invalid", "sec-purpose-no-sec-fetch",
})


def _parse_score_breakdown(breakdown: str) -> set[str]:
    """Extract signal IDs from score_breakdown string (e.g. 'BROWSER[http2(+2) ...] BOT[bot-ua(+3)]')."""
    if not breakdown or not isinstance(breakdown, str):
        return set()
    out: set[str] = set()
    # Match tokens like "http2(+2)" or "bot-ua(+3)" inside brackets
    import re
    for m in re.finditer(r"([a-z0-9\-*/><=]+)\(\+\d+\)", breakdown):
        out.add(m.group(1))
    return out


# --- Normalization ---

def _normalize_user_agent(ua: str) -> str:
    """Normalize User-Agent to family: curl, python, Chrome, Safari, Firefox, go-http-client, other."""
    if not ua or not ua.strip():
        return "(empty)"
    ua_lower = ua.lower()
    if "curl" in ua_lower:
        return "curl"
    if "wget" in ua_lower:
        return "wget"
    if "python" in ua_lower:
        return "python"
    if "go-http-client" in ua_lower:
        return "go-http-client"
    if "httpie" in ua_lower:
        return "httpie"
    if "postman" in ua_lower:
        return "postman"
    if "axios" in ua_lower or "node-fetch" in ua_lower or "undici" in ua_lower:
        return "node"
    if "chrome" in ua_lower and "chromium" in ua_lower:
        return "Chrome"
    if "edg/" in ua_lower or "edge" in ua_lower:
        return "Edge"
    if "firefox" in ua_lower:
        return "Firefox"
    if "safari" in ua_lower and "chrome" not in ua_lower:
        return "Safari"
    if "opr/" in ua_lower or "opera" in ua_lower:
        return "Opera"
    if "mozilla" in ua_lower:
        return "Chrome"  # Mozilla/5.0 ... Chrome/... → Chrome
    return "other"


def _accept_lang_category(accept_lang: str) -> str:
    """Category: empty, short (<40 chars or <3 parts), rich."""
    if not accept_lang or not accept_lang.strip():
        return "empty"
    s = accept_lang.strip()
    parts = [p.strip() for p in s.split(",") if p.strip()]
    if len(s) < 40 and len(parts) < 3:
        return "short"
    return "rich"


def _sec_ch_ua_prefix(sec_ch_ua: str, max_len: int = 40) -> str:
    """First brand or prefix for grouping."""
    if not sec_ch_ua or not sec_ch_ua.strip():
        return "(empty)"
    s = sec_ch_ua.strip()[:max_len]
    return s if s else "(empty)"


def _header_count_bucket(hc: int) -> str:
    """Bucket: 0-2, 3-5, 6-9, 10+."""
    if hc <= 2:
        return "0-2"
    if hc <= 5:
        return "3-5"
    if hc <= 9:
        return "6-9"
    return "10+"


def _get_ja3_hash(rec: dict[str, Any]) -> str:
    """JA3 from fingerprint.tls or fallback from proxy_headers / headers."""
    fp = rec.get("fingerprint") or {}
    tls = fp.get("tls") or {}
    ja3 = (tls.get("ja3_hash") or "").strip()
    if ja3:
        return ja3
    ph = fp.get("proxy_headers") or {}
    ja3 = (ph.get("X-FP-JA3-HASH") or ph.get("x-fp-ja3-hash") or "").strip()
    if ja3:
        return ja3
    http = fp.get("http") or {}
    headers = http.get("headers") or {}
    ja3 = (headers.get("x-fp-ja3-hash") or "").strip()
    if ja3:
        return ja3
    return "(empty)"


def _get_ja4_hash(rec: dict[str, Any]) -> str:
    """JA4 from fingerprint.tls; empty when absent."""
    fp = rec.get("fingerprint") or {}
    tls = fp.get("tls") or {}
    ja4 = (tls.get("ja4_hash") or "").strip()
    return ja4 if ja4 else "(empty)"


def _has_sec_fetch(rec: dict[str, Any]) -> bool:
    """True if any Sec-Fetch-* header is present."""
    fp = rec.get("fingerprint") or {}
    http = fp.get("http") or {}
    for k in ("sec_fetch_site", "sec_fetch_mode", "sec_fetch_dest", "sec_fetch_user"):
        if (http.get(k) or "").strip():
            return True
    return False


def extract_record(rec: dict[str, Any]) -> dict[str, Any] | None:
    """Extract normalized fields and classification from one log record."""
    classification = (rec.get("classification") or "").strip().lower()
    if classification not in ("bot", "browser"):
        return None
    fp = rec.get("fingerprint") or {}
    tls = fp.get("tls") or {}
    http = fp.get("http") or {}
    sig = rec.get("signals") or {}

    user_agent = (http.get("user_agent") or "").strip()
    accept = (http.get("accept") or "").strip() or "(empty)"
    accept_lang = (http.get("accept_lang") or "").strip()
    sec_ch_ua = (http.get("sec_ch_ua") or "").strip()
    header_count = int(http.get("header_count") or 0)
    tls_from_proxy = bool(tls.get("from_proxy")) or bool(sig.get("tls_from_proxy"))
    is_http2 = bool(sig.get("is_http2"))
    # Canonical client protocol: do NOT use fingerprint.http.version when from_proxy (backend sees HTTP/1.0)
    http_version = "HTTP/2.0" if is_http2 else "HTTP/1.1"
    alpn = (tls.get("alpn") or "").strip() or "(empty)"
    ja4h = (http.get("ja4h_hash") or "").strip() or "(empty)"
    path = (http.get("path") or "").strip() or "(empty)"
    method = (http.get("method") or "GET").strip().upper() or "GET"
    remote_addr = (rec.get("remote_addr") or "").strip() or "(empty)"
    # Always strip port for aggregation (IP only): any "addr:port" -> "addr"
    if remote_addr and re.match(r".*:\d+$", remote_addr):
        remote_addr = re.sub(r":\d+$", "", remote_addr)
    # Normalise localhost to (empty): IPv4 and IPv6
    if not remote_addr or remote_addr == "127.0.0.1" or remote_addr == "::1" or remote_addr == "[::1]":
        remote_addr = "(empty)"
    score_signal_ids = _parse_score_breakdown((sig.get("score_breakdown") or ""))

    # Raw User-Agent for separate stats (truncate to limit cardinality in aggregation)
    user_agent_raw = (user_agent[:200] + "…") if len(user_agent) > 200 else (user_agent or "(empty)")

    return {
        "classification": classification,
        "path": path,
        "method": method,
        "remote_addr": remote_addr,
        "score_signal_ids": score_signal_ids,
        "user_agent": _normalize_user_agent(user_agent),
        "user_agent_raw": user_agent_raw,
        "accept": accept[:80] if len(accept) > 80 else accept,  # truncate long
        "accept_lang_category": _accept_lang_category(accept_lang),
        "ja3_hash": _get_ja3_hash(rec),
        "ja4_hash": _get_ja4_hash(rec),
        "ja4h_hash": ja4h,
        "http_version": http_version,
        "is_http2": is_http2,
        "alpn": alpn,
        "header_count": header_count,
        "header_count_bucket": _header_count_bucket(header_count),
        "sec_ch_ua_present": bool(sec_ch_ua),
        "sec_ch_ua_prefix": _sec_ch_ua_prefix(sec_ch_ua),
        "has_sec_fetch": _has_sec_fetch(rec),
        "score": int(rec.get("score") or 0),
        "ua_is_bot": bool(sig.get("ua_is_bot")),
        "has_sec_fetch_headers": bool(sig.get("has_sec_fetch_headers")),
        "has_accept_language": bool(sig.get("has_accept_language")),
        "sec_ch_ua_modern_order": bool(sig.get("sec_ch_ua_modern_order")),
        "tls_from_proxy": tls_from_proxy,
    }


def iter_jsonl_files(globs: list[str]) -> list[Path] | None:
    """Expand globs to sorted list of existing files. If globs is ['-'], returns None (read from stdin)."""
    if len(globs) == 1 and globs[0].strip() == "-":
        return None
    seen: set[Path] = set()
    for g in globs:
        for p in glob.glob(g):
            path = Path(p).resolve()
            if path.is_file():
                seen.add(path)
    return sorted(seen)


PROGRESS_UPDATE_EVERY = 1000


def _count_lines_in_files(file_paths: list[Path]) -> int:
    """Count total non-empty lines in files (for progress bar total)."""
    total = 0
    for path in tqdm(
        file_paths,
        desc="Reading",
        unit=" files",
        file=sys.stderr,
        mininterval=0.5,
    ):
        try:
            with open(path, "rb") as f:
                total += sum(1 for line in f if line.strip())
        except OSError:
            pass
    return total


def read_jsonl_stream(
    file_paths: list[Path] | None,
    progress_callback: Callable[[int, Path | None], None] | None = None,
):
    """Yield parsed records (dict) from JSONL files or stdin (if file_paths is None); skip invalid lines.
    If progress_callback is set, call it every PROGRESS_UPDATE_EVERY lines as (delta, current_path)."""
    total_skipped = 0
    lines_done = 0
    pending_update = 0

    def maybe_progress(path: Path | None) -> None:
        nonlocal pending_update
        if progress_callback is None or pending_update == 0:
            return
        progress_callback(pending_update, path)
        pending_update = 0

    if file_paths is None:
        current_path: Path | None = None
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            lines_done += 1
            pending_update += 1
            if pending_update >= PROGRESS_UPDATE_EVERY:
                maybe_progress(current_path)
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                total_skipped += 1
                continue
            yield rec, total_skipped
        maybe_progress(current_path)
        yield None, total_skipped
        return

    for path in file_paths:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    lines_done += 1
                    pending_update += 1
                    if pending_update >= PROGRESS_UPDATE_EVERY:
                        maybe_progress(path)
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        total_skipped += 1
                        continue
                    yield rec, total_skipped
        except OSError:
            total_skipped += 1
            continue
        maybe_progress(path)
    yield None, total_skipped  # sentinel


def aggregate(
    records: list[dict[str, Any]],
    sort_by: str = "count",
    filter_significance: bool = True,
) -> dict[str, Any]:
    """Compute summary and per-field top-N counts (value -> {total, bot, browser}). sort_by: count | discriminative. filter_significance: hide rows with total < sqrt(N)."""
    if not records:
        return {
            "summary": {
                "total": 0,
                "bot_count": 0,
                "browser_count": 0,
                "bot_pct": 0.0,
                "browser_pct": 0.0,
                "median_score_bot": None,
                "median_score_browser": None,
                "p50_score_bot": None,
                "p50_score_browser": None,
                "p95_score_bot": None,
                "p95_score_browser": None,
                "p50_header_count_bot": None,
                "p50_header_count_browser": None,
                "p95_header_count_bot": None,
                "p95_header_count_browser": None,
                "ua_is_bot_pct": 0.0,
                "has_sec_fetch_headers_pct": 0.0,
                "has_accept_language_pct": 0.0,
                "sec_ch_ua_modern_order_pct": 0.0,
                "h2_ratio": 0.0,
                "tls_from_proxy_pct": 0.0,
                "unique_ips": 0,
                "unique_urls": 0,
            },
            "top_values": {},
            "scoring_signals": [],
        }

    df = pd.DataFrame(records)
    total = len(df)
    bot = df["classification"] == "bot"
    browser = df["classification"] == "browser"
    bot_count = int(bot.sum())
    browser_count = int(browser.sum())
    bot_pct = 100.0 * bot_count / total if total else 0.0
    browser_pct = 100.0 * browser_count / total if total else 0.0

    score_bot = np.array(df.loc[bot, "score"].dropna(), dtype=float)
    score_browser = np.array(df.loc[browser, "score"].dropna(), dtype=float)
    median_score_bot = float(np.median(score_bot)) if score_bot.size else None
    median_score_browser = float(np.median(score_browser)) if score_browser.size else None
    p50_score_bot = float(np.percentile(score_bot, 50)) if score_bot.size else None
    p50_score_browser = float(np.percentile(score_browser, 50)) if score_browser.size else None
    p95_score_bot = float(np.percentile(score_bot, 95)) if score_bot.size else None
    p95_score_browser = float(np.percentile(score_browser, 95)) if score_browser.size else None

    hc_bot = np.array(df.loc[bot, "header_count"].dropna(), dtype=float)
    hc_browser = np.array(df.loc[browser, "header_count"].dropna(), dtype=float)
    p50_hc_bot = float(np.percentile(hc_bot, 50)) if hc_bot.size else None
    p50_hc_browser = float(np.percentile(hc_browser, 50)) if hc_browser.size else None
    p95_hc_bot = float(np.percentile(hc_bot, 95)) if hc_bot.size else None
    p95_hc_browser = float(np.percentile(hc_browser, 95)) if hc_browser.size else None

    summary = {
        "total": total,
        "bot_count": bot_count,
        "browser_count": browser_count,
        "bot_pct": round(bot_pct, 2),
        "browser_pct": round(browser_pct, 2),
        "median_score_bot": round(median_score_bot, 2) if median_score_bot is not None else None,
        "median_score_browser": round(median_score_browser, 2) if median_score_browser is not None else None,
        "p50_score_bot": round(p50_score_bot, 2) if p50_score_bot is not None else None,
        "p50_score_browser": round(p50_score_browser, 2) if p50_score_browser is not None else None,
        "p95_score_bot": round(p95_score_bot, 2) if p95_score_bot is not None else None,
        "p95_score_browser": round(p95_score_browser, 2) if p95_score_browser is not None else None,
        "p50_header_count_bot": round(p50_hc_bot, 2) if p50_hc_bot is not None else None,
        "p50_header_count_browser": round(p50_hc_browser, 2) if p50_hc_browser is not None else None,
        "p95_header_count_bot": round(p95_hc_bot, 2) if p95_hc_bot is not None else None,
        "p95_header_count_browser": round(p95_hc_browser, 2) if p95_hc_browser is not None else None,
        "ua_is_bot_pct": round(100.0 * df["ua_is_bot"].sum() / total, 2),
        "has_sec_fetch_headers_pct": round(100.0 * df["has_sec_fetch_headers"].sum() / total, 2),
        "has_accept_language_pct": round(100.0 * df["has_accept_language"].sum() / total, 2),
        "sec_ch_ua_modern_order_pct": round(100.0 * df["sec_ch_ua_modern_order"].sum() / total, 2),
        "h2_ratio": round(100.0 * df["is_http2"].sum() / total, 2),
        "tls_from_proxy_pct": round(100.0 * df["tls_from_proxy"].sum() / total, 2),
        "unique_ips": int(df["remote_addr"].nunique()),
        "unique_urls": int(df["path"].nunique()),
    }

    # Per-field value counts; for fingerprint fields add diversity (Signals Intelligence style)
    categorical_fields = [
        "path",
        "method",
        "remote_addr",  # top IPs
        "user_agent",
        "user_agent_raw",  # raw User-Agent string (truncated)
        "accept",
        "accept_lang_category",
        "ja3_hash",
        "ja4_hash",
        "ja4h_hash",
        "http_version",
        "alpn",
        "header_count_bucket",
        "sec_ch_ua_prefix",
    ]
    bool_fields = ["sec_ch_ua_present", "has_sec_fetch", "is_http2"]
    # For bool we use "True"/"False" as value for consistency in output

    fingerprint_fields = {"ja3_hash", "ja4_hash", "ja4h_hash"}
    top_values: dict[str, list[dict[str, Any]]] = {}

    def _count_classification(g: pd.DataFrame, include_distinct: bool) -> pd.Series:
        out: dict[str, Any] = {
            "total": g["classification"].count(),
            "bot": (g["classification"] == "bot").sum(),
            "browser": (g["classification"] == "browser").sum(),
        }
        if include_distinct:
            out["distinct_user_agents"] = g["user_agent"].nunique()
            out["distinct_paths"] = g["path"].nunique()
            out["distinct_ips"] = g["remote_addr"].nunique()
        return pd.Series(out)

    for field in categorical_fields + bool_fields:
        work = df.assign(**{field: df[field].astype(str)}) if field in bool_fields else df
        counts = (
            work.groupby(field, dropna=False)
            .apply(lambda g: _count_classification(g, field in fingerprint_fields), include_groups=False)
            .reset_index()
        )
        counts = counts.rename(columns={field: "value"})
        counts["bot_pct"] = (100.0 * counts["bot"] / counts["total"]).round(2)
        counts["browser_ratio"] = (100.0 * counts["browser"] / counts["total"]).round(2)
        if sort_by == "discriminative":
            counts["_discriminative"] = (counts["bot"] - counts["browser"]).abs()
            counts = counts.sort_values("_discriminative", ascending=False).drop(columns=["_discriminative"])
        else:
            counts = counts.sort_values("total", ascending=False)
        rows = counts.to_dict("records")
        if filter_significance:
            non_empty = [r for r in rows if str(r.get("value", "")).strip() != "(empty)"]
            N = max((r["total"] for r in non_empty), default=0)
            threshold = math.sqrt(N)
            rows = [r for r in rows if r["total"] >= threshold]
        top_values[field] = rows

    # For fingerprint fields: add per-hash lists of unique raw UAs, paths, IPs with request counts (skip empty)
    for field in fingerprint_fields:
        if field not in top_values:
            continue
        work = df
        for row in top_values[field]:
            val = row.get("value")
            if val is None or str(val).strip() == "" or str(val).strip() == "(empty)":
                continue
            g = work[work[field].astype(str) == str(val)]
            ua_counts = g["user_agent_raw"].value_counts()
            path_counts = g["path"].value_counts()
            ip_counts = g["remote_addr"].value_counts()
            row["top_user_agents"] = [{"value": v, "count": int(c)} for v, c in ua_counts.items()]
            row["top_paths"] = [{"value": v, "count": int(c)} for v, c in path_counts.items()]
            row["top_ips"] = [{"value": v, "count": int(c)} for v, c in ip_counts.items()]

    # Per-signal stats (from score_breakdown): for each config signal ID, count records where it fired
    scoring_signals: list[dict[str, Any]] = []
    for signal_id in ALL_SCORING_SIGNAL_IDS:
        total_s = 0
        bot_s = 0
        browser_s = 0
        for r in records:
            ids = r.get("score_signal_ids")
            if ids is None:
                ids = set()
            elif not isinstance(ids, set):
                ids = set(ids) if ids else set()
            if signal_id not in ids:
                continue
            total_s += 1
            if r.get("classification") == "bot":
                bot_s += 1
            elif r.get("classification") == "browser":
                browser_s += 1
        bot_pct_s = round(100.0 * bot_s / total_s, 2) if total_s else 0.0
        browser_pct_s = round(100.0 * browser_s / total_s, 2) if total_s else 0.0
        scoring_signals.append({
            "signal_id": signal_id,
            "total": total_s,
            "bot": bot_s,
            "browser": browser_s,
            "bot_pct": bot_pct_s,
            "browser_pct": browser_pct_s,
        })

    if filter_significance and scoring_signals:
        N_sig = max(r["total"] for r in scoring_signals)
        threshold_sig = math.sqrt(N_sig)
        scoring_signals = [r for r in scoring_signals if r["total"] >= threshold_sig]

    return {"summary": summary, "top_values": top_values, "scoring_signals": scoring_signals}


def format_text(stats: dict[str, Any], top_n: int) -> str:
    """Format stats as human-readable text."""
    lines: list[str] = []
    s = stats["summary"]
    lines.append("=== Summary ===")
    lines.append(f"Total requests (after filters): {s['total']}")
    lines.append(f"Unique IPs: {s.get('unique_ips', '—')}  Unique URLs (paths): {s.get('unique_urls', '—')}")
    lines.append(f"Bot: {s['bot_count']} ({s['bot_pct']}%)")
    lines.append(f"Browser: {s['browser_count']} ({s['browser_pct']}%)")
    lines.append(f"Score: median bot={s['median_score_bot']} browser={s['median_score_browser']} | P50 bot={s.get('p50_score_bot')} browser={s.get('p50_score_browser')} | P95 bot={s.get('p95_score_bot')} browser={s.get('p95_score_browser')}")
    lines.append(f"Header count: P50 bot={s['p50_header_count_bot']} browser={s['p50_header_count_browser']} | P95 bot={s.get('p95_header_count_bot')} browser={s.get('p95_header_count_browser')}")
    lines.append(f"Prevalence: ua_is_bot={s['ua_is_bot_pct']}%, has_sec_fetch_headers={s['has_sec_fetch_headers_pct']}%, has_accept_language={s['has_accept_language_pct']}%, sec_ch_ua_modern_order={s.get('sec_ch_ua_modern_order_pct', 0)}%")
    lines.append(f"HTTP/2 ratio (h2_ratio): {s.get('h2_ratio', 0)}%")
    lines.append(f"TLS from trusted proxy (X-FP-*): {s.get('tls_from_proxy_pct', 0)}%")
    lines.append("")

    for field, rows in stats["top_values"].items():
        lines.append(f"=== Top-{top_n}: {field} ===")
        has_diversity = bool(rows and "distinct_user_agents" in (rows[0] or {}))
        for i, row in enumerate(rows[:top_n], 1):
            val = row["value"]
            if isinstance(val, str) and len(val) > 70:
                val = val[:67] + "..."
            line = f"  {i}. {val}  total={row['total']}  bot={row['bot']}  browser={row['browser']}  bot%={row['bot_pct']}"
            if has_diversity and row.get("distinct_user_agents") is not None:
                line += f"  | distinct_ua={row.get('distinct_user_agents')} paths={row.get('distinct_paths')} ips={row.get('distinct_ips')}"
            lines.append(line)
        lines.append("")

    lines.append("=== Scoring signals (from score_breakdown) ===")
    for row in stats.get("scoring_signals") or []:
        lines.append(f"  {row['signal_id']}: total={row['total']}  bot={row['bot']}  browser={row['browser']}  bot%={row['bot_pct']}  browser%={row['browser_pct']}")
    lines.append("")

    return "\n".join(lines)


def format_json(stats: dict[str, Any], top_n: int) -> str:
    """Format stats as JSON (top_values truncated to top_n per field)."""
    out = {
        "summary": stats["summary"],
        "top_values": {
            field: rows[:top_n]
            for field, rows in stats["top_values"].items()
        },
        "scoring_signals": stats.get("scoring_signals") or [],
    }
    return json.dumps(out, indent=2, ensure_ascii=False)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Request log statistics for bot-detection (top-N signals with bot/browser breakdown)."
    )
    parser.add_argument(
        "globs",
        nargs="+",
        help="Glob mask(s) for JSONL files, e.g. logs/**/requests_*.jsonl",
    )
    parser.add_argument(
        "-n", "--top",
        type=int,
        default=15,
        metavar="N",
        help="Number of top values per field (default: 15)",
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
        "--sort",
        choices=("count", "discriminative"),
        default="count",
        help="Sort top values by total count (default) or by |bot-browser| discriminativity",
    )
    parser.add_argument(
        "--exclude-stress-tests",
        action="store_true",
        help="Exclude go-http-client requests only for paths /, /health, /debug (stress-test traffic)",
    )
    parser.add_argument(
        "--no-significance-filter",
        action="store_true",
        help="Show all grouped values (disable filter by sqrt(N) statistical significance)",
    )
    args = parser.parse_args()

    file_paths = iter_jsonl_files(args.globs)
    if file_paths is not None and not file_paths:
        print("No files matched the given glob(s).", file=sys.stderr)
        return 1

    # Progress bar: total lines when reading from files (pre-count), else indeterminate for stdin; update every 1000 lines
    pbar: tqdm | None = None
    if file_paths:
        total_lines = _count_lines_in_files(file_paths)
        pbar = tqdm(
            total=total_lines,
            unit=" lines",
            unit_scale=False,
            desc="Processing",
            file=sys.stderr,
            mininterval=0.5,
            maxinterval=2.0,
        )
    else:
        pbar = tqdm(
            total=None,
            unit=" lines",
            desc="Processing",
            file=sys.stderr,
            mininterval=0.5,
        )

    def on_progress(delta: int, current_path: Path | None) -> None:
        if pbar is not None:
            pbar.update(delta)
            pbar.set_postfix_str(str(current_path.name) if current_path else "stdin", refresh=False)

    records: list[dict[str, Any]] = []
    skipped_lines = 0
    skipped_class = 0
    for rec, skip_count in read_jsonl_stream(file_paths, progress_callback=on_progress):
        if rec is None:
            skipped_lines = skip_count
            break
        extracted = extract_record(rec)
        if extracted is not None:
            records.append(extracted)
        else:
            skipped_class += 1

    if pbar is not None:
        pbar.close()
    if skipped_lines:
        print(f"Warning: skipped {skipped_lines} invalid JSON line(s).", file=sys.stderr)
    if skipped_class:
        print(f"Warning: skipped {skipped_class} record(s) with classification not bot/browser.", file=sys.stderr)

    STRESS_PATHS = ("/", "/health", "/debug")

    if args.exclude_stress_tests:
        before = len(records)
        records = [
            r
            for r in records
            if not (r.get("user_agent") == "go-http-client" and r.get("path") in STRESS_PATHS)
        ]
        excluded = before - len(records)
        if excluded:
            print(
                f"Excluded {excluded} go-http-client record(s) for {', '.join(STRESS_PATHS)} (stress tests).",
                file=sys.stderr,
            )

    stats = aggregate(
        records,
        sort_by=args.sort,
        filter_significance=not args.no_significance_filter,
    )
    if args.format == "text":
        text = format_text(stats, args.top)
    else:
        text = format_json(stats, args.top)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

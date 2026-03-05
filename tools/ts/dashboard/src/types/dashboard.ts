/**
 * Dashboard JSON contract: time-window aggregates, per-second timeline, and signal stats.
 * Consumed by the dashboard UI; produced by a separate generator (e.g. Python script via cron).
 */

export type TimeWindowKey = "hour" | "day" | "week" | "month" | "all";

export interface TimeWindowStats {
  total: number;
  bot: number;
  browser: number;
  bot_pct?: number;
  browser_pct?: number;
}

export interface TimelinePoint {
  /** Timestamp: Unix seconds or ISO 8601 string */
  t: number | string;
  total: number;
  bot: number;
  browser: number;
}

export interface SignalStat {
  signal_id: string;
  total: number;
  bot: number;
  browser: number;
  bot_pct: number;
  browser_pct: number;
}

/** Behavioral edge thresholds used to compute req_per_min, gap_median, gap_std_mean, gap_mean_median (METHODOLOGY Appendix M). */
export interface BehavioralEdges {
  request_rate_per_min_above: number;
  inter_arrival_median_sec_below: number;
  inter_arrival_std_per_mean_above: number;
  inter_arrival_mean_median_ratio_above: number;
}

export interface DashboardData {
  windows: Record<TimeWindowKey, TimeWindowStats>;
  timeline: TimelinePoint[];
  /** Timeline bucket size in seconds (1, 60, or 600); used for section title. */
  timeline_bucket_sec?: number;
  /** Timeline window in seconds; used for section title. */
  timeline_window_sec?: number;
  signals: SignalStat[];
  /** Edge thresholds used for behavioural signals (from build_dashboard_payload). */
  behavioral_edges?: BehavioralEdges;
}

export function isTimeWindowKey(k: string): k is TimeWindowKey {
  return ["hour", "day", "week", "month", "all"].includes(k);
}

export function isDashboardData(x: unknown): x is DashboardData {
  if (x === null || typeof x !== "object") return false;
  const o = x as Record<string, unknown>;
  if (!o.windows || typeof o.windows !== "object") return false;
  if (!Array.isArray(o.timeline)) return false;
  if (!Array.isArray(o.signals)) return false;
  for (const sig of o.signals as Record<string, unknown>[]) {
    if (!sig || typeof sig !== "object" || typeof sig.signal_id !== "string")
      return false;
  }
  const keys: TimeWindowKey[] = ["hour", "day", "week", "month", "all"];
  for (const k of keys) {
    const w = (o.windows as Record<string, unknown>)[k];
    if (!w || typeof w !== "object") return false;
    const s = w as Record<string, unknown>;
    if (
      typeof s.total !== "number" ||
      typeof s.bot !== "number" ||
      typeof s.browser !== "number"
    )
      return false;
  }
  return true;
}

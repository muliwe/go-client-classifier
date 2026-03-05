import type { DashboardData } from "../types/dashboard";
import { isDashboardData } from "../types/dashboard";

const DEFAULT_URL = "/dashboard.json";

/**
 * Load dashboard JSON from the configured URL (or default).
 * Uses VITE_DASHBOARD_JSON_URL when set at build time.
 */
export function getDashboardJsonUrl(): string {
  const env = import.meta.env?.VITE_DASHBOARD_JSON_URL;
  if (typeof env === "string" && env.trim()) return env.trim();
  return DEFAULT_URL;
}

export type LoadResult =
  | { ok: true; data: DashboardData }
  | { ok: false; error: string };

/**
 * Fetches and parses the dashboard JSON. Performs basic runtime validation.
 */
export async function loadDashboard(): Promise<LoadResult> {
  const url = getDashboardJsonUrl();
  let res: Response;
  try {
    res = await fetch(url);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return { ok: false, error: `Network error: ${message}` };
  }
  if (!res.ok) {
    return { ok: false, error: `HTTP ${res.status}: ${res.statusText}` };
  }
  let raw: unknown;
  try {
    raw = await res.json();
  } catch {
    return { ok: false, error: "Invalid JSON" };
  }
  if (!isDashboardData(raw)) {
    return {
      ok: false,
      error:
        "Invalid dashboard schema: missing or invalid windows/timeline/signals",
    };
  }
  return { ok: true, data: raw };
}

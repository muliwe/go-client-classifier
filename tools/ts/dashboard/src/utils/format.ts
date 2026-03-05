/**
 * Format integer with underscore as thousands separator (Python-style: 1_234_567).
 */
export function formatInt(n: number): string {
  const s = Math.round(n).toString();
  return s.replace(/\B(?=(\d{3})+(?!\d))/g, "_");
}

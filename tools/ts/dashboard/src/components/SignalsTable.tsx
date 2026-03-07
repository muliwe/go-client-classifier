import { useMemo, useState } from "react";
import type { SignalStat } from "../types/dashboard";
import { formatInt } from "../utils/format";
import { BlockWithPipes } from "./BlockWithPipes";
import { SectionFrameTop, SectionFrameBottom } from "./SectionFrame";

type SortKey =
  | "signal_id"
  | "total"
  | "browser"
  | "bot"
  | "browser_pct"
  | "bot_pct";

/** Intensity: browser ≥75% max, bot ≥95% max; 25+ medium; 40–60% neutral; 0 cases dark. */
type SignalIntensity = "dark" | "neutral" | "medium" | "max";

function getSignalCellIntensity(
  s: SignalStat,
  side: "browser" | "bot",
): SignalIntensity {
  if (s.total === 0) return "dark";
  const pct = side === "browser" ? s.browser_pct : s.bot_pct;
  if (side === "browser" && pct >= 75) return "max";
  if (side === "bot" && pct >= 95) return "max";
  if (pct >= 40 && pct <= 60) return "neutral";
  if (pct >= 25) return "medium";
  return "medium";
}

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: "signal_id", label: "signal_id" },
  { key: "total", label: "total" },
  { key: "browser", label: "browser" },
  { key: "bot", label: "bot" },
  { key: "browser_pct", label: "browser%" },
  { key: "bot_pct", label: "bot%" },
];

function sortSignals(
  signals: SignalStat[],
  key: SortKey,
  dir: "asc" | "desc",
): SignalStat[] {
  return [...signals].sort((a, b) => {
    let cmp: number;
    if (key === "signal_id") {
      cmp = (a.signal_id ?? "").localeCompare(b.signal_id ?? "");
    } else {
      const va = a[key] as number;
      const vb = b[key] as number;
      cmp = va - vb;
    }
    return dir === "asc" ? cmp : -cmp;
  });
}

interface SignalsTableProps {
  signals: SignalStat[];
}

export function SignalsTable({ signals }: SignalsTableProps) {
  const [sortKey, setSortKey] = useState<SortKey>("signal_id");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const handleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "signal_id" ? "asc" : "desc");
    }
  };

  const sorted = useMemo(
    () => sortSignals(signals, sortKey, sortDir),
    [signals, sortKey, sortDir],
  );

  if (signals.length === 0) {
    return (
      <section className="dashboard-section" aria-labelledby="signals-heading">
        <h2 id="signals-heading" className="dashboard-section-title">
          <SectionFrameTop title="Signal activation statistics" />
        </h2>
        <BlockWithPipes>
          <p className="dashboard-empty">No signal data.</p>
        </BlockWithPipes>
        <div className="dashboard-section-bottom">
          <SectionFrameBottom />
        </div>
      </section>
    );
  }

  return (
    <section className="dashboard-section" aria-labelledby="signals-heading">
      <h2 id="signals-heading" className="dashboard-section-title">
        <SectionFrameTop title="Signal activation statistics" />
      </h2>
      <BlockWithPipes>
        <div className="signals-table-wrap">
          <table className="signals-table">
            <thead>
              <tr>
                {COLUMNS.map(({ key, label }) => (
                  <th
                    key={key}
                    className="signals-table-th--sortable"
                    onClick={() => handleSort(key)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        handleSort(key);
                      }
                    }}
                    role="button"
                    tabIndex={0}
                    title={`Sort by ${label} (${sortKey === key ? (sortDir === "asc" ? "ascending" : "descending") : key === "signal_id" ? "asc" : "desc"})`}
                  >
                    {key === "browser" ? (
                      <>
                        <span className="signals-table-th-label-full">
                          browser
                        </span>
                        <span className="signals-table-th-label-short">
                          br.
                        </span>
                      </>
                    ) : key === "browser_pct" ? (
                      <>
                        <span className="signals-table-th-label-full">
                          browser%
                        </span>
                        <span className="signals-table-th-label-short">
                          br.%
                        </span>
                      </>
                    ) : (
                      label
                    )}
                    {sortKey === key && (
                      <span className="signals-table-th-sort" aria-hidden>
                        {sortDir === "asc" ? " ▲" : " ▼"}
                      </span>
                    )}
                  </th>
                ))}
                <th className="signals-table-th--spacer" aria-hidden />
              </tr>
            </thead>
            <tbody>
              {sorted.map((s, i) => {
                const isBehavioral = (s.signal_id ?? "").startsWith(
                  "behavioral_",
                );
                const browserIntensity = getSignalCellIntensity(s, "browser");
                const botIntensity = getSignalCellIntensity(s, "bot");
                return (
                  <tr
                    key={s.signal_id}
                    className={
                      (i % 2 === 0
                        ? "signals-table-row--even"
                        : "signals-table-row--odd") +
                      (isBehavioral ? " signals-table-row--behavioral" : "")
                    }
                  >
                    <td className="signals-table-cell--id">
                      <span className="signals-table-cell-id-inner">
                        {String(s.signal_id ?? "")}
                      </span>
                    </td>
                    <td
                      className={
                        s.total === 0
                          ? "signals-table-cell--total signals-table-cell--total--dark"
                          : "signals-table-cell--total"
                      }
                    >
                      {formatInt(s.total)}
                    </td>
                    <td
                      className={`signals-table-cell--browser signals-table-cell--browser--${browserIntensity}`}
                    >
                      {formatInt(s.browser)}
                    </td>
                    <td
                      className={`signals-table-cell--bot signals-table-cell--bot--${botIntensity}`}
                    >
                      {formatInt(s.bot)}
                    </td>
                    <td
                      className={`signals-table-cell--browser signals-table-cell--browser--${browserIntensity}`}
                    >
                      {s.browser_pct.toFixed(1)}%
                    </td>
                    <td
                      className={`signals-table-cell--bot signals-table-cell--bot--${botIntensity}`}
                    >
                      {s.bot_pct.toFixed(1)}%
                    </td>
                    <td className="signals-table-cell--spacer" aria-hidden />
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </BlockWithPipes>
      <div className="dashboard-section-bottom">
        <SectionFrameBottom />
      </div>
    </section>
  );
}

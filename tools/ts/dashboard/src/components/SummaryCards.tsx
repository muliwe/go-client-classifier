import type { DashboardData, TimeWindowKey } from "../types/dashboard";
import { formatInt } from "../utils/format";
import { BlockWithPipes } from "./BlockWithPipes";
import { SectionFrameTop, SectionFrameBottom } from "./SectionFrame";

const WINDOW_LABELS: Record<TimeWindowKey, string> = {
  hour: "Last hour",
  day: "Last 24h",
  week: "Last 7 days",
  month: "Last 30 days",
  all: "All time",
};

interface SummaryCardsProps {
  windows: DashboardData["windows"];
}

export function SummaryCards({ windows }: SummaryCardsProps) {
  const keys: TimeWindowKey[] = ["hour", "day", "week", "month", "all"];
  return (
    <section className="dashboard-section" aria-labelledby="summary-heading">
      <h2 id="summary-heading" className="dashboard-section-title">
        <SectionFrameTop title="Summary by time window" />
      </h2>
      <BlockWithPipes>
        <div className="summary-cards">
          {keys.map((key) => {
            const w = windows[key];
            const botPct = w.bot_pct ?? (w.total ? (100 * w.bot) / w.total : 0);
            const browserPct =
              w.browser_pct ?? (w.total ? (100 * w.browser) / w.total : 0);
            return (
              <div key={key} className="summary-card">
                <BlockWithPipes>
                  <div className="summary-card-inner">
                    <div className="summary-card-title">
                      {WINDOW_LABELS[key]}
                    </div>
                    <div className="summary-card-body">
                      <div className="summary-row">
                        <span className="summary-label">total</span>
                        <span className="summary-value">
                          {formatInt(w.total)}
                        </span>
                      </div>
                      <div className="summary-row">
                        <span className="summary-label">bot</span>
                        <span className="summary-value summary-value--bot">
                          {formatInt(w.bot)} {botPct.toFixed(1)}%
                        </span>
                      </div>
                      <div className="summary-row">
                        <span className="summary-label">browser</span>
                        <span className="summary-value summary-value--browser">
                          {formatInt(w.browser)} {browserPct.toFixed(1)}%
                        </span>
                      </div>
                    </div>
                  </div>
                </BlockWithPipes>
              </div>
            );
          })}
        </div>
      </BlockWithPipes>
      <div className="dashboard-section-bottom">
        <SectionFrameBottom />
      </div>
    </section>
  );
}

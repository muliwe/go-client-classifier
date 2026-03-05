import { useLayoutEffect, useRef, useState } from "react";
import type { TimelinePoint } from "../types/dashboard";
import { formatInt } from "../utils/format";
import { BlockWithPipes } from "./BlockWithPipes";
import { SectionFrameTop, SectionFrameBottom } from "./SectionFrame";

interface TimelineProps {
  points: TimelinePoint[];
  /** Window length in seconds (from payload); used for section title. */
  timelineWindowSec?: number;
  /** Bucket size in seconds (10, 60, 600); used for section title. */
  timelineBucketSec?: number;
}

/** Build timeline section title from payload meta (window + bucket). */
function timelineTitle(
  windowSec: number | undefined,
  bucketSec: number | undefined,
): string {
  const w = windowSec ?? 600;
  const b = bucketSec ?? 10;
  const minutes = Math.round(w / 60);
  const hours = w / 3600;
  if (hours >= 1 && Math.abs(hours - Math.round(hours)) < 0.01) {
    const h = Math.round(hours);
    if (b === 60)
      return `Timeline (last ${h} hour${h > 1 ? "s" : ""}, by minute)`;
    if (b === 600)
      return `Timeline (last ${h} hour${h > 1 ? "s" : ""}, by 10 min)`;
  }
  if (b === 10) return `Timeline (last ${minutes} minutes, by 10 sec)`;
  if (b === 60) return `Timeline (last ${minutes} minutes, by minute)`;
  if (b === 600) return `Timeline (last ${minutes} minutes, by 10 min)`;
  return `Timeline (last ${minutes} minutes)`;
}

/** Normalise t to a number (Unix seconds) for comparison. */
function toSeconds(t: number | string): number {
  if (typeof t === "number") return t;
  const n = Date.parse(t);
  return Number.isNaN(n) ? 0 : n / 1000;
}

/** Format t as HH:MM:SS or HH:MM (no seconds when bucketSec >= 60). */
function formatTime(t: number | string, bucketSec?: number): string {
  const sec = toSeconds(t);
  const s = new Date(sec * 1000).toTimeString();
  return bucketSec != null && bucketSec >= 60 ? s.slice(0, 5) : s.slice(0, 8);
}

export function Timeline({
  points,
  timelineWindowSec,
  timelineBucketSec,
}: TimelineProps) {
  const title = timelineTitle(timelineWindowSec, timelineBucketSec);
  const chartRef = useRef<HTMLDivElement>(null);
  const chRulerRef = useRef<HTMLSpanElement>(null);
  const [maxBarChars, setMaxBarChars] = useState(50);

  useLayoutEffect(() => {
    const chartEl = chartRef.current;
    const rulerEl = chRulerRef.current;
    if (!chartEl || !rulerEl) return;

    const update = () => {
      const chartWidth = chartEl.getBoundingClientRect().width;
      const chWidth = rulerEl.getBoundingClientRect().width;
      if (chWidth <= 0) return;
      const n = Math.floor((chartWidth * 0.6) / chWidth);
      setMaxBarChars(Math.max(0, n));
    };

    update();
    const ro = new ResizeObserver(update);
    ro.observe(chartEl);
    return () => ro.disconnect();
  }, []);

  if (points.length === 0) {
    return (
      <section className="dashboard-section" aria-labelledby="timeline-heading">
        <h2 id="timeline-heading" className="dashboard-section-title">
          <SectionFrameTop title={title} />
        </h2>
        <BlockWithPipes>
          <p className="dashboard-empty">No timeline data.</p>
        </BlockWithPipes>
        <div className="dashboard-section-bottom">
          <SectionFrameBottom />
        </div>
      </section>
    );
  }

  const sorted = [...points].sort((a, b) => toSeconds(b.t) - toSeconds(a.t));
  const maxTotal = Math.max(1, ...sorted.map((p) => p.total || 0));

  return (
    <section className="dashboard-section" aria-labelledby="timeline-heading">
      <h2 id="timeline-heading" className="dashboard-section-title">
        <SectionFrameTop title={title} />
      </h2>
      <BlockWithPipes>
        <div ref={chartRef} className="timeline-chart">
          <span
            ref={chRulerRef}
            className="timeline-chart-ruler"
            aria-hidden="true"
          >
            █
          </span>
          <div className="timeline-legend">
            <span className="timeline-legend-item timeline-legend-item--browser">
              {"\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0\u00A0 "}■
              browser
            </span>
            <span className="timeline-legend-item timeline-legend-item--bot">
              {"\u00A0 "}■ bot
            </span>
          </div>
          <div className="timeline-bars">
            {sorted.map((p, i) => {
              const isEmpty = (p.total ?? 0) === 0;
              if (isEmpty) {
                return (
                  <div
                    key={i}
                    className="timeline-bar-row"
                    title={`t=${p.t} total=0`}
                  >
                    <span className="timeline-bar-time">
                      {"\u00A0"}
                      {formatTime(p.t, timelineBucketSec)}
                    </span>
                    <span
                      className="timeline-bar-empty"
                      style={{ width: `${maxBarChars}ch` }}
                    />
                  </div>
                );
              }
              const total = p.total || 1;
              const totalBarChars = Math.round(
                (maxBarChars * total) / maxTotal,
              );
              const browserChars =
                totalBarChars > 0
                  ? Math.round((totalBarChars * p.browser) / total)
                  : 0;
              const botChars = totalBarChars - browserChars;
              const browserPct = total > 0 ? (100 * p.browser) / total : 0;
              const botPct = total > 0 ? (100 * p.bot) / total : 0;
              return (
                <div
                  key={i}
                  className="timeline-bar-row"
                  title={`t=${p.t} total=${p.total} bot=${p.bot} browser=${p.browser}`}
                >
                  <span className="timeline-bar-time">
                    {"\u00A0"}
                    {formatTime(p.t, timelineBucketSec)}
                  </span>
                  <span className="timeline-char timeline-char--browser">
                    {"█".repeat(browserChars)}
                  </span>
                  <span className="timeline-char timeline-char--bot">
                    {"█".repeat(botChars)}
                  </span>
                  <span className="timeline-bar-legend">
                    {" "}
                    <span className="timeline-char timeline-char--browser">
                      {formatInt(p.browser)}
                    </span>
                    /
                    <span className="timeline-char timeline-char--bot">
                      {formatInt(p.bot)}
                    </span>{" "}
                    <span className="timeline-char timeline-char--browser">
                      {browserPct.toFixed(0)}%
                    </span>
                    /
                    <span className="timeline-char timeline-char--bot">
                      {botPct.toFixed(0)}%
                    </span>
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </BlockWithPipes>
      <div className="dashboard-section-bottom">
        <SectionFrameBottom />
      </div>
    </section>
  );
}

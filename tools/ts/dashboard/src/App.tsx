import { useEffect, useState } from "react";
import { loadDashboard, type LoadResult } from "./api/loadDashboard";
import { SectionFrameTop } from "./components/SectionFrame";
import { formatInt } from "./utils/format";
import { SummaryCards } from "./components/SummaryCards";
import { Timeline } from "./components/Timeline";
import { SignalsTable } from "./components/SignalsTable";
import { BehavioralEdgesBlock } from "./components/BehavioralEdgesBlock";
import type { DashboardData } from "./types/dashboard";
import "./App.css";

const DEFAULT_BUCKET_SEC = 10;

function formatRefreshInterval(bucketSec: number): string {
  const sec = Math.round(bucketSec / 2);
  if (sec < 60) return `${sec} sec`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min`;
  return `${Math.round(min / 60)} h`;
}

export default function App() {
  const [result, setResult] = useState<LoadResult | null>(null);

  useEffect(() => {
    let cancelled = false;
    loadDashboard().then((r) => {
      if (!cancelled) setResult(r);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!result?.ok) return;
    const bucketSec = result.data.timeline_bucket_sec ?? DEFAULT_BUCKET_SEC;
    const delayMs = (bucketSec / 2) * 1000;
    const id = setTimeout(() => {
      loadDashboard().then(setResult);
    }, delayMs);
    return () => clearTimeout(id);
  }, [result]);

  if (result === null) {
    return (
      <div className="dashboard-root">
        <header className="dashboard-header">
          <h1>Bot Detector Dashboard</h1>
        </header>
        <main className="dashboard-main">
          <p className="dashboard-message dashboard-message--loading">
            Loading…
          </p>
        </main>
      </div>
    );
  }

  if (!result.ok) {
    return (
      <div className="dashboard-root">
        <header className="dashboard-header">
          <h1>Bot Detector Dashboard</h1>
        </header>
        <main className="dashboard-main">
          <p className="dashboard-message dashboard-message--error">
            {result.error}
          </p>
        </main>
      </div>
    );
  }

  const data: DashboardData = result.data;
  const bucketSec = data.timeline_bucket_sec ?? DEFAULT_BUCKET_SEC;
  const refreshLabel = formatRefreshInterval(bucketSec);
  return (
    <div className="dashboard-root">
      <header className="dashboard-header">
        <h1 className="dashboard-header-title">
          <SectionFrameTop title="Bot Detector Dashboard" />
        </h1>
        <p className="dashboard-header-meta">
          &nbsp;Data loaded. Total {formatInt(data.windows.all.total)} requests.
          Auto-refresh every {refreshLabel}.{" "}
          <span className="dashboard-header-cursor" aria-hidden="true">
            ▌
          </span>
        </p>
      </header>
      <main className="dashboard-main">
        <SummaryCards windows={data.windows} />
        <Timeline
          points={data.timeline}
          timelineWindowSec={data.timeline_window_sec}
          timelineBucketSec={data.timeline_bucket_sec}
        />
        <SignalsTable signals={data.signals} />
        {data.behavioral_edges && (
          <BehavioralEdgesBlock edges={data.behavioral_edges} />
        )}
      </main>
    </div>
  );
}

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
const RETRY_INTERVAL_MS = 60_000;

function formatRefreshInterval(bucketSec: number): string {
  const sec = Math.round(bucketSec / 2);
  if (sec < 60) return `${sec} sec`;
  const min = Math.round(sec / 60);
  if (min < 60) return `${min} min`;
  return `${Math.round(min / 60)} h`;
}

function formatDataAge(ageMs: number): string {
  const totalMin = Math.max(0, Math.floor(ageMs / 60_000));
  const hours = Math.floor(totalMin / 60);
  const minutes = totalMin % 60;
  return `${hours} h ${String(minutes).padStart(2, "0")} min old`;
}

export default function App() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const [viewportKey, setViewportKey] = useState(
    () => `${window.innerWidth}x${window.innerHeight}`,
  );

  useEffect(() => {
    const onResize = () =>
      setViewportKey(`${window.innerWidth}x${window.innerHeight}`);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const schedule = (delayMs: number) => {
      timer = setTimeout(() => {
        loadDashboard().then((r: LoadResult) => {
          if (cancelled) return;
          if (r.ok) {
            setData(r.data);
            setLoadedAt(Date.now());
            setError(null);
            const bucketSec =
              r.data.timeline_bucket_sec ?? DEFAULT_BUCKET_SEC;
            schedule((bucketSec / 2) * 1000);
            return;
          }
          setNow(Date.now());
          setError(r.error);
          schedule(RETRY_INTERVAL_MS);
        });
      }, delayMs);
    };

    schedule(0);
    return () => {
      cancelled = true;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, []);

  const stale = data !== null && error !== null && loadedAt !== null;

  useEffect(() => {
    if (!stale || loadedAt === null) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [stale, loadedAt]);

  if (data === null && error === null) {
    return (
      <div className="dashboard-root">
        <header className="dashboard-header">
          <h1 className="dashboard-header-title">
            <SectionFrameTop title="Bot Detector Dashboard" />
          </h1>
          <p className="dashboard-header-line">
            <a
              href="https://github.com/muliwe/go-client-classifier/"
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub
            </a>
            {" · "}
            <a
              href="https://antibot.invent.sale/"
              target="_blank"
              rel="noopener noreferrer"
            >
              https://antibot.invent.sale/
            </a>
          </p>
        </header>
        <main className="dashboard-main">
          <p className="dashboard-message dashboard-message--loading">
            Loading…
          </p>
        </main>
      </div>
    );
  }

  if (data === null) {
    return (
      <div className="dashboard-root">
        <header className="dashboard-header">
          <h1 className="dashboard-header-title">
            <SectionFrameTop title="Bot Detector Dashboard" />
          </h1>
          <p className="dashboard-header-line">
            <a
              href="https://github.com/muliwe/go-client-classifier/"
              target="_blank"
              rel="noopener noreferrer"
            >
              GitHub
            </a>
            {" · "}
            <a
              href="https://antibot.invent.sale/"
              target="_blank"
              rel="noopener noreferrer"
            >
              https://antibot.invent.sale/
            </a>
          </p>
        </header>
        <main className="dashboard-main">
          <p className="dashboard-message dashboard-message--error">
            {error}
            <br />
            Retrying every 1 min…
          </p>
        </main>
      </div>
    );
  }

  const bucketSec = data.timeline_bucket_sec ?? DEFAULT_BUCKET_SEC;
  const refreshLabel = formatRefreshInterval(bucketSec);
  const ageLabel =
    stale && loadedAt !== null ? formatDataAge(now - loadedAt) : null;
  return (
    <div className="dashboard-root">
      <header className="dashboard-header">
        {ageLabel && (
          <p className="dashboard-stale" role="status">
            <span className="dashboard-stale-badge">▲ stale · {ageLabel}</span>
          </p>
        )}
        <h1 className="dashboard-header-title">
          <SectionFrameTop title="Bot Detector Dashboard" />
        </h1>
        <p className="dashboard-header-line">
          &nbsp;&nbsp;
          <a
            href="https://github.com/muliwe/go-client-classifier/"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub
          </a>
          {" · "}
          <a
            href="https://antibot.invent.sale/"
            target="_blank"
            rel="noopener noreferrer"
          >
            https://antibot.invent.sale/
          </a>
          {" · "}
          Data loaded {" · "} Total {formatInt(data.windows.all.total)}{" "}
          request(s) {" · "}
          Auto-refresh every&nbsp;&nbsp;{refreshLabel}{" "}
          <span className="dashboard-header-cursor" aria-hidden="true">
            ▌
          </span>
          <br />
          <br />
        </p>
      </header>
      <main className="dashboard-main" key={viewportKey}>
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

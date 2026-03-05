/**
 * Terminal-style frame: the horizontal line is drawn with the box-drawing character "─"
 * repeated so that it fills the available width, as in a real terminal (columns-based).
 * Width is measured with ResizeObserver; character count is derived from container width
 * and monospace character width.
 */

import { useLayoutEffect, useRef, useState } from "react";

const DASH = "─";

function useFillDashes() {
  const lineRef = useRef<HTMLDivElement>(null);
  const charRef = useRef<HTMLSpanElement>(null);
  const [dashCount, setDashCount] = useState(0);

  useLayoutEffect(() => {
    const lineEl = lineRef.current;
    const charEl = charRef.current;
    if (!lineEl || !charEl) return;

    const update = () => {
      const lineWidth = lineEl.getBoundingClientRect().width;
      const charWidth = charEl.getBoundingClientRect().width;
      if (charWidth <= 0) return;
      const n = Math.floor(lineWidth / charWidth);
      setDashCount(Math.max(0, n));
    };

    update();
    const ro = new ResizeObserver(update);
    ro.observe(lineEl);
    return () => ro.disconnect();
  }, []);

  return { lineRef, charRef, dashCount };
}

interface SectionFrameTopProps {
  title: string;
}

export function SectionFrameTop({ title }: SectionFrameTopProps) {
  const { lineRef, charRef, dashCount } = useFillDashes();

  return (
    <div
      className="dashboard-section-frame dashboard-section-frame--top"
      role="presentation"
    >
      <span className="dashboard-section-frame-start" aria-hidden="true">
        ┌─ {title}{" "}
      </span>
      <div
        ref={lineRef}
        className="dashboard-section-frame-line"
        aria-hidden="true"
      >
        <span
          ref={charRef}
          className="dashboard-section-frame-char-ruler"
          aria-hidden="true"
        >
          {DASH}
        </span>
        <span className="dashboard-section-frame-dashes">
          {DASH.repeat(dashCount)}
        </span>
      </div>
      <span className="dashboard-section-frame-end" aria-hidden="true">
        ┐
      </span>
    </div>
  );
}

export function SectionFrameBottom() {
  const { lineRef, charRef, dashCount } = useFillDashes();

  return (
    <div
      className="dashboard-section-frame dashboard-section-frame--bottom"
      role="presentation"
    >
      <span className="dashboard-section-frame-start" aria-hidden="true">
        └
      </span>
      <div
        ref={lineRef}
        className="dashboard-section-frame-line"
        aria-hidden="true"
      >
        <span
          ref={charRef}
          className="dashboard-section-frame-char-ruler"
          aria-hidden="true"
        >
          {DASH}
        </span>
        <span className="dashboard-section-frame-dashes">
          {DASH.repeat(dashCount)}
        </span>
      </div>
      <span className="dashboard-section-frame-end" aria-hidden="true">
        ┘
      </span>
    </div>
  );
}

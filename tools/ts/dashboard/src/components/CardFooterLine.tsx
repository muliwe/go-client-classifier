/**
 * Card footer line: "─" repeated to fill the container width (monospace).
 */

import { useLayoutEffect, useRef, useState } from "react";

const DASH = "─";

export function CardFooterLine() {
  const containerRef = useRef<HTMLDivElement>(null);
  const charRef = useRef<HTMLSpanElement>(null);
  const [dashCount, setDashCount] = useState(0);

  useLayoutEffect(() => {
    const containerEl = containerRef.current;
    const charEl = charRef.current;
    if (!containerEl || !charEl) return;

    const update = () => {
      const containerWidth = containerEl.getBoundingClientRect().width;
      const chWidth = charEl.getBoundingClientRect().width;
      if (chWidth <= 0) return;
      const n = Math.floor(containerWidth / chWidth);
      setDashCount(Math.max(0, n));
    };

    update();
    const ro = new ResizeObserver(update);
    ro.observe(containerEl);
    return () => ro.disconnect();
  }, []);

  return (
    <div ref={containerRef} className="summary-card-footer">
      <span
        ref={charRef}
        className="summary-card-footer-ruler"
        aria-hidden="true"
      >
        {DASH}
      </span>
      {DASH.repeat(dashCount)}
    </div>
  );
}

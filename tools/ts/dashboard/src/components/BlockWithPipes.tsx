/**
 * Wraps block content with vertical pipe (│) borders on the left and right.
 * The number of pipes is computed from the content container height and line-height.
 */

import { useLayoutEffect, useRef, useState } from "react";

const PIPE = "│";

interface BlockWithPipesProps {
  children: React.ReactNode;
  className?: string;
}

export function BlockWithPipes({
  children,
  className = "",
}: BlockWithPipesProps) {
  const contentRef = useRef<HTMLDivElement>(null);
  const lineRulerRef = useRef<HTMLSpanElement>(null);
  const [pipeCount, setPipeCount] = useState(0);

  useLayoutEffect(() => {
    const contentEl = contentRef.current;
    const rulerEl = lineRulerRef.current;
    if (!contentEl || !rulerEl) return;

    const update = () => {
      const contentHeight = contentEl.getBoundingClientRect().height;
      const lineHeight = rulerEl.getBoundingClientRect().height;
      if (lineHeight <= 0) return;
      const n = Math.ceil(contentHeight / lineHeight);
      setPipeCount(Math.max(0, n));
    };

    update();
    const ro = new ResizeObserver(update);
    ro.observe(contentEl);
    return () => ro.disconnect();
  }, []);

  const pipeColumn =
    pipeCount > 0
      ? Array.from({ length: pipeCount }, () => PIPE).join("\n")
      : "";

  return (
    <div
      className={`dashboard-block-with-pipes ${className}`.trim()}
      role="presentation"
    >
      <div className="dashboard-block-pipe dashboard-block-pipe--left">
        <span
          ref={lineRulerRef}
          className="dashboard-block-pipe-ruler"
          aria-hidden="true"
        >
          {PIPE}
        </span>
        <span className="dashboard-block-pipe-text" aria-hidden="true">
          {pipeColumn}
        </span>
      </div>
      <div ref={contentRef} className="dashboard-block-content">
        {children}
      </div>
      <div className="dashboard-block-pipe dashboard-block-pipe--right">
        <span className="dashboard-block-pipe-text" aria-hidden="true">
          {pipeColumn}
        </span>
      </div>
    </div>
  );
}

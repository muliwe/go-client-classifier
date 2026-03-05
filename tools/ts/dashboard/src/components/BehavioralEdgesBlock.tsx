import type { BehavioralEdges } from "../types/dashboard";
import { BlockWithPipes } from "./BlockWithPipes";
import { SectionFrameTop, SectionFrameBottom } from "./SectionFrame";

interface BehavioralEdgesBlockProps {
  edges: BehavioralEdges;
}

/** Labels and direction for each edge (METHODOLOGY Appendix M). */
const EDGE_ROWS: {
  key: keyof BehavioralEdges;
  label: string;
  direction: ">" | "<";
}[] = [
  {
    key: "request_rate_per_min_above",
    label: "request_rate_per_min",
    direction: ">",
  },
  {
    key: "inter_arrival_median_sec_below",
    label: "inter_arrival_median_sec",
    direction: "<",
  },
  {
    key: "inter_arrival_std_per_mean_above",
    label: "inter_arrival_std_per_mean",
    direction: ">",
  },
  {
    key: "inter_arrival_mean_median_ratio_above",
    label: "inter_arrival_mean_median_ratio",
    direction: ">",
  },
];

export function BehavioralEdgesBlock({ edges }: BehavioralEdgesBlockProps) {
  return (
    <section
      className="dashboard-section"
      aria-labelledby="behavioral-edges-heading"
    >
      <h2 id="behavioral-edges-heading" className="dashboard-section-title">
        <SectionFrameTop title="Behavioral edges (signal if)" />
      </h2>
      <BlockWithPipes>
        <div className="behavioral-edges-wrap">
          {EDGE_ROWS.map(({ key, label, direction }) => (
            <div key={key} className="behavioral-edges-row">
              <span className="behavioral-edges-label">
                {"\u00A0"}
                {label}
              </span>
              <span className="behavioral-edges-op">{direction}</span>
              <span className="behavioral-edges-value">
                {String(edges[key])}
              </span>
            </div>
          ))}
        </div>
      </BlockWithPipes>
      <div className="dashboard-section-bottom">
        <SectionFrameBottom />
      </div>
    </section>
  );
}

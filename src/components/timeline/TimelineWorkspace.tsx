import { useEffect, useRef, useState } from "react";
import { useTimelineStore } from "../../stores/timeline-store";
import { useLaneBuckets } from "./hooks/useLaneBuckets";
import { SwimLaneCanvas } from "./SwimLaneCanvas";
import { LaneLegend } from "./LaneLegend";
import { IncidentChipBar } from "./IncidentChipBar";
import { IncidentDetailPanel } from "./IncidentDetailPanel";
import { TimelineRuler } from "./TimelineRuler";
import { BrushOverlay } from "./BrushOverlay";
import { LogListView } from "../log-view/LogListView";
import { timelineLogListDataSource } from "./log-list-adapter";

const LANE_HEIGHT = 22;

export function TimelineWorkspace() {
  const bundle = useTimelineStore((s) => s.bundle);
  const laneVisibility = useTimelineStore((s) => s.laneVisibility);
  const soloSourceIdx = useTimelineStore((s) => s.soloSourceIdx);
  const [hover, setHover] = useState<string | null>(null);

  // Resize-observer for lane width so the canvas/ruler/brush all match.
  const laneBoxRef = useRef<HTMLDivElement>(null);
  const [laneWidth, setLaneWidth] = useState(800);
  useEffect(() => {
    const el = laneBoxRef.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const w = Math.floor(entry.contentRect.width);
        if (w > 0) setLaneWidth(w);
      }
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const buckets = useLaneBuckets(
    Math.max(100, Math.min(800, Math.floor(laneWidth))),
  );

  if (!bundle) {
    return (
      <div style={{ padding: 40, textAlign: "center", color: "#6b7280" }}>
        Timeline is empty. Open a folder via File → New Timeline from Folder…
      </div>
    );
  }

  const visibleCount = bundle.sources.filter(
    (s) =>
      (soloSourceIdx == null || s.idx === soloSourceIdx) &&
      laneVisibility[s.idx] !== false,
  ).length;
  const laneAreaHeight = Math.max(LANE_HEIGHT, visibleCount * LANE_HEIGHT);

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "1fr 340px",
        gridTemplateRows: "auto auto auto 1fr",
        height: "100%",
      }}
    >
      <LaneLegend />
      <div />
      <IncidentChipBar />
      <div />
      <div
        ref={laneBoxRef}
        style={{
          position: "relative",
          borderTop: "1px solid #e5e7eb",
          borderBottom: "1px solid #e5e7eb",
          padding: "0 0 2px 0",
        }}
      >
        <TimelineRuler timeRangeMs={bundle.timeRangeMs} width={laneWidth} />
        <SwimLaneCanvas
          sources={bundle.sources}
          buckets={buckets}
          timeRangeMs={bundle.timeRangeMs}
          width={laneWidth}
          laneHeight={LANE_HEIGHT}
          laneVisibility={laneVisibility}
          soloSourceIdx={soloSourceIdx}
          onBucketHover={(b) =>
            setHover(
              b ? `${b.totalCount} rows · ${b.errorCount} errors` : null,
            )
          }
        />
        <BrushOverlay
          timeRangeMs={bundle.timeRangeMs}
          width={laneWidth}
          height={20 + laneAreaHeight}
        />
        {hover && (
          <div
            style={{
              position: "absolute",
              right: 8,
              top: 2,
              fontSize: 10,
              color: "#6b7280",
              background: "#fff",
              padding: "1px 4px",
              pointerEvents: "none",
            }}
          >
            {hover}
          </div>
        )}
      </div>
      <div />
      <LogListView dataSource={timelineLogListDataSource} />
      <IncidentDetailPanel />
    </div>
  );
}

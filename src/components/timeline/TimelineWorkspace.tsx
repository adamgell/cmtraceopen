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
import { buildTimelineFromSources } from "./hooks/useTimelineBundle";

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

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "copy";
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files);
    const paths = files
      .map((f) => (f as File & { path?: string }).path)
      .filter((p): p is string => typeof p === "string" && p.length > 0);
    if (paths.length === 0) return;
    const existing =
      useTimelineStore.getState().bundle?.sources.map((s) => s.path) ?? [];
    const merged = Array.from(new Set([...existing, ...paths])).map(
      (path) => ({ path }),
    );
    try {
      await buildTimelineFromSources(merged);
    } catch (err) {
      console.error("[timeline] failed to add sources to timeline", err);
    }
  };

  if (!bundle) {
    return (
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        style={{
          padding: 40,
          textAlign: "center",
          color: "#6b7280",
          border: "2px dashed #d1d5db",
          margin: 40,
          borderRadius: 8,
        }}
      >
        <div style={{ fontSize: 14, marginBottom: 6 }}>
          Drop log files here
        </div>
        <div style={{ fontSize: 11 }}>
          Or use File → New Timeline from Folder…
        </div>
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
      onDrop={handleDrop}
      onDragOver={handleDragOver}
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

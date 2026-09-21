import { useEffect, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
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
  const loadError = useTimelineStore((s) => s.loadError);
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
    try {
      const { openTimelineFiles } = await import(
        "../../workspaces/timeline/open-timeline-source"
      );
      await openTimelineFiles(paths);
    } catch (error) {
      console.error("[timeline] failed to add sources to timeline", error);
      useTimelineStore
        .getState()
        .setLoadError(error instanceof Error ? error.message : String(error));
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
          color: tokens.colorNeutralForeground3,
          border: `2px dashed ${tokens.colorNeutralStroke1}`,
          margin: 40,
          borderRadius: 8,
        }}
      >
        {loadError && (
          <div
            role="alert"
            style={{
              marginBottom: 8,
              color: tokens.colorPaletteRedForeground1,
              fontSize: 12,
            }}
          >
            {loadError}
          </div>
        )}
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
  const hasLoadAlerts = Boolean(loadError) || bundle.errors.length > 0;

  return (
    <div
      onDrop={handleDrop}
      onDragOver={handleDragOver}
      style={{
        position: "relative",
        display: "grid",
        gridTemplateColumns: "1fr 340px",
        gridTemplateRows: hasLoadAlerts
          ? "auto auto auto auto 1fr"
          : "auto auto auto 1fr",
        height: "100%",
      }}
    >
      {hasLoadAlerts && (
        <div
          style={{
            gridColumn: "1 / -1",
            padding: "6px 10px",
            color: tokens.colorPaletteRedForeground1,
            background: tokens.colorNeutralBackground1,
            border: `1px solid ${tokens.colorPaletteRedBorder2}`,
            fontSize: 12,
            maxHeight: 120,
            overflowY: "auto",
          }}
        >
          {loadError && <div role="alert">{loadError}</div>}
          {bundle.errors.length > 0 && (
            <div role="alert" aria-label="Timeline source errors">
              <strong>
                {bundle.errors.length} timeline source
                {bundle.errors.length === 1 ? "" : "s"} could not be loaded
              </strong>
              <ul style={{ margin: "4px 0 0", paddingLeft: 20 }}>
                {bundle.errors.map((error, index) => (
                  <li key={`${error.path}:${index}`}>
                    <code>{error.path}</code>: {error.message}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
      <LaneLegend />
      <div />
      <IncidentChipBar />
      <div />
      <div
        ref={laneBoxRef}
        style={{
          position: "relative",
          borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
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
              color: tokens.colorNeutralForeground3,
              background: tokens.colorNeutralBackground1,
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

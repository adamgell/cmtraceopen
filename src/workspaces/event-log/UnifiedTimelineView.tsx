import { useMemo, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";

import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { formatEventTime } from "./evtx-time";
import { useEvtxStore } from "./evtx-store";
import {
  isEventOrigin,
  originContext,
  originDetail,
  originLabel,
  timelineCounts,
  unplacedSummary,
  type TimelineCorrelationEdge,
  type TimelineSeverity,
  type UnifiedTimeline,
} from "./unified-timeline";

const UNPLACED_PREVIEW_LIMIT = 100;

const SEVERITY_COLORS: Record<TimelineSeverity, string> = {
  critical: tokens.colorPaletteRedForeground1,
  error: tokens.colorPaletteRedForeground1,
  warning: tokens.colorPaletteMarigoldForeground1,
  info: tokens.colorBrandForeground1,
  verbose: tokens.colorNeutralForeground4,
};

function correlationEdgeLabel(edge: TimelineCorrelationEdge): string {
  return `${edge.strength} · ${edge.confidence} · ${edge.key.kind}: ${edge.key.value}`;
}

export interface UnifiedTimelineViewProps {
  timeline: UnifiedTimeline;
  pending?: boolean;
}

/**
 * The merged view of events and text logs.
 *
 * Rows carry a source badge because the whole value of the view is knowing, at a glance, which
 * side of the merge a line came from. Without it the two blur together and the reader loses the
 * distinction that makes the correlation meaningful.
 */
export function UnifiedTimelineView({ timeline, pending = false }: UnifiedTimelineViewProps) {
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: timeline.items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => metrics.rowHeight + 2,
    overscan: 12,
  });

  const counts = useMemo(() => timelineCounts(timeline), [timeline]);
  const correlationEdges = timeline.edges ?? [];
  const coverageGaps = timeline.coverageGaps ?? [];
  const correlationCounts = useMemo(() => {
    const result = { exact: 0, candidate: 0, ambiguous: 0 };
    for (const edge of correlationEdges) result[edge.strength] += 1;
    return result;
  }, [correlationEdges]);
  const coverageGapCount = coverageGaps.length;
  const dropped = useMemo(() => unplacedSummary(timeline), [timeline]);
  const unplacedCount = timeline.unplaced.length;
  const unplacedPreview = timeline.unplaced.slice(0, UNPLACED_PREVIEW_LIMIT);
  const unplacedOmittedCount = unplacedCount - unplacedPreview.length;

  const fontSize = metrics.fontSize;
  const smallFontSize = Math.max(9, fontSize - 3);
  const monoFontSize = Math.max(10, fontSize - 1);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          padding: "4px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground2,
          fontSize: `${smallFontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
          color: tokens.colorNeutralForeground3,
          flexShrink: 0,
        }}
      >
        <span>{counts.logs.toLocaleString()} log lines</span>
        <span>{counts.events.toLocaleString()} events</span>
        {/* Only shown when something was actually dropped; a "0 unplaced" badge would read as
            reassurance and invite no attention. */}
        {dropped && (
          <span
            style={{ color: tokens.colorPaletteMarigoldForeground1 }}
            title="These carried no timestamp, so placing them would invent a sequence the evidence does not support"
          >
            {dropped}
          </span>
        )}
        {correlationCounts.exact > 0 && (
          <span title="Unique explicit identity matches within one normalized machine">
            exact {correlationCounts.exact}
          </span>
        )}
        {correlationCounts.candidate > 0 && (
          <span
            style={{ color: tokens.colorNeutralForeground4 }}
            title="Secondary identity only; not a causal relationship"
          >
            candidate {correlationCounts.candidate}
          </span>
        )}
        {correlationCounts.ambiguous > 0 && (
          <span
            style={{ color: tokens.colorPaletteMarigoldForeground1 }}
            title="Contradictory or duplicate exact candidates remain unresolved"
          >
            ambiguous {correlationCounts.ambiguous}
          </span>
        )}
        {coverageGapCount > 0 && (
          <span
            style={{ color: tokens.colorPaletteMarigoldForeground1 }}
            title="Missing or unsupported identity coverage prevents a stronger conclusion"
          >
            coverage gaps {coverageGapCount}
          </span>
        )}
      </div>
      {(correlationEdges.length > 0 || coverageGaps.length > 0) && (
        <div
          role="region"
          aria-label="Correlation details"
          style={{
            display: "grid",
            gap: "4px",
            padding: "6px 12px",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground2,
            fontSize: `${smallFontSize}px`,
            fontFamily: LOG_UI_FONT_FAMILY,
            flexShrink: 0,
          }}
        >
          {correlationEdges.map((edge) => (
            <div
              key={edge.id}
              data-testid="correlation-edge"
              style={{
                display: "grid",
                gap: "2px",
                padding: "4px 6px",
                borderLeft: `3px solid ${
                  edge.strength === "ambiguous"
                    ? tokens.colorPaletteMarigoldForeground1
                    : tokens.colorNeutralStroke2
                }`,
              }}
            >
              <span>
                {correlationEdgeLabel(edge)}
              </span>
              <span>
                from: {edge.fromId} → {edge.toId ?? "unresolved"}
              </span>
              {edge.candidateIds.length > 0 && (
                <span>candidate IDs: {edge.candidateIds.join(", ")}</span>
              )}
              {edge.evidence.map((evidence) => (
                <span key={`${edge.id}-${evidence.originId}-${evidence.field}`}>
                  {evidence.field}: {evidence.value} ({evidence.originId})
                </span>
              ))}
              {edge.coverage.gap && (
                <span>
                  coverage reason: {edge.coverage.gap.reason} ({edge.coverage.gap.source})
                </span>
              )}
            </div>
          ))}
          {coverageGaps.map((gap) => (
            <div key={`${gap.source}-${gap.reason}`} data-testid="correlation-gap">
              coverage: {gap.reason} ({gap.source})
            </div>
          ))}
        </div>
      )}

      {timeline.items.length === 0 ? (
        <div
          style={{
            padding: "24px",
            textAlign: "center",
            color: tokens.colorNeutralForeground3,
            fontSize: `${fontSize}px`,
            fontFamily: LOG_UI_FONT_FAMILY,
            overflowY: "auto",
          }}
        >
          {pending ? (
            "Building the unified timeline..."
          ) : timeline.unplaced.length === 0 ? (
            "Nothing to place on the timeline yet. Load a log file and an event source to correlate them."
          ) : (
            <>
              <div style={{ marginBottom: "16px", fontWeight: 600 }}>{dropped}</div>
              <div
                role="list"
                aria-label="Unplaced timeline entries"
                style={{
                  display: "grid",
                  gap: "4px",
                  margin: "0 auto",
                  maxWidth: "1100px",
                  textAlign: "left",
                }}
              >
                {unplacedPreview.map((entry, index) => (
                  <div
                    key={`${originDetail(entry.origin)}-${index}`}
                    role="listitem"
                    title={originDetail(entry.origin)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "10px",
                      padding: "6px 8px",
                      border: `1px solid ${tokens.colorNeutralStroke2}`,
                      backgroundColor: tokens.colorNeutralBackground2,
                      fontSize: `${smallFontSize}px`,
                      textAlign: "left",
                    }}
                  >
                    <span
                      style={{
                        width: "70px",
                        flexShrink: 0,
                        fontWeight: 700,
                        color: tokens.colorPaletteMarigoldForeground1,
                      }}
                    >
                      {isEventOrigin(entry.origin) ? "UNPLACED EVT" : "UNPLACED LOG"}
                    </span>
                    <span
                      style={{
                        width: "220px",
                        flexShrink: 0,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}
                    >
                      {originLabel(entry.origin)}
                    </span>
                    <span
                      style={{
                        width: "220px",
                        flexShrink: 0,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: tokens.colorNeutralForeground4,
                      }}
                    >
                      {originContext(entry.origin)}
                    </span>
                    <span style={{ color: tokens.colorNeutralForeground3 }}>No timestamp</span>
                  </div>
                ))}
              </div>
              {unplacedOmittedCount > 0 && (
                <div style={{ marginTop: "12px", fontSize: `${smallFontSize}px` }}>
                  Showing the first {unplacedPreview.length.toLocaleString()} of{" "}
                  {unplacedCount.toLocaleString()} unplaced entries;{" "}
                  {unplacedOmittedCount.toLocaleString()} omitted. Use the source details above to
                  investigate the missing timestamps.
                </div>
              )}
            </>
          )}
        </div>
      ) : (
        <div
          ref={parentRef}
          style={{
            overflowY: "auto",
            flex: 1,
            minHeight: 0,
            backgroundColor: tokens.colorNeutralBackground1,
            fontFamily: LOG_UI_FONT_FAMILY,
          }}
        >
          <div style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative" }}>
            {virtualizer.getVirtualItems().map((virtualRow) => {
              const item = timeline.items[virtualRow.index];
              if (!item) return null;
              const color = SEVERITY_COLORS[item.severity];
              const fromEvent = isEventOrigin(item.origin);

              return (
                <div
                  key={virtualRow.key}
                  data-index={virtualRow.index}
                  ref={virtualizer.measureElement}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    transform: `translateY(${virtualRow.start}px)`,
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                    padding: "2px 12px",
                    boxSizing: "border-box",
                    borderLeft: `4px solid ${color}`,
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    backgroundColor:
                      virtualRow.index % 2 === 0
                        ? tokens.colorNeutralBackground1
                        : tokens.colorNeutralBackground2,
                    fontSize: `${fontSize}px`,
                    lineHeight: `${metrics.rowLineHeight}px`,
                  }}
                >
                  <span
                    style={{
                      width: "40px",
                      flexShrink: 0,
                      textAlign: "center",
                      fontSize: `${smallFontSize}px`,
                      fontWeight: 700,
                      borderRadius: "4px",
                      backgroundColor: fromEvent
                        ? tokens.colorBrandBackground2
                        : tokens.colorNeutralBackground4,
                      color: tokens.colorNeutralForeground2,
                    }}
                    title={fromEvent ? "Windows event" : "Text log line"}
                  >
                    {fromEvent ? "EVT" : "LOG"}
                  </span>

                  <span
                    style={{
                      width: "175px",
                      flexShrink: 0,
                      fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                      fontSize: `${monoFontSize}px`,
                      color: tokens.colorNeutralForeground3,
                    }}
                  >
                    {formatEventTime(item.timestampMs, timeZoneMode)}
                  </span>
                  <span
                    style={{
                      width: "220px",
                      flexShrink: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontSize: `${smallFontSize}px`,
                      color: tokens.colorNeutralForeground3,
                    }}
                    title={originDetail(item.origin)}
                  >
                    {originLabel(item.origin)}
                  </span>

                  <span
                    style={{
                      width: "180px",
                      flexShrink: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontSize: `${smallFontSize}px`,
                      color: tokens.colorNeutralForeground4,
                    }}
                    title={originDetail(item.origin)}
                  >
                    {originContext(item.origin)}
                  </span>

                  <span
                    style={{
                      flex: 1,
                      minWidth: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      color: tokens.colorNeutralForeground1,
                    }}
                    title={item.message}
                  >
                    {item.message}
                  </span>
                </div>
              );
            })}
          </div>
          {timeline.unplaced.length > 0 && (
            <div
              style={{
                padding: "10px 12px",
                borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
                color: tokens.colorPaletteMarigoldForeground1,
                fontSize: `${smallFontSize}px`,
              }}
            >
              {unplacedPreview.map((unplaced, index) => (
                <div
                  key={`${originDetail(unplaced.origin)}-${index}`}
                  style={{ padding: "4px 0" }}
                >
                  {isEventOrigin(unplaced.origin) ? "Unplaced event" : "Unplaced log"}: no timestamp ·{" "}
                  {originContext(unplaced.origin)}
                </div>
              ))}
              {unplacedOmittedCount > 0 && (
                <div style={{ padding: "4px 0" }}>
                  Showing the first {unplacedPreview.length.toLocaleString()} of{" "}
                  {unplacedCount.toLocaleString()} unplaced entries;{" "}
                  {unplacedOmittedCount.toLocaleString()} omitted.
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

import { useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { tokens } from "@fluentui/react-components";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import {
  LOG_UI_FONT_FAMILY,
  LOG_MONOSPACE_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import type { IntuneEvent, IntuneStatus, IntuneEventType } from "../../types/intune";
import { useIntuneStore } from "../../stores/intune-store";

const STATUS_COLORS: Record<IntuneStatus, string> = {
  Success: "#22c55e",
  Failed: "#ef4444",
  InProgress: "#3b82f6",
  Pending: "#9ca3af",
  Timeout: "#f59e0b",
  Unknown: "#6b7280",
};

const EVENT_TYPE_LABELS: Record<IntuneEventType, string> = {
  Win32App: "Win32",
  WinGetApp: "WinGet",
  PowerShellScript: "Script",
  Remediation: "Remed.",
  Esp: "ESP",
  SyncSession: "Sync",
  PolicyEvaluation: "Policy",
  ContentDownload: "Download",
  Other: "Other",
};

interface EventTimelineProps {
  events: IntuneEvent[];
}

export function EventTimeline({ events }: EventTimelineProps) {
  const selectedEventId = useIntuneStore((s) => s.selectedEventId);
  const selectEvent = useIntuneStore((s) => s.selectEvent);
  const timelineScope = useIntuneStore((s) => s.timelineScope);
  const sourceFiles = useIntuneStore((s) => s.sourceFiles);
  const filterEventType = useIntuneStore((s) => s.filterEventType);
  const filterStatus = useIntuneStore((s) => s.filterStatus);
  const showSourceFileLabel = sourceFiles.length > 1 && timelineScope.filePath == null;

  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );

  const collapsedRowEstimate = metrics.rowHeight + 2;
  const expandedRowEstimate = Math.max(160, metrics.rowHeight * 5);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (timelineScope.filePath != null && e.sourceFile !== timelineScope.filePath) {
        return false;
      }
      if (filterEventType !== "All" && e.eventType !== filterEventType) {
        return false;
      }
      if (filterStatus !== "All" && e.status !== filterStatus) {
        return false;
      }
      return true;
    });
  }, [events, filterEventType, filterStatus, timelineScope.filePath]);

  useEffect(() => {
    if (selectedEventId == null) {
      return;
    }

    const selectedStillVisible = filteredEvents.some((e) => e.id === selectedEventId);
    if (!selectedStillVisible) {
      selectEvent(null);
    }
  }, [filteredEvents, selectEvent, selectedEventId]);

  const parentRef = useRef<HTMLDivElement>(null);
  const selectedIndex = useMemo(
    () => filteredEvents.findIndex((event) => event.id === selectedEventId),
    [filteredEvents, selectedEventId]
  );

  const virtualizer = useVirtualizer({
    count: filteredEvents.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) =>
      filteredEvents[index]?.id === selectedEventId ? expandedRowEstimate : collapsedRowEstimate,
    getItemKey: (index) => filteredEvents[index]?.id ?? index,
    overscan: 10,
  });

  const virtualRows = virtualizer.getVirtualItems();

  useEffect(() => {
    if (selectedIndex >= 0) {
      virtualizer.scrollToIndex(selectedIndex, { align: "center" });
    }
  }, [selectedIndex, virtualizer]);

  const fontSize = metrics.fontSize;
  const smallFontSize = Math.max(9, fontSize - 3);
  const monoFontSize = Math.max(10, fontSize - 1);
  const lineHeight = `${metrics.rowLineHeight}px`;

  if (events.length === 0) {
    return (
      <div style={{ padding: "20px", color: tokens.colorNeutralForeground3, textAlign: "center", fontSize: `${fontSize}px`, fontFamily: LOG_UI_FONT_FAMILY }}>
        No Intune timeline events were found in this analysis.
      </div>
    );
  }

  if (filteredEvents.length === 0) {
    return (
      <div style={{ padding: "20px", color: tokens.colorNeutralForeground3, textAlign: "center", fontSize: `${fontSize}px`, fontFamily: LOG_UI_FONT_FAMILY }}>
        {timelineScope.filePath
          ? `No events from ${getFileName(timelineScope.filePath)} match the current timeline scope${filterEventType !== "All" || filterStatus !== "All" ? " and filters." : "."
          }`
          : "No events match the current filters."}
      </div>
    );
  }

  return (
    <div
      ref={parentRef}
      role="listbox"
      aria-label={`Intune event timeline — ${filteredEvents.length} events`}
      style={{
        overflowY: "auto",
        height: "100%",
        padding: "0",
        backgroundColor: tokens.colorNeutralBackground1,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            width: "100%",
            transform: `translateY(${virtualRows[0]?.start ?? 0}px)`,
          }}
        >
          {virtualRows.map((virtualRow) => {
            const event = filteredEvents[virtualRow.index];
            const isSelected = selectedEventId === event.id;

            return (
              <div
                key={virtualRow.key}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                onClick={() => selectEvent(isSelected ? null : event.id)}
                role="option"
                aria-selected={isSelected}
                style={{
                  display: "flex",
                  flexDirection: isSelected ? "column" : "row",
                  alignItems: isSelected ? "stretch" : "center",
                  padding: isSelected ? "8px 12px" : "2px 12px",
                  cursor: "pointer",
                  backgroundColor: isSelected
                    ? tokens.colorNeutralBackground1Selected
                    : virtualRow.index % 2 === 0
                      ? tokens.colorNeutralBackground1
                      : tokens.colorNeutralBackground2,
                  borderLeft: `4px solid ${STATUS_COLORS[event.status]}`,
                  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                  height: "100%",
                  boxSizing: "border-box",
                  fontSize: `${fontSize}px`,
                  lineHeight,
                }}
              >
                {/* Header / Summary Line */}
                <div style={{ display: "flex", alignItems: "center", width: "100%", minWidth: 0, gap: "10px" }}>
                  <div
                    style={{
                      fontSize: `${monoFontSize}px`,
                      color: tokens.colorNeutralForeground3,
                      flexShrink: 0,
                      width: "165px",
                      fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                    }}
                    title={event.startTime ?? undefined}
                  >
                    {formatDisplayDateTime(event.startTime) ?? "Not timestamped"}
                  </div>

                  <div
                    style={{
                      fontSize: `${smallFontSize}px`,
                      fontWeight: 700,
                      padding: "2px 6px",
                      borderRadius: "3px",
                      backgroundColor: tokens.colorNeutralBackground4,
                      color: tokens.colorNeutralForeground2,
                      width: "55px",
                      textAlign: "center",
                      flexShrink: 0,
                      textTransform: "uppercase",
                    }}
                  >
                    {EVENT_TYPE_LABELS[event.eventType]}
                  </div>

                  <div
                    style={{
                      flex: 1,
                      fontSize: `${fontSize}px`,
                      fontWeight: isSelected ? 600 : 500,
                      color: isSelected ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={event.name}
                  >
                    {event.name}
                  </div>

                  {event.errorCode && !isSelected && (
                    <div style={{ fontSize: `${monoFontSize}px`, color: tokens.colorPaletteRedForeground1, fontFamily: LOG_MONOSPACE_FONT_FAMILY, flexShrink: 0 }}>
                      {event.errorCode}
                    </div>
                  )}

                  {showSourceFileLabel && (
                    <div
                      title={event.sourceFile}
                      style={{
                        fontSize: `${smallFontSize}px`,
                        color: tokens.colorNeutralForeground2,
                        backgroundColor: tokens.colorNeutralBackground3,
                        border: `1px solid ${tokens.colorNeutralStroke2}`,
                        borderRadius: "999px",
                        padding: "2px 6px",
                        maxWidth: "130px",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        flexShrink: 1,
                      }}
                    >
                      {getFileName(event.sourceFile)}
                    </div>
                  )}

                  {event.durationSecs != null && (
                    <div style={{ fontSize: `${monoFontSize}px`, color: tokens.colorNeutralForeground4, width: "50px", textAlign: "right", flexShrink: 0 }}>
                      {formatDuration(event.durationSecs)}
                    </div>
                  )}

                  <div
                    style={{
                      fontSize: `${smallFontSize}px`,
                      fontWeight: 700,
                      padding: "2px 6px",
                      borderRadius: "3px",
                      backgroundColor: STATUS_COLORS[event.status],
                      color: "#fff",
                      width: "65px",
                      textAlign: "center",
                      flexShrink: 0,
                      textTransform: "uppercase",
                    }}
                  >
                    {event.status}
                  </div>
                </div>

                {/* Expanded Details */}
                {isSelected && (
                  <div style={{ marginTop: "8px", display: "flex", gap: "12px" }}>
                    <div style={{ flex: 1 }}>
                      <div
                        style={{
                          fontSize: `${monoFontSize}px`,
                          color: tokens.colorNeutralForeground1,
                          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                          maxHeight: "120px",
                          overflow: "auto",
                          backgroundColor: tokens.colorNeutralBackground1,
                          border: `1px solid ${tokens.colorNeutralStroke1}`,
                          padding: "6px",
                          borderRadius: "4px",
                          lineHeight: `${metrics.rowLineHeight + 2}px`,
                        }}
                      >
                        {event.detail}
                      </div>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", width: "200px", flexShrink: 0, fontSize: `${monoFontSize}px` }}>
                      {event.startTime && (
                        <div><strong style={{ color: tokens.colorNeutralForeground3 }}>Start:</strong> {formatDisplayDateTime(event.startTime) ?? event.startTime}</div>
                      )}
                      {event.endTime && (
                        <div><strong style={{ color: tokens.colorNeutralForeground3 }}>End:</strong> {formatDisplayDateTime(event.endTime) ?? event.endTime}</div>
                      )}
                      {event.errorCode && (
                        <div><strong style={{ color: tokens.colorNeutralForeground3 }}>Error:</strong> <span style={{ color: tokens.colorPaletteRedForeground1, fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>{event.errorCode}</span></div>
                      )}
                      <div>
                        <strong style={{ color: tokens.colorNeutralForeground3 }}>Source:</strong>
                        <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, display: "block", color: tokens.colorNeutralForeground2 }} title={event.sourceFile}>
                          {formatSourceLabel(event.sourceFile, event.lineNumber)}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function formatSourceLabel(sourceFile: string, lineNumber: number): string {
  return `${getFileName(sourceFile)}:${lineNumber}`;
}

function getFileName(sourceFile: string): string {
  const normalized = sourceFile.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return segments[segments.length - 1] || sourceFile;
}

function formatDuration(secs: number): string {
  if (secs < 60) return `${Math.round(secs)}s`;
  const m = Math.floor(secs / 60);
  const s = Math.round(secs % 60);
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}h ${rm}m ${s}s`;
}

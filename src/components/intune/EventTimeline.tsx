import { useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { IntuneEvent, IntuneStatus, IntuneEventType } from "../../types/intune";
import { useIntuneStore } from "../../stores/intune-store";

const COLLAPSED_ROW_ESTIMATE = 28;
const EXPANDED_ROW_ESTIMATE = 160;

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
      filteredEvents[index]?.id === selectedEventId ? EXPANDED_ROW_ESTIMATE : COLLAPSED_ROW_ESTIMATE,
    getItemKey: (index) => filteredEvents[index]?.id ?? index,
    overscan: 10,
  });

  const virtualRows = virtualizer.getVirtualItems();

  useEffect(() => {
    if (selectedIndex >= 0) {
      virtualizer.scrollToIndex(selectedIndex, { align: "center" });
    }
  }, [selectedIndex, virtualizer]);

  if (events.length === 0) {
    return (
      <div style={{ padding: "20px", color: "#666", textAlign: "center", fontSize: "12px" }}>
        No Intune timeline events were found in this analysis.
      </div>
    );
  }

  if (filteredEvents.length === 0) {
    return (
      <div style={{ padding: "20px", color: "#666", textAlign: "center", fontSize: "12px" }}>
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
      style={{
        overflowY: "auto",
        height: "100%",
        padding: "0",
        backgroundColor: "#ffffff",
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
                style={{
                  display: "flex",
                  flexDirection: isSelected ? "column" : "row",
                  alignItems: isSelected ? "stretch" : "center",
                  padding: isSelected ? "8px 12px" : "2px 12px",
                  cursor: "pointer",
                  backgroundColor: isSelected ? "#eff6ff" : virtualRow.index % 2 === 0 ? "#ffffff" : "#fafafa",
                  borderLeft: `4px solid ${STATUS_COLORS[event.status]}`,
                  borderBottom: "1px solid #f1f5f9",
                  height: "100%",
                  boxSizing: "border-box",
                }}
              >
                {/* Header / Summary Line */}
                <div style={{ display: "flex", alignItems: "center", width: "100%", minWidth: 0, gap: "10px" }}>
                  <div style={{ fontSize: "11px", color: "#64748b", flexShrink: 0, width: "65px", fontFamily: "'Courier New', monospace" }}>
                    {event.startTime ? event.startTime.split(" ")[1] || event.startTime : "--:--:--"}
                  </div>

                  <div
                    style={{
                      fontSize: "9px",
                      fontWeight: 700,
                      padding: "2px 6px",
                      borderRadius: "3px",
                      backgroundColor: "#e2e8f0",
                      color: "#475569",
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
                      fontSize: "12px",
                      fontWeight: isSelected ? 600 : 500,
                      color: isSelected ? "#1e3a8a" : "#1e293b",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={event.name}
                  >
                    {event.name}
                  </div>

                  {event.errorCode && !isSelected && (
                    <div style={{ fontSize: "11px", color: "#ef4444", fontFamily: "'Courier New', monospace", flexShrink: 0 }}>
                      {event.errorCode}
                    </div>
                  )}

                  {showSourceFileLabel && (
                    <div
                      title={event.sourceFile}
                      style={{
                        fontSize: "10px",
                        color: "#475569",
                        backgroundColor: "#f1f5f9",
                        border: "1px solid #e2e8f0",
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
                    <div style={{ fontSize: "11px", color: "#94a3b8", width: "50px", textAlign: "right", flexShrink: 0 }}>
                      {formatDuration(event.durationSecs)}
                    </div>
                  )}

                  <div
                    style={{
                      fontSize: "9px",
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
                          fontSize: "11px",
                          color: "#334155",
                          fontFamily: "'Courier New', monospace",
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                          maxHeight: "80px",
                          overflow: "auto",
                          backgroundColor: "#fff",
                          border: "1px solid #cbd5e1",
                          padding: "6px",
                          borderRadius: "4px",
                        }}
                      >
                        {event.detail}
                      </div>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", width: "200px", flexShrink: 0, fontSize: "11px" }}>
                      {event.startTime && (
                        <div><strong style={{ color: "#64748b" }}>Start:</strong> {event.startTime}</div>
                      )}
                      {event.errorCode && (
                        <div><strong style={{ color: "#64748b" }}>Error:</strong> <span style={{ color: "#ef4444", fontFamily: "'Courier New', monospace" }}>{event.errorCode}</span></div>
                      )}
                      <div>
                        <strong style={{ color: "#64748b" }}>Source:</strong>
                        <span style={{ fontFamily: "'Courier New', monospace", display: "block", color: "#475569" }} title={event.sourceFile}>
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

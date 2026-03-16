import { useVirtualizer } from "@tanstack/react-virtual";
import { useMemo, useRef, useCallback } from "react";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import type { EventLogAnalysis, EventLogEntry, EventLogChannel, EventLogSeverity } from "../../types/event-log";

const COLLAPSED_ROW_ESTIMATE = 28;
const EXPANDED_ROW_ESTIMATE = 200;

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#dc2626",
  Error: "#ea580c",
  Warning: "#d97706",
  Information: "#2563eb",
  Verbose: "#6b7280",
  Unknown: "#9ca3af",
};

function channelKey(channel: EventLogChannel): string {
  if (typeof channel === "string") return channel;
  return channel.Other ?? "Other";
}

function formatTimestamp(iso: string): string {
  try {
    const date = new Date(iso);
    return date.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

function getFileName(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

interface DsregcmdEventLogSurfaceProps {
  eventLogAnalysis: EventLogAnalysis;
}

export function DsregcmdEventLogSurface({ eventLogAnalysis }: DsregcmdEventLogSurfaceProps) {
  const filterChannel = useDsregcmdStore((s) => s.eventLogFilterChannel);
  const filterSeverity = useDsregcmdStore((s) => s.eventLogFilterSeverity);
  const selectedEntryId = useDsregcmdStore((s) => s.selectedEventLogEntryId);
  const setFilterChannel = useDsregcmdStore((s) => s.setEventLogFilterChannel);
  const setFilterSeverity = useDsregcmdStore((s) => s.setEventLogFilterSeverity);
  const selectEntry = useDsregcmdStore((s) => s.selectEventLogEntry);

  const scrollRef = useRef<HTMLDivElement>(null);

  const filteredEntries = useMemo(() => {
    return eventLogAnalysis.entries.filter((entry) => {
      if (filterChannel !== "All") {
        const entryKey = channelKey(entry.channel);
        const filterKey = typeof filterChannel === "string" ? filterChannel : channelKey(filterChannel);
        if (entryKey !== filterKey) return false;
      }
      if (filterSeverity !== "All" && entry.severity !== filterSeverity) return false;
      return true;
    });
  }, [eventLogAnalysis.entries, filterChannel, filterSeverity]);

  const virtualizer = useVirtualizer({
    count: filteredEntries.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: (index) =>
      filteredEntries[index]?.id === selectedEntryId
        ? EXPANDED_ROW_ESTIMATE
        : COLLAPSED_ROW_ESTIMATE,
    overscan: 10,
  });

  const handleRowClick = useCallback(
    (id: number) => selectEntry(id),
    [selectEntry],
  );

  const uniqueChannels = useMemo(() => {
    const seen = new Set<string>();
    const channels: { key: string; display: string }[] = [];
    for (const entry of eventLogAnalysis.entries) {
      const key = channelKey(entry.channel);
      if (!seen.has(key)) {
        seen.add(key);
        channels.push({ key, display: entry.channelDisplay });
      }
    }
    return channels;
  }, [eventLogAnalysis.entries]);

  if (eventLogAnalysis.entries.length === 0) {
    return (
      <div style={{ padding: 24, color: "#6b7280", textAlign: "center" }}>
        No event log entries were collected for dsregcmd-related channels.
        {eventLogAnalysis.liveQuery && (
          <div style={{ marginTop: 8, fontSize: 12 }}>
            Attempted {eventLogAnalysis.liveQuery.attemptedChannelCount} channels,{" "}
            {eventLogAnalysis.liveQuery.failedChannelCount} failed.
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", minHeight: 0 }}>
      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "6px 12px",
          borderBottom: "1px solid #e5e7eb",
          background: "#f9fafb",
          flexShrink: 0,
        }}
      >
        <label style={{ fontSize: 12, color: "#6b7280" }}>Channel:</label>
        <select
          value={typeof filterChannel === "string" ? filterChannel : channelKey(filterChannel)}
          onChange={(e) => {
            const val = e.target.value;
            if (val === "All") {
              setFilterChannel("All");
            } else {
              setFilterChannel(val as EventLogChannel);
            }
          }}
          style={{ fontSize: 12, padding: "2px 4px" }}
        >
          <option value="All">All</option>
          {uniqueChannels.map((ch) => (
            <option key={ch.key} value={ch.key}>
              {ch.display}
            </option>
          ))}
        </select>

        <label style={{ fontSize: 12, color: "#6b7280", marginLeft: 8 }}>Severity:</label>
        <select
          value={filterSeverity}
          onChange={(e) =>
            setFilterSeverity(e.target.value as EventLogSeverity | "All")
          }
          style={{ fontSize: 12, padding: "2px 4px" }}
        >
          <option value="All">All</option>
          <option value="Critical">Critical</option>
          <option value="Error">Error</option>
          <option value="Warning">Warning</option>
          <option value="Information">Information</option>
          <option value="Verbose">Verbose</option>
        </select>

        <span style={{ fontSize: 12, color: "#9ca3af", marginLeft: "auto" }}>
          {filteredEntries.length} of {eventLogAnalysis.totalEntryCount} entries
        </span>
      </div>

      {/* Channel summary chips */}
      <div
        style={{
          display: "flex",
          gap: 6,
          padding: "6px 12px",
          borderBottom: "1px solid #e5e7eb",
          overflowX: "auto",
          flexShrink: 0,
        }}
      >
        {eventLogAnalysis.channelSummaries.map((summary) => {
          const isActive =
            filterChannel !== "All" &&
            channelKey(summary.channel) ===
              (typeof filterChannel === "string" ? filterChannel : channelKey(filterChannel));
          return (
            <button
              key={channelKey(summary.channel)}
              onClick={() => {
                if (isActive) {
                  setFilterChannel("All");
                } else {
                  setFilterChannel(summary.channel);
                }
              }}
              style={{
                fontSize: 11,
                padding: "2px 8px",
                borderRadius: 4,
                border: isActive ? "1px solid #2563eb" : "1px solid #d1d5db",
                background: isActive ? "#eff6ff" : "#fff",
                color: isActive ? "#2563eb" : "#374151",
                cursor: "pointer",
                whiteSpace: "nowrap",
              }}
            >
              {summary.channelDisplay}
              <span style={{ color: "#6b7280", marginLeft: 4 }}>
                {summary.entryCount}
              </span>
              {summary.errorCount > 0 && (
                <span style={{ color: "#dc2626", marginLeft: 4 }}>
                  {summary.errorCount}E
                </span>
              )}
              {summary.warningCount > 0 && (
                <span style={{ color: "#d97706", marginLeft: 4 }}>
                  {summary.warningCount}W
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Virtualized entries */}
      <div
        ref={scrollRef}
        style={{
          flex: 1,
          overflow: "auto",
          contain: "strict",
          minHeight: 0,
        }}
      >
        <div
          style={{
            height: virtualizer.getTotalSize(),
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((virtualItem) => {
            const entry = filteredEntries[virtualItem.index];
            if (!entry) return null;
            const isExpanded = entry.id === selectedEntryId;

            return (
              <div
                key={entry.id}
                data-index={virtualItem.index}
                ref={virtualizer.measureElement}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  transform: `translateY(${virtualItem.start}px)`,
                }}
              >
                <EventLogRow
                  entry={entry}
                  isExpanded={isExpanded}
                  onClick={handleRowClick}
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

interface EventLogRowProps {
  entry: EventLogEntry;
  isExpanded: boolean;
  onClick: (id: number) => void;
}

function EventLogRow({ entry, isExpanded, onClick }: EventLogRowProps) {
  const severityColor = SEVERITY_COLORS[entry.severity] ?? "#9ca3af";

  return (
    <div
      onClick={() => onClick(entry.id)}
      style={{
        borderBottom: "1px solid #f3f4f6",
        cursor: "pointer",
        background: isExpanded ? "#f9fafb" : "transparent",
      }}
    >
      {/* Collapsed row */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "4px 12px",
          height: COLLAPSED_ROW_ESTIMATE,
          fontSize: 12,
          overflow: "hidden",
        }}
      >
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: severityColor,
            flexShrink: 0,
          }}
        />
        <span style={{ width: 110, flexShrink: 0, color: "#6b7280" }}>
          {formatTimestamp(entry.timestamp)}
        </span>
        <span
          style={{
            width: 100,
            flexShrink: 0,
            fontWeight: 500,
            color: "#374151",
          }}
        >
          {entry.channelDisplay}
        </span>
        <span style={{ width: 50, flexShrink: 0, color: "#9ca3af" }}>
          {entry.eventId}
        </span>
        <span
          style={{
            flex: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            color: "#4b5563",
          }}
        >
          {entry.message}
        </span>
      </div>

      {/* Expanded details */}
      {isExpanded && (
        <div
          style={{
            padding: "8px 12px 12px 28px",
            fontSize: 12,
            borderTop: "1px solid #e5e7eb",
          }}
        >
          <div
            style={{
              background: "#f3f4f6",
              padding: 8,
              borderRadius: 4,
              fontFamily: "monospace",
              fontSize: 11,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              maxHeight: 200,
              overflow: "auto",
              marginBottom: 8,
            }}
          >
            {entry.message}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: "2px 8px", color: "#6b7280" }}>
            <span>Provider:</span>
            <span style={{ color: "#374151" }}>{entry.provider}</span>
            <span>Severity:</span>
            <span style={{ color: severityColor }}>{entry.severity}</span>
            <span>Event ID:</span>
            <span style={{ color: "#374151" }}>{entry.eventId}</span>
            {entry.computer && (
              <>
                <span>Computer:</span>
                <span style={{ color: "#374151" }}>{entry.computer}</span>
              </>
            )}
            {entry.correlationActivityId && (
              <>
                <span>Activity ID:</span>
                <span style={{ color: "#374151", fontFamily: "monospace", fontSize: 11 }}>
                  {entry.correlationActivityId}
                </span>
              </>
            )}
            <span>Source:</span>
            <span style={{ color: "#374151" }}>{getFileName(entry.sourceFile)}</span>
          </div>
        </div>
      )}
    </div>
  );
}

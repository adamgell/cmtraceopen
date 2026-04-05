import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { tokens } from "@fluentui/react-components";
import { getLogListMetrics, LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useSysmonStore } from "../../stores/sysmon-store";
import { useUiStore } from "../../stores/ui-store";
import { getThemeById } from "../../lib/themes";
import type { SysmonEvent } from "../../types/sysmon";

const DETAIL_HEIGHT = 200;

function formatTimestamp(ts: string): string {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    return d.toISOString().replace("T", " ").replace("Z", "");
  } catch {
    return ts;
  }
}

export function SysmonEventTable() {
  const events = useSysmonStore((s) => s.events);
  const selectedEventId = useSysmonStore((s) => s.selectedEventId);
  const selectEvent = useSysmonStore((s) => s.selectEvent);
  const filterEventType = useSysmonStore((s) => s.filterEventType);
  const filterSeverity = useSysmonStore((s) => s.filterSeverity);
  const searchQuery = useSysmonStore((s) => s.searchQuery);
  const setFilterEventType = useSysmonStore((s) => s.setFilterEventType);
  const setFilterSeverity = useSysmonStore((s) => s.setFilterSeverity);
  const setSearchQuery = useSysmonStore((s) => s.setSearchQuery);
  const summary = useSysmonStore((s) => s.summary);
  const themeId = useUiStore((s) => s.themeId);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const severityPalette = useMemo(() => getThemeById(themeId).severityPalette, [themeId]);

  const filteredEvents = useMemo(() => {
    let result = events;
    if (filterEventType !== "All") {
      result = result.filter((e) => e.eventType === filterEventType);
    }
    if (filterSeverity !== "All") {
      result = result.filter((e) => e.severity === filterSeverity);
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (e) =>
          e.message.toLowerCase().includes(q) ||
          (e.image && e.image.toLowerCase().includes(q)) ||
          (e.commandLine && e.commandLine.toLowerCase().includes(q)) ||
          (e.targetFilename && e.targetFilename.toLowerCase().includes(q)) ||
          (e.queryName && e.queryName.toLowerCase().includes(q)) ||
          (e.targetObject && e.targetObject.toLowerCase().includes(q)) ||
          (e.destinationIp && e.destinationIp.includes(q)) ||
          (e.sourceIp && e.sourceIp.includes(q))
      );
    }
    return result;
  }, [events, filterEventType, filterSeverity, searchQuery]);

  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: filteredEvents.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) =>
      filteredEvents[index]?.id === selectedEventId ? DETAIL_HEIGHT : metrics.rowHeight,
    overscan: 20,
  });

  const eventTypes = useMemo(() => {
    if (!summary) return [];
    return summary.eventTypeCounts.map((c) => ({
      value: c.eventType,
      label: `${c.displayName} (${c.count})`,
    }));
  }, [summary]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", overflow: "hidden" }}>
      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          gap: "8px",
          padding: "6px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
          alignItems: "center",
          fontSize: `${metrics.fontSize}px`,
          flexWrap: "wrap",
        }}
      >
        <label>
          Type:{" "}
          <select
            value={filterEventType}
            onChange={(e) => setFilterEventType(e.target.value as typeof filterEventType)}
            style={{
              fontSize: `${metrics.fontSize}px`,
              backgroundColor: tokens.colorNeutralBackground1,
              color: tokens.colorNeutralForeground1,
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "3px",
              padding: "2px 4px",
            }}
          >
            <option value="All">All types</option>
            {eventTypes.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Severity:{" "}
          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value as typeof filterSeverity)}
            style={{
              fontSize: `${metrics.fontSize}px`,
              backgroundColor: tokens.colorNeutralBackground1,
              color: tokens.colorNeutralForeground1,
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              borderRadius: "3px",
              padding: "2px 4px",
            }}
          >
            <option value="All">All</option>
            <option value="Info">Info</option>
            <option value="Warning">Warning</option>
            <option value="Error">Error</option>
          </select>
        </label>
        <input
          type="text"
          aria-label="Search events"
          placeholder="Search events..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          style={{
            fontSize: `${metrics.fontSize}px`,
            backgroundColor: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: "3px",
            padding: "2px 8px",
            minWidth: "200px",
            flex: 1,
            maxWidth: "400px",
          }}
        />
        <span style={{ color: tokens.colorNeutralForeground3, marginLeft: "auto" }}>
          {filteredEvents.length.toLocaleString()} events
        </span>
      </div>

      {/* Header row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "160px 140px 70px 1fr",
          padding: "4px 12px",
          fontSize: `${metrics.headerFontSize}px`,
          fontWeight: 600,
          color: tokens.colorNeutralForeground3,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
          gap: "8px",
        }}
      >
        <span>Timestamp</span>
        <span>Event Type</span>
        <span>Severity</span>
        <span>Message</span>
      </div>

      {/* Virtual list */}
      <div
        ref={parentRef}
        style={{ flex: 1, overflow: "auto" }}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const event = filteredEvents[virtualRow.index];
            const isSelected = event.id === selectedEventId;

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
                }}
              >
                <EventRow
                  event={event}
                  isSelected={isSelected}
                  onClick={() => selectEvent(isSelected ? null : event.id)}
                  severityPalette={severityPalette}
                  rowHeight={metrics.rowHeight}
                  fontSize={metrics.fontSize}
                />
                {isSelected && <EventDetail event={event} />}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function EventRow({
  event,
  isSelected,
  onClick,
  severityPalette,
  rowHeight,
  fontSize,
}: {
  event: SysmonEvent;
  isSelected: boolean;
  onClick: () => void;
  severityPalette: import("../../lib/constants").LogSeverityPalette;
  rowHeight: number;
  fontSize: number;
}) {
  const severityColor =
    event.severity === "Error"
      ? severityPalette.error.text
      : event.severity === "Warning"
        ? severityPalette.warning.text
        : severityPalette.info.text;

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onClick();
    }
  };

  return (
    <div
      role="button"
      tabIndex={0}
      aria-selected={isSelected}
      onClick={onClick}
      onKeyDown={handleKeyDown}
      style={{
        display: "grid",
        gridTemplateColumns: "160px 140px 70px 1fr",
        padding: "4px 12px",
        height: `${rowHeight}px`,
        alignItems: "center",
        gap: "8px",
        cursor: "pointer",
        fontSize: `${fontSize}px`,
        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
        backgroundColor: isSelected
          ? tokens.colorNeutralBackground1Selected
          : "transparent",
        borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
      }}
    >
      <span style={{ color: tokens.colorNeutralForeground3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {formatTimestamp(event.timestamp)}
      </span>
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {event.eventTypeDisplay}
      </span>
      <span style={{ color: severityColor }}>
        {event.severity}
      </span>
      <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {event.message}
      </span>
    </div>
  );
}

function EventDetail({ event }: { event: SysmonEvent }) {
  const fields: [string, string | number | null | undefined][] = [
    ["Event ID", event.eventId],
    ["Record ID", event.recordId],
    ["Computer", event.computer],
    ["User", event.user],
    ["Image", event.image],
    ["Command Line", event.commandLine],
    ["Process ID", event.processId],
    ["Process GUID", event.processGuid],
    ["Parent Image", event.parentImage],
    ["Parent Command Line", event.parentCommandLine],
    ["Parent PID", event.parentProcessId],
    ["Target Filename", event.targetFilename],
    ["Target Object", event.targetObject],
    ["Details", event.details],
    ["Protocol", event.protocol],
    ["Source IP", event.sourceIp],
    ["Source Port", event.sourcePort],
    ["Destination IP", event.destinationIp],
    ["Destination Port", event.destinationPort],
    ["Destination Host", event.destinationHostname],
    ["DNS Query", event.queryName],
    ["DNS Results", event.queryResults],
    ["Source Image", event.sourceImage],
    ["Target Image", event.targetImage],
    ["Granted Access", event.grantedAccess],
    ["Hashes", event.hashes],
    ["Rule Name", event.ruleName],
    ["Source File", event.sourceFile],
  ];

  const populated = fields.filter(
    ([, v]) => v != null && v !== "" && v !== undefined
  );

  return (
    <div
      style={{
        padding: "8px 12px 8px 24px",
        backgroundColor: tokens.colorNeutralBackground1,
        borderBottom: `2px solid ${tokens.colorBrandStroke1}`,
        overflow: "auto",
        maxHeight: `${DETAIL_HEIGHT}px`,
        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "150px 1fr",
          gap: "2px 12px",
        }}
      >
        {populated.map(([label, value]) => (
          <div key={label} style={{ display: "contents" }}>
            <span style={{ color: tokens.colorNeutralForeground3, fontWeight: 600 }}>
              {label}
            </span>
            <span
              style={{
                wordBreak: "break-all",
                color: tokens.colorNeutralForeground1,
              }}
            >
              {String(value)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

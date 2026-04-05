import { useEffect, useMemo, useRef, useCallback } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import type {
  EventLogEntry,
  EventLogChannel,
  EventLogSeverity,
  EventLogCorrelationLink,
} from "../../types/event-log";
import {
  useIntuneStore,
  getCorrelationLinksForEntry,
} from "./intune-store";

const COLLAPSED_ROW_ESTIMATE = 28;
const EXPANDED_ROW_ESTIMATE = 200;

const SEVERITY_COLORS: Record<EventLogSeverity, string> = {
  Critical: tokens.colorPaletteRedForeground1,
  Error: tokens.colorPaletteRedForeground1,
  Warning: tokens.colorPaletteMarigoldForeground1,
  Information: tokens.colorBrandForeground1,
  Verbose: tokens.colorNeutralForeground4,
  Unknown: tokens.colorNeutralForeground3,
};

function channelKey(ch: EventLogChannel): string {
  return typeof ch === "string" ? ch : `Other:${ch.Other}`;
}

interface EventLogSurfaceProps {
  onNavigateToTimeline?: (intuneEventId: number) => void;
  onNavigateToOverview?: () => void;
}

export function EventLogSurface({
  onNavigateToTimeline,
  onNavigateToOverview,
}: EventLogSurfaceProps) {
  const eventLogAnalysis = useIntuneStore((s) => s.eventLogAnalysis);
  const selectedEntryId = useIntuneStore((s) => s.selectedEventLogEntryId);
  const selectEntry = useIntuneStore((s) => s.selectEventLogEntry);
  const filterChannel = useIntuneStore((s) => s.eventLogFilterChannel);
  const filterSeverity = useIntuneStore((s) => s.eventLogFilterSeverity);
  const setFilterChannel = useIntuneStore((s) => s.setEventLogFilterChannel);
  const setFilterSeverity = useIntuneStore((s) => s.setEventLogFilterSeverity);
  const events = useIntuneStore((s) => s.events);

  const entries = eventLogAnalysis?.entries ?? [];
  const channelSummaries = eventLogAnalysis?.channelSummaries ?? [];
  const correlationLinks = eventLogAnalysis?.correlationLinks ?? [];
  const liveQuery = eventLogAnalysis?.liveQuery ?? null;

  const filteredEntries = useMemo(() => {
    return entries.filter((e) => {
      if (filterChannel !== "All" && channelKey(e.channel) !== channelKey(filterChannel)) {
        return false;
      }
      if (filterSeverity !== "All" && e.severity !== filterSeverity) {
        return false;
      }
      return true;
    });
  }, [entries, filterChannel, filterSeverity]);

  useEffect(() => {
    if (selectedEntryId == null) return;
    const stillVisible = filteredEntries.some((e) => e.id === selectedEntryId);
    if (!stillVisible) {
      selectEntry(null);
    }
  }, [filteredEntries, selectEntry, selectedEntryId]);

  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: filteredEntries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) =>
      filteredEntries[index]?.id === selectedEntryId
        ? EXPANDED_ROW_ESTIMATE
        : COLLAPSED_ROW_ESTIMATE,
    overscan: 10,
  });

  const handleRowClick = useCallback(
    (entry: EventLogEntry) => {
      selectEntry(entry.id === selectedEntryId ? null : entry.id);
    },
    [selectEntry, selectedEntryId]
  );

  const handleNavigateToTimeline = useCallback(
    (intuneEventId: number) => {
      if (onNavigateToTimeline) {
        onNavigateToTimeline(intuneEventId);
      }
    },
    [onNavigateToTimeline]
  );

  if (!eventLogAnalysis || entries.length === 0) {
    if (eventLogAnalysis?.sourceKind === "Live" && liveQuery) {
      return (
        <div style={{ padding: 24, color: tokens.colorNeutralForeground1, fontSize: 13, display: "grid", gap: 12 }}>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Live Windows Event Log query completed.</div>
            <div>
              {liveQuery.channelsWithResultsCount === 0
                ? `No matching entries were returned from ${liveQuery.attemptedChannelCount} queried channels.`
                : `${entries.length} entries were returned from ${liveQuery.channelsWithResultsCount} of ${liveQuery.attemptedChannelCount} queried channels.`}
            </div>
            {liveQuery.failedChannelCount > 0 && (
              <div style={{ marginTop: 4, color: tokens.colorPaletteMarigoldForeground2 }}>
                {liveQuery.failedChannelCount} channel query{liveQuery.failedChannelCount === 1 ? "" : "ies"} failed.
              </div>
            )}
          </div>

          <div style={{ display: "grid", gap: 8 }}>
            {liveQuery.channels.map((channel) => (
              <div
                key={channel.channelPath}
                style={{
                  border: `1px solid ${tokens.colorNeutralStroke2}`,
                  borderRadius: 6,
                  padding: "10px 12px",
                  background: tokens.colorNeutralBackground2,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                  <div style={{ fontWeight: 600 }}>{channel.channelDisplay}</div>
                  <div style={{ fontSize: 11, color: tokens.colorNeutralForeground3 }}>{channel.status}</div>
                </div>
                <div style={{ marginTop: 4, fontSize: 12, color: tokens.colorNeutralForeground3 }}>
                  {channel.entryCount} entr{channel.entryCount === 1 ? "y" : "ies"} collected
                </div>
                {channel.errorMessage && (
                  <div style={{ marginTop: 4, fontSize: 12, color: tokens.colorPaletteRedForeground1 }}>{channel.errorMessage}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      );
    }

    return (
      <div style={{ padding: 24, color: tokens.colorNeutralForeground3, fontSize: 13 }}>
        No Windows Event Log evidence is available for this analysis.
      </div>
    );
  }

  const severityOptions: EventLogSeverity[] = [
    "Critical",
    "Error",
    "Warning",
    "Information",
    "Verbose",
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: 0 }}>
      {/* Filter bar */}
      <div
        style={{
          display: "flex",
          gap: 8,
          padding: "8px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          alignItems: "center",
          flexShrink: 0,
        }}
      >
        <select
          value={filterChannel === "All" ? "All" : channelKey(filterChannel)}
          onChange={(e) => {
            if (e.target.value === "All") {
              setFilterChannel("All");
            } else {
              const summary = channelSummaries.find(
                (s) => channelKey(s.channel) === e.target.value
              );
              if (summary) {
                setFilterChannel(summary.channel);
              }
            }
          }}
          style={{
            fontSize: 12,
            padding: "3px 6px",
            borderRadius: 4,
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            background: tokens.colorNeutralCardBackground,
          }}
        >
          <option value="All">All channels ({entries.length})</option>
          {channelSummaries.map((s) => (
            <option key={channelKey(s.channel)} value={channelKey(s.channel)}>
              {s.channelDisplay} ({s.entryCount})
            </option>
          ))}
        </select>

        <select
          value={filterSeverity}
          onChange={(e) =>
            setFilterSeverity(e.target.value as EventLogSeverity | "All")
          }
          style={{
            fontSize: 12,
            padding: "3px 6px",
            borderRadius: 4,
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            background: tokens.colorNeutralCardBackground,
          }}
        >
          <option value="All">All severities</option>
          {severityOptions.map((sev) => (
            <option key={sev} value={sev}>
              {sev}
            </option>
          ))}
        </select>

        <span style={{ fontSize: 11, color: tokens.colorNeutralForeground3, marginLeft: "auto" }}>
          {filteredEntries.length} of {entries.length} entries
        </span>
      </div>

      {/* Channel summary cards */}
      <div
        style={{
          display: "flex",
          gap: 6,
          padding: "6px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          overflowX: "auto",
          flexShrink: 0,
        }}
      >
        {channelSummaries.map((s) => (
          <button
            key={channelKey(s.channel)}
            onClick={() => {
              if (
                filterChannel !== "All" &&
                channelKey(filterChannel) === channelKey(s.channel)
              ) {
                setFilterChannel("All");
              } else {
                setFilterChannel(s.channel);
              }
            }}
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 2,
              padding: "4px 8px",
              border:
                filterChannel !== "All" &&
                channelKey(filterChannel) === channelKey(s.channel)
                  ? `1px solid ${tokens.colorPaletteTealForeground2}`
                  : `1px solid ${tokens.colorNeutralStroke2}`,
              borderRadius: 4,
              background:
                filterChannel !== "All" &&
                channelKey(filterChannel) === channelKey(s.channel)
                  ? tokens.colorPaletteTealBackground2
                  : tokens.colorNeutralBackground2,
              cursor: "pointer",
              whiteSpace: "nowrap",
              fontSize: 11,
              minWidth: 90,
            }}
          >
            <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
              {s.channelDisplay}
            </span>
            <span style={{ color: tokens.colorNeutralForeground3 }}>
              {s.entryCount} entries
              {s.errorCount > 0 && (
                <span style={{ color: tokens.colorPaletteRedForeground1, marginLeft: 4 }}>
                  {s.errorCount} err
                </span>
              )}
              {s.warningCount > 0 && (
                <span style={{ color: tokens.colorPaletteMarigoldForeground1, marginLeft: 4 }}>
                  {s.warningCount} warn
                </span>
              )}
            </span>
          </button>
        ))}
      </div>

      {/* Virtual-scrolling entry list */}
      <div
        ref={parentRef}
        style={{
          flex: 1,
          overflow: "auto",
          contain: "strict",
        }}
      >
        <div
          style={{
            height: virtualizer.getTotalSize(),
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const entry = filteredEntries[virtualRow.index];
            if (!entry) return null;
            const isExpanded = entry.id === selectedEntryId;
            const entryLinks = isExpanded
              ? getCorrelationLinksForEntry(entry.id, correlationLinks)
              : [];

            return (
              <div
                key={entry.id}
                ref={virtualizer.measureElement}
                data-index={virtualRow.index}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              >
                {/* Collapsed row */}
                <div
                  onClick={() => handleRowClick(entry)}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                    padding: "4px 12px",
                    cursor: "pointer",
                    height: 28,
                    borderBottom: isExpanded ? "none" : `1px solid ${tokens.colorNeutralStroke2}`,
                    background: isExpanded ? tokens.colorNeutralBackground3 : "transparent",
                    fontSize: 12,
                  }}
                >
                  {/* Severity dot */}
                  <span
                    style={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      background: SEVERITY_COLORS[entry.severity],
                      flexShrink: 0,
                    }}
                  />

                  {/* Timestamp */}
                  <span
                    style={{
                      fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                      fontSize: 11,
                      color: tokens.colorNeutralForeground1,
                      whiteSpace: "nowrap",
                      minWidth: 140,
                    }}
                  >
                    {formatTimestamp(entry.timestamp)}
                  </span>

                  {/* Channel badge */}
                  <span
                    style={{
                      fontSize: 10,
                      padding: "1px 4px",
                      borderRadius: 3,
                      background: tokens.colorNeutralBackground3,
                      color: tokens.colorNeutralForeground1,
                      whiteSpace: "nowrap",
                      fontWeight: 500,
                    }}
                  >
                    {entry.channelDisplay}
                  </span>

                  {/* Event ID */}
                  <span
                    style={{
                      fontSize: 10,
                      padding: "1px 4px",
                      borderRadius: 3,
                      background: tokens.colorNeutralBackground3,
                      color: tokens.colorNeutralForeground3,
                      whiteSpace: "nowrap",
                    }}
                  >
                    ID {entry.eventId}
                  </span>

                  {/* Message */}
                  <span
                    style={{
                      flex: 1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      color: tokens.colorNeutralForeground1,
                    }}
                  >
                    {entry.message || "(no message)"}
                  </span>

                  {/* Correlation indicator */}
                  {hasCorrelationLinks(entry.id, correlationLinks) && (
                    <span
                      style={{
                        fontSize: 10,
                        padding: "1px 4px",
                        borderRadius: 3,
                        background: tokens.colorPaletteTealForeground2,
                        color: tokens.colorNeutralCardBackground,
                        whiteSpace: "nowrap",
                        flexShrink: 0,
                      }}
                    >
                      linked
                    </span>
                  )}
                </div>

                {/* Expanded details */}
                {isExpanded && (
                  <div
                    style={{
                      padding: "8px 12px 12px 30px",
                      background: tokens.colorNeutralBackground3,
                      borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                      fontSize: 12,
                    }}
                  >
                    {/* Full message */}
                    <div
                      style={{
                        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                        fontSize: 11,
                        padding: "6px 8px",
                        background: tokens.colorNeutralCardBackground,
                        border: `1px solid ${tokens.colorNeutralStroke2}`,
                        borderRadius: 4,
                        maxHeight: 100,
                        overflow: "auto",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-word",
                        marginBottom: 8,
                      }}
                    >
                      {entry.message || "(no message)"}
                    </div>

                    {/* Metadata */}
                    <div
                      style={{
                        display: "flex",
                        gap: 16,
                        flexWrap: "wrap",
                        color: tokens.colorNeutralForeground3,
                        fontSize: 11,
                        marginBottom: 8,
                      }}
                    >
                      <span>
                        <strong>Provider:</strong> {entry.provider}
                      </span>
                      {entry.computer && (
                        <span>
                          <strong>Computer:</strong> {entry.computer}
                        </span>
                      )}
                      {entry.correlationActivityId && (
                        <span>
                          <strong>Activity:</strong>{" "}
                          {entry.correlationActivityId}
                        </span>
                      )}
                      <span>
                        <strong>Source:</strong>{" "}
                        {getFileName(entry.sourceFile)}
                      </span>
                    </div>

                    {/* Correlation links */}
                    {entryLinks.length > 0 && (
                      <div style={{ marginTop: 4 }}>
                        <div
                          style={{
                            fontSize: 11,
                            fontWeight: 600,
                            color: tokens.colorNeutralForeground1,
                            marginBottom: 4,
                          }}
                        >
                          Related IME Evidence
                        </div>
                        {entryLinks.map((link, i) => (
                          <CorrelationLinkRow
                            key={i}
                            link={link}
                            events={events}
                            onNavigateToTimeline={handleNavigateToTimeline}
                            onNavigateToOverview={onNavigateToOverview}
                          />
                        ))}
                      </div>
                    )}
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

function CorrelationLinkRow({
  link,
  events,
  onNavigateToTimeline,
  onNavigateToOverview,
}: {
  link: EventLogCorrelationLink;
  events: { id: number; name: string; eventType: string; status: string }[];
  onNavigateToTimeline?: (id: number) => void;
  onNavigateToOverview?: () => void;
}) {
  if (link.linkedIntuneEventId != null) {
    const imeEvent = events.find((e) => e.id === link.linkedIntuneEventId);
    const label = imeEvent
      ? `${imeEvent.eventType}: ${imeEvent.name} (${imeEvent.status})`
      : `IME Event #${link.linkedIntuneEventId}`;
    const deltaLabel = link.timeDeltaSecs != null ? ` (${formatDelta(link.timeDeltaSecs)})` : "";

    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          fontSize: 11,
          color: tokens.colorNeutralForeground1,
          padding: "2px 0",
        }}
      >
        <span
          style={{
            fontSize: 9,
            padding: "1px 3px",
            borderRadius: 2,
            background: tokens.colorNeutralBackground3,
            color: tokens.colorNeutralForeground3,
          }}
        >
          {link.correlationKind}
        </span>
        <span style={{ flex: 1 }}>
          {label}
          {deltaLabel}
        </span>
        {onNavigateToTimeline && link.linkedIntuneEventId != null && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onNavigateToTimeline(link.linkedIntuneEventId!);
            }}
            style={{
              fontSize: 10,
              padding: "2px 6px",
              borderRadius: 3,
              border: `1px solid ${tokens.colorPaletteTealForeground2}`,
              background: "transparent",
              color: tokens.colorPaletteTealForeground2,
              cursor: "pointer",
            }}
          >
            View in Timeline
          </button>
        )}
      </div>
    );
  }

  if (link.linkedDiagnosticId != null) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          fontSize: 11,
          color: tokens.colorNeutralForeground1,
          padding: "2px 0",
        }}
      >
        <span
          style={{
            fontSize: 9,
            padding: "1px 3px",
            borderRadius: 2,
            background: tokens.colorNeutralBackground3,
            color: tokens.colorNeutralForeground3,
          }}
        >
          {link.correlationKind}
        </span>
        <span>Diagnostic: {link.linkedDiagnosticId}</span>
        {onNavigateToOverview && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onNavigateToOverview();
            }}
            style={{
              fontSize: 10,
              padding: "2px 6px",
              borderRadius: 3,
              border: `1px solid ${tokens.colorPaletteTealForeground2}`,
              background: "transparent",
              color: tokens.colorPaletteTealForeground2,
              cursor: "pointer",
            }}
          >
            View Diagnostic
          </button>
        )}
      </div>
    );
  }

  return null;
}

function hasCorrelationLinks(
  entryId: number,
  links: EventLogCorrelationLink[]
): boolean {
  return links.some((l) => l.eventLogEntryId === entryId);
}

function formatTimestamp(ts: string): string {
  if (!ts) return "";
  try {
    return formatDisplayDateTime(ts) ?? ts.replace("T", " ").replace("Z", "").slice(0, 23);
  } catch {
    return ts.replace("T", " ").replace("Z", "").slice(0, 23);
  }
}

function formatDelta(secs: number): string {
  if (secs < 60) return `${Math.round(secs)}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  return `${Math.round(secs / 3600)}h`;
}

function getFileName(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return segments[segments.length - 1] || path;
}

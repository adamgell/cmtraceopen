import { tokens } from "@fluentui/react-components";
import type { TimelineEntry, LogSource, TimelineEventType } from "./types";

function sourceColors(source: LogSource) {
  switch (source) {
    case "detect":
      return {
        badge: tokens.colorPaletteBlueForeground2,
        badgeBg: tokens.colorPaletteBlueBorderActive,
      };
    case "remediate":
      return {
        badge: tokens.colorPaletteMarigoldForeground2,
        badgeBg: tokens.colorPaletteYellowBackground1,
      };
    case "system":
    default:
      return {
        badge: tokens.colorNeutralForeground3,
        badgeBg: tokens.colorNeutralBackground3,
      };
  }
}

function isHighlightedEvent(eventType: TimelineEventType): boolean {
  return (
    eventType === "stageTransition" ||
    eventType === "error" ||
    eventType === "fallback"
  );
}

function highlightBorderColor(eventType: TimelineEventType): string | undefined {
  switch (eventType) {
    case "stageTransition":
      return tokens.colorPaletteGreenBorder2;
    case "error":
      return tokens.colorPaletteRedBorder2;
    case "fallback":
      return tokens.colorPaletteYellowBorder2;
    default:
      return undefined;
  }
}

function TimelineRow({ entry }: { entry: TimelineEntry }) {
  const colors = sourceColors(entry.source);
  const highlighted = isHighlightedEvent(entry.eventType);
  const leftBorder = highlighted ? highlightBorderColor(entry.eventType) : undefined;

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "180px 80px minmax(0, 1fr)",
        gap: "8px",
        padding: "6px 10px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        borderLeft: leftBorder ? `3px solid ${leftBorder}` : "3px solid transparent",
        alignItems: "baseline",
        fontFamily: "monospace",
        fontSize: "12px",
        backgroundColor: highlighted
          ? tokens.colorNeutralBackground2
          : undefined,
      }}
    >
      <span
        style={{
          color: tokens.colorNeutralForeground3,
          whiteSpace: "nowrap",
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {entry.timestamp}
      </span>

      <span
        style={{
          display: "inline-block",
          padding: "1px 5px",
          borderRadius: "3px",
          fontSize: "10px",
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.03em",
          color: colors.badge,
          backgroundColor: colors.badgeBg,
          whiteSpace: "nowrap",
          fontFamily: "inherit",
        }}
      >
        {entry.source}
      </span>

      <span
        style={{
          color: tokens.colorNeutralForeground1,
          wordBreak: "break-word",
          fontWeight: highlighted ? 600 : 400,
        }}
      >
        {entry.message}
        {entry.errorCode && (
          <span style={{ marginLeft: "6px", color: tokens.colorPaletteRedForeground1 }}>
            [{entry.errorCode}]
          </span>
        )}
        {entry.stage && (
          <span style={{ marginLeft: "6px", color: tokens.colorPaletteGreenForeground1 }}>
            → {entry.stage}
          </span>
        )}
      </span>
    </div>
  );
}

export interface TimelineTabProps {
  timeline: TimelineEntry[];
}

export function TimelineTab({ timeline }: TimelineTabProps) {
  if (timeline.length === 0) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "48px 24px",
          color: tokens.colorNeutralForeground3,
          fontSize: "13px",
          textAlign: "center",
        }}
      >
        No timeline data is available for this analysis.
      </div>
    );
  }

  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderRadius: "8px",
        overflow: "hidden",
        backgroundColor: tokens.colorNeutralCardBackground,
      }}
    >
      {/* Header row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "180px 80px minmax(0, 1fr)",
          gap: "8px",
          padding: "6px 10px",
          paddingLeft: "13px",
          backgroundColor: tokens.colorNeutralBackground3,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          fontSize: "11px",
          fontWeight: 700,
          color: tokens.colorNeutralForeground3,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        <span>Timestamp</span>
        <span>Source</span>
        <span>Message</span>
      </div>

      {timeline.map((entry, index) => (
        <TimelineRow key={`${entry.timestamp}-${index}`} entry={entry} />
      ))}
    </div>
  );
}

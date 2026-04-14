import { memo } from "react";
import { tokens } from "@fluentui/react-components";
import type { LogEntry } from "../../types/log";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";

interface SectionDividerRowProps {
  entry: LogEntry;
  resolvedColor: string;
  listFontSize: number;
  rowLineHeight: number;
  onClick: (id: number) => void;
}

/**
 * Full-width banner row for Section and Iteration entry kinds.
 * Rendered in place of a LogRow inside the virtualizer.
 */
export const SectionDividerRow = memo(function SectionDividerRow({
  entry,
  resolvedColor,
  listFontSize,
  rowLineHeight,
  onClick,
}: SectionDividerRowProps) {
  // ~13% opacity tint of the section color
  const bgTint = `${resolvedColor}21`;

  return (
    <div
      id={`log-list-row-${entry.id}`}
      role="option"
      aria-selected={false}
      className="section-divider-row"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        height: "100%",
        padding: "0 8px",
        backgroundColor: bgTint,
        borderLeft: `4px solid ${resolvedColor}`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        fontFamily: LOG_UI_FONT_FAMILY,
        fontSize: `${listFontSize}px`,
        lineHeight: `${rowLineHeight}px`,
        fontWeight: 600,
        color: tokens.colorNeutralForeground1,
        cursor: "pointer",
        whiteSpace: "nowrap",
        overflow: "hidden",
        textOverflow: "ellipsis",
        boxSizing: "border-box",
      }}
      onClick={() => onClick(entry.id)}
    >
      {/* Section/Iteration icon */}
      <span
        style={{
          display: "inline-block",
          width: 10,
          height: 10,
          borderRadius: entry.entryKind === "Iteration" ? 2 : "50%",
          backgroundColor: resolvedColor,
          flexShrink: 0,
        }}
      />

      <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
        {entry.message}
      </span>

      {entry.entryKind === "Iteration" && entry.iteration && (
        <span
          style={{
            fontSize: `${Math.max(listFontSize - 1, 9)}px`,
            opacity: 0.7,
            fontWeight: 400,
          }}
        >
          {entry.iteration}
        </span>
      )}
    </div>
  );
});

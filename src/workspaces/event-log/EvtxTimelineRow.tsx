import { memo, forwardRef } from "react";
import { tokens } from "@fluentui/react-components";
import {
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { EvtxRecord, EvtxLevel } from "./types";

const LEVEL_COLORS: Record<EvtxLevel, string> = {
  Critical: tokens.colorPaletteRedForeground1,
  Error: tokens.colorPaletteRedForeground1,
  Warning: tokens.colorPaletteMarigoldForeground1,
  Information: tokens.colorBrandForeground1,
  Verbose: tokens.colorNeutralForeground4,
};

const LEVEL_SHORT: Record<EvtxLevel, string> = {
  Critical: "CRIT",
  Error: "ERR",
  Warning: "WARN",
  Information: "INFO",
  Verbose: "VERB",
};

export interface EvtxTimelineRowProps {
  record: EvtxRecord;
  dataIndex: number;
  isSelected: boolean;
  fontSize: number;
  smallFontSize: number;
  monoFontSize: number;
  lineHeight: string;
  onSelect: (id: number | null) => void;
}

export const EvtxTimelineRow = memo(
  forwardRef<HTMLDivElement, EvtxTimelineRowProps>(function EvtxTimelineRow(
    {
      record,
      dataIndex,
      isSelected,
      fontSize,
      smallFontSize,
      monoFontSize,
      lineHeight,
      onSelect,
    },
    ref
  ) {
    const levelColor = LEVEL_COLORS[record.level];

    return (
      <div
        data-index={dataIndex}
        ref={ref}
        onClick={() => onSelect(isSelected ? null : record.id)}
        role="option"
        aria-selected={isSelected}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelect(isSelected ? null : record.id);
          }
        }}
        style={{
          display: "flex",
          alignItems: "center",
          padding: "2px 12px",
          cursor: "pointer",
          backgroundColor: isSelected
            ? tokens.colorNeutralBackground1Selected
            : dataIndex % 2 === 0
              ? tokens.colorNeutralBackground1
              : tokens.colorNeutralBackground2,
          borderLeft: `4px solid ${levelColor}`,
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          height: "100%",
          boxSizing: "border-box",
          fontSize: `${fontSize}px`,
          lineHeight,
          gap: "10px",
          minWidth: 0,
        }}
      >
        {/* Level badge */}
        <div
          style={{
            fontSize: `${smallFontSize}px`,
            fontWeight: 700,
            padding: "2px 6px",
            borderRadius: "3px",
            backgroundColor: levelColor,
            color: tokens.colorNeutralForegroundOnBrand,
            width: "40px",
            textAlign: "center",
            flexShrink: 0,
            textTransform: "uppercase",
          }}
        >
          {LEVEL_SHORT[record.level]}
        </div>

        {/* Timestamp */}
        <div
          style={{
            fontSize: `${monoFontSize}px`,
            color: tokens.colorNeutralForeground3,
            flexShrink: 0,
            width: "165px",
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          }}
          title={record.timestamp}
        >
          {record.timestamp}
        </div>

        {/* Event ID */}
        <div
          style={{
            fontSize: `${monoFontSize}px`,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            color: tokens.colorNeutralForeground2,
            width: "50px",
            textAlign: "right",
            flexShrink: 0,
          }}
        >
          {record.eventId}
        </div>

        {/* Channel badge */}
        <div
          style={{
            fontSize: `${smallFontSize}px`,
            color: tokens.colorNeutralForeground2,
            backgroundColor: tokens.colorNeutralBackground3,
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: "999px",
            padding: "2px 6px",
            maxWidth: "140px",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flexShrink: 1,
          }}
          title={record.channel}
        >
          {record.channel}
        </div>

        {/* Provider */}
        <div
          style={{
            fontSize: `${smallFontSize}px`,
            color: tokens.colorNeutralForeground4,
            maxWidth: "120px",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            flexShrink: 1,
          }}
          title={record.provider}
        >
          {record.provider}
        </div>

        {/* Message preview */}
        <div
          style={{
            flex: 1,
            fontSize: `${fontSize}px`,
            fontWeight: isSelected ? 600 : 400,
            color: isSelected
              ? tokens.colorBrandForeground1
              : tokens.colorNeutralForeground1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
          title={record.message}
        >
          {record.message}
        </div>
      </div>
    );
  })
);

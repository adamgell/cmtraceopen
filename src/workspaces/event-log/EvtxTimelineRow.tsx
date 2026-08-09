import { memo, forwardRef } from "react";
import { tokens } from "@fluentui/react-components";
import {
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { EvtxRecord, EvtxLevel } from "./types";
import {
  columnValue,
  columnWidth,
  visibleColumns,
  type EvtxColumnConfig,
} from "./evtx-columns";
import type { EvtxTimeZoneMode } from "./evtx-time";

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
  columnConfig: EvtxColumnConfig;
  /** Passed rather than read from the store, so a memoized row re-renders when the clock changes. */
  timeZoneMode: EvtxTimeZoneMode;
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
      columnConfig,
      timeZoneMode,
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
        {visibleColumns(columnConfig).map((column) => {
          const width = columnWidth(columnConfig, column);
          const value = columnValue(record, column.id, timeZoneMode);

          if (column.id === "level") {
            return (
              <div
                key={column.id}
                style={{
                  fontSize: `${smallFontSize}px`,
                  fontWeight: 700,
                  padding: "2px 6px",
                  borderRadius: "4px",
                  backgroundColor: levelColor,
                  color: tokens.colorNeutralForegroundOnBrand,
                  width: width != null ? `${width}px` : undefined,
                  textAlign: "center",
                  flexShrink: 0,
                  boxSizing: "border-box",
                }}
              >
                {LEVEL_SHORT[record.level]}
              </div>
            );
          }

          const isDescription = column.id === "message";
          const isMono = column.id === "timestamp" || column.id === "keywords";

          return (
            <div
              key={column.id}
              style={
                isDescription
                  ? {
                      flex: 1,
                      fontSize: `${fontSize}px`,
                      fontWeight: isSelected ? 600 : 400,
                      color: isSelected
                        ? tokens.colorBrandForeground1
                        : tokens.colorNeutralForeground1,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      minWidth: 0,
                    }
                  : {
                      width: width != null ? `${width}px` : undefined,
                      flexShrink: width != null ? 0 : 1,
                      fontSize: `${isMono ? monoFontSize : smallFontSize}px`,
                      fontFamily: isMono ? LOG_MONOSPACE_FONT_FAMILY : undefined,
                      color: tokens.colorNeutralForeground3,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      boxSizing: "border-box",
                    }
              }
              title={value}
            >
              {value}
            </div>
          );
        })}
      </div>
    );
  })
);

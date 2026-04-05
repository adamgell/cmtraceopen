import { memo, forwardRef } from "react";
import { Button, Tooltip, tokens } from "@fluentui/react-components";
import { CopyRegular } from "@fluentui/react-icons";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import {
  LOG_MONOSPACE_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { IntuneEvent, IntuneStatus, IntuneEventType } from "./types";
import { ScriptCodeViewer } from "./ScriptCodeViewer";

export const STATUS_COLORS: Record<IntuneStatus, string> = {
  Success: tokens.colorPaletteGreenForeground1,
  Failed: tokens.colorPaletteRedForeground1,
  InProgress: tokens.colorBrandForeground1,
  Pending: tokens.colorNeutralForeground4,
  Timeout: tokens.colorPaletteMarigoldForeground1,
  Unknown: tokens.colorNeutralForeground3,
};

export const EVENT_TYPE_LABELS: Record<IntuneEventType, string> = {
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

export function getFileName(sourceFile: string): string {
  const normalized = sourceFile.replace(/\\/g, "/");
  const segments = normalized.split("/");
  return segments[segments.length - 1] || sourceFile;
}

export function formatDuration(secs: number): string {
  const totalSeconds = Math.round(secs);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const totalMinutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (totalMinutes < 60) return `${totalMinutes}m ${seconds}s`;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${hours}h ${minutes}m ${seconds}s`;
}

function formatSourceLabel(sourceFile: string, lineNumber: number): string {
  return `${getFileName(sourceFile)}:${lineNumber}`;
}

function buildClipboardText(event: IntuneEvent): string {
  const details = [
    `Event: ${event.name}`,
    `Type: ${event.eventType}`,
    `Status: ${event.status}`,
    event.startTime
      ? `Start: ${formatDisplayDateTime(event.startTime) ?? event.startTime}`
      : null,
    event.endTime
      ? `End: ${formatDisplayDateTime(event.endTime) ?? event.endTime}`
      : null,
    event.errorCode ? `Error: ${event.errorCode}` : null,
    `Source: ${formatSourceLabel(event.sourceFile, event.lineNumber)}`,
    "",
    event.detail,
  ];

  return details.filter((line): line is string => line !== null).join("\n");
}

export interface EventTimelineRowProps {
  event: IntuneEvent;
  dataIndex: number;
  isSelected: boolean;
  fontSize: number;
  smallFontSize: number;
  monoFontSize: number;
  lineHeight: string;
  rowLineHeightExpanded: number;
  showSourceFileLabel: boolean;
  onSelect: (eventId: number | null) => void;
}

export const EventTimelineRow = memo(
  forwardRef<HTMLDivElement, EventTimelineRowProps>(function EventTimelineRow(
    {
      event,
      dataIndex,
      isSelected,
      fontSize,
      smallFontSize,
      monoFontSize,
      lineHeight,
      rowLineHeightExpanded,
      showSourceFileLabel,
      onSelect,
    },
    ref
  ) {
    const copyLabel =
      event.status === "Failed" || event.status === "Timeout"
        ? "Copy error + context"
        : "Copy details";

    const handleCopy = async () => {
      try {
        await writeText(buildClipboardText(event));
      } catch (err) {
        console.warn("Clipboard write failed:", err);
      }
    };

    return (
      <div
        data-index={dataIndex}
        ref={ref}
        onClick={() => onSelect(isSelected ? null : event.id)}
        role="option"
        aria-selected={isSelected}
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelect(isSelected ? null : event.id);
          }
        }}
        style={{
          display: "flex",
          flexDirection: isSelected ? "column" : "row",
          alignItems: isSelected ? "stretch" : "center",
          padding: isSelected ? "8px 12px" : "2px 12px",
          cursor: "pointer",
          backgroundColor: isSelected
            ? tokens.colorNeutralBackground1Selected
            : dataIndex % 2 === 0
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
              color: tokens.colorNeutralForegroundOnBrand,
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
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  gap: "8px",
                  marginBottom: "6px",
                }}
              >
                <div
                  style={{
                    fontSize: `${smallFontSize}px`,
                    fontWeight: 700,
                    color: tokens.colorNeutralForeground3,
                    textTransform: "uppercase",
                    letterSpacing: "0.04em",
                  }}
                >
                  {event.status === "Failed" || event.status === "Timeout"
                    ? "Failure context"
                    : "Details"}
                </div>
                <Tooltip content={copyLabel} relationship="label">
                  <Button
                    size="small"
                    appearance="subtle"
                    icon={<CopyRegular />}
                    onClick={(e) => {
                      e.stopPropagation();
                      void handleCopy();
                    }}
                  >
                    {copyLabel}
                  </Button>
                </Tooltip>
              </div>
              <div
                style={{
                  fontSize: `${monoFontSize}px`,
                  color: tokens.colorNeutralForeground1,
                  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-all",
                  overflowWrap: "anywhere",
                  maxHeight:
                    event.status === "Failed" || event.status === "Timeout"
                      ? "320px"
                      : "120px",
                  overflow: "auto",
                  backgroundColor: tokens.colorNeutralBackground1,
                  border: `1px solid ${tokens.colorNeutralStroke1}`,
                  padding: "6px",
                  borderRadius: "4px",
                  lineHeight: `${rowLineHeightExpanded}px`,
                }}
              >
                {event.detail}
              </div>
              {event.scriptBody && (
                <ScriptCodeViewer script={event.scriptBody} maxHeight={250} />
              )}
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
  })
);

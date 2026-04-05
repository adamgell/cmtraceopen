import { useCallback, useEffect, useRef, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import type { DeploymentLogFile } from "./deployment-store";

function displayName(file: DeploymentLogFile): string {
  return file.appName ?? file.fileName;
}

function formatTimestamp(ts: string | null): string {
  if (!ts) return "";
  const dotIndex = ts.indexOf(".");
  return dotIndex > 0 ? ts.substring(0, dotIndex) : ts;
}

interface Column {
  key: string;
  label: string;
  defaultWidth: number;
  minWidth: number;
  render: (file: DeploymentLogFile) => React.ReactNode;
  style?: React.CSSProperties;
}

const COLUMNS: Column[] = [
  {
    key: "application",
    label: "Application",
    defaultWidth: 360,
    minWidth: 100,
    render: (f) => displayName(f),
  },
  {
    key: "version",
    label: "Version",
    defaultWidth: 100,
    minWidth: 50,
    render: (f) => f.appVersion ?? "",
  },
  {
    key: "type",
    label: "Type",
    defaultWidth: 70,
    minWidth: 40,
    render: (f) => f.deployType ?? "",
  },
  {
    key: "format",
    label: "Format",
    defaultWidth: 90,
    minWidth: 50,
    render: (f) => f.format,
  },
  {
    key: "outcome",
    label: "Outcome",
    defaultWidth: 80,
    minWidth: 50,
    render: (f) => f.outcome,
    style: {},
  },
  {
    key: "exitCode",
    label: "Exit Code",
    defaultWidth: 70,
    minWidth: 40,
    render: (f) => (f.exitCode != null ? String(f.exitCode) : ""),
  },
  {
    key: "start",
    label: "Start",
    defaultWidth: 140,
    minWidth: 60,
    render: (f) => formatTimestamp(f.startTime),
    style: { fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: "11px", color: tokens.colorNeutralForeground3 },
  },
  {
    key: "end",
    label: "End",
    defaultWidth: 140,
    minWidth: 60,
    render: (f) => formatTimestamp(f.endTime),
    style: { fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: "11px", color: tokens.colorNeutralForeground3 },
  },
];

function buildGridTemplate(widths: Record<string, number>): string {
  return COLUMNS.map((col) => `${widths[col.key] ?? col.defaultWidth}px`).join(" ");
}

export function DeploymentSuccessTable({
  files,
}: {
  files: DeploymentLogFile[];
}) {
  const [colWidths, setColWidths] = useState<Record<string, number>>({});
  const resizeRef = useRef<{
    key: string;
    startX: number;
    startWidth: number;
  } | null>(null);

  const onResizeStart = useCallback(
    (key: string, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const col = COLUMNS.find((c) => c.key === key);
      const currentWidth = colWidths[key] ?? col?.defaultWidth ?? 100;
      resizeRef.current = { key, startX: e.clientX, startWidth: currentWidth };
    },
    [colWidths]
  );

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      const { key, startX, startWidth } = resizeRef.current;
      const col = COLUMNS.find((c) => c.key === key);
      const minW = col?.minWidth ?? 40;
      const newWidth = Math.max(minW, startWidth + (e.clientX - startX));
      setColWidths((prev) => ({ ...prev, [key]: newWidth }));
    };
    const onMouseUp = () => {
      resizeRef.current = null;
    };
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };
  }, []);

  const gridTemplate = buildGridTemplate(colWidths);

  return (
    <div
      style={{
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        borderRadius: "4px",
        overflow: "auto",
        fontSize: "12px",
      }}
    >
      {/* Header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: gridTemplate,
          backgroundColor: tokens.colorNeutralBackground3,
          fontWeight: 600,
          position: "sticky",
          top: 0,
          zIndex: 1,
        }}
      >
        {COLUMNS.map((col, i) => (
          <ResizableHeader
            key={col.key}
            label={col.label}
            isFirst={i === 0}
            onResizeStart={(e) => onResizeStart(col.key, e)}
          />
        ))}
      </div>

      {/* Rows */}
      {files.map((file) => (
        <div
          key={file.path}
          style={{
            display: "grid",
            gridTemplateColumns: gridTemplate,
            borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
          }}
        >
          {COLUMNS.map((col, i) => (
            <div
              key={col.key}
              title={col.key === "application" ? file.fileName : undefined}
              style={{
                padding: "5px 10px",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                ...(i > 0
                  ? { borderLeft: `1px solid ${tokens.colorNeutralStroke2}` }
                  : {}),
                ...(col.key === "outcome"
                  ? {
                      color:
                        file.outcome === "success"
                          ? tokens.colorPaletteGreenForeground1
                          : file.outcome === "failure"
                            ? tokens.colorPaletteRedForeground1
                            : tokens.colorPaletteYellowForeground1,
                    }
                  : {}),
                ...col.style,
              }}
            >
              {col.render(file)}
            </div>
          ))}
        </div>
      ))}
    </div>
  );
}

function ResizableHeader({
  label,
  isFirst,
  onResizeStart,
}: {
  label: string;
  isFirst: boolean;
  onResizeStart: (e: React.MouseEvent) => void;
}) {
  const [hover, setHover] = useState(false);

  return (
    <div
      style={{
        position: "relative",
        padding: "6px 10px",
        overflow: "hidden",
        textOverflow: "ellipsis",
        whiteSpace: "nowrap",
        ...(isFirst
          ? {}
          : { borderLeft: `1px solid ${tokens.colorNeutralStroke2}` }),
      }}
    >
      {label}
      <div
        onMouseDown={onResizeStart}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        style={{
          position: "absolute",
          right: -2,
          top: 0,
          width: 10,
          height: "100%",
          cursor: "col-resize",
          zIndex: 1,
          display: "flex",
          alignItems: "flex-start",
          justifyContent: "center",
          paddingTop: 2,
        }}
      >
        <div
          style={{
            width: 4,
            height: 10,
            borderRadius: 1,
            backgroundColor: hover
              ? tokens.colorBrandStroke1
              : tokens.colorNeutralStroke2,
          }}
        />
      </div>
    </div>
  );
}

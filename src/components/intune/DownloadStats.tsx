import { useMemo, useCallback } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_UI_FONT_FAMILY, LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import type { DownloadStat } from "../../types/intune";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { compareDownloads } from "../../lib/intune-sort";
import { useIntuneStore } from "../../stores/intune-store";
import type { DownloadSortField } from "../../stores/intune-store";

interface DownloadStatsProps {
  downloads: DownloadStat[];
}

export function DownloadStats({ downloads }: DownloadStatsProps) {
  const downloadSortField = useIntuneStore((s) => s.downloadSortField);
  const downloadSortDirection = useIntuneStore((s) => s.downloadSortDirection);
  const setDownloadSortField = useIntuneStore((s) => s.setDownloadSortField);
  const toggleDownloadSortDirection = useIntuneStore((s) => s.toggleDownloadSortDirection);

  const aggregate = useMemo(() => {
    let success = 0;
    let failed = 0;
    let totalBytes = 0;

    for (const download of downloads) {
      if (download.success) {
        success += 1;
      } else {
        failed += 1;
      }
      totalBytes += Math.max(download.sizeBytes, 0);
    }

    return { success, failed, totalBytes };
  }, [downloads]);

  const sortedDownloads = useMemo(() => {
    return [...downloads].sort((a, b) =>
      compareDownloads(a, b, downloadSortField, downloadSortDirection)
    );
  }, [downloads, downloadSortField, downloadSortDirection]);

  const sortIndicator = (field: DownloadSortField) =>
    downloadSortField === field ? (downloadSortDirection === "asc" ? " ▲" : " ▼") : "";

  const handleHeaderClick = (field: DownloadSortField) => {
    if (downloadSortField === field) {
      toggleDownloadSortDirection();
    } else {
      setDownloadSortField(field);
    }
  };

  const handleHeaderKeyDown = useCallback(
    (e: React.KeyboardEvent, field: DownloadSortField) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleHeaderClick(field);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [downloadSortField],
  );

  const ariaSort = (field: DownloadSortField): "ascending" | "descending" | "none" =>
    downloadSortField === field
      ? downloadSortDirection === "asc"
        ? "ascending"
        : "descending"
      : "none";

  if (downloads.length === 0) {
    return (
      <div style={{ padding: "20px", color: tokens.colorNeutralForeground3, textAlign: "center", fontSize: "12px" }}>
        No content download events were found in this analysis.
      </div>
    );
  }

  return (
    <div style={{ overflow: "auto", height: "100%", backgroundColor: tokens.colorNeutralCardBackground, display: "flex", flexDirection: "column" }}>
      <div
        style={{
          display: "flex",
          gap: "24px",
          alignItems: "center",
          padding: "6px 16px",
          fontSize: "11px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground3,
          flexShrink: 0,
        }}
      >
        <strong style={{ fontSize: "12px", color: tokens.colorNeutralForeground1 }}>{downloads.length} files</strong>
        <div style={{ display: "flex", gap: "16px", color: tokens.colorNeutralForeground3 }}>
          <span>Success: <strong style={{ color: tokens.colorPaletteGreenForeground1 }}>{aggregate.success}</strong></span>
          <span>Failure: <strong style={{ color: tokens.colorPaletteRedForeground1 }}>{aggregate.failed}</strong></span>
          <span>Transferred: <strong style={{ color: tokens.colorNeutralForeground1 }}>{formatBytes(aggregate.totalBytes)}</strong></span>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: "11px",
            fontFamily: LOG_UI_FONT_FAMILY,
          }}
        >
          <thead style={{ position: "sticky", top: 0, zIndex: 1 }}>
            <tr
              style={{
                backgroundColor: tokens.colorNeutralBackground2,
                borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
              }}
            >
              <th style={thStyle}>Status</th>
              <th style={{ ...thStyle, cursor: "pointer" }} tabIndex={0} aria-sort={ariaSort("name")} onClick={() => handleHeaderClick("name")} onKeyDown={(e) => handleHeaderKeyDown(e, "name")}>Content{sortIndicator("name")}</th>
              <th style={{ ...thStyle, textAlign: "right", width: "80px", cursor: "pointer" }} tabIndex={0} aria-sort={ariaSort("size")} onClick={() => handleHeaderClick("size")} onKeyDown={(e) => handleHeaderKeyDown(e, "size")}>Size{sortIndicator("size")}</th>
              <th style={{ ...thStyle, textAlign: "right", width: "90px", cursor: "pointer" }} tabIndex={0} aria-sort={ariaSort("speed")} onClick={() => handleHeaderClick("speed")} onKeyDown={(e) => handleHeaderKeyDown(e, "speed")}>Speed{sortIndicator("speed")}</th>
              <th style={{ ...thStyle, width: "120px", cursor: "pointer" }} tabIndex={0} aria-sort={ariaSort("doPercentage")} onClick={() => handleHeaderClick("doPercentage")} onKeyDown={(e) => handleHeaderKeyDown(e, "doPercentage")}>DO %{sortIndicator("doPercentage")}</th>
              <th style={{ ...thStyle, textAlign: "right", width: "70px", cursor: "pointer" }} tabIndex={0} aria-sort={ariaSort("duration")} onClick={() => handleHeaderClick("duration")} onKeyDown={(e) => handleHeaderKeyDown(e, "duration")}>Dur.{sortIndicator("duration")}</th>
              <th style={{ ...thStyle, width: "130px", cursor: "pointer" }} tabIndex={0} aria-sort={ariaSort("timestamp")} onClick={() => handleHeaderClick("timestamp")} onKeyDown={(e) => handleHeaderKeyDown(e, "timestamp")}>Timestamp{sortIndicator("timestamp")}</th>
            </tr>
          </thead>
          <tbody>
            {sortedDownloads.map((dl, i) => (
              <tr
                key={`${dl.contentId}-${dl.timestamp ?? i}-${i}`}
                style={{
                  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                  backgroundColor: i % 2 === 0 ? tokens.colorNeutralCardBackground : tokens.colorNeutralBackground2,
                }}
              >
                <td style={tdStyle}>
                  <div
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      backgroundColor: dl.success ? tokens.colorPaletteGreenForeground1 : tokens.colorPaletteRedForeground1,
                      margin: "0 auto",
                    }}
                    title={dl.success ? "Success" : "Failed"}
                  />
                </td>
                <td style={{ ...tdStyle, color: tokens.colorNeutralForeground1, fontWeight: 500 }} title={dl.contentId}>
                  {dl.name}
                </td>
                <td style={{ ...tdStyle, textAlign: "right", color: tokens.colorNeutralForeground3, fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
                  {formatBytes(dl.sizeBytes)}
                </td>
                <td style={{ ...tdStyle, textAlign: "right", color: tokens.colorNeutralForeground3, fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
                  {dl.speedBps > 0 ? `${formatBytes(dl.speedBps)}/s` : "—"}
                </td>
                <td style={tdStyle}>
                  {dl.doPercentage > 0 ? (
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <div
                        style={{
                          flex: 1,
                          height: "6px",
                          backgroundColor: tokens.colorNeutralBackground3,
                          borderRadius: "3px",
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            width: `${Math.min(dl.doPercentage, 100)}%`,
                            height: "100%",
                            backgroundColor: dl.doPercentage > 50 ? tokens.colorPaletteGreenForeground1 : tokens.colorBrandForeground1,
                            borderRadius: "3px",
                          }}
                        />
                      </div>
                      <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground3, width: "32px", textAlign: "right" }}>
                        {dl.doPercentage.toFixed(1)}%
                      </span>
                    </div>
                  ) : (
                    <span style={{ color: tokens.colorNeutralForeground4 }}>—</span>
                  )}
                </td>
                <td style={{ ...tdStyle, textAlign: "right", color: tokens.colorNeutralForeground3, fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
                  {dl.durationSecs > 0 ? `${dl.durationSecs.toFixed(1)}s` : "—"}
                </td>
                <td style={{ ...tdStyle, color: tokens.colorNeutralForeground3, fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: "10px" }}>
                  {(dl.timestamp && formatDisplayDateTime(dl.timestamp)) || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  padding: "4px 8px",
  textAlign: "left",
  fontWeight: 600,
  color: tokens.colorNeutralForeground3,
  whiteSpace: "nowrap",
  textTransform: "uppercase",
  fontSize: "9px",
  letterSpacing: "0.05em",
};

const tdStyle: React.CSSProperties = {
  padding: "4px 8px",
  whiteSpace: "nowrap",
  overflow: "hidden",
  textOverflow: "ellipsis",
};

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i > 0 ? 1 : 0)} ${units[Math.min(i, units.length - 1)]}`;
}

import { useMemo } from "react";
import type { DownloadStat } from "../../types/intune";

interface DownloadStatsProps {
  downloads: DownloadStat[];
}

export function DownloadStats({ downloads }: DownloadStatsProps) {
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

  if (downloads.length === 0) {
    return (
      <div style={{ padding: "20px", color: "#666", textAlign: "center", fontSize: "12px" }}>
        No content download events were found in this analysis.
      </div>
    );
  }

  return (
    <div style={{ overflow: "auto", height: "100%", backgroundColor: "#ffffff", display: "flex", flexDirection: "column" }}>
      <div
        style={{
          display: "flex",
          gap: "24px",
          alignItems: "center",
          padding: "6px 16px",
          fontSize: "11px",
          borderBottom: "1px solid #cbd5e1",
          backgroundColor: "#f1f5f9",
          flexShrink: 0,
        }}
      >
        <strong style={{ fontSize: "12px", color: "#0f172a" }}>{downloads.length} files</strong>
        <div style={{ display: "flex", gap: "16px", color: "#475569" }}>
          <span>Success: <strong style={{ color: "#16a34a" }}>{aggregate.success}</strong></span>
          <span>Failure: <strong style={{ color: "#dc2626" }}>{aggregate.failed}</strong></span>
          <span>Transferred: <strong style={{ color: "#0f172a" }}>{formatBytes(aggregate.totalBytes)}</strong></span>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            fontSize: "11px",
            fontFamily: "'Segoe UI', Tahoma, sans-serif",
          }}
        >
          <thead style={{ position: "sticky", top: 0, zIndex: 1 }}>
            <tr
              style={{
                backgroundColor: "#f8fafc",
                borderBottom: "1px solid #cbd5e1",
                boxShadow: "0 1px 2px rgba(0,0,0,0.02)",
              }}
            >
              <th style={thStyle}>Status</th>
              <th style={thStyle}>Content</th>
              <th style={{ ...thStyle, textAlign: "right", width: "80px" }}>Size</th>
              <th style={{ ...thStyle, textAlign: "right", width: "90px" }}>Speed</th>
              <th style={{ ...thStyle, width: "120px" }}>DO %</th>
              <th style={{ ...thStyle, textAlign: "right", width: "70px" }}>Dur.</th>
              <th style={{ ...thStyle, width: "130px" }}>Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {downloads.map((dl, i) => (
              <tr
                key={`${dl.contentId}-${dl.timestamp ?? i}-${i}`}
                style={{
                  borderBottom: "1px solid #f1f5f9",
                  backgroundColor: i % 2 === 0 ? "#ffffff" : "#fafafa",
                }}
              >
                <td style={tdStyle}>
                  <div
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      backgroundColor: dl.success ? "#22c55e" : "#ef4444",
                      margin: "0 auto",
                    }}
                    title={dl.success ? "Success" : "Failed"}
                  />
                </td>
                <td style={{ ...tdStyle, color: "#1e293b", fontWeight: 500 }} title={dl.contentId}>
                  {dl.name}
                </td>
                <td style={{ ...tdStyle, textAlign: "right", color: "#475569", fontFamily: "'Courier New', monospace" }}>
                  {formatBytes(dl.sizeBytes)}
                </td>
                <td style={{ ...tdStyle, textAlign: "right", color: "#475569", fontFamily: "'Courier New', monospace" }}>
                  {dl.speedBps > 0 ? `${formatBytes(dl.speedBps)}/s` : "—"}
                </td>
                <td style={tdStyle}>
                  {dl.doPercentage > 0 ? (
                    <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                      <div
                        style={{
                          flex: 1,
                          height: "6px",
                          backgroundColor: "#e2e8f0",
                          borderRadius: "3px",
                          overflow: "hidden",
                        }}
                      >
                        <div
                          style={{
                            width: `${Math.min(dl.doPercentage, 100)}%`,
                            height: "100%",
                            backgroundColor: dl.doPercentage > 50 ? "#10b981" : "#3b82f6",
                            borderRadius: "3px",
                          }}
                        />
                      </div>
                      <span style={{ fontSize: "10px", color: "#64748b", width: "32px", textAlign: "right" }}>
                        {dl.doPercentage.toFixed(1)}%
                      </span>
                    </div>
                  ) : (
                    <span style={{ color: "#94a3b8" }}>—</span>
                  )}
                </td>
                <td style={{ ...tdStyle, textAlign: "right", color: "#475569", fontFamily: "'Courier New', monospace" }}>
                  {dl.durationSecs > 0 ? `${dl.durationSecs.toFixed(1)}s` : "—"}
                </td>
                <td style={{ ...tdStyle, color: "#64748b", fontFamily: "'Courier New', monospace", fontSize: "10px" }}>
                  {dl.timestamp || "—"}
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
  color: "#475569",
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

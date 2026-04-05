import { useCallback, useEffect, useMemo } from "react";
import {
  Body1,
  Button,
  makeStyles,
  shorthands,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import { useMacosDiagStore } from "../../stores/macos-diag-store";
import { useUiStore } from "../../stores/ui-store";
import { macosScanIntuneLogs, openLogFile } from "../../lib/commands";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useLogStore } from "../../stores/log-store";
import type { MacosLogFileEntry } from "../../types/macos-diag";

const useStyles = makeStyles({
  statCards: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
    gap: "12px",
    marginBottom: "16px",
  },
  statCard: {
    ...shorthands.padding("14px", "16px"),
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    boxShadow: tokens.shadow2,
  },
  statLabel: {
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.4px",
    fontWeight: 600,
    marginBottom: "4px",
  },
  statValue: {
    fontSize: "22px",
    fontWeight: 700,
    color: tokens.colorNeutralForeground1,
    letterSpacing: "-0.5px",
  },
  statSub: {
    fontSize: "11px",
    color: tokens.colorNeutralForeground3,
    marginTop: "2px",
  },
  tableWrap: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    overflow: "hidden",
    boxShadow: tokens.shadow2,
  },
  tableHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    ...shorthands.padding("10px", "14px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground3,
  },
  tableTitle: {
    fontSize: "12px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  table: {
    width: "100%",
    borderCollapse: "collapse" as const,
  },
  th: {
    textAlign: "left" as const,
    ...shorthands.padding("8px", "14px"),
    fontSize: "10.5px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.4px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground3,
  },
  td: {
    ...shorthands.padding("9px", "14px"),
    fontSize: "12.5px",
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    color: tokens.colorNeutralForeground1,
  },
  mono: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11.5px",
  },
  sourceBadgeSystem: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
  },
  sourceBadgeUser: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPalettePurpleBackground2,
    color: tokens.colorPalettePurpleForeground2,
  },
  centered: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    ...shorthands.padding("40px"),
  },
  errorText: {
    color: tokens.colorPaletteRedForeground1,
    textAlign: "center" as const,
  },
});

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDate(unixMs: number | null): string {
  if (unixMs === null) return "--";
  const d = new Date(unixMs);
  const month = d.toLocaleString("en-US", { month: "short" });
  const day = d.getDate();
  const hours = d.getHours();
  const minutes = d.getMinutes().toString().padStart(2, "0");
  const ampm = hours >= 12 ? "PM" : "AM";
  const h = hours % 12 || 12;
  return `${month} ${day}, ${h}:${minutes} ${ampm}`;
}

function getSourceType(sourceDirectory: string): "system" | "user" {
  const lower = sourceDirectory.toLowerCase();
  // Check for user home paths first to avoid misclassifying ~/Library/Logs as system
  if (lower.startsWith("/users/") || lower.startsWith("~/")) {
    return "user";
  }
  if (
    lower.startsWith("/library/logs") ||
    lower.startsWith("/var/log")
  ) {
    return "system";
  }
  return "user";
}

export function MacosDiagIntuneLogsTab() {
  const styles = useStyles();
  const intuneLogScan = useMacosDiagStore((s) => s.intuneLogScan);
  const loading = useMacosDiagStore((s) => s.intuneLogScanLoading);
  const setIntuneLogScan = useMacosDiagStore((s) => s.setIntuneLogScan);
  const setLoading = useMacosDiagStore((s) => s.setIntuneLogScanLoading);
  const setActiveView = useUiStore((s) => s.setActiveView);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  const scan = useCallback(async () => {
    setLoading(true);
    try {
      const result = await macosScanIntuneLogs();
      setIntuneLogScan(result);
    } catch (err) {
      console.error("[macos-diag] intune log scan failed", err);
      setLoading(false);
    }
  }, [setLoading, setIntuneLogScan]);

  useEffect(() => {
    if (!intuneLogScan && !loading) {
      scan();
    }
  }, [intuneLogScan, loading, scan]);

  const handleOpenInLogViewer = async (file: MacosLogFileEntry) => {
    try {
      const result = await openLogFile(file.path);
      const logState = useLogStore.getState();
      logState.setEntries(result.entries);
      logState.setSourceStatus({
        kind: "loaded",
        message: `Loaded ${file.fileName}`,
      });
      setActiveView("log");
    } catch (err) {
      console.error("[macos-diag] failed to open log file", err);
    }
  };

  if (loading) {
    return (
      <div className={styles.centered}>
        <Spinner size="medium" label="Scanning Intune log directories..." />
      </div>
    );
  }

  if (!intuneLogScan) {
    return (
      <div className={styles.centered}>
        <Body1 className={styles.errorText}>
          No scan results available. Click Rescan to try again.
        </Body1>
        <Button appearance="primary" size="small" onClick={scan}>
          Rescan
        </Button>
      </div>
    );
  }

  const { files, scannedDirectories, totalSizeBytes } = intuneLogScan;

  const latestModified = (() => {
    const timestamps = files
      .map((f) => f.modifiedUnixMs)
      .filter((ms): ms is number => ms !== null);
    return timestamps.length > 0 ? Math.max(...timestamps) : null;
  })();

  const dirTotal = 4; // Expected: system, user, company portal, scripts
  const dirFound = scannedDirectories.length;

  return (
    <>
      <div className={styles.statCards}>
        <div className={styles.statCard}>
          <div className={styles.statLabel}>Log Files Found</div>
          <div className={styles.statValue}>{files.length}</div>
          <div className={styles.statSub}>
            across {scannedDirectories.length} directories
          </div>
        </div>
        <div className={styles.statCard}>
          <div className={styles.statLabel}>Total Size</div>
          <div className={styles.statValue}>{formatFileSize(totalSizeBytes)}</div>
          <div className={styles.statSub}>combined log data</div>
        </div>
        <div className={styles.statCard}>
          <div className={styles.statLabel}>Last Modified</div>
          <div className={styles.statValue}>
            {latestModified !== null
              ? new Date(latestModified).toLocaleTimeString("en-US", {
                  hour: "2-digit",
                  minute: "2-digit",
                })
              : "--"}
          </div>
          <div className={styles.statSub}>
            {latestModified !== null
              ? new Date(latestModified).toLocaleDateString("en-US", {
                  month: "long",
                  day: "numeric",
                  year: "numeric",
                })
              : "No files found"}
          </div>
        </div>
        <div className={styles.statCard}>
          <div className={styles.statLabel}>Directories</div>
          <div className={styles.statValue}>
            {dirFound} / {dirTotal}
          </div>
          <div className={styles.statSub}>
            {dirFound < dirTotal
              ? `${dirTotal - dirFound} not found`
              : "all present"}
          </div>
        </div>
      </div>

      <div className={styles.tableWrap}>
        <div className={styles.tableHeader}>
          <div className={styles.tableTitle}>Discovered Log Files</div>
          <Button size="small" appearance="subtle" onClick={scan}>
            Rescan
          </Button>
        </div>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.th}>File Name</th>
              <th className={styles.th}>Size</th>
              <th className={styles.th}>Last Modified</th>
              <th className={styles.th}>Source</th>
              <th className={styles.th}></th>
            </tr>
          </thead>
          <tbody>
            {files.map((file) => {
              const sourceType = getSourceType(file.sourceDirectory);
              return (
                <tr key={file.path} style={{ height: metrics.rowHeight }}>
                  <td className={`${styles.td} ${styles.mono}`} style={{ fontSize: metrics.fontSize }}>
                    {file.fileName}
                  </td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>{formatFileSize(file.sizeBytes)}</td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                    {formatDate(file.modifiedUnixMs)}
                  </td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                    <span
                      className={
                        sourceType === "system"
                          ? styles.sourceBadgeSystem
                          : styles.sourceBadgeUser
                      }
                    >
                      {sourceType}
                    </span>
                  </td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                    <Button
                      size="small"
                      appearance="primary"
                      onClick={() => handleOpenInLogViewer(file)}
                    >
                      Open in Log Viewer
                    </Button>
                  </td>
                </tr>
              );
            })}
            {files.length === 0 && (
              <tr>
                <td className={styles.td} colSpan={5} style={{ textAlign: "center", fontSize: metrics.fontSize }}>
                  No Intune log files found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

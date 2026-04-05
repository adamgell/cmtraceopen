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
import { useLogStore } from "../../stores/log-store";
import { macosInspectDefender, openLogFile } from "../../lib/commands";
import { getLogListMetrics } from "../../lib/log-accessibility";
import type { MacosLogFileEntry } from "../../types/macos-diag";

const useStyles = makeStyles({
  healthCard: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    ...shorthands.padding("16px"),
    marginBottom: "16px",
    boxShadow: tokens.shadow2,
  },
  healthHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
  },
  healthStatus: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
  },
  healthDot: {
    width: "10px",
    height: "10px",
    ...shorthands.borderRadius("50%"),
  },
  healthDotOk: {
    backgroundColor: tokens.colorPaletteGreenForeground1,
  },
  healthDotBad: {
    backgroundColor: tokens.colorPaletteRedForeground1,
  },
  healthDotUnknown: {
    backgroundColor: tokens.colorNeutralForeground3,
  },
  healthTitle: {
    fontSize: "15px",
    fontWeight: 700,
  },
  healthGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
    gap: "12px",
    marginTop: "12px",
  },
  healthItem: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    ...shorthands.padding("8px", "12px"),
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
  },
  healthItemLabel: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
  },
  healthItemValue: {
    fontSize: "12px",
    fontWeight: 600,
  },
  healthItemGood: {
    color: tokens.colorPaletteGreenForeground1,
  },
  healthItemBad: {
    color: tokens.colorPaletteRedForeground1,
  },
  tablesGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "12px",
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

export function MacosDiagDefenderTab() {
  const styles = useStyles();
  const defenderResult = useMacosDiagStore((s) => s.defenderResult);
  const loading = useMacosDiagStore((s) => s.defenderLoading);
  const setDefenderResult = useMacosDiagStore((s) => s.setDefenderResult);
  const setLoading = useMacosDiagStore((s) => s.setDefenderLoading);
  const setActiveView = useUiStore((s) => s.setActiveView);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  const fetch = useCallback(async () => {
    setLoading(true);
    try {
      const result = await macosInspectDefender();
      setDefenderResult(result);
    } catch (err) {
      console.error("[macos-diag] defender inspection failed", err);
      setLoading(false);
    }
  }, [setLoading, setDefenderResult]);

  useEffect(() => {
    if (!defenderResult && !loading) {
      fetch();
    }
  }, [defenderResult, loading, fetch]);

  const handleOpenLogFile = async (file: MacosLogFileEntry) => {
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
      console.error("[macos-diag] failed to open defender log", err);
    }
  };

  if (loading) {
    return (
      <div className={styles.centered}>
        <Spinner size="medium" label="Inspecting Defender..." />
      </div>
    );
  }

  if (!defenderResult) {
    return (
      <div className={styles.centered}>
        <Body1 className={styles.errorText}>
          No Defender data available.
        </Body1>
        <Button appearance="primary" size="small" onClick={fetch}>
          Refresh
        </Button>
      </div>
    );
  }

  const { health, logFiles, diagFiles } = defenderResult;

  const healthLabel =
    health === null
      ? "Defender Not Installed"
      : health.healthy === true
        ? "Defender Health: OK"
        : health.healthy === false
          ? "Defender Health: Issues Detected"
          : "Defender Health: Unknown";

  const healthDotClass =
    health === null
      ? styles.healthDotUnknown
      : health.healthy === true
        ? styles.healthDotOk
        : health.healthy === false
          ? styles.healthDotBad
          : styles.healthDotUnknown;

  interface HealthRow {
    label: string;
    value: string;
    good?: boolean;
  }

  const healthRows: HealthRow[] = health
    ? [
        {
          label: "Real-time Protection",
          value:
            health.realTimeProtectionEnabled === true
              ? "Enabled"
              : health.realTimeProtectionEnabled === false
                ? "Disabled"
                : "Unknown",
          good: health.realTimeProtectionEnabled === true,
        },
        {
          label: "Definitions",
          value: health.definitionsStatus ?? "Unknown",
          good: health.definitionsStatus?.toLowerCase().includes("up to date"),
        },
        {
          label: "Engine Version",
          value: health.engineVersion ?? "Unknown",
        },
        {
          label: "App Version",
          value: health.appVersion ?? "Unknown",
        },
      ]
    : [];

  return (
    <>
      {/* Health Card */}
      <div className={styles.healthCard}>
        <div className={styles.healthHeader}>
          <div className={styles.healthStatus}>
            <div className={`${styles.healthDot} ${healthDotClass}`} />
            <span className={styles.healthTitle}>{healthLabel}</span>
          </div>
          <Button size="small" appearance="subtle" onClick={fetch}>
            Refresh
          </Button>
        </div>

        {healthRows.length > 0 && (
          <div className={styles.healthGrid}>
            {healthRows.map((row) => (
              <div key={row.label} className={styles.healthItem}>
                <span className={styles.healthItemLabel} style={{ fontSize: metrics.fontSize }}>{row.label}</span>
                <span
                  className={`${styles.healthItemValue} ${
                    row.good === true
                      ? styles.healthItemGood
                      : row.good === false
                        ? styles.healthItemBad
                        : ""
                  }`}
                  style={{ fontSize: metrics.fontSize }}
                >
                  {row.value}
                </span>
              </div>
            ))}
          </div>
        )}

        {health && health.healthIssues.length > 0 && (
          <div style={{ marginTop: "12px" }}>
            {health.healthIssues.map((issue, i) => (
              <div
                key={i}
                style={{
                  fontSize: metrics.fontSize,
                  color: tokens.colorPaletteRedForeground1,
                  marginBottom: "4px",
                }}
              >
                {issue}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Two side-by-side tables */}
      <div className={styles.tablesGrid}>
        <div className={styles.tableWrap}>
          <div className={styles.tableHeader}>
            <div className={styles.tableTitle}>Log Files</div>
          </div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.th}>File</th>
                <th className={styles.th}>Size</th>
                <th className={styles.th}></th>
              </tr>
            </thead>
            <tbody>
              {logFiles.map((file) => (
                <tr key={file.path} style={{ height: metrics.rowHeight }}>
                  <td className={`${styles.td} ${styles.mono}`} style={{ fontSize: metrics.fontSize }}>
                    {file.fileName}
                  </td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                    {formatFileSize(file.sizeBytes)}
                  </td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                    <Button
                      size="small"
                      appearance="subtle"
                      onClick={() => handleOpenLogFile(file)}
                    >
                      Open
                    </Button>
                  </td>
                </tr>
              ))}
              {logFiles.length === 0 && (
                <tr>
                  <td className={styles.td} colSpan={3} style={{ textAlign: "center", fontSize: metrics.fontSize }}>
                    No log files found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className={styles.tableWrap}>
          <div className={styles.tableHeader}>
            <div className={styles.tableTitle}>Diagnostic Files</div>
          </div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th className={styles.th}>File</th>
                <th className={styles.th}>Size</th>
                <th className={styles.th}></th>
              </tr>
            </thead>
            <tbody>
              {diagFiles.map((file) => (
                <tr key={file.path} style={{ height: metrics.rowHeight }}>
                  <td className={`${styles.td} ${styles.mono}`} style={{ fontSize: metrics.fontSize }}>
                    {file.fileName}
                  </td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                    {formatFileSize(file.sizeBytes)}
                  </td>
                  <td className={styles.td} style={{ fontSize: metrics.fontSize }}>
                    <Button
                      size="small"
                      appearance="subtle"
                      onClick={() => handleOpenLogFile(file)}
                    >
                      Open
                    </Button>
                  </td>
                </tr>
              ))}
              {diagFiles.length === 0 && (
                <tr>
                  <td className={styles.td} colSpan={3} style={{ textAlign: "center", fontSize: metrics.fontSize }}>
                    No diagnostic files found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

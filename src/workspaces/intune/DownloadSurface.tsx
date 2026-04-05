import { useMemo } from "react";
import {
  Badge,
  Body1,
  Body1Strong,
  Caption1,
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import type { DownloadStat } from "./types";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import {
  LOG_UI_FONT_FAMILY,
  LOG_MONOSPACE_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";

interface DownloadSurfaceProps {
  downloads: DownloadStat[];
}

const useStyles = makeStyles({
  root: {
    display: "flex",
    flexDirection: "column",
    height: "100%",
    minHeight: 0,
  },
  summaryRow: {
    display: "flex",
    gap: "12px",
    flexWrap: "wrap",
    ...shorthands.padding("12px", "16px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground2,
    flexShrink: 0,
  },
  factCard: {
    ...shorthands.padding("10px", "14px"),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    backgroundColor: tokens.colorNeutralBackground1,
    minWidth: "120px",
    display: "grid",
    gap: "2px",
  },
  factValue: {
    fontWeight: 700,
    lineHeight: 1.2,
    color: tokens.colorNeutralForeground1,
  },
  tableWrapper: {
    flex: 1,
    overflowY: "auto",
    minHeight: 0,
  },
  table: {
    width: "100%",
    borderCollapse: "collapse" as const,
  },
  thead: {
    position: "sticky" as const,
    top: 0,
    zIndex: 1,
  },
  headerRow: {
    backgroundColor: tokens.colorNeutralBackground3,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  doBar: {
    display: "flex",
    alignItems: "center",
    gap: "6px",
  },
  doTrack: {
    flex: 1,
    height: "6px",
    backgroundColor: tokens.colorNeutralBackground4,
    ...shorthands.borderRadius("3px"),
    overflowX: "hidden",
  },
});

export function DownloadSurface({ downloads }: DownloadSurfaceProps) {
  const styles = useStyles();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );

  const aggregate = useMemo(() => {
    let totalBytes = 0;
    let successCount = 0;
    let failedCount = 0;
    let speedSum = 0;
    let speedCount = 0;
    let doWeightedSum = 0;
    let doWeightedBytes = 0;

    for (const dl of downloads) {
      if (dl.success) {
        successCount++;
        totalBytes += Math.max(dl.sizeBytes, 0);
      } else {
        failedCount++;
      }
      if (dl.speedBps > 0) {
        speedSum += dl.speedBps;
        speedCount++;
      }
      if (dl.doPercentage > 0 && dl.sizeBytes > 0) {
        doWeightedSum += dl.doPercentage * dl.sizeBytes;
        doWeightedBytes += dl.sizeBytes;
      }
    }

    return {
      totalBytes,
      successCount,
      failedCount,
      successRate:
        downloads.length > 0
          ? (successCount / downloads.length) * 100
          : 0,
      avgSpeed: speedCount > 0 ? speedSum / speedCount : 0,
      doEffectiveness:
        doWeightedBytes > 0 ? doWeightedSum / doWeightedBytes : 0,
    };
  }, [downloads]);

  const factFontSize = Math.round(metrics.fontSize * 1.4);

  if (downloads.length === 0) {
    return (
      <div
        style={{
          padding: 24,
          textAlign: "center",
        }}
      >
        <Body1>No content download events were found in this analysis.</Body1>
      </div>
    );
  }

  const thStyle: React.CSSProperties = {
    padding: `${Math.round(metrics.fontSize * 0.3)}px 8px`,
    textAlign: "left",
    fontWeight: 600,
    fontFamily: LOG_UI_FONT_FAMILY,
    color: tokens.colorNeutralForeground3,
    whiteSpace: "nowrap",
    textTransform: "uppercase",
    fontSize: `${Math.max(9, metrics.headerFontSize - 3)}px`,
    letterSpacing: "0.05em",
    lineHeight: `${metrics.headerLineHeight}px`,
  };

  const tdStyle: React.CSSProperties = {
    padding: `${Math.round(metrics.fontSize * 0.3)}px 8px`,
    whiteSpace: "nowrap",
    fontSize: `${metrics.fontSize}px`,
    fontFamily: LOG_UI_FONT_FAMILY,
    lineHeight: `${metrics.rowLineHeight}px`,
  };

  const monoStyle: React.CSSProperties = {
    ...tdStyle,
    fontFamily: LOG_MONOSPACE_FONT_FAMILY,
    color: tokens.colorNeutralForeground2,
  };

  return (
    <div className={styles.root}>
      {/* Aggregate summary row */}
      <div className={styles.summaryRow} role="region" aria-label="Download summary">
        <div className={styles.factCard}>
          <Caption1>Total transferred</Caption1>
          <div className={styles.factValue} style={{ fontSize: `${factFontSize}px` }}>
            {formatBytes(aggregate.totalBytes)}
          </div>
          <Caption1>
            across {aggregate.successCount} successful download
            {aggregate.successCount !== 1 ? "s" : ""}
          </Caption1>
        </div>

        <div className={styles.factCard}>
          <Caption1>Success rate</Caption1>
          <div
            className={styles.factValue}
            style={{
              fontSize: `${factFontSize}px`,
              color:
                aggregate.successRate >= 80
                  ? tokens.colorPaletteGreenForeground1
                  : aggregate.successRate >= 50
                    ? tokens.colorPaletteYellowForeground2
                    : tokens.colorPaletteRedForeground1,
            }}
          >
            {aggregate.successRate.toFixed(0)}%
          </div>
          <Caption1>
            {aggregate.successCount} succeeded, {aggregate.failedCount} failed
          </Caption1>
        </div>

        <div className={styles.factCard}>
          <Caption1>Avg speed</Caption1>
          <div className={styles.factValue} style={{ fontSize: `${factFontSize}px` }}>
            {aggregate.avgSpeed > 0
              ? `${formatBytes(aggregate.avgSpeed)}/s`
              : "—"}
          </div>
          <Caption1>
            {aggregate.avgSpeed > 0
              ? `across ${downloads.filter((d) => d.speedBps > 0).length} measured`
              : "no speed data"}
          </Caption1>
        </div>

        <div className={styles.factCard}>
          <Caption1>DO effectiveness</Caption1>
          <div className={styles.factValue} style={{ fontSize: `${factFontSize}px` }}>
            {aggregate.doEffectiveness > 0
              ? `${aggregate.doEffectiveness.toFixed(1)}%`
              : "—"}
          </div>
          <Caption1>
            {aggregate.doEffectiveness > 0
              ? "weighted by download size"
              : "no Delivery Optimization data"}
          </Caption1>
        </div>
      </div>

      {/* Detail table */}
      <div className={styles.tableWrapper}>
        <table
          className={styles.table}
          role="table"
          aria-label={`Content downloads — ${downloads.length} entries`}
        >
          <thead className={styles.thead}>
            <tr className={styles.headerRow}>
              <th style={thStyle} scope="col">Status</th>
              <th style={thStyle} scope="col">Content</th>
              <th style={{ ...thStyle, textAlign: "right", width: 80 }} scope="col">
                Size
              </th>
              <th style={{ ...thStyle, textAlign: "right", width: 90 }} scope="col">
                Speed
              </th>
              <th style={{ ...thStyle, width: 120 }} scope="col">DO %</th>
              <th style={{ ...thStyle, textAlign: "right", width: 70 }} scope="col">
                Dur.
              </th>
              <th style={{ ...thStyle, width: 160 }} scope="col">Timestamp</th>
            </tr>
          </thead>
          <tbody>
            {downloads.map((dl, i) => (
              <tr
                key={`${dl.contentId}-${dl.timestamp ?? i}-${i}`}
                style={{
                  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                  backgroundColor:
                    i % 2 === 0
                      ? tokens.colorNeutralBackground1
                      : tokens.colorNeutralBackground2,
                }}
              >
                <td style={{ ...tdStyle, textAlign: "center" }}>
                  <Badge
                    size="tiny"
                    appearance="filled"
                    color={dl.success ? "success" : "danger"}
                  >
                    {dl.success ? "OK" : "FAIL"}
                  </Badge>
                </td>
                <td style={tdStyle}>
                  <Body1Strong
                    style={{
                      display: "block",
                      whiteSpace: "normal",
                      wordBreak: "break-word",
                      fontSize: `${metrics.fontSize}px`,
                      lineHeight: `${metrics.rowLineHeight}px`,
                    }}
                    title={dl.contentId}
                  >
                    {dl.name}
                  </Body1Strong>
                </td>
                <td style={{ ...monoStyle, textAlign: "right" }}>
                  {formatBytes(dl.sizeBytes)}
                </td>
                <td style={{ ...monoStyle, textAlign: "right" }}>
                  {dl.speedBps > 0 ? `${formatBytes(dl.speedBps)}/s` : "—"}
                </td>
                <td style={tdStyle}>
                  {dl.doPercentage > 0 ? (
                    <div className={styles.doBar}>
                      <div
                        className={styles.doTrack}
                        role="meter"
                        aria-valuenow={dl.doPercentage}
                        aria-valuemin={0}
                        aria-valuemax={100}
                        aria-label={`Delivery Optimization ${dl.doPercentage.toFixed(1)}%`}
                      >
                        <div
                          style={{
                            width: `${Math.min(dl.doPercentage, 100)}%`,
                            height: "100%",
                            backgroundColor:
                              dl.doPercentage > 50
                                ? tokens.colorPaletteGreenBackground3
                                : tokens.colorBrandBackground,
                            borderRadius: "3px",
                          }}
                        />
                      </div>
                      <span
                        style={{
                          fontSize: `${Math.max(10, metrics.fontSize - 2)}px`,
                          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                          color: tokens.colorNeutralForeground3,
                          width: "40px",
                          textAlign: "right",
                        }}
                      >
                        {dl.doPercentage.toFixed(1)}%
                      </span>
                    </div>
                  ) : (
                    <span style={{ color: tokens.colorNeutralForeground4 }}>
                      —
                    </span>
                  )}
                </td>
                <td style={{ ...monoStyle, textAlign: "right" }}>
                  {dl.durationSecs > 0
                    ? `${dl.durationSecs.toFixed(1)}s`
                    : "—"}
                </td>
                <td style={monoStyle}>
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

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i > 0 ? 1 : 0)} ${units[Math.min(i, units.length - 1)]}`;
}

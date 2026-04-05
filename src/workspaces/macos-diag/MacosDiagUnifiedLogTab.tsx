import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Body1,
  Button,
  makeStyles,
  shorthands,
  Spinner,
  tokens,
} from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useMacosDiagStore } from "../../stores/macos-diag-store";
import { useUiStore } from "../../stores/ui-store";
import { macosQueryUnifiedLog } from "../../lib/commands";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { simplifyMessage } from "../../lib/unified-log-utils";

const PRESETS = [
  { id: "mdm-client", label: "MDM Client (mdmclient)" },
  { id: "managed-client", label: "Managed Client Subsystem" },
  { id: "install-activity", label: "Install Activity" },
  { id: "intune-agent", label: "Intune Agent Processes" },
] as const;

const TIME_RANGES = [
  { label: "Last 15 minutes", minutes: 15 },
  { label: "Last 30 minutes", minutes: 30 },
  { label: "Last 1 hour", minutes: 60 },
  { label: "Last 6 hours", minutes: 360 },
  { label: "Last 24 hours", minutes: 1440 },
] as const;

const useStyles = makeStyles({
  controls: {
    display: "flex",
    gap: "10px",
    alignItems: "flex-end",
    marginBottom: "16px",
    flexWrap: "wrap" as const,
  },
  controlGroup: {
    display: "flex",
    flexDirection: "column",
    gap: "3px",
  },
  controlLabel: {
    fontSize: "10px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.4px",
  },
  select: {
    fontFamily: tokens.fontFamilyBase,
    fontSize: "12px",
    ...shorthands.padding("5px", "10px"),
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    backgroundColor: tokens.colorNeutralBackground1,
    color: tokens.colorNeutralForeground1,
    minWidth: "160px",
    outlineStyle: "none",
    ":focus": {
      borderTopColor: tokens.colorBrandStroke1,
      borderRightColor: tokens.colorBrandStroke1,
      borderBottomColor: tokens.colorBrandStroke1,
      borderLeftColor: tokens.colorBrandStroke1,
    },
  },
  input: {
    fontFamily: tokens.fontFamilyBase,
    fontSize: "12px",
    ...shorthands.padding("5px", "10px"),
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusSmall),
    backgroundColor: tokens.colorNeutralBackground1,
    color: tokens.colorNeutralForeground1,
    minWidth: "90px",
    outlineStyle: "none",
    ":focus": {
      borderTopColor: tokens.colorBrandStroke1,
      borderRightColor: tokens.colorBrandStroke1,
      borderBottomColor: tokens.colorBrandStroke1,
      borderLeftColor: tokens.colorBrandStroke1,
    },
  },
  cappedBar: {
    display: "flex",
    alignItems: "center",
    gap: "8px",
    ...shorthands.padding("8px", "12px"),
    backgroundColor: tokens.colorPaletteYellowBackground1,
    ...shorthands.border("1px", "solid", tokens.colorPaletteYellowBorder2),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
    fontSize: "11.5px",
    color: tokens.colorPaletteMarigoldForeground2,
    fontWeight: 500,
    marginBottom: "12px",
  },
  tableWrap: {
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusXLarge),
    overflow: "hidden",
    boxShadow: tokens.shadow2,
    display: "flex",
    flexDirection: "column",
  },
  tableHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    ...shorthands.padding("10px", "14px"),
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground3,
    flexShrink: 0,
  },
  tableTitle: {
    fontSize: "12px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground1,
  },
  headerRow: {
    display: "flex",
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground3,
    flexShrink: 0,
  },
  headerCell: {
    ...shorthands.padding("8px", "14px"),
    fontSize: "10.5px",
    fontWeight: 600,
    color: tokens.colorNeutralForeground3,
    textTransform: "uppercase" as const,
    letterSpacing: "0.4px",
    flexShrink: 0,
    position: "relative" as const,
    userSelect: "none" as const,
  },
  resizeHandle: {
    position: "absolute" as const,
    right: 0,
    top: 0,
    bottom: 0,
    width: "5px",
    cursor: "col-resize",
    backgroundColor: "transparent",
    ":hover": {
      backgroundColor: tokens.colorBrandStroke1,
    },
  },
  resizeHandleActive: {
    position: "absolute" as const,
    right: 0,
    top: 0,
    bottom: 0,
    width: "5px",
    cursor: "col-resize",
    backgroundColor: tokens.colorBrandStroke1,
  },
  scrollContainer: {
    flex: 1,
    overflow: "auto",
    maxHeight: "calc(100vh - 380px)",
    minHeight: "200px",
  },
  row: {
    display: "flex",
    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
    alignItems: "center",
    ":hover": {
      backgroundColor: tokens.colorNeutralBackground3,
    },
  },
  cell: {
    ...shorthands.padding("6px", "14px"),
    fontSize: "12px",
    color: tokens.colorNeutralForeground1,
    flexShrink: 0,
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap" as const,
  },
  cellTimestamp: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11px",
  },
  cellProcess: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11px",
  },
  cellLevel: {
  },
  cellMessage: {
    flex: 1,
    minWidth: 0,
    fontSize: "12px",
  },
  levelDefault: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorNeutralBackground3,
    color: tokens.colorNeutralForeground3,
  },
  levelInfo: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
  },
  levelWarning: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteYellowBackground1,
    color: tokens.colorPaletteMarigoldForeground2,
  },
  levelError: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteRedBackground1,
    color: tokens.colorPaletteRedForeground1,
  },
  levelFault: {
    fontSize: "10px",
    fontWeight: 600,
    ...shorthands.padding("2px", "7px"),
    ...shorthands.borderRadius("100px"),
    textTransform: "uppercase" as const,
    letterSpacing: "0.3px",
    backgroundColor: tokens.colorPaletteRedBackground1,
    color: tokens.colorPaletteRedForeground1,
  },
  centered: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    ...shorthands.padding("40px"),
    gap: "8px",
  },
  loadingBar: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    ...shorthands.padding("8px", "12px"),
    marginBottom: "12px",
    backgroundColor: tokens.colorNeutralBackground1,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
    ...shorthands.borderRadius(tokens.borderRadiusMedium),
  },
  loadingBarTrack: {
    flex: 1,
    height: "4px",
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.borderRadius("2px"),
    overflow: "hidden",
  },
  loadingBarFill: {
    height: "100%",
    width: "30%",
    backgroundColor: tokens.colorBrandBackground,
    ...shorthands.borderRadius("2px"),
    animationName: {
      "0%": { transform: "translateX(-100%)" },
      "100%": { transform: "translateX(400%)" },
    },
    animationDuration: "1.5s",
    animationIterationCount: "infinite",
    animationTimingFunction: "ease-in-out",
  },
  emptyState: {
    ...shorthands.padding("40px"),
    textAlign: "center" as const,
    color: tokens.colorNeutralForeground3,
  },
});

function getLevelClass(
  level: string,
  styles: ReturnType<typeof useStyles>
): string {
  const lower = level.toLowerCase();
  if (lower === "info") return styles.levelInfo;
  if (lower === "warning" || lower === "warn") return styles.levelWarning;
  if (lower === "error") return styles.levelError;
  if (lower === "fault") return styles.levelFault;
  return styles.levelDefault;
}

export function MacosDiagUnifiedLogTab() {
  const styles = useStyles();
  const unifiedLogResult = useMacosDiagStore((s) => s.unifiedLogResult);
  const loading = useMacosDiagStore((s) => s.unifiedLogLoading);
  const presetId = useMacosDiagStore((s) => s.unifiedLogPresetId);
  const setUnifiedLogResult = useMacosDiagStore((s) => s.setUnifiedLogResult);
  const setLoading = useMacosDiagStore((s) => s.setUnifiedLogLoading);
  const setPresetId = useMacosDiagStore((s) => s.setUnifiedLogPresetId);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  const [timeRangeMinutes, setTimeRangeMinutes] = useState(60);
  const [maxResults, setMaxResults] = useState(5000);
  const [hideNoise, setHideNoise] = useState(true);

  // Column resize state
  const [colWidths, setColWidths] = useState({ timestamp: 170, process: 140, level: 80 });
  const resizeRef = useRef<{ col: keyof typeof colWidths; startX: number; startWidth: number } | null>(null);

  const onResizeStart = useCallback(
    (col: keyof typeof colWidths, e: React.MouseEvent) => {
      e.preventDefault();
      resizeRef.current = { col, startX: e.clientX, startWidth: colWidths[col] };
    },
    [colWidths]
  );

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      const { col, startX, startWidth } = resizeRef.current;
      const delta = e.clientX - startX;
      const newWidth = Math.max(50, startWidth + delta);
      setColWidths((prev) => ({ ...prev, [col]: newWidth }));
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

  const scrollRef = useRef<HTMLDivElement>(null);

  const rawEntries = unifiedLogResult?.entries ?? [];
  const entries = useMemo(() => {
    if (!hideNoise) return rawEntries;
    return rawEntries.filter((e) => {
      const s = simplifyMessage(e.message, e.process);
      return !s || s.category !== "noise";
    });
  }, [rawEntries, hideNoise]);

  const virtualizer = useVirtualizer({
    count: entries.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => metrics.rowHeight,
    overscan: 20,
  });

  const runQuery = useCallback(async () => {
    setLoading(true);
    try {
      const result = await macosQueryUnifiedLog(
        presetId,
        timeRangeMinutes,
        maxResults
      );
      setUnifiedLogResult(result);
    } catch (err) {
      console.error("[macos-diag] unified log query failed", err);
      setLoading(false);
    }
  }, [presetId, timeRangeMinutes, maxResults, setLoading, setUnifiedLogResult]);

  return (
    <>
      {/* Control Bar */}
      <div className={styles.controls}>
        <div className={styles.controlGroup}>
          <span className={styles.controlLabel}>Preset</span>
          <select
            className={styles.select}
            value={presetId}
            onChange={(e) => setPresetId(e.target.value)}
          >
            {PRESETS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.controlGroup}>
          <span className={styles.controlLabel}>Time Range</span>
          <select
            className={styles.select}
            value={timeRangeMinutes}
            onChange={(e) => setTimeRangeMinutes(Number(e.target.value))}
          >
            {TIME_RANGES.map((t) => (
              <option key={t.minutes} value={t.minutes}>
                {t.label}
              </option>
            ))}
          </select>
        </div>

        <div className={styles.controlGroup}>
          <span className={styles.controlLabel}>Max Results</span>
          <input
            type="number"
            className={styles.input}
            value={maxResults}
            min={100}
            max={50000}
            step={500}
            onChange={(e) => setMaxResults(Number(e.target.value))}
          />
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: "5px", alignSelf: "flex-end", fontSize: "11px", color: tokens.colorNeutralForeground3, cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={hideNoise}
            onChange={(e) => setHideNoise(e.target.checked)}
          />
          Hide NSURLSession noise
        </label>

        <Button
          appearance="primary"
          size="small"
          onClick={runQuery}
          disabled={loading}
          icon={loading ? <Spinner size="tiny" /> : undefined}
          style={{ alignSelf: "flex-end" }}
        >
          {loading ? "Querying..." : "Run Query"}
        </Button>
      </div>

      {/* Loading — show centered spinner only when no prior results exist */}
      {loading && !unifiedLogResult && (
        <div className={styles.centered}>
          <Spinner size="medium" label="Querying unified log..." />
        </div>
      )}

      {/* Loading overlay bar when re-querying with existing results */}
      {loading && unifiedLogResult && (
        <div className={styles.loadingBar}>
          <div className={styles.loadingBarTrack}>
            <div className={styles.loadingBarFill} />
          </div>
          <span style={{ fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
            Querying unified log...
          </span>
        </div>
      )}

      {/* Capped Warning */}
      {!loading && unifiedLogResult?.capped && (
        <div className={styles.cappedBar}>
          Results capped at {unifiedLogResult.resultCap.toLocaleString()} entries
          ({unifiedLogResult.totalMatched.toLocaleString()} total matched).
          Narrow time range or use a more specific predicate.
        </div>
      )}

      {/* Results Table */}
      {entries.length > 0 && (
        <div className={styles.tableWrap}>
          <div className={styles.tableHeader}>
            <div className={styles.tableTitle}>
              Unified Log ({entries.length.toLocaleString()} entries{hideNoise && rawEntries.length !== entries.length ? `, ${(rawEntries.length - entries.length).toLocaleString()} hidden` : ""})
            </div>
          </div>

          {/* Header row */}
          <div className={styles.headerRow}>
            <div
              className={styles.headerCell}
              style={{ width: `${colWidths.timestamp}px` }}
            >
              Timestamp
              <div
                className={resizeRef.current?.col === "timestamp" ? styles.resizeHandleActive : styles.resizeHandle}
                onMouseDown={(e) => onResizeStart("timestamp", e)}
              />
            </div>
            <div
              className={styles.headerCell}
              style={{ width: `${colWidths.process}px` }}
            >
              Process
              <div
                className={resizeRef.current?.col === "process" ? styles.resizeHandleActive : styles.resizeHandle}
                onMouseDown={(e) => onResizeStart("process", e)}
              />
            </div>
            <div
              className={styles.headerCell}
              style={{ width: `${colWidths.level}px` }}
            >
              Level
              <div
                className={resizeRef.current?.col === "level" ? styles.resizeHandleActive : styles.resizeHandle}
                onMouseDown={(e) => onResizeStart("level", e)}
              />
            </div>
            <div
              className={styles.headerCell}
              style={{ flex: 1, minWidth: 0 }}
            >
              Message
            </div>
          </div>

          {/* Virtualized rows */}
          <div ref={scrollRef} className={styles.scrollContainer}>
            <div
              style={{
                height: `${virtualizer.getTotalSize()}px`,
                width: "100%",
                position: "relative",
              }}
            >
              {virtualizer.getVirtualItems().map((virtualRow) => {
                const entry = entries[virtualRow.index];
                return (
                  <div
                    key={virtualRow.index}
                    className={styles.row}
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: `${virtualRow.size}px`,
                      transform: `translateY(${virtualRow.start}px)`,
                    }}
                  >
                    <div
                      className={`${styles.cell} ${styles.cellTimestamp}`}
                      style={{ width: `${colWidths.timestamp}px`, fontSize: metrics.fontSize - 2 }}
                    >
                      {entry.timestamp}
                    </div>
                    <div
                      className={`${styles.cell} ${styles.cellProcess}`}
                      style={{ width: `${colWidths.process}px`, fontSize: metrics.fontSize - 2 }}
                    >
                      {entry.process}
                    </div>
                    <div
                      className={`${styles.cell} ${styles.cellLevel}`}
                      style={{ width: `${colWidths.level}px` }}
                    >
                      <span className={getLevelClass(entry.level, styles)}>
                        {entry.level}
                      </span>
                    </div>
                    {(() => {
                      const simplified = simplifyMessage(entry.message, entry.process);
                      return (
                        <div
                          className={`${styles.cell} ${styles.cellMessage}`}
                          style={{ fontSize: metrics.fontSize }}
                          title={entry.message}
                        >
                          {simplified ? (
                            <>
                              <span style={{ fontWeight: 500 }}>{simplified.summary}</span>
                              {simplified.category === "http" && (
                                <span style={{ color: tokens.colorNeutralForeground3, marginLeft: "6px", fontSize: metrics.fontSize - 2 }}>
                                  {entry.message.length > 80 ? entry.message.slice(0, 80) + "…" : ""}
                                </span>
                              )}
                            </>
                          ) : (
                            entry.message
                          )}
                        </div>
                      );
                    })()}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && !unifiedLogResult && (
        <div className={styles.emptyState}>
          <Body1>
            Select a preset and time range, then click Run Query to search the
            macOS unified log.
          </Body1>
        </div>
      )}

      {/* No Results */}
      {!loading && unifiedLogResult && entries.length === 0 && (
        <div className={styles.emptyState}>
          <Body1>
            No log entries matched the query. Try a wider time range or different
            preset.
          </Body1>
        </div>
      )}
    </>
  );
}

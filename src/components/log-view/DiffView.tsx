import { useMemo, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useLogStore } from "../../stores/log-store";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { diffFileBaseName } from "../../lib/diff-entries";
import { useUiStore } from "../../stores/ui-store";
import { DiffHeader } from "./DiffHeader";
import type { LogEntry } from "../../types/log";
import type { EntryClassification } from "../../lib/diff-entries";

const CLASS_COLORS: Record<EntryClassification, { bg: string; border: string }> = {
  common: { bg: "transparent", border: "transparent" },
  "only-a": { bg: tokens.colorPaletteGreenBackground1, border: tokens.colorPaletteGreenForeground1 },
  "only-b": { bg: tokens.colorPaletteRedBackground1, border: tokens.colorPaletteRedForeground1 },
};

export function DiffView() {
  const diffState = useLogStore((s) => s.diffState);
  const selectEntry = useLogStore((s) => s.selectEntry);
  const selectedId = useLogStore((s) => s.selectedId);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  if (!diffState) return null;

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", fontFamily: LOG_UI_FONT_FAMILY }}>
      <DiffHeader />
      {diffState.displayMode === "side-by-side" ? (
        <SideBySideView
          diffState={diffState}
          metrics={metrics}
          selectedId={selectedId}
          onSelect={selectEntry}
        />
      ) : (
        <UnifiedView
          diffState={diffState}
          metrics={metrics}
          selectedId={selectedId}
          onSelect={selectEntry}
        />
      )}
    </div>
  );
}

function SideBySideView({
  diffState,
  metrics,
  selectedId,
  onSelect,
}: {
  diffState: NonNullable<ReturnType<typeof useLogStore.getState>["diffState"]>;
  metrics: ReturnType<typeof getLogListMetrics>;
  selectedId: number | null;
  onSelect: (id: number | null) => void;
}) {
  const parentRefA = useRef<HTMLDivElement>(null);
  const parentRefB = useRef<HTMLDivElement>(null);
  const isSyncingRef = useRef(false);
  const rowHeight = metrics.rowHeight;

  const handleScrollA = () => {
    if (isSyncingRef.current || !parentRefA.current || !parentRefB.current) return;
    isSyncingRef.current = true;
    parentRefB.current.scrollTop = parentRefA.current.scrollTop;
    requestAnimationFrame(() => { isSyncingRef.current = false; });
  };

  const handleScrollB = () => {
    if (isSyncingRef.current || !parentRefA.current || !parentRefB.current) return;
    isSyncingRef.current = true;
    parentRefA.current.scrollTop = parentRefB.current.scrollTop;
    requestAnimationFrame(() => { isSyncingRef.current = false; });
  };

  const virtualizerA = useVirtualizer({
    count: diffState.entriesA.length,
    getScrollElement: () => parentRefA.current,
    estimateSize: () => rowHeight,
    overscan: 10,
  });

  const virtualizerB = useVirtualizer({
    count: diffState.entriesB.length,
    getScrollElement: () => parentRefB.current,
    estimateSize: () => rowHeight,
    overscan: 10,
  });

  return (
    <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column", borderRight: `1px solid ${tokens.colorNeutralStroke1}` }}>
        <div style={{ padding: "4px 8px", fontSize: "11px", fontWeight: 600, backgroundColor: tokens.colorNeutralBackground3, borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, color: tokens.colorPaletteGreenForeground1 }}>
          A: {diffFileBaseName(diffState.sourceA.filePath)} ({diffState.entriesA.length})
        </div>
        <div ref={parentRefA} onScroll={handleScrollA} style={{ flex: 1, overflowY: "auto" }}>
          <div style={{ height: `${virtualizerA.getTotalSize()}px`, position: "relative" }}>
            {virtualizerA.getVirtualItems().map((row) => {
              const entry = diffState.entriesA[row.index];
              const cls = diffState.entryClassification.get(entry.id) ?? "common";
              return (
                <div
                  key={row.key}
                  data-index={row.index}
                  ref={virtualizerA.measureElement}
                  style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${row.start}px)` }}
                >
                  <DiffRow entry={entry} classification={cls} isSelected={entry.id === selectedId} fontSize={metrics.fontSize} onSelect={onSelect} />
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <div style={{ padding: "4px 8px", fontSize: "11px", fontWeight: 600, backgroundColor: tokens.colorNeutralBackground3, borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, color: tokens.colorPaletteRedForeground1 }}>
          B: {diffFileBaseName(diffState.sourceB.filePath)} ({diffState.entriesB.length})
        </div>
        <div ref={parentRefB} onScroll={handleScrollB} style={{ flex: 1, overflowY: "auto" }}>
          <div style={{ height: `${virtualizerB.getTotalSize()}px`, position: "relative" }}>
            {virtualizerB.getVirtualItems().map((row) => {
              const entry = diffState.entriesB[row.index];
              const cls = diffState.entryClassification.get(entry.id) ?? "common";
              return (
                <div
                  key={row.key}
                  data-index={row.index}
                  ref={virtualizerB.measureElement}
                  style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${row.start}px)` }}
                >
                  <DiffRow entry={entry} classification={cls} isSelected={entry.id === selectedId} fontSize={metrics.fontSize} onSelect={onSelect} />
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

function UnifiedView({
  diffState,
  metrics,
  selectedId,
  onSelect,
}: {
  diffState: NonNullable<ReturnType<typeof useLogStore.getState>["diffState"]>;
  metrics: ReturnType<typeof getLogListMetrics>;
  selectedId: number | null;
  onSelect: (id: number | null) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const rowHeight = metrics.rowHeight;

  const unifiedEntries = useMemo(() => {
    const all = [
      ...diffState.entriesA.map((e) => ({ entry: e, source: "a" as const })),
      ...diffState.entriesB.map((e) => ({ entry: e, source: "b" as const })),
    ];
    all.sort((x, y) => {
      if (x.entry.timestamp != null && y.entry.timestamp != null) {
        if (x.entry.timestamp !== y.entry.timestamp) return x.entry.timestamp - y.entry.timestamp;
      }
      return x.entry.lineNumber - y.entry.lineNumber;
    });
    return all;
  }, [diffState.entriesA, diffState.entriesB]);

  const virtualizer = useVirtualizer({
    count: unifiedEntries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowHeight,
    overscan: 10,
  });

  return (
    <div ref={parentRef} style={{ flex: 1, overflowY: "auto" }}>
      <div style={{ height: `${virtualizer.getTotalSize()}px`, position: "relative" }}>
        {virtualizer.getVirtualItems().map((row) => {
          const { entry, source } = unifiedEntries[row.index];
          const cls = diffState.entryClassification.get(entry.id) ?? "common";
          return (
            <div
              key={row.key}
              data-index={row.index}
              ref={virtualizer.measureElement}
              style={{ position: "absolute", top: 0, left: 0, width: "100%", transform: `translateY(${row.start}px)` }}
            >
              <DiffRow
                entry={entry}
                classification={cls}
                isSelected={entry.id === selectedId}
                fontSize={metrics.fontSize}
                onSelect={onSelect}
                sourceBadge={source.toUpperCase()}
              />
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DiffRow({
  entry,
  classification,
  isSelected,
  fontSize,
  onSelect,
  sourceBadge,
}: {
  entry: LogEntry;
  classification: EntryClassification;
  isSelected: boolean;
  fontSize: number;
  onSelect: (id: number | null) => void;
  sourceBadge?: string;
}) {
  const colors = CLASS_COLORS[classification];
  const monoFont = Math.max(fontSize - 1, 10);

  return (
    <div
      onClick={() => onSelect(isSelected ? null : entry.id)}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "6px",
        padding: "2px 8px",
        fontSize: `${fontSize}px`,
        backgroundColor: isSelected ? tokens.colorBrandBackground : colors.bg,
        color: isSelected ? tokens.colorNeutralForegroundOnBrand : tokens.colorNeutralForeground1,
        borderLeft: `3px solid ${colors.border}`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        cursor: "pointer",
        height: "100%",
        boxSizing: "border-box",
      }}
    >
      {sourceBadge && (
        <span style={{
          fontSize: "9px",
          fontWeight: 700,
          padding: "1px 4px",
          borderRadius: "2px",
          backgroundColor: classification === "only-a" ? tokens.colorPaletteGreenBackground1 : classification === "only-b" ? tokens.colorPaletteRedBackground1 : tokens.colorNeutralBackground4,
          color: classification === "only-a" ? tokens.colorPaletteGreenForeground1 : classification === "only-b" ? tokens.colorPaletteRedForeground1 : tokens.colorNeutralForeground3,
          flexShrink: 0,
          width: "16px",
          textAlign: "center",
        }}>
          {sourceBadge}
        </span>
      )}
      <span style={{ fontSize: `${monoFont}px`, color: isSelected ? "inherit" : tokens.colorNeutralForeground3, fontFamily: LOG_MONOSPACE_FONT_FAMILY, flexShrink: 0, width: "145px" }}>
        {formatDisplayDateTime(entry.timestampDisplay ?? entry.timestamp) ?? "\u2014"}
      </span>
      <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: `${monoFont}px` }}>
        {entry.message}
      </span>
    </div>
  );
}

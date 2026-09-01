import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { tokens } from "@fluentui/react-components";
import {
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useMarkerStore } from "../../stores/marker-store";
import {
  evtxMarkerKey,
  getEvtxMarker,
  isEvtxMarkerAddressable,
  loadEvtxMarkers,
  toggleEvtxBookmark,
  toggleEvtxTag,
} from "./evtx-marker-adapter";
import { useEvtxStore, type EvtxSortField } from "./evtx-store";
import {
  selectVisibleRecords,
  buildGroupedRows,
  matchesQuickFilter,
  type EvtxRow,
} from "./evtx-filter";
import type { EvtxRecord, EvtxLevel } from "./types";
import { visibleColumns } from "./evtx-columns";
import { EvtxTimelineRow } from "./EvtxTimelineRow";

const LEVEL_ORDER: Record<EvtxLevel, number> = {
  Critical: 0,
  Error: 1,
  Warning: 2,
  Information: 3,
  Verbose: 4,
};

function compareRecords(
  a: EvtxRecord,
  b: EvtxRecord,
  field: EvtxSortField,
  direction: "asc" | "desc"
): number {
  let cmp = 0;
  switch (field) {
    case "time":
      cmp = a.timestampEpoch - b.timestampEpoch;
      break;
    case "eventId":
      cmp = a.eventId - b.eventId;
      break;
    case "level":
      cmp = LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level];
      break;
    case "provider":
      cmp = a.provider.localeCompare(b.provider);
      break;
    case "channel":
      cmp = a.channel.localeCompare(b.channel);
      break;
  }
  return direction === "asc" ? cmp : -cmp;
}
function evtxRowKeys(rows: readonly EvtxRow[]): string[] {
  const occurrencesByFingerprint = new Map<string, number>();
  return rows.map((row) => {
    if (row.kind === "group") return `group:${row.key}`;
    const key = `event:${evtxMarkerKey(row.record)}`;
    if (isEvtxMarkerAddressable(row.record)) return key;

    const occurrence = occurrencesByFingerprint.get(key) ?? 0;
    occurrencesByFingerprint.set(key, occurrence + 1);
    return `${key}:occurrence:${occurrence}`;
  });
}
export function EvtxTimeline({ nowEpoch }: { nowEpoch?: number } = {}) {
  const [liveNowEpoch, setLiveNowEpoch] = useState(() => Date.now());
  useEffect(() => {
    if (nowEpoch !== undefined) return;
    setLiveNowEpoch(Date.now());
    const timer = window.setInterval(() => setLiveNowEpoch(Date.now()), 30_000);
    return () => window.clearInterval(timer);
  }, [nowEpoch]);
  const records = useEvtxStore((s) => s.records);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const sortField = useEvtxStore((s) => s.sortField);
  const sortDirection = useEvtxStore((s) => s.sortDirection);
  const groupBy = useEvtxStore((s) => s.groupBy);
  const collapsedGroups = useEvtxStore((s) => s.collapsedGroups);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const toggleGroup = useEvtxStore((s) => s.toggleGroup);
  const columnConfig = useEvtxStore((s) => s.columnConfig);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const setSelectedRecordId = useEvtxStore((s) => s.setSelectedRecordId);
  const markersByFile = useMarkerStore((s) => s.markersByFile);
  const logListFontSize = useUiStore((s) => s.logListFontSize);

  const currentNowEpoch = nowEpoch ?? liveNowEpoch;
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );
  const recordRowExtra = columnConfig.order.includes("level") ? 6 : 2;
  const rowEstimate = metrics.rowHeight + recordRowExtra;


  const filteredRecords = useMemo(
    () =>
      selectVisibleRecords({
        records,
        selectedChannels,
        filterLevels,
        filterEventIds,
        filterSearch,
        quickFilter,
        visibleColumns: columnConfig.order,
        timeZoneMode,
        timeWindow,
        nowEpoch: currentNowEpoch,
      }),
    [
      records,
      selectedChannels,
      filterLevels,
      filterEventIds,
      filterSearch,
      quickFilter,
      columnConfig.order,
      timeZoneMode,
      timeWindow,
      currentNowEpoch,
    ]
  );

  const sortedRecords = useMemo(() => {
    return [...filteredRecords].sort((a, b) =>
      compareRecords(a, b, sortField, sortDirection)
    );
  }, [filteredRecords, sortField, sortDirection]);

  const parentRef = useRef<HTMLDivElement>(null);
  const rowElementsRef = useRef(new Set<HTMLElement>());
  const previousUiRowKeysRef = useRef<readonly string[]>([]);

  // Grouping produces header rows interleaved with records, so the virtualizer indexes rows rather
  // than records. With no grouping the row list is the record list and nothing changes.
  // Computed once rather than per row: columnConfig is stable between renders, and the row
  // renderer was rebuilding the spec array and re-synthesizing every map column spec for each of
  // potentially a hundred thousand rows.
  const columns = useMemo(() => visibleColumns(columnConfig), [columnConfig]);

  const rows: EvtxRow[] = useMemo(
    () => buildGroupedRows(sortedRecords, groupBy, collapsedGroups, timeZoneMode),
    [sortedRecords, groupBy, collapsedGroups, timeZoneMode]
  );
  const uiRowKeys = useMemo(() => evtxRowKeys(rows), [rows]);
  const uiRowIndexByKey = useMemo(
    () => new Map(uiRowKeys.map((key, index) => [key, index])),
    [uiRowKeys]
  );
  const [activeRowKey, setActiveRowKey] = useState<string | null>(null);
  const activeRowIndex = useMemo(() => {
    if (rows.length === 0) return -1;
    if (activeRowKey === null) return 0;
    const index = uiRowIndexByKey.get(activeRowKey);
    return index === undefined ? 0 : index;
  }, [activeRowKey, rows.length, uiRowIndexByKey]);
  const setActiveRowIndex = useCallback(
    (index: number) => {
      const key = uiRowKeys[index];
      if (key) setActiveRowKey(key);
    },
    [uiRowKeys]
  );
  useEffect(() => {
    if (rows.length === 0) {
      if (activeRowKey !== null) setActiveRowKey(null);
      return;
    }
    if (activeRowKey === null || !uiRowIndexByKey.has(activeRowKey)) {
      setActiveRowKey(uiRowKeys[0]);
    }
  }, [activeRowKey, rows.length, uiRowIndexByKey, uiRowKeys]);
  const rowIndexByRecordId = useMemo(() => {
    const indexes = new Map<number, number>();
    rows.forEach((row, index) => {
      if (row.kind === "record") indexes.set(row.record.id, index);
    });
    return indexes;
  }, [rows]);
  useEffect(() => {
    if (selectedRecordId === null) return;
    const selectedRowIndex = rowIndexByRecordId.get(selectedRecordId);
    if (selectedRowIndex !== undefined) setActiveRowIndex(selectedRowIndex);
  }, [rowIndexByRecordId, selectedRecordId, setActiveRowIndex]);
  const sourceLabels = useMemo(
    () => [...new Set(records.map((record) => record.sourceLabel).filter(Boolean))],
    [records]
  );

  useEffect(() => {
    loadEvtxMarkers(sourceLabels);
  }, [sourceLabels]);

  const handleTag = useCallback((record: EvtxRecord) => {
    toggleEvtxTag(record);
  }, []);
  const handleBookmark = useCallback((record: EvtxRecord) => {
    toggleEvtxBookmark(record);
  }, []);


  // Checked against the rendered rows, not the filtered records. Filtering already dropped a
  // hidden selection, but collapsing a group leaves the record in sortedRecords while taking its
  // row out of the list, so keyboard navigation could not find the current position and the
  // detail pane showed a record that was not on screen. Rows covers both.
  useEffect(() => {
    if (selectedRecordId === null) return;
    const stillVisible = rows.some(
      (row) => row.kind === "record" && row.record.id === selectedRecordId
    );
    if (!stillVisible) setSelectedRecordId(null);
  }, [rows, selectedRecordId, setSelectedRecordId]);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) =>
      rows[index]?.kind === "group" ? metrics.rowHeight : rowEstimate,
    getItemKey: (index) => uiRowKeys[index] ?? "row:empty",
    overscan: 10,
  });
  const measureRow = useCallback(
    (node: HTMLElement | null) => {
      if (node) {
        rowElementsRef.current.add(node);
      } else {
        for (const element of rowElementsRef.current) {
          if (!element.isConnected) rowElementsRef.current.delete(element);
        }
      }
      virtualizer.measureElement(node);
    },
    [virtualizer.measureElement]
  );


  // Persisted font-size and row-shape changes alter rendered row heights. Estimates remain correct
  // for offscreen rows, while connected rows must use their actual border-box height because
  // TanStack's no-entry measurement path may return the existing cache.
  const measureConnectedRow = useCallback(
    (element: HTMLElement) => {
      const height = element.getBoundingClientRect().height;
      if (height > 0) {
        virtualizer.resizeItem(Number(element.dataset.index), height);
      } else {
        virtualizer.measureElement(element);
      }
    },
    [virtualizer.measureElement, virtualizer.resizeItem]
  );

  useEffect(() => {
    virtualizer.measure();
    for (const element of rowElementsRef.current) {
      if (element.isConnected) measureConnectedRow(element);
    }
  }, [metrics.rowHeight, rowEstimate, measureConnectedRow, virtualizer.measure]);

  // Row filtering and the rolling time-window clock may create a new rows array without changing
  // any rendered identity or dimension. Preserve TanStack's keyed cache in that case. When rows
  // really move, only the connected DOM rows whose index now owns a different key need a fresh
  // measurement; offscreen sizes remain keyed to the row identity.
  useEffect(() => {
    const previousKeys = previousUiRowKeysRef.current;
    for (const element of rowElementsRef.current) {
      if (!element.isConnected) continue;
      const index = Number(element.dataset.index);
      if (previousKeys[index] !== uiRowKeys[index]) measureConnectedRow(element);
    }
    previousUiRowKeysRef.current = uiRowKeys;
  }, [measureConnectedRow, uiRowKeys]);

  const virtualRows = virtualizer.getVirtualItems();

  const fontSize = metrics.fontSize;
  const smallFontSize = Math.max(9, fontSize - 3);
  const monoFontSize = Math.max(10, fontSize - 1);
  const lineHeight = `${metrics.rowLineHeight}px`;

  const focusRow = useCallback(
    (index: number) => {
      setActiveRowIndex(index);
      virtualizer.scrollToIndex(index, { align: "auto" });
      const element = [...rowElementsRef.current].find(
        (candidate) => Number(candidate.dataset.index) === index
      );
      if (element) {
        element.focus();
        return;
      }
      const focus = () => {
        [...rowElementsRef.current]
          .find((candidate) => Number(candidate.dataset.index) === index)
          ?.focus();
      };
      if (typeof requestAnimationFrame === "function") requestAnimationFrame(focus);
    },
    [setActiveRowIndex, virtualizer.scrollToIndex]
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const focusedElement =
        e.target instanceof HTMLElement
          ? e.target.closest<HTMLElement>("[data-index]")
          : null;
      const focusedIndex = focusedElement ? Number(focusedElement.dataset.index) : NaN;
      const targetIndex =
        groupBy.length > 0 &&
        Number.isInteger(focusedIndex) &&
        focusedIndex >= 0 &&
        focusedIndex < rows.length
          ? focusedIndex
          : activeRowIndex;
      const currentRow = rows[targetIndex];
      if (
        groupBy.length > 0 &&
        currentRow?.kind === "group" &&
        (e.key === "ArrowLeft" || e.key === "ArrowRight")
      ) {
        e.preventDefault();
        e.stopPropagation();
        if (e.key === "ArrowRight" && currentRow.collapsed) toggleGroup(currentRow.key);
        if (e.key === "ArrowLeft" && !currentRow.collapsed) toggleGroup(currentRow.key);
        return;
      }
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown" && e.key !== "Home" && e.key !== "End") return;
      e.preventDefault();
      e.stopPropagation();
      if (rows.length === 0) return;

      const currentIndex = Math.min(targetIndex, rows.length - 1);
      let nextIndex = currentIndex;
      if (e.key === "ArrowDown") nextIndex = Math.min(rows.length - 1, currentIndex + 1);
      if (e.key === "ArrowUp") nextIndex = Math.max(0, currentIndex - 1);
      if (e.key === "Home") nextIndex = 0;
      if (e.key === "End") nextIndex = rows.length - 1;

      setActiveRowIndex(nextIndex);
      const row = rows[nextIndex];
      if (row?.kind === "record") setSelectedRecordId(row.record.id);
      focusRow(nextIndex);
    },
    [activeRowIndex, focusRow, groupBy.length, rows, setSelectedRecordId, toggleGroup]
  );

  if (records.length === 0) {
    return (
      <div
        style={{
          padding: "20px",
          color: tokens.colorNeutralForeground3,
          textAlign: "center",
          fontSize: `${fontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
        }}
      >
        No event log records loaded.
      </div>
    );
  }

  if (sortedRecords.length === 0) {
    return (
      <div
        style={{
          padding: "20px",
          fontSize: `${fontSize}px`,
          fontFamily: LOG_UI_FONT_FAMILY,
        }}
      >
        No records match the current filters.
      </div>
    );
  }

  return (
    <div
      ref={parentRef}
      // Rows contain real marker buttons. A grid permits those controls inside a gridcell while a
      // treegrid also carries the grouped rows' hierarchy and disclosure state.
      role={groupBy.length > 0 ? "treegrid" : "grid"}
      tabIndex={-1}
      onKeyDown={handleKeyDown}
      aria-label={`Event log timeline - ${sortedRecords.length} records`}
      aria-rowcount={rows.length}
      aria-colcount={columns.length + 1}
      style={{
        overflowY: "auto",
        height: "100%",
        padding: "0",
        fontFamily: LOG_UI_FONT_FAMILY,
        outline: "none",
      }}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: 0,
            left: 0,
            width: "100%",
            transform: `translateY(${virtualRows[0]?.start ?? 0}px)`,
          }}
        >
          {virtualRows.map((virtualRow) => {
            const row = rows[virtualRow.index];
            if (!row) return null;

            if (row.kind === "group") {
              return (
                <div
                  key={uiRowKeys[virtualRow.index] ?? virtualRow.key}
                  ref={measureRow}
                  data-index={virtualRow.index}
                  role="row"
                  aria-rowindex={virtualRow.index + 1}
                  aria-level={row.depth + 1}
                  // Focusable and activated by keyboard. It was reachable only by pointer, so a
                  // keyboard user could not expand or collapse a group at all.
                  tabIndex={activeRowIndex === virtualRow.index ? 0 : -1}
                  aria-expanded={!row.collapsed}
                  onFocus={() => setActiveRowIndex(virtualRow.index)}
                  onClick={() => {
                    setActiveRowIndex(virtualRow.index);
                    toggleGroup(row.key);
                  }}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" || event.key === " ") {
                      event.preventDefault();
                      toggleGroup(row.key);
                    }
                  }}
                  style={{
                    // Normal flow, matching the record rows. The wrapper above is already
                    // translated to the first visible row's offset and its children stack inside
                    // it, so positioning a header absolutely applied that offset a second time and
                    // took it out of flow, letting the rows beneath slide up into its place.
                    width: "100%",
                    display: "flex",
                    alignItems: "center",
                    paddingLeft: `${8 + row.depth * 16}px`,
                    height: `${metrics.rowHeight}px`,
                    boxSizing: "border-box",
                    fontSize: `${smallFontSize}px`,
                    fontWeight: 600,
                    cursor: "pointer",
                    backgroundColor: tokens.colorNeutralBackground3,
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    color: tokens.colorNeutralForeground2,
                  }}
                  title={`${row.count} events`}
                >
                  <div
                    role="gridcell"
                    aria-colindex={1}
                    aria-colspan={columns.length + 1}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      width: "100%",
                      minWidth: 0,
                    }}
                  >
                    <span style={{ width: "10px" }}>{row.collapsed ? "\u25B8" : "\u25BE"}</span>
                    <span>{row.label}</span>
                    <span style={{ color: tokens.colorNeutralForeground4 }}>({row.count})</span>
                  </div>
                </div>
              );
            }

            const record = row.record;
            const marker = getEvtxMarker(record, markersByFile);
            const quickFilterMatch =
              Boolean(quickFilter.query.trim()) &&
              matchesQuickFilter(record, quickFilter, columnConfig.order, timeZoneMode);
            return (
              <EvtxTimelineRow
                key={uiRowKeys[virtualRow.index] ?? virtualRow.key}
                ref={measureRow}
                record={record}
                dataIndex={virtualRow.index}
                isSelected={selectedRecordId === record.id}
                fontSize={fontSize}
                smallFontSize={smallFontSize}
                monoFontSize={monoFontSize}
                lineHeight={lineHeight}
                columnConfig={columnConfig}
                columns={columns}
                timeZoneMode={timeZoneMode}
                onSelect={setSelectedRecordId}
                marker={marker}
                quickFilter={quickFilter}
                quickFilterMatch={quickFilterMatch}
                grouped={groupBy.length > 0}
                depth={row.depth}
                tabIndex={activeRowIndex === virtualRow.index ? 0 : -1}
                onFocus={() => setActiveRowIndex(virtualRow.index)}
                onTag={handleTag}
                onBookmark={handleBookmark}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

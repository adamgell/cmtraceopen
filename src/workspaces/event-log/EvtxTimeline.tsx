import { useCallback, useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { tokens } from "@fluentui/react-components";
import {
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useEvtxStore, type EvtxSortField } from "./evtx-store";
import {
  parseEventIdFilter,
  buildGroupedRows,
  type EvtxRow,
} from "./evtx-filter";
import type { EvtxRecord, EvtxLevel } from "./types";
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

export function EvtxTimeline() {
  const records = useEvtxStore((s) => s.records);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const sortField = useEvtxStore((s) => s.sortField);
  const sortDirection = useEvtxStore((s) => s.sortDirection);
  const groupBy = useEvtxStore((s) => s.groupBy);
  const collapsedGroups = useEvtxStore((s) => s.collapsedGroups);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const toggleGroup = useEvtxStore((s) => s.toggleGroup);
  const columnConfig = useEvtxStore((s) => s.columnConfig);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const setSelectedRecordId = useEvtxStore((s) => s.setSelectedRecordId);

  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );

  const rowEstimate = metrics.rowHeight + 2;

  const eventIdSet = useMemo(
    () => parseEventIdFilter(filterEventIds),
    [filterEventIds]
  );

  const searchLower = useMemo(
    () => filterSearch.trim().toLowerCase(),
    [filterSearch]
  );

  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      if (!selectedChannels.has(r.channel)) return false;
      if (!filterLevels.has(r.level)) return false;
      if (eventIdSet && !eventIdSet.has(r.eventId)) return false;
      if (searchLower && !r.message.toLowerCase().includes(searchLower) && !r.provider.toLowerCase().includes(searchLower)) {
        return false;
      }
      return true;
    });
  }, [records, selectedChannels, filterLevels, eventIdSet, searchLower]);

  const sortedRecords = useMemo(() => {
    return [...filteredRecords].sort((a, b) =>
      compareRecords(a, b, sortField, sortDirection)
    );
  }, [filteredRecords, sortField, sortDirection]);

  useEffect(() => {
    if (selectedRecordId == null) return;
    const stillVisible = sortedRecords.some((r) => r.id === selectedRecordId);
    if (!stillVisible) {
      setSelectedRecordId(null);
    }
  }, [sortedRecords, setSelectedRecordId, selectedRecordId]);

  const parentRef = useRef<HTMLDivElement>(null);

  // Grouping produces header rows interleaved with records, so the virtualizer indexes rows rather
  // than records. With no grouping the row list is the record list and nothing changes.
  const rows: EvtxRow[] = useMemo(
    () => buildGroupedRows(sortedRecords, groupBy, collapsedGroups, timeZoneMode),
    [sortedRecords, groupBy, collapsedGroups, timeZoneMode]
  );

  // Keyboard navigation moves between records, skipping headers, because a header is not a
  // selectable event.
  const recordRowIndexes = useMemo(
    () =>
      rows.reduce<number[]>((indexes, row, index) => {
        if (row.kind === "record") indexes.push(index);
        return indexes;
      }, []),
    [rows]
  );

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowEstimate,
    getItemKey: (index) => {
      const row = rows[index];
      return row?.kind === "group" ? `group:${row.key}` : row?.record.id ?? index;
    },
    overscan: 10,
  });

  const virtualRows = virtualizer.getVirtualItems();

  const fontSize = metrics.fontSize;
  const smallFontSize = Math.max(9, fontSize - 3);
  const monoFontSize = Math.max(10, fontSize - 1);
  const lineHeight = `${metrics.rowLineHeight}px`;

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown" && e.key !== "Home" && e.key !== "End") return;
      e.preventDefault();
      e.stopPropagation();

      if (recordRowIndexes.length === 0) return;

      const currentPosition = selectedRecordId != null
        ? recordRowIndexes.findIndex((rowIndex) => {
            const row = rows[rowIndex];
            return row.kind === "record" && row.record.id === selectedRecordId;
          })
        : -1;

      let nextPosition: number;
      if (e.key === "ArrowDown") {
        nextPosition = currentPosition < recordRowIndexes.length - 1 ? currentPosition + 1 : currentPosition;
      } else if (e.key === "ArrowUp") {
        nextPosition = currentPosition > 0 ? currentPosition - 1 : 0;
      } else if (e.key === "Home") {
        nextPosition = 0;
      } else {
        nextPosition = recordRowIndexes.length - 1;
      }

      if (nextPosition < 0) nextPosition = 0;
      const rowIndex = recordRowIndexes[nextPosition];
      const row = rows[rowIndex];
      if (row?.kind === "record") {
        setSelectedRecordId(row.record.id);
        virtualizer.scrollToIndex(rowIndex, { align: "auto" });
        // Keep focus on the container so subsequent arrow keys work
        parentRef.current?.focus();
      }
    },
    [selectedRecordId, rows, recordRowIndexes, setSelectedRecordId, virtualizer]
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
          color: tokens.colorNeutralForeground3,
          textAlign: "center",
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
      role="listbox"
      tabIndex={0}
      onKeyDown={handleKeyDown}
      aria-label={`Event log timeline - ${sortedRecords.length} records`}
      style={{
        overflowY: "auto",
        height: "100%",
        padding: "0",
        backgroundColor: tokens.colorNeutralBackground1,
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
                  key={virtualRow.key}
                  ref={virtualizer.measureElement}
                  data-index={virtualRow.index}
                  role="button"
                  // Focusable and activated by keyboard. It was reachable only by pointer, so a
                  // keyboard user could not expand or collapse a group at all.
                  tabIndex={0}
                  aria-expanded={!row.collapsed}
                  onClick={() => toggleGroup(row.key)}
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
                    gap: "6px",
                    paddingLeft: `${8 + row.depth * 16}px`,
                    height: `${metrics.rowHeight}px`,
                    fontSize: `${smallFontSize}px`,
                    fontWeight: 600,
                    cursor: "pointer",
                    backgroundColor: tokens.colorNeutralBackground3,
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    color: tokens.colorNeutralForeground2,
                  }}
                  title={`${row.count} events`}
                >
                  <span style={{ width: "10px" }}>{row.collapsed ? "\u25B8" : "\u25BE"}</span>
                  <span>{row.label}</span>
                  <span style={{ color: tokens.colorNeutralForeground4 }}>({row.count})</span>
                </div>
              );
            }

            const record = row.record;
            return (
              <EvtxTimelineRow
                key={virtualRow.key}
                ref={virtualizer.measureElement}
                record={record}
                dataIndex={virtualRow.index}
                isSelected={selectedRecordId === record.id}
                fontSize={fontSize}
                smallFontSize={smallFontSize}
                monoFontSize={monoFontSize}
                lineHeight={lineHeight}
                columnConfig={columnConfig}
                timeZoneMode={timeZoneMode}
                onSelect={setSelectedRecordId}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

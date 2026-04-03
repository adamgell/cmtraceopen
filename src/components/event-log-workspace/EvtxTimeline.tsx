import { useCallback, useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { tokens } from "@fluentui/react-components";
import {
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useEvtxStore, type EvtxSortField } from "../../stores/evtx-store";
import type { EvtxRecord, EvtxLevel } from "../../types/event-log-workspace";
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

function parseEventIdFilter(raw: string): Set<number> | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const ids = new Set<number>();
  for (const part of trimmed.split(",")) {
    const n = parseInt(part.trim(), 10);
    if (!isNaN(n)) ids.add(n);
  }
  return ids.size > 0 ? ids : null;
}

export function EvtxTimeline() {
  const records = useEvtxStore((s) => s.records);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const sortField = useEvtxStore((s) => s.sortField);
  const sortDirection = useEvtxStore((s) => s.sortDirection);
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

  const virtualizer = useVirtualizer({
    count: sortedRecords.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => rowEstimate,
    getItemKey: (index) => sortedRecords[index]?.id ?? index,
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

      const currentIndex = selectedRecordId != null
        ? sortedRecords.findIndex((r) => r.id === selectedRecordId)
        : -1;

      let nextIndex: number;
      if (e.key === "ArrowDown") {
        nextIndex = currentIndex < sortedRecords.length - 1 ? currentIndex + 1 : currentIndex;
      } else if (e.key === "ArrowUp") {
        nextIndex = currentIndex > 0 ? currentIndex - 1 : 0;
      } else if (e.key === "Home") {
        nextIndex = 0;
      } else {
        nextIndex = sortedRecords.length - 1;
      }

      if (nextIndex >= 0 && nextIndex < sortedRecords.length) {
        setSelectedRecordId(sortedRecords[nextIndex].id);
        virtualizer.scrollToIndex(nextIndex, { align: "auto" });
        // Keep focus on the container so subsequent arrow keys work
        parentRef.current?.focus();
      }
    },
    [selectedRecordId, sortedRecords, setSelectedRecordId, virtualizer]
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
            const record = sortedRecords[virtualRow.index];
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
                onSelect={setSelectedRecordId}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}

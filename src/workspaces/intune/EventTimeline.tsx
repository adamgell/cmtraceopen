import { useEffect, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { tokens } from "@fluentui/react-components";
import {
  LOG_UI_FONT_FAMILY,
  getLogListMetrics,
} from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import type { IntuneEvent } from "./types";
import { compareEvents } from "../../lib/intune-sort";
import { useIntuneStore } from "./intune-store";
import { EventTimelineRow, getFileName } from "./EventTimelineRow";
import { EventActivityView } from "./EventActivityView";

interface EventTimelineProps {
  events: IntuneEvent[];
}

export function EventTimeline({ events }: EventTimelineProps) {
  const selectedEventId = useIntuneStore((s) => s.selectedEventId);
  const selectEvent = useIntuneStore((s) => s.selectEvent);
  const timelineScope = useIntuneStore((s) => s.timelineScope);
  const sourceFiles = useIntuneStore((s) => s.sourceFiles);
  const filterEventType = useIntuneStore((s) => s.filterEventType);
  const filterStatus = useIntuneStore((s) => s.filterStatus);
  const sortField = useIntuneStore((s) => s.sortField);
  const sortDirection = useIntuneStore((s) => s.sortDirection);
  const timelineViewMode = useIntuneStore((s) => s.timelineViewMode);
  const showSourceFileLabel = sourceFiles.length > 1 && timelineScope.filePath == null;

  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );

  const collapsedRowEstimate = metrics.rowHeight + 2;
  const expandedRowEstimate = Math.max(160, metrics.rowHeight * 5);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      if (timelineScope.filePath != null && e.sourceFile !== timelineScope.filePath) {
        return false;
      }
      if (filterEventType !== "All" && e.eventType !== filterEventType) {
        return false;
      }
      if (filterStatus !== "All" && e.status !== filterStatus) {
        return false;
      }
      return true;
    });
  }, [events, filterEventType, filterStatus, timelineScope.filePath]);

  const sortedEvents = useMemo(() => {
    return [...filteredEvents].sort((a, b) =>
      compareEvents(a, b, sortField, sortDirection)
    );
  }, [filteredEvents, sortField, sortDirection]);

  useEffect(() => {
    if (selectedEventId == null) {
      return;
    }

    const selectedStillVisible = sortedEvents.some((e) => e.id === selectedEventId);
    if (!selectedStillVisible) {
      selectEvent(null);
    }
  }, [sortedEvents, selectEvent, selectedEventId]);

  const parentRef = useRef<HTMLDivElement>(null);
  const selectedIndex = useMemo(
    () => sortedEvents.findIndex((event) => event.id === selectedEventId),
    [sortedEvents, selectedEventId]
  );

  const virtualizer = useVirtualizer({
    count: sortedEvents.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) =>
      sortedEvents[index]?.id === selectedEventId ? expandedRowEstimate : collapsedRowEstimate,
    getItemKey: (index) => sortedEvents[index]?.id ?? index,
    overscan: 10,
  });

  const virtualRows = virtualizer.getVirtualItems();

  useEffect(() => {
    if (selectedIndex >= 0) {
      virtualizer.scrollToIndex(selectedIndex, { align: "center" });
    }
  }, [selectedIndex, virtualizer]);

  const fontSize = metrics.fontSize;
  const smallFontSize = Math.max(9, fontSize - 3);
  const monoFontSize = Math.max(10, fontSize - 1);
  const lineHeight = `${metrics.rowLineHeight}px`;

  if (events.length === 0) {
    return (
      <div style={{ padding: "20px", color: tokens.colorNeutralForeground3, textAlign: "center", fontSize: `${fontSize}px`, fontFamily: LOG_UI_FONT_FAMILY }}>
        No Intune timeline events were found in this analysis.
      </div>
    );
  }

  if (sortedEvents.length === 0) {
    return (
      <div style={{ padding: "20px", color: tokens.colorNeutralForeground3, textAlign: "center", fontSize: `${fontSize}px`, fontFamily: LOG_UI_FONT_FAMILY }}>
        {timelineScope.filePath
          ? `No events from ${getFileName(timelineScope.filePath)} match the current timeline scope${filterEventType !== "All" || filterStatus !== "All" ? " and filters." : "."
          }`
          : "No events match the current filters."}
      </div>
    );
  }

  if (timelineViewMode === "activity") {
    return <EventActivityView events={filteredEvents} />;
  }

  return (
    <div
      ref={parentRef}
      role="listbox"
      aria-label={`Intune event timeline — ${sortedEvents.length} events`}
      style={{
        overflowY: "auto",
        height: "100%",
        padding: "0",
        backgroundColor: tokens.colorNeutralBackground1,
        fontFamily: LOG_UI_FONT_FAMILY,
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
            const event = sortedEvents[virtualRow.index];
            return (
              <EventTimelineRow
                key={virtualRow.key}
                ref={virtualizer.measureElement}
                event={event}
                dataIndex={virtualRow.index}
                isSelected={selectedEventId === event.id}
                fontSize={fontSize}
                smallFontSize={smallFontSize}
                monoFontSize={monoFontSize}
                lineHeight={lineHeight}
                rowLineHeightExpanded={metrics.rowLineHeight + 2}
                showSourceFileLabel={showSourceFileLabel}
                onSelect={selectEvent}
              />
            );
          })}
        </div>
      </div>
    </div>
  );
}


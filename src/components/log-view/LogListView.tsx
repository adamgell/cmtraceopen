import {
  useRef,
  useEffect,
  useCallback,
  useMemo,
  useState,
  useLayoutEffect,
} from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { useFilterStore } from "../../stores/filter-store";
import { LogRow } from "./LogRow";
import {
  COLUMN_NAMES,
  getLogViewGridTemplateColumns,
} from "../../lib/constants";

export function LogListView() {
  const entries = useLogStore((s) => s.entries);
  const selectedId = useLogStore((s) => s.selectedId);
  const selectEntry = useLogStore((s) => s.selectEntry);
  const highlightText = useLogStore((s) => s.highlightText);
  const highlightCaseSensitive = useLogStore((s) => s.highlightCaseSensitive);
  const isPaused = useLogStore((s) => s.isPaused);
  const showDetails = useUiStore((s) => s.showDetails);
  const filteredIds = useFilterStore((s) => s.filteredIds);

  const [hasKeyboardFocus, setHasKeyboardFocus] = useState(false);
  const [scrollbarWidth, setScrollbarWidth] = useState(0);

  const displayEntries = useMemo(() => {
    if (!filteredIds) return entries;
    return entries.filter((entry) => filteredIds.has(entry.id));
  }, [entries, filteredIds]);

  const selectedEntryIndex = useMemo(
    () => displayEntries.findIndex((entry) => entry.id === selectedId),
    [displayEntries, selectedId]
  );

  const parentRef = useRef<HTMLDivElement>(null);
  const isAtBottomRef = useRef(true);
  const gridTemplateColumns = useMemo(
    () => getLogViewGridTemplateColumns(showDetails),
    [showDetails]
  );

  const virtualizer = useVirtualizer({
    count: displayEntries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 20,
  });

  const handleScroll = useCallback(() => {
    const element = parentRef.current;

    if (!element) {
      return;
    }

    const threshold = 50;
    isAtBottomRef.current =
      element.scrollHeight - element.scrollTop - element.clientHeight < threshold;
  }, []);

  const updateScrollbarWidth = useCallback(() => {
    const element = parentRef.current;

    if (!element) {
      setScrollbarWidth(0);
      return;
    }

    setScrollbarWidth(element.offsetWidth - element.clientWidth);
  }, []);

  const prevCount = useRef(displayEntries.length);

  useEffect(() => {
    if (
      displayEntries.length > prevCount.current &&
      displayEntries.length > 0 &&
      isAtBottomRef.current &&
      !isPaused
    ) {
      virtualizer.scrollToIndex(displayEntries.length - 1, { align: "end" });
    }

    prevCount.current = displayEntries.length;
  }, [displayEntries.length, isPaused, virtualizer]);

  useEffect(() => {
    if (selectedEntryIndex < 0) {
      return;
    }

    virtualizer.scrollToIndex(selectedEntryIndex, { align: "center" });
  }, [selectedEntryIndex, virtualizer]);

  useLayoutEffect(() => {
    updateScrollbarWidth();

    const element = parentRef.current;

    if (!element || typeof ResizeObserver === "undefined") {
      return;
    }

    const observer = new ResizeObserver(() => {
      updateScrollbarWidth();
    });

    observer.observe(element);

    return () => {
      observer.disconnect();
    };
  }, [displayEntries.length, showDetails, updateScrollbarWidth]);

  const activeRowDomId =
    selectedEntryIndex >= 0
      ? `log-list-row-${displayEntries[selectedEntryIndex].id}`
      : undefined;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns,
          backgroundColor: "#f0f0f0",
          borderBottom: "2px solid #c0c0c0",
          fontSize: "13px",
          fontWeight: "bold",
          fontFamily: "'Segoe UI', Tahoma, sans-serif",
          lineHeight: "24px",
          whiteSpace: "nowrap",
          flexShrink: 0,
          boxSizing: "border-box",
          paddingRight: `${scrollbarWidth}px`,
        }}
      >
        <div
          style={{
            minWidth: 0,
            padding: "1px 4px",
            overflow: "hidden",
            textOverflow: "ellipsis",
          }}
        >
          {COLUMN_NAMES.logText}
        </div>
        {showDetails && (
          <>
            <div
              style={{
                padding: "1px 4px",
                borderLeft: "1px solid #c0c0c0",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {COLUMN_NAMES.component}
            </div>
            <div
              style={{
                padding: "1px 4px",
                borderLeft: "1px solid #c0c0c0",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {COLUMN_NAMES.dateTime}
            </div>
            <div
              style={{
                padding: "1px 4px",
                borderLeft: "1px solid #c0c0c0",
                overflow: "hidden",
                textOverflow: "ellipsis",
              }}
            >
              {COLUMN_NAMES.thread}
            </div>
          </>
        )}
      </div>

      <div
        ref={parentRef}
        data-log-list="true"
        role="listbox"
        tabIndex={0}
        aria-label="Log entries"
        aria-activedescendant={activeRowDomId}
        onScroll={handleScroll}
        onFocus={() => setHasKeyboardFocus(true)}
        onBlur={() => setHasKeyboardFocus(false)}
        onMouseDown={() => parentRef.current?.focus()}
        style={{
          flex: 1,
          overflow: "auto",
          outline: "none",
          boxShadow: hasKeyboardFocus ? "inset 0 0 0 1px #0078D7" : "none",
          scrollbarGutter: "stable",
        }}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const entry = displayEntries[virtualRow.index];

            return (
              <div
                key={entry.id}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: `${virtualRow.size}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                }}
              >
                <LogRow
                  entry={entry}
                  rowDomId={`log-list-row-${entry.id}`}
                  isSelected={entry.id === selectedId}
                  showDetails={showDetails}
                  highlightText={highlightText}
                  highlightCaseSensitive={highlightCaseSensitive}
                  onClick={selectEntry}
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

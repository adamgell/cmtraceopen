import {
  useRef,
  useEffect,
  useCallback,
  useMemo,
  useState,
  useLayoutEffect,
} from "react";
import { tokens } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { useFilterStore } from "../../stores/filter-store";
import { LogRow } from "./LogRow";
import type { ErrorCodeSpan } from "../../types/log";
import { useContextMenu } from "../../hooks/use-context-menu";
import {
  applyColumnOrder,
  getVisibleColumns,
  buildGridTemplateColumns,
  getColumnDef,
  type ColumnId,
  type ColumnDefinition,
} from "../../lib/column-config";
import { getThemeById } from "../../lib/themes";
import {
  getLogListMetrics,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";

export function LogListView() {
  const entries = useLogStore((s) => s.entries);
  const selectedId = useLogStore((s) => s.selectedId);
  const selectEntry = useLogStore((s) => s.selectEntry);
  const highlightText = useLogStore((s) => s.highlightText);
  const highlightCaseSensitive = useLogStore((s) => s.highlightCaseSensitive);
  const isPaused = useLogStore((s) => s.isPaused);
  const findMatchIds = useLogStore((s) => s.findMatchIds);
  const showDetails = useUiStore((s) => s.showDetails);

  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const themeId = useUiStore((s) => s.themeId);
  const severityPalette = useMemo(
    () => getThemeById(themeId).severityPalette,
    [themeId]
  );
  const filteredIds = useFilterStore((s) => s.filteredIds);

  // Column preferences from ui-store (persisted)
  const columnWidths = useUiStore((s) => s.columnWidths);
  const columnOrder = useUiStore((s) => s.columnOrder);
  const setColumnWidth = useUiStore((s) => s.setColumnWidth);
  const setColumnOrder = useUiStore((s) => s.setColumnOrder);

  const [hasKeyboardFocus, setHasKeyboardFocus] = useState(false);
  const [scrollbarWidth, setScrollbarWidth] = useState(0);

  const findMatchSet = useMemo(
    () => new Set(findMatchIds),
    [findMatchIds]
  );

  const displayEntries = useMemo(() => {
    if (!filteredIds) return entries;
    return entries.filter((entry) => filteredIds.has(entry.id));
  }, [entries, filteredIds]);

  const selectedEntryIndex = useMemo(
    () => displayEntries.findIndex((entry) => entry.id === selectedId),
    [displayEntries, selectedId]
  );

  const activeColumns = useLogStore((s) => s.activeColumns);

  const parentRef = useRef<HTMLDivElement>(null);
  const isAtBottomRef = useRef(true);
  /** When true, the next selectedEntryIndex change should NOT auto-scroll (user clicked a visible row). */
  const suppressScrollRef = useRef(false);

  // Apply user column order, then filter by showDetails
  const orderedColumns = useMemo(
    () => applyColumnOrder(activeColumns, columnOrder),
    [activeColumns, columnOrder]
  );
  const visibleColumns = useMemo(
    () =>
      getVisibleColumns(orderedColumns, showDetails),
    [orderedColumns, showDetails]
  );
  const gridTemplateColumns = useMemo(
    () => buildGridTemplateColumns(visibleColumns, columnWidths),
    [visibleColumns, columnWidths]
  );
  const listMetrics = useMemo(
    () => getLogListMetrics(logListFontSize),
    [logListFontSize]
  );

  const { showContextMenu } = useContextMenu();

  const handleErrorCodeClick = useCallback((span: ErrorCodeSpan) => {
    if (!useUiStore.getState().showInfoPane) {
      useUiStore.getState().toggleInfoPane();
    }
    useUiStore.getState().setFocusedErrorCode({
      codeHex: span.codeHex,
      codeDecimal: span.codeDecimal,
      description: span.description,
      category: span.category,
    });
  }, []);

  const virtualizer = useVirtualizer({
    count: displayEntries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => listMetrics.rowHeight,
    overscan: 20,
  });

  const handleScroll = useCallback(() => {
    const element = parentRef.current;
    if (!element) return;
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
    if (selectedEntryIndex < 0) return;
    if (suppressScrollRef.current) {
      suppressScrollRef.current = false;
      return;
    }
    virtualizer.scrollToIndex(selectedEntryIndex, { align: "center" });
  }, [selectedEntryIndex, virtualizer]);

  // ── Consume pending scroll target from deployment workspace ────────
  const pendingScrollTarget = useLogStore((s) => s.pendingScrollTarget);
  const openFilePath = useLogStore((s) => s.openFilePath);

  useEffect(() => {
    if (!pendingScrollTarget) return;
    if (displayEntries.length === 0) return;
    // Only consume if the loaded file matches the target
    if (openFilePath !== pendingScrollTarget.filePath) return;

    const targetLine = pendingScrollTarget.lineNumber;
    // Find the entry closest to the target line number
    const targetEntry = displayEntries.find((e) => e.lineNumber >= targetLine)
      ?? displayEntries[displayEntries.length - 1];

    if (targetEntry) {
      selectEntry(targetEntry.id);
    }

    // Clear the pending target
    useLogStore.getState().setPendingScrollTarget(null);
  }, [pendingScrollTarget, displayEntries, openFilePath, selectEntry]);

  useLayoutEffect(() => {
    updateScrollbarWidth();
    const element = parentRef.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(() => updateScrollbarWidth());
    observer.observe(element);
    return () => observer.disconnect();
  }, [displayEntries.length, showDetails, updateScrollbarWidth]);

  // ── Column resize ────────────────────────────────────────────────────
  const resizeRef = useRef<{
    colId: ColumnId;
    startX: number;
    startWidth: number;
  } | null>(null);

  const onResizeStart = useCallback(
    (colId: ColumnId, e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const def = getColumnDef(colId);
      const currentWidth = columnWidths[colId] ?? def?.defaultWidth ?? 100;
      resizeRef.current = { colId, startX: e.clientX, startWidth: currentWidth };
    },
    [columnWidths]
  );

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!resizeRef.current) return;
      const { colId, startX, startWidth } = resizeRef.current;
      const def = getColumnDef(colId);
      const minW = def?.minWidth ?? 40;
      const newWidth = Math.max(minW, startWidth + (e.clientX - startX));
      setColumnWidth(colId, newWidth);
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
  }, [setColumnWidth]);

  // ── Column drag-to-reorder ───────────────────────────────────────────
  const [dragState, setDragState] = useState<{
    draggedIndex: number;
    dropTarget: { index: number; side: "left" | "right" } | null;
  } | null>(null);

  const onDragStart = useCallback(
    (index: number, e: React.DragEvent) => {
      e.dataTransfer.effectAllowed = "move";
      e.dataTransfer.setData("text/plain", String(index));
      setDragState({ draggedIndex: index, dropTarget: null });
    },
    []
  );

  const onDragOver = useCallback(
    (index: number, e: React.DragEvent) => {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
      if (!dragState) return;
      const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
      const midX = rect.left + rect.width / 2;
      const side = e.clientX < midX ? "left" : "right";
      setDragState((prev) =>
        prev ? { ...prev, dropTarget: { index, side } } : null
      );
    },
    [dragState]
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      if (!dragState?.dropTarget) return;
      const { draggedIndex, dropTarget } = dragState;
      const cols = [...visibleColumns.map((c) => c.id)];
      const [dragged] = cols.splice(draggedIndex, 1);
      let insertAt = dropTarget.index;
      if (draggedIndex < dropTarget.index) insertAt--;
      if (dropTarget.side === "right") insertAt++;
      cols.splice(insertAt, 0, dragged);
      // Build full order including hidden detail columns
      const fullOrder = [...cols];
      for (const id of orderedColumns) {
        if (!fullOrder.includes(id)) fullOrder.push(id);
      }
      setColumnOrder(fullOrder);
      setDragState(null);
    },
    [dragState, visibleColumns, orderedColumns, setColumnOrder]
  );

  const onDragEnd = useCallback(() => setDragState(null), []);

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
      {/* Column header with resize handles and drag-to-reorder */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns,
          backgroundColor: tokens.colorNeutralBackground4,
          borderBottom: `2px solid ${tokens.colorNeutralStroke2}`,
          fontSize: `${listMetrics.headerFontSize}px`,
          fontWeight: "bold",
          fontFamily: LOG_UI_FONT_FAMILY,
          lineHeight: `${listMetrics.headerLineHeight}px`,
          whiteSpace: "nowrap",
          flexShrink: 0,
          boxSizing: "border-box",
          paddingRight: `${scrollbarWidth}px`,
        }}
      >
        {visibleColumns.map((col, i) => (
          <HeaderCell
            key={col.id}
            col={col}
            index={i}
            isFirst={i === 0}
            isDragged={dragState?.draggedIndex === i}
            dropIndicator={
              dragState?.dropTarget?.index === i
                ? dragState.dropTarget.side
                : null
            }
            onResizeStart={onResizeStart}
            onDragStart={onDragStart}
            onDragOver={onDragOver}
            onDrop={onDrop}
            onDragEnd={onDragEnd}
          />
        ))}
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
          boxShadow: hasKeyboardFocus ? `inset 0 0 0 1px ${tokens.colorBrandStroke1}` : "none",
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
                  isFindMatch={findMatchSet.has(entry.id)}
                  visibleColumns={visibleColumns}
                  gridTemplateColumns={gridTemplateColumns}
                  listFontSize={listMetrics.fontSize}
                  rowLineHeight={listMetrics.rowLineHeight}
                  severityPalette={severityPalette}
                  highlightText={highlightText}
                  highlightCaseSensitive={highlightCaseSensitive}
                  onClick={(id) => { if (id !== selectedId) { suppressScrollRef.current = true; } selectEntry(id); }}
                  onContextMenu={showContextMenu}
                  onErrorCodeClick={handleErrorCodeClick}
                />
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── Header cell with resize handle + drag-to-reorder ─────────────────

interface HeaderCellProps {
  col: ColumnDefinition;
  index: number;
  isFirst: boolean;
  isDragged: boolean;
  dropIndicator: "left" | "right" | null;
  onResizeStart: (colId: ColumnId, e: React.MouseEvent) => void;
  onDragStart: (index: number, e: React.DragEvent) => void;
  onDragOver: (index: number, e: React.DragEvent) => void;
  onDrop: (e: React.DragEvent) => void;
  onDragEnd: () => void;
}

function HeaderCell({
  col,
  index,
  isFirst,
  isDragged,
  dropIndicator,
  onResizeStart,
  onDragStart,
  onDragOver,
  onDrop,
  onDragEnd,
}: HeaderCellProps) {
  const [resizeHover, setResizeHover] = useState(false);

  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(index, e)}
      onDragOver={(e) => onDragOver(index, e)}
      onDrop={onDrop}
      onDragEnd={onDragEnd}
      style={{
        position: "relative",
        ...(col.isFlex ? { minWidth: 0 } : {}),
        padding: "1px 4px",
        overflow: "hidden",
        textOverflow: "ellipsis",
        cursor: "grab",
        opacity: isDragged ? 0.5 : 1,
        ...(isFirst
          ? {}
          : { borderLeft: `1px solid ${tokens.colorNeutralStroke2}` }),
        // Drop indicator
        ...(dropIndicator === "left"
          ? { boxShadow: `inset 3px 0 0 ${tokens.colorBrandStroke1}` }
          : dropIndicator === "right"
            ? { boxShadow: `inset -3px 0 0 ${tokens.colorBrandStroke1}` }
            : {}),
      }}
    >
      {col.label}

      {/* Resize handle in upper-right corner */}
      {(
        <div
          onMouseDown={(e) => onResizeStart(col.id, e)}
          onMouseEnter={() => setResizeHover(true)}
          onMouseLeave={() => setResizeHover(false)}
          style={{
            position: "absolute",
            right: -2,
            top: 0,
            width: 10,
            height: "100%",
            cursor: "col-resize",
            zIndex: 1,
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "center",
            paddingTop: 2,
          }}
        >
          {/* Visual grip indicator */}
          <div
            style={{
              width: 4,
              height: 10,
              borderRadius: 1,
              backgroundColor: resizeHover
                ? tokens.colorBrandStroke1
                : tokens.colorNeutralStroke2,
            }}
          />
        </div>
      )}
    </div>
  );
}

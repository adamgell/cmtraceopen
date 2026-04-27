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
import { SectionDividerRow } from "./SectionDividerRow";
import { MergeLegendBar } from "./MergeLegendBar";
import type { ErrorCodeSpan } from "../../types/log";
import type { Marker } from "../../types/markers";
import { useMarkerStore } from "../../stores/marker-store";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { formatLogEntryTimestamp } from "../../lib/date-time-format";
import { useContextMenu } from "../../hooks/use-context-menu";
import { ArrowBidirectionalLeftRightRegular } from "@fluentui/react-icons";
import {
  applyColumnOrder,
  getVisibleColumns,
  buildGridTemplateColumns,
  getColumnDef,
  calcAutoFitWidth,
  type ColumnId,
  type ColumnDefinition,
} from "../../lib/column-config";
import {
  ArrowSortDownRegular,
  ArrowSortUpRegular,
} from "@fluentui/react-icons";

type SortDir = "asc" | "desc";
import { getThemeById } from "../../lib/themes";
import {
  getLogListMetrics,
  getCanvasFont,
  LOG_UI_FONT_FAMILY,
} from "../../lib/log-accessibility";
import type { LogListDataSource } from "./log-list-data-source";

const defaultLogStoreDataSource: LogListDataSource = {
  useEntries: () => useLogStore((s) => s.entries),
  useSelectedId: () => useLogStore((s) => s.selectedId),
  useHighlightText: () => useLogStore((s) => s.highlightText),
  useHighlightCaseSensitive: () => useLogStore((s) => s.highlightCaseSensitive),
  useIsPaused: () => useLogStore((s) => s.isPaused),
  useFindMatchIds: () => {
    const arr = useLogStore((s) => s.findMatchIds);
    return useMemo(() => new Set(arr), [arr]);
  },
  selectEntry: (id) => useLogStore.getState().selectEntry(id),
};

export function LogListView({ dataSource }: { dataSource?: LogListDataSource } = {}) {
  const ds = dataSource ?? defaultLogStoreDataSource;
  const entries = ds.useEntries();
  const selectedId = ds.useSelectedId();
  const highlightText = ds.useHighlightText();
  const highlightCaseSensitive = ds.useHighlightCaseSensitive();
  const isPaused = ds.useIsPaused();
  const findMatchIds = ds.useFindMatchIds();
  const externalFilterRange = ds.useExternalFilterRange?.() ?? null;
  const highlightedRange = ds.useHighlightedRange?.() ?? null;
  const selectEntry = ds.selectEntry;
  const showDetails = useUiStore((s) => s.showDetails);

  const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  const mergedTabState = useLogStore((s) => s.mergedTabState);
  const correlatedEntries = useLogStore((s) => s.correlatedEntries);
  const openFilePath = useLogStore((s) => s.openFilePath);

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
  const setColumnWidths = useUiStore((s) => s.setColumnWidths);
  const setColumnOrder = useUiStore((s) => s.setColumnOrder);

  const [hasKeyboardFocus, setHasKeyboardFocus] = useState(false);
  const [scrollbarWidth, setScrollbarWidth] = useState(0);

  // Column sort state
  const [sortColumn, setSortColumn] = useState<ColumnId | null>(null);
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const handleColumnSort = useCallback((colId: ColumnId) => {
    setSortColumn((prev) => {
      if (prev === colId) {
        setSortDir((d) => (d === "asc" ? "desc" : "asc"));
        return colId;
      }
      setSortDir(colId === "dateTime" || colId === "lineNumber" ? "asc" : "asc");
      return colId;
    });
  }, []);

  const findMatchSet = useMemo(
    () => findMatchIds ?? new Set<number>(),
    [findMatchIds]
  );

  const correlatedIdSet = useMemo(
    () => new Set(correlatedEntries.map((c) => c.entry.id)),
    [correlatedEntries]
  );

  const displayEntries = useMemo(() => {
    let result = entries;
    if (externalFilterRange) {
      const [lo, hi] = externalFilterRange;
      result = result.filter(
        (e) => e.timestamp != null && e.timestamp >= lo && e.timestamp <= hi,
      );
    }
    if (filteredIds) {
      result = result.filter((entry) => filteredIds.has(entry.id));
    }
    if (sortColumn) {
      const col = getColumnDef(sortColumn);
      const sorted = [...result].sort((a, b) => {
        let cmp: number;
        if (sortColumn === "dateTime") {
          cmp = (a.timestamp ?? 0) - (b.timestamp ?? 0);
        } else if (sortColumn === "lineNumber") {
          cmp = a.lineNumber - b.lineNumber;
        } else if (sortColumn === "severity") {
          const order: Record<string, number> = { Error: 0, Warning: 1, Info: 2 };
          cmp = (order[a.severity] ?? 3) - (order[b.severity] ?? 3);
        } else if (col) {
          const aVal = col.accessor(a);
          const bVal = col.accessor(b);
          if (typeof aVal === "number" && typeof bVal === "number") {
            cmp = aVal - bVal;
          } else {
            cmp = String(aVal ?? "").localeCompare(String(bVal ?? ""));
          }
        } else {
          cmp = 0;
        }
        return sortDir === "asc" ? cmp : -cmp;
      });
      return sorted;
    }
    return result;
  }, [entries, externalFilterRange, filteredIds, sortColumn, sortDir]);

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

  // ── Section color auto-assignment (uses theme merge palette) ─────────
  const sectionColorMap = useMemo(() => {
    const palette = severityPalette.mergeColors;
    const map = new Map<string, string>();
    let paletteIndex = 0;
    for (const entry of displayEntries) {
      if (
        (entry.entryKind === "Section" || entry.entryKind === "Iteration") &&
        entry.sectionName &&
        !map.has(entry.sectionName)
      ) {
        const color = entry.sectionColor ?? palette[paletteIndex % palette.length];
        map.set(entry.sectionName, color);
        if (!entry.sectionColor) paletteIndex++;
      }
    }
    return map;
  }, [displayEntries, severityPalette.mergeColors]);

  // ── Marker store wiring ───────────────────────────────────────────────
  const isMerged = sourceOpenMode === "merged";
  const markersByFile = useMarkerStore((s) => s.markersByFile);
  const loadMarkers = useMarkerStore((s) => s.loadMarkers);
  const saveMarkers = useMarkerStore((s) => s.saveMarkers);
  const toggleMarker = useMarkerStore((s) => s.toggleMarker);
  const setMarkerCategory = useMarkerStore((s) => s.setMarkerCategory);
  const markerCategories = useMarkerStore((s) => s.categories);

  // Use openFilePath if set, otherwise derive from the first entry's filePath
  const activeFilePath = openFilePath ?? (entries.length > 0 ? entries[0].filePath : "");
  const fileMarkers: Map<number, Marker> = useMemo(
    () => isMerged ? new Map() : (markersByFile.get(activeFilePath) ?? new Map()),
    [markersByFile, activeFilePath, isMerged]
  );

  // Load markers when tab changes (skip in merged mode)
  useEffect(() => {
    if (isMerged) return;
    if (activeFilePath) {
      loadMarkers(activeFilePath);
    }
  }, [activeFilePath, loadMarkers, isMerged]);

  // Auto-save markers on changes with 1-second debounce.
  // markersDirtyRef prevents save from firing after loadMarkers hydrates state.
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const markersDirtyRef = useRef(false);
  useEffect(() => {
    if (isMerged) return;
    if (!activeFilePath) return;
    if (!markersDirtyRef.current) return;
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      saveMarkers(activeFilePath);
      markersDirtyRef.current = false;
    }, 1000);
    return () => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    };
  }, [fileMarkers, activeFilePath, saveMarkers, isMerged]);

  const handleToggleMarker = useCallback(
    (lineId: number) => {
      if (isMerged) return;
      if (activeFilePath) {
        markersDirtyRef.current = true;
        toggleMarker(activeFilePath, lineId);
      }
    },
    [activeFilePath, toggleMarker, isMerged]
  );

  const handleSetMarkerCategory = useCallback(
    (lineId: number, category: string) => {
      if (isMerged) return;
      if (activeFilePath) {
        markersDirtyRef.current = true;
        setMarkerCategory(activeFilePath, lineId, category);
      }
    },
    [activeFilePath, setMarkerCategory, isMerged]
  );

  // ── Multi-select state ─────────────────────────────────────────────
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const lastClickedIdRef = useRef<number | null>(null);
  /** Tracks whether the last selection change came from a mouse interaction. */
  const mouseSelectRef = useRef(false);

  // Sync selectedIds when selectedId changes from keyboard navigation
  useEffect(() => {
    if (mouseSelectRef.current) {
      mouseSelectRef.current = false;
      return;
    }
    if (selectedId !== null) {
      setSelectedIds(new Set([selectedId]));
    }
  }, [selectedId]);

  const handleRowClick = useCallback(
    (id: number, event: React.MouseEvent) => {
      const isMeta = event.metaKey || event.ctrlKey;
      const isShift = event.shiftKey;

      if (isMeta) {
        // Ctrl/Cmd+Click: toggle additive
        setSelectedIds((prev) => {
          const next = new Set(prev);
          if (next.has(id)) {
            next.delete(id);
          } else {
            next.add(id);
          }
          return next;
        });
        lastClickedIdRef.current = id;
      } else if (isShift && lastClickedIdRef.current !== null) {
        // Shift+Click: range select
        const lastIdx = displayEntries.findIndex(
          (e) => e.id === lastClickedIdRef.current
        );
        const currentIdx = displayEntries.findIndex((e) => e.id === id);
        if (lastIdx >= 0 && currentIdx >= 0) {
          const start = Math.min(lastIdx, currentIdx);
          const end = Math.max(lastIdx, currentIdx);
          const rangeIds = new Set<number>();
          for (let i = start; i <= end; i++) {
            rangeIds.add(displayEntries[i].id);
          }
          setSelectedIds(rangeIds);
        }
      } else {
        // Plain click: single select (clear others)
        setSelectedIds(new Set([id]));
        lastClickedIdRef.current = id;
      }

      // Mark as mouse-driven so the selectedId sync effect skips
      mouseSelectRef.current = true;

      // Always update the details pane via the store's single-selection
      if (id !== selectedId) {
        suppressScrollRef.current = true;
      }
      selectEntry(id);
    },
    [displayEntries, selectedId, selectEntry]
  );

  const handleCopySelected = useCallback(() => {
    if (selectedIds.size === 0) return;
    const selected = displayEntries.filter((e) => selectedIds.has(e.id));
    if (selected.length === 0) return;

    let text: string;
    if (selected.length === 1) {
      // Single entry: tab-separated format matching legacy Ctrl+C behavior
      const entry = selected[0];
      text = [
        entry.message,
        entry.component ?? "",
        formatLogEntryTimestamp(entry) ?? "",
        entry.threadDisplay ?? "",
      ].join("\t");
    } else {
      // Multi-select: plain messages, one per line
      text = selected.map((e) => e.message).join("\n");
    }
    writeText(text).catch(console.error);
  }, [selectedIds, displayEntries]);

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

  // ── Auto-fit column width ────────────────────────────────────────────────
  const handleHeaderDoubleClick = useCallback(
    (colId: ColumnId) => {
      if (colId === "message") return;
      const def = getColumnDef(colId);
      if (!def) return;
      // Use a rendered row element so the font-family is fully resolved (no CSS variables)
      const rowEl = parentRef.current?.querySelector<HTMLElement>(".log-row") ?? null;
      const contentFont = getCanvasFont(logListFontSize, false, rowEl);
      const headerFont = getCanvasFont(listMetrics.headerFontSize, true, rowEl);
      setColumnWidth(colId, calcAutoFitWidth(def, displayEntries, contentFont, headerFont));
    },
    [displayEntries, logListFontSize, listMetrics, setColumnWidth]
  );

  const handleFitAllColumns = useCallback(() => {
    const rowEl = parentRef.current?.querySelector<HTMLElement>(".log-row") ?? null;
    const contentFont = getCanvasFont(logListFontSize, false, rowEl);
    const headerFont = getCanvasFont(listMetrics.headerFontSize, true, rowEl);
    const updates: Record<string, number> = {};
    for (const col of visibleColumns) {
      if (col.id === "message") continue;
      updates[col.id] = calcAutoFitWidth(col, displayEntries, contentFont, headerFont);
    }
    setColumnWidths(updates);
  }, [visibleColumns, displayEntries, logListFontSize, listMetrics, setColumnWidths]);

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
          gridTemplateColumns: `20px ${gridTemplateColumns}`,
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
        {/* Gutter header spacer */}
        <div style={{ width: 20 }} />
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
            onDoubleClick={handleHeaderDoubleClick}
            onFitAll={col.id === "severity" ? handleFitAllColumns : undefined}
            sortColumn={sortColumn}
            sortDir={sortDir}
            onSort={handleColumnSort}
          />
        ))}
      </div>

      {sourceOpenMode === "merged" && mergedTabState && <MergeLegendBar />}

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
        onKeyDown={(e) => {
          const mod = e.ctrlKey || e.metaKey;
          // Ctrl+M / Cmd+M: toggle marker on selected row
          if (mod && e.key === "m") {
            e.preventDefault();
            if (selectedId !== null) {
              handleToggleMarker(selectedId);
            }
          }
          // Ctrl+A / Cmd+A: select all visible entries
          if (mod && e.key === "a") {
            e.preventDefault();
            setSelectedIds(new Set(displayEntries.map((entry) => entry.id)));
          }
          // Ctrl+C / Cmd+C: copy selected entries
          if (mod && e.key === "c") {
            e.preventDefault();
            handleCopySelected();
          }
        }}
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
            const isSectionDivider =
              entry.entryKind === "Section" || entry.entryKind === "Iteration";

            // Resolve section band color for regular rows
            const sectionBandColor = !isSectionDivider && entry.sectionName
              ? (entry.sectionColor ?? sectionColorMap.get(entry.sectionName) ?? null)
              : null;

            const isInHighlightedRange =
              highlightedRange != null &&
              entry.timestamp != null &&
              entry.timestamp >= highlightedRange[0] &&
              entry.timestamp <= highlightedRange[1];

            return (
              <div
                key={entry.id}
                data-highlighted={isInHighlightedRange ? "true" : undefined}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: `${virtualRow.size}px`,
                  transform: `translateY(${virtualRow.start}px)`,
                  boxShadow: isInHighlightedRange
                    ? `inset 3px 0 0 ${tokens.colorBrandStroke1}`
                    : undefined,
                }}
              >
                {isSectionDivider ? (
                  <SectionDividerRow
                    entry={entry}
                    resolvedColor={
                      entry.sectionColor ??
                      sectionColorMap.get(entry.sectionName ?? entry.message) ??
                      "#3b82f6"
                    }
                    listFontSize={listMetrics.fontSize}
                    rowLineHeight={listMetrics.rowLineHeight}
                    onClick={(id) => { if (id !== selectedId) { suppressScrollRef.current = true; } selectEntry(id); }}
                  />
                ) : (
                  <LogRow
                    entry={entry}
                    rowDomId={`log-list-row-${entry.id}`}
                    isSelected={entry.id === selectedId}
                    isMultiSelected={selectedIds.has(entry.id)}
                    isFindMatch={findMatchSet.has(entry.id)}
                    visibleColumns={visibleColumns}
                    gridTemplateColumns={gridTemplateColumns}
                    listFontSize={listMetrics.fontSize}
                    rowLineHeight={listMetrics.rowLineHeight}
                    severityPalette={severityPalette}
                    highlightText={highlightText}
                    highlightCaseSensitive={highlightCaseSensitive}
                    onClick={handleRowClick}
                    onContextMenu={showContextMenu}
                    onErrorCodeClick={handleErrorCodeClick}
                    mergeFileColor={sourceOpenMode === "merged" ? mergedTabState?.colorAssignments[entry.filePath] ?? null : null}
                    isCorrelated={sourceOpenMode === "merged" && correlatedIdSet.has(entry.id)}
                    correlationColor={sourceOpenMode === "merged" ? mergedTabState?.colorAssignments[entry.filePath] ?? null : null}
                    sectionBandColor={sectionBandColor}
                    marker={isMerged ? null : (fileMarkers.get(entry.id) ?? null)}
                    onToggleMarker={handleToggleMarker}
                    onSetMarkerCategory={handleSetMarkerCategory}
                    markerCategories={isMerged ? [] : markerCategories}
                  />
                )}
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
  onDoubleClick: (colId: ColumnId) => void;
  onFitAll?: () => void;
  sortColumn: ColumnId | null;
  sortDir: SortDir;
  onSort: (colId: ColumnId) => void;
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
  onDoubleClick,
  onFitAll,
  sortColumn,
  sortDir,
  onSort,
}: HeaderCellProps) {
  const [resizeHover, setResizeHover] = useState(false);
  const [fitAllHover, setFitAllHover] = useState(false);
  const isSorted = sortColumn === col.id;

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
      {onFitAll ? (
        /* Fit-all-columns button lives in the severity column header (no label, always first) */
        <div
          role="button"
          aria-label="Auto-fit all columns to content width"
          title="Auto-fit all columns to content width"
          draggable={false}
          onDragStart={(e) => { e.preventDefault(); e.stopPropagation(); }}
          onClick={(e) => { e.stopPropagation(); onFitAll(); }}
          onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onFitAll(); } }}
          tabIndex={0}
          onMouseEnter={() => setFitAllHover(true)}
          onMouseLeave={() => setFitAllHover(false)}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: "100%",
            height: "100%",
            cursor: "pointer",
            color: fitAllHover ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground2,
          }}
        >
          <ArrowBidirectionalLeftRightRegular style={{ fontSize: 12 }} />
        </div>
      ) : (
        <span style={{ display: "inline-flex", alignItems: "center", gap: "2px" }}>
          {col.label}
          {col.label && (
            <button
              type="button"
              title={`Sort by ${col.label}`}
              onClick={(e) => { e.stopPropagation(); e.preventDefault(); onSort(col.id); }}
              onMouseDown={(e) => e.stopPropagation()}
              style={{
                display: "inline-flex",
                alignItems: "center",
                justifyContent: "center",
                padding: "1px 2px",
                border: `1px solid ${isSorted ? tokens.colorBrandStroke1 : tokens.colorNeutralStroke1}`,
                borderRadius: "4px",
                background: isSorted ? tokens.colorBrandBackground2 : tokens.colorNeutralBackground3,
                cursor: "pointer",
                color: isSorted ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground2,
                fontSize: "10px",
                lineHeight: 1,
                marginLeft: "2px",
                flexShrink: 0,
              }}
            >
              {isSorted
                ? (sortDir === "asc" ? <ArrowSortUpRegular style={{ fontSize: "10px" }} /> : <ArrowSortDownRegular style={{ fontSize: "10px" }} />)
                : <ArrowSortDownRegular style={{ fontSize: "10px" }} />}
            </button>
          )}
        </span>
      )}

      {/* Resize handle in upper-right corner */}
      {(
        <div
          onMouseDown={(e) => onResizeStart(col.id, e)}
          onDoubleClick={(e) => { e.preventDefault(); e.stopPropagation(); onDoubleClick(col.id); }}
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
              borderRadius: 2,
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

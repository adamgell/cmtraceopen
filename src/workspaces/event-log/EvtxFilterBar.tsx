import { useMemo, useState } from "react";
import {
  Button,
  Checkbox,
  Dropdown,
  Input,
  Option,
  tokens,
} from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import {
  selectVisibleRecords,
  EVTX_GROUP_LABELS,
  type EvtxGroupField,
  type EvtxQuickFilterMode,
  type EvtxQuickFilterScope,
  type EvtxQuickFilterAction,
} from "./evtx-filter";
import { useSavedFilterStore } from "./evtx-filter-store";
import { orderFilters, sanitizeCriteria } from "./evtx-saved-filters";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import {
  availableColumns,
  discoverMappedProperties,
  type EvtxColumnId,
} from "./evtx-columns";
import {
  useEvtxStore,
  type EvtxSortField,
} from "./evtx-store";
import type { EvtxLevel, EvtxTimeWindow } from "./types";
import { EVTX_TIME_WINDOW_LABELS } from "./types";
import { timeZoneLabel } from "./evtx-time";

const TIME_WINDOWS: EvtxTimeWindow[] = ["1h", "24h", "7d", "30d", "all"];

const EXPORT_FORMATS = [
  { value: "csv", label: "CSV", extension: "csv" },
  { value: "tsv", label: "TSV", extension: "tsv" },
  { value: "json", label: "JSON", extension: "json" },
  { value: "xml", label: "Event XML", extension: "xml" },
] as const;

const GROUP_FIELDS: EvtxGroupField[] = ["level", "provider", "channel", "eventId", "day"];

const LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];

const LEVEL_COLORS: Record<EvtxLevel, string> = {
  Critical: tokens.colorPaletteRedForeground1,
  Error: tokens.colorPaletteRedForeground1,
  Warning: tokens.colorPaletteMarigoldForeground1,
  Information: tokens.colorBrandForeground1,
  Verbose: tokens.colorNeutralForeground4,
};

const LEVEL_SHORT_LABELS: Record<EvtxLevel, string> = {
  Critical: "Crit",
  Error: "Err",
  Warning: "Warn",
  Information: "Info",
  Verbose: "Verb",
};

const SORT_FIELD_LABELS: Record<EvtxSortField, string> = {
  time: "Time",
  eventId: "Event ID",
  level: "Level",
  provider: "Provider",
  channel: "Channel",
};

const SORT_FIELDS: EvtxSortField[] = ["time", "eventId", "level", "provider", "channel"];

const QUICK_FILTER_MODE_LABELS: Record<EvtxQuickFilterMode, string> = {
  oneString: "One string",
  multipleWords: "Any words",
  multipleStrings: "Any strings",
  allWords: "All words",
  allStrings: "All strings",
  eventIds: "Event IDs",
};
const QUICK_FILTER_MODES: EvtxQuickFilterMode[] = [
  "oneString",
  "multipleWords",
  "multipleStrings",
  "allWords",
  "allStrings",
  "eventIds",
];
const QUICK_FILTER_SCOPE_LABELS: Record<EvtxQuickFilterScope, string> = {
  allColumns: "All columns",
  visibleColumns: "Visible columns",
};
const QUICK_FILTER_ACTION_LABELS: Record<EvtxQuickFilterAction, string> = {
  show: "Show matches",
  hide: "Hide matches",
};

export function EvtxFilterBar() {
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const toggleFilterLevel = useEvtxStore((s) => s.toggleFilterLevel);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const setFilterEventIds = useEvtxStore((s) => s.setFilterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const setFilterSearch = useEvtxStore((s) => s.setFilterSearch);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const setQuickFilter = useEvtxStore((s) => s.setQuickFilter);
  const sortField = useEvtxStore((s) => s.sortField);
  const setSortField = useEvtxStore((s) => s.setSortField);
  const sortDirection = useEvtxStore((s) => s.sortDirection);
  const setSortDirection = useEvtxStore((s) => s.setSortDirection);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  // Sized from the operator's list font rather than hardcoded, so raising the list size raises
  // these controls with it. Clamped down a step because a toolbar control sits beside the list
  // rather than in it.
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const controlFontSize = `${Math.max(11, getLogListMetrics(logListFontSize).fontSize - 1)}px`;
  const records = useEvtxStore((s) => s.records);
  // Map columns are offered only when a loaded map actually produced them, so the chooser does not
  // fill with columns that are empty for the log in front of the operator.
  const choosableColumns = useMemo(
    () => availableColumns(discoverMappedProperties(records)),
    [records]
  );
  const setTimeZoneMode = useEvtxStore((s) => s.setTimeZoneMode);
  const setTimeWindow = useEvtxStore((s) => s.setTimeWindow);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);

  const sortFieldLabel = useMemo(() => SORT_FIELD_LABELS[sortField], [sortField]);

  const groupBy = useEvtxStore((s) => s.groupBy);
  const setGroupBy = useEvtxStore((s) => s.setGroupBy);

  const setBeforeLoadCriteria = useEvtxStore((s) => s.setBeforeLoadCriteria);
  const savedFilters = useSavedFilterStore((s) => s.savedFilters);
  const saveFilter = useSavedFilterStore((s) => s.save);
  const markFilterUsed = useSavedFilterStore((s) => s.markUsed);
  // The one ordering, not a second one. This re-implemented it and dropped the lastUsed
  // tiebreak, so marking a filter used changed the stored order and never changed what the
  // operator saw.
  const orderedFilters = useMemo(() => orderFilters(savedFilters), [savedFilters]);

  const columnConfig = useEvtxStore((s) => s.columnConfig);
  const toggleColumnVisible = useEvtxStore((s) => s.toggleColumnVisible);
  const moveColumnBy = useEvtxStore((s) => s.moveColumnBy);
  const resetColumns = useEvtxStore((s) => s.resetColumns);

  const [exportState, setExportState] = useState<string | null>(null);
  // An in-app field rather than window.prompt. Tauri's macOS webview is WKWebView, which does not
  // implement prompt, so the save-filter action silently did nothing on macOS.
  const [pendingName, setPendingName] = useState<string | null>(null);
  const [reorderTarget, setReorderTarget] = useState<EvtxColumnId | null>(null);
  const columnLabel = (id: EvtxColumnId) =>
    choosableColumns.find((column) => column.id === id)?.label ?? id;

  const commitFilterName = (name: string) => {
    const trimmed = name.trim();
    if (!trimmed) return;
    const state = useEvtxStore.getState();
    const saved = saveFilter(
      trimmed,
      sanitizeCriteria({
        beforeLoad: {
          levels: [...state.filterLevels],
          eventIds: state.filterEventIds,
          timeWindow: state.timeWindow,
        },
        onLoad: {
          search: state.filterSearch,
          quickFilter: state.quickFilter,
        },
        afterLoad: { groupBy: state.groupBy },
      })
    );
    setPendingName(null);
    setExportState(saved ? `Saved "${trimmed}"` : "That name cannot be used");
  };

  const applySavedFilter = (id: string) => {
    const filter = savedFilters.find((candidate) => candidate.id === id);
    if (!filter) return;
    const { criteria } = filter;
    setBeforeLoadCriteria(criteria.beforeLoad);
    setFilterSearch(criteria.onLoad.search);
    setQuickFilter(criteria.onLoad.quickFilter);
    setGroupBy(criteria.afterLoad.groupBy);
    markFilterUsed(id);
  };

  // Exports what is on screen, using the same predicate the list uses, so the file cannot quietly
  // differ from the view.
  const exportVisible = async (format: (typeof EXPORT_FORMATS)[number]) => {
    const state = useEvtxStore.getState();
    const records = selectVisibleRecords({
      ...state,
      timeWindow: state.sourceMode === "live" ? state.timeWindow : undefined,
      visibleColumns: state.columnConfig.order,
      timeZoneMode: state.timeZoneMode,
    });
    if (records.length === 0) {
      setExportState("Nothing to export");
      return;
    }
    try {
      const destination = await save({
        defaultPath: `events.${format.extension}`,
        filters: [{ name: format.label, extensions: [format.extension] }],
      });
      if (!destination) return;
      setExportState("Exporting...");
      // The delimited writers read neither rawXml nor eventData, and rawXml dominates the payload:
      // sending them for a CSV export serializes every record's XML and field list across the IPC
      // bridge for nothing, which on a hundred-thousand-record export is the bulk of the transfer.
      const payload =
        format.value === "csv" || format.value === "tsv"
          ? records.map(({ rawXml: _rawXml, eventData: _eventData, ...rest }) => rest)
          : records;
      const bytes = await invoke<unknown>("evtx_export_records", {
        records: payload,
        format: format.value,
        destination,
      });
      // The IPC boundary is typed by assertion, not by the compiler. A malformed reply would
      // otherwise render as "Exported ... (NaN KB)", which still reads as success, and an operator
      // would believe a file was written.
      // A safe integer, not merely finite: a count past Number.MAX_SAFE_INTEGER would format into
      // a confidently wrong size.
      if (typeof bytes !== "number" || !Number.isSafeInteger(bytes) || bytes < 0) {
        setExportState("Export failed: the writer did not report how much it wrote");
        return;
      }
      setExportState(`Exported ${records.length} events (${Math.round(bytes / 1024)} KB)`);
    } catch (error) {
      setExportState(
        `Export failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  };

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        padding: "6px 12px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
        flexWrap: "wrap",
        flexShrink: 0,
      }}
    >
      {sourceMode === "live" && (
        <>
          <Dropdown
            size="small"
            value={EVTX_TIME_WINDOW_LABELS[timeWindow]}
            selectedOptions={[timeWindow]}
            disabled={isLoading}
            style={{ minWidth: "132px" }}
            title="How far back to query. Applied by the Event Log service, so events outside the window are never fetched."
            onOptionSelect={(_, data) => {
              const next = data.optionValue as EvtxTimeWindow;
              if (!next || next === timeWindow) return;
              setTimeWindow(next);
            }}
          >
            {TIME_WINDOWS.map((window) => (
              <Option key={window} value={window}>
                {EVTX_TIME_WINDOW_LABELS[window]}
              </Option>
            ))}
          </Dropdown>

          <div
            style={{
              width: "1px",
              height: "20px",
              backgroundColor: tokens.colorNeutralStroke2,
            }}
          />
        </>
      )}

      <Button
        size="small"
        appearance="outline"
        onClick={() => setTimeZoneMode(timeZoneMode === "local" ? "utc" : "local")}
        style={{ minWidth: "auto", padding: "2px 8px", fontSize: controlFontSize }}
        title={
          timeZoneMode === "utc"
            ? "Event times are shown in UTC, as Windows recorded them. Click for local time."
            : "Event times are shown in this machine's local time. Click for UTC, which is what most other logs use."
        }
      >
        {timeZoneLabel(timeZoneMode)}
      </Button>

      <div
        style={{
          width: "1px",
          height: "20px",
          backgroundColor: tokens.colorNeutralStroke2,
        }}
      />

      {LEVELS.map((level) => {
        const active = filterLevels.has(level);
        return (
          <Button
            key={level}
            size="small"
            appearance={active ? "primary" : "outline"}
            onClick={() => toggleFilterLevel(level)}
            style={{
              minWidth: "auto",
              padding: "2px 8px",
              fontSize: controlFontSize,
              borderColor: active ? undefined : LEVEL_COLORS[level],
              color: active ? undefined : LEVEL_COLORS[level],
            }}
            title={`Toggle ${level} events`}
          >
            {LEVEL_SHORT_LABELS[level]}
          </Button>
        );
      })}

      <div
        style={{
          width: "1px",
          height: "20px",
          backgroundColor: tokens.colorNeutralStroke2,
        }}
      />

      <Input
        value={filterEventIds}
        onChange={(_, data) => setFilterEventIds(data.value)}
        placeholder="Event IDs (comma sep.)"
        size="small"
        style={{ width: "160px" }}
      />

      <Dropdown
        size="small"
        multiselect
        placeholder="Columns"
        value={`${columnConfig.order.length} shown`}
        selectedOptions={columnConfig.order}
        style={{ minWidth: "104px" }}
        title="Choose which columns the list shows."
        onOptionSelect={(_, data) => {
          const id = data.optionValue as EvtxColumnId | undefined;
          if (id) toggleColumnVisible(id);
        }}
      >
        {choosableColumns.map((column) => (
          <Option key={column.id} value={column.id} text={column.label}>
            {column.label}
          </Option>
        ))}
      </Dropdown>

      {/*
        A button, not an option. In a multiselect listbox every option carries a selection
        indicator, so "Reset to defaults" rendered as though it were a column that could be
        checked, and it is an action rather than a member of the set.
      */}
      <Button
        size="small"
        appearance="outline"
        onClick={resetColumns}
        title="Restore the default columns, order and widths"
        style={{ minWidth: "auto", padding: "2px 8px", fontSize: controlFontSize }}
      >
        Reset columns
      </Button>

      {/*
        Reordering lives outside the listbox. Buttons nested in a Fluent Option are invalid ARIA
        and never receive focus, because a listbox moves focus between options rather than into
        them, so a keyboard-only operator could show and hide columns but never order them.
      */}
      <Dropdown
        size="small"
        placeholder="Reorder"
        value={reorderTarget ? columnLabel(reorderTarget) : ""}
        selectedOptions={reorderTarget ? [reorderTarget] : []}
        style={{ minWidth: "104px" }}
        title="Pick a column, then use the arrows to move it."
        onOptionSelect={(_, data) => {
          if (data.optionValue) setReorderTarget(data.optionValue as EvtxColumnId);
        }}
      >
        {columnConfig.order.map((id) => (
          <Option key={id} value={id} text={columnLabel(id)}>
            {columnLabel(id)}
          </Option>
        ))}
      </Dropdown>

      <Button
        size="small"
        appearance="outline"
        aria-label="Move the selected column earlier"
        title="Move the selected column earlier"
        disabled={!reorderTarget || columnConfig.order.indexOf(reorderTarget) <= 0}
        onClick={() => reorderTarget && moveColumnBy(reorderTarget, -1)}
        style={{ minWidth: "auto", padding: "2px 8px", fontSize: controlFontSize }}
      >
        {"\u2191"}
      </Button>
      <Button
        size="small"
        appearance="outline"
        aria-label="Move the selected column later"
        title="Move the selected column later"
        disabled={
          !reorderTarget ||
          columnConfig.order.indexOf(reorderTarget) === columnConfig.order.length - 1
        }
        onClick={() => reorderTarget && moveColumnBy(reorderTarget, 1)}
        style={{ minWidth: "auto", padding: "2px 8px", fontSize: controlFontSize }}
      >
        {"\u2193"}
      </Button>

      <Dropdown
        size="small"
        placeholder="Saved"
        value=""
        selectedOptions={[]}
        style={{ minWidth: "104px" }}
        title="Apply a saved filter"
        onOptionSelect={(_, data) => {
          if (data.optionValue === "__save__") setPendingName("");
          else if (data.optionValue) applySavedFilter(data.optionValue);
        }}
      >
        <Option value="__save__">Save current...</Option>
        {orderedFilters.map((filter) => (
          <Option key={filter.id} value={filter.id}>
            {filter.favorite ? `\u2605 ${filter.name}` : filter.name}
          </Option>
        ))}
      </Dropdown>

      <Dropdown
        size="small"
        multiselect
        placeholder="Group by"
        value={groupBy.map((field) => EVTX_GROUP_LABELS[field]).join(" > ")}
        selectedOptions={groupBy}
        style={{ minWidth: "128px" }}
        title="Group the list. Selecting several nests them in the order chosen."
        onOptionSelect={(_, data) => {
          const field = data.optionValue as EvtxGroupField;
          if (!field) return;
          // Appending rather than sorting keeps the nesting order under the operator's control.
          setGroupBy(
            groupBy.includes(field)
              ? groupBy.filter((existing) => existing !== field)
              : [...groupBy, field]
          );
        }}
      >
        {GROUP_FIELDS.map((field) => (
          <Option key={field} value={field}>
            {EVTX_GROUP_LABELS[field]}
          </Option>
        ))}
      </Dropdown>

      <Dropdown
        size="small"
        placeholder="Export"
        value=""
        selectedOptions={[]}
        style={{ minWidth: "96px" }}
        title="Export the events currently shown, using the same filters as the list"
        onOptionSelect={(_, data) => {
          const format = EXPORT_FORMATS.find((f) => f.value === data.optionValue);
          if (format) void exportVisible(format);
        }}
      >
        {EXPORT_FORMATS.map((format) => (
          <Option key={format.value} value={format.value}>
            {format.label}
          </Option>
        ))}
      </Dropdown>

      {pendingName !== null && (
        <Input
          autoFocus
          size="small"
          value={pendingName}
          placeholder="Name this filter"
          aria-label="Name this filter"
          style={{ width: "180px" }}
          onChange={(_, data) => setPendingName(data.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") commitFilterName(pendingName);
            if (event.key === "Escape") setPendingName(null);
          }}
          onBlur={() => setPendingName(null)}
        />
      )}

      {exportState && (
        <span style={{ fontSize: controlFontSize, color: tokens.colorNeutralForeground3 }}>
          {exportState}
        </span>
      )}

      <Input
        value={quickFilter.query}
        onChange={(_, data) => setQuickFilter({ ...quickFilter, query: data.value })}
        placeholder={quickFilter.mode === "eventIds" ? "Quick IDs (e.g. 4624-4626)" : "Quick filter..."}
        aria-label="Quick filter query"
        size="small"
        style={{ width: "180px" }}
      />
      <Dropdown
        size="small"
        value={QUICK_FILTER_MODE_LABELS[quickFilter.mode]}
        selectedOptions={[quickFilter.mode]}
        title="Quick filter matching grammar"
        onOptionSelect={(_, data) => {
          if (data.optionValue) {
            setQuickFilter({
              ...quickFilter,
              mode: data.optionValue as EvtxQuickFilterMode,
            });
          }
        }}
      >
        {QUICK_FILTER_MODES.map((mode) => (
          <Option key={mode} value={mode}>
            {QUICK_FILTER_MODE_LABELS[mode]}
          </Option>
        ))}
      </Dropdown>
      <Dropdown
        size="small"
        value={QUICK_FILTER_SCOPE_LABELS[quickFilter.scope]}
        selectedOptions={[quickFilter.scope]}
        title="Quick filter column scope"
        onOptionSelect={(_, data) => {
          if (data.optionValue) {
            setQuickFilter({
              ...quickFilter,
              scope: data.optionValue as EvtxQuickFilterScope,
            });
          }
        }}
      >
        {(Object.keys(QUICK_FILTER_SCOPE_LABELS) as EvtxQuickFilterScope[]).map((scope) => (
          <Option key={scope} value={scope}>
            {QUICK_FILTER_SCOPE_LABELS[scope]}
          </Option>
        ))}
      </Dropdown>
      <Dropdown
        size="small"
        value={QUICK_FILTER_ACTION_LABELS[quickFilter.action]}
        selectedOptions={[quickFilter.action]}
        title="Quick filter show or hide behavior"
        onOptionSelect={(_, data) => {
          if (data.optionValue) {
            setQuickFilter({
              ...quickFilter,
              action: data.optionValue as EvtxQuickFilterAction,
            });
          }
        }}
      >
        {(Object.keys(QUICK_FILTER_ACTION_LABELS) as EvtxQuickFilterAction[]).map((action) => (
          <Option key={action} value={action}>
            {QUICK_FILTER_ACTION_LABELS[action]}
          </Option>
        ))}
      </Dropdown>
      <Checkbox
        checked={quickFilter.caseSensitive}
        label="Case"
        title="Case-sensitive quick filter"
        onChange={(_, data) =>
          setQuickFilter({ ...quickFilter, caseSensitive: data.checked === true })
        }
      />
      <Checkbox
        checked={quickFilter.highlight}
        label="Highlight"
        title="Highlight quick-filter matches"
        onChange={(_, data) =>
          setQuickFilter({ ...quickFilter, highlight: data.checked === true })
        }
      />

      <Input
        value={filterSearch}
        onChange={(_, data) => setFilterSearch(data.value)}
        placeholder="Search..."
        size="small"
        style={{ width: "180px" }}
      />

      <div style={{ flex: 1 }} />

      <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
        <span
          style={{
            fontSize: controlFontSize,
            color: tokens.colorNeutralForeground3,
          }}
        >
          Sort:
        </span>
        <Dropdown
          value={sortFieldLabel}
          selectedOptions={[sortField]}
          onOptionSelect={(_, data) => {
            if (data.optionValue) {
              setSortField(data.optionValue as EvtxSortField);
            }
          }}
          size="small"
          style={{ minWidth: "100px" }}
        >
          {SORT_FIELDS.map((f) => (
            <Option key={f} value={f}>
              {SORT_FIELD_LABELS[f]}
            </Option>
          ))}
        </Dropdown>
        <Button
          size="small"
          appearance="subtle"
          onClick={() =>
            setSortDirection(
              sortDirection === "asc" ? "desc" : "asc"
            )
          }
          title={`Sort ${sortDirection === "asc" ? "ascending" : "descending"}`}
          style={{ minWidth: "auto", padding: "2px 6px" }}
        >
          {sortDirection === "asc" ? "\u2191" : "\u2193"}
        </Button>
      </div>
    </div>
  );
}

import { useMemo, useState } from "react";
import { Button, Dropdown, Input, Option, tokens } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import { selectVisibleRecords } from "./evtx-filter";
import {
  useEvtxStore,
  type EvtxSortField,
} from "./evtx-store";
import type { EvtxLevel, EvtxTimeWindow } from "./types";
import { EVTX_TIME_WINDOW_LABELS } from "./types";

const TIME_WINDOWS: EvtxTimeWindow[] = ["1h", "24h", "7d", "30d", "all"];

const EXPORT_FORMATS = [
  { value: "csv", label: "CSV", extension: "csv" },
  { value: "tsv", label: "TSV", extension: "tsv" },
  { value: "json", label: "JSON", extension: "json" },
  { value: "xml", label: "Event XML", extension: "xml" },
] as const;

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

export function EvtxFilterBar() {
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const toggleFilterLevel = useEvtxStore((s) => s.toggleFilterLevel);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const setFilterEventIds = useEvtxStore((s) => s.setFilterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const setFilterSearch = useEvtxStore((s) => s.setFilterSearch);
  const sortField = useEvtxStore((s) => s.sortField);
  const setSortField = useEvtxStore((s) => s.setSortField);
  const sortDirection = useEvtxStore((s) => s.sortDirection);
  const setSortDirection = useEvtxStore((s) => s.setSortDirection);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const setTimeWindow = useEvtxStore((s) => s.setTimeWindow);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const refreshLoadedChannels = useEvtxStore((s) => s.refreshLoadedChannels);

  const sortFieldLabel = useMemo(() => SORT_FIELD_LABELS[sortField], [sortField]);

  const [exportState, setExportState] = useState<string | null>(null);

  // Exports what is on screen, using the same predicate the list uses, so the file cannot quietly
  // differ from the view.
  const exportVisible = async (format: (typeof EXPORT_FORMATS)[number]) => {
    const records = selectVisibleRecords(useEvtxStore.getState());
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
      const bytes = await invoke<number>("evtx_export_records", {
        records,
        format: format.value,
        destination,
      });
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
              // The window is a server-side predicate, so it only takes effect on a refetch.
              void refreshLoadedChannels();
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
              fontSize: "11px",
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

      {exportState && (
        <span style={{ fontSize: "11px", color: tokens.colorNeutralForeground3 }}>
          {exportState}
        </span>
      )}

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
            fontSize: "11px",
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

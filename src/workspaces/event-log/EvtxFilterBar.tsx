import { useMemo } from "react";
import { Button, Dropdown, Input, Option, tokens } from "@fluentui/react-components";
import {
  useEvtxStore,
  type EvtxSortField,
} from "./evtx-store";
import type { EvtxLevel } from "./types";

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

  const sortFieldLabel = useMemo(() => SORT_FIELD_LABELS[sortField], [sortField]);

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

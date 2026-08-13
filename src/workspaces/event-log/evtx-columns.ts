/**
 * Column configuration for the event list.
 *
 * FullEventLogView exposes sixteen columns with a chooser that reorders them and sets widths; we
 * showed six with no control at all. The model is kept pure so ordering and validation are
 * testable without a React or Tauri runtime.
 */
import type { EvtxRecord } from "./types";
import { formatEventTime, type EvtxTimeZoneMode } from "./evtx-time";

/**
 * A column whose meaning is fixed by the event schema.
 */
export type EvtxFixedColumnId =
  | "level"
  | "timestamp"
  | "eventId"
  | "recordId"
  | "channel"
  | "provider"
  | "computer"
  | "task"
  | "opcode"
  | "processId"
  | "threadId"
  | "keywords"
  | "message";

/**
 * A column produced by an event map, such as `PayloadData1` or `RemoteHost`.
 *
 * These cannot be a fixed list: which ones exist depends on which maps are loaded and which events
 * they matched. Encoding the property in the id keeps the configuration a flat list of strings,
 * which is what makes it survive being written to disk by one build and read by another.
 */
export type EvtxMappedColumnId = `mapped:${string}`;

export type EvtxColumnId = EvtxFixedColumnId | EvtxMappedColumnId;

const MAPPED_PREFIX = "mapped:";

/** The column id carrying an event map's `property`. */
export function mappedColumnId(property: string): EvtxMappedColumnId {
  return `${MAPPED_PREFIX}${property}`;
}

/** The map property behind a column id, or null when the column is a fixed one. */
export function mappedColumnProperty(id: string): string | null {
  return id.startsWith(MAPPED_PREFIX) ? id.slice(MAPPED_PREFIX.length) : null;
}

/**
 * The map columns present in a set of records.
 *
 * Discovered from the data rather than declared, because a map only contributes a column to events
 * it actually matched. Offering every property every map could ever emit would fill the chooser
 * with columns that are empty for the log in front of the operator.
 */
export function discoverMappedProperties(
  records: readonly EvtxRecord[]
): string[] {
  const seen = new Set<string>();
  for (const record of records) {
    for (const column of record.mapped ?? []) {
      seen.add(column.property);
    }
  }
  return [...seen].sort();
}

/** A renderable spec for a map column, derived from its id alone. */
function mappedColumnSpec(id: EvtxMappedColumnId): EvtxColumnSpec {
  return {
    id,
    label: mappedColumnProperty(id) ?? id,
    defaultWidth: 140,
    defaultVisible: false,
  };
}

/**
 * Every column offerable for the loaded records: the fixed ones, then whatever the maps produced.
 */
export function availableColumns(
  mappedProperties: readonly string[]
): EvtxColumnSpec[] {
  return [
    ...EVTX_COLUMNS,
    ...mappedProperties.map((property) => mappedColumnSpec(mappedColumnId(property))),
  ];
}

export interface EvtxColumnSpec {
  id: EvtxColumnId;
  label: string;
  /** Default width in pixels, or null for the column that absorbs remaining space. */
  defaultWidth: number | null;
  /** Shown when no configuration has been saved. */
  defaultVisible: boolean;
}

/** Every column, in the order a fresh install presents them. */
export const EVTX_COLUMNS: EvtxColumnSpec[] = [
  { id: "level", label: "Level", defaultWidth: 40, defaultVisible: true },
  { id: "timestamp", label: "Event Time", defaultWidth: 165, defaultVisible: true },
  { id: "eventId", label: "Event ID", defaultWidth: 50, defaultVisible: true },
  { id: "recordId", label: "Record ID", defaultWidth: 70, defaultVisible: false },
  { id: "channel", label: "Channel", defaultWidth: 140, defaultVisible: true },
  { id: "provider", label: "Provider", defaultWidth: 160, defaultVisible: true },
  { id: "computer", label: "Computer", defaultWidth: 120, defaultVisible: false },
  { id: "task", label: "Task", defaultWidth: 60, defaultVisible: false },
  { id: "opcode", label: "Opcode", defaultWidth: 60, defaultVisible: false },
  { id: "processId", label: "PID", defaultWidth: 60, defaultVisible: false },
  { id: "threadId", label: "TID", defaultWidth: 60, defaultVisible: false },
  { id: "keywords", label: "Keywords", defaultWidth: 140, defaultVisible: false },
  // Last and unbounded: the description absorbs whatever width remains.
  { id: "message", label: "Description", defaultWidth: null, defaultVisible: true },
];

const COLUMN_IDS = new Set<string>(EVTX_COLUMNS.map((column) => column.id));

/**
 * Fixed columns keyed by id.
 *
 * Module scope because EVTX_COLUMNS never changes and the row renderer calls visibleColumns once
 * per rendered row; rebuilding the map there allocated one per row per render.
 */
const FIXED_COLUMNS_BY_ID = new Map<string, EvtxColumnSpec>(
  EVTX_COLUMNS.map((column) => [column.id, column])
);

/**
 * Whether a stored id is one this build can render.
 *
 * A map column is accepted whatever its property, because the maps loaded at the time the
 * configuration was written may not be loaded now. Dropping it would silently discard a column the
 * operator arranged, and it costs nothing to keep: a map column with no matching value renders
 * empty, exactly as an event that the map did not match already does.
 */
function isKnownColumnId(candidate: string): boolean {
  if (COLUMN_IDS.has(candidate)) return true;
  const property = mappedColumnProperty(candidate);
  return property !== null && property.length > 0;
}

export interface EvtxColumnConfig {
  /** Visible columns in display order. */
  order: EvtxColumnId[];
  /** Width overrides, keyed by column id. */
  widths: Partial<Record<EvtxColumnId, number>>;
}

/** The configuration a fresh install starts from. */
export function defaultColumnConfig(): EvtxColumnConfig {
  return {
    order: EVTX_COLUMNS.filter((column) => column.defaultVisible).map((column) => column.id),
    widths: {},
  };
}

/**
 * Coerces stored configuration into something this build can render.
 *
 * Configuration outlives the build that wrote it. A removed column would otherwise render as an
 * empty cell forever, and a column added by a later build would be invisible with no way to reach
 * it, so unknown ids are dropped and the order is deduplicated.
 */
export function sanitizeColumnConfig(input: unknown): EvtxColumnConfig {
  const raw =
    typeof input === "object" && input !== null && !Array.isArray(input)
      ? (input as Record<string, unknown>)
      : {};

  const seen = new Set<EvtxColumnId>();
  const order: EvtxColumnId[] = [];
  if (Array.isArray(raw.order)) {
    for (const candidate of raw.order) {
      if (typeof candidate !== "string" || !isKnownColumnId(candidate)) continue;
      const id = candidate as EvtxColumnId;
      if (seen.has(id)) continue;
      seen.add(id);
      order.push(id);
    }
  }

  const widths: Partial<Record<EvtxColumnId, number>> = {};
  if (typeof raw.widths === "object" && raw.widths !== null) {
    for (const [key, value] of Object.entries(raw.widths as Record<string, unknown>)) {
      if (!isKnownColumnId(key)) continue;
      // A zero or negative width would hide a column the operator believes is shown.
      if (typeof value === "number" && Number.isFinite(value) && value >= 24) {
        widths[key as EvtxColumnId] = Math.round(value);
      }
    }
  }

  // Every column hidden leaves an empty list with no way back, so that falls back to the defaults.
  return order.length > 0 ? { order, widths } : { ...defaultColumnConfig(), widths };
}

/** Specs for the visible columns, in display order. */
export function visibleColumns(config: EvtxColumnConfig): EvtxColumnSpec[] {
  return config.order
    .map((id) => {
      const fixed = FIXED_COLUMNS_BY_ID.get(id);
      if (fixed) return fixed;
      // Synthesized from the id, so rendering a map column needs no knowledge of which maps are
      // loaded. That keeps the row renderer independent of load order.
      return mappedColumnProperty(id) ? mappedColumnSpec(id as EvtxMappedColumnId) : undefined;
    })
    .filter((column): column is EvtxColumnSpec => column !== undefined);
}

/** Width to render `column` at, honouring any override. */
export function columnWidth(config: EvtxColumnConfig, column: EvtxColumnSpec): number | null {
  const override = config.widths[column.id];
  if (override !== undefined) return override;
  return column.defaultWidth;
}

/** Moves a column one position earlier or later, ignoring moves off either end. */
export function moveColumn(
  config: EvtxColumnConfig,
  id: EvtxColumnId,
  direction: -1 | 1
): EvtxColumnConfig {
  const index = config.order.indexOf(id);
  const target = index + direction;
  if (index < 0 || target < 0 || target >= config.order.length) return config;
  const order = [...config.order];
  [order[index], order[target]] = [order[target], order[index]];
  return { ...config, order };
}

/** Shows or hides a column, appending a newly shown one at the end. */
export function toggleColumn(config: EvtxColumnConfig, id: EvtxColumnId): EvtxColumnConfig {
  if (config.order.includes(id)) {
    const order = config.order.filter((existing) => existing !== id);
    // Refuse to hide the last column; an empty list has no affordance to recover from.
    return order.length > 0 ? { ...config, order } : config;
  }
  return { ...config, order: [...config.order, id] };
}

/**
 * Renders a record's value for a column, as displayed text.
 *
 * The time zone is explicit rather than implied. This column previously printed the raw string
 * Windows wrote, which is UTC, while the rest of the workspace showed local time, so the same
 * event carried two different clocks depending on where it was read.
 */
export function columnValue(
  record: EvtxRecord,
  id: EvtxColumnId,
  timeZone: EvtxTimeZoneMode = "local"
): string {
  const mappedProperty = mappedColumnProperty(id);
  if (mappedProperty !== null) {
    const column = record.mapped?.find((entry) => entry.property === mappedProperty);
    // An event the map did not match, or matched incompletely, renders empty. Showing a partially
    // substituted template would put a literal %3 in a column an operator is scanning.
    return column && column.complete ? column.text : "";
  }
  return fixedColumnValue(record, id as EvtxFixedColumnId, timeZone);
}

/**
 * Renders a fixed column.
 *
 * Split out so the switch stays exhaustive over `EvtxFixedColumnId`. Folding map columns into the
 * same switch would widen it to a template literal type and lose the compile error that catches a
 * newly added column nobody wrote a case for.
 */
function fixedColumnValue(
  record: EvtxRecord,
  id: EvtxFixedColumnId,
  timeZone: EvtxTimeZoneMode
): string {
  switch (id) {
    case "level":
      return record.level;
    case "timestamp":
      return formatEventTime(record.timestampEpoch, timeZone, record.timestamp);
    case "eventId":
      return String(record.eventId);
    case "recordId":
      return String(record.eventRecordId);
    case "channel":
      return record.channel;
    case "provider":
      return record.provider;
    case "computer":
      return record.computer;
    // Absent values render empty rather than as 0, matching the record model: the provider wrote
    // nothing, and 0 would be a value it never claimed.
    case "task":
      return record.task != null ? String(record.task) : "";
    case "opcode":
      return record.opcode != null ? String(record.opcode) : "";
    case "processId":
      return record.processId != null ? String(record.processId) : "";
    case "threadId":
      return record.threadId != null ? String(record.threadId) : "";
    case "keywords":
      return record.keywords ?? "";
    case "message":
      return record.message;
  }
}

/**
 * Column configuration for the event list.
 *
 * FullEventLogView exposes sixteen columns with a chooser that reorders them and sets widths; we
 * showed six with no control at all. The model is kept pure so ordering and validation are
 * testable without a React or Tauri runtime.
 */
import type { EvtxRecord } from "./types";

export type EvtxColumnId =
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
      if (typeof candidate !== "string" || !COLUMN_IDS.has(candidate)) continue;
      const id = candidate as EvtxColumnId;
      if (seen.has(id)) continue;
      seen.add(id);
      order.push(id);
    }
  }

  const widths: Partial<Record<EvtxColumnId, number>> = {};
  if (typeof raw.widths === "object" && raw.widths !== null) {
    for (const [key, value] of Object.entries(raw.widths as Record<string, unknown>)) {
      if (!COLUMN_IDS.has(key)) continue;
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
  const byId = new Map(EVTX_COLUMNS.map((column) => [column.id, column]));
  return config.order
    .map((id) => byId.get(id))
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

/** Renders a record's value for a column, as displayed text. */
export function columnValue(record: EvtxRecord, id: EvtxColumnId): string {
  switch (id) {
    case "level":
      return record.level;
    case "timestamp":
      return record.timestamp;
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

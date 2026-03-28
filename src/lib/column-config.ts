import type { LogEntry, ParserKind } from "../types/log";

/** Unique identifier for each possible log viewer column. */
export type ColumnId =
  | "severity"
  | "lineNumber"
  | "dateTime"
  | "message"
  | "component"
  | "thread"
  | "sourceFile"
  | "filePath"
  | "ipAddress"
  | "hostName"
  | "macAddress"
  | "resultCode"
  | "gleCode"
  | "setupPhase"
  | "operationName";

/** Static definition for a column — label, width, and how to read data from a LogEntry. */
export interface ColumnDefinition {
  id: ColumnId;
  label: string;
  /** Default width in pixels. -1 means flex (fills remaining space). */
  defaultWidth: number;
  /** Minimum width in pixels when resizing. */
  minWidth: number;
  /** True only for the message column (takes remaining space). */
  isFlex: boolean;
  /** True = hidden when showDetails is off. Severity is always visible. */
  isDetail: boolean;
  /**
   * Read the display value from a LogEntry.
   * Returns null when the field is not populated by the parser.
   * Note: "severity" renders a colored dot, "dateTime" uses formatLogEntryTimestamp(),
   * and "message" has special rich rendering — all handled in the view layer.
   */
  accessor: (entry: LogEntry) => string | number | null;
}

/**
 * Ordered catalog of every possible column.
 * Default rendering order follows this array (severity first, timestamp before message).
 */
export const ALL_COLUMNS: readonly ColumnDefinition[] = [
  {
    id: "severity",
    label: "",
    defaultWidth: 28,
    minWidth: 24,
    isFlex: false,
    isDetail: false,
    accessor: (e) => e.severity,
  },
  {
    id: "lineNumber",
    label: "#",
    defaultWidth: 60,
    minWidth: 40,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.lineNumber,
  },
  {
    id: "dateTime",
    label: "Date/Time",
    defaultWidth: 200,
    minWidth: 100,
    isFlex: false,
    isDetail: true,
    accessor: () => null, // handled via formatLogEntryTimestamp() in view layer
  },
  {
    id: "message",
    label: "Log Text",
    defaultWidth: 600,
    minWidth: 100,
    isFlex: false,
    isDetail: false,
    accessor: (e) => e.message,
  },
  {
    id: "component",
    label: "Component",
    defaultWidth: 180,
    minWidth: 60,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.component,
  },
  {
    id: "thread",
    label: "Thread",
    defaultWidth: 120,
    minWidth: 60,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.threadDisplay,
  },
  {
    id: "sourceFile",
    label: "Source",
    defaultWidth: 160,
    minWidth: 60,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.sourceFile,
  },
  {
    id: "filePath",
    label: "File",
    defaultWidth: 180,
    minWidth: 60,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.filePath.split(/[\\/]/).pop() ?? e.filePath,
  },
  {
    id: "ipAddress",
    label: "IP Address",
    defaultWidth: 140,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.ipAddress ?? null,
  },
  {
    id: "hostName",
    label: "Host Name",
    defaultWidth: 200,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.hostName ?? null,
  },
  {
    id: "macAddress",
    label: "MAC Address",
    defaultWidth: 150,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.macAddress ?? null,
  },
  {
    id: "resultCode",
    label: "Result Code",
    defaultWidth: 130,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.resultCode ?? null,
  },
  {
    id: "gleCode",
    label: "GLE",
    defaultWidth: 100,
    minWidth: 60,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.gleCode ?? null,
  },
  {
    id: "setupPhase",
    label: "Setup Phase",
    defaultWidth: 160,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.setupPhase ?? null,
  },
  {
    id: "operationName",
    label: "Operation",
    defaultWidth: 220,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.operationName ?? null,
  },
];

/** Lookup from ColumnId to its definition for O(1) access. */
const COLUMN_BY_ID = new Map<ColumnId, ColumnDefinition>(
  ALL_COLUMNS.map((c) => [c.id, c])
);

export function getColumnDef(id: ColumnId): ColumnDefinition | undefined {
  return COLUMN_BY_ID.get(id);
}

/** Which columns each parser populates (in display order — severity first, timestamp before message). */
const PARSER_COLUMN_MAP: Record<ParserKind, ColumnId[]> = {
  ccm: ["severity", "dateTime", "message", "component", "thread", "sourceFile"],
  simple: ["severity", "dateTime", "message", "component", "thread"],
  dism: ["severity", "dateTime", "message", "component"],
  panther: ["severity", "dateTime", "message", "component", "thread", "sourceFile", "resultCode", "gleCode", "setupPhase", "operationName"],
  cbs: ["severity", "dateTime", "message", "component"],
  reportingEvents: ["severity", "dateTime", "message", "component"],
  timestamped: ["severity", "dateTime", "message"],
  plain: ["severity", "message"],
  msi: ["severity", "dateTime", "message", "component", "thread"],
  psadtLegacy: ["severity", "dateTime", "message", "component", "sourceFile"],
  intuneMacOs: ["severity", "dateTime", "message", "component", "thread", "sourceFile"],
  dhcp: ["severity", "dateTime", "message", "ipAddress", "hostName", "macAddress"],
  burn: ["severity", "dateTime", "message", "component", "thread"],
};

/** Default columns used before any file is loaded. */
export const DEFAULT_COLUMNS: ColumnId[] = [
  "severity",
  "dateTime",
  "message",
  "component",
  "thread",
];

/** Get the columns relevant to a single parser. */
export function getColumnsForParser(parser: ParserKind): ColumnId[] {
  return PARSER_COLUMN_MAP[parser] ?? DEFAULT_COLUMNS;
}

/** Get the union of columns for an aggregate folder view (mixed parsers). */
export function getColumnsForAggregate(parsers: ParserKind[]): ColumnId[] {
  const unionSet = new Set<ColumnId>(["severity", "message", "filePath"]);
  for (const parser of parsers) {
    for (const col of getColumnsForParser(parser)) {
      unionSet.add(col);
    }
  }
  // Return in canonical order (ALL_COLUMNS order)
  return ALL_COLUMNS.filter((c) => unionSet.has(c.id)).map((c) => c.id);
}

/**
 * Apply a user-specified column order to the active column set.
 * Filters the user order to only include columns that are active (parser-relevant).
 * Any active columns not in the user order are appended at the end.
 */
export function applyColumnOrder(
  activeColumns: ColumnId[],
  userOrder: ColumnId[] | null
): ColumnId[] {
  if (!userOrder) return activeColumns;
  const activeSet = new Set(activeColumns);
  // Start with user-ordered columns that are active
  const ordered = userOrder.filter((id) => activeSet.has(id));
  // Append any active columns not in user order
  for (const id of activeColumns) {
    if (!ordered.includes(id)) ordered.push(id);
  }
  return ordered;
}

/**
 * Filter active columns by showDetails toggle, returning full ColumnDefinition objects.
 * When showDetails is off, only non-detail columns (severity, message) are returned.
 */
export function getVisibleColumns(
  activeColumns: ColumnId[],
  showDetails: boolean
): ColumnDefinition[] {
  const result: ColumnDefinition[] = [];
  for (const id of activeColumns) {
    const def = COLUMN_BY_ID.get(id);
    if (!def) continue;
    if (def.isDetail && !showDetails) continue;
    result.push(def);
  }
  return result;
}

/**
 * Build a CSS grid-template-columns string from visible column definitions.
 * Uses width overrides from user preferences when available, otherwise defaults.
 */
export function buildGridTemplateColumns(
  columns: ColumnDefinition[],
  widthOverrides?: Record<string, number>
): string {
  return columns
    .map((c) => {
      const w = widthOverrides?.[c.id] ?? c.defaultWidth;
      return `${w}px`;
    })
    .join(" ");
}

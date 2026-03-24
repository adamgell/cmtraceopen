import type { LogEntry, ParserKind } from "../types/log";

/** Unique identifier for each possible log viewer column. */
export type ColumnId =
  | "lineNumber"
  | "message"
  | "component"
  | "dateTime"
  | "thread"
  | "sourceFile"
  | "filePath";

/** Static definition for a column — label, width, and how to read data from a LogEntry. */
export interface ColumnDefinition {
  id: ColumnId;
  label: string;
  /** CSS grid column width: "180px" or "minmax(0, 1fr)" */
  width: string;
  /** True only for the message column (takes remaining space). */
  isFlex: boolean;
  /** True = hidden when showDetails is off. Only "message" is false. */
  isDetail: boolean;
  /**
   * Read the display value from a LogEntry.
   * Returns null when the field is not populated by the parser.
   * Note: "dateTime" uses formatLogEntryTimestamp() instead of this accessor,
   * and "message" has special rich rendering — both are handled in the view layer.
   */
  accessor: (entry: LogEntry) => string | number | null;
}

/** Ordered catalog of every possible column. Rendering order follows this array. */
export const ALL_COLUMNS: readonly ColumnDefinition[] = [
  {
    id: "lineNumber",
    label: "#",
    width: "60px",
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.lineNumber,
  },
  {
    id: "message",
    label: "Log Text",
    width: "minmax(0, 1fr)",
    isFlex: true,
    isDetail: false,
    accessor: (e) => e.message,
  },
  {
    id: "component",
    label: "Component",
    width: "180px",
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.component,
  },
  {
    id: "dateTime",
    label: "Date/Time",
    width: "200px",
    isFlex: false,
    isDetail: true,
    accessor: () => null, // handled via formatLogEntryTimestamp() in view layer
  },
  {
    id: "thread",
    label: "Thread",
    width: "120px",
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.threadDisplay,
  },
  {
    id: "sourceFile",
    label: "Source",
    width: "160px",
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.sourceFile,
  },
  {
    id: "filePath",
    label: "File",
    width: "180px",
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.filePath.split(/[\\/]/).pop() ?? e.filePath,
  },
];

/** Lookup from ColumnId to its definition for O(1) access. */
const COLUMN_BY_ID = new Map<ColumnId, ColumnDefinition>(
  ALL_COLUMNS.map((c) => [c.id, c])
);

/** Which columns each parser populates (in display order). */
const PARSER_COLUMN_MAP: Record<ParserKind, ColumnId[]> = {
  ccm: ["message", "component", "dateTime", "thread", "sourceFile"],
  simple: ["message", "component", "dateTime", "thread"],
  dism: ["message", "component", "dateTime"],
  panther: ["message", "component", "dateTime"],
  cbs: ["message", "component", "dateTime"],
  reportingEvents: ["message", "component", "dateTime"],
  timestamped: ["message", "dateTime"],
  plain: ["message"],
};

/** Default columns used before any file is loaded. Matches legacy hardcoded layout. */
export const DEFAULT_COLUMNS: ColumnId[] = [
  "message",
  "component",
  "dateTime",
  "thread",
];

/** Get the columns relevant to a single parser. */
export function getColumnsForParser(parser: ParserKind): ColumnId[] {
  return PARSER_COLUMN_MAP[parser] ?? DEFAULT_COLUMNS;
}

/** Get the union of columns for an aggregate folder view (mixed parsers). */
export function getColumnsForAggregate(parsers: ParserKind[]): ColumnId[] {
  const unionSet = new Set<ColumnId>(["message", "filePath"]);
  for (const parser of parsers) {
    for (const col of getColumnsForParser(parser)) {
      unionSet.add(col);
    }
  }
  // Return in canonical order (ALL_COLUMNS order)
  return ALL_COLUMNS.filter((c) => unionSet.has(c.id)).map((c) => c.id);
}

/**
 * Filter active columns by showDetails toggle, returning full ColumnDefinition objects.
 * When showDetails is off, only non-detail columns (message) are returned.
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

/** Build a CSS grid-template-columns string from visible column definitions. */
export function buildGridTemplateColumns(
  columns: ColumnDefinition[]
): string {
  return columns.map((c) => c.width).join(" ");
}

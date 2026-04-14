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
  | "clientIp"
  | "serverIp"
  | "hostName"
  | "macAddress"
  | "httpMethod"
  | "uri"
  | "statusCode"
  | "timeTakenMs"
  | "userAgent"
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
    id: "clientIp",
    label: "Client IP",
    defaultWidth: 140,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.clientIp ?? null,
  },
  {
    id: "serverIp",
    label: "Server IP",
    defaultWidth: 140,
    minWidth: 80,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.serverIp ?? null,
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
    id: "httpMethod",
    label: "Method",
    defaultWidth: 100,
    minWidth: 70,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.httpMethod ?? null,
  },
  {
    id: "uri",
    label: "URI",
    defaultWidth: 280,
    minWidth: 120,
    isFlex: false,
    isDetail: true,
    accessor: (e) =>
      e.uriStem
        ? e.uriQuery
          ? `${e.uriStem}?${e.uriQuery}`
          : e.uriStem
        : null,
  },
  {
    id: "statusCode",
    label: "Status",
    defaultWidth: 90,
    minWidth: 60,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.statusCode ?? null,
  },
  {
    id: "timeTakenMs",
    label: "Time (ms)",
    defaultWidth: 110,
    minWidth: 70,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.timeTakenMs ?? null,
  },
  {
    id: "userAgent",
    label: "User Agent",
    defaultWidth: 260,
    minWidth: 120,
    isFlex: false,
    isDetail: true,
    accessor: (e) => e.userAgent ?? null,
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
  iisW3c: ["severity", "dateTime", "message", "httpMethod", "uri", "statusCode", "clientIp", "timeTakenMs", "serverIp", "userAgent"],
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
  patchMyPcDetection: ["severity", "dateTime", "message", "component", "hostName", "operationName"],
  registry: ["message"],
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
// ── Auto-fit measurement ─────────────────────────────────────────────────────

/** Singleton canvas context for measuring text width without DOM layout. */
let _measureCtx: CanvasRenderingContext2D | null = null;
function getMeasureCtx(): CanvasRenderingContext2D | null {
  if (!_measureCtx) {
    const canvas = document.createElement("canvas");
    _measureCtx = canvas.getContext("2d");
  }
  return _measureCtx;
}

export function measureTextWidth(text: string, font: string): number {
  const ctx = getMeasureCtx();
  if (!ctx) return text.length * 8;
  ctx.font = font;
  return ctx.measureText(text).width;
}

const CELL_PAD = 10;   // 4px left + 4px right cell padding + 2px buffer
const HEADER_PAD = 24; // extra room for the resize grip
/** Hard cap to prevent absurdly wide columns (e.g., 2000-char log messages). */
const MAX_AUTOFIT_WIDTH = 1200;

/**
 * Calculate the auto-fit width for a column given the current display entries.
 * - severity: returns defaultWidth (renders a colored dot, not text)
 * - dateTime: uses a fixed representative timestamp string (view layer formats it)
 * - all others: two-pass approach —
 *     Pass 1 (O(n), no canvas): find the max string length across ALL entries
 *     Pass 2 (O(k), canvas): measure only strings within 90% of the max length
 *   This ensures the widest entry is always found regardless of how large the log is,
 *   while keeping canvas calls to a minimum.
 */
export function calcAutoFitWidth(
  col: ColumnDefinition,
  entries: readonly LogEntry[],
  contentFont: string,
  headerFont: string
): number {
  if (col.id === "severity") return col.defaultWidth;

  // The message column contains arbitrarily long content (JSON blobs, stack traces, etc.).
  // Auto-fitting it just pushes everything off-screen — keep its current/default width.
  if (col.id === "message") return col.defaultWidth;

  if (col.id === "dateTime") {
    // Representative sample matching the widest output of formatLogEntryTimestamp().
    // Update this if the display format changes (see src/lib/date-time-format.ts).
    const sample = "2024-01-01 00:00:00.000";
    return Math.ceil(Math.max(measureTextWidth(sample, contentFont) + CELL_PAD, col.minWidth));
  }

  const headerW = measureTextWidth(col.label, headerFont) + HEADER_PAD;

  // Pass 1: find the longest string length (cheap — no canvas)
  let maxLen = 0;
  for (const entry of entries) {
    const val = col.accessor(entry);
    if (val == null) continue;
    const len = String(val).length;
    if (len > maxLen) maxLen = len;
  }

  // No data found — use defaultWidth so we never shrink an empty column below its designed size
  if (maxLen === 0) return Math.ceil(Math.max(headerW, col.defaultWidth));

  // Pass 2: canvas-measure only strings ≥ 90% of max length
  const threshold = maxLen * 0.9;
  let maxContent = 0;
  for (const entry of entries) {
    const val = col.accessor(entry);
    if (val == null) continue;
    const text = String(val);
    if (text.length < threshold) continue;
    const w = measureTextWidth(text, contentFont);
    if (w > maxContent) maxContent = w;
  }

  return Math.min(
    MAX_AUTOFIT_WIDTH,
    Math.ceil(Math.max(headerW, maxContent + CELL_PAD, col.minWidth)),
  );
}

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

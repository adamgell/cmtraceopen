import type { LogEntry } from "../types/log";

// ── Types ─────────────────────────────────────────────────────────────

export interface DiffSource {
  filePath: string;
  label: string;
  startTime?: number; // epoch ms, for time-range mode
  endTime?: number; // epoch ms, for time-range mode
}

export interface DiffState {
  mode: "two-file" | "time-range";
  sourceA: DiffSource;
  sourceB: DiffSource;
  displayMode: "side-by-side" | "unified";
  entriesA: LogEntry[];
  entriesB: LogEntry[];
  commonKeys: Set<string>;
  onlyAKeys: Set<string>;
  onlyBKeys: Set<string>;
  entryClassification: Map<number, "common" | "only-a" | "only-b">;
  stats: DiffStats;
}

export interface DiffStats {
  common: number;
  onlyA: number;
  onlyB: number;
}

export type EntryClassification = "common" | "only-a" | "only-b";

// ── Normalization ─────────────────────────────────────────────────────

const GUID_RE =
  /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g;
const ISO_TS_RE =
  /\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g;
const COMMON_TS_RE =
  /\d{1,2}\/\d{1,2}\/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?/gi;
const LONG_NUM_RE = /\b\d{5,}\b/g;

/**
 * Normalize a log message for fuzzy comparison.
 * Replaces GUIDs, timestamps, and long numbers with placeholders,
 * then lowercases and trims.
 */
export function normalizeMessage(message: string): string {
  return message
    .replace(GUID_RE, "{GUID}")
    .replace(ISO_TS_RE, "{TS}")
    .replace(COMMON_TS_RE, "{TS}")
    .replace(LONG_NUM_RE, "{NUM}")
    .toLowerCase()
    .trim();
}

/**
 * Generate a pattern key for a log entry.
 * Combines normalized message, component, and severity into a single string.
 */
export function patternKey(entry: LogEntry): string {
  const normalizedMsg = normalizeMessage(entry.message);
  const component = (entry.component ?? "").toLowerCase();
  const severity = entry.severity.toLowerCase();
  return `${severity}|${component}|${normalizedMsg}`;
}

// ── Classification ────────────────────────────────────────────────────

/**
 * Build a map of pattern key → entry IDs for a list of entries.
 */
function buildPatternMap(entries: LogEntry[]): Map<string, number[]> {
  const map = new Map<string, number[]>();
  for (const entry of entries) {
    const key = patternKey(entry);
    const existing = map.get(key);
    if (existing) {
      existing.push(entry.id);
    } else {
      map.set(key, [entry.id]);
    }
  }
  return map;
}

/**
 * Classify entries from two sources into common, only-A, and only-B.
 */
export function classifyEntries(
  entriesA: LogEntry[],
  entriesB: LogEntry[],
): {
  commonKeys: Set<string>;
  onlyAKeys: Set<string>;
  onlyBKeys: Set<string>;
  entryClassification: Map<number, EntryClassification>;
  stats: DiffStats;
} {
  const mapA = buildPatternMap(entriesA);
  const mapB = buildPatternMap(entriesB);

  const commonKeys = new Set<string>();
  const onlyAKeys = new Set<string>();
  const onlyBKeys = new Set<string>();

  // Classify keys from A
  for (const key of mapA.keys()) {
    if (mapB.has(key)) {
      commonKeys.add(key);
    } else {
      onlyAKeys.add(key);
    }
  }

  // Find keys only in B
  for (const key of mapB.keys()) {
    if (!mapA.has(key)) {
      onlyBKeys.add(key);
    }
  }

  // Build per-entry classification
  const entryClassification = new Map<number, EntryClassification>();

  for (const [key, ids] of mapA) {
    const cls: EntryClassification = commonKeys.has(key) ? "common" : "only-a";
    for (const id of ids) {
      entryClassification.set(id, cls);
    }
  }

  for (const [key, ids] of mapB) {
    const cls: EntryClassification = commonKeys.has(key) ? "common" : "only-b";
    for (const id of ids) {
      entryClassification.set(id, cls);
    }
  }

  return {
    commonKeys,
    onlyAKeys,
    onlyBKeys,
    entryClassification,
    stats: {
      common: commonKeys.size,
      onlyA: onlyAKeys.size,
      onlyB: onlyBKeys.size,
    },
  };
}

/**
 * Filter entries by time range (for time-range diff mode).
 */
export function filterByTimeRange(
  entries: LogEntry[],
  startTime: number,
  endTime: number,
): LogEntry[] {
  return entries.filter(
    (e) =>
      e.timestamp != null && e.timestamp >= startTime && e.timestamp <= endTime,
  );
}

/**
 * Get the basename of a file path.
 */
export function diffFileBaseName(filePath: string): string {
  return filePath.split(/[\\/]/).pop() ?? filePath;
}

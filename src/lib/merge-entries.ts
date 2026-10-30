import type { LogEntry, LogFormat } from "../types/log";
import { themeSeverityPalettes } from "./themes/palettes";

/** Default merge palette (light theme). Consumers should prefer the per-theme
 *  `severityPalette.mergeColors` when a theme context is available. */
export const MERGE_FILE_COLORS = themeSeverityPalettes.light.mergeColors;

export interface MergedTabState {
  sourceFilePaths: string[];
  colorAssignments: Record<string, string>;
  fileVisibility: Record<string, boolean>;
  mergedEntries: LogEntry[];
  cacheKey: string;
  /**
   * Where to start tailing each source file, captured from its tab snapshot
   * when the merged tab was created. Fixed for the life of the merged tab so
   * the watcher does not restart (and re-read lines) on every tail batch.
   */
  sourceTails?: Record<string, MergedSourceTail>;
  /**
   * Highest physical line merged from each tailed source. A watcher restart
   * re-reads from the `sourceTails` offset, so lines at or below this cursor
   * are replays and are dropped. A truncation/rotation reset restarts it.
   */
  tailCursors?: Record<string, number>;
}

export interface MergedSourceTail {
  formatDetected: LogFormat;
  byteOffset: number;
  totalLines: number;
}

export interface CorrelatedEntry {
  entry: LogEntry;
  deltaMs: number;
  fileColor: string;
}

export function assignFileColors(
  filePaths: string[],
  palette: readonly string[] = MERGE_FILE_COLORS
): Record<string, string> {
  const assignments: Record<string, string> = {};
  for (let i = 0; i < filePaths.length; i++) {
    assignments[filePaths[i]] = palette[i % palette.length];
  }
  return assignments;
}

export function buildMergeCacheKey(
  filePaths: string[],
  entryCounts: Record<string, number>
): string {
  return filePaths
    .map((fp) => `${fp}:${entryCounts[fp] ?? 0}`)
    .sort()
    .join("|");
}

/**
 * The time each entry of one file should sort at when merged with other files.
 *
 * Untimestamped lines (stack frames, wrapped output) take the timestamp of the
 * timestamped line above them in the same file; lines before a file's first
 * timestamp take the first one. A file with no timestamps at all stays null,
 * so it is still placed after every timestamped entry.
 */
function effectiveTimestamps(fileEntries: LogEntry[]): (number | null)[] {
  const ordered = fileEntries
    .map((entry, index) => ({ entry, index }))
    .sort((a, b) => a.entry.lineNumber - b.entry.lineNumber);
  const keys: (number | null)[] = new Array(fileEntries.length).fill(null);

  let carried: number | null = null;
  const leading: number[] = [];
  for (const { entry, index } of ordered) {
    if (entry.timestamp != null) {
      carried = entry.timestamp;
      for (const leadingIndex of leading) keys[leadingIndex] = carried;
      leading.length = 0;
      keys[index] = carried;
    } else if (carried != null) {
      keys[index] = carried;
    } else {
      leading.push(index);
    }
  }
  return keys;
}

/** Merge order: sort time (untimestamped files last), then file, then line. */
export function compareMergedEntries(a: LogEntry, b: LogEntry): number {
  const at = a.mergeTimestamp ?? null;
  const bt = b.mergeTimestamp ?? null;
  if (at == null || bt == null) {
    if (at != null) return -1;
    if (bt != null) return 1;
  } else if (at !== bt) {
    return at - bt;
  }
  const fileCmp = a.filePath.localeCompare(b.filePath);
  if (fileCmp !== 0) return fileCmp;
  return a.lineNumber - b.lineNumber;
}

export function mergeEntries(
  entriesByFile: Record<string, LogEntry[]>
): LogEntry[] {
  const allEntries: LogEntry[] = [];
  for (const fileEntries of Object.values(entriesByFile)) {
    const keys = effectiveTimestamps(fileEntries);
    fileEntries.forEach((entry, index) => {
      allEntries.push({ ...entry, mergeTimestamp: keys[index] });
    });
  }

  allEntries.sort(compareMergedEntries);

  // Reassign IDs to be globally unique across merged files
  for (let i = 0; i < allEntries.length; i++) {
    allEntries[i].id = i;
  }

  return allEntries;
}

/**
 * Replace one file's entries in an already-merged list, keeping merge order.
 *
 * `fileEntries` is the file's complete new set (ids already assigned). Its
 * sort times are recomputed as a whole, so a tailed continuation line picks up
 * the timestamp above it even when that line arrived in an earlier batch.
 * Other files' entries keep their object identity, and the result is built
 * with one linear merge rather than re-sorting the whole timeline.
 */
export function replaceFileInMerge(
  merged: LogEntry[],
  filePath: string,
  fileEntries: LogEntry[]
): LogEntry[] {
  const keys = effectiveTimestamps(fileEntries);
  const keyed = fileEntries
    .map((entry, index) =>
      entry.mergeTimestamp === keys[index] ? entry : { ...entry, mergeTimestamp: keys[index] }
    )
    .sort(compareMergedEntries);
  const others = merged.filter((entry) => entry.filePath !== filePath);

  const result: LogEntry[] = new Array(others.length + keyed.length);
  let i = 0;
  let j = 0;
  let k = 0;
  while (i < others.length && j < keyed.length) {
    result[k++] = compareMergedEntries(others[i], keyed[j]) <= 0 ? others[i++] : keyed[j++];
  }
  while (i < others.length) result[k++] = others[i++];
  while (j < keyed.length) result[k++] = keyed[j++];
  return result;
}

/** Last physical line an entry covers (multi-line records span several). */
export function entryEndLine(entry: LogEntry): number {
  return entry.lineNumber + entry.message.split("\n").length - 1;
}

/**
 * Highest physical line covered by `entries`, never below `floor`. A loop
 * rather than `Math.max(...spread)`: a reset batch is a whole file re-read and
 * can exceed the engine's argument limit.
 */
export function maxEntryEndLine(entries: LogEntry[], floor: number): number {
  let max = floor;
  for (const entry of entries) {
    const end = entryEndLine(entry);
    if (end > max) max = end;
  }
  return max;
}

export function filterByVisibility(
  entries: LogEntry[],
  visibility: Record<string, boolean>
): LogEntry[] {
  return entries.filter((e) => visibility[e.filePath] !== false);
}

export function countEntriesByFile(
  entries: LogEntry[]
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const entry of entries) {
    counts[entry.filePath] = (counts[entry.filePath] ?? 0) + 1;
  }
  return counts;
}

/** Sort key of a merged entry; falls back to `timestamp` for unmerged input. */
function sortKey(entry: LogEntry): number | null {
  return entry.mergeTimestamp !== undefined ? entry.mergeTimestamp : entry.timestamp;
}

export function findCorrelatedEntries(
  entries: LogEntry[],
  targetEntry: LogEntry,
  windowMs: number,
  colorAssignments: Record<string, string>
): CorrelatedEntry[] {
  if (targetEntry.timestamp == null) return [];

  const targetTs = targetEntry.timestamp;
  const results: CorrelatedEntry[] = [];

  // `entries` is in merge order, so the sort key is non-decreasing and every
  // null key (files with no timestamps) is in a suffix. Keep the binary
  // search and scan inside the keyed prefix.
  let prefixLo = 0;
  let prefixHi = entries.length;
  while (prefixLo < prefixHi) {
    const mid = (prefixLo + prefixHi) >>> 1;
    if (sortKey(entries[mid]) == null) {
      prefixHi = mid;
    } else {
      prefixLo = mid + 1;
    }
  }
  const timestampedEnd = prefixLo;
  const windowStart = targetTs - windowMs;
  const windowEnd = targetTs + windowMs;
  let lo = 0;
  let hi = timestampedEnd;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    const key = sortKey(entries[mid]);
    if (key == null || key >= windowStart) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }

  // Scan from window start to window end
  for (let i = lo; i < timestampedEnd; i++) {
    const entry = entries[i];
    const key = sortKey(entry);
    if (key == null || key > windowEnd) break;
    // Continuation lines have no time of their own to report a delta for.
    const timestamp = entry.timestamp;
    if (timestamp == null) continue;
    if (entry.filePath === targetEntry.filePath) continue;
    if (entry.id === targetEntry.id) continue;

    results.push({
      entry,
      deltaMs: timestamp - targetTs,
      fileColor: colorAssignments[entry.filePath] ?? "#888",
    });
  }

  results.sort((a, b) => Math.abs(a.deltaMs) - Math.abs(b.deltaMs));
  return results;
}

export function fileBaseName(filePath: string): string {
  return filePath.split(/[\\/]/).pop() ?? filePath;
}

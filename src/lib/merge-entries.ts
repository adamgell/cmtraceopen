import type { LogEntry } from "../types/log";
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

export function mergeEntries(
  entriesByFile: Record<string, LogEntry[]>
): LogEntry[] {
  const allEntries = Object.values(entriesByFile).flat();

  allEntries.sort((a, b) => {
    if (a.timestamp == null || b.timestamp == null) {
      if (a.timestamp != null) return -1;
      if (b.timestamp != null) return 1;
    } else if (a.timestamp !== b.timestamp) {
      return a.timestamp - b.timestamp;
    }
    const fileCmp = a.filePath.localeCompare(b.filePath);
    if (fileCmp !== 0) return fileCmp;
    return a.lineNumber - b.lineNumber;
  });

  // Reassign IDs to be globally unique across merged files
  for (let i = 0; i < allEntries.length; i++) {
    allEntries[i] = { ...allEntries[i], id: i };
  }

  return allEntries;
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

export function findCorrelatedEntries(
  entries: LogEntry[],
  targetEntry: LogEntry,
  windowMs: number,
  colorAssignments: Record<string, string>
): CorrelatedEntry[] {
  if (targetEntry.timestamp == null) return [];

  const targetTs = targetEntry.timestamp;
  const results: CorrelatedEntry[] = [];

  // Null-timestamp entries sort after timestamped entries. Keep the binary
  // search and scan inside the timestamped prefix.
  let prefixLo = 0;
  let prefixHi = entries.length;
  while (prefixLo < prefixHi) {
    const mid = (prefixLo + prefixHi) >>> 1;
    if (entries[mid].timestamp == null) {
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
    const timestamp = entries[mid].timestamp;
    if (timestamp == null || timestamp >= windowStart) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }

  // Scan from window start to window end
  for (let i = lo; i < timestampedEnd; i++) {
    const entry = entries[i];
    const timestamp = entry.timestamp;
    if (timestamp == null) break;
    if (timestamp > windowEnd) break;
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

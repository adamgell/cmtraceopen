import type { LogEntry } from "../types/log";

export const MERGE_FILE_COLORS = [
  "#2563eb", "#dc2626", "#16a34a", "#9333ea",
  "#ea580c", "#0891b2", "#c026d3", "#854d0e",
];

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
  filePaths: string[]
): Record<string, string> {
  const assignments: Record<string, string> = {};
  for (let i = 0; i < filePaths.length; i++) {
    assignments[filePaths[i]] = MERGE_FILE_COLORS[i % MERGE_FILE_COLORS.length];
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
  const allTimestamped: LogEntry[] = [];

  for (const entries of Object.values(entriesByFile)) {
    for (const entry of entries) {
      if (entry.timestamp != null) {
        allTimestamped.push(entry);
      }
    }
  }

  allTimestamped.sort((a, b) => {
    if (a.timestamp !== b.timestamp) return a.timestamp! - b.timestamp!;
    const fileCmp = a.filePath.localeCompare(b.filePath);
    if (fileCmp !== 0) return fileCmp;
    return a.lineNumber - b.lineNumber;
  });

  return allTimestamped;
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

  for (const entry of entries) {
    if (entry.filePath === targetEntry.filePath) continue;
    if (entry.timestamp == null) continue;

    const delta = entry.timestamp - targetTs;
    if (Math.abs(delta) <= windowMs) {
      results.push({
        entry,
        deltaMs: delta,
        fileColor: colorAssignments[entry.filePath] ?? "#888",
      });
    }
  }

  results.sort((a, b) => Math.abs(a.deltaMs) - Math.abs(b.deltaMs));
  return results;
}

export function fileBaseName(filePath: string): string {
  return filePath.split(/[\\/]/).pop() ?? filePath;
}

import type { LogEntry, LogFormat, ParserSelectionInfo } from "../types/log";
import type { ColumnId } from "./column-config";

/**
 * Module-level in-memory cache of parsed tab state. Lives outside Zustand
 * so storing/retrieving snapshots doesn't trigger re-renders.
 *
 * Extracted into its own module so both `log-store` and `ui-store` can
 * import the helpers without going through each other (the two stores
 * already cross-import for other reasons; keeping the snapshot cache
 * standalone trims one source of cyclic-init risk).
 */

export type SourceOpenMode =
  | "single-file"
  | "aggregate-folder"
  | "merged"
  | "diff"
  | null;

/** Snapshot of parsed file state cached for instant tab restoration. */
export interface TabEntrySnapshot {
  entries: LogEntry[];
  formatDetected: LogFormat | null;
  parserSelection: ParserSelectionInfo | null;
  totalLines: number;
  byteOffset: number;
  selectedSourceFilePath: string | null;
  sourceOpenMode: SourceOpenMode;
  activeColumns: ColumnId[];
}

const TAB_CACHE_MAX_SIZE = 30;

const tabEntryCache = new Map<string, TabEntrySnapshot>();

export function getCachedTabSnapshot(filePath: string): TabEntrySnapshot | undefined {
  return tabEntryCache.get(filePath);
}

export function setCachedTabSnapshot(filePath: string, snapshot: TabEntrySnapshot): void {
  if (tabEntryCache.size >= TAB_CACHE_MAX_SIZE && !tabEntryCache.has(filePath)) {
    const oldestKey = tabEntryCache.keys().next().value;
    if (oldestKey) tabEntryCache.delete(oldestKey);
  }
  tabEntryCache.set(filePath, snapshot);
}

export function clearCachedTabSnapshot(filePath: string): void {
  tabEntryCache.delete(filePath);
}

export function clearAllTabSnapshots(): void {
  tabEntryCache.clear();
}

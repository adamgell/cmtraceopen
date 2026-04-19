import type { LogEntry } from "../../types/log";

/**
 * Abstraction that lets LogListView render entries from either the log-store
 * (normal log view) or the timeline-store (timeline mode). All methods are
 * hooks — subscribe inside selectors so LogListView re-renders on change.
 *
 * The optional methods give the timeline mode a way to restrict the rendered
 * entries to a time range and highlight a sub-range. Log view mode omits them.
 */
export interface LogListDataSource {
  useEntries(): LogEntry[];
  useSelectedId(): number | null;
  useHighlightText(): string;
  useHighlightCaseSensitive(): boolean;
  useIsPaused(): boolean;
  useFindMatchIds(): Set<number> | null;

  selectEntry(id: number | null): void;

  useExternalFilterRange?(): [number, number] | null;
  useHighlightedRange?(): [number, number] | null;
}

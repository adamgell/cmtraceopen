import { useMemo } from "react";
import type { LogListDataSource } from "../log-view/log-list-data-source";
import { useTimelineStore } from "../../stores/timeline-store";
import { useTimelineEntries } from "./hooks/useTimelineEntries";
import type { LogEntry } from "../../types/log";

/**
 * Data source for LogListView when running in the unified timeline's
 * log-stream pane. Pulls the current page of entries from the timeline
 * store, filters down to the log-entry subset (drops IME events), and
 * exposes the brush range as the external filter range.
 */
export const timelineLogListDataSource: LogListDataSource = {
  useEntries(): LogEntry[] {
    const entries = useTimelineEntries(0);
    return useMemo(
      () =>
        entries
          .filter((e): e is Extract<typeof e, { kind: "log" }> => e.kind === "log")
          .map((e) => ({
            ...e.entry,
            // Backend's single-line materializer reuses id=0 for every entry;
            // synthesize a stable cross-source unique id so React keys work.
            id: e.sourceIdx * 10_000_000 + e.entry.lineNumber,
          })),
      [entries],
    );
  },
  useSelectedId() {
    // Timeline doesn't have per-row selection v1; the chip and detail drive state.
    return useTimelineStore((s) => s.selectedIncidentId);
  },
  useHighlightText() {
    return "";
  },
  useHighlightCaseSensitive() {
    return false;
  },
  useIsPaused() {
    return true;
  },
  useFindMatchIds() {
    return null;
  },
  selectEntry(_id) {
    /* no-op in v1 */
    void _id;
  },
  useExternalFilterRange() {
    return useTimelineStore((s) => s.brushRange);
  },
  useHighlightedRange() {
    const sel = useTimelineStore((s) => s.selectedIncidentId);
    const bundle = useTimelineStore((s) => s.bundle);
    if (sel == null) return null;
    const inc = bundle?.incidents.find((i) => i.id === sel);
    return inc ? [inc.tsStartMs, inc.tsEndMs] : null;
  },
};

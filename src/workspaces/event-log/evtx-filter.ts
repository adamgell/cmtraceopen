/**
 * Pure filtering helpers for the event log view.
 *
 * Deliberately separate from `evtx-store.ts`, which subscribes to Tauri events at module scope.
 * Importing the store from a test fires that subscription, so anything worth unit-testing lives
 * here where it can be imported without a Tauri runtime.
 */
import type { EvtxLevel, EvtxRecord } from "./types";

/**
 * Parses the Event ID filter box into a set, or null when it constrains nothing.
 *
 * Accepts comma or space separated ids and inclusive `low-high` ranges, matching what operators
 * expect from the incumbent tools.
 */
export function parseEventIdFilter(raw: string): Set<number> | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  const ids = new Set<number>();
  for (const token of trimmed.split(/[\s,]+/).filter(Boolean)) {
    const range = token.match(/^(\d+)-(\d+)$/);
    if (range) {
      const low = Number(range[1]);
      const high = Number(range[2]);
      const [from, to] = low <= high ? [low, high] : [high, low];
      for (let id = from; id <= to; id += 1) ids.add(id);
      continue;
    }
    const single = Number(token);
    if (Number.isInteger(single)) ids.add(single);
  }
  return ids.size > 0 ? ids : null;
}

/** The subset of store state that decides which records are on screen. */
export interface VisibleRecordsInput {
  records: EvtxRecord[];
  selectedChannels: Set<string>;
  filterLevels: Set<EvtxLevel>;
  filterEventIds: string;
  filterSearch: string;
}

/**
 * The records currently on screen, before sorting.
 *
 * Shared so an export writes exactly what the operator is looking at. Recomputing the predicate at
 * the export site would let the two drift, and an export that quietly differs from the view is
 * worse than no export at all.
 */
export function selectVisibleRecords(input: VisibleRecordsInput): EvtxRecord[] {
  const eventIdSet = parseEventIdFilter(input.filterEventIds);
  const search = input.filterSearch.trim().toLowerCase();
  return input.records.filter((r) => {
    if (!input.selectedChannels.has(r.channel)) return false;
    if (!input.filterLevels.has(r.level)) return false;
    if (eventIdSet && !eventIdSet.has(r.eventId)) return false;
    if (
      search &&
      !r.message.toLowerCase().includes(search) &&
      !r.provider.toLowerCase().includes(search)
    ) {
      return false;
    }
    return true;
  });
}

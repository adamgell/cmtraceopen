/**
 * Pure filtering helpers for the event log view.
 *
 * Deliberately separate from `evtx-store.ts`, which subscribes to Tauri events at module scope.
 * Importing the store from a test fires that subscription, so anything worth unit-testing lives
 * here where it can be imported without a Tauri runtime.
 */
import type { EvtxLevel, EvtxRecord } from "./types";
import { eventDateKey, type EvtxTimeZoneMode } from "./evtx-time";

export type EvtxSortField = "time" | "eventId" | "level" | "provider" | "channel";
export type EvtxSortDirection = "asc" | "desc";

const LEVEL_ORDER: Record<EvtxLevel, number> = {
  Critical: 0,
  Error: 1,
  Warning: 2,
  Information: 3,
  Verbose: 4,
};

export function sortRecords(
  records: readonly EvtxRecord[],
  field: EvtxSortField,
  direction: EvtxSortDirection
): EvtxRecord[] {
  return [...records].sort((a, b) => {
    let comparison = 0;
    switch (field) {
      case "time":
        comparison = a.timestampEpoch - b.timestampEpoch;
        break;
      case "eventId":
        comparison = a.eventId - b.eventId;
        break;
      case "level":
        comparison = LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level];
        break;
      case "provider":
        comparison = a.provider.localeCompare(b.provider);
        break;
      case "channel":
        comparison = a.channel.localeCompare(b.channel);
        break;
    }
    return direction === "asc" ? comparison : -comparison;
  });
}

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
      // Clamped to the range an Event ID can actually occupy. This runs on every keystroke, so
      // "4624-46240000" typed halfway would otherwise build a set of tens of millions on the UI
      // thread and freeze the tab before the operator finished the number.
      if (from > MAX_EVENT_ID) continue;
      for (let id = from; id <= Math.min(to, MAX_EVENT_ID); id += 1) ids.add(id);
      continue;
    }
    const single = Number(token);
    if (Number.isInteger(single)) ids.add(single);
  }
  return ids;
}

/**
 * Largest value a Windows Event ID can hold.
 *
 * The field is 16 bits, so nothing above this can match an event and expanding past it only costs
 * time. Used to bound range expansion rather than to reject input: an operator mid-way through
 * typing a number should see no result, not an error.
 */
const MAX_EVENT_ID = 65535;

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

/** A field the event list can group by. */
export type EvtxGroupField = "level" | "provider" | "channel" | "eventId" | "day";

export const EVTX_GROUP_LABELS: Record<EvtxGroupField, string> = {
  level: "Level",
  provider: "Provider",
  channel: "Channel",
  eventId: "Event ID",
  day: "Day",
};

/** A group header row. */
export interface EvtxGroupRow {
  kind: "group";
  /** Stable identity across renders, built from the whole ancestry so sibling groups never collide. */
  key: string;
  field: EvtxGroupField;
  label: string;
  /** Nesting level, zero for the outermost grouping. */
  depth: number;
  /** Records beneath this header, including those inside nested groups. */
  count: number;
  collapsed: boolean;
}

/** A record row. */
export interface EvtxRecordRow {
  kind: "record";
  record: EvtxRecord;
  depth: number;
}

export type EvtxRow = EvtxGroupRow | EvtxRecordRow;

function groupValue(
  record: EvtxRecord,
  field: EvtxGroupField,
  timeZone: EvtxTimeZoneMode
): string {
  switch (field) {
    case "level":
      return record.level;
    case "provider":
      return record.provider || "(no provider)";
    case "channel":
      return record.channel || "(no channel)";
    case "eventId":
      return String(record.eventId);
    case "day":
      // The same zone the timestamps are displayed in, so an event never appears under a day that
      // disagrees with the time printed beside it.
      return eventDateKey(record.timestampEpoch, timeZone);
  }
}

/**
 * Flattens records into the row list a virtualized list renders.
 *
 * Returns a flat array rather than a tree because the list virtualizes on row index; a tree would
 * have to be flattened on every render anyway.
 *
 * Group order follows `groupBy`, and within the deepest group the incoming record order is
 * preserved, so whatever sort the operator chose still applies inside each group.
 */
export function buildGroupedRows(
  records: EvtxRecord[],
  groupBy: EvtxGroupField[],
  collapsedKeys: ReadonlySet<string>,
  timeZone: EvtxTimeZoneMode = "local"
): EvtxRow[] {
  if (groupBy.length === 0) {
    return records.map((record) => ({ kind: "record", record, depth: 0 }));
  }

  const rows: EvtxRow[] = [];

  const walk = (subset: EvtxRecord[], depth: number, parentKey: string) => {
    if (depth >= groupBy.length) {
      for (const record of subset) {
        rows.push({ kind: "record", record, depth });
      }
      return;
    }

    const field = groupBy[depth];
    // Insertion order is preserved by Map, so groups appear in the order they are first seen,
    // which follows the caller's sort rather than imposing an alphabetical one.
    const buckets = new Map<string, EvtxRecord[]>();
    for (const record of subset) {
      const value = groupValue(record, field, timeZone);
      const bucket = buckets.get(value);
      if (bucket) bucket.push(record);
      else buckets.set(value, [record]);
    }

    for (const [value, bucket] of buckets) {
      // Encoded, so a value containing the delimiters cannot forge another group's ancestry. Two
      // distinct paths sharing a key would make collapsing one collapse the other.
      const key = `${parentKey}/${field}=${encodeURIComponent(value)}`;
      const collapsed = collapsedKeys.has(key);
      rows.push({
        kind: "group",
        key,
        field,
        label: value,
        depth,
        count: bucket.length,
        collapsed,
      });
      if (!collapsed) {
        walk(bucket, depth + 1, key);
      }
    }
  };

  walk(records, 0, "");
  return rows;
}

/** Every group key present for `records` under `groupBy`, for expand-all and collapse-all. */
export function allGroupKeys(
  records: EvtxRecord[],
  groupBy: EvtxGroupField[]
): Set<string> {
  const keys = new Set<string>();
  for (const row of buildGroupedRows(records, groupBy, new Set())) {
    if (row.kind === "group") keys.add(row.key);
  }
  return keys;
}

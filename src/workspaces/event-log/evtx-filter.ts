/**
 * Pure filtering helpers for the event log view.
 *
 * Deliberately separate from `evtx-store.ts`, which subscribes to Tauri events at module scope.
 * Importing the store from a test fires that subscription, so anything worth unit-testing lives
 * here where it can be imported without a Tauri runtime.
 */
import {
  EVTX_TIME_WINDOW_MS,
  type EvtxLevel,
  type EvtxRecord,
  type EvtxTimeWindow,
} from "./types";
import {
  availableColumns,
  columnValue,
  discoverMappedProperties,
  type EvtxColumnId,
} from "./evtx-columns";
import { eventDateKey, type EvtxTimeZoneMode } from "./evtx-time";

/** The six quick-filter grammars supported by the event viewer. */
export type EvtxQuickFilterMode =
  | "oneString"
  | "multipleWords"
  | "multipleStrings"
  | "allWords"
  | "allStrings"
  | "eventIds";

/** Which rendered event columns a quick filter searches. */
export type EvtxQuickFilterScope = "allColumns" | "visibleColumns";

/** Whether matching records are retained or removed. */
export type EvtxQuickFilterAction = "show" | "hide";

/** Interactive filter state shared by local evaluation, persistence, and the UI. */
export interface EvtxQuickFilter {
  mode: EvtxQuickFilterMode;
  query: string;
  scope: EvtxQuickFilterScope;
  action: EvtxQuickFilterAction;
  caseSensitive: boolean;
  /** The next triage lane consumes this flag when it renders match highlights. */
  highlight: boolean;
}


export const DEFAULT_QUICK_FILTER: EvtxQuickFilter = {
  mode: "oneString",
  query: "",
  scope: "allColumns",
  action: "show",
  caseSensitive: false,
  highlight: true,
};
/** Tests the same inclusive lower boundary used by the server's `timediff <=` XPath predicate. */
export function isWithinTimeWindow(
  timestampEpoch: number,
  window: EvtxTimeWindow,
  nowEpoch = Date.now()
): boolean {
  if (window === "all") return true;
  return timestampEpoch >= nowEpoch - EVTX_TIME_WINDOW_MS[window];
}

/**
 * Parses the Event ID filter box into a set, or null when it constrains nothing.
 *
 * Accepts comma or space separated ids and inclusive `low-high` ranges, matching what operators
 * expect from the incumbent tools.
 */
export interface EvtxEventIdSelector {
  kind: "single" | "range";
  id?: number;
  low?: number;
  high?: number;
}

export interface EvtxEventIdSelectorParseResult {
  selectors: EvtxEventIdSelector[];
  invalid: boolean;
}

/** Parses IDs without expanding ranges, for the server-side XPath contract. */
export function parseEventIdSelectors(raw: string): EvtxEventIdSelectorParseResult {
  const trimmed = raw.trim();
  if (!trimmed) return { selectors: [], invalid: false };
  const selectors: EvtxEventIdSelector[] = [];
  let invalid = false;
  for (const token of trimmed.split(/[\s,]+/).filter(Boolean)) {
    const range = token.match(/^(\d+)-(\d+)$/);
    if (range) {
      const low = Number(range[1]);
      const high = Number(range[2]);
      if (
        !Number.isSafeInteger(low) ||
        !Number.isSafeInteger(high) ||
        low > MAX_EVENT_ID ||
        high > MAX_EVENT_ID
      ) {
        invalid = true;
        continue;
      }
      selectors.push({
        kind: "range",
        low: Math.min(low, high),
        high: Math.max(low, high),
      });
      continue;
    }
    if (!/^\d+$/.test(token)) {
      invalid = true;
      continue;
    }
    const id = Number(token);
    if (!Number.isSafeInteger(id) || id > MAX_EVENT_ID) {
      invalid = true;
      continue;
    }
    selectors.push({ kind: "single", id });
  }
  return { selectors, invalid };
}


/**
 * Largest value a Windows Event ID can hold.
 *
 * The field is 16 bits, so nothing above this can match an event and expanding past it only costs
 * time. Used to bound range expansion rather than to reject input: an operator mid-way through
 * typing a number should see no result, not an error.
 */
const MAX_EVENT_ID = 65535;
/**
 * Parses the Event ID filter box into a set, or null when it constrains nothing.
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
      if (from > MAX_EVENT_ID) continue;
      for (let id = from; id <= Math.min(to, MAX_EVENT_ID); id += 1) ids.add(id);
      continue;
    }
    if (!/^\d+$/.test(token)) continue;
    const single = Number(token);
    if (Number.isSafeInteger(single) && single <= MAX_EVENT_ID) ids.add(single);
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
  quickFilter?: EvtxQuickFilter;
  /** The ordered column ids currently shown by the grid. */
  visibleColumns?: readonly EvtxColumnId[];
}

function normalizeText(value: string, caseSensitive: boolean): string {
  return caseSensitive ? value : value.toLocaleLowerCase();
}

function queryParts(query: string, separator: RegExp, caseSensitive: boolean): string[] {
  return query
    .split(separator)
    .map((part) => normalizeText(part.trim(), caseSensitive))
    .filter(Boolean);
}

function searchableValues(
  record: EvtxRecord,
  scope: EvtxQuickFilterScope,
  visibleColumns: readonly EvtxColumnId[] | undefined,
  caseSensitive: boolean
): string[] {
  const columns =
    scope === "visibleColumns" && visibleColumns
      ? visibleColumns
      : availableColumns(discoverMappedProperties([record])).map((column) => column.id);
  const values = columns.map((id) => columnValue(record, id));
  // EventData is the source for mapped/inserted values when no map column exists. It is included in
  // all-columns mode, but never leaks into visible-column matching unless a rendered column carries
  // it.
  if (scope === "allColumns") {
    values.push(...record.eventData.map((field) => field.value));
  }
  return values.map((value) => normalizeText(value, caseSensitive)).filter(Boolean);
}

/** True when a record's quick-filter grammar matches at least one searched value. */
export function matchesQuickFilter(
  record: EvtxRecord,
  quickFilter: EvtxQuickFilter,
  visibleColumns?: readonly EvtxColumnId[]
): boolean {
  const query = quickFilter.query.trim();
  if (!query) return false;

  if (quickFilter.mode === "eventIds") {
    const parsed = parseEventIdSelectors(query);
    if (parsed.invalid || parsed.selectors.length === 0) return false;
    const ids = parseEventIdFilter(query);
    return ids !== null && ids.has(record.eventId);
  }

  const values = searchableValues(
    record,
    quickFilter.scope,
    visibleColumns,
    quickFilter.caseSensitive
  );
  const normalizedQuery = normalizeText(query, quickFilter.caseSensitive);
  const contains = (term: string) => values.some((value) => value.includes(term));

  switch (quickFilter.mode) {
    case "oneString":
      return contains(normalizedQuery);
    case "multipleWords": {
      const words = queryParts(query, /\s+/, quickFilter.caseSensitive);
      return words.some(contains);
    }
    case "multipleStrings": {
      const strings = queryParts(query, /[,;\u000a]+/, quickFilter.caseSensitive);
      return strings.some(contains);
    }
    case "allWords": {
      const words = queryParts(query, /\s+/, quickFilter.caseSensitive);
      return words.every(contains);
    }
    case "allStrings": {
      const strings = queryParts(query, /[,;\u000a]+/, quickFilter.caseSensitive);
      return strings.every(contains);
    }
  }
}

/** A record's final visibility after all filter stages have been evaluated. */
export function recordMatchesVisibleFilter(
  record: EvtxRecord,
  input: Pick<VisibleRecordsInput, "filterEventIds" | "filterSearch" | "filterLevels" | "selectedChannels"> & {
    quickFilter?: EvtxQuickFilter;
    visibleColumns?: readonly EvtxColumnId[];
  }
): boolean {
  if (!input.selectedChannels.has(record.channel)) return false;
  if (!input.filterLevels.has(record.level)) return false;
  const eventIdSet = parseEventIdFilter(input.filterEventIds);
  if (eventIdSet && !eventIdSet.has(record.eventId)) return false;
  const search = input.filterSearch.trim().toLocaleLowerCase();
  if (
    search &&
    !record.message.toLocaleLowerCase().includes(search) &&
    !record.provider.toLocaleLowerCase().includes(search)
  ) {
    return false;
  }

  const quickFilter = input.quickFilter;
  if (!quickFilter || !quickFilter.query.trim()) return true;
  const matched = matchesQuickFilter(record, quickFilter, input.visibleColumns);
  return quickFilter.action === "hide" ? !matched : matched;
}

/**
 * The records currently on screen, before sorting.
 *
 * Shared so an export writes exactly what the operator is looking at. Recomputing the predicate at
 * the export site would let the two drift, and an export that quietly differs from the view is
 * worse than no export at all.
 */
export function selectVisibleRecords(input: VisibleRecordsInput): EvtxRecord[] {
  return input.records.filter((record) => recordMatchesVisibleFilter(record, input));
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

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

export type EvtxSortField = "time" | "eventId" | "level" | "provider" | "channel";
export type EvtxSortDirection = "asc" | "desc";

/** Delimiters accepted by the multi-string quick-filter grammar. */
export const EVTX_STRING_QUERY_SEPARATOR = /[,;\r\n]+/;

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

export const EVTX_QUICK_FILTER_MODES: readonly EvtxQuickFilterMode[] = [
  "oneString",
  "multipleWords",
  "multipleStrings",
  "allWords",
  "allStrings",
  "eventIds",
];
export const EVTX_QUICK_FILTER_SCOPES: readonly EvtxQuickFilterScope[] = [
  "allColumns",
  "visibleColumns",
];
export const EVTX_QUICK_FILTER_ACTIONS: readonly EvtxQuickFilterAction[] = [
  "show",
  "hide",
];
/** Interactive filter state shared by local evaluation, persistence, and the UI. */
export interface EvtxQuickFilter {
  mode: EvtxQuickFilterMode;
  query: string;
  scope: EvtxQuickFilterScope;
  action: EvtxQuickFilterAction;
  caseSensitive: boolean;
  highlight: boolean;
}

/** Criteria that can be compiled into the backend query before records load. */
export interface EvtxBeforeLoadCriteria {
  levels: EvtxLevel[];
  eventIds: string;
  timeWindow: EvtxTimeWindow;
  selectedChannels?: string[];
}

/** Criteria evaluated synchronously by the shared local visible selector as records arrive/render. */
export interface EvtxOnLoadCriteria {
  search: string;
  quickFilter: EvtxQuickFilter;
}

/** Criteria applied only after records are loaded for presentation. */
export interface EvtxAfterLoadCriteria {
  groupBy: EvtxGroupField[];
}

/** Single typed contract shared by server derivation, local matching, and persistence. */
export interface EvtxFilterModel {
  beforeLoad: EvtxBeforeLoadCriteria;
  onLoad: EvtxOnLoadCriteria;
  afterLoad: EvtxAfterLoadCriteria;
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

/** One parsed Event ID or inclusive range from the filter grammar. */
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
function eventIdMatchesSelectors(eventId: number, parsed: EvtxEventIdSelectorParseResult): boolean {
  return !parsed.invalid && parsed.selectors.some((selector) =>
    selector.kind === "single"
      ? selector.id === eventId
      : eventId >= (selector.low ?? 0) && eventId <= (selector.high ?? 0)
  );
}



/**
 * Largest unsigned 32-bit Event ID accepted by the Event Log query contract. Ranges are matched
 * without expansion, so valid IDs are not rejected due to a 16-bit assumption.
 */
const MAX_EVENT_ID = 0xffffffff;
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
  /** Timezone used by the rendered timestamp column. */
  timeZoneMode?: EvtxTimeZoneMode;
  /** Before-load time criterion retained for local/file evaluation. */
  timeWindow?: EvtxTimeWindow;
  /** Injectable clock for deterministic boundary tests; production uses Date.now(). */
  nowEpoch?: number;
  /** Parsed once by selectVisibleRecords for the whole visible-record pass. */
  eventIdSelectors?: EvtxEventIdSelectorParseResult;
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
  caseSensitive: boolean,
  timeZoneMode: EvtxTimeZoneMode,
  discoveredColumns?: readonly EvtxColumnId[]
): string[] {
  const columns =
    scope === "visibleColumns" && visibleColumns
      ? visibleColumns
      : discoveredColumns ??
        availableColumns(discoverMappedProperties([record])).map((column) => column.id);
  const values = columns.map((id) => columnValue(record, id, timeZoneMode));
  if (scope === "allColumns") values.push(...record.eventData.map((field) => field.value));
  return values.map((value) => normalizeText(value, caseSensitive)).filter(Boolean);
}

/** True when a record's quick-filter grammar matches at least one searched value. */
export function matchesQuickFilter(
  record: EvtxRecord,
  quickFilter: EvtxQuickFilter,
  visibleColumns?: readonly EvtxColumnId[],
  timeZoneMode: EvtxTimeZoneMode = "local",
  parsedEventIdSelectors?: EvtxEventIdSelectorParseResult,
  discoveredColumns?: readonly EvtxColumnId[]
): boolean {
  const query = quickFilter.query.trim();
  if (!query) return false;

  if (quickFilter.mode === "eventIds") {
    return eventIdMatchesSelectors(
      record.eventId,
      parsedEventIdSelectors ?? parseEventIdSelectors(query)
    );
  }

  const values = searchableValues(
    record,
    quickFilter.scope,
    visibleColumns,
    quickFilter.caseSensitive,
    timeZoneMode,
    discoveredColumns
  );
  const normalizedQuery = normalizeText(query, quickFilter.caseSensitive);
  const contains = (term: string) => values.some((value) => value.includes(term));

  switch (quickFilter.mode) {
    case "oneString":
      return contains(normalizedQuery);
    case "multipleWords": {
      const words = queryParts(query, /\s+/, quickFilter.caseSensitive);
      return words.length > 0 && words.some(contains);
    }
    case "multipleStrings": {
      const strings = queryParts(
        query,
        EVTX_STRING_QUERY_SEPARATOR,
        quickFilter.caseSensitive,
      );
      return strings.length > 0 && strings.some(contains);
    }
    case "allWords": {
      const words = queryParts(query, /\s+/, quickFilter.caseSensitive);
      return words.length > 0 && words.every(contains);
    }
    case "allStrings": {
      const strings = queryParts(
        query,
        EVTX_STRING_QUERY_SEPARATOR,
        quickFilter.caseSensitive,
      );
      return strings.length > 0 && strings.every(contains);
    }
  }
}

/** A record's final visibility after all filter stages have been evaluated. */
export function recordMatchesVisibleFilter(
  record: EvtxRecord,
  input: Pick<
    VisibleRecordsInput,
    "filterEventIds" | "filterSearch" | "filterLevels" | "selectedChannels"
  > & {
    quickFilter?: EvtxQuickFilter;
    visibleColumns?: readonly EvtxColumnId[];
    eventIdSelectors?: EvtxEventIdSelectorParseResult;
    quickEventIdSelectors?: EvtxEventIdSelectorParseResult;
    quickFilterColumns?: readonly EvtxColumnId[];
    timeWindow?: EvtxTimeWindow;
    timeZoneMode?: EvtxTimeZoneMode;
    nowEpoch?: number;
  }
): boolean {
  if (!input.selectedChannels.has(record.channel)) return false;
  if (
    input.timeWindow &&
    !isWithinTimeWindow(record.timestampEpoch, input.timeWindow, input.nowEpoch)
  ) {
    return false;
  }
  if (!input.filterLevels.has(record.level)) return false;
  if (input.eventIdSelectors) {
    if (!eventIdMatchesSelectors(record.eventId, input.eventIdSelectors)) return false;
  } else if (
    input.filterEventIds.trim() &&
    !eventIdMatchesSelectors(record.eventId, parseEventIdSelectors(input.filterEventIds))
  ) {
    return false;
  }
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

  if (
    quickFilter.mode === "eventIds" &&
    (!input.quickEventIdSelectors ||
      input.quickEventIdSelectors.invalid ||
      input.quickEventIdSelectors.selectors.length === 0)
  ) {
    return quickFilter.action === "hide";
  }
  const matched = matchesQuickFilter(
    record,
    quickFilter,
    input.visibleColumns,
    input.timeZoneMode,
    input.quickEventIdSelectors,
    input.quickFilterColumns
  );
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
  const quickFilterColumns =
    input.quickFilter?.query.trim() &&
    input.quickFilter.mode !== "eventIds" &&
    (input.quickFilter.scope === "allColumns" || input.visibleColumns === undefined)
      ? availableColumns(discoverMappedProperties(input.records)).map((column) => column.id)
      : undefined;
  const predicateInput = {
    ...input,
    nowEpoch: input.nowEpoch ?? Date.now(),
    eventIdSelectors: input.filterEventIds.trim()
      ? parseEventIdSelectors(input.filterEventIds)
      : undefined,
    quickEventIdSelectors:
      input.quickFilter?.mode === "eventIds" && input.quickFilter.query.trim()
        ? parseEventIdSelectors(input.quickFilter.query)
        : undefined,
    quickFilterColumns,
  };
  return input.records.filter((record) => recordMatchesVisibleFilter(record, predicateInput));
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

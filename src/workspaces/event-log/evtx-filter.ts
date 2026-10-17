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
import {
  parseFieldQuery,
  type EvtxQueryError,
  type EvtxQueryField,
} from "./evtx-query-grammar";

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

/** Every level, most severe first: the order the level toggles and the counts use. */
export const EVTX_LEVELS: readonly EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

/**
 * How many of `records` sit at each level, in one pass.
 *
 * The level toggles show these as the loaded totals, so callers pass the loaded records and not the
 * visible ones: a toggle's count is what turning it on can show, not what the other filters leave.
 * A level with no loaded records is zero here. Whether that zero means "none exist" or "none were
 * requested" is the caller's to decide: see `levelsFilteredAtSource`.
 */
export function countByLevel(records: readonly EvtxRecord[]): Record<EvtxLevel, number> {
  const counts: Record<EvtxLevel, number> = {
    Critical: 0,
    Error: 0,
    Warning: 0,
    Information: 0,
    Verbose: 0,
  };
  for (const record of records) counts[record.level] += 1;
  return counts;
}

/**
 * True when a live query sends a level predicate to the event service, so records at a deselected
 * level are never loaded.
 *
 * Information is a raw-level domain with no upper bound (6..254), and the XPath compiler caps its OR
 * expressions, so any selection that includes Information is evaluated locally instead. Only a
 * strict subset without Information is pushed down.
 *
 * `evtx-store.ts` keeps its own copy of this predicate in `buildServerFilter`; it does not call this
 * function. The filter row's unknown counts depend on this one, so `evtx-store-server-filter.test.ts`
 * pins the two together for every level subset. Merging them is a store change that belongs to
 * Phase 6a (#834).
 */
export function levelsFilteredAtSource(levels: ReadonlySet<EvtxLevel>): boolean {
  return levels.size > 0 && levels.size < EVTX_LEVELS.length && !levels.has("Information");
}

/**
 * The level selection after one toggle: the level flips, and emptying the selection selects every
 * level again, since "no level" is never a view the operator wants.
 */
export function levelsAfterToggle(
  levels: ReadonlySet<EvtxLevel>,
  level: EvtxLevel,
): Set<EvtxLevel> {
  const next = new Set(levels);
  if (next.has(level)) next.delete(level);
  else next.add(level);
  return next.size === 0 ? new Set(EVTX_LEVELS) : next;
}

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
 * The quick-filter grammars supported by the event viewer. `fieldQuery` is the field-scoped search
 * grammar (`evtx-query-grammar.ts`), the same one the search box speaks.
 */
export type EvtxQuickFilterMode =
  | "oneString"
  | "multipleWords"
  | "multipleStrings"
  | "allWords"
  | "allStrings"
  | "eventIds"
  | "fieldQuery";

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
  "fieldQuery",
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
  /** The applied search, read as a field query (`compileFieldQuery`): the last text that parsed. */
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

/** The fields whose term is a substring of one record property. */
type EvtxQueryTextField = Exclude<EvtxQueryField, "id" | "level">;

function queryFieldText(record: EvtxRecord, field: EvtxQueryTextField): string {
  switch (field) {
    case "provider":
      return record.provider;
    case "channel":
      return record.channel;
    case "computer":
      return record.computer;
    case "source":
      // The label the backend gives the record: an EVTX file's path, an archive member's
      // "<archive>::<member>" label (text members too), or "Live" / "Remote: <machine>". For a
      // text-log line that is the file it came from, the analysis session's origin.file, never
      // the code file a CCM line names. The grid filters these records only; the text logs
      // correlated from the Log workspace are not grid records.
      return record.sourceLabel;
  }
}

/**
 * One field-query term with its value checked. A free-text needle is normalized for the Case
 * setting; a field value's needle is always lower case, because field values ignore Case.
 */
type EvtxCompiledTerm = { negated: boolean } & (
  | { kind: "text"; needle: string }
  | { kind: "id"; selectors: EvtxEventIdSelectorParseResult }
  | { kind: "level"; levels: ReadonlySet<EvtxLevel> }
  | { kind: "textField"; field: EvtxQueryTextField; needle: string }
  /** `name` is lower case: EventData names match case-insensitively, like the field names. */
  | { kind: "data"; name: string; needle: string }
);

/** A field query ready to test records with: every clause must match, any one term in a clause. */
export interface EvtxCompiledFieldQuery {
  clauses: EvtxCompiledTerm[][];
}

/**
 * A field value or the record text it is tested against, in the one case rule field terms use:
 * insensitive, whatever the Case setting (spec 8.3 says provider:, channel: and computer: match a
 * case-insensitive substring; source: and data.<Name>: follow the same rule).
 */
function fieldValueText(value: string): string {
  return value.toLocaleLowerCase();
}

export type EvtxFieldQueryResult =
  | { ok: true; query: EvtxCompiledFieldQuery }
  | { ok: false; error: EvtxQueryError };

/** Each level by name, case-insensitively, and "info", the label the filter row's toggle shows. */
function levelForQueryName(name: string): EvtxLevel | undefined {
  const lower = name.toLowerCase();
  if (lower === "info") return "Information";
  return EVTX_LEVELS.find((level) => level.toLowerCase() === lower);
}

/**
 * Gives each term of a field query its meaning and checks its value.
 *
 * - `id:` reads its value with the Event ID grammar (`parseEventIdSelectors`): a comma list of IDs
 *   and inclusive ranges, matched exactly, as the Event IDs quick-filter mode does.
 * - `level:` takes a comma list of level names, mapped through `EVTX_LEVELS`.
 * - `provider:`, `channel:`, `computer:`, `source:` (the record's source label) and
 *   `data.<Name>:` (the record's EventData field of that name) match a case-insensitive
 *   substring. `caseSensitive` does not apply to them, and neither does a quick filter's scope.
 * - Free text is a substring too, case-sensitive only when `caseSensitive`; which values it
 *   searches is the caller's (`matchesFieldQuery`).
 *
 * The first malformed term fails the whole query: an invalid query never filters on what is left.
 */
export function compileFieldQuery(text: string, caseSensitive: boolean): EvtxFieldQueryResult {
  const parsed = parseFieldQuery(text);
  if (!parsed.ok) return parsed;
  const clauses: EvtxCompiledTerm[][] = [];
  for (const clause of parsed.query.clauses) {
    const compiled: EvtxCompiledTerm[] = [];
    for (const term of clause) {
      const { negated, value } = term;
      if (term.kind === "text") {
        compiled.push({ kind: "text", negated, needle: normalizeText(value, caseSensitive) });
      } else if (term.kind === "data") {
        compiled.push({
          kind: "data",
          negated,
          name: term.name.toLowerCase(),
          needle: fieldValueText(value),
        });
      } else if (term.field === "id") {
        const selectors = parseEventIdSelectors(value);
        if (selectors.invalid || selectors.selectors.length === 0) {
          return {
            ok: false,
            error: {
              position: term.valuePosition,
              message: `id: takes Event IDs and ranges from 0 to ${MAX_EVENT_ID}, as in id:4624,4625 or id:4624-4634, not "${value}".`,
            },
          };
        }
        compiled.push({ kind: "id", negated, selectors });
      } else if (term.field === "level") {
        const levels = new Set<EvtxLevel>();
        let offset = 0;
        for (const entry of value.split(",")) {
          const name = entry.trim();
          const entryPosition = term.valuePosition + offset + (entry.length - entry.trimStart().length);
          offset += entry.length + 1;
          if (!name) continue;
          const level = levelForQueryName(name);
          if (!level) {
            return {
              ok: false,
              error: {
                position: entryPosition,
                message: `level: takes critical, error, warning, info, information or verbose, not "${name}".`,
              },
            };
          }
          levels.add(level);
        }
        if (levels.size === 0) {
          return { ok: false, error: { position: term.position, message: "level: needs a value." } };
        }
        compiled.push({ kind: "level", negated, levels });
      } else {
        compiled.push({
          kind: "textField",
          negated,
          field: term.field,
          needle: fieldValueText(value),
        });
      }
    }
    clauses.push(compiled);
  }
  return { ok: true, query: { clauses } };
}

/** The first problem in a field query for the operator to read, or null when there is none. */
export function fieldQueryError(text: string): EvtxQueryError | null {
  if (!text.trim()) return null;
  const result = compileFieldQuery(text, false);
  return result.ok ? null : result.error;
}

/**
 * Whether a quick filter can be applied as edited: every mode but a field query that does not
 * parse. The Event IDs mode keeps its own rule for an invalid list (`recordMatchesVisibleFilter`).
 */
export function quickFilterApplies(filter: EvtxQuickFilter): boolean {
  return filter.mode !== "fieldQuery" || fieldQueryError(filter.query) === null;
}

function termMatches(
  record: EvtxRecord,
  term: EvtxCompiledTerm,
  matchesText: (needle: string) => boolean
): boolean {
  switch (term.kind) {
    case "text":
      return matchesText(term.needle);
    case "id":
      return eventIdMatchesSelectors(record.eventId, term.selectors);
    case "level":
      return term.levels.has(record.level);
    case "textField":
      return fieldValueText(queryFieldText(record, term.field)).includes(term.needle);
    case "data":
      // A record without the field does not match, so a negated term keeps it.
      return record.eventData.some(
        (field) =>
          field.name.toLowerCase() === term.name &&
          fieldValueText(field.value).includes(term.needle)
      );
  }
}

/** Tests a record against a compiled field query; `matchesText` decides what free text searches. */
function matchesFieldQuery(
  record: EvtxRecord,
  query: EvtxCompiledFieldQuery,
  matchesText: (needle: string) => boolean
): boolean {
  return query.clauses.every((clause) =>
    clause.some((term) => {
      const matched = termMatches(record, term, matchesText);
      return term.negated ? !matched : matched;
    })
  );
}

/**
 * The search box's free text: a case-insensitive substring of the message or the provider, the
 * rule the box had before it spoke the field grammar. Lowered once per record, on first use.
 */
function searchBoxText(record: EvtxRecord): (needle: string) => boolean {
  let message: string | undefined;
  let provider: string | undefined;
  return (needle) =>
    (message ??= record.message.toLocaleLowerCase()).includes(needle) ||
    (provider ??= record.provider.toLocaleLowerCase()).includes(needle);
}

/** True when a record's quick-filter grammar matches at least one searched value. */
export function matchesQuickFilter(
  record: EvtxRecord,
  quickFilter: EvtxQuickFilter,
  visibleColumns?: readonly EvtxColumnId[],
  timeZoneMode: EvtxTimeZoneMode = "local",
  parsedEventIdSelectors?: EvtxEventIdSelectorParseResult,
  discoveredColumns?: readonly EvtxColumnId[],
  compiledFieldQuery?: EvtxFieldQueryResult
): boolean {
  const query = quickFilter.query.trim();
  if (!query) return false;

  if (quickFilter.mode === "eventIds") {
    return eventIdMatchesSelectors(
      record.eventId,
      parsedEventIdSelectors ?? parseEventIdSelectors(query)
    );
  }

  if (quickFilter.mode === "fieldQuery") {
    const compiled = compiledFieldQuery ?? compileFieldQuery(query, quickFilter.caseSensitive);
    if (!compiled.ok) return false;
    // Free text searches what the other text modes search: the scoped columns, plus EventData
    // for all columns. A field term names its field, so the scope does not apply to it.
    let values: string[] | undefined;
    return matchesFieldQuery(record, compiled.query, (needle) => {
      values ??= searchableValues(
        record,
        quickFilter.scope,
        visibleColumns,
        quickFilter.caseSensitive,
        timeZoneMode,
        discoveredColumns
      );
      return values.some((value) => value.includes(needle));
    });
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
    /** `filterSearch` compiled once by selectVisibleRecords for the whole pass. */
    searchQuery?: EvtxFieldQueryResult;
    /** A `fieldQuery` quick filter compiled once by selectVisibleRecords for the whole pass. */
    quickFieldQuery?: EvtxFieldQueryResult;
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
  const search =
    input.searchQuery ??
    (input.filterSearch.trim() ? compileFieldQuery(input.filterSearch, false) : undefined);
  // A search that does not parse is not applied at all (spec 8.3), never in part. The store keeps
  // the last search that parsed as `filterSearch`, so one only reaches here from outside the store.
  if (search?.ok && !matchesFieldQuery(record, search.query, searchBoxText(record))) {
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
  const quickFieldQuery =
    quickFilter.mode === "fieldQuery"
      ? input.quickFieldQuery ?? compileFieldQuery(quickFilter.query, quickFilter.caseSensitive)
      : undefined;
  // A field query that does not parse is not applied, whether it would show or hide (spec 8.3).
  // The Event IDs mode above keeps its own rule.
  if (quickFieldQuery && !quickFieldQuery.ok) return true;
  const matched = matchesQuickFilter(
    record,
    quickFilter,
    input.visibleColumns,
    input.timeZoneMode,
    input.quickEventIdSelectors,
    input.quickFilterColumns,
    quickFieldQuery
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
    searchQuery: input.filterSearch.trim()
      ? compileFieldQuery(input.filterSearch, false)
      : undefined,
    quickFieldQuery:
      input.quickFilter?.mode === "fieldQuery" && input.quickFilter.query.trim()
        ? compileFieldQuery(input.quickFilter.query, input.quickFilter.caseSensitive)
        : undefined,
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

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

/** Every level, most severe first: the order the level toggles and the counts use. */
export const EVTX_LEVELS: readonly EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

/**
 * The Windows raw level number of each level, as the Event Log service filters on it. Stated
 * outright rather than read from a level's position in `EVTX_LEVELS`: a reorder of that list for
 * display would otherwise change the XPath the service is sent.
 */
export const EVTX_RAW_LEVEL: Readonly<Record<EvtxLevel, number>> = {
  Critical: 1,
  Error: 2,
  Warning: 3,
  Information: 4,
  Verbose: 5,
};

/** How far down the severity order a level sits: 0 for Critical, 4 for Verbose. */
export const EVTX_LEVEL_RANK = Object.fromEntries(
  EVTX_LEVELS.map((level, index) => [level, index]),
) as Readonly<Record<EvtxLevel, number>>;

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
 * `buildServerFilter` in `evtx-store.ts` calls this function, so the request the store sends and
 * the filter row's unknown counts read one rule. `evtx-store-server-filter.test.ts` pins the level
 * numbers it sends for every level subset.
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
        comparison = EVTX_LEVEL_RANK[a.level] - EVTX_LEVEL_RANK[b.level];
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

/**
 * A span of event time, half open: `startMs` is inside it and `endMs` is not, so the span of one
 * histogram bucket and the span of the next never share an event. Both are epoch milliseconds.
 */
export interface EvtxTimeRange {
  startMs: number;
  endMs: number;
}

/** What a record scope was made from. */
export type EvtxRecordScopeKind = "finding" | "chain";

/**
 * What did not make it into a record scope, kept apart so the interface can say each one. A scope
 * never claims to be the whole of what it was built from. Every number counts REFERENCES (what the
 * finding or chain cited), never records: two candidates of one reference are one reference, and
 * the same event cited twice is one.
 */
export interface EvtxRecordScopeCounts {
  /** References whose identity is usable but which now name no loaded record. */
  notLoaded: number;
  /** References with no usable identity (a fallback hash, or none), which can never match. */
  noUsableIdentity: number;
  /** References that name more than one loaded record. Every candidate is in the scope. */
  ambiguous: number;
  /** The source may have cited more events than it sent (the engine bounds a finding's evidence). */
  bounded: boolean;
  /**
   * References whose record cannot be looked for at all, because the timeline item that would say
   * which record they name was not read (a chain member whose item was never loaded). Nothing is
   * known about them: this is NOT "not loaded", which is an absence found by looking. Absent means
   * none, which is what a finding's evidence always has.
   */
  unresolved?: number;
}

/**
 * The counts a scope's references give: a reference with no candidate left is not loaded, and one
 * with more than one is ambiguous. Used where a scope is built and where it is pruned, so the two
 * cannot count differently.
 */
export function countScopeReferences(
  references: readonly (readonly EvtxRecord[])[],
  noUsableIdentity: number,
  bounded: boolean,
  unresolved = 0,
): EvtxRecordScopeCounts {
  let notLoaded = 0;
  let ambiguous = 0;
  for (const candidates of references) {
    if (candidates.length === 0) notLoaded += 1;
    else if (candidates.length > 1) ambiguous += 1;
  }
  // Unresolved references are not in `references` (they have no records to prune), so the count is
  // carried, and it is only present when there is one.
  return {
    notLoaded,
    noUsableIdentity,
    ambiguous,
    bounded,
    ...(unresolved > 0 ? { unresolved } : {}),
  };
}

/**
 * Records the operator narrowed the view to, from a finding (or, later, a chain).
 *
 * Held by record OBJECT: `EvtxRecord.id` is an index the store reassigns on every merge, so a set
 * of ids would point at other events after one live-tail batch. A merge keeps the objects it
 * already holds, so this set follows its events through a renumber.
 */
export interface EvtxRecordScope {
  kind: EvtxRecordScopeKind;
  /** The finding's or chain's title, captured when the scope was applied: a rebuilt diagnosis may drop it. */
  title: string;
  records: ReadonlySet<EvtxRecord>;
  /**
   * For each distinct cited reference with a usable identity, the loaded records it names: none
   * (not loaded), one (a match) or several (ambiguous, all of them in `records`). Pruned with the
   * records, and `counts` is recomputed from it, so a count never reads in records. Absent, each
   * record is a reference of its own and a record that leaves is counted as not loaded.
   */
  references?: readonly (readonly EvtxRecord[])[];
  counts: EvtxRecordScopeCounts;
}

/**
 * Criteria that live only in the current view: not read from the service, never saved. They are
 * deliberately NOT part of `EvtxFilterModel`, whose shape is what a saved filter stores; a field
 * added there would be serialized. A load or a change of source clears them.
 */
export interface EvtxTransientCriteria {
  timeRange: EvtxTimeRange | null;
  recordScope: EvtxRecordScope | null;
}

/** A timestamp a time range can place: finite and after the epoch origin. */
export function hasUsableTimestamp(record: EvtxRecord): boolean {
  return Number.isFinite(record.timestampEpoch) && record.timestampEpoch > 0;
}

/**
 * Whether a record lies inside the range. A record with no usable timestamp lies in no range: it
 * cannot be shown to be inside one.
 */
export function isWithinTimeRange(record: EvtxRecord, range: EvtxTimeRange): boolean {
  return (
    hasUsableTimestamp(record) &&
    record.timestampEpoch >= range.startMs &&
    record.timestampEpoch < range.endMs
  );
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
  /**
   * The transient time range, or null for none. Required rather than optional: `tsc` then lists
   * every caller of the selector, and a caller that left it out would show a set the others do not.
   */
  timeRange: EvtxTimeRange | null;
  /**
   * The records of the transient record scope, or null for none. Required for the same reason as
   * `timeRange`. An empty set is a scope of nothing and shows nothing; it is not the same as null.
   */
  scopeRecords: ReadonlySet<EvtxRecord> | null;
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
    | "filterEventIds"
    | "filterSearch"
    | "filterLevels"
    | "selectedChannels"
    | "timeRange"
    | "scopeRecords"
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
  // The transient criteria first: a set lookup and two comparisons, cheaper than any text match.
  if (input.scopeRecords !== null && !input.scopeRecords.has(record)) return false;
  if (input.timeRange !== null && !isWithinTimeRange(record, input.timeRange)) return false;
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

/**
 * How many events a time range hides only because they have no usable timestamp: the events every
 * other criterion shows, which the range cannot place. Zero without a range.
 */
export function countHiddenForWantOfTimestamp(input: VisibleRecordsInput): number {
  if (input.timeRange === null) return 0;
  // The records without a usable timestamp first, then every other criterion on only those: the
  // criteria are per record, so this is the count of running them all and keeping the untimed, at
  // the cost of a cheap pass over the loaded records and the full predicate over the few.
  const untimed = input.records.filter((record) => !hasUsableTimestamp(record));
  if (untimed.length === 0) return 0;
  return selectVisibleRecords({ ...input, records: untimed, timeRange: null }).length;
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

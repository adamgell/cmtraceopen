/**
 * Saved event-log filters.
 *
 * EventLogExpert and Event Log Explorer both keep a filter library; we had none, so every
 * investigation started by retyping the same criteria. Kept separate from the store so the
 * serialization rules are testable without a Zustand or Tauri runtime.
 */
import type { EvtxLevel, EvtxTimeWindow } from "./types";
import {
  DEFAULT_QUICK_FILTER,
  type EvtxFilterModel,
  type EvtxGroupField,
  type EvtxQuickFilter,
  type EvtxQuickFilterAction,
  type EvtxQuickFilterMode,
  type EvtxQuickFilterScope,
} from "./evtx-filter";

/** Everything a saved filter restores, using the same layered model as runtime evaluation. */
export interface EvtxFilterCriteria extends EvtxFilterModel {}

export interface EvtxSavedFilter {
  id: string;
  name: string;
  favorite: boolean;
  tags: string[];
  criteria: EvtxFilterCriteria;
  /** Epoch millis of the last apply, for a recents list. Null when never applied. */
  lastUsed: number | null;
}

/** Every level, and the fallback when a stored filter names none this build recognizes. */
export const ALL_LEVELS: EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];
const TIME_WINDOWS: EvtxTimeWindow[] = ["1h", "24h", "7d", "30d", "all"];
const QUICK_FILTER_MODES: EvtxQuickFilterMode[] = [
  "oneString",
  "multipleWords",
  "multipleStrings",
  "allWords",
  "allStrings",
  "eventIds",
];
const QUICK_FILTER_SCOPES: EvtxQuickFilterScope[] = ["allColumns", "visibleColumns"];
const QUICK_FILTER_ACTIONS: EvtxQuickFilterAction[] = ["show", "hide"];

/** Revalidates the interactive grammar when a filter is loaded from disk. */
export function sanitizeQuickFilter(input: unknown): EvtxQuickFilter {
  const raw = isRecord(input) ? input : {};
  return {
    mode: QUICK_FILTER_MODES.includes(raw.mode as EvtxQuickFilterMode)
      ? (raw.mode as EvtxQuickFilterMode)
      : DEFAULT_QUICK_FILTER.mode,
    query: typeof raw.query === "string" ? raw.query : "",
    scope: QUICK_FILTER_SCOPES.includes(raw.scope as EvtxQuickFilterScope)
      ? (raw.scope as EvtxQuickFilterScope)
      : DEFAULT_QUICK_FILTER.scope,
    action: QUICK_FILTER_ACTIONS.includes(raw.action as EvtxQuickFilterAction)
      ? (raw.action as EvtxQuickFilterAction)
      : DEFAULT_QUICK_FILTER.action,
    caseSensitive: raw.caseSensitive === true,
    highlight: raw.highlight !== false,
  };
}
const GROUP_FIELDS: EvtxGroupField[] = [
  "level",
  "provider",
  "channel",
  "eventId",
  "day",
];

/** The current schema version, so an older export can be recognised rather than misread. */
export const SAVED_FILTER_SCHEMA = 2;

export interface EvtxFilterExport {
  schema: number;
  filters: EvtxSavedFilter[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Coerces untrusted input into criteria, dropping anything unrecognised.
 *
 * Import files are edited by hand and shared between machines, so every field is validated against
 * the values this build knows. An unknown level silently widening a filter would be worse than
 * dropping it: the operator would believe they were filtering when they were not.
 */
export function sanitizeCriteria(input: unknown): EvtxFilterCriteria {
  const raw = isRecord(input) ? input : {};
  const before = isRecord(raw.beforeLoad) ? raw.beforeLoad : {};
  const onLoad = isRecord(raw.onLoad) ? raw.onLoad : {};
  const after = isRecord(raw.afterLoad) ? raw.afterLoad : {};

  const levels = Array.isArray(before.levels)
    ? (before.levels.filter((level): level is EvtxLevel =>
        ALL_LEVELS.includes(level as EvtxLevel)
      ) as EvtxLevel[])
    : [];
  const groupBy = Array.isArray(after.groupBy)
    ? (after.groupBy.filter((field): field is EvtxGroupField =>
        GROUP_FIELDS.includes(field as EvtxGroupField)
      ) as EvtxGroupField[])
    : [];

  return {
    beforeLoad: {
      levels: levels.length > 0 ? levels : [...ALL_LEVELS],
      eventIds: typeof before.eventIds === "string" ? before.eventIds : "",
      timeWindow: TIME_WINDOWS.includes(before.timeWindow as EvtxTimeWindow)
        ? (before.timeWindow as EvtxTimeWindow)
        : "24h",
    },
    onLoad: {
      search: typeof onLoad.search === "string" ? onLoad.search : "",
      quickFilter: sanitizeQuickFilter(onLoad.quickFilter),
    },
    afterLoad: { groupBy },
  };
}

/** Coerces untrusted input into a saved filter, or null when it carries no usable name. */
export function sanitizeSavedFilter(input: unknown, fallbackId: string): EvtxSavedFilter | null {
  if (!isRecord(input)) return null;
  const name = typeof input.name === "string" ? input.name.trim() : "";
  if (!name) return null;

  return {
    id: typeof input.id === "string" && input.id ? input.id : fallbackId,
    name,
    favorite: input.favorite === true,
    tags: Array.isArray(input.tags)
      ? Array.from(
          new Set(
            input.tags
              .filter((tag): tag is string => typeof tag === "string")
              .map((tag) => tag.trim())
              .filter(Boolean)
          )
        )
      : [],
    criteria: sanitizeCriteria(input.criteria),
    // Finite only. JSON admits 1e309, which parses to Infinity and would reach the ordering
    // comparator as a non-finite operand.
    lastUsed: typeof input.lastUsed === "number" && Number.isFinite(input.lastUsed)
      ? input.lastUsed
      : null,
  };
}

/**
 * Parses an exported filter file.
 *
 * Individually invalid filters are skipped rather than failing the whole import, so one bad entry
 * in a shared file does not cost the operator the rest of it.
 */
export function parseFilterExport(text: string): {
  filters: EvtxSavedFilter[];
  skipped: number;
  /** True when the file was written by a build using a schema this one does not know. */
  unsupportedSchema?: boolean;
} {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { filters: [], skipped: 0 };
  }

  // The schema is written on export and must be checked on import. A newer file would otherwise be
  // sanitized into whatever this build understands and imported silently, quietly changing the
  // operator's criteria rather than telling them the file is from a later version.
  if (
    !isRecord(parsed) ||
    typeof parsed.schema !== "number" ||
    parsed.schema !== SAVED_FILTER_SCHEMA
  ) {
    return { filters: [], skipped: 0, unsupportedSchema: true };
  }
  const list = isRecord(parsed) && Array.isArray(parsed.filters) ? parsed.filters : [];
  const filters: EvtxSavedFilter[] = [];
  let skipped = 0;

  list.forEach((entry, index) => {
    const filter = sanitizeSavedFilter(entry, `imported-${index}`);
    if (filter) filters.push(filter);
    else skipped += 1;
  });

  return { filters, skipped };
}

/** Serializes filters for export. */
export function buildFilterExport(filters: EvtxSavedFilter[]): string {
  const payload: EvtxFilterExport = { schema: SAVED_FILTER_SCHEMA, filters };
  return JSON.stringify(payload, null, 2);
}

/**
 * Merges imported filters into an existing library.
 *
 * Matching is by name rather than id, because ids are generated per machine and the same filter
 * shared twice would otherwise accumulate duplicates. An import replaces a same-named filter, since
 * the operator chose to import it.
 */
export function mergeFilters(
  existing: EvtxSavedFilter[],
  imported: EvtxSavedFilter[]
): EvtxSavedFilter[] {
  const merged = [...existing];
  for (const filter of imported) {
    const index = merged.findIndex(
      (candidate) => candidate.name.toLowerCase() === filter.name.toLowerCase()
    );
    if (index >= 0) merged[index] = { ...filter, id: merged[index].id };
    else merged.push(filter);
  }
  return merged;
}

/** Favorites first, then most recently used, then by name. */
export function orderFilters(filters: EvtxSavedFilter[]): EvtxSavedFilter[] {
  return [...filters].sort((a, b) => {
    if (a.favorite !== b.favorite) return a.favorite ? -1 : 1;
    if (a.lastUsed !== b.lastUsed) return (b.lastUsed ?? 0) - (a.lastUsed ?? 0);
    return a.name.localeCompare(b.name);
  });
}

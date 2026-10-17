/**
 * Event Logs views (spec section 8.15, Q-5 and Q-12): a name for a set of filters, and optionally a
 * layout, that the view strip applies in one click.
 *
 * Pure, like `evtx-saved-filters.ts` whose criteria model and sanitization it reuses: no store, no
 * Tauri. The persisted library is `evtx-views-store.ts`.
 *
 * What a view holds is exactly `EvtxFilterCriteria` (the saved-filter model) plus a layout. The
 * transient time range and record scope are not on that model and are never read, written or
 * exported here (Q-2): every stored or imported view is rebuilt from explicit keys.
 *
 * AGENTS.md forbids compatibility layers, fallbacks and migrations, so there is none. Schema 1 is
 * the first version; any other schema in a file is refused. And a view that cannot be read exactly
 * as written is skipped and counted, never approximated: `sanitizeCriteria` quietly turns an
 * unknown level list into every level, a missing or unknown window into 24 hours and an unknown
 * quick-filter mode into "One string", and a view that did that would not filter the way its author
 * meant. So a view must carry every key (except the optional channel list), and the only value
 * coerced is a layout panel this build cannot show yet (`dock: true` reads as `false`).
 */
import {
  DEFAULT_QUICK_FILTER,
  EVTX_LEVELS,
  EVTX_LEVEL_RANK,
  parseEventIdSelectors,
  type EvtxQuickFilter,
} from "./evtx-filter";
import {
  EVTX_PANELS_AVAILABLE,
  EVTX_VIEW_IDS,
  type EvtxPanelId,
  type EvtxPanels,
  type EvtxViewId,
} from "./evtx-layout-store";
import { sanitizeCriteria, type EvtxFilterCriteria } from "./evtx-saved-filters";
import type { EvtxLevel } from "./types";

/** The version of the exported file and of the persisted envelope. */
export const SAVED_VIEW_SCHEMA = 1;

/** Custom views kept. The strip lays every card out, so an unbounded library is unusable. */
export const MAX_CUSTOM_VIEWS = 32;
export const MAX_VIEW_NAME_LENGTH = 60;
/** One view's JSON. Bounds a query or a channel list without truncating either. */
export const MAX_VIEW_JSON_LENGTH = 65_536;
/** An import file's text, checked before it is parsed. */
export const MAX_VIEW_FILE_LENGTH = 1_048_576;

export interface EvtxViewLayout {
  activeView: EvtxViewId;
  panels: EvtxPanels;
}

/** What a view is, and what an export carries. */
export interface EvtxViewBody {
  name: string;
  criteria: EvtxFilterCriteria;
  /** Null when the view was saved without "Include current layout". */
  layout: EvtxViewLayout | null;
}

/** A custom view as persisted: a body and an id the library made on this machine. */
export interface EvtxStoredView extends EvtxViewBody {
  id: string;
}

/**
 * A view as the strip shows it. `builtIn` is derived from where the view came from and is never
 * read from storage or from a file: a stored `builtIn: true` would make a view undeletable and
 * impersonate one of ours.
 */
export type EvtxView =
  | (EvtxStoredView & { builtIn: false })
  | (EvtxStoredView & { builtIn: true; subtitle: string; description: string });

const ALL_PANELS = Object.keys(EVTX_PANELS_AVAILABLE) as EvtxPanelId[];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwn(object: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

// ---------------------------------------------------------------------------------------------
// The built-in view
// ---------------------------------------------------------------------------------------------

const DMEDP_CHANNEL = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin";
const AAD_CHANNEL = "Microsoft-Windows-AAD/Operational";
/**
 * [Unverified on a real machine] DNS-Client 1014 is logged in System: the screenshot fixture
 * places it there (e2e/fixtures/event-log-data.ts), and the spec names only "DNS-Client 1014".
 */
const SYSTEM_CHANNEL = "System";

/**
 * "Enrollment triage" as one field query (spec 8.15, Q-12). Three separate selections, joined by
 * "or":
 *
 *   DeviceManagement Admin and Event ID 75 or 76,
 *   AAD Operational and level Warning, Error or Critical,
 *   provider DNS-Client and Event ID 1014.
 *
 * The before-load criteria cannot say this: `levels` and `eventIds` are one global set each,
 * applied to every selected channel, so "Warning and above in AAD only" has no form there, and the
 * query is the only place a per-channel rule can live. The field grammar is an AND of clauses with
 * OR inside a clause, so the union is written as one clause that names the three sources and one
 * clause per source that says "not this source, or its rule":
 *
 *   in one of the three sources
 *   and (not DeviceManagement Admin, or Event ID 75/76)
 *   and (not AAD Operational, or Warning and above)
 *   and (not provider DNS-Client, or Event ID 1014)
 *
 * That equals the union whenever a record belongs to at most one of the three sources, which every
 * real record does: the one exception would be a record in the DeviceManagement or AAD channel whose
 * provider is DNS-Client, and DNS-Client does not log to those channels. The test pins that row as
 * a known difference rather than leaving it unsaid. (The exact expansion into an AND of OR clauses
 * is 8 clauses and 659 characters.)
 *
 * It is the search text, not the quick filter: a Top IDs click replaces the quick filter, and a
 * quick filter that matches also marks every row. The search is ANDed with such a click instead.
 * Nothing here can be pushed to the service, so a live source reads the three whole channels in the
 * window and filters them locally.
 */
export const ENROLLMENT_TRIAGE_QUERY = [
  "channel:DeviceManagement-Enterprise-Diagnostics-Provider/Admin OR channel:AAD/Operational OR provider:DNS-Client",
  "-channel:DeviceManagement-Enterprise-Diagnostics-Provider/Admin OR id:75,76",
  "-channel:AAD/Operational OR level:warning,error,critical",
  "-provider:DNS-Client OR id:1014",
].join(" ");

export const ENROLLMENT_TRIAGE_ID = "builtin:enrollment-triage";

/**
 * The copy states what the view selects, one source at a time. It makes no statement about how the
 * events relate: they are three selections shown together, and nothing here has established a link
 * between them (the epic's non-goal). The test pins every string and scans for relational words.
 */
const ENROLLMENT_TRIAGE: EvtxView = {
  id: ENROLLMENT_TRIAGE_ID,
  builtIn: true,
  name: "Enrollment triage",
  subtitle: "Built-in, 3 filters",
  description:
    "Selects events from three sources. " +
    "DeviceManagement Admin: Event IDs 75 and 76. " +
    "AAD Operational: Warning, Error and Critical events. " +
    "DNS-Client: Event ID 1014. " +
    "Channels: DeviceManagement Admin, AAD Operational and System. Time window: all.",
  criteria: {
    beforeLoad: {
      levels: [...EVTX_LEVELS],
      eventIds: "",
      timeWindow: "all",
      selectedChannels: [DMEDP_CHANNEL, AAD_CHANNEL, SYSTEM_CHANNEL],
    },
    onLoad: { search: ENROLLMENT_TRIAGE_QUERY, quickFilter: { ...DEFAULT_QUICK_FILTER } },
    afterLoad: { groupBy: [] },
  },
  layout: null,
};

export const EVTX_BUILT_IN_VIEWS: readonly EvtxView[] = [ENROLLMENT_TRIAGE];

/** The strip's cards in order: built-ins, then custom views in the order they were made. */
export function listViews(custom: readonly EvtxStoredView[]): EvtxView[] {
  return [...EVTX_BUILT_IN_VIEWS, ...custom.map((view) => ({ ...view, builtIn: false as const }))];
}

export function viewSubtitle(view: EvtxView): string {
  if (view.builtIn) return view.subtitle;
  return view.layout ? "Filters and layout" : "Filters";
}

export function viewDescription(view: EvtxView): string {
  if (view.builtIn) return view.description;
  return `${view.name}. Saved ${view.layout ? "filters and layout" : "filters"}.`;
}

// ---------------------------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------------------------

/**
 * What a typed name never holds: control characters, format characters (bidi marks and overrides,
 * zero width and tag characters, soft hyphen) and the other default-ignorable code points. They draw
 * nothing, so a name with them reads as another name: "Enrollment triage" followed by U+061C looks
 * like the built-in's. Matched by Unicode property, so a code point added to a class later is
 * covered without this list changing.
 */
const INVISIBLE_NAME_CHARACTERS = /[\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/gu;

/**
 * A name as the library keeps it: whitespace collapsed, invisible characters removed, trimmed. The
 * invisible characters are removed rather than refused, so the name that results is the name that
 * shows, and it collides with the built-in's or another view's exactly when it reads as it. Null when
 * nothing usable is left or it is over the limit.
 */
export function cleanViewName(input: unknown): string | null {
  if (typeof input !== "string") return null;
  // Whitespace first: a tab or a newline is a space between words, not an invisible character that
  // would join them. By the White_Space property, not `\s`, which also counts U+FEFF as a space: that
  // one draws nothing and is removed with the rest.
  const name = input
    .replace(/\p{White_Space}+/gu, " ")
    .replace(INVISIBLE_NAME_CHARACTERS, "")
    .replace(/\p{White_Space}+/gu, " ")
    .trim();
  if (!name || name.length > MAX_VIEW_NAME_LENGTH) return null;
  return name;
}

function sameName(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/** Whether `name` is taken, ignoring case, by a built-in or by one of `custom`. */
export function viewNameTaken(name: string, custom: readonly { name: string }[]): boolean {
  return (
    EVTX_BUILT_IN_VIEWS.some((view) => sameName(view.name, name)) ||
    custom.some((view) => sameName(view.name, name))
  );
}

/** `wanted`, or `wanted (2)`, `wanted (3)`... when that is taken, within the length limit. */
export function uniqueViewName(wanted: string, custom: readonly { name: string }[]): string {
  if (!viewNameTaken(wanted, custom)) return wanted;
  for (let n = 2; ; n += 1) {
    const suffix = ` (${n})`;
    const candidate = `${wanted.slice(0, MAX_VIEW_NAME_LENGTH - suffix.length).trimEnd()}${suffix}`;
    if (!viewNameTaken(candidate, custom)) return candidate;
  }
}

// ---------------------------------------------------------------------------------------------
// Capture
// ---------------------------------------------------------------------------------------------

export interface EvtxLayoutSource {
  activeView: EvtxViewId;
  panels: EvtxPanels;
}

/** The layout as a view keeps it: named fields only. A panel that cannot be shown yet is off. */
export function captureLayout(source: EvtxLayoutSource): EvtxViewLayout {
  return {
    activeView: source.activeView,
    panels: {
      channels: EVTX_PANELS_AVAILABLE.channels && source.panels.channels,
      insights: EVTX_PANELS_AVAILABLE.insights && source.panels.insights,
      dock: EVTX_PANELS_AVAILABLE.dock && source.panels.dock,
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Reading untrusted input
// ---------------------------------------------------------------------------------------------

/** The one key a view may leave out: the model's own optional field, a view with no channel list. */
const OPTIONAL_KEYS: ReadonlySet<string> = new Set(["selectedChannels"]);

/**
 * True when `raw` wrote every key `clean` has, and each is equal, all the way down. A key only
 * `raw` has is ignored (nothing is copied from it). A key only `clean` has is a default the reader
 * made up, and it is a difference unless the key is optional: a missing time window would read as
 * 24 hours, a missing level list as every level, and the view would not filter the way its author
 * meant. So a value that was absent, changed, dropped or coerced is the difference.
 */
function survives(raw: unknown, clean: unknown): boolean {
  if (Array.isArray(clean)) {
    return (
      Array.isArray(raw) &&
      raw.length === clean.length &&
      clean.every((item, index) => survives(raw[index], item))
    );
  }
  if (isRecord(clean)) {
    if (!isRecord(raw)) return false;
    return Object.keys(clean).every((key) =>
      hasOwn(raw, key) ? survives(raw[key], clean[key]) : OPTIONAL_KEYS.has(key),
    );
  }
  return raw === clean;
}

/** The layout must be written: null for a view saved without one, else an object. An export always writes it. */
function readLayout(raw: unknown): { ok: true; layout: EvtxViewLayout | null } | { ok: false } {
  if (raw === null) return { ok: true, layout: null };
  if (!isRecord(raw)) return { ok: false };
  const activeView = EVTX_VIEW_IDS.find((id) => id === raw.activeView);
  if (activeView === undefined || !isRecord(raw.panels)) return { ok: false };
  const panels = {} as EvtxPanels;
  for (const id of ALL_PANELS) {
    const value = raw.panels[id];
    if (typeof value !== "boolean") return { ok: false };
    // A panel that cannot be shown in this build is off, as in the layout store. Not a skip: it
    // changes what is laid out, never what is filtered, and a later build may export it on.
    panels[id] = EVTX_PANELS_AVAILABLE[id] && value;
  }
  return { ok: true, layout: { activeView, panels } };
}

/**
 * Reads one view from untrusted input, or null when it cannot be read exactly as written.
 *
 * Rebuilt from explicit keys: the name, `sanitizeCriteria` of the criteria, and the layout. The
 * transient criteria, an id, `builtIn` and any other key the input carries are not copied. The input
 * must carry every key it is rebuilt with (only `selectedChannels` may be absent), so nothing in the
 * result is a default. The one value coerced rather than refused is a panel this build cannot show.
 */
export function sanitizeViewBody(input: unknown): EvtxViewBody | null {
  if (!isRecord(input)) return null;
  const name = cleanViewName(input.name);
  if (name === null || !isRecord(input.criteria)) return null;

  const criteria = sanitizeCriteria(input.criteria);
  // An Event ID list that does not parse reads nothing on a live refetch (evtx-store.ts), so a view
  // carrying one would empty the grid when applied.
  if (parseEventIdSelectors(criteria.beforeLoad.eventIds).invalid) return null;
  if (!survives(input.criteria, criteria)) return null;

  const layout = readLayout(input.layout);
  if (!layout.ok) return null;

  const body: EvtxViewBody = { name, criteria, layout: layout.layout };
  return JSON.stringify(body).length > MAX_VIEW_JSON_LENGTH ? null : body;
}

/**
 * Reads the persisted list. Entries that cannot be read are skipped; an id that is missing, taken
 * or one of ours is made anew, and a name that is taken is made unique. At most `MAX_CUSTOM_VIEWS`.
 */
export function sanitizeStoredViews(
  input: unknown,
  makeId: () => string,
): { views: EvtxStoredView[]; skipped: number } {
  const list = Array.isArray(input) ? input : [];
  const views: EvtxStoredView[] = [];
  const ids = new Set<string>(EVTX_BUILT_IN_VIEWS.map((view) => view.id));
  let skipped = 0;
  for (const entry of list) {
    const body = sanitizeViewBody(entry);
    if (body === null || views.length >= MAX_CUSTOM_VIEWS) {
      skipped += 1;
      continue;
    }
    const wanted = isRecord(entry) && typeof entry.id === "string" ? entry.id : "";
    const id = wanted && !ids.has(wanted) ? wanted : makeId();
    ids.add(id);
    views.push({ id, ...body, name: uniqueViewName(body.name, views) });
  }
  return { views, skipped };
}

// ---------------------------------------------------------------------------------------------
// Export and import
// ---------------------------------------------------------------------------------------------

export interface EvtxViewExport {
  schema: number;
  views: EvtxViewBody[];
}

/** The file: name, criteria and layout of each view. Ids are per machine and are not written. */
export function buildViewExport(views: readonly EvtxViewBody[]): string {
  const payload: EvtxViewExport = {
    schema: SAVED_VIEW_SCHEMA,
    views: views.map(({ name, criteria, layout }) => ({ name, criteria, layout })),
  };
  return JSON.stringify(payload, null, 2);
}

export type EvtxViewImportFailure = "too-large" | "not-json" | "unsupported-schema" | "not-a-view-file";

export type EvtxViewImportResult =
  | { ok: true; views: EvtxViewBody[]; skipped: number }
  | { ok: false; reason: EvtxViewImportFailure };

/**
 * Parses an exported file. One unreadable view costs only itself, and is counted. A schema other
 * than this build's is refused, never converted.
 */
export function parseViewExport(text: string): EvtxViewImportResult {
  if (text.length > MAX_VIEW_FILE_LENGTH) return { ok: false, reason: "too-large" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, reason: "not-json" };
  }
  if (!isRecord(parsed) || parsed.schema !== SAVED_VIEW_SCHEMA) {
    return { ok: false, reason: "unsupported-schema" };
  }
  if (!Array.isArray(parsed.views)) return { ok: false, reason: "not-a-view-file" };

  const views: EvtxViewBody[] = [];
  let skipped = 0;
  parsed.views.forEach((entry, index) => {
    const body = index < MAX_CUSTOM_VIEWS ? sanitizeViewBody(entry) : null;
    if (body) views.push(body);
    else skipped += 1;
  });
  return { ok: true, views, skipped };
}

export interface EvtxViewMerge {
  views: EvtxStoredView[];
  added: number;
  replaced: number;
  /** Imported views left out because the library is full. */
  skipped: number;
}

/**
 * Adds imported views to the library. An entry whose name matches a custom view ALREADY in the
 * library, ignoring case, replaces it (the operator chose to import it) and keeps its id. An entry
 * whose name matches an earlier entry of the same file never replaces it: it is added under a
 * unique name, as `sanitizeStoredViews` makes duplicates unique, and counts as added. A name that is
 * a built-in's is made unique too, so an import can neither replace nor pose as a built-in. Ids from
 * the file are never used.
 */
export function mergeViews(
  existing: readonly EvtxStoredView[],
  imported: readonly EvtxViewBody[],
  makeId: () => string,
): EvtxViewMerge {
  const views = [...existing];
  // The names this file has already used, lower case: a later entry of the same name is not a
  // replacement of the library's view, and not of the earlier entry either.
  const usedByFile = new Set<string>();
  let added = 0;
  let replaced = 0;
  let skipped = 0;
  for (const body of imported) {
    const key = body.name.toLowerCase();
    const at = usedByFile.has(key)
      ? -1
      : existing.findIndex((view) => sameName(view.name, body.name));
    usedByFile.add(key);
    if (at >= 0) {
      views[at] = { ...body, id: views[at].id };
      replaced += 1;
    } else if (views.length >= MAX_CUSTOM_VIEWS) {
      skipped += 1;
    } else {
      views.push({ ...body, id: makeId(), name: uniqueViewName(body.name, views) });
      added += 1;
    }
  }
  return { views, added, replaced, skipped };
}

// ---------------------------------------------------------------------------------------------
// Which view is active
// ---------------------------------------------------------------------------------------------

function sortedLevels(levels: readonly EvtxLevel[]): EvtxLevel[] {
  return [...levels].sort((a, b) => EVTX_LEVEL_RANK[a] - EVTX_LEVEL_RANK[b]);
}

function quickFilterKey(filter: EvtxQuickFilter): unknown[] {
  return [
    filter.mode,
    filter.query,
    filter.scope,
    filter.action,
    filter.caseSensitive,
    filter.highlight,
  ];
}

/**
 * A view is active when the criteria the operator has equal its own: levels and channels as sets,
 * grouping in order, the text as typed. A view saved without channels does not constrain them.
 * Layout is not compared (filters persist across layout switches, spec 9) and the transient
 * criteria are not on the shape. Derived on every render, never remembered: a Stop that restores
 * the window, a source change or a channel clear then deactivates it with no code of its own.
 */
export function viewMatchesCriteria(view: EvtxViewBody, current: EvtxFilterCriteria): boolean {
  const a = view.criteria;
  const b = current;
  const channels = a.beforeLoad.selectedChannels;
  if (channels !== undefined) {
    const have = b.beforeLoad.selectedChannels;
    if (have === undefined || new Set(have).size !== new Set(channels).size) return false;
    const held = new Set(have);
    if (!channels.every((channel) => held.has(channel))) return false;
  }
  return (
    JSON.stringify(sortedLevels(a.beforeLoad.levels)) ===
      JSON.stringify(sortedLevels(b.beforeLoad.levels)) &&
    a.beforeLoad.eventIds.trim() === b.beforeLoad.eventIds.trim() &&
    a.beforeLoad.timeWindow === b.beforeLoad.timeWindow &&
    a.onLoad.search === b.onLoad.search &&
    JSON.stringify(quickFilterKey(a.onLoad.quickFilter)) ===
      JSON.stringify(quickFilterKey(b.onLoad.quickFilter)) &&
    JSON.stringify(a.afterLoad.groupBy) === JSON.stringify(b.afterLoad.groupBy)
  );
}

/** The view's channels that are not in `held`: what the strip says its view cannot show. */
export function missingViewChannels(view: EvtxViewBody, held: ReadonlySet<string>): string[] {
  return (view.criteria.beforeLoad.selectedChannels ?? []).filter((channel) => !held.has(channel));
}

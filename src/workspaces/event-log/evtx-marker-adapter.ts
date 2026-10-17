import type { Marker } from "../../types/markers";
import { useMarkerStore } from "../../stores/marker-store";
import {
  EVTX_STRING_QUERY_SEPARATOR,
  type EvtxQuickFilter,
} from "./evtx-filter";
import type { EvtxColumnId } from "./evtx-columns";
import { parseFieldQuery, type EvtxQueryField } from "./evtx-query-grammar";
import type { EvtxRecord } from "./types";

export const DEFAULT_EVTX_QUICK_FILTER: EvtxQuickFilter = {
  mode: "oneString",
  query: "",
  scope: "allColumns",
  action: "show",
  caseSensitive: false,
  highlight: true,
};

/**
 * Marker files are still persisted by the existing line-marker store. This prefix keeps EVTX
 * markers out of a text-log file's namespace while retaining the established load/save seam.
 */
export function evtxMarkerFileKey(sourceLabel: string): string {
  return `event-log:${sourceLabel}`;
}

/**
 * Resolve the producer-backed identity used for marker persistence. `id` is deliberately absent:
 * the store reassigns it while merging streamed channels and sorting/refetching rows.
 *
 * EventRecordID is transported as text when it exceeds JavaScript's safe integer range. A missing,
 * zero, or malformed EventRecordID has no stable producer discriminator, so it is not addressable
 * by the marker store.
 */
function evtxMarkerRecordIdentity(record: EvtxRecord): string | null {
  const textId = record.eventRecordIdText?.trim() ?? "";
  if (textId !== "") {
    const canonicalTextId = textId.replace(/^0+(?=\d)/, "");
    if (!/^\d+$/.test(canonicalTextId) || /^0+$/.test(canonicalTextId)) {
      return null;
    }
    const textNumber = Number(canonicalTextId);
    return Number.isSafeInteger(textNumber) &&
      String(textNumber) === canonicalTextId
      ? `record-number:${textNumber}`
      : `record-text:${canonicalTextId}`;
  }
  return Number.isSafeInteger(record.eventRecordId) && record.eventRecordId > 0
    ? `record-number:${record.eventRecordId}`
    : null;
}

export function isEvtxMarkerAddressable(record: EvtxRecord): boolean {
  return evtxMarkerRecordIdentity(record) !== null;
}

/**
 * Build a source-scoped projection key. The unaddressable fallback is for row rendering only;
 * marker lookup and mutation fail closed unless the producer supplied EventRecordID.
 */
export function evtxMarkerKey(record: EvtxRecord): string {
  const recordIdentity =
    evtxMarkerRecordIdentity(record) ??
    `unaddressable:${evtxOccurrenceDigest(record)}`;
  return JSON.stringify([
    record.originKind ?? "event",
    record.sourceLabel,
    record.channel,
    recordIdentity,
  ]);
}

function hashEvtxMarkerKey(key: string, seed = 2166136261): number {
  let hash = seed;
  for (let index = 0; index < key.length; index += 1) {
    hash ^= key.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

/** A deterministic non-positional ID for the existing numeric marker persistence format. */
export function evtxMarkerLineId(record: EvtxRecord): number {
  return hashEvtxMarkerKey(evtxMarkerKey(record));
}

/** Bounded projection identity for malformed records without a producer record ID. */
function evtxOccurrenceDigest(record: EvtxRecord): string {
  let first = 2166136261;
  let second = first ^ 0x9e3779b9;
  const feed = (value: string) => {
    const framed = String(value.length) + ":" + value;
    first = hashEvtxMarkerKey(framed, first);
    second = hashEvtxMarkerKey(framed, second);
  };
  feed(String(record.timestampEpoch));
  feed(record.eventRecordIdText ?? "");
  feed(String(record.eventId));
  feed(record.provider);
  feed(record.message);
  feed(String(record.eventData.length));
  for (const field of record.eventData) {
    feed(field.name);
    feed(field.value);
  }
  feed(record.rawXml);
  return (
    first.toString(16).padStart(8, "0") +
    second.toString(16).padStart(8, "0")
  );
}

interface EvtxMarkerMatch {
  lineId: number;
  marker: Marker;
}
const markerIdentityIndexes = new WeakMap<
  object,
  Map<string, Map<string, EvtxMarkerMatch>>
>();

function getMarkerIdentityIndex(
  markersByFile: ReadonlyMap<string, ReadonlyMap<number, Marker>>,
): Map<string, Map<string, EvtxMarkerMatch>> {
  const cacheKey = markersByFile as object;
  const cached = markerIdentityIndexes.get(cacheKey);
  if (cached) return cached;

  const index = new Map<string, Map<string, EvtxMarkerMatch>>();
  for (const [fileKey, fileMap] of markersByFile) {
    const fileIndex = new Map<string, EvtxMarkerMatch>();
    for (const [lineId, marker] of fileMap) {
      if (marker.identity !== undefined) {
        fileIndex.set(marker.identity, { lineId, marker });
      }
    }
    if (fileIndex.size > 0) index.set(fileKey, fileIndex);
  }
  markerIdentityIndexes.set(cacheKey, index);
  return index;
}

function findEvtxMarker(
  record: EvtxRecord,
  markersByFile: ReadonlyMap<string, ReadonlyMap<number, Marker>>,
): EvtxMarkerMatch | null {
  if (!isEvtxMarkerAddressable(record)) return null;
  const identity = evtxMarkerKey(record);
  return (
    getMarkerIdentityIndex(markersByFile)
      .get(evtxMarkerFileKey(record.sourceLabel))
      ?.get(identity) ?? null
  );
}

function evtxMarkerStorageLineId(
  record: EvtxRecord,
  markersByFile: ReadonlyMap<string, ReadonlyMap<number, Marker>>,
): number {
  const fileMap = markersByFile.get(evtxMarkerFileKey(record.sourceLabel));
  const identity = evtxMarkerKey(record);
  let lineId = evtxMarkerLineId(record);
  while (true) {
    const existing = fileMap?.get(lineId);
    if (!existing || existing.identity === identity) {
      return lineId;
    }
    lineId = (lineId + 1) >>> 0;
  }
}

export function getEvtxMarker(
  record: EvtxRecord,
  markersByFile: ReadonlyMap<string, ReadonlyMap<number, Marker>>,
): Marker | null {
  return findEvtxMarker(record, markersByFile)?.marker ?? null;
}
export function isEvtxBookmark(marker: Marker | null | undefined): boolean {
  return marker?.category === "bookmark";
}

export function loadEvtxMarkers(sourceLabels: readonly string[]): void {
  for (const sourceLabel of sourceLabels) {
    void useMarkerStore.getState().loadMarkers(evtxMarkerFileKey(sourceLabel));
  }
}

function persistEvtxMarkers(sourceLabel: string): void {
  void useMarkerStore.getState().saveMarkers(evtxMarkerFileKey(sourceLabel));
}
interface EvtxMarkerMutation {
  fileKey: string;
  lineId: number;
  existing: Marker | undefined;
  mutationIdentity: string;
}

function resolveEvtxMarkerMutation(
  record: EvtxRecord,
  markersByFile: ReadonlyMap<string, ReadonlyMap<number, Marker>>,
): EvtxMarkerMutation | null {
  if (!isEvtxMarkerAddressable(record)) return null;
  const existingMatch = findEvtxMarker(record, markersByFile);
  const fileKey = evtxMarkerFileKey(record.sourceLabel);
  const lineId =
    existingMatch?.lineId ?? evtxMarkerStorageLineId(record, markersByFile);
  const existing = existingMatch?.marker;
  const mutationIdentity = evtxMarkerKey(record);
  return { fileKey, lineId, existing, mutationIdentity };
}

export function toggleEvtxTag(record: EvtxRecord): void {
  const store = useMarkerStore.getState();
  const mutation = resolveEvtxMarkerMutation(record, store.markersByFile);
  if (!mutation) return;
  const { fileKey, lineId, existing, mutationIdentity } = mutation;
  const tagCategory =
    store.activeCategory === "bookmark"
      ? (store.categories.find((category) => category.id !== "bookmark")?.id ??
        "bug")
      : store.activeCategory;
  if (store.activeCategory === "bookmark") store.setActiveCategory(tagCategory);
  if (existing?.category === "bookmark") {
    store.setMarkerCategory(fileKey, lineId, tagCategory, mutationIdentity);
  } else {
    store.toggleMarker(fileKey, lineId, mutationIdentity);
  }
  persistEvtxMarkers(record.sourceLabel);
}

export function toggleEvtxBookmark(record: EvtxRecord): void {
  const store = useMarkerStore.getState();
  const mutation = resolveEvtxMarkerMutation(record, store.markersByFile);
  if (!mutation) return;
  const { fileKey, lineId, existing, mutationIdentity } = mutation;

  if (!store.categories.some((category) => category.id === "bookmark")) {
    store.addCategory({ id: "bookmark", label: "Bookmark", color: "#8b5cf6" });
  }
  if (existing?.category === "bookmark") {
    store.removeMarker(fileKey, lineId, mutationIdentity);
  } else if (existing) {
    store.setMarkerCategory(fileKey, lineId, "bookmark", mutationIdentity);
  } else {
    store.setActiveCategory("bookmark");
    store.toggleMarker(fileKey, lineId, mutationIdentity);
  }
  persistEvtxMarkers(record.sourceLabel);
}

/**
 * The text a row marks for its quick filter. Row visibility still comes from the centralized
 * matcher; these only choose what is drawn as <mark>.
 */
export interface EvtxHighlightTerms {
  /** Free text, marked in any cell, with the quick filter's Case setting. */
  text: string[];
  /**
   * Field-term values by the column that renders the field the term tested. Each is marked only
   * in that column's cell, in any case, as field values match (spec 8.3).
   */
  columns: Partial<Record<EvtxColumnId, string[]>>;
}

/**
 * The grid column that renders each field a term can test. `source:` has no column (the grid does
 * not render the source label) and `data.<Name>:` has none (the grid renders no EventData field),
 * so their values mark nothing; `id:` and `level:` values are not text the row contains as typed.
 */
const FIELD_HIGHLIGHT_COLUMNS: Partial<Record<EvtxQueryField, EvtxColumnId>> = {
  provider: "provider",
  channel: "channel",
  computer: "computer",
};

/** Select the terms rendered as <mark> nodes; row visibility still comes from the centralized matcher. */
export function evtxQuickFilterTerms(quickFilter: EvtxQuickFilter): EvtxHighlightTerms {
  const query = quickFilter.query.trim();
  if (quickFilter.mode === "fieldQuery") return fieldQueryHighlightTerms(query);
  return { text: textModeTerms(quickFilter.mode, query), columns: {} };
}

function textModeTerms(mode: EvtxQuickFilter["mode"], query: string): string[] {
  if (!query || mode === "eventIds") {
    return query ? query.split(/[\s,;]+/).filter(Boolean) : [];
  }
  if (mode === "multipleStrings" || mode === "allStrings") {
    return query
      .split(EVTX_STRING_QUERY_SEPARATOR)
      .map((part) => part.trim())
      .filter(Boolean);
  }
  if (mode === "multipleWords" || mode === "allWords") {
    return query
      .split(/\s+/)
      .map((part) => part.trim())
      .filter(Boolean);
  }
  return [query];
}

/**
 * A field query's marks: its free text, bare or quoted, for every cell, and each field term's value
 * for its own column's cell only. A negated term names what a matching row lacks, so it marks
 * nothing, and a query that does not parse marks nothing.
 */
function fieldQueryHighlightTerms(query: string): EvtxHighlightTerms {
  const terms: EvtxHighlightTerms = { text: [], columns: {} };
  const parsed = parseFieldQuery(query);
  if (!parsed.ok) return terms;
  for (const term of parsed.query.clauses.flat()) {
    if (term.negated) continue;
    if (term.kind === "text") {
      terms.text.push(term.value);
    } else if (term.kind === "field") {
      const column = FIELD_HIGHLIGHT_COLUMNS[term.field];
      if (column) (terms.columns[column] ??= []).push(term.value);
    }
  }
  return terms;
}

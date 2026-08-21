import type { Marker } from "../../types/markers";
import { useMarkerStore } from "../../stores/marker-store";
import type { EvtxColumnId } from "./evtx-columns";
import * as filterModule from "./evtx-filter";
import type { EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxRecord } from "./types";

const saveQueues = new Map<string, Promise<void>>();
/** The quick-filter shape is repeated here so this lane can be applied beside the filter lane. */
export interface EvtxQuickFilterLike {
  mode:
    | "oneString"
    | "multipleWords"
    | "multipleStrings"
    | "allWords"
    | "allStrings"
    | "eventIds";
  query: string;
  scope: "allColumns" | "visibleColumns";
  action: "show" | "hide";
  caseSensitive: boolean;
  highlight: boolean;
}

export const DEFAULT_EVTX_QUICK_FILTER: EvtxQuickFilterLike = {
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
    `unaddressable:${evtxOccurrenceKey(record)}`;
  return JSON.stringify([
    record.originKind ?? "event",
    record.sourceLabel,
    record.channel,
    recordIdentity,
  ]);
}

function hashEvtxMarkerKey(key: string): number {
  let hash = 2166136261;
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

/** Projection identity for malformed/legacy records without a provider record ID. */
export function evtxOccurrenceKey(record: EvtxRecord): string {
  return JSON.stringify([
    record.timestampEpoch,
    record.eventRecordIdText ?? "",
    record.eventId,
    record.provider,
    record.message,
    record.eventData.map((field) => [field.name, field.value]),
    record.rawXml,
  ]);
}

/** The delimiter/FNV identity used by marker files written before structured identities. */
function legacyEvtxMarkerLineId(record: EvtxRecord): number {
  const key = [
    record.sourceLabel,
    record.channel,
    `record:${record.eventRecordId}`,
    record.eventId,
  ].join("\u001f");
  return hashEvtxMarkerKey(key);
}

/**
 * Marker files written before structured identities used this delimiter projection for records
 * whose numeric EventRecordID was unsafe. Keep it separate from the current collision-resistant
 * JSON projection so those files can still be discovered.
 */
function legacyEvtxOccurrenceLineId(record: EvtxRecord): number {
  const occurrenceKey = [
    record.timestampEpoch,
    record.eventRecordIdText ?? "",
    record.eventId,
    record.provider,
    record.message,
    record.eventData
      .map((field) => `${field.name}=${field.value}`)
      .join("\u001e"),
    record.rawXml,
  ].join("\u001f");
  const key = [
    record.sourceLabel,
    record.channel,
    `occurrence:${occurrenceKey}`,
    record.eventId,
  ].join("\u001f");
  return hashEvtxMarkerKey(key);
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
  const addressable = isEvtxMarkerAddressable(record);
  const textId = record.eventRecordIdText?.trim() ?? "";
  const legacyUnsafeRecordId =
    !addressable &&
    textId === "" &&
    Number.isFinite(record.eventRecordId) &&
    record.eventRecordId > Number.MAX_SAFE_INTEGER;
  if (!addressable && !legacyUnsafeRecordId) return null;
  const fileMap = markersByFile.get(evtxMarkerFileKey(record.sourceLabel));
  if (!fileMap) return null;

  if (addressable) {
    const identity = evtxMarkerKey(record);
    const match = getMarkerIdentityIndex(markersByFile)
      .get(evtxMarkerFileKey(record.sourceLabel))
      ?.get(identity);
    if (match) return match;
  }

  // Numeric line IDs are only legacy lookups. Never let a hash collision select another
  // identity-bearing EVTX marker. Probe the previous unsafe-ID occurrence format before the
  // newer structured hash and the original delimiter/FNV numeric format.
  const legacyLineIds = legacyUnsafeRecordId
    ? [legacyEvtxOccurrenceLineId(record)]
    : [
        legacyEvtxOccurrenceLineId(record),
        evtxMarkerLineId(record),
        legacyEvtxMarkerLineId(record),
      ];
  const seenLineIds = new Set<number>();
  for (const lineId of legacyLineIds) {
    if (seenLineIds.has(lineId)) continue;
    seenLineIds.add(lineId);
    const marker = fileMap.get(lineId);
    if (marker && marker.identity === undefined) return { lineId, marker };
  }
  return null;
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
    if (
      !existing ||
      existing.identity === undefined ||
      existing.identity === identity
    ) {
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
  const loadMarkers = useMarkerStore.getState().loadMarkers;
  for (const sourceLabel of sourceLabels) {
    void loadMarkers(evtxMarkerFileKey(sourceLabel));
  }
}

function persistEvtxMarkers(sourceLabel: string): void {
  const filePath = evtxMarkerFileKey(sourceLabel);
  const previous = saveQueues.get(filePath) ?? Promise.resolve();
  const next = previous
    .catch(() => undefined)
    .then(() => useMarkerStore.getState().saveMarkers(filePath));
  saveQueues.set(filePath, next);
  void next.then(
    () => {
      if (saveQueues.get(filePath) === next) saveQueues.delete(filePath);
    },
    () => {
      if (saveQueues.get(filePath) === next) saveQueues.delete(filePath);
    },
  );
}
interface EvtxMarkerMutation {
  fileKey: string;
  lineId: number;
  existing: Marker | undefined;
  mutationIdentity: string | undefined;
}

function resolveEvtxMarkerMutation(
  record: EvtxRecord,
  markersByFile: ReadonlyMap<string, ReadonlyMap<number, Marker>>,
): EvtxMarkerMutation | null {
  const existingMatch = findEvtxMarker(record, markersByFile);
  if (!isEvtxMarkerAddressable(record) && !existingMatch) return null;
  const fileKey = evtxMarkerFileKey(record.sourceLabel);
  const lineId =
    existingMatch?.lineId ?? evtxMarkerStorageLineId(record, markersByFile);
  const existing = existingMatch?.marker;
  const mutationIdentity =
    existingMatch?.marker.identity === undefined && existingMatch !== undefined
      ? undefined
      : evtxMarkerKey(record);
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
 * Use Task 5's centralized matcher for both visibility and row highlighting. Returning false when
 * the dependent export is absent is deliberately fail-closed; this lane must not invent a second
 * matching grammar or broaden the visible set during branch integration.
 */
export function matchesEvtxQuickFilter(
  record: EvtxRecord,
  quickFilter: EvtxQuickFilterLike,
  visibleColumns?: readonly EvtxColumnId[],
  timeZoneMode: EvtxTimeZoneMode = "local",
): boolean {
  const centralized = (
    filterModule as typeof filterModule & {
      matchesQuickFilter?: (
        record: EvtxRecord,
        quickFilter: EvtxQuickFilterLike,
        visibleColumns?: readonly EvtxColumnId[],
        timeZoneMode?: EvtxTimeZoneMode,
      ) => boolean;
    }
  ).matchesQuickFilter;
  if (!centralized) return false;
  return centralized(record, quickFilter, visibleColumns, timeZoneMode);
}

/** Select the terms rendered as <mark> nodes; row visibility still comes from the centralized matcher. */
export function evtxQuickFilterTerms(
  quickFilter: EvtxQuickFilterLike,
): string[] {
  const query = quickFilter.query.trim();
  if (!query || quickFilter.mode === "eventIds") {
    return query ? query.split(/[\s,;]+/).filter(Boolean) : [];
  }
  if (
    quickFilter.mode === "multipleStrings" ||
    quickFilter.mode === "allStrings"
  ) {
    return query
      .split(/[,;\u000a]+/)
      .map((part) => part.trim())
      .filter(Boolean);
  }
  if (quickFilter.mode === "multipleWords" || quickFilter.mode === "allWords") {
    return query
      .split(/\s+/)
      .map((part) => part.trim())
      .filter(Boolean);
  }
  return [query];
}

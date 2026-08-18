import type { Marker } from "../../types/markers";
import { useMarkerStore } from "../../stores/marker-store";
import type { EvtxColumnId } from "./evtx-columns";
import { columnValue } from "./evtx-columns";
import * as filterModule from "./evtx-filter";
import type { EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxRecord } from "./types";

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
 * Build an identity from source provenance and the provider's record identity. `id` is deliberately
 * absent: the store reassigns it while merging streamed channels and sorting/refetching rows.
 */
export function evtxMarkerKey(record: EvtxRecord, occurrenceKey?: string): string {
  const recordIdentity =
    Number.isSafeInteger(record.eventRecordId) && record.eventRecordId > 0
      ? `record:${record.eventRecordId}`
      : `occurrence:${occurrenceKey ?? evtxOccurrenceKey(record)}`;
  return [record.sourceLabel, record.channel, recordIdentity, record.eventId].join("\u001f");
}

/** A deterministic non-positional ID for the existing numeric marker persistence format. */
export function evtxMarkerLineId(record: EvtxRecord, occurrenceKey?: string): number {
  const key = evtxMarkerKey(record, occurrenceKey);
  let hash = 2166136261;
  for (let index = 0; index < key.length; index += 1) {
    hash ^= key.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

/** Fallback identity for malformed/legacy records without a provider record ID. */
function evtxOccurrenceKey(record: EvtxRecord): string {
  return [
    record.timestampEpoch,
    record.eventId,
    record.provider,
    record.message,
    record.eventData.map((field) => `${field.name}=${field.value}`).join("\u001e"),
  ].join("\u001f");
}

export function getEvtxMarker(
  record: EvtxRecord,
  markersByFile: ReadonlyMap<string, ReadonlyMap<number, Marker>>
): Marker | null {
  return markersByFile.get(evtxMarkerFileKey(record.sourceLabel))?.get(evtxMarkerLineId(record)) ?? null;
}

export function loadEvtxMarkers(sourceLabels: readonly string[]): void {
  const loadMarkers = useMarkerStore.getState().loadMarkers;
  for (const sourceLabel of sourceLabels) {
    void loadMarkers(evtxMarkerFileKey(sourceLabel));
  }
}

function persistEvtxMarkers(sourceLabel: string): void {
  void useMarkerStore.getState().saveMarkers(evtxMarkerFileKey(sourceLabel));
}

export function toggleEvtxTag(record: EvtxRecord): void {
  const store = useMarkerStore.getState();
  const fileKey = evtxMarkerFileKey(record.sourceLabel);
  const lineId = evtxMarkerLineId(record);
  const existing = store.markersByFile.get(fileKey)?.get(lineId);
  const tagCategory =
    store.activeCategory === "bookmark"
      ? store.categories.find((category) => category.id !== "bookmark")?.id ?? "bug"
      : store.activeCategory;
  if (store.activeCategory === "bookmark") {
    store.setActiveCategory(tagCategory);
  }
  if (existing?.category === "bookmark") {
    store.setMarkerCategory(fileKey, lineId, tagCategory);
  } else {
    store.toggleMarker(fileKey, lineId);
  }
  persistEvtxMarkers(record.sourceLabel);
}

export function toggleEvtxBookmark(record: EvtxRecord): void {
  const store = useMarkerStore.getState();
  const fileKey = evtxMarkerFileKey(record.sourceLabel);
  const lineId = evtxMarkerLineId(record);
  const existing = store.markersByFile.get(fileKey)?.get(lineId);

  if (!store.categories.some((category) => category.id === "bookmark")) {
    store.addCategory({ id: "bookmark", label: "Bookmark", color: "#8b5cf6" });
  }

  if (existing?.category === "bookmark") {
    store.removeMarker(fileKey, lineId);
  } else if (existing) {
    store.setMarkerCategory(fileKey, lineId, "bookmark");
  } else {
    store.setActiveCategory("bookmark");
    store.toggleMarker(fileKey, lineId);
  }
  persistEvtxMarkers(record.sourceLabel);
}

export function isEvtxBookmark(marker: Marker | null): boolean {
  return marker?.category === "bookmark";
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
  timeZoneMode: EvtxTimeZoneMode = "local"
): boolean {
  const centralized = (
    filterModule as typeof filterModule & {
      matchesQuickFilter?: (
        record: EvtxRecord,
        quickFilter: EvtxQuickFilterLike,
        visibleColumns?: readonly EvtxColumnId[],
        timeZoneMode?: EvtxTimeZoneMode
      ) => boolean;
    }
  ).matchesQuickFilter;
  if (!centralized) return false;
  return centralized(record, quickFilter, visibleColumns, timeZoneMode);
}

/** Select the terms rendered as <mark> nodes; row visibility still comes from the centralized matcher. */
export function evtxQuickFilterTerms(quickFilter: EvtxQuickFilterLike): string[] {
  const query = quickFilter.query.trim();
  if (!query || quickFilter.mode === "eventIds") {
    return query ? query.split(/[\s,;]+/).filter(Boolean) : [];
  }
  if (quickFilter.mode === "multipleStrings" || quickFilter.mode === "allStrings") {
    return query.split(/[,;\u000a]+/).map((part) => part.trim()).filter(Boolean);
  }
  if (quickFilter.mode === "multipleWords" || quickFilter.mode === "allWords") {
    return query.split(/\s+/).map((part) => part.trim()).filter(Boolean);
  }
  return [query];
}

import { create } from "zustand";
import {
  assertParseResultShape,
  formatCoverageGap,
  mergeCoverageGaps,
  mergeStructuredCoverageGaps,
  sourceCoverageMessages,
} from "./evtx-coverage";
import type { EvtxTimeZoneMode } from "./evtx-time";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  EvtxRecord,
  EvtxChannelInfo,
  EvtxCoverageGap,
  EvtxLevel,
  EvtxParseResult,
  EvtxArchiveMember,
  EvtxTimeWindow,
  EventLogSourceCoverage,
  EventLogSourceManifest,
  EventQueryFilterSubset,
  EvtxLiveMode,
  EvtxTailBatch,
  EvtxTailStatus,
} from "./types";
import { EVTX_TIME_WINDOW_MS } from "./types";
import type { LogEntry } from "../../types/log";
import {
  clearEventLogChannel,
  type EvtxClearStatusResult,
} from "../../lib/commands";
import { assertUnifiedTimelineShape, type UnifiedTimeline } from "./unified-timeline";

// Re-exported so callers have one import site; the implementations live in a Tauri-free module.
export { parseEventIdFilter, selectVisibleRecords } from "./evtx-filter";
import {
  DEFAULT_QUICK_FILTER,
  parseEventIdSelectors,
  type EvtxBeforeLoadCriteria,
  type EvtxEventIdSelector,
  type EvtxGroupField,
  type EvtxQuickFilter,
} from "./evtx-filter";
import {
  defaultColumnConfig,
  moveColumn,
  sanitizeColumnConfig,
  toggleColumn,
  type EvtxColumnConfig,
  type EvtxColumnId,
} from "./evtx-columns";

type ServerFilter = EventQueryFilterSubset & {
  eventIds?: EvtxEventIdSelector[];
  eventIdMode?: "include";
};
function decimalIdParts(record: EvtxRecord): {
  valid: boolean;
  digits: string;
  raw: string;
} {
  const rawText = record.eventRecordIdText?.trim() ?? "";
  if (/^\d+$/.test(rawText) && !/^0+$/.test(rawText)) {
    return { valid: true, digits: rawText.replace(/^0+(?=\d)/, ""), raw: rawText };
  }
  if (!rawText && Number.isSafeInteger(record.eventRecordId) && record.eventRecordId !== 0) {
    const raw = String(record.eventRecordId);
    if (/^\d+$/.test(raw)) return { valid: true, digits: raw, raw };
  }
  return { valid: false, digits: "", raw: rawText };
}

function compareDecimalRecordIds(a: EvtxRecord, b: EvtxRecord): number {
  const aId = decimalIdParts(a);
  const bId = decimalIdParts(b);
  if (aId.valid !== bId.valid) return aId.valid ? -1 : 1;
  if (aId.valid) {
    if (aId.digits.length !== bId.digits.length) {
      return aId.digits.length < bId.digits.length ? -1 : 1;
    }
    const numericComparison = aId.digits < bId.digits ? -1 : aId.digits > bId.digits ? 1 : 0;
    if (numericComparison !== 0) return numericComparison;
  }
  return aId.raw.localeCompare(bId.raw);
}

function compareStoredRecords(a: EvtxRecord, b: EvtxRecord): number {
  return (
    a.timestampEpoch - b.timestampEpoch ||
    a.sourceLabel.localeCompare(b.sourceLabel) ||
    a.channel.localeCompare(b.channel) ||
    compareDecimalRecordIds(a, b) ||
    a.eventId - b.eventId
  );
}
function recordKey(record: EvtxRecord): string | null {
  const identity = decimalIdParts(record);
  if (!identity.valid) return null;
  return `${record.sourceLabel}\u0000${record.channel}\u0000decimal:${identity.digits}`;
}

/**
 * Producer-less records cannot be deduplicated safely: two events can have the same visible
 * fields. Selection still needs a refresh-local address, so use a full row fingerprint plus its
 * occurrence among equivalent rows. The occurrence makes identical rows distinct without turning
 * this fallback into a canonical deduplication key.
 */
const producerlessFingerprintCache = new WeakMap<EvtxRecord, string>();

function producerlessFingerprint(record: EvtxRecord): string {
  const cached = producerlessFingerprintCache.get(record);
  if (cached !== undefined) return cached;

  const fingerprint = JSON.stringify([
    record.sourceLabel,
    record.channel,
    record.timestampEpoch,
    record.provider,
    record.eventId,
    record.level,
    record.computer,
    record.message,
    record.eventData.map((field) => [field.name, field.value]),
    record.rawXml,
  ]);
  producerlessFingerprintCache.set(record, fingerprint);
  return fingerprint;
}

function selectionKeyForIndex(records: EvtxRecord[], index: number): string | null {
  const record = records[index];
  if (!record) return null;
  const stableKey = recordKey(record);
  if (stableKey !== null) return `stable:${stableKey}`;
  const fingerprint = producerlessFingerprint(record);
  let occurrence = 0;
  for (let current = 0; current < index; current++) {
    if (producerlessFingerprint(records[current]) === fingerprint) occurrence++;
  }
  return `transient:${fingerprint}\u0000${occurrence}`;
}

function findSelectionIndex(records: EvtxRecord[], key: string): number {
  const occurrences = new Map<string, number>();
  for (let index = 0; index < records.length; index++) {
    const record = records[index];
    const stableKey = recordKey(record);
    if (stableKey !== null) {
      if (`stable:${stableKey}` === key) return index;
      continue;
    }
    const fingerprint = producerlessFingerprint(record);
    const occurrence = occurrences.get(fingerprint) ?? 0;
    occurrences.set(fingerprint, occurrence + 1);
    if (`transient:${fingerprint}\u0000${occurrence}` === key) return index;
  }
  return -1;
}

function appendUniqueRecords(
  existing: EvtxRecord[],
  incoming: EvtxRecord[],
  options: { deduplicateProducerless?: boolean } = {}
): { records: EvtxRecord[]; droppedAgainstExisting: number } {
  const existingKeys = new Set(
    existing.map(recordKey).filter((key): key is string => key !== null)
  );
  const keys = new Set(existingKeys);
  const existingRecordSet = new Set(existing);
  const seenRecords = new Set(existing);
  const existingProducerlessFingerprints = options.deduplicateProducerless
    ? new Set(
        existing
          .filter((record) => recordKey(record) === null)
          .map(producerlessFingerprint)
      )
    : null;
  const producerlessFingerprints = existingProducerlessFingerprints
    ? new Set(existingProducerlessFingerprints)
    : null;
  const unique: EvtxRecord[] = [];
  let droppedAgainstExisting = 0;
  for (const record of incoming) {
    const key = recordKey(record);
    if (key === null) {
      // Stream reconciliation can present the same logical record as distinct objects in the
      // live batch and terminal reply. Only that boundary has enough context to compare fallback
      // fingerprints; ordinary merges must keep equivalent producer-less rows separate.
      if (seenRecords.has(record)) {
        if (existingRecordSet.has(record)) droppedAgainstExisting++;
        continue;
      }
      if (producerlessFingerprints !== null) {
        const fingerprint = producerlessFingerprint(record);
        if (producerlessFingerprints.has(fingerprint)) {
          if (existingProducerlessFingerprints?.has(fingerprint)) {
            droppedAgainstExisting++;
          }
          continue;
        }
        producerlessFingerprints.add(fingerprint);
      }
      seenRecords.add(record);
      unique.push(record);
      continue;
    }
    if (keys.has(key)) {
      if (existingKeys.has(key)) droppedAgainstExisting++;
      continue;
    }
    keys.add(key);
    unique.push(record);
  }
  return {
    records: [...existing, ...unique],
    droppedAgainstExisting,
  };
}
let preservedSelectedRecordKey: string | null = null;

const tailSequences = new Map<string, Set<number>>();
const tailSequenceSnapshots = new Map<string, Set<number>>();

function tailSequenceKey(requestId: string, channel: string): string {
  return `${requestId}\u0000${channel}`;
}

function aggregateTailMode(modes: EvtxLiveMode[]): EvtxLiveMode {
  const unique = new Set(modes);
  if (unique.size === 0) return "unsupported";
  if (unique.size > 1) return "mixed";
  return modes[0];
}

type TailStopOutcome = {
  requestId: string;
  channel: string;
  attempt: number;
  status?: EvtxTailStatus;
  error?: string;
};

// A stale cleanup failure stays visible until that exact request/channel stop succeeds. The key is
// intentionally request-scoped so a retry cannot remove a current tail's unrelated gap.
const staleTailStopFailures = new Map<string, string>();
const tailStopGapOwners = new Map<string, Set<string>>();

function rememberTailStopGapOwner(gap: string, owner: string): void {
  let owners = tailStopGapOwners.get(gap);
  if (!owners) {
    owners = new Set<string>();
    tailStopGapOwners.set(gap, owners);
  }
  owners.add(owner);
}

function forgetTailStopGapOwner(gap: string, owner: string): boolean {
  const owners = tailStopGapOwners.get(gap);
  if (!owners?.delete(owner)) return false;
  if (owners.size === 0) tailStopGapOwners.delete(gap);
  return owners.size === 0;
}

function canUpdateStaleTailGap(requestId: string): boolean {
  const state = useEvtxStore.getState();
  return (
    (state.tailRequestId === null || state.tailRequestId === requestId) &&
    (activeTailRequestId === null || activeTailRequestId === requestId)
  );
}

function reportStaleTailStopOutcome(outcome: TailStopOutcome): void {
  if (!isLatestTailStop(outcome)) return;
  const failureKey = tailSequenceKey(outcome.requestId, outcome.channel);
  if (outcome.error) {
    const gap = `${outcome.channel}: live tail stop failed (${outcome.error})`;
    const previousGap = staleTailStopFailures.get(failureKey);
    if (previousGap !== undefined && previousGap !== gap) {
      forgetTailStopGapOwner(previousGap, failureKey);
    }
    staleTailStopFailures.set(failureKey, gap);
    rememberTailStopGapOwner(gap, failureKey);
    if (!canUpdateStaleTailGap(outcome.requestId)) return;
    useEvtxStore.setState((state) => ({
      tailCoverageGaps: mergeCoverageGaps(
        state.tailCoverageGaps.filter((currentGap) => currentGap !== previousGap),
        [gap]
      ),
    }));
    return;
  }

  const gap = staleTailStopFailures.get(failureKey);
  if (!gap) return;
  staleTailStopFailures.delete(failureKey);
  if (!forgetTailStopGapOwner(gap, failureKey)) return;
  if (!canUpdateStaleTailGap(outcome.requestId)) return;
  useEvtxStore.setState((state) => ({
    tailCoverageGaps: state.tailCoverageGaps.filter((currentGap) => currentGap !== gap),
  }));
}

function observeStaleTailStop(requestId: string, channel: string): void {
  void stopTailRequest(requestId, channel).then(reportStaleTailStopOutcome);
}

// A failed stop belongs to the backend request that could not be stopped, not to whichever load
// happens to be current when the rejection arrives. Keeping this retry state outside the Zustand
// view prevents stale cleanup from contaminating a newer session while ensuring it is not lost.
const pendingTailStops = new Map<string, Set<string>>();
const tailStopLatestAttempts = new Map<string, number>();
const tailStopInFlight = new Map<string, Promise<TailStopOutcome>>();
let tailStopGeneration = 0;

function rememberTailStop(requestId: string, channel: string): void {
  let channels = pendingTailStops.get(requestId);
  if (!channels) {
    channels = new Set<string>();
    pendingTailStops.set(requestId, channels);
  }
  channels.add(channel);
}

function forgetTailStop(requestId: string, channel: string): void {
  const channels = pendingTailStops.get(requestId);
  channels?.delete(channel);
  if (channels?.size === 0) pendingTailStops.delete(requestId);
}

function stopTailRequest(requestId: string, channel: string): Promise<TailStopOutcome> {
  rememberTailStop(requestId, channel);
  const key = tailSequenceKey(requestId, channel);
  const existing = tailStopInFlight.get(key);
  if (existing) return existing;

  const attempt = ++tailStopGeneration;
  tailStopLatestAttempts.set(key, attempt);
  const operation = Promise.resolve()
    .then(() =>
      invoke<EvtxTailStatus>("evtx_stop_tail", {
        requestId,
        channel,
      })
    )
    .then(
      (status) => {
        if (tailStopLatestAttempts.get(key) === attempt) {
          tailStopInFlight.delete(key);
          forgetTailStop(requestId, channel);
          tailSequences.delete(key);
          tailSequenceSnapshots.delete(key);
        }
        return { requestId, channel, attempt, status };
      },
      (error: unknown) => {
        if (tailStopLatestAttempts.get(key) === attempt) {
          tailStopInFlight.delete(key);
          rememberTailStop(requestId, channel);
        }
        return {
          requestId,
          channel,
          attempt,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    );
  tailStopInFlight.set(key, operation);
  return operation;
}

function isLatestTailStop(outcome: TailStopOutcome): boolean {
  return tailStopLatestAttempts.get(tailSequenceKey(outcome.requestId, outcome.channel)) === outcome.attempt;
}

let requestGeneration = 0;
let activeRequestId = "initial";
let tailGeneration = 0;
let activeTailRequestId: string | null = null;
let activeTailSourceRequestId: string | null = null;
let activeTailChannels = new Set<string>();
const pendingTailStarts = new Map<string, Set<string>>();

function resolveTailStart(requestId: string, channel: string): void {
  const channels = pendingTailStarts.get(requestId);
  channels?.delete(channel);
  if (channels?.size === 0) pendingTailStarts.delete(requestId);
}

function captureTailSequenceSnapshot(requestId: string, channel: string): void {
  const key = tailSequenceKey(requestId, channel);
  tailSequenceSnapshots.set(key, new Set(tailSequences.get(key) ?? []));
}

function isCurrentTailStart(requestId: string, sourceRequestId: string): boolean {
  return (
    activeTailRequestId === requestId &&
    activeTailSourceRequestId === sourceRequestId &&
    isCurrentRequest(sourceRequestId)
  );
}

/**
 * Stops a backend tail whose start completed after its request was superseded. This deliberately
 * does not touch Zustand state: only the current start owns the visible tail identity.
 */
function cleanupStaleTailStart(
  requestId: string,
  sourceRequestId: string,
  channels: Iterable<string>
): void {
  if (isCurrentTailStart(requestId, sourceRequestId)) return;
  for (const channel of channels) {
    captureTailSequenceSnapshot(requestId, channel);
    observeStaleTailStop(requestId, channel);
  }
}

/** Detaches an existing start before assigning a newer tail request. */
function supersedeActiveTailStart(): void {
  const staleRequestId = activeTailRequestId;
  const staleChannels = new Set(activeTailChannels);
  activeTailRequestId = null;
  activeTailSourceRequestId = null;
  activeTailChannels = new Set<string>();
  if (!staleRequestId) return;

  for (const channel of staleChannels) {
    // A start still pending must be stopped after it resolves; stopping before it resolves can
    // race the backend registration and leave the newly-created worker orphaned.
    if (pendingTailStarts.get(staleRequestId)?.has(channel)) continue;
    captureTailSequenceSnapshot(staleRequestId, channel);
    observeStaleTailStop(staleRequestId, channel);
  }
}

function retryPendingTailStops(): void {
  for (const [requestId, channels] of pendingTailStops) {
    if (
      activeTailRequestId === requestId &&
      activeTailSourceRequestId === activeRequestId
    ) {
      continue;
    }
    for (const channel of channels) observeStaleTailStop(requestId, channel);
  }
}

function beginRequest(): string {
  const staleTailRequestId = activeTailRequestId;
  const staleTailChannels = new Set(activeTailChannels);
  const cleanupRequests = new Map<string, Set<string>>();
  for (const [requestId, channels] of pendingTailStops) {
    cleanupRequests.set(requestId, new Set(channels));
  }
  if (staleTailRequestId) {
    let channels = cleanupRequests.get(staleTailRequestId);
    if (!channels) {
      channels = new Set<string>();
      cleanupRequests.set(staleTailRequestId, channels);
    }
    for (const channel of staleTailChannels) {
      captureTailSequenceSnapshot(staleTailRequestId, channel);
      // A start still pending must be stopped after it resolves; stopping before it resolves can
      // race the backend registration and leave the newly-created worker orphaned.
      if (pendingTailStarts.get(staleTailRequestId)?.has(channel)) continue;
      channels.add(channel);
    }
  }
  activeTailRequestId = null;
  activeTailSourceRequestId = null;
  activeTailChannels = new Set<string>();
  activeRequestId = `event-log-${++requestGeneration}`;
  // A new request supersedes every stale tail cleanup represented above. Remove its old failure
  // records before clearing the gap-owner index, otherwise a later stop completion can retain
  // request-scoped state that no longer has a visible owner.
  for (const requestId of cleanupRequests.keys()) {
    const prefix = `${requestId}\u0000`;
    for (const failureKey of staleTailStopFailures.keys()) {
      if (failureKey.startsWith(prefix)) staleTailStopFailures.delete(failureKey);
    }
  }
  // Drop the visible tail identity before any asynchronous stale-stop completion can observe it.
  // Some load paths (notably channel enumeration) do not otherwise rewrite these fields.
  tailStopGapOwners.clear();
  useEvtxStore.setState({
    tailMode: null,
    tailRequestId: null,
    tailChannels: new Set<string>(),
    tailCoverageGaps: [],
  });
  for (const [requestId, channels] of cleanupRequests) {
    for (const channel of channels) observeStaleTailStop(requestId, channel);
  }
  // A superseded load can be waiting for a terminal event that will never arrive. Resolve those
  // waiters before dropping the map so stale callers can observe the new request and return.
  cancelAllPendingStreams();
  tailSequences.clear();
  return activeRequestId;
}

function isCurrentRequest(requestId: string): boolean {
  return requestId === activeRequestId;
}

function invokeEventQuery<T>(
  requestId: string,
  remoteMachine: string | null,
  channels: string[],
  maxEvents: number | null,
  filter: EventQueryFilterSubset
): Promise<T> {
  if (remoteMachine) {
    return invoke<T>("evtx_query_remote_channels", {
      machine: remoteMachine,
      channels,
      maxEvents,
      filter,
      requestId,
    });
  }

  return invoke<T>("evtx_query_channels", { channels, maxEvents, filter, requestId });
}
function mergeRecordsPreservingSelection(
  existing: EvtxRecord[],
  selectedRecordId: number | null,
  incoming: EvtxRecord[],
  options: { preserveMissingSelection?: boolean } = {}
): { records: EvtxRecord[]; selectedRecordId: number | null } {
  const selectedKey = preservedSelectedRecordKey;
  const selected =
    selectedKey === null
      ? selectedRecordId === null
        ? null
        : existing.find((record) => record.id === selectedRecordId) ?? null
      : (() => {
          const existingIndex = findSelectionIndex(existing, selectedKey);
          if (existingIndex >= 0) return existing[existingIndex];
          const incomingIndex = findSelectionIndex(incoming, selectedKey);
          return incomingIndex >= 0 ? incoming[incomingIndex] : null;
        })();
  const records = appendUniqueRecords(existing, incoming).records;
  records.sort(compareStoredRecords);
  for (let index = 0; index < records.length; index++) records[index].id = index;
  const selectedIdentity =
    selected === null
      ? null
      : selectedKey !== null
        ? selectedKey
        : selectionKeyForIndex(existing, existing.indexOf(selected));
  const remappedSelectedRecordId =
    selected === null
      ? null
      : selectedIdentity === null
        ? records.findIndex((record) => record === selected)
        : findSelectionIndex(records, selectedIdentity);
  if (selected !== null || selectedKey === null || !options.preserveMissingSelection) {
    preservedSelectedRecordKey = null;
  }
  return {
    records,
    selectedRecordId:
      remappedSelectedRecordId !== null && remappedSelectedRecordId >= 0
        ? remappedSelectedRecordId
        : null,
  };
}
function captureSelectedRecord(records: EvtxRecord[], selectedRecordId: number | null): void {
  const selectedIndex =
    selectedRecordId === null ? -1 : records.findIndex((record) => record.id === selectedRecordId);
  preservedSelectedRecordKey =
    selectedIndex < 0 ? null : selectionKeyForIndex(records, selectedIndex);
}
/** Builds the backend-owned merged timeline for the records currently shown in this workspace. */
export function buildUnifiedTimeline(
  records: EvtxRecord[],
  entries: LogEntry[] = []
): Promise<UnifiedTimeline> {
  if (
    records.some(
      (record) =>
        record.eventRecordId !== 0 &&
        !record.eventRecordIdText &&
        !Number.isSafeInteger(record.eventRecordId)
    )
  ) {
    return Promise.reject(new Error("EventRecordID exceeds JavaScript safe integer precision"));
  }
  const transportRecords = records.map((record) => ({
    ...record,
    eventRecordId: record.eventRecordIdText ?? String(record.eventRecordId),
  }));
  return invoke<unknown>("evtx_build_unified_timeline", {
    entries,
    records: transportRecords,
  }).then(assertUnifiedTimelineShape);
}
export type EvtxSourceMode = "files" | "live" | null;
export type EvtxSortField = "time" | "eventId" | "level" | "provider" | "channel";
export type EvtxSortDirection = "asc" | "desc";


/**
 * Builds the filter handed to the backend, which compiles it to XPath.
 *
 * Only criteria with an exact XPath equivalent are pushed down. Text, case sensitivity, visible
 * column scope and hide mode stay local; sending an approximation would silently broaden or narrow
 * the query compared with the rows the operator sees.
 */
function buildServerFilter(
  timeWindow: EvtxTimeWindow,
  filterEventIds: string,
  filterLevels: Set<EvtxLevel>
): ServerFilter {
  const filter: ServerFilter =
    timeWindow === "all"
      ? {}
      : { time: { kind: "last", milliseconds: EVTX_TIME_WINDOW_MS[timeWindow] } };

  const parsedIds = parseEventIdSelectors(filterEventIds);
  if (parsedIds.selectors.length > 0 && !parsedIds.invalid) {
    filter.eventIds = parsedIds.selectors;
    filter.eventIdMode = "include";
  }

  // Information includes an unbounded provider-specific raw-level domain (6..254). The parser
  // intentionally caps XPath OR expressions, so leave level selection local whenever Information
  // is selected rather than issuing an over-budget or incomplete server predicate.
  if (
    filterLevels.size > 0 &&
    filterLevels.size < ALL_LEVELS.length &&
    !filterLevels.has("Information")
  ) {
    filter.levels = [...filterLevels].map((level) => ALL_LEVELS.indexOf(level) + 1);
  }
  return filter;
}
function hasInvalidEventIdFilter(raw: string): boolean {
  const trimmed = raw.trim();
  return trimmed.length > 0 && parseEventIdSelectors(trimmed).invalid;
}

const ALL_LEVELS: EvtxLevel[] = ["Critical", "Error", "Warning", "Information", "Verbose"];
type FilterSnapshot = {
  timeWindow: EvtxTimeWindow;
  filterEventIds: string;
  filterLevels: Set<EvtxLevel>;
};

function snapshotFilterInputs(
  timeWindow: EvtxTimeWindow,
  filterEventIds: string,
  filterLevels: Set<EvtxLevel>
): FilterSnapshot {
  return {
    timeWindow,
    filterEventIds,
    filterLevels: new Set(filterLevels),
  };
}

interface EvtxState {
  records: EvtxRecord[];
  channels: EvtxChannelInfo[];
  sourceMode: EvtxSourceMode;
  /** Paths currently represented by `records`; used to protect export destinations. */
  sourcePaths: string[];
  /** Remote target used for live queries; credentials stay in the Windows session only. */
  remoteMachine: string | null;
  isLoading: boolean;
  loadingChannel: string | null;
  loadingProgress: number | null;
  loadStartTime: number | null;
  loadElapsedMs: number | null;
  loadError: string | null;
  coverageGaps: string[];
  sourceManifest: EventLogSourceManifest | null;
  selectedChannels: Set<string>;
  loadedChannels: Set<string>;
  /**
   * Structured parser locations behind `coverageGaps`. The legacy strings remain for live
   * streaming diagnostics, while file recovery gaps retain chunk/record identity here.
   */
  coverageDetails: EvtxCoverageGap[];
  archiveMembers: EvtxArchiveMember[];
  filterLevels: Set<EvtxLevel>;
  filterEventIds: string;
  filterSearch: string;
  /** The on-load and after-load quick criteria are retained across every refetch. */
  quickFilter: EvtxQuickFilter;
  timeWindow: EvtxTimeWindow;
  /** Which clock event times are shown in. */
  timeZoneMode: EvtxTimeZoneMode;
  columnConfig: EvtxColumnConfig;
  groupBy: EvtxGroupField[];
  collapsedGroups: Set<string>;
  sortField: EvtxSortField;
  sortDirection: EvtxSortDirection;
  selectedRecordId: number | null;
loadGeneration: number;
  tailMode: EvtxLiveMode | null;
  tailRequestId: string | null;
  tailChannels: Set<string>;
  tailCoverageGaps: string[];
  parseFiles: (paths: string[]) => Promise<void>;
  parseManifest: (manifest: EventLogSourceManifest) => Promise<void>;
  enumerateChannels: () => Promise<void>;
  enumerateLocalChannels: () => Promise<void>;
  enumerateRemoteChannels: (machine: string) => Promise<void>;
  queryChannels: (channels: string[], maxEvents?: number) => Promise<void>;
  loadSelectedChannels: () => Promise<void>;
  refreshLoadedChannels: () => Promise<void>;
  startLiveTail: () => Promise<EvtxTailStatus[]>;
  stopLiveTail: () => Promise<void>;
  clearChannel: (channel: string, confirmed: boolean) => Promise<EvtxClearStatusResult>;
  setLoadError: (error: string | null) => void;
  setTimeZoneMode: (mode: EvtxTimeZoneMode) => void;
  setSelectedChannels: (channels: Set<string>) => void;
  toggleChannel: (channel: string) => void;
  selectAllChannels: () => void;
  deselectAllChannels: () => void;
  setFilterLevels: (levels: Set<EvtxLevel>) => void;
  toggleFilterLevel: (level: EvtxLevel) => void;
  setFilterEventIds: (eventIds: string) => void;
  setBeforeLoadCriteria: (criteria: EvtxBeforeLoadCriteria) => void;
  setFilterSearch: (search: string) => void;
  setQuickFilter: (filter: EvtxQuickFilter) => void;
  setTimeWindow: (window: EvtxTimeWindow) => void;
  setGroupBy: (fields: EvtxGroupField[]) => void;
  toggleColumnVisible: (id: EvtxColumnId) => void;
  moveColumnBy: (id: EvtxColumnId, direction: -1 | 1) => void;
  resetColumns: () => void;
  toggleGroup: (key: string) => void;
  setSortField: (field: EvtxSortField) => void;
  setSortDirection: (direction: EvtxSortDirection) => void;
  setSelectedRecordId: (id: number | null) => void;
  reset: () => void;
}

function hasUsableChannelData(
  recordCount: number,
  eventCount: number,
  gapCount: number,
  streamIncomplete: boolean
): boolean {
  return !streamIncomplete && (gapCount === 0 || recordCount > 0 || eventCount > 0);
}
function hasStructuredEvtxBasename(value: string, channel: string): boolean {
  const lowerValue = value.toLowerCase();
  const lowerBasename = `${channel}.evtx`.toLowerCase();
  for (let start = 0; start <= lowerValue.length - lowerBasename.length; start++) {
    if (start > 0 && value[start - 1] !== "/" && value[start - 1] !== "\\") continue;
    if (!lowerValue.startsWith(lowerBasename, start)) continue;
    const end = start + lowerBasename.length;
    const suffix = value[end];
    if (suffix === undefined || suffix === ":" || suffix.trim() === "") return true;
  }
  return false;
}

function coverageBelongsToChannel(
  value: string,
  channel: string,
  remoteMachine: string | null
): boolean {
  const source = remoteMachine ? `${remoteMachine}/${channel}` : channel;
  if (value === source || value.startsWith(`${source}:`)) return true;

  // Structured file coverage keeps the source path (for example
  // `/logs/Application.evtx`) rather than the live channel banner. Match only an exact
  // basename, not arbitrary channel substrings such as `App` in `Application.evtx`.
  return hasStructuredEvtxBasename(value, channel);
}

function applyParseResult(
  result: EvtxParseResult,
  sourceMode: EvtxSourceMode,
  sourceCoverage: readonly EventLogSourceCoverage[] = [],
): Partial<EvtxState> {
  const channelNames = new Set(result.channels.map((c) => c.name));
  const coverageMessages = [
    ...sourceCoverageMessages(sourceCoverage),
    ...sourceCoverageMessages(result.coverage ?? []),
  ];
  return {
    records: result.records,
    channels: result.channels,
    sourceMode,
    isLoading: false,
    loadError: null,
    coverageGaps: [
      ...new Set([
        ...result.errorMessages,
        ...coverageMessages,
        ...(result.coverageGaps ?? []).map(formatCoverageGap),
      ]),
    ],
    coverageDetails: result.coverageGaps ?? [],
    archiveMembers: result.archiveMembers ?? [],
    selectedChannels: channelNames,
    selectedRecordId: null,
    tailMode: null,
    tailRequestId: null,
    tailChannels: new Set<string>(),
    tailCoverageGaps: [],
  };
}

export const useEvtxStore = create<EvtxState>()((set, get) => {
  let refreshScheduled = false;
  let refreshRequested = false;
  const refreshBeforeLoad = () => {
    refreshRequested = true;
    if (refreshScheduled) return;
    refreshScheduled = true;
    queueMicrotask(() => {
      refreshScheduled = false;
      const state = get();
      if (state.isLoading) return;
      if (state.sourceMode === "live" && state.loadedChannels.size > 0) {
        refreshRequested = false;
        void state.refreshLoadedChannels();
      } else if (!state.isLoading) {
        refreshRequested = false;
      }
    });
  };

  return ({
  records: [],
  remoteMachine: null,
  channels: [],
  sourceMode: null,
  sourcePaths: [],
  isLoading: false,
  loadError: null,
  loadingChannel: null,
  loadingProgress: null,
  loadStartTime: null,
  loadElapsedMs: null,
  loadGeneration: 0,
  coverageGaps: [],
  coverageDetails: [],
  archiveMembers: [],
  sourceManifest: null,
  selectedChannels: new Set<string>(),
  loadedChannels: new Set<string>(),
  filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
  filterEventIds: "",
  filterSearch: "",
  quickFilter: { ...DEFAULT_QUICK_FILTER },
  timeZoneMode: "local" as EvtxTimeZoneMode,
  timeWindow: "24h",
  columnConfig: defaultColumnConfig(),
  groupBy: [],
  collapsedGroups: new Set<string>(),
  sortField: "time",
  sortDirection: "asc",
  selectedRecordId: null,
  tailMode: null,
  tailRequestId: null,
  tailChannels: new Set<string>(),
  tailCoverageGaps: [],
  parseFiles: async (paths) => {
    const previousTimeWindow = get().timeWindow;
    const generation = get().loadGeneration + 1;
    const requestId = beginRequest();
    preservedSelectedRecordKey = null;
    invalidateAllStreamedRecords(requestId);
    refreshRequested = false;
    set({
      loadGeneration: generation,
      records: [],
      channels: [],
      sourceMode: null,
      sourcePaths: [],
      remoteMachine: null,
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      coverageGaps: [],
      coverageDetails: [],
      archiveMembers: [],
      sourceManifest: null,
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      tailCoverageGaps: [],
      timeWindow: "all",
      isLoading: true,
      loadError: null,
    });
    try {
      const result = await invoke<EvtxParseResult>("evtx_parse_files", { paths });
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const checked = assertParseResultShape(result);
      set({
        ...applyParseResult(
          {
            ...result,
            errorMessages: checked.errorMessages,
            coverageGaps: checked.coverageGaps,
            coverage: checked.coverage,
            archiveMembers: checked.archiveMembers,
          },
          "files",
        ),
        sourcePaths: [...paths],
        loadGeneration: generation,
      });
    } catch (error) {
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const message = error instanceof Error ? error.message : String(error);
      set({
        isLoading: false,
        loadError: message,
        sourceManifest: null,
        coverageDetails: [],
        timeWindow: previousTimeWindow,
      });
    }
  },

  parseManifest: async (manifest) => {
    const previousTimeWindow = get().timeWindow;
    const generation = get().loadGeneration + 1;
    const requestId = beginRequest();
    preservedSelectedRecordKey = null;
    invalidateAllStreamedRecords(requestId);
    refreshRequested = false;
    set({
      loadGeneration: generation,
      records: [],
      channels: [],
      sourceMode: null,
      sourcePaths: manifest.entries.map((entry) => entry.path),
      remoteMachine: null,
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      coverageGaps: [],
      coverageDetails: [],
      archiveMembers: [],
      sourceManifest: manifest,
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      tailCoverageGaps: [],
      timeWindow: "all",
      isLoading: true,
      loadError: null,
    });
    try {
      const result = await invoke<EvtxParseResult>("evtx_parse_manifest", { manifest });
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const checked = assertParseResultShape(result);
      set({
        ...applyParseResult(
          {
            ...result,
            errorMessages: checked.errorMessages,
            coverageGaps: checked.coverageGaps,
            coverage: checked.coverage,
            archiveMembers: checked.archiveMembers,
          },
          "files",
          manifest.coverage,
        ),
        sourceManifest: manifest,
        loadGeneration: generation,
      });
    } catch (error) {
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const message = error instanceof Error ? error.message : String(error);
      set({
        isLoading: false,
        loadError: message,
        sourceManifest: manifest,
        coverageGaps: sourceCoverageMessages(manifest.coverage),
        timeWindow: previousTimeWindow,
      });
    }
  },

  enumerateChannels: async () => {
    const generation = get().loadGeneration + 1;
    const requestId = beginRequest();
    captureSelectedRecord(get().records, get().selectedRecordId);
    invalidateAllStreamedRecords(requestId);
    set({
      loadGeneration: generation,
      isLoading: true,
      loadError: null,
      sourceManifest: null,
      coverageDetails: [],
      archiveMembers: [],
      timeWindow:
        get().sourceMode === null && get().timeWindow === "all" ? "24h" : get().timeWindow,
    });
    const filterSnapshot = snapshotFilterInputs(
      get().timeWindow,
      get().filterEventIds,
      get().filterLevels
    );
    try {
      const remoteMachine = get().remoteMachine;
      const channels = remoteMachine
        ? await invoke<EvtxChannelInfo[]>("evtx_enumerate_remote_channels", {
            machine: remoteMachine,
          })
        : await invoke<EvtxChannelInfo[]>("evtx_enumerate_channels");
      if (!isCurrentRequest(requestId)) return;

      // Step 2: Auto-query the core Windows Logs channels immediately
      const coreChannels = ["Application", "System", "Security", "Setup"];
      const availableCore = coreChannels.filter((c) =>
        channels.some((ch) => ch.name === c)
      );
      let updatedChannels = channels;
      let loadError: string | null = null;
      const emptyRemoteGaps =
        remoteMachine && channels.length === 0
          ? [`${remoteMachine}: remote source is empty (no channels available)`]
          : [];

      // Show channels immediately, then load events in parallel
      const selectedNames = new Set(availableCore);
      const startTime = performance.now();
      captureSelectedRecord(get().records, get().selectedRecordId);
      set({
        channels: updatedChannels,
        sourceMode: "live",
        sourcePaths: [],
        remoteMachine,
        sourceManifest: null,
        isLoading: true,
        loadError: null,
        coverageGaps: emptyRemoteGaps,
        loadStartTime: startTime,
        coverageDetails: [],
        archiveMembers: [],
        loadElapsedMs: null,
        selectedChannels: selectedNames,
        loadedChannels: new Set<string>(),
        records: [],
        selectedRecordId: null,
      });
      // Live query records arrive through the batch event. This path invokes the backend directly
      // rather than through queryChannels, so it must drain the same stream before merging.
      const mergeResult = (ch: string, reconciliation: StreamReconciliation) => {
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        const state = get();
        const { checked, result, records, gaps } = reconciliation;
        const merged = mergeRecordsPreservingSelection(
          state.records,
          state.selectedRecordId,
          records
        );

        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const newChannels = state.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const newLoaded = new Set(state.loadedChannels);
        const channelHasUsableData = hasUsableChannelData(
          records.length,
          result.channels.find((c) => c.name === ch)?.eventCount ?? 0,
          gaps.length,
          reconciliation.missingSequences.length > 0 || reconciliation.recordShortfall
        );
        if (channelHasUsableData) newLoaded.add(ch);
        else newLoaded.delete(ch);

        set({
          ...merged,
          channels: newChannels,
          loadedChannels: newLoaded,
          loadElapsedMs: performance.now() - startTime,
          // Channels load one at a time and each may report its own gaps, so they accumulate
          // rather than replace. Deduplicated because re-querying a channel would otherwise
          // repeat the same line.
          coverageGaps: mergeCoverageGaps(state.coverageGaps, gaps),
          coverageDetails: mergeStructuredCoverageGaps(
            state.coverageDetails,
            checked.coverageGaps
          ),
        });
      };
      const promises = availableCore.map(async (ch) => {
        const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
        resetStreamedRecords([ch], requestId);
        try {
          const result = await invokeEventQuery<EvtxParseResult>(
            requestId,
            remoteMachine,
            [ch],
            hasInvalidEventIdFilter(filterSnapshot.filterEventIds) ? 0 : null,
            buildServerFilter(
              filterSnapshot.timeWindow,
              filterSnapshot.filterEventIds,
              filterSnapshot.filterLevels
            )
          );
          observeStreamReply(ch, requestId, { kind: "success" });
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          await waitForStreamReconciliation(ch, requestId);
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          const reconciliation = reconcileStreamedResult(ch, requestId, result, context);
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          mergeResult(ch, reconciliation);
          acknowledgeStreamedRecords(ch, requestId);
        } catch (e) {
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          const msg = e instanceof Error ? e.message : String(e);
          observeStreamReply(ch, requestId, { kind: "error", message: msg });
          await waitForStreamReconciliation(ch, requestId);
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          console.warn(`[evtx] Failed to query ${context}: ${msg}`);
          if (!loadError) loadError = `${context}: ${msg}`;
          drainStreamedRecords(ch, requestId);
          acknowledgeStreamedRecords(ch, requestId);
          set((s) => ({
            coverageGaps: mergeCoverageGaps(s.coverageGaps, [
              `${context}: not read (${msg})`,
            ]),
          }));
        }
      });
      await Promise.all(promises);
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const finalState = get();
      const remoteQueryFailed =
        remoteMachine !== null &&
        (availableCore.length === 0
          ? channels.length === 0
          : finalState.loadedChannels.size === 0 && finalState.coverageGaps.length > 0);
      set({
        sourceMode: remoteQueryFailed ? null : "live",
        isLoading: false,
        loadingChannel: null,
        loadingProgress: null,
        loadElapsedMs: performance.now() - startTime,
        loadError,
      });
    if (refreshRequested) refreshBeforeLoad();
  } catch (error) {
    if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const message = error instanceof Error ? error.message : String(error);
      const remoteMachine = get().remoteMachine;
      const remoteGap = remoteMachine
        ? message.startsWith(`${remoteMachine}:`)
          ? message
          : message.includes("access denied") || message.includes("credentials rejected")
            ? `${remoteMachine}: remote source access denied (${message})`
            : message.includes("unavailable")
              ? `${remoteMachine}: remote source unavailable (${message})`
              : `${remoteMachine}: remote source query failed (${message})`
        : null;
      set((state) => ({
        isLoading: false,
        loadError: message,
        coverageGaps: remoteGap
          ? mergeCoverageGaps(state.coverageGaps, [remoteGap])
          : state.coverageGaps,
      }));
    }
  },

  enumerateLocalChannels: async () => {
    set({
      remoteMachine: null,
      channels: [],
      records: [],
      sourceMode: null,
      sourceManifest: null,
      coverageGaps: [],
      coverageDetails: [],
      archiveMembers: [],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
    });
    await get().enumerateChannels();
  },
  enumerateRemoteChannels: async (machine) => {
    beginRequest();
    set({
      remoteMachine: null,
      channels: [],
      records: [],
      sourceMode: null,
      sourceManifest: null,
      coverageGaps: [],
      coverageDetails: [],
      archiveMembers: [],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      isLoading: false,
      loadError: null,
    });
    const normalized = machine.trim().replace(/^[/\\]+/, "");
    if (!normalized || /[\u0000-\u001f\u007f]/.test(normalized)) {
      set({
        isLoading: false,
        loadError: "Enter a valid remote computer name.",
      });
      return;
    }
    set({
      remoteMachine: normalized,
      channels: [],
      records: [],
      sourceMode: null,
      sourceManifest: null,
      coverageGaps: [],
      coverageDetails: [],
      archiveMembers: [],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      loadError: null,
    });
    await get().enumerateChannels();
  },

  queryChannels: async (channels, maxEvents) => {
    const generation = get().loadGeneration + 1;
    const requestId = beginRequest();
    captureSelectedRecord(get().records, get().selectedRecordId);
    set({
      isLoading: true,
      loadError: null,
      sourceManifest: null,
      archiveMembers: [],
      selectedRecordId: null,
      loadGeneration: generation,
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      tailCoverageGaps: [],
    });
    const remoteMachine = get().remoteMachine;
    const filterSnapshot = snapshotFilterInputs(
      get().timeWindow,
      get().filterEventIds,
      get().filterLevels
    );
    // One request per channel rather than one request for all of them. The backend collects a
    // whole request's records into a single vector before replying, so asking for forty channels
    // at once held every event of every channel in memory twice, once per channel and once in the
    // combined vector, before anything reached the screen.
    //
    // It also isolates failure. A single request fails as a whole, so one unreadable channel threw
    // away the results of every channel queried alongside it and left the view empty.
    let loadError: string | null = null;

    // Anything left over from an earlier attempt at these channels is dropped, so a retry cannot
    // count a previous run's batches towards this one.
    invalidateAllStreamedRecords(requestId);
    for (const channel of channels) resetStreamedRecords([channel], requestId);

    const results = await Promise.all(
      channels.map(async (ch) => {
        try {
          const result = await invokeEventQuery<EvtxParseResult>(
            requestId,
            remoteMachine,
            [ch],
            hasInvalidEventIdFilter(filterSnapshot.filterEventIds) ? 0 : maxEvents ?? null,
            buildServerFilter(
              filterSnapshot.timeWindow,
              filterSnapshot.filterEventIds,
              filterSnapshot.filterLevels
            )
          );
          observeStreamReply(ch, requestId, { kind: "success" });
          return { channel: ch, result, error: null as string | null };
        } catch (e) {
          const message = e instanceof Error ? e.message : String(e);
          observeStreamReply(ch, requestId, { kind: "error", message });
          const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
          console.warn(`[evtx] Failed to query ${context}: ${message}`);
          if (!loadError) loadError = `${context}: ${message}`;
          return { channel: ch, result: null, error: message };
        }
      })
    );
    if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
    for (const { channel, result, error } of results) {
      if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
      const context = remoteMachine ? `${remoteMachine}/${channel}` : channel;
      try {
        if (!result) {
          await waitForStreamReconciliation(channel, requestId);
          if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
          drainStreamedRecords(channel, requestId);
          acknowledgeStreamedRecords(channel, requestId);
          set((s) => ({
            coverageGaps: mergeCoverageGaps(s.coverageGaps, [
              `${context}: not read (${error ?? "unknown error"})`,
            ]),
          }));
          continue;
        }
        await waitForStreamReconciliation(channel, requestId);
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        const reconciliation = reconcileStreamedResult(channel, requestId, result, context);
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        const { checked, records } = reconciliation;
        const state = get();
        const merged = mergeRecordsPreservingSelection(
          state.records,
          state.selectedRecordId,
          records
        );
        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const updatedChannels = state.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const reportedGaps = reconciliation.gaps;
        const newLoaded = new Set(state.loadedChannels);
        const channelHasUsableData = hasUsableChannelData(
          records.length,
          result.channels.find((c) => c.name === channel)?.eventCount ?? 0,
          reportedGaps.length,
          reconciliation.missingSequences.length > 0 || reconciliation.recordShortfall
        );
        if (channelHasUsableData) newLoaded.add(channel);
        else newLoaded.delete(channel);
        const priorGaps = state.coverageGaps.filter(
          (gap) => !coverageBelongsToChannel(gap, channel, remoteMachine)
        );
        set({
          ...merged,
          channels: updatedChannels,
          loadedChannels: newLoaded,
          coverageGaps: mergeCoverageGaps(priorGaps, reportedGaps),
          coverageDetails: mergeStructuredCoverageGaps(
            state.coverageDetails.filter((detail) =>
              !coverageBelongsToChannel(detail.source, channel, remoteMachine)
            ),
            checked.coverageGaps
          ),
        });
        acknowledgeStreamedRecords(channel, requestId);
      } catch (processingError) {
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        drainStreamedRecords(channel, requestId);
        acknowledgeStreamedRecords(channel, requestId);
        const message =
          processingError instanceof Error ? processingError.message : String(processingError);
        console.warn(`[evtx] Failed to process ${context}: ${message}`);
        if (!loadError) loadError = `${context}: ${message}`;
        set((s) => ({
          coverageGaps: mergeCoverageGaps(s.coverageGaps, [`${context}: not read (${message})`]),
        }));
      }
    }

    set({ isLoading: false, loadError });
    if (refreshRequested && get().sourceMode === "live") {
      refreshRequested = false;
      const refreshChannels = [...new Set([...channels, ...get().loadedChannels])];
      set((s) => ({
        records: s.records.filter((record) => !refreshChannels.includes(record.channel)),
        loadedChannels: new Set(
          [...s.loadedChannels].filter((channel) => !refreshChannels.includes(channel))
        ),
        sourceManifest: null,
        coverageGaps: s.coverageGaps.filter(
          (gap) =>
            !refreshChannels.some((channel) =>
              coverageBelongsToChannel(gap, channel, s.remoteMachine)
            )
        ),
        coverageDetails: s.coverageDetails.filter(
          (detail) =>
            !refreshChannels.some((channel) =>
              coverageBelongsToChannel(detail.source, channel, s.remoteMachine)
            )
        ),
      }));
      void get().queryChannels(refreshChannels, maxEvents);
    } else {
      refreshRequested = false;
    }
  },
  loadSelectedChannels: async () => {
    const state = get();
    const unloaded = [...state.selectedChannels].filter(
      (channel) => !state.loadedChannels.has(channel)
    );
    if (unloaded.length === 0) return;
    await get().queryChannels(unloaded);
  },
  refreshLoadedChannels: async () => {
    const state = get();
    const loaded = [...state.loadedChannels];
    if (loaded.length === 0) return;
    const requestId = beginRequest();
    const generation = state.loadGeneration + 1;
    const remoteMachine = state.remoteMachine;
    const startTime = performance.now();
    captureSelectedRecord(get().records, get().selectedRecordId);
    invalidateAllStreamedRecords(requestId);
    set({
      records: [],
      loadedChannels: new Set<string>(),
      selectedRecordId: null,
      sourceManifest: null,
      loadGeneration: generation,
      isLoading: true,
      loadError: null,
      loadStartTime: startTime,
      loadElapsedMs: null,
      coverageGaps: [],
      coverageDetails: [],
      archiveMembers: [],
    });
    const filterSnapshot = snapshotFilterInputs(
      get().timeWindow,
      get().filterEventIds,
      get().filterLevels
    );
    for (const channel of loaded) resetStreamedRecords([channel], requestId);
    // Refresh invokes the streaming command directly, so drain its batch before merging the
    // command reply (which intentionally carries only records not emitted in batches).
    const promises = loaded.map(async (ch) => {
      const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
      try {
        resetStreamedRecords([ch], requestId);
        const result = await invokeEventQuery<EvtxParseResult>(
          requestId,
          remoteMachine,
          [ch],
          hasInvalidEventIdFilter(filterSnapshot.filterEventIds) ? 0 : null,
          buildServerFilter(
            filterSnapshot.timeWindow,
            filterSnapshot.filterEventIds,
            filterSnapshot.filterLevels
          )
        );
        observeStreamReply(ch, requestId, { kind: "success" });
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        await waitForStreamReconciliation(ch, requestId);
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        const reconciliation = reconcileStreamedResult(ch, requestId, result, context);
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        const { checked, records } = reconciliation;
        const s = get();
        const merged = mergeRecordsPreservingSelection(
          s.records,
          s.selectedRecordId,
          records
        );
        const countMap = new Map(result.channels.map((c) => [c.name, c.eventCount]));
        const newChannels = s.channels.map((c) => ({
          ...c,
          eventCount: countMap.get(c.name) ?? c.eventCount,
        }));
        const reportedGaps = reconciliation.gaps;
        const newLoaded = new Set(s.loadedChannels);
        const channelHasUsableData = hasUsableChannelData(
          records.length,
          result.channels.find((c) => c.name === ch)?.eventCount ?? 0,
          reportedGaps.length,
          reconciliation.missingSequences.length > 0 || reconciliation.recordShortfall
        );
        if (channelHasUsableData) newLoaded.add(ch);
        else newLoaded.delete(ch);

        set({
          ...merged,
          channels: newChannels,
          loadedChannels: newLoaded,
          loadElapsedMs: performance.now() - startTime,
          coverageGaps: mergeCoverageGaps(s.coverageGaps, reportedGaps),
          coverageDetails: mergeStructuredCoverageGaps(s.coverageDetails, checked.coverageGaps),
        });
      } catch (e) {
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        observeStreamReply(
          ch,
          requestId,
          { kind: "error", message: e instanceof Error ? e.message : String(e) }
        );
        await waitForStreamReconciliation(ch, requestId);
        if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
        drainStreamedRecords(ch, requestId);
        acknowledgeStreamedRecords(ch, requestId);
        const message = e instanceof Error ? e.message : String(e);
        const context = remoteMachine ? `${remoteMachine}/${ch}` : ch;
        console.warn(`[evtx] Refresh failed for ${context}: ${message}`);
        // Recorded, not only logged. The refresh cleared the previous gaps, so a silent failure
        // here presents a view that is missing a whole channel as complete.
        set((s) => ({
          coverageGaps: mergeCoverageGaps(s.coverageGaps, [
            `${context}: not read (${message})`,
          ]),
          loadError: s.loadError ?? `${context}: ${message}`,
        }));
      }
    });
    await Promise.all(promises);
    if (!isCurrentRequest(requestId) || get().loadGeneration !== generation) return;
    const finalState = get();
    const remoteRefreshFailed =
      remoteMachine !== null &&
      finalState.loadedChannels.size === 0 &&
      finalState.coverageGaps.length > 0;
    set({
      sourceMode: remoteRefreshFailed ? null : finalState.sourceMode,
      isLoading: false,
      loadingChannel: null,
      loadingProgress: null,
      loadElapsedMs: performance.now() - startTime,
    });
    if (refreshRequested) refreshBeforeLoad();
  },
  startLiveTail: async () => {
    const state = get();
    if (state.sourceMode !== "live") return [];
    const channels = [...state.loadedChannels];
    if (channels.length === 0) return [];
    tailStopGapOwners.clear();
    set({ tailCoverageGaps: [] });

    const sourceRequestId = activeRequestId;
    const filterSnapshot = snapshotFilterInputs(
      state.timeWindow,
      state.filterEventIds,
      state.filterLevels
    );
    supersedeActiveTailStart();
    retryPendingTailStops();

    const requestId = `event-log-tail-${++tailGeneration}`;
    const remoteMachine = state.remoteMachine;
    activeTailRequestId = requestId;
    activeTailSourceRequestId = sourceRequestId;
    activeTailChannels = new Set(channels);
    pendingTailStarts.set(requestId, new Set(channels));
    const startedChannels = new Set<string>();
    const statuses = await Promise.all(
      channels.map(async (channel) => {
        try {
          const status = await invoke<EvtxTailStatus>("evtx_start_tail", {
            channel,
            requestId,
            filter: buildServerFilter(
              filterSnapshot.timeWindow,
              filterSnapshot.filterEventIds,
              filterSnapshot.filterLevels
            ),
            remoteMachine,
          });
          startedChannels.add(channel);
          resolveTailStart(requestId, channel);
          if (!isCurrentTailStart(requestId, sourceRequestId)) {
            cleanupStaleTailStart(requestId, sourceRequestId, [channel]);
          }
          return status;
        } catch (error) {
          resolveTailStart(requestId, channel);
          const message = error instanceof Error ? error.message : String(error);
          return {
            requestId,
            channel,
            mode: "unsupported" as const,
            active: false,
            nextSequence: 0,
            coverageGaps: [`${channel}: live tail unavailable (${message})`],
          };
        }
      })
    );
    if (!isCurrentTailStart(requestId, sourceRequestId)) {
      cleanupStaleTailStart(requestId, sourceRequestId, startedChannels);
      pendingTailStarts.delete(requestId);
      return [];
    }
    const modes = statuses.map((status) => status.mode);
    const gaps = statuses.flatMap((status) => status.coverageGaps);
    const currentTailChannels = new Set(
      statuses.filter((status) => status.active).map((status) => status.channel)
    );
    activeTailChannels = currentTailChannels;
    pendingTailStarts.delete(requestId);
    set((current) => ({
      tailMode: aggregateTailMode(modes),
      tailRequestId: requestId,
      tailChannels: new Set(currentTailChannels),
      tailCoverageGaps: mergeCoverageGaps(current.tailCoverageGaps, gaps),
    }));
    return statuses;
  },
  stopLiveTail: async () => {
    const state = get();
    const requestId = state.tailRequestId;
    const sourceRequestId = activeRequestId;
    if (!requestId) return;
    const channels = [...state.tailChannels];
    const sequenceSnapshots = new Map(
      channels.map((channel) => {
        const key = tailSequenceKey(requestId, channel);
        const received = new Set(
          tailSequenceSnapshots.get(key) ?? tailSequences.get(key) ?? []
        );
        tailSequenceSnapshots.set(key, received);
        return [channel, received] as const;
      })
    );
    const outcomes = await Promise.all(
      channels.map((channel) => stopTailRequest(requestId, channel))
    );
    const current = get();
    if (
      current.tailRequestId !== requestId ||
      activeRequestId !== sourceRequestId ||
      (activeTailRequestId !== null && activeTailRequestId !== requestId)
    ) {
      for (const channel of channels) {
        tailSequences.delete(tailSequenceKey(requestId, channel));
      }
      return;
    }

    const successfulChannels = new Set<string>();
    const clearedGaps: string[] = [];
    const finalGaps: string[] = [];
    for (const outcome of outcomes) {
      if (!isLatestTailStop(outcome)) continue;
      if (outcome.error) {
        const gap = `${outcome.channel}: live tail stop failed (${outcome.error})`;
        rememberTailStopGapOwner(gap, tailSequenceKey(requestId, outcome.channel));
        finalGaps.push(gap);
        continue;
      }
      successfulChannels.add(outcome.channel);
      const failureKey = tailSequenceKey(requestId, outcome.channel);
      const previousGap = staleTailStopFailures.get(failureKey);
      if (previousGap) {
        staleTailStopFailures.delete(failureKey);
        if (forgetTailStopGapOwner(previousGap, failureKey)) {
          clearedGaps.push(previousGap);
        }
      }
      tailSequenceSnapshots.delete(failureKey);
      if (!outcome.status) continue;
      const received = sequenceSnapshots.get(outcome.channel) ?? new Set<number>();
      const missingSequences = Array.from(
        { length: outcome.status.nextSequence },
        (_, sequence) =>
          received.has(sequence)
            ? null
            : `${outcome.status!.channel}: live tail batch ${sequence} was not received`
      ).filter((gap): gap is string => gap !== null);
      finalGaps.push(...outcome.status.coverageGaps, ...missingSequences);
    }
    for (const channel of successfulChannels) {
      tailSequences.delete(tailSequenceKey(requestId, channel));
    }
    const failedChannels = new Set(
      outcomes
        .filter((outcome) => isLatestTailStop(outcome) && outcome.error)
        .map((outcome) => outcome.channel)
    );
    const clearedGapSet = new Set(clearedGaps);
    const remainingChannels = new Set(
      channels.filter((channel) => !successfulChannels.has(channel) || failedChannels.has(channel))
    );
    if (
      activeTailRequestId === requestId &&
      activeTailSourceRequestId === sourceRequestId
    ) {
      if (remainingChannels.size > 0) {
        activeTailChannels = new Set(remainingChannels);
      } else {
        activeTailRequestId = null;
        activeTailSourceRequestId = null;
        activeTailChannels = new Set<string>();
      }
    }
    if (remainingChannels.size > 0) {
      set((current) => ({
        tailMode: current.tailMode,
        tailRequestId: requestId,
        tailChannels: remainingChannels,
        tailCoverageGaps: mergeCoverageGaps(
          current.tailCoverageGaps.filter((gap) => !clearedGapSet.has(gap)),
          finalGaps
        ),
      }));
    } else {
      set((current) => ({
        tailMode: null,
        tailRequestId: null,
        tailChannels: new Set<string>(),
        tailCoverageGaps: mergeCoverageGaps(
          current.tailCoverageGaps.filter((gap) => !clearedGapSet.has(gap)),
          finalGaps
        ),
      }));
    }
  },

  clearChannel: async (channel, confirmed) => {
    const state = get();
    const requestId = state.tailRequestId;
    const sourceRequestId = activeRequestId;
    const wasTailing = requestId !== null && state.tailChannels.has(channel);
    if (wasTailing) {
      const key = tailSequenceKey(requestId, channel);
      const received = new Set(
        tailSequenceSnapshots.get(key) ?? tailSequences.get(key) ?? []
      );
      tailSequenceSnapshots.set(key, received);
      if (activeTailRequestId === requestId) activeTailChannels.delete(channel);
      const outcome = await stopTailRequest(requestId, channel);
      if (outcome.error) {
        const gap = `${channel}: live tail stop failed (${outcome.error})`;
        rememberTailStopGapOwner(gap, tailSequenceKey(requestId, channel));
        if (
          isLatestTailStop(outcome) &&
          get().tailRequestId === requestId &&
          isCurrentRequest(sourceRequestId) &&
          activeTailRequestId === requestId &&
          activeTailSourceRequestId === sourceRequestId
        ) {
          set((current) => ({
            tailCoverageGaps: mergeCoverageGaps(current.tailCoverageGaps, [gap]),
          }));
        }
        if (
          isLatestTailStop(outcome) &&
          activeTailRequestId === requestId &&
          activeTailSourceRequestId === sourceRequestId
        ) {
          activeTailChannels.add(channel);
        }
        return {
          status: "unavailable",
          detail: `${channel}: live tail stop failed (${outcome.error})`,
        };
      }
      if (outcome.status && isLatestTailStop(outcome)) {
        const missingSequences = Array.from(
          { length: outcome.status.nextSequence },
          (_, sequence) =>
            received.has(sequence)
              ? null
              : `${outcome.status!.channel}: live tail batch ${sequence} was not received`
        ).filter((gap): gap is string => gap !== null);
        if (
          isCurrentRequest(sourceRequestId) &&
          get().tailRequestId === requestId &&
          activeTailRequestId === requestId &&
          activeTailSourceRequestId === sourceRequestId &&
          (outcome.status.coverageGaps.length > 0 || missingSequences.length > 0)
        ) {
          set((current) => ({
            tailCoverageGaps: mergeCoverageGaps(current.tailCoverageGaps, [
              ...outcome.status!.coverageGaps,
              ...missingSequences,
            ]),
          }));
        }
      }
      tailSequences.delete(key);
      tailSequenceSnapshots.delete(key);
    }
    const currentAfterStop = get();
    const tailIdentityStillCurrent =
      requestId === null
        ? activeTailRequestId === null
        : activeTailRequestId === requestId &&
          activeTailSourceRequestId === sourceRequestId;
    if (
      !isCurrentRequest(sourceRequestId) ||
      currentAfterStop.tailRequestId !== requestId ||
      !tailIdentityStillCurrent
    ) {
      return {
        status: "unavailable",
        detail: `${channel}: clear cancelled because the event-log source or live tail changed`,
      };
    }
    const response = await clearEventLogChannel(
      channel,
      confirmed,
      get().remoteMachine
    );
    const result = response.result;
    const currentAfterClear = get();
    const canMutateCurrentTail =
      sourceRequestId === activeRequestId &&
      requestId === currentAfterClear.tailRequestId &&
      (requestId === null
        ? activeTailRequestId === null
        : activeTailRequestId === requestId &&
          activeTailSourceRequestId === sourceRequestId);
    if (result.status === "cleared" && canMutateCurrentTail) {
      const remainingTailChannels = new Set(
        [...currentAfterClear.tailChannels].filter((name) => name !== channel)
      );
      if (
        wasTailing &&
        remainingTailChannels.size === 0 &&
        activeTailRequestId === requestId &&
        activeTailSourceRequestId === sourceRequestId
      ) {
        activeTailRequestId = null;
        activeTailSourceRequestId = null;
        activeTailChannels = new Set<string>();
      }
      set((current) => {
        const tailChannels = new Set(
          [...current.tailChannels].filter((name) => name !== channel)
        );
        return {
          records: current.records.filter((record) => record.channel !== channel),
          loadedChannels: new Set([...current.loadedChannels].filter((name) => name !== channel)),
          channels: current.channels.map((info) =>
            info.name === channel ? { ...info, eventCount: 0 } : info
          ),
          sourceManifest: null,
          coverageGaps: current.coverageGaps.filter(
            (gap) => !coverageBelongsToChannel(gap, channel, current.remoteMachine)
          ),
          coverageDetails: current.coverageDetails.filter(
            (detail) => !coverageBelongsToChannel(detail.source, channel, current.remoteMachine)
          ),
          tailCoverageGaps: current.tailCoverageGaps.filter(
            (gap) => !gap.startsWith(`${channel}:`)
          ),
          tailMode: tailChannels.size > 0 ? current.tailMode : null,
          tailRequestId: tailChannels.size > 0 ? current.tailRequestId : null,
          tailChannels,
        };
      });
    } else if (
      result.status !== "cleared" &&
      wasTailing &&
      canMutateCurrentTail
    ) {
      // A denied, unavailable, or cancelled clear must leave the live view in the state the
      // operator was using before confirmation.
      await get().startLiveTail();
    }
    return result;
  },
  setLoadError: (error) =>
    set(
      error === null
        ? { loadError: null }
        : { isLoading: false, loadError: error },
    ),

  setTimeZoneMode: (mode) => set({ timeZoneMode: mode }),

  setSelectedChannels: (channels) => set({ selectedChannels: channels }),

  toggleChannel: (channel) => {
    const current = get().selectedChannels;
    const next = new Set(current);
    if (next.has(channel)) {
      next.delete(channel);
    } else {
      next.add(channel);
    }
    set({ selectedChannels: next });
  },

  selectAllChannels: () => {
    const channelNames = new Set(get().channels.map((c) => c.name));
    set({ selectedChannels: channelNames });
  },

  deselectAllChannels: () => {
    set({ selectedChannels: new Set<string>() });
  },

  setFilterLevels: (levels) => {
    set({ filterLevels: levels });
    refreshBeforeLoad();
  },

  toggleFilterLevel: (level) => {
    const current = get().filterLevels;
    const next = new Set(current);
    if (next.has(level)) next.delete(level);
    else next.add(level);
    if (next.size === 0) ALL_LEVELS.forEach((known) => next.add(known));
    set({ filterLevels: next });
    refreshBeforeLoad();
  },

  setFilterEventIds: (eventIds) => {
    set({ filterEventIds: eventIds });
    refreshBeforeLoad();
  },
  setBeforeLoadCriteria: (criteria) => {
    set({
      filterLevels: new Set(criteria.levels),
      filterEventIds: criteria.eventIds,
      timeWindow: criteria.timeWindow,
      ...(criteria.selectedChannels
        ? { selectedChannels: new Set(criteria.selectedChannels) }
        : {}),
    });
    refreshBeforeLoad();
  },
  setFilterSearch: (search) => set({ filterSearch: search }),
  setQuickFilter: (filter) => set({ quickFilter: { ...filter } }),
  setTimeWindow: (window) => {
    set({ timeWindow: window });
    refreshBeforeLoad();
  },
  // Changing the grouping invalidates every collapse key, so the old set is discarded rather than
  // left to collapse unrelated groups that happen to share a key.
  setGroupBy: (fields) => set({ groupBy: fields, collapsedGroups: new Set<string>() }),
  toggleColumnVisible: (id) =>
    set({ columnConfig: sanitizeColumnConfig(toggleColumn(get().columnConfig, id)) }),
  moveColumnBy: (id, direction) =>
    set({ columnConfig: sanitizeColumnConfig(moveColumn(get().columnConfig, id, direction)) }),
  resetColumns: () => set({ columnConfig: defaultColumnConfig() }),
  toggleGroup: (key) => {
    const next = new Set(get().collapsedGroups);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    set({ collapsedGroups: next });
  },
  setSortField: (field) => set({ sortField: field }),
  setSortDirection: (direction) => set({ sortDirection: direction }),
  setSelectedRecordId: (id) => set({ selectedRecordId: id }),

  reset: () => {
    const loadGeneration = get().loadGeneration + 1;
    staleTailStopFailures.clear();
    preservedSelectedRecordKey = null;
    const requestId = beginRequest();
    invalidateAllStreamedRecords(requestId);
    tailStopGapOwners.clear();
    set({
      records: [],
      channels: [],
      sourceMode: null,
      sourcePaths: [],
      remoteMachine: null,
      isLoading: false,
      loadError: null,
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      loadingChannel: null,
      loadingProgress: null,
      loadStartTime: null,
      loadElapsedMs: null,
      loadGeneration,
      filterLevels: new Set<EvtxLevel>(ALL_LEVELS),
      filterEventIds: "",
      filterSearch: "",
      timeZoneMode: "local",
      quickFilter: { ...DEFAULT_QUICK_FILTER },
      timeWindow: "24h",
      // Reset with everything else. Gaps describe records that are gone, so surviving a reset
      // would report a hole in a set no longer on screen, and a zone left over from a previous
      // session would silently reinterpret the next one's timestamps.
      coverageGaps: [],
      coverageDetails: [],
      archiveMembers: [],
      sourceManifest: null,
      columnConfig: defaultColumnConfig(),
      groupBy: [],
      collapsedGroups: new Set<string>(),
      sortField: "time",
      sortDirection: "asc",
      selectedRecordId: null,
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      tailCoverageGaps: [],
    });
  },
});
});

// Listen for progress events from the Rust backend
listen<{ requestId: string; channel: string; fetched: number }>(
  "evtx-query-progress",
  (event) => {
    if (!isCurrentRequest(event.payload.requestId)) return;
    useEvtxStore.setState({
      loadingChannel: event.payload.channel,
      loadingProgress: event.payload.fetched,
    });
  }
);
type StreamReply =
  | { kind: "success" }
  | { kind: "error"; message: string };

interface PendingStream {
  channel: string;
  requestId: string;
  records: EvtxRecord[];
  receivedRecordCount: number;
  sequences: Set<number>;
  terminal?: { sequenceCount: number; totalRecords: number };
  terminalSynthetic: boolean;
  reply?: StreamReply;
  consumerAcknowledged: boolean;
  settled: boolean;
  settling: boolean;
  terminalGraceDeadline?: number;
  terminalGraceTimer?: ReturnType<typeof setTimeout>;
  acknowledgementTimer?: ReturnType<typeof setTimeout>;
  waiters: Array<() => void>;
}

/**
 * A request may query more than one channel, so channel alone is not a stream identity. Keeping
 * the request in the key also lets a late event from an older query be rejected after a refresh.
 */
const pendingBatches = new Map<string, PendingStream>();
const activeRequestIds = new Map<string, string>();

function streamKey(channel: string, requestId: string): string {
  return `${requestId}\u0000${channel}`;
}

interface QueuedVisibleBatch {
  channel: string;
  requestId: string;
  records: EvtxRecord[];
}

const queuedVisibleBatches = new Map<string, QueuedVisibleBatch>();
let visibleBatchFlushScheduled = false;

function flushQueuedVisibleBatches(): void {
  visibleBatchFlushScheduled = false;
  const queued = [...queuedVisibleBatches.values()];
  queuedVisibleBatches.clear();
  const recordsByRequest = new Map<string, EvtxRecord[]>();
  for (const batch of queued) {
    if (
      !isCurrentRequest(batch.requestId) ||
      activeRequestIds.get(batch.channel) !== batch.requestId
    ) {
      continue;
    }
    recordsByRequest.set(
      batch.requestId,
      appendUniqueRecords(recordsByRequest.get(batch.requestId) ?? [], batch.records).records
    );
  }
  for (const [requestId, records] of recordsByRequest) {
    if (!isCurrentRequest(requestId) || records.length === 0) continue;
    const state = useEvtxStore.getState();
    useEvtxStore.setState(
      mergeRecordsPreservingSelection(
        state.records,
        state.selectedRecordId,
        records,
        { preserveMissingSelection: true }
      )
    );
  }
}

function queueVisibleBatch(channel: string, requestId: string, records: EvtxRecord[]): void {
  const key = streamKey(channel, requestId);
  const existing = queuedVisibleBatches.get(key);
  queuedVisibleBatches.set(key, {
    channel,
    requestId,
    records: appendUniqueRecords(existing?.records ?? [], records).records,
  });
  if (visibleBatchFlushScheduled) return;
  visibleBatchFlushScheduled = true;
  queueMicrotask(flushQueuedVisibleBatches);
}

function createPendingStream(channel: string, requestId: string): PendingStream {
  const pending: PendingStream = {
    channel,
    requestId,
    records: [],
    receivedRecordCount: 0,
    sequences: new Set<number>(),
    terminalSynthetic: false,
    consumerAcknowledged: false,
    settled: false,
    settling: false,
    waiters: [],
  };
  pendingBatches.set(streamKey(channel, requestId), pending);
  return pending;
}

function pendingFor(channel: string, requestId: string): PendingStream | undefined {
  return pendingBatches.get(streamKey(channel, requestId));
}

function sequenceNumbers(pending: PendingStream): number[] {
  if (!pending.terminal) return [];
  const missing: number[] = [];
  for (let sequence = 0; sequence < pending.terminal.sequenceCount; sequence++) {
    if (!pending.sequences.has(sequence)) missing.push(sequence);
  }
  return missing;
}

const TERMINAL_BATCH_GRACE_MS = 25;

function resolvePendingWaiters(pending: PendingStream): void {
  const waiters = pending.waiters.splice(0);
  for (const resolve of waiters) resolve();
}

function cancelPendingStream(pending: PendingStream): void {
  if (pending.terminalGraceTimer !== undefined) {
    clearTimeout(pending.terminalGraceTimer);
    pending.terminalGraceTimer = undefined;
  }
  if (pending.acknowledgementTimer !== undefined) {
    clearTimeout(pending.acknowledgementTimer);
    pending.acknowledgementTimer = undefined;
  }
  pending.settling = false;
  pending.settled = true;
  resolvePendingWaiters(pending);
}

function cancelAllPendingStreams(): void {
  for (const pending of pendingBatches.values()) cancelPendingStream(pending);
  pendingBatches.clear();
}

function settlePendingStream(pending: PendingStream): void {
  if (pending.settled || pending.settling || !pending.reply || !pending.terminal) return;
  // Keep the stream available for a bounded grace period even when the terminal claims every
  // sequence arrived. The backend can publish the invoke reply and terminal before the final event
  // callback is dispatched; resolving immediately lets the consumer acknowledge and delete that
  // state before the callback gets a chance to append its records.
  if (!pending.terminalSynthetic) {
    const now = Date.now();
    const deadline =
      pending.terminalGraceDeadline ??
      (pending.terminalGraceDeadline = now + TERMINAL_BATCH_GRACE_MS);
    const remaining = deadline - now;
    if (remaining > 0) {
      if (pending.terminalGraceTimer === undefined) {
        pending.terminalGraceTimer = setTimeout(() => {
          pending.terminalGraceTimer = undefined;
          settlePendingStream(pending);
        }, remaining);
      }
      return;
    }
  }
  pending.settling = true;
  queueMicrotask(() => {
    pending.settling = false;
    if (pending.settled || !pending.reply || !pending.terminal) return;
    pending.settled = true;
    resolvePendingWaiters(pending);
  });
}

function observeStreamReply(channel: string, requestId: string, reply: StreamReply): void {
  const pending = pendingFor(channel, requestId);
  if (!pending || pending.requestId !== requestId || pending.consumerAcknowledged) return;
  pending.reply = reply;
  if (reply.kind === "error") {
    // A rejected invoke is terminal from the consumer's point of view. It must not leave a waiter
    // behind for an event the backend could not deliver.
    let highest = -1;
    for (const sequence of pending.sequences) highest = Math.max(highest, sequence);
    pending.terminal = { sequenceCount: highest + 1, totalRecords: 0 };
    pending.terminalSynthetic = true;
    settlePendingStream(pending);
    return;
  }
  if (pending.terminal) settlePendingStream(pending);
}

function waitForStreamReconciliation(channel: string, requestId: string): Promise<void> {
  const pending = pendingFor(channel, requestId);
  if (!pending || pending.requestId !== requestId || pending.settled) return Promise.resolve();
  return new Promise<void>((resolve) => pending.waiters.push(resolve));
}

type StreamReconciliation = {
  checked: ReturnType<typeof assertParseResultShape>;
  result: EvtxParseResult;
  records: EvtxRecord[];
  missingSequences: number[];
  recordShortfall: boolean;
  gaps: string[];
};
function reconcileStreamedResult(
  channel: string,
  requestId: string,
  result: EvtxParseResult,
  context: string
): StreamReconciliation {
  const checked = assertParseResultShape(result);
  const streamed = drainStreamedRecords(channel, requestId);
  const appended = appendUniqueRecords(streamed.records, result.records, {
    deduplicateProducerless: true,
  });
  const records = appended.records;
  const gaps = [...checked.errorMessages, ...checked.coverageGaps.map(formatCoverageGap)];
  if (streamed.missingSequences.length > 0) {
    gaps.push(
      `${context}: ${streamed.missingSequences.length} batches of events were not received`
    );
  }
  const pending = pendingFor(channel, requestId);
  const expectedRaw =
    checked.totalRecords ??
    (pending?.terminal && pending.terminal.totalRecords > 0
      ? pending.terminal.totalRecords
      : null);
  // The stream and invoke reply can carry the same logical record. The backend count reflects
  // transport records, while the view owns the canonical identity set, so discount duplicates
  // observed across those two transport legs before deciding that records are missing.
  const duplicateRecordCount = appended.droppedAgainstExisting;
  const expected =
    expectedRaw === null
      ? null
      : Math.max(records.length, expectedRaw - duplicateRecordCount);
  const recordShortfall = expected !== null && records.length < expected;
  if (recordShortfall) {
    gaps.push(`${context}: ${expected - records.length} of ${expected} events did not reach the view`);
  }
  return {
    checked,
    result,
    records,
    missingSequences: streamed.missingSequences,
    recordShortfall,
    gaps,
  };
}

function invalidateAllStreamedRecords(requestId: string): void {
  const channels = new Set([
    ...[...pendingBatches.values()].map((pending) => pending.channel),
    ...activeRequestIds.keys(),
  ]);
  for (const channel of channels) resetStreamedRecords([channel], requestId);
}

listen<{ channel: string; requestId: string; sequence: number; records: EvtxRecord[] }>(
  "evtx-record-batch",
  (event) => {
    const { channel, requestId, sequence, records } = event.payload;
    if (!isCurrentRequest(requestId) || activeRequestIds.get(channel) !== requestId) return;
    const pending = pendingFor(channel, requestId) ?? createPendingStream(channel, requestId);
    if (pending.consumerAcknowledged || pending.sequences.has(sequence)) return;

    pending.sequences.add(sequence);
    pending.receivedRecordCount += records.length;
    if (records.length > 0) {
      pending.records = appendUniqueRecords(pending.records, records).records;

      // Batches remain visible while a request is running, but same-turn deliveries share one
      // identity-preserving merge/sort instead of repeatedly sorting the full visible set.
      queueVisibleBatch(channel, requestId, records);
    }

    // A terminal can race the final batch. Keep the pending state until the consumer acknowledges
    // the drain; the records above remain available even after reconciliation has resolved.
    settlePendingStream(pending);
  }
);

listen<{ channel: string; requestId: string; sequenceCount: number; totalRecords: number }>(
  "evtx-record-stream-complete",
  (event) => {
    const { channel, requestId, sequenceCount, totalRecords } = event.payload;
    if (!isCurrentRequest(requestId) || activeRequestIds.get(channel) !== requestId) return;
    const pending = pendingFor(channel, requestId) ?? createPendingStream(channel, requestId);
    if (pending.consumerAcknowledged) return;
    pending.terminal = { sequenceCount, totalRecords };
    pending.terminalSynthetic = false;
    settlePendingStream(pending);
  }
);

listen<EvtxTailBatch>("evtx-tail-batch", (event) => {
  const payload = event.payload;
  if (
    activeTailSourceRequestId === null ||
    !isCurrentRequest(activeTailSourceRequestId) ||
    activeTailRequestId !== payload.requestId ||
    !activeTailChannels.has(payload.channel)
  ) {
    return;
  }
  const key = tailSequenceKey(payload.requestId, payload.channel);
  let sequences = tailSequences.get(key);
  if (!sequences) {
    sequences = new Set<number>();
    tailSequences.set(key, sequences);
  }
  if (sequences.has(payload.sequence)) return;

  const missing: string[] = [];
  let highest = -1;
  for (const sequence of sequences) highest = Math.max(highest, sequence);
  for (let sequence = highest + 1; sequence < payload.sequence; sequence++) {
    if (!sequences.has(sequence)) {
      missing.push(`${payload.channel}: live tail batch ${sequence} was not received`);
    }
  }
  sequences.add(payload.sequence);
  if (payload.coverageGaps.length > 0) missing.push(...payload.coverageGaps);

  useEvtxStore.setState((state) => {
    const merged = mergeRecordsPreservingSelection(
      state.records,
      state.selectedRecordId,
      payload.records
    );
    const existingMode = state.tailMode;
    const mode =
      existingMode === null || existingMode === payload.mode
        ? payload.mode
        : existingMode === "unsupported"
          ? payload.mode
          : "mixed";
    return {
      ...merged,
      tailMode: mode,
      tailRequestId: payload.requestId,
      tailChannels: new Set([...state.tailChannels, payload.channel]),
      tailCoverageGaps: mergeCoverageGaps(state.tailCoverageGaps, missing),
    };
  });
});

/** Takes everything received for `channel`, and reports whether it is contiguous. */
export function drainStreamedRecords(channel: string, requestId: string): {
  records: EvtxRecord[];
  missingSequences: number[];
} {
  const pending = pendingFor(channel, requestId);
  if (!pending || pending.requestId !== requestId) {
    return { records: [], missingSequences: [] };
  }
  return { records: pending.records, missingSequences: sequenceNumbers(pending) };
}

/**
 * A load path calls this only after merging the drained snapshot. Until then events may still
 * arrive after the terminal marker and must remain available for exactly-once draining.
 */
export function acknowledgeStreamedRecords(channel: string, requestId: string): void {
  const pending = pendingFor(channel, requestId);
  if (!pending) return;
  const remaining =
    pending.terminalGraceDeadline === undefined
      ? 0
      : pending.terminalGraceDeadline - Date.now();
  if (remaining > 0) {
    if (pending.acknowledgementTimer === undefined) {
      pending.acknowledgementTimer = setTimeout(() => {
        pending.acknowledgementTimer = undefined;
        if (pendingBatches.get(streamKey(channel, requestId)) === pending) {
          acknowledgeStreamedRecords(channel, requestId);
        }
      }, remaining);
    }
    return;
  }
  pending.consumerAcknowledged = true;
  clearTimeout(pending.terminalGraceTimer);
  pending.terminalGraceTimer = undefined;
  pending.waiters.length = 0;
  pendingBatches.delete(streamKey(channel, requestId));
  if (activeRequestIds.get(channel) === requestId) activeRequestIds.delete(channel);
}

/** Discards anything buffered for channels a query is about to start, and registers the request. */
export function resetStreamedRecords(channels: string[], requestId: string): void {
  for (const channel of channels) {
    const activeRequestId = activeRequestIds.get(channel);
    if (activeRequestId !== undefined) {
      queuedVisibleBatches.delete(streamKey(channel, activeRequestId));
      const activePending = pendingFor(channel, activeRequestId);
      if (activePending) cancelPendingStream(activePending);
      pendingBatches.delete(streamKey(channel, activeRequestId));
    }
    queuedVisibleBatches.delete(streamKey(channel, requestId));
    activeRequestIds.set(channel, requestId);
    createPendingStream(channel, requestId);
  }
}

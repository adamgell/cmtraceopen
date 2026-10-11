/**
 * Comparing the current time window with the period immediately before it.
 *
 * The comparison is evidence for a delta KPI ("3x vs prior 24 h", "4 new vs prior 24 h"), so every
 * way it can fail to be a faithful count is a state the caller can see, never a zero. A previous
 * period that cannot be defined, a capture that does not reach it, a channel that could not be
 * read and an event that cannot be placed in time are each reported as such.
 *
 * Records are aggregated and dropped. Only counters and the distinct (provider, event id) keys are
 * kept, so a comparison over a busy channel costs memory in proportion to the number of distinct
 * events and not the number of events. Nothing here touches the store's `records`, so nothing a
 * comparison reads can reach the grid, the diagnosis or the analysis session.
 *
 * This module does no I/O and imports neither Tauri nor the store. The store owns the query
 * transport and routes streamed batches here by request ID.
 */

import { create } from "zustand";
import { assertParseResultShape, formatCoverageGap } from "./evtx-coverage";
import { selectVisibleRecords, type VisibleRecordsInput } from "./evtx-filter";
import {
  EVTX_TIME_WINDOW_MS,
  type EvtxLevel,
  type EvtxParseResult,
  type EvtxRecord,
  type EvtxTimeWindow,
} from "./types";

/** A time window that has a length, and therefore a previous period. */
export type ComparableWindow = Exclude<EvtxTimeWindow, "all">;

/** The period of the same length that ends one millisecond before the current window begins. */
export interface PriorWindow {
  window: ComparableWindow;
  lengthMs: number;
  /**
   * The instant the current window was measured from. The current window begins at
   * `anchorEpoch - lengthMs`, so a consumer whose own anchor differs is looking at a different
   * current window than this comparison was made against.
   */
  anchorEpoch: number;
  /** Inclusive epoch-millisecond bounds. */
  fromMs: number;
  toMs: number;
  /** The same bounds as ISO 8601 UTC, ready for `TimeWindow::Between`. */
  from: string;
  to: string;
}

export type PriorWindowResult =
  | { status: "available"; prior: PriorWindow }
  | {
      status: "unavailable";
      reason: "allTime" | "unsupportedWindow" | "invalidAnchor";
      detail: string;
    };

/**
 * The previous period for a current window, anchored at `anchorEpoch`.
 *
 * `anchorEpoch` is the instant the current window is measured from: the workspace's `nowEpoch`,
 * the same value `isWithinTimeWindow` subtracts the window from. The current window owns
 * `[anchor - length, ...)`. The service treats both `between` bounds as inclusive, so the previous
 * period ends at `anchor - length - 1` ms; ending it at `anchor - length` would count an event
 * stamped on that exact millisecond in both periods.
 *
 * "All time" has no length and so no previous period. That is a different answer from "the files
 * do not cover it", and the caller words the two differently.
 */
export function computePriorWindow(window: EvtxTimeWindow, anchorEpoch: number): PriorWindowResult {
  if (window === "all") {
    return {
      status: "unavailable",
      reason: "allTime",
      detail: "All time has no previous period.",
    };
  }
  const lengthMs = EVTX_TIME_WINDOW_MS[window] as number | undefined;
  if (lengthMs === undefined) {
    return {
      status: "unavailable",
      reason: "unsupportedWindow",
      detail: `The time window "${String(window)}" has no defined length.`,
    };
  }
  const fromMs = anchorEpoch - 2 * lengthMs;
  const toMs = anchorEpoch - lengthMs - 1;
  if (
    !Number.isSafeInteger(anchorEpoch) ||
    Number.isNaN(new Date(fromMs).getTime()) ||
    Number.isNaN(new Date(toMs).getTime())
  ) {
    return {
      status: "unavailable",
      reason: "invalidAnchor",
      detail: "The time the current window is measured from is not a usable date.",
    };
  }
  return {
    status: "available",
    prior: {
      window,
      lengthMs,
      anchorEpoch,
      fromMs,
      toMs,
      from: new Date(fromMs).toISOString(),
      to: new Date(toMs).toISOString(),
    },
  };
}

/**
 * Whether a record's timestamp says when it happened.
 *
 * The native parser writes 0 for a timestamp it could not read (`parse_timestamp_to_epoch_ms`
 * falls back to 0, and the timeline treats 0 as "missing"). Such a record is stamped 1970, which
 * would satisfy any "earliest event is before the period starts" test, so it is never evidence of
 * when anything happened.
 */
function hasUsableTimestamp(epoch: number): boolean {
  return Number.isFinite(epoch) && epoch > 0;
}

/** The key under which a (provider, event id) pair is stored in `ComparisonCounts.distinctEvents`. */
export function eventIdentityKey(provider: string, eventId: number): string {
  return `${provider}\u0000${eventId}`;
}

/** The criteria that decide which records the current view shows, other than the time window. */
export type ComparisonVisibility = Pick<
  VisibleRecordsInput,
  | "selectedChannels"
  | "filterLevels"
  | "filterEventIds"
  | "filterSearch"
  | "quickFilter"
  | "visibleColumns"
  | "timeZoneMode"
>;

export interface ComparisonCounts {
  /** Events that fall in the previous period and pass the view's criteria. */
  total: number;
  levels: Record<EvtxLevel, number>;
  /** Event counts by the channel stamped on each record. */
  channels: ReadonlyMap<string, number>;
  /** Keys built by `eventIdentityKey`; the current period's set is built the same way. */
  distinctEvents: ReadonlySet<string>;
}

export interface ComparisonTally {
  counts: ComparisonCounts;
  /** Visible records with no usable timestamp or level: counted nowhere, so counts may be low. */
  unplacedRecords: number;
  /** Visible records stamped outside the previous period. Expected from files, a fault from a query. */
  outsideWindowRecords: number;
}

export interface ComparisonAggregator {
  add(records: readonly EvtxRecord[]): void;
  finish(): ComparisonTally;
}

function emptyLevels(): Record<EvtxLevel, number> {
  return { Critical: 0, Error: 0, Warning: 0, Information: 0, Verbose: 0 };
}

/**
 * Counts the records of the previous period that the current view would show.
 *
 * The visibility criteria are the grid's own (`selectVisibleRecords` without a time window), so a
 * ratio between the two periods compares like with like. The period is applied here as well as by
 * a live query, which keeps files and live on one definition and turns a query that returns
 * something outside its bounds into a visible fault instead of a quiet miscount.
 */
export function createAggregator(
  prior: PriorWindow,
  visibility: ComparisonVisibility
): ComparisonAggregator {
  let total = 0;
  let unplacedRecords = 0;
  let outsideWindowRecords = 0;
  const levels = emptyLevels();
  const channels = new Map<string, number>();
  const distinctEvents = new Set<string>();

  return {
    add(records) {
      for (const candidate of selectVisibleRecords({ ...visibility, records: [...records] })) {
        if (
          !hasUsableTimestamp(candidate.timestampEpoch) ||
          !Object.prototype.hasOwnProperty.call(levels, candidate.level)
        ) {
          unplacedRecords++;
        } else if (candidate.timestampEpoch < prior.fromMs || candidate.timestampEpoch > prior.toMs) {
          outsideWindowRecords++;
        } else {
          total++;
          levels[candidate.level]++;
          channels.set(candidate.channel, (channels.get(candidate.channel) ?? 0) + 1);
          distinctEvents.add(eventIdentityKey(candidate.provider, candidate.eventId));
        }
      }
    },
    finish() {
      return {
        counts: {
          total,
          levels: { ...levels },
          channels: new Map(channels),
          distinctEvents: new Set(distinctEvents),
        },
        unplacedRecords,
        outsideWindowRecords,
      };
    },
  };
}

export type ComparisonMode = "files" | "live";

export interface ComparisonResult {
  mode: ComparisonMode;
  /** The current window, for copy such as "vs prior 24 h". */
  window: ComparableWindow;
  prior: PriorWindow;
  counts: ComparisonCounts;
  /** Why the counts may understate the previous period. Empty exactly when the status is complete. */
  gaps: string[];
  unplacedRecords: number;
  /** Queried channels that could not be read. Absent from `counts.channels`, never counted as 0. */
  unreadChannels: string[];
}

export type ComparisonUnavailableReason =
  | "allTime"
  | "unsupportedWindow"
  | "invalidAnchor"
  | "notReady"
  | "noChannels"
  | "currentPeriodIncomplete"
  | "noTimedRecords"
  | "priorPeriodNotSpanned"
  | "queryFailed";

export type ComparisonOutcome =
  | { status: "complete" | "partial"; result: ComparisonResult }
  | { status: "unavailable"; reason: ComparisonUnavailableReason; detail: string };

const FILES_NOT_COVERED = "The loaded files do not cover the previous period.";

export type FilesCoverage =
  | { covered: true }
  | {
      covered: false;
      reason: "noTimedRecords" | "priorPeriodNotSpanned";
      detail: string;
    };

/**
 * Whether the loaded records can speak for the whole previous period.
 *
 * A capture covers the period when its earliest timed event is at or before the period's start and
 * its latest timed event is at or after the period's end: the log was already running when the
 * period began and was still being written when it finished, so a quiet stretch inside it is a
 * real absence of events and not a hole in the capture.
 *
 * Event logs roll over per channel, and two files can share a channel name, so the test is made per
 * (source, channel) over the selected channels. Pooled, one deep capture would vouch for a shallow
 * one. Records without a usable timestamp are excluded from the span and cannot prove anything.
 */
export function checkFilesCoverage(
  records: readonly EvtxRecord[],
  selectedChannels: ReadonlySet<string>,
  prior: PriorWindow
): FilesCoverage {
  const spans = new Map<string, { earliest: number; latest: number }>();
  for (const candidate of records) {
    if (!selectedChannels.has(candidate.channel)) continue;
    const key = `${candidate.sourceLabel}\u0000${candidate.channel}`;
    let span = spans.get(key);
    if (!span) {
      span = { earliest: Number.POSITIVE_INFINITY, latest: Number.NEGATIVE_INFINITY };
      spans.set(key, span);
    }
    if (!hasUsableTimestamp(candidate.timestampEpoch)) continue;
    span.earliest = Math.min(span.earliest, candidate.timestampEpoch);
    span.latest = Math.max(span.latest, candidate.timestampEpoch);
  }

  if (spans.size === 0) {
    return {
      covered: false,
      reason: "noTimedRecords",
      detail: "No events are loaded for the selected channels.",
    };
  }
  for (const span of spans.values()) {
    if (span.earliest === Number.POSITIVE_INFINITY) {
      return {
        covered: false,
        reason: "noTimedRecords",
        detail: "A loaded capture has no event with a usable timestamp.",
      };
    }
    if (span.earliest > prior.fromMs || span.latest < prior.toMs) {
      return { covered: false, reason: "priorPeriodNotSpanned", detail: FILES_NOT_COVERED };
    }
  }
  return { covered: true };
}

function plural(count: number, singular: string, pluralForm: string): string {
  return count === 1 ? singular : pluralForm;
}

function unplacedGap(count: number, scope: "files" | "live"): string {
  return scope === "files"
    ? `${count} loaded ${plural(count, "event has", "events have")} no usable timestamp and could not be placed in either period.`
    : `${count} ${plural(count, "event has", "events have")} no usable timestamp and could not be placed in the previous period.`;
}

export interface FilesComparisonInput {
  records: readonly EvtxRecord[];
  window: EvtxTimeWindow;
  anchorEpoch: number;
  visibility: ComparisonVisibility;
}

/**
 * The previous-period counts computed from the records already loaded, or why they cannot be.
 *
 * Pure, so a caller can ask it whether the comparison is available (to disable a button) without
 * publishing anything.
 */
export function compareLoadedFiles(input: FilesComparisonInput): ComparisonOutcome {
  const windowResult = computePriorWindow(input.window, input.anchorEpoch);
  if (windowResult.status === "unavailable") return windowResult;
  const { prior } = windowResult;

  const coverage = checkFilesCoverage(input.records, input.visibility.selectedChannels, prior);
  if (!coverage.covered) {
    return { status: "unavailable", reason: coverage.reason, detail: coverage.detail };
  }

  const aggregator = createAggregator(prior, input.visibility);
  aggregator.add(input.records);
  const tally = aggregator.finish();
  const gaps = tally.unplacedRecords > 0 ? [unplacedGap(tally.unplacedRecords, "files")] : [];
  return {
    status: gaps.length === 0 ? "complete" : "partial",
    result: {
      mode: "files",
      window: prior.window,
      prior,
      counts: tally.counts,
      gaps,
      unplacedRecords: tally.unplacedRecords,
      unreadChannels: [],
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Published state
// ---------------------------------------------------------------------------------------------

export type ComparisonState =
  | { phase: "idle" }
  | { phase: "running"; mode: "live"; requestId: string; prior: PriorWindow }
  | { phase: "settled"; outcome: ComparisonOutcome };

/**
 * What the comparison currently is. A result is published once, when the comparison settles, and
 * never as a running tally: a delta against a half-read period is an estimate, and the workspace
 * shows no estimate.
 */
export const useComparisonStore = create<{ state: ComparisonState }>(() => ({
  state: { phase: "idle" },
}));

export function getComparisonState(): ComparisonState {
  return useComparisonStore.getState().state;
}

function publish(state: ComparisonState): void {
  useComparisonStore.setState({ state });
}

/** Publishes that no comparison can be made, and why. Ends any comparison in flight. */
export function publishComparisonUnavailable(
  reason: ComparisonUnavailableReason,
  detail: string
): void {
  endActiveSession();
  publish({ phase: "settled", outcome: { status: "unavailable", reason, detail } });
}

/** Computes and publishes the files-mode comparison. Ends any comparison in flight. */
export function publishFilesComparison(input: FilesComparisonInput): ComparisonOutcome {
  endActiveSession();
  const outcome = compareLoadedFiles(input);
  publish({ phase: "settled", outcome });
  return outcome;
}

/**
 * Ends the comparison and clears its result.
 *
 * Stops the backend read of a comparison still in flight, so abandoning a comparison of a large
 * channel does not leave the scan running. Safe to call at any time and when nothing is running.
 */
export function cancelComparison(): void {
  endActiveSession();
  if (getComparisonState().phase !== "idle") publish({ phase: "idle" });
}

// ---------------------------------------------------------------------------------------------
// Live comparison
// ---------------------------------------------------------------------------------------------

/**
 * Request IDs of comparison queries. The store routes any batch carrying one to this module and
 * never to its own streams, so a comparison cannot be mistaken for, or merged into, a load.
 */
export const COMPARISON_REQUEST_ID_PREFIX = "event-log-compare-";

export function isComparisonRequestId(requestId: string): boolean {
  return requestId.startsWith(COMPARISON_REQUEST_ID_PREFIX);
}

/**
 * How long a channel waits, after the query replied, for batches the event channel has not yet
 * delivered. The reply and the end-of-stream marker travel on different paths from the batches, so
 * either can arrive first; the grace turns "the last batch is a moment behind" into a complete
 * count and "a batch was lost" into a stated gap.
 */
const COMPARISON_STRAGGLER_GRACE_MS = 250;

export interface LiveComparisonInput {
  window: EvtxTimeWindow;
  anchorEpoch: number;
  /** The channels to read, each queried under the session's request ID. */
  channels: readonly string[];
  visibility: ComparisonVisibility;
  /** Stops the backend read for a comparison that is cancelled or superseded before it settles. */
  cancelQuery: (requestId: string) => void;
}

export interface LiveComparisonSession {
  /** The dedicated request ID every channel query of this comparison must carry. */
  readonly requestId: string;
  /** The previous period the queries must be bounded to. */
  readonly prior: PriorWindow;
  /** Resolves when the comparison settles or is cancelled. */
  readonly done: Promise<void>;
  /** False once the comparison has settled, been cancelled or been superseded. */
  isActive(): boolean;
  /** A channel's query resolved. Ignored when the comparison is no longer active. */
  replied(channel: string, reply: EvtxParseResult): void;
  /** A channel's query rejected. Ignored when the comparison is no longer active. */
  failed(channel: string, message: string): void;
}

interface ChannelStream {
  received: number;
  sequences: Set<number>;
  terminal?: { sequenceCount: number; totalRecords: number };
  reply?: { expected: number | null; gaps: string[]; replyRecords: number };
  failure?: string;
  settled: boolean;
  timer?: ReturnType<typeof setTimeout>;
  gaps: string[];
  unread: boolean;
}

interface ActiveSession {
  requestId: string;
  prior: PriorWindow;
  channels: string[];
  streams: Map<string, ChannelStream>;
  aggregator: ComparisonAggregator;
  active: boolean;
  cancelQuery: (requestId: string) => void;
  resolveDone: () => void;
}

let activeSession: ActiveSession | null = null;
let comparisonGeneration = 0;

function endActiveSession(): void {
  const session = activeSession;
  if (!session) return;
  activeSession = null;
  session.active = false;
  for (const stream of session.streams.values()) clearTimeout(stream.timer);
  session.cancelQuery(session.requestId);
  session.resolveDone();
}

function missingSequences(stream: ChannelStream): number {
  if (!stream.terminal) return 0;
  let missing = 0;
  for (let sequence = 0; sequence < stream.terminal.sequenceCount; sequence++) {
    if (!stream.sequences.has(sequence)) missing++;
  }
  return missing;
}

function expectedEvents(stream: ChannelStream): number | null {
  return stream.reply?.expected ?? stream.terminal?.totalRecords ?? null;
}

function describeChannel(channel: string, stream: ChannelStream): void {
  if (stream.failure !== undefined) {
    stream.gaps = [`${channel}: ${stream.failure}`];
    stream.unread = true;
    return;
  }
  const reply = stream.reply;
  const gaps = reply ? [...reply.gaps] : [];
  if (reply && reply.replyRecords > 0) {
    const n = reply.replyRecords;
    gaps.push(
      `${channel}: ${n} ${plural(n, "event arrived", "events arrived")} in the reply instead of the stream and ${plural(n, "was", "were")} not counted`
    );
  }
  const expected = expectedEvents(stream);
  if (expected === null) {
    gaps.push(`${channel}: the reader did not report how many events it sent`);
  }
  if (stream.terminal) {
    const missing = missingSequences(stream);
    if (missing > 0) {
      gaps.push(
        `${channel}: ${missing} ${plural(missing, "batch of events was", "batches of events were")} not received`
      );
    }
  } else {
    gaps.push(`${channel}: the end-of-stream marker was not received`);
  }
  if (expected !== null) {
    if (stream.received < expected) {
      gaps.push(
        `${channel}: ${expected - stream.received} of ${expected} events did not reach the comparison`
      );
    } else if (stream.received > expected && (reply?.gaps.length ?? 0) === 0) {
      gaps.push(`${channel}: more events arrived than the reader reported`);
    }
  }
  stream.gaps = gaps;
  // A channel that delivered nothing and has something to report is not a channel with no events.
  stream.unread = stream.received === 0 && gaps.length > 0;
}

function finishIfSettled(session: ActiveSession): void {
  if (!session.active) return;
  for (const stream of session.streams.values()) if (!stream.settled) return;

  const tally = session.aggregator.finish();
  const gaps = session.channels.flatMap((channel) => session.streams.get(channel)?.gaps ?? []);
  const unreadChannels = session.channels.filter((channel) => session.streams.get(channel)?.unread);
  if (tally.unplacedRecords > 0) gaps.push(unplacedGap(tally.unplacedRecords, "live"));
  if (tally.outsideWindowRecords > 0) {
    const n = tally.outsideWindowRecords;
    gaps.push(
      `${n} ${plural(n, "event the query returned lies", "events the query returned lie")} outside the previous period and ${plural(n, "was", "were")} not counted.`
    );
  }

  const outcome: ComparisonOutcome =
    unreadChannels.length === session.channels.length
      ? { status: "unavailable", reason: "queryFailed", detail: gaps.join(" ") }
      : {
          status: gaps.length === 0 ? "complete" : "partial",
          result: {
            mode: "live",
            window: session.prior.window,
            prior: session.prior,
            counts: tally.counts,
            gaps,
            unplacedRecords: tally.unplacedRecords,
            unreadChannels,
          },
        };

  activeSession = null;
  session.active = false;
  publish({ phase: "settled", outcome });
  session.resolveDone();
}

function settleChannel(session: ActiveSession, channel: string, stream: ChannelStream): void {
  stream.settled = true;
  clearTimeout(stream.timer);
  stream.timer = undefined;
  describeChannel(channel, stream);
  finishIfSettled(session);
}

/**
 * Settles a channel once everything it will say has been heard: its query replied, its
 * end-of-stream marker arrived, no batch is missing and the events received equal the events the
 * reader reported. Anything short of that waits for the straggler grace and then settles with the
 * shortfall stated.
 */
function trySettleChannel(
  session: ActiveSession,
  channel: string,
  stream: ChannelStream,
  graceExpired = false
): void {
  if (!session.active || stream.settled) return;
  if (stream.failure !== undefined) {
    settleChannel(session, channel, stream);
    return;
  }
  if (!stream.reply) return;

  const expected = expectedEvents(stream);
  const reconciled =
    stream.terminal !== undefined &&
    missingSequences(stream) === 0 &&
    expected !== null &&
    stream.received >= expected;
  if (reconciled || graceExpired) {
    settleChannel(session, channel, stream);
    return;
  }
  stream.timer ??= setTimeout(
    () => trySettleChannel(session, channel, stream, true),
    COMPARISON_STRAGGLER_GRACE_MS
  );
}

/**
 * Starts a live comparison, or publishes why it cannot start and returns null.
 *
 * Ends whatever comparison was in flight or on show first. The caller issues one query per channel,
 * each under `session.requestId` and bounded by `session.prior`, and reports each channel's reply
 * or rejection on the session. Streamed batches reach the session through
 * `observeComparisonBatch`, which the store calls for any comparison request ID.
 */
export function beginLiveComparison(input: LiveComparisonInput): LiveComparisonSession | null {
  endActiveSession();
  const windowResult = computePriorWindow(input.window, input.anchorEpoch);
  if (windowResult.status === "unavailable") {
    publishComparisonUnavailable(windowResult.reason, windowResult.detail);
    return null;
  }
  const channels = [...new Set(input.channels)];
  if (channels.length === 0) {
    publishComparisonUnavailable("noChannels", "No loaded channel is selected to compare.");
    return null;
  }

  const { prior } = windowResult;
  const requestId = `${COMPARISON_REQUEST_ID_PREFIX}${++comparisonGeneration}`;
  let resolveDone: () => void = () => {};
  const done = new Promise<void>((resolve) => {
    resolveDone = resolve;
  });
  const session: ActiveSession = {
    requestId,
    prior,
    channels,
    streams: new Map(
      channels.map((channel) => [
        channel,
        { received: 0, sequences: new Set<number>(), settled: false, gaps: [], unread: false },
      ])
    ),
    aggregator: createAggregator(prior, input.visibility),
    active: true,
    cancelQuery: input.cancelQuery,
    resolveDone,
  };
  activeSession = session;
  publish({ phase: "running", mode: "live", requestId, prior });

  return {
    requestId,
    prior,
    done,
    isActive: () => session.active,
    replied(channel, result) {
      const stream = session.active ? session.streams.get(channel) : undefined;
      if (!stream || stream.settled) return;
      try {
        const checked = assertParseResultShape(result);
        stream.reply = {
          expected: checked.totalRecords,
          // Provider-description failures leave every count intact; anything else may not.
          gaps: checked.coverageGaps
            .filter((coverageGap) => coverageGap.kind !== "provider")
            .map(formatCoverageGap),
          replyRecords: checked.records.length,
        };
      } catch (error) {
        stream.failure = error instanceof Error ? error.message : String(error);
      }
      trySettleChannel(session, channel, stream);
    },
    failed(channel, message) {
      const stream = session.active ? session.streams.get(channel) : undefined;
      if (!stream || stream.settled) return;
      stream.failure = message;
      trySettleChannel(session, channel, stream);
    },
  };
}

export interface ComparisonBatch {
  requestId: string;
  channel: string;
  sequence: number;
  records: readonly EvtxRecord[];
}

/**
 * Takes a streamed batch for the active comparison and aggregates it. A batch for any other
 * request, a cancelled or superseded comparison, a channel not being read, or a channel that has
 * already settled is dropped.
 */
export function observeComparisonBatch(batch: ComparisonBatch): void {
  const session = activeSession;
  if (!session || session.requestId !== batch.requestId) return;
  const stream = session.streams.get(batch.channel);
  if (!stream || stream.settled || stream.sequences.has(batch.sequence)) return;
  stream.sequences.add(batch.sequence);
  if (Array.isArray(batch.records) && batch.records.length > 0) {
    stream.received += batch.records.length;
    session.aggregator.add(batch.records);
  }
  trySettleChannel(session, batch.channel, stream);
}

export interface ComparisonStreamComplete {
  requestId: string;
  channel: string;
  sequenceCount: number;
  totalRecords: number;
}

/** Takes a channel's end-of-stream marker for the active comparison; otherwise drops it. */
export function observeComparisonComplete(complete: ComparisonStreamComplete): void {
  const session = activeSession;
  if (!session || session.requestId !== complete.requestId) return;
  const stream = session.streams.get(complete.channel);
  if (!stream || stream.settled) return;
  stream.terminal = {
    sequenceCount: complete.sequenceCount,
    totalRecords: complete.totalRecords,
  };
  trySettleChannel(session, complete.channel, stream);
}

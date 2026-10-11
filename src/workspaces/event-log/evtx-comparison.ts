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

import { selectVisibleRecords, type VisibleRecordsInput } from "./evtx-filter";
import {
  EVTX_TIME_WINDOW_MS,
  type EvtxLevel,
  type EvtxRecord,
  type EvtxTimeWindow,
} from "./types";

/** A time window that has a length, and therefore a previous period. */
export type ComparableWindow = Exclude<EvtxTimeWindow, "all">;

/** The period of the same length that ends one millisecond before the current window begins. */
export interface PriorWindow {
  window: ComparableWindow;
  lengthMs: number;
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
  | "sourceNotReady"
  | "noChannels"
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

function unplacedGap(count: number): string {
  return `${count} loaded ${plural(count, "event has", "events have")} no usable timestamp and could not be placed in either period.`;
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
  const gaps = tally.unplacedRecords > 0 ? [unplacedGap(tally.unplacedRecords)] : [];
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

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
  type EventLogSourceCoverage,
  type EvtxCoverageGap,
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
   * The instant the current window was measured from, and where the current period ends. The
   * current period is `[anchorEpoch - lengthMs, anchorEpoch]`. For a live source it is the earliest
   * instant a compared channel's current read was issued, not the workspace clock, so it does not
   * equal `nowEpoch`; a consumer must count its current side over this period
   * (`countCurrentPeriod`) and not over a window measured from `nowEpoch`, or the two sides stop
   * meeting. Events a live tail appended after it are outside the period and are not counted.
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
 * `anchorEpoch` is the instant the current window was measured from. For a live source that is the
 * earliest instant a compared channel's current read was issued, because the workspace's `nowEpoch`
 * keeps moving after the load; for loaded files it is the workspace's `nowEpoch`, the value
 * `isWithinTimeWindow` subtracts the window from. The current window owns `[anchor - length, ...)`. The service treats
 * both `between` bounds as inclusive, so the previous period ends at `anchor - length - 1` ms;
 * ending it at `anchor - length` would count an event stamped on that exact millisecond in both
 * periods.
 *
 * Both periods are computed on this computer's clock. For a local source that is the clock that
 * stamps the events. For a remote source, skew between the two machines shifts the boundary: the
 * current period was cut by the target's clock (a `last` window is evaluated there) while the
 * previous period is cut by this one. The comparison cannot measure that skew, so the outcome for
 * a remote source carries a note saying whose clock the periods use.
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
  // Whole-millisecond bounds, with a known hole. The service compares @SystemTime at (inferred, not
  // yet verified on Windows) 100 ns resolution, while the native parser truncates an event's time
  // to whole milliseconds. An event stamped strictly between this bound and `anchor - length`, for
  // example 11:59:59.9995 against a bound of 11:59:59.999, is excluded by the inclusive `to` sent
  // to the service, and its truncated epoch puts it before the current window, so on a live source
  // it can fall in neither period. The sliver is under one millisecond wide. Closing it means
  // sending a seven-digit bound (...9999999Z) once the Windows lab has confirmed the service
  // accepts one; until then a test pins the millisecond form.
  const toMs = anchorEpoch - lengthMs - 1;
  if (
    !Number.isSafeInteger(anchorEpoch) ||
    anchorEpoch <= 0 ||
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
  /** The channels of those records, which may hold events of the period that went uncounted. */
  unplacedChannels: ReadonlySet<string>;
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
  period: { fromMs: number; toMs: number },
  visibility: ComparisonVisibility
): ComparisonAggregator {
  let total = 0;
  let unplacedRecords = 0;
  const unplacedChannels = new Set<string>();
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
          unplacedChannels.add(candidate.channel);
        } else if (candidate.timestampEpoch < period.fromMs || candidate.timestampEpoch > period.toMs) {
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
        unplacedChannels: new Set(unplacedChannels),
        outsideWindowRecords,
      };
    },
  };
}

/**
 * Records the live tail appended. A tail reads events that have not happened yet, so they belong
 * after the comparison's anchor, but a record's own timestamp does not guarantee it: a subscription
 * can deliver an event late (a collector's ForwardedEvents) or from a machine whose clock runs
 * behind. Whatever its timestamp, a record the tail appended is never part of the current period,
 * which keeps the note that the comparison leaves the tail's events out true by construction.
 */
const tailAppendedRecords = new WeakSet<EvtxRecord>();

/** Marks records as appended by the live tail. */
export function markTailAppended(records: readonly EvtxRecord[]): void {
  for (const record of records) tailAppendedRecords.add(record);
}

export function isTailAppended(record: EvtxRecord): boolean {
  return tailAppendedRecords.has(record);
}

/** What `countCurrentPeriod` needs of a comparison result. */
export type CurrentPeriodBasis = Pick<
  ComparisonResult,
  "prior" | "comparedChannels" | "channelsWithGaps"
>;

/**
 * The events of the CURRENT period that the view shows, counted the way the previous period is.
 *
 * The current period is `[anchor - length, anchor]` for the anchor the comparison was made at. A
 * ratio needs both sides over periods that meet exactly; counting the current side from the grid's
 * window, measured from a clock that has since moved, would shift it away from the previous period
 * and read as a decline that never happened.
 *
 * Every compared channel with no event in the period is recorded as 0 only when it was read without
 * a hole and holds nothing that could not be placed in time, the rule the previous period follows;
 * otherwise it is absent, so a read zero differs from an unknown count.
 */
export function countCurrentPeriod(
  records: readonly EvtxRecord[],
  basis: CurrentPeriodBasis,
  visibility: ComparisonVisibility
): ComparisonTally {
  const { prior } = basis;
  const aggregator = createAggregator(
    { fromMs: prior.anchorEpoch - prior.lengthMs, toMs: prior.anchorEpoch },
    visibility
  );
  aggregator.add(records.filter((candidate) => !isTailAppended(candidate)));
  const tally = aggregator.finish();
  const withGaps = new Set(basis.channelsWithGaps);
  const channels = new Map(tally.counts.channels);
  for (const channel of basis.comparedChannels) {
    if (!channels.has(channel) && !withGaps.has(channel) && !tally.unplacedChannels.has(channel)) {
      channels.set(channel, 0);
    }
  }
  return { ...tally, counts: { ...tally.counts, channels } };
}

export type ComparisonMode = "files" | "live";

/**
 * Where the anchor came from. `load` is the earliest instant a compared channel's current read was
 * issued, and `clock` the workspace's `nowEpoch` (loaded files). A live tail never sets it: the
 * tail reads only events that have not happened yet, so what lies between a read and the tail's
 * start is in neither the records nor a gap. `result.prior.anchorEpoch` is the anchor itself.
 */
export type ComparisonAnchorBasis = "load" | "clock";

export interface ComparisonResult {
  mode: ComparisonMode;
  /** The current window, for copy such as "vs prior 24 h". */
  window: ComparableWindow;
  prior: PriorWindow;
  anchorBasis: ComparisonAnchorBasis;
  counts: ComparisonCounts;
  /**
   * Why the counts may understate the previous period or misrepresent the current one. Empty
   * exactly when the status is complete.
   */
  gaps: string[];
  /** Context the reader should see that is not a shortfall, such as whose clock cut the periods. */
  notes: string[];
  unplacedRecords: number;
  /**
   * Queried channels that could not be read. Absent from `counts.channels`, never counted as 0. A
   * channel that was read in full and held no events is present with a count of 0.
   */
  unreadChannels: string[];
  /** The channels compared, in order: those selected and loaded (live) or with a capture (files). */
  comparedChannels: string[];
  /**
   * Compared channels with a hole somewhere in what was read, in either period, or an event that
   * could not be placed in time. A count of 0 for one of these cannot be trusted, so
   * `countCurrentPeriod` leaves it absent.
   */
  channelsWithGaps: string[];
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

/** One loaded capture: the events of one channel from one source, and the span they cover. */
export interface FilesCapture {
  source: string;
  channel: string;
  earliestMs: number;
  latestMs: number;
}

export type FilesCoverage =
  | { covered: true; captures: FilesCapture[] }
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
 * period began and was still being written when it finished, so a quiet stretch inside it is a real
 * absence of events. That holds only while the load itself reported no hole, such as a damaged
 * chunk or an exhausted record budget; `compareLoadedFiles` carries those as gaps.
 *
 * Event logs roll over per channel, and two files can share a channel name, so the test is made per
 * (source, channel) over the selected channels. Pooled, one deep capture would vouch for a shallow
 * one. Records without a usable timestamp are excluded from the span and cannot prove anything.
 *
 * The spans are returned so the caller can also ask whether each capture reaches the anchor, which
 * is where the current period ends.
 */
export function checkFilesCoverage(
  records: readonly EvtxRecord[],
  selectedChannels: ReadonlySet<string>,
  prior: PriorWindow
): FilesCoverage {
  const captures = new Map<string, FilesCapture>();
  for (const candidate of records) {
    if (!selectedChannels.has(candidate.channel)) continue;
    const key = `${candidate.sourceLabel}\u0000${candidate.channel}`;
    let capture = captures.get(key);
    if (!capture) {
      capture = {
        source: candidate.sourceLabel,
        channel: candidate.channel,
        earliestMs: Number.POSITIVE_INFINITY,
        latestMs: Number.NEGATIVE_INFINITY,
      };
      captures.set(key, capture);
    }
    if (!hasUsableTimestamp(candidate.timestampEpoch)) continue;
    capture.earliestMs = Math.min(capture.earliestMs, candidate.timestampEpoch);
    capture.latestMs = Math.max(capture.latestMs, candidate.timestampEpoch);
  }

  if (captures.size === 0) {
    return {
      covered: false,
      reason: "noTimedRecords",
      detail: "No events are loaded for the selected channels.",
    };
  }
  for (const capture of captures.values()) {
    if (capture.earliestMs === Number.POSITIVE_INFINITY) {
      return {
        covered: false,
        reason: "noTimedRecords",
        detail: "A loaded capture has no event with a usable timestamp.",
      };
    }
    if (capture.earliestMs > prior.fromMs || capture.latestMs < prior.toMs) {
      return { covered: false, reason: "priorPeriodNotSpanned", detail: FILES_NOT_COVERED };
    }
  }
  return { covered: true, captures: [...captures.values()] };
}

function plural(count: number, singular: string, pluralForm: string): string {
  return count === 1 ? singular : pluralForm;
}

function unplacedGap(count: number, scope: "files" | "live"): string {
  return scope === "files"
    ? `${count} loaded ${plural(count, "event has", "events have")} no usable timestamp and could not be placed in either period.`
    : `${count} ${plural(count, "event has", "events have")} no usable timestamp and could not be placed in the previous period.`;
}

/** A length of time as the largest two units that matter, for gap text. */
function formatSpan(ms: number): string {
  if (ms < 1000) return `${Math.max(0, Math.round(ms))} ms`;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds} s`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    const rest = minutes % 60;
    return rest === 0 ? `${hours} h` : `${hours} h ${rest} min`;
  }
  const days = Math.floor(hours / 24);
  const restHours = hours % 24;
  return restHours === 0 ? `${days} d` : `${days} d ${restHours} h`;
}

function isoOrUnknown(epochMs: number): string {
  return Number.isNaN(new Date(epochMs).getTime()) ? "an unknown time" : new Date(epochMs).toISOString();
}

/** The most gap lines one cause may add; the rest are counted, not listed. */
const MAX_LISTED_GAPS = 5;

export function limitGapLines(lines: readonly string[]): string[] {
  if (lines.length <= MAX_LISTED_GAPS) return [...lines];
  return [
    ...lines.slice(0, MAX_LISTED_GAPS),
    `and ${lines.length - MAX_LISTED_GAPS} more not shown.`,
  ];
}

/**
 * The share of the window the start of a channel's current period may be uncertain by before it is
 * stated. The anchor is the earliest read among the compared channels, and a read that waited its
 * turn in the pool, or behind a slow session, began later; the service also evaluates a window at
 * some point after the invoke that this side does not observe. Either way the first part of the
 * comparison's current period may not be in what the channel loaded. Under this share that band is
 * a documented tolerance, in the same spirit as the sub-millisecond sliver at the previous period's
 * end: real, small, and not worth a gap on every comparison. Above it the band is stated. Recorded
 * for Adam as a policy choice (1% of the window).
 */
const MAX_UNREPORTED_START_BAND_SHARE = 0.01;

/**
 * When a channel's current-period read was issued, and when its invoke resolved. The service
 * evaluates the window at an instant between the two that is not observed, so they bound it.
 */
export interface ChannelRead {
  issuedEpoch: number;
  repliedEpoch: number;
}

export interface StartGap {
  /** True when the band is certain; false when the evaluation instant leaves it only possible. */
  definite: boolean;
  text: string;
}

/**
 * What may be missing from the start of one channel's current period, or null when it is within
 * the tolerance above.
 *
 * The comparison's current period is `[anchor - length, anchor]`, anchored at the earliest issue
 * time among the compared channels. A channel's window starts `length` before the instant the
 * service evaluated it, which is somewhere in `[issued, replied]`, so the part of the comparison's
 * period it lacks is at least `issued - anchor` and at most `replied - anchor`; for the anchoring
 * channel the least is nothing and the most is the length of its own read. An unknown instant is
 * stated, never assumed to be the earliest:
 * - the least exceeds the tolerance: the band is certain and stated as missing;
 * - only the most exceeds it: the band is stated as possible;
 * - the most is within it: nothing is stated.
 * Either statement is capped at the whole window.
 */
export function channelStartGap(
  channel: string,
  read: ChannelRead,
  anchorEpoch: number,
  lengthMs: number
): StartGap | null {
  const tolerance = lengthMs * MAX_UNREPORTED_START_BAND_SHARE;
  const least = read.issuedEpoch - anchorEpoch;
  const most = Math.max(read.repliedEpoch - anchorEpoch, least);
  if (most <= tolerance) return null;
  if (least > tolerance) {
    return {
      definite: true,
      text: `${channel} was read at ${isoOrUnknown(read.issuedEpoch)}, ${formatSpan(least)} after the comparison anchor ${isoOrUnknown(anchorEpoch)}, so the first ${formatSpan(Math.min(least, lengthMs))} of its current period is not covered.`,
    };
  }
  return {
    definite: false,
    text: `${channel} may be missing up to ${formatSpan(Math.min(most, lengthMs))} at the start of its current period: the service evaluated its window at some point during a read that took ${formatSpan(read.repliedEpoch - read.issuedEpoch)}.`,
  };
}

/**
 * Whether a text criterion could be silently changing the count.
 *
 * A provider-description gap means an event's message text was not rendered. That leaves every
 * count intact until a criterion reads the message: a search, or a quick filter whose scope
 * includes the message column. Then an event can drop out of the view on text it never had.
 */
export function messageTextCriterionActive(visibility: ComparisonVisibility): boolean {
  if (visibility.filterSearch.trim() !== "") return true;
  const quick = visibility.quickFilter;
  if (!quick || quick.query.trim() === "" || quick.mode === "eventIds") return false;
  return (
    quick.scope === "allColumns" ||
    visibility.visibleColumns === undefined ||
    visibility.visibleColumns.includes("message")
  );
}

/** A coverage gap that can change a count, or that could while a text criterion is active. */
function gapAffectsCounts(kind: EvtxCoverageGap["kind"], visibility: ComparisonVisibility): boolean {
  return kind !== "provider" || messageTextCriterionActive(visibility);
}

export interface FilesComparisonInput {
  records: readonly EvtxRecord[];
  window: EvtxTimeWindow;
  /** The workspace's `nowEpoch`: the instant the current window is measured from. */
  anchorEpoch: number;
  visibility: ComparisonVisibility;
  /** Structured gaps the load recorded (damaged chunks and records, XML, record budget). */
  coverageDetails: readonly EvtxCoverageGap[];
  /** Sources the manifest could not read or truncated. */
  sourceCoverage: readonly EventLogSourceCoverage[];
}

/**
 * The previous-period counts computed from the records already loaded, or why they cannot be.
 *
 * The outcome is `partial`, with the shortfall stated, when:
 * - a loaded capture ends before the anchor, so part of the current period is not in the files (a
 *   capture older than the anchor never covers the current period it is compared with);
 * - the load reported a hole in a selected source (a damaged chunk, an exhausted record budget, a
 *   source it could not read); or
 * - visible events have no usable timestamp.
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

  const gaps: string[] = [];
  const shortCaptures = coverage.captures
    .filter((capture) => capture.latestMs < prior.anchorEpoch)
    .sort((a, b) => a.latestMs - b.latestMs);
  gaps.push(
    ...limitGapLines(
      shortCaptures.map(
        (capture) =>
          `${capture.source} (${capture.channel}) has no events after ${isoOrUnknown(capture.latestMs)}, so the last ${formatSpan(prior.anchorEpoch - capture.latestMs)} of the current period is not covered.`
      )
    )
  );

  // Holes the load itself reported. A source the loaded records never mention might hold any of the
  // selected channels, so its gaps are carried; a source whose records are all in unselected
  // channels is not what this comparison counts.
  const knownSources = new Set<string>();
  const selectedSources = new Set<string>();
  for (const candidate of input.records) {
    knownSources.add(candidate.sourceLabel);
    if (input.visibility.selectedChannels.has(candidate.channel)) {
      selectedSources.add(candidate.sourceLabel);
    }
  }
  const carried = new Map<string, string>();
  for (const gap of input.coverageDetails) {
    if (!gapAffectsCounts(gap.kind, input.visibility)) continue;
    if (knownSources.has(gap.source) && !selectedSources.has(gap.source)) continue;
    carried.set(formatCoverageGap(gap), gap.source);
  }
  for (const entry of input.sourceCoverage) carried.set(`${entry.path}: ${entry.reason}`, entry.path);
  gaps.push(...limitGapLines([...carried.keys()]));

  if (tally.unplacedRecords > 0) gaps.push(unplacedGap(tally.unplacedRecords, "files"));

  // A channel read in full that held no events in the period is a real zero. A channel is read in
  // full only if none of the sources that hold it reported a hole: a clean capture of System does
  // not make System zero when another capture of System lost a chunk.
  // Nor is a channel with an event that could not be placed in time, or any channel while a hole
  // is in a source no loaded record can place, since that source might hold any of them.
  const counted = new Map(tally.counts.channels);
  const gapSources = new Set(carried.values());
  const captureSources = new Set(coverage.captures.map((capture) => capture.source));
  const holeInAnUnplacedSource = [...gapSources].some((source) => !captureSources.has(source));
  const channelsWithAHole = new Set(
    coverage.captures
      .filter((capture) => gapSources.has(capture.source))
      .map((capture) => capture.channel)
  );
  const comparedChannels = [...new Set(coverage.captures.map((capture) => capture.channel))];
  // A capture that stops before the anchor leaves the end of the current period unread too.
  const shortChannels = new Set(shortCaptures.map((capture) => capture.channel));
  const channelsWithGaps = comparedChannels.filter(
    (channel) =>
      holeInAnUnplacedSource ||
      channelsWithAHole.has(channel) ||
      shortChannels.has(channel) ||
      tally.unplacedChannels.has(channel)
  );
  for (const capture of coverage.captures) {
    if (
      !counted.has(capture.channel) &&
      !holeInAnUnplacedSource &&
      !channelsWithAHole.has(capture.channel) &&
      !tally.unplacedChannels.has(capture.channel)
    ) {
      counted.set(capture.channel, 0);
    }
  }

  return {
    status: gaps.length === 0 ? "complete" : "partial",
    result: {
      mode: "files",
      window: prior.window,
      prior,
      anchorBasis: "clock",
      counts: { ...tally.counts, channels: counted },
      gaps,
      notes: [],
      unplacedRecords: tally.unplacedRecords,
      unreadChannels: [],
      comparedChannels,
      channelsWithGaps,
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Published state
// ---------------------------------------------------------------------------------------------

export type ComparisonState =
  | { phase: "idle" }
  | {
      phase: "running";
      mode: "live";
      requestId: string;
      prior: PriorWindow;
      /**
       * Events the query has scanned so far, across channels. Progress of the work, not a count of
       * anything: the previous period's totals are published only when it settles.
       */
      scanned: number;
    }
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
  /** The earliest instant a compared channel's current read was issued. */
  anchorEpoch: number;
  /** True for a remote machine, whose clock this computer's clock is compared against. */
  remote: boolean;
  /** Context for the reader that is not a shortfall, such as events deliberately left out. */
  notes: readonly string[];
  /** The channels to read, each queried under the session's request ID. */
  channels: readonly string[];
  visibility: ComparisonVisibility;
  /**
   * Shortfalls in the CURRENT period that the load reported for the compared channels, already
   * worded and grouped by cause. They make the outcome partial: the previous period can be read
   * cleanly while the period it is compared with is not. Each cause is limited on its own, so one
   * flood of lines cannot starve another.
   */
  currentPeriodGaps: ReadonlyArray<readonly string[]>;
  /** The compared channels those gaps concern, whose current count of 0 cannot be trusted. */
  currentPeriodHoleChannels: readonly string[];
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
  /** Events the query reports having scanned so far (progress events). */
  fetched: number;
  settled: boolean;
  timer?: ReturnType<typeof setTimeout>;
  gaps: string[];
  unread: boolean;
}

interface ActiveSession {
  requestId: string;
  prior: PriorWindow;
  notes: string[];
  currentPeriodGaps: string[][];
  currentPeriodHoleChannels: Set<string>;
  /** Whether provider-description gaps can change a count, fixed when the comparison starts. */
  providerGapsMatter: boolean;
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
  const channelGaps = session.channels.flatMap(
    (channel) => session.streams.get(channel)?.gaps ?? []
  );
  // Every cause is limited, so a comparison of hundreds of channels states a few and counts the rest.
  const gaps = [...limitGapLines(channelGaps)];
  const unreadChannels = session.channels.filter((channel) => session.streams.get(channel)?.unread);
  if (tally.unplacedRecords > 0) gaps.push(unplacedGap(tally.unplacedRecords, "live"));
  if (tally.outsideWindowRecords > 0) {
    const n = tally.outsideWindowRecords;
    gaps.push(
      `${n} ${plural(n, "event the query returned lies", "events the query returned lie")} outside the previous period and ${plural(n, "was", "were")} not counted.`
    );
  }

  for (const cause of session.currentPeriodGaps) {
    gaps.push(...limitGapLines(cause.map((gap) => `Current period: ${gap}`)));
  }

  // A channel read in full that held no events in the period is a real zero, which an unread
  // channel, one whose stream reported anything missing, or one with an event that could not be
  // placed in time, is not.
  const counted = new Map(tally.counts.channels);
  for (const channel of session.channels) {
    const stream = session.streams.get(channel);
    if (
      !counted.has(channel) &&
      stream !== undefined &&
      stream.gaps.length === 0 &&
      !tally.unplacedChannels.has(channel)
    ) {
      counted.set(channel, 0);
    }
  }

  const channelsWithGaps = session.channels.filter(
    (channel) =>
      (session.streams.get(channel)?.gaps.length ?? 0) > 0 ||
      session.currentPeriodHoleChannels.has(channel) ||
      tally.unplacedChannels.has(channel)
  );

  const outcome: ComparisonOutcome =
    unreadChannels.length === session.channels.length
      ? { status: "unavailable", reason: "queryFailed", detail: limitGapLines(channelGaps).join(" ") }
      : {
          status: gaps.length === 0 ? "complete" : "partial",
          result: {
            mode: "live",
            window: session.prior.window,
            prior: session.prior,
            anchorBasis: "load",
            counts: { ...tally.counts, channels: counted },
            gaps,
            notes: session.notes,
            unplacedRecords: tally.unplacedRecords,
            unreadChannels,
            comparedChannels: session.channels,
            channelsWithGaps,
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
    notes: [
      ...(input.remote ? ["Periods are computed on this computer's clock"] : []),
      ...input.notes,
    ],
    currentPeriodGaps: input.currentPeriodGaps.map((cause) => [...cause]),
    currentPeriodHoleChannels: new Set(input.currentPeriodHoleChannels),
    providerGapsMatter: messageTextCriterionActive(input.visibility),
    channels,
    streams: new Map(
      channels.map((channel) => [
        channel,
        {
          received: 0,
          fetched: 0,
          sequences: new Set<number>(),
          settled: false,
          gaps: [],
          unread: false,
        },
      ])
    ),
    aggregator: createAggregator(prior, input.visibility),
    active: true,
    cancelQuery: input.cancelQuery,
    resolveDone,
  };
  activeSession = session;
  publish({ phase: "running", mode: "live", requestId, prior, scanned: 0 });

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
          // A provider-description failure leaves every count intact unless a criterion reads the
          // message text, in which case an event can drop out of the count for text it never had.
          gaps: checked.coverageGaps
            .filter((coverageGap) => coverageGap.kind !== "provider" || session.providerGapsMatter)
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

export interface ComparisonProgress {
  requestId: string;
  channel: string;
  fetched: number;
}

/**
 * Takes a channel's scan progress for the active comparison and publishes the total scanned so far.
 * The query is unbounded, so this is the only sign of life a long scan gives; it carries no counts.
 */
export function observeComparisonProgress(progress: ComparisonProgress): void {
  const session = activeSession;
  if (!session || session.requestId !== progress.requestId) return;
  const stream = session.streams.get(progress.channel);
  if (!stream || stream.settled || !Number.isFinite(progress.fetched)) return;
  stream.fetched = Math.max(stream.fetched, progress.fetched);
  let scanned = 0;
  for (const each of session.streams.values()) scanned += each.fetched;
  publish({
    phase: "running",
    mode: "live",
    requestId: session.requestId,
    prior: session.prior,
    scanned,
  });
}

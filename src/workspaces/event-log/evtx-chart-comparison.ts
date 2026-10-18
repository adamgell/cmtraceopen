/**
 * What the Charts view says about a previous-period comparison, state by state (spec 8.10, 8.16
 * and D15). Pure: the store's published state, the availability of the control and the tiles' clock
 * go in, plain text and flags come out.
 *
 * Evidence-first rules this module keeps:
 * - A delta exists only for a comparison that finished complete AND still describes the period the
 *   tiles show. A running, refused, partial, out-of-date or cleared comparison has none.
 * - A partial result withholds every delta and lists the comparison's own reasons as written. Its
 *   gap lines name the period and channel they concern, but carry no field to filter on, and a
 *   hole in the previous period inflates a ratio while one in the current period deflates it, so no
 *   number is shown that a hole could have moved.
 * - A refusal is stated in the comparison's own words, never reworded into something it did not
 *   say. A control is disabled with the same words, shown beside it as well as in a tooltip.
 * - An out-of-date comparison says which period it covers and which the tiles now show.
 * - Every time is printed by `formatEventTime` in the clock the operator reads, with the zone named.
 */
import type { EvtxChartComparison } from "./evtx-chart-data";
import {
  currentPeriodOf,
  isComparisonStale,
  type ComparisonOutcome,
  type ComparisonState,
  type PriorWindow,
} from "./evtx-comparison";
import { formatEventTime, timeZoneLabel, type EvtxTimeZoneMode } from "./evtx-time";

export const COMPARE_LABEL = "Compare with previous period";
export const CLEARED_NOTICE = "The comparison was cleared because what it measured changed.";

const plural = (count: number, one: string, many: string) => `${count.toLocaleString()} ${count === 1 ? one : many}`;

/** Whether Compare can be offered now, with the comparison's own reason when it cannot. */
export type ComparisonAvailability = { available: true } | { available: false; detail: string };

/** The current period of a completed comparison, counted the way its previous period was. */
export interface CurrentPeriodFigures {
  errors: number;
  distinctIds: ReadonlySet<string>;
  /** Tail events the count set aside, from the same rows as the other figures. */
  tailExcluded: number;
}

export interface ComparisonPresentationInput {
  state: ComparisonState;
  availability: ComparisonAvailability;
  timeZoneMode: EvtxTimeZoneMode;
  /** The instant the tiles are measured from (the workspace's `nowEpoch`). */
  snapshotEpoch: number;
  /** Called at most once, and only for a complete comparison that is still current. */
  countCurrent: () => CurrentPeriodFigures;
  /** The store went idle after a comparison was on show, without the operator clearing it. */
  cleared: boolean;
}

export interface ComparisonAction {
  label: string;
  /** `compare` starts a comparison; `recompare` replaces one that is out of date. */
  kind: "compare" | "recompare";
  disabled: boolean;
  /** Why the action is disabled, in the comparison's words; null when it is not. */
  reason: string | null;
}

export interface ComparisonPresentation {
  phase: "off" | "running" | "complete" | "partial" | "unavailable" | "stale";
  /** "Comparing with {start} to {end} ({zone})": the previous period, while one is running or on show. */
  label: string | null;
  status: string | null;
  /** Lines listed under the status: a partial comparison's reasons, as the comparison wrote them. */
  reasons: readonly string[];
  /** Context for a comparison on show: its notes, and the tail events left out. */
  notes: readonly string[];
  action: ComparisonAction | null;
  /** Clear is offered exactly while a comparison is running or on show. */
  canClear: boolean;
  clearedNotice: string | null;
  /** The deltas' two periods; present only for a complete comparison that is still current. */
  deltas: EvtxChartComparison | null;
}

function zoneName(mode: EvtxTimeZoneMode, epochMs: number): string {
  return timeZoneLabel(mode, epochMs);
}

/**
 * Two bounds as a period, each in the operator's clock. The offset in force can differ between the
 * bounds when the clock changes in between (daylight saving), so each is named when they differ;
 * when they share one it is named once.
 */
function span(fromMs: number, toMs: number, mode: EvtxTimeZoneMode): string {
  const from = zoneName(mode, fromMs);
  const to = zoneName(mode, toMs);
  const start = formatEventTime(fromMs, mode);
  const end = formatEventTime(toMs, mode);
  return from === to ? `${start} to ${end} (${from})` : `${start} (${from}) to ${end} (${to})`;
}

function priorLabel(prior: PriorWindow, mode: EvtxTimeZoneMode): string {
  return `Comparing with ${span(prior.fromMs, prior.toMs, mode)}`;
}

function staleStatus(prior: PriorWindow, snapshotEpoch: number, mode: EvtxTimeZoneMode): string {
  const covered = currentPeriodOf(prior);
  const covers = span(covered.fromMs, covered.toMs, mode);
  const tilesFrom = snapshotEpoch - prior.lengthMs;
  const tiles = Number.isFinite(snapshotEpoch)
    ? `the tiles now show events from ${formatEventTime(tilesFrom, mode)} (${zoneName(mode, tilesFrom)})`
    : "the time the tiles are measured from is not known";
  return `Out of date. The comparison covers ${covers}; ${tiles}. No change is shown.`;
}

function offered(availability: ComparisonAvailability): ComparisonAction {
  return {
    label: COMPARE_LABEL,
    kind: "compare",
    disabled: !availability.available,
    reason: availability.available ? null : availability.detail,
  };
}

const NOTHING = {
  label: null,
  status: null,
  reasons: [],
  notes: [],
  action: null,
  canClear: false,
  clearedNotice: null,
  deltas: null,
} as const;

function onShow(
  outcome: Exclude<ComparisonOutcome, { status: "unavailable" }>,
  input: ComparisonPresentationInput,
): ComparisonPresentation {
  const { result } = outcome;
  const { timeZoneMode, snapshotEpoch } = input;
  if (isComparisonStale(result.prior, snapshotEpoch)) {
    return {
      ...NOTHING,
      phase: "stale",
      status: staleStatus(result.prior, snapshotEpoch, timeZoneMode),
      // A live read keeps its anchor until the channels are read again, so comparing again alone
      // would describe the same period; the read comes first.
      action: {
        label: result.mode === "live" ? "Refresh and compare again" : "Compare again",
        kind: "recompare",
        disabled: false,
        reason: null,
      },
      canClear: true,
    };
  }
  const label = priorLabel(result.prior, timeZoneMode);
  if (outcome.status === "partial") {
    return {
      ...NOTHING,
      phase: "partial",
      label,
      status:
        result.gaps.length > 0
          ? "Partial. No change is shown, because the counts for these periods are not complete:"
          : "Partial. No change is shown.",
      reasons: result.gaps,
      notes: result.notes,
      canClear: true,
    };
  }
  const current = input.countCurrent();
  const notes = [...result.notes];
  if (current.tailExcluded > 0) {
    notes.push(
      `Left out of the current period: ${plural(current.tailExcluded, "event", "events")} appended by the live tail.`,
    );
  }
  return {
    ...NOTHING,
    phase: "complete",
    label,
    notes,
    canClear: true,
    deltas: {
      window: result.window,
      current: { errors: current.errors, distinctIds: current.distinctIds },
      prior: {
        errors: result.counts.levels.Error,
        distinctIds: result.counts.distinctEvents,
      },
    },
  };
}

export function buildComparisonPresentation(
  input: ComparisonPresentationInput,
): ComparisonPresentation {
  const { state } = input;
  if (state.phase === "running") {
    return {
      ...NOTHING,
      phase: "running",
      label: priorLabel(state.prior, input.timeZoneMode),
      status:
        state.scanned > 0
          ? `Reading the previous period: ${plural(state.scanned, "event", "events")} scanned so far.`
          : "Reading the previous period.",
      canClear: true,
    };
  }
  if (state.phase === "settled") {
    if (state.outcome.status === "unavailable") {
      return {
        ...NOTHING,
        phase: "unavailable",
        status: `Comparison unavailable: ${state.outcome.detail}`,
        action: offered(input.availability),
        canClear: true,
      };
    }
    return onShow(state.outcome, input);
  }
  return {
    ...NOTHING,
    phase: "off",
    action: offered(input.availability),
    clearedNotice: input.cleared ? CLEARED_NOTICE : null,
  };
}

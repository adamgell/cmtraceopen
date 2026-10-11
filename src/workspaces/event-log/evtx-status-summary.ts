/**
 * What the global status bar needs from the Event Logs workspace (spec 8.14), published by the
 * workspace and read by `StatusBar`.
 *
 * Kept out of both `StatusBar.tsx` and `evtx-store.ts` on purpose. Importing the status bar pulls
 * in every workspace store, and the evtx store registers Tauri listeners at module scope; this
 * module imports neither, so the workspace and its tests can publish without either.
 *
 * Two values are published, both derived from rows the workspace has already computed, so the
 * status bar never runs a second pass over the records:
 * - the visible summary: how many rows the grid shows, how many of them are errors and warnings,
 *   how many events are loaded behind them (the chip row's "Showing {visible} of {loaded}") and
 *   how many channels those events came from;
 * - the correlation counts for the Correlation view variant.
 *
 * Every value carries the evtx store's `loadGeneration` as its key. A generation is bumped by each
 * new load, refresh, source change and reset, so a value published for one source can never be
 * shown against another: the reader compares the key with the store's current generation
 * (`valueForGeneration`) and treats a mismatch as "not published". The publisher also clears the
 * value on unmount, while a query runs and whenever the analysis session is rebuilt.
 */
import { create } from "zustand";
import type { CorrelationChainModel } from "./evtx-correlation-chains";
import type { EvtxRecord } from "./types";

/** A published value, valid only for the evtx store generation it was computed under. */
export interface GenerationKeyed {
  /** `useEvtxStore.getState().loadGeneration` when the value was computed. */
  generation: number;
}

export interface EvtxProblemCounts {
  errors: number;
  warnings: number;
}

/**
 * Errors and warnings among `records`.
 *
 * Critical is counted with Error. The status bar has one slot for the two ("{e} errors") and the
 * grid tints Critical and Error rows alike (spec D3), so leaving Critical out would leave red
 * rows on screen that no count accounts for. Verbose and Information are not problems.
 */
export function countProblemLevels(
  records: readonly Pick<EvtxRecord, "level">[],
): EvtxProblemCounts {
  let errors = 0;
  let warnings = 0;
  for (const record of records) {
    if (record.level === "Error" || record.level === "Critical") errors += 1;
    else if (record.level === "Warning") warnings += 1;
  }
  return { errors, warnings };
}

/**
 * Loaded channels as the status bar counts them (spec 8.14).
 *
 * Live mode counts the channels whose load completed (`loadedChannels`), not every channel that
 * was enumerated. Files mode counts the DISTINCT channel names of the event records that loaded.
 * It must not count the parse result's `channels` list: the archive reader sets the `channel` of
 * an archived text log to that log's source label, so a text log would count as a channel; a
 * rotated archive repeats one channel once per file; and a file with no records would count as
 * a channel that contributed nothing. Text-log records (`originKind` "log") are not channels.
 */
export function loadedChannelCountFor(input: {
  sourceMode: "files" | "live" | null;
  loadedChannels: ReadonlySet<string>;
  records: readonly Pick<EvtxRecord, "channel" | "originKind">[];
}): number {
  if (input.sourceMode === "live") return input.loadedChannels.size;
  const names = new Set<string>();
  for (const record of input.records) {
    if (record.originKind !== "log") names.add(record.channel);
  }
  return names.size;
}

export interface EvtxVisibleSummary extends GenerationKeyed, EvtxProblemCounts {
  /** Rows the grid shows: `{n} events`, equal to the chip row's "Showing {visible}". */
  visible: number;
  /** Events loaded behind them: the chip row's "of {loaded}". */
  loaded: number;
  /** `loadedChannelCountFor` for the source on screen: `{c} channels`. */
  channels: number;
}

/**
 * Summarizes the rows the workspace computed. `visible` is its `visibleRecords`, not a new pass;
 * `loaded` and `channels` describe the records behind it.
 */
export function summarizeVisibleRecords(
  visible: readonly Pick<EvtxRecord, "level">[],
  loaded: { events: number; channels: number },
  generation: number,
): EvtxVisibleSummary {
  return {
    generation,
    visible: visible.length,
    loaded: loaded.events,
    channels: loaded.channels,
    ...countProblemLevels(visible),
  };
}

/**
 * What the Correlation view variant of the left segment needs (spec 8.14). `exact` and
 * `candidate` are the chain counts; ambiguous and coverage-blocked rows are not chains (Q-4) and
 * `timestampOnly` / `notCausal` relations are never counted at all (D7).
 */
export interface EvtxCorrelationStatus extends GenerationKeyed {
  exact: number;
  candidate: number;
  ambiguous: number;
  /** Items the analysis session could not place: the session total, not the capped preview. */
  unplaced: number;
}

/**
 * Reduces the chain model to the status counts, or null when they would not be totals.
 *
 * `model.counts` is taken before the 100-row render cap. It is only the session's total when
 * every edge was loaded (`edgeInputComplete`): a bounded edge preview can miss chains, and a
 * missed ambiguous or coverage-blocked edge would also have vetoed a link that is counted. No
 * bound on either direction holds, so an incomplete model yields no counts rather than a number
 * that reads as a total.
 *
 * `totalUnplaced` is `EventLogAnalysisSessionStatus.totalUnplaced`, not the length of
 * `unplacedPreview`, which is capped.
 */
export function summarizeEvtxCorrelationStatus(
  model: Pick<CorrelationChainModel, "counts" | "edgeInputComplete">,
  totalUnplaced: number,
  generation: number,
): EvtxCorrelationStatus | null {
  if (!model.edgeInputComplete) return null;
  if (!Number.isSafeInteger(totalUnplaced) || totalUnplaced < 0) return null;
  return {
    generation,
    exact: model.counts.exact,
    candidate: model.counts.candidate,
    ambiguous: model.counts.ambiguous,
    unplaced: totalUnplaced,
  };
}

/** The value, only if it was published for `generation`; a value from another source is null. */
export function valueForGeneration<T extends GenerationKeyed>(
  value: T | null | undefined,
  generation: number,
): T | null {
  return value != null && value.generation === generation ? value : null;
}

interface EvtxVisibleSummaryState {
  summary: EvtxVisibleSummary | null;
  publish: (summary: EvtxVisibleSummary | null) => void;
}

/** Published by `EventLogWorkspace`; cleared while a query runs and on unmount. */
export const useEvtxVisibleSummaryStore = create<EvtxVisibleSummaryState>()(
  (set) => ({
    summary: null,
    publish: (summary) => set({ summary }),
  }),
);

interface EvtxCorrelationStatusState {
  status: EvtxCorrelationStatus | null;
  publish: (status: EvtxCorrelationStatus | null) => void;
}

/**
 * Phase 10 publishes the chain counts here, through `summarizeEvtxCorrelationStatus`, once it
 * builds the chain model. The workspace clears it on every analysis rebuild and on unmount.
 */
export const useEvtxCorrelationStatusStore = create<EvtxCorrelationStatusState>()(
  (set) => ({
    status: null,
    publish: (status) => set({ status }),
  }),
);

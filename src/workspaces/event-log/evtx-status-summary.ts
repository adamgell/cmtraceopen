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
 *   how many channels and text-log sources those events came from;
 * - the correlation counts for the Correlation view variant.
 *
 * The visible summary carries the evtx store's `loadGeneration` as its key. A generation is
 * bumped by each new load, refresh, source change and reset, so a summary published for one
 * source can never be shown against another: the reader compares the key with the store's current
 * generation (`valueForGeneration`) and treats a mismatch as "not published". The correlation
 * counts are keyed by the analysis session and revision they were built from, and the reader
 * compares them with the session the workspace named (`currentCorrelationStatus`), not with the
 * current generation: a load that is refused or fails leaves the session on screen, and its counts
 * stay valid. The workspace publishes nothing while a query runs or when nothing was read, and
 * clears everything on unmount.
 */
import { create } from "zustand";
import type { CorrelationChainModel } from "./evtx-correlation-chains";
import type { EvtxRecord } from "./types";

/** A published value, valid only for the evtx store generation it was computed under. */
export interface GenerationKeyed {
  /** `useEvtxStore.getState().loadGeneration` when the value was computed. */
  readonly generation: number;
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

/** What the source on screen has produced. */
export type EvtxReadState =
  /** Nothing: no channel completed (live), or no record at all (files). */
  | "nothing"
  /** Files whose records are all archived text logs: no event record was read. */
  | "textLogsOnly"
  | "events";

/**
 * What the source on screen has read. A live load counts once a channel has completed
 * (`loadedChannels`, which a cancelled or refused read never fills). A file source counts as
 * having read events once it produced an EVENT record; records that are all archived text logs
 * are "textLogsOnly", because the event files beside them may have failed to read.
 *
 * Without a read event the error and warning counts are unknown, not zero, and so are the event
 * and channel counts: "0 channels" would read as "this source has no event channels" rather than
 * "they could not be read". The status bar therefore publishes no event counts for "textLogsOnly"
 * and no counts at all for "nothing" (soul.md rule 4).
 */
export function readStateFor(input: {
  sourceMode: "files" | "live" | null;
  loadedChannelCount: number;
  records: readonly Pick<EvtxRecord, "originKind">[];
}): EvtxReadState {
  if (input.sourceMode === "live") {
    return input.loadedChannelCount > 0 ? "events" : "nothing";
  }
  if (input.sourceMode !== "files") return "nothing";
  let sawTextLog = false;
  for (const record of input.records) {
    if (record.originKind !== "log") return "events";
    sawTextLog = true;
  }
  return sawTextLog ? "textLogsOnly" : "nothing";
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
 *
 * Phase 14 (#846) exports a helper with this name and rule from `evtx-chart-data.ts`. Whichever of
 * #846 and #847 merges second imports the other's and deletes its own copy.
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

/**
 * Distinct text-log sources: the file paths of the log-store entries the workspace correlates
 * (already scoped by `scopeLogEntries`) plus the source labels of archived text-log records,
 * de-duplicated across both. This counts sources, not lines.
 *
 * Phase 14 (#846) exports a helper with this name and rule from `evtx-chart-data.ts`. Whichever of
 * #846 and #847 merges second imports the other's and deletes its own copy.
 */
export function countTextLogSources(
  entries: readonly { filePath: string }[],
  records: readonly Pick<EvtxRecord, "originKind" | "sourceLabel">[],
): number {
  const sources = new Set<string>();
  for (const entry of entries) sources.add(entry.filePath);
  for (const record of records) {
    if (record.originKind === "log") sources.add(record.sourceLabel);
  }
  return sources.size;
}

/** The event counts of a visible summary. */
export interface EvtxEventCounts extends EvtxProblemCounts {
  /** Rows the grid shows: `{n} events`, equal to the chip row's "Showing {visible}". */
  visible: number;
  /** Events loaded behind them: the chip row's "of {loaded}". */
  loaded: number;
  /** `loadedChannelCountFor` for the source on screen: `{c} channels`. */
  channels: number;
}

export interface EvtxVisibleSummary extends GenerationKeyed {
  /** `countTextLogSources` for the source on screen: `{l} text logs`. Known whenever one exists. */
  textLogs: number;
  /**
   * The event, channel, error and warning counts, or null when no event record was read (a files
   * source whose records are all text logs): those counts are unknown, not zero.
   */
  events: EvtxEventCounts | null;
}

/**
 * Summarizes the rows the workspace computed. `visible` is its `visibleRecords`, not a new pass;
 * `loaded` describes the records behind it. With `eventsRead` false the event counts are absent.
 */
export function summarizeVisibleRecords(
  visible: readonly Pick<EvtxRecord, "level">[],
  loaded: { records: number; channels: number; textLogs: number; eventsRead: boolean },
  generation: number,
): EvtxVisibleSummary {
  return {
    generation,
    textLogs: loaded.textLogs,
    events: loaded.eventsRead
      ? {
          visible: visible.length,
          loaded: loaded.records,
          channels: loaded.channels,
          ...countProblemLevels(visible),
        }
      : null,
  };
}

/**
 * The analysis session the correlation counts were built from. A session id alone is not enough:
 * a session is rebuilt as its input changes, and its revision says which build the counts belong
 * to. `generation` is the load generation the build's input was snapshotted under; it names the
 * build and is not compared with the store's current generation, which moves on loads that
 * rebuild nothing (a refused or failed open leaves the session on screen valid).
 */
export interface EvtxAnalysisKey extends GenerationKeyed {
  readonly sessionId: string;
  readonly revision: number;
}

declare const summarized: unique symbol;

/**
 * What the Correlation view variant of the left segment needs (spec 8.14). `exact` and
 * `candidate` are the chain counts; ambiguous and coverage-blocked rows are not chains (Q-4) and
 * `timestampOnly` / `notCausal` relations are never counted at all (D7).
 *
 * Only `summarizeEvtxCorrelationStatus` issues one. The brand makes a hand-written literal a type
 * error, but a spread of an existing status keeps the brand, so the store also checks at runtime
 * that it was issued by the summarizer and refuses any other object.
 */
export type EvtxCorrelationStatus = Readonly<{
  exact: number;
  candidate: number;
  ambiguous: number;
  /** Items the analysis session could not place: the session total, not the capped preview. */
  unplaced: number;
}> &
  EvtxAnalysisKey & { readonly [summarized]: true };

/** The statuses `summarizeEvtxCorrelationStatus` issued; the store refuses anything else. */
const issuedStatuses = new WeakSet<object>();

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
 * `unplacedPreview`, which is capped. `key` names the analysis session and revision the model
 * was built from.
 */
export function summarizeEvtxCorrelationStatus(
  model: Pick<CorrelationChainModel, "counts" | "edgeInputComplete">,
  totalUnplaced: number,
  key: EvtxAnalysisKey,
): EvtxCorrelationStatus | null {
  if (!model.edgeInputComplete) return null;
  if (!Number.isSafeInteger(totalUnplaced) || totalUnplaced < 0) return null;
  const status = Object.freeze({
    generation: key.generation,
    sessionId: key.sessionId,
    revision: key.revision,
    exact: model.counts.exact,
    candidate: model.counts.candidate,
    ambiguous: model.counts.ambiguous,
    unplaced: totalUnplaced,
  }) as unknown as EvtxCorrelationStatus;
  issuedStatuses.add(status);
  return status;
}

function sameAnalysis(a: EvtxAnalysisKey, b: EvtxAnalysisKey): boolean {
  return (
    a.generation === b.generation &&
    a.sessionId === b.sessionId &&
    a.revision === b.revision
  );
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

/**
 * Published by `EventLogWorkspace`. Null while a query runs, when nothing was read, and after
 * unmount.
 */
export const useEvtxVisibleSummaryStore = create<EvtxVisibleSummaryState>()(
  (set) => ({
    summary: null,
    publish: (summary) => set({ summary }),
  }),
);

interface EvtxCorrelationStatusState {
  /** The analysis session on screen, or null while it is being rebuilt. */
  analysis: EvtxAnalysisKey | null;
  status: EvtxCorrelationStatus | null;
  /** The workspace names the session on screen; counts built for any other one are dropped. */
  setAnalysis: (analysis: EvtxAnalysisKey | null) => void;
  /** Accepts only the summarizer's output, and only for the session `setAnalysis` named. */
  publish: (status: EvtxCorrelationStatus | null) => void;
}

/**
 * The counts, only if they were built for the analysis session the workspace has on screen. The
 * store already keeps them that way; the reader re-checks so a status can never outlive the
 * session it names.
 */
export function currentCorrelationStatus(state: {
  analysis: EvtxAnalysisKey | null;
  status: EvtxCorrelationStatus | null;
}): EvtxCorrelationStatus | null {
  return state.status !== null &&
    state.analysis !== null &&
    sameAnalysis(state.status, state.analysis)
    ? state.status
    : null;
}

/**
 * Phase 10 publishes the chain counts here, through `summarizeEvtxCorrelationStatus`, once it
 * builds the chain model. The workspace names the analysis session on screen with `setAnalysis`
 * when it is ready and clears it at the start of every rebuild and on unmount.
 *
 * Counts for a session or revision that is not the one on screen are never held: `setAnalysis`
 * drops them, and `publish` refuses them, however late the work that produced them finished.
 */
export const useEvtxCorrelationStatusStore = create<EvtxCorrelationStatusState>()(
  (set) => ({
    analysis: null,
    status: null,
    setAnalysis: (analysis) =>
      set((state) => ({
        analysis,
        status:
          state.status !== null &&
          analysis !== null &&
          sameAnalysis(state.status, analysis)
            ? state.status
            : null,
      })),
    publish: (status) =>
      set((state) => {
        if (status === null) return { status: null };
        return issuedStatuses.has(status) &&
          state.analysis !== null &&
          sameAnalysis(status, state.analysis)
          ? { status }
          : {};
      }),
  }),
);

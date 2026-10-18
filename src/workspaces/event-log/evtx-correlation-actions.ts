/**
 * What a chain offers outside the lazy Correlation view (spec 8.11, 8.12, 8.13): filter the table to
 * it, open it in the Correlation view, and whether either may act. The view, the dock, the Details
 * context list and the rail's Chains tab all call these, so the rule for each is written once and
 * nothing imports from the view, which is loaded on demand.
 *
 * Reads the stores when called and holds no state of its own.
 */
import type { CorrelationChain } from "./evtx-correlation-chains";
import { WAIT_FOR_ENTRIES_REASON } from "./evtx-correlation-copy";
import type { EvtxRecordScopeCounts } from "./evtx-filter";
import { scopeForChain, type OriginLookup } from "./evtx-correlation-origin-index";
import { openCorrelationView, openUnplacedList } from "./evtx-correlation-store";
import { chainTitle } from "./evtx-correlation-view-model";
import { buildEvidenceIndex, describeScopeCounts, type EvidenceIndex } from "./evtx-insights-data";
import { evtxViewTabId, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import { WAIT_FOR_UPDATE_REASON } from "./evtx-unplaced";

/**
 * The index of the records loaded NOW, built when a click needs it and not before. Loaded records
 * change with every live-tail batch while a surface is open, and nothing reads the index until a
 * marker is clicked or the table is filtered, so a memo over the records would rebuild it (tens of
 * milliseconds at 100,000 events) for nothing, on every batch.
 */
export function loadedEvidenceIndex(): EvidenceIndex {
  return buildEvidenceIndex(useEvtxStore.getState().records);
}

/**
 * Why the table was not filtered when `setRecordScope` returned false. It never says "no loaded
 * events" while an entry could not be looked for (`unresolved`): an absence is claimed only for
 * what was found absent by looking, and the counts say which is which.
 */
export function scopeFailureText(counts: EvtxRecordScopeCounts, eventsLoading: boolean): string {
  if (eventsLoading) {
    return "The table was not filtered: events are still loading. Try again when loading has finished.";
  }
  const reasons = describeScopeCounts(counts, "chain");
  return reasons.length > 0
    ? `The table was not filtered: this chain names no event it can show. ${reasons.join(" ")}`
    : "The table was not filtered: this chain names no event it can show.";
}

export type FilterTableToChainResult = { applied: true } | { applied: false; text: string };

/**
 * "Filter table to chain" and "Show in table" (spec 9): applies the chain's record scope, and only
 * when it was applied switches to the Table and moves focus to its tab (the button that was pressed
 * may unmount with its view). A scope that could not be applied changes nothing and returns why.
 */
export function filterTableToChain(input: {
  chain: CorrelationChain;
  origins: OriginLookup;
  /** `CorrelationChainModel.edgeInputComplete`: when false the scope is marked bounded. */
  edgeInputComplete: boolean;
}): FilterTableToChainResult {
  const chainScope = scopeForChain(input.chain, input.origins, loadedEvidenceIndex(), {
    edgeInputComplete: input.edgeInputComplete,
  });
  const store = useEvtxStore.getState();
  const applied = store.setRecordScope({
    kind: "chain",
    title: chainTitle(input.chain),
    records: new Set(chainScope.records),
    references: chainScope.references,
    counts: chainScope.counts,
  });
  if (!applied) {
    return { applied: false, text: scopeFailureText(chainScope.counts, useEvtxStore.getState().isLoading) };
  }
  useEvtxLayoutStore.getState().setActiveView("table");
  document.getElementById(evtxViewTabId("table"))?.focus();
  return { applied: true };
}

/**
 * "Open in correlation view" (spec 9): shows the Correlation view with `chainId` selected, through
 * `openCorrelationView`, which counts as an open so the view drops a lost-selection record it holds,
 * and moves focus to the Correlation tab. Without a chain id the view's selection is left alone.
 */
export function openChainInCorrelationView(chainId?: string | null): void {
  openCorrelationView(chainId);
  document.getElementById(evtxViewTabId("correlation"))?.focus();
}

/**
 * "Review unplaced lines" (spec 8.11a): shows the Correlation view with the Not placed list open, the
 * chain selection left alone, and moves focus to the Correlation tab like every other Open.
 */
export function openUnplacedInCorrelationView(): void {
  openUnplacedList();
  document.getElementById(evtxViewTabId("correlation"))?.focus();
}

/**
 * Whether an action on the model on show (filter the table, copy, open) may act. It waits for a
 * rebuild first, then for the entries to be read: the model on show can be an earlier session's,
 * and a chain whose entries were not read has no records to name.
 */
export function chainActionAvailability(input: {
  hasItems: boolean;
  updating: boolean;
  hasChain: boolean;
}): { canAct: boolean; reason: string | undefined } {
  const canAct = input.hasItems && !input.updating && input.hasChain;
  return {
    canAct,
    reason: canAct ? undefined : input.updating ? WAIT_FOR_UPDATE_REASON : WAIT_FOR_ENTRIES_REASON,
  };
}

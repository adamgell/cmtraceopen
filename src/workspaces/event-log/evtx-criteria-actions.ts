/**
 * Applying saved criteria to the event store: the one place a saved filter or a view is applied
 * from, so the two cannot set different parts of the model. `captureCriteria`
 * (`evtx-saved-filters.ts`) is the matching read.
 *
 * Kept out of `evtx-saved-filters.ts` because that module is free of the store, and the store
 * subscribes to Tauri events at import.
 */
import type { EvtxFilterCriteria } from "./evtx-saved-filters";
import { useEvtxStore } from "./evtx-store";

/**
 * Replaces the before-load criteria, both on-load criteria and the grouping.
 *
 * Before-load criteria go through the store's own setter, so Phase 5's rules apply unchanged: a live
 * source refetches once when the request the service would receive changes, a change made during a
 * load is queued and replayed once (or restored if the load was stopped), and a file source
 * evaluates them locally. A search or quick filter that cannot be applied is kept as a draft and
 * applies nothing, rather than leaving the one from before.
 *
 * The transient criteria (time range, record scope) are not touched here.
 */
export function applyCriteria(criteria: EvtxFilterCriteria): void {
  const store = useEvtxStore.getState();
  store.setBeforeLoadCriteria(criteria.beforeLoad);
  store.setOnLoadCriteria(criteria.onLoad);
  store.setGroupBy(criteria.afterLoad.groupBy);
}

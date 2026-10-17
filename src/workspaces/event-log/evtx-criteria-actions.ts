/**
 * Applying saved criteria to the event store: the one place a saved filter or a view is applied
 * from, so the two cannot set different parts of the model. `captureCriteria`
 * (`evtx-saved-filters.ts`) is the matching read.
 *
 * Kept out of `evtx-saved-filters.ts` because that module is free of the store, and the store
 * subscribes to Tauri events at import.
 */
import { useEvtxLayoutStore, type EvtxPanelId } from "./evtx-layout-store";
import type { EvtxFilterCriteria } from "./evtx-saved-filters";
import { useEvtxStore } from "./evtx-store";
import type { EvtxViewBody } from "./evtx-views";

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

const PANELS: readonly EvtxPanelId[] = ["channels", "insights", "dock"];

/**
 * Applies a view: its criteria, and its layout when it has one.
 *
 * It clears the transient time range and record scope first, in both source modes. A view that
 * changes what a live source is asked for starts a load, and a load start clears them anyway
 * (evtx-store.ts, the subscription below the store); one that does not, and every one on files,
 * would otherwise keep a brushed span or a finding's events drawn over the previous view. One click
 * should do the same in both, and the chips show them go. This differs from applying a saved filter,
 * which leaves them, and from a Top IDs click, which keeps the scope.
 *
 * A view with no layout leaves the layout alone. A panel this build cannot show yet stays off
 * (`setPanel` refuses it).
 */
export function applyView(view: EvtxViewBody): void {
  const store = useEvtxStore.getState();
  if (store.timeRange !== null || store.recordScope !== null) store.clearTransientCriteria();
  applyCriteria(view.criteria);
  if (view.layout === null) return;
  const layout = useEvtxLayoutStore.getState();
  layout.setActiveView(view.layout.activeView);
  for (const id of PANELS) layout.setPanel(id, view.layout.panels[id]);
}

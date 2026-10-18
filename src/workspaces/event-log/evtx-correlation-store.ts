/**
 * What the Correlation view shows in its detail area: a chain (spec section 9, "Open in
 * Correlation view") or the "Not placed" pane (spec 8.11a).
 *
 * Transient on purpose, and deliberately NOT persisted: a chain id embeds origin ids, which carry
 * the machine, the source and the file path, and spec section 9 bars record content from anything
 * saved. The layout store persists the active view and nothing here, so reloading the app opens
 * the view with no chain selected and the view picks its first.
 *
 * The selection is kept here and not in the view because the view is lazy and not kept alive: its
 * own state would be lost on every switch to another view, and the dock and the rail (later
 * phases) select a chain from outside it.
 *
 * "Not placed" is a selection of its own, not a chain id: a reserved id would fail the view's
 * check that a selected chain still exists, and be replaced and announced as lost. The rail's
 * "Review unplaced lines" opens it from outside the view (`openUnplacedList`).
 */
import { create } from "zustand";
import { useEvtxLayoutStore } from "./evtx-layout-store";

interface EvtxCorrelationSelectionState {
  /** The selected chain's id, or null for none (the view then shows its first chain). */
  selectedChainId: string | null;
  /** The "Not placed" pane is the one shown, in place of a chain's detail. */
  unplacedOpen: boolean;
  /**
   * How many chains have been opened from outside the view (`openChain`). The view drops the loss
   * it holds when this changes: a chain the operator has just asked for replaces the selection the
   * loss was about, and the loss must not be said, or shown, about a selection that is gone.
   */
  openedCount: number;
  /** Selects a chain (or none) and leaves the "Not placed" pane. */
  selectChain: (chainId: string | null) => void;
  /**
   * Selects a chain on behalf of something outside the view (the dock's Open) and leaves the "Not
   * placed" pane, like `selectChain`, and counts it in `openedCount`. The view's own reconcile
   * replaces a selection through `selectChain`, which does not count: that is the loss itself.
   */
  openChain: (chainId: string) => void;
  /** Shows the "Not placed" pane. The selected chain is kept, to be there when the pane is left. */
  showUnplaced: () => void;
}

export const useEvtxCorrelationStore = create<EvtxCorrelationSelectionState>()((set) => ({
  selectedChainId: null,
  unplacedOpen: false,
  openedCount: 0,
  selectChain: (chainId) => set({ selectedChainId: chainId, unplacedOpen: false }),
  openChain: (chainId) =>
    set((state) => ({ selectedChainId: chainId, unplacedOpen: false, openedCount: state.openedCount + 1 })),
  showUnplaced: () => set({ unplacedOpen: true }),
}));

/**
 * Switches to the Correlation view, preselecting `chainId` when one is given (through `openChain`,
 * so a loss the view holds is dropped). A call without one (the rail card's "Open correlation
 * view") leaves the current selection alone.
 */
export function openCorrelationView(chainId?: string | null): void {
  if (chainId !== undefined && chainId !== null) {
    useEvtxCorrelationStore.getState().openChain(chainId);
  }
  useEvtxLayoutStore.getState().setActiveView("correlation");
}

/**
 * Switches to the Correlation view with the "Not placed" pane shown ("Review unplaced lines", spec
 * 8.11a). The selected chain and the rail tab are left alone.
 */
export function openUnplacedList(): void {
  useEvtxCorrelationStore.getState().showUnplaced();
  useEvtxLayoutStore.getState().setActiveView("correlation");
}

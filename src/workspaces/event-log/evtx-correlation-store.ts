/**
 * Which correlation chain is selected (spec section 9, "Open in Correlation view").
 *
 * Transient on purpose, and deliberately NOT persisted: a chain id embeds origin ids, which carry
 * the machine, the source and the file path, and spec section 9 bars record content from anything
 * saved. The layout store persists the active view and nothing here, so reloading the app opens
 * the view with no chain selected and the view picks its first.
 *
 * The selection is kept here and not in the view because the view is lazy and not kept alive: its
 * own state would be lost on every switch to another view, and the dock and the rail (later
 * phases) select a chain from outside it.
 */
import { create } from "zustand";
import { useEvtxLayoutStore } from "./evtx-layout-store";

interface EvtxCorrelationSelectionState {
  /** The selected chain's id, or null for none (the view then shows its first chain). */
  selectedChainId: string | null;
  selectChain: (chainId: string | null) => void;
}

export const useEvtxCorrelationStore = create<EvtxCorrelationSelectionState>()((set) => ({
  selectedChainId: null,
  selectChain: (chainId) => set({ selectedChainId: chainId }),
}));

/**
 * Switches to the Correlation view, preselecting `chainId` when one is given. A call without one
 * (the rail card's "Open correlation view") leaves the current selection alone.
 */
export function openCorrelationView(chainId?: string | null): void {
  if (chainId !== undefined && chainId !== null) {
    useEvtxCorrelationStore.getState().selectChain(chainId);
  }
  useEvtxLayoutStore.getState().setActiveView("correlation");
}

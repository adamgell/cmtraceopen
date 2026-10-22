import { beforeEach, describe, expect, it } from "vitest";
import { EVTX_LAYOUT_STORAGE_KEY, useEvtxLayoutStore } from "./evtx-layout-store";
import { openCorrelationView, openUnplacedList, useEvtxCorrelationStore } from "./evtx-correlation-store";
import storeSource from "./evtx-correlation-store.ts?raw";

const CHAIN = "6:chain1|57:source4:Live|machine10:DESKTOP-01|channel6:System|record1";

beforeEach(() => {
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false, openedCount: 0 });
  useEvtxLayoutStore.setState({ activeView: "table", railTab: "insights" });
  localStorage.clear();
});

describe("the chain selection", () => {
  it("starts with none and holds the chain it is given", () => {
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBeNull();
    useEvtxCorrelationStore.getState().selectChain(CHAIN);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(CHAIN);
    useEvtxCorrelationStore.getState().selectChain(null);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBeNull();
  });
});

describe("a chain opened from outside the view (#842, the dock's Open)", () => {
  it("is selected like any other, leaves the Not placed pane, and is counted", () => {
    const store = useEvtxCorrelationStore;
    store.getState().showUnplaced();
    store.getState().openChain(CHAIN);
    expect(store.getState().selectedChainId).toBe(CHAIN);
    expect(store.getState().unplacedOpen).toBe(false);
    expect(store.getState().openedCount).toBe(1);
    store.getState().openChain(CHAIN);
    expect(store.getState().openedCount).toBe(2);
  });

  it("is the one selection that counts: the view's own selectChain does not", () => {
    const store = useEvtxCorrelationStore;
    store.getState().selectChain(CHAIN);
    store.getState().selectChain(null);
    store.getState().showUnplaced();
    expect(store.getState().openedCount).toBe(0);
  });

  it("is what openCorrelationView does with a chain, and only with a chain", () => {
    openCorrelationView(CHAIN);
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(1);
    openCorrelationView();
    openCorrelationView(null);
    openUnplacedList();
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(1);
  });
});

describe("openCorrelationView", () => {
  it("switches to the Correlation view and preselects the chain it is given", () => {
    openCorrelationView(CHAIN);
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(CHAIN);
  });

  it("switches the view and keeps the current selection when it is given no chain", () => {
    useEvtxCorrelationStore.getState().selectChain(CHAIN);
    openCorrelationView();
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(CHAIN);
    openCorrelationView(null);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(CHAIN);
  });
});

describe("the Not placed pane (spec 8.11a)", () => {
  it("starts closed, opens without touching the selected chain, and closes when a chain is selected", () => {
    const store = useEvtxCorrelationStore;
    expect(store.getState().unplacedOpen).toBe(false);
    store.getState().selectChain(CHAIN);
    store.getState().showUnplaced();
    expect(store.getState().unplacedOpen).toBe(true);
    expect(store.getState().selectedChainId).toBe(CHAIN);
    store.getState().selectChain(CHAIN);
    expect(store.getState().unplacedOpen).toBe(false);
  });

  it("closes on selecting no chain too, so a cleared selection never leaves the pane showing", () => {
    useEvtxCorrelationStore.getState().showUnplaced();
    useEvtxCorrelationStore.getState().selectChain(null);
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(false);
  });

  it("is left by opening a chain from outside, and kept by opening the view with no chain", () => {
    useEvtxCorrelationStore.getState().showUnplaced();
    openCorrelationView();
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
    openCorrelationView(null);
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
    openCorrelationView(CHAIN);
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(false);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(CHAIN);
  });

  it("is opened from outside by openUnplacedList, which switches the view and leaves the rest alone", () => {
    useEvtxCorrelationStore.getState().selectChain(CHAIN);
    openUnplacedList();
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(CHAIN);
  });
});

describe("a chain id is never saved", () => {
  it("is absent from everything the layout store persists", () => {
    openCorrelationView(CHAIN);
    useEvtxLayoutStore.getState().setRailWidth(300);
    const saved = localStorage.getItem(EVTX_LAYOUT_STORAGE_KEY);
    expect(saved).not.toBeNull();
    expect(saved).toContain("correlation"); // the active view is saved, as it always was
    expect(saved).not.toContain("DESKTOP-01");
    expect(saved).not.toContain(CHAIN);
  });

  it("writes nothing to storage of its own, and the open pane is not saved", () => {
    openCorrelationView(CHAIN);
    useEvtxCorrelationStore.getState().selectChain(CHAIN);
    openUnplacedList();
    const keys = Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i));
    expect(keys.filter((key) => key !== EVTX_LAYOUT_STORAGE_KEY)).toEqual([]);
    for (const key of keys) expect(localStorage.getItem(key!)).not.toContain(CHAIN);
  });

  it("does not use the persist middleware or browser storage", () => {
    const code = storeSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    expect(code).not.toMatch(/zustand\/middleware|persist|localStorage|sessionStorage/);
  });
});

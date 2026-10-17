import { beforeEach, describe, expect, it } from "vitest";
import { EVTX_LAYOUT_STORAGE_KEY, useEvtxLayoutStore } from "./evtx-layout-store";
import { openCorrelationView, useEvtxCorrelationStore } from "./evtx-correlation-store";
import storeSource from "./evtx-correlation-store.ts?raw";

const CHAIN = "6:chain1|57:source4:Live|machine10:DESKTOP-01|channel6:System|record1";

beforeEach(() => {
  useEvtxCorrelationStore.setState({ selectedChainId: null });
  useEvtxLayoutStore.setState({ activeView: "table" });
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

  it("writes nothing to storage of its own", () => {
    openCorrelationView(CHAIN);
    useEvtxCorrelationStore.getState().selectChain(CHAIN);
    const keys = Array.from({ length: localStorage.length }, (_, i) => localStorage.key(i));
    expect(keys.filter((key) => key !== EVTX_LAYOUT_STORAGE_KEY)).toEqual([]);
    for (const key of keys) expect(localStorage.getItem(key!)).not.toContain(CHAIN);
  });

  it("does not use the persist middleware or browser storage", () => {
    const code = storeSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    expect(code).not.toMatch(/zustand\/middleware|persist|localStorage|sessionStorage/);
  });
});

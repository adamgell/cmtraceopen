import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { applyCriteria } from "./evtx-criteria-actions";
import { DEFAULT_QUICK_FILTER, type EvtxQuickFilter } from "./evtx-filter";
import { captureCriteria, sanitizeCriteria, type EvtxFilterCriteria } from "./evtx-saved-filters";
import { useEvtxStore } from "./evtx-store";

const fieldQuick = (query: string): EvtxQuickFilter => ({
  ...DEFAULT_QUICK_FILTER,
  mode: "fieldQuery",
  query,
});

const CRITERIA: EvtxFilterCriteria = sanitizeCriteria({
  beforeLoad: {
    levels: ["Error", "Warning"],
    eventIds: "75,76",
    timeWindow: "7d",
    selectedChannels: ["System", "Microsoft-Windows-AAD/Operational"],
  },
  onLoad: { search: "id:76", quickFilter: fieldQuick("level:error") },
  afterLoad: { groupBy: ["provider", "level"] },
});

describe("applyCriteria", () => {
  beforeEach(() => {
    useEvtxStore.getState().reset();
  });

  it("sets every part of the model, and a capture of the result is the criteria applied", () => {
    applyCriteria(CRITERIA);
    const state = useEvtxStore.getState();
    expect([...state.filterLevels].sort()).toEqual(["Error", "Warning"]);
    expect(state.filterEventIds).toBe("75,76");
    expect(state.timeWindow).toBe("7d");
    expect([...state.selectedChannels]).toEqual(["System", "Microsoft-Windows-AAD/Operational"]);
    expect(state.filterSearch).toBe("id:76");
    expect(state.quickFilter).toEqual(fieldQuick("level:error"));
    expect(state.groupBy).toEqual(["provider", "level"]);
    expect(captureCriteria(state)).toEqual(CRITERIA);
  });

  it("applies no search that does not parse, and keeps none from before", () => {
    useEvtxStore.setState({ filterSearch: "id:1" });
    applyCriteria({ ...CRITERIA, onLoad: { search: "provider:", quickFilter: fieldQuick("level:erro") } });
    const state = useEvtxStore.getState();
    expect(state.filterSearch).toBe("");
    expect(state.filterSearchDraft).toBe("provider:");
    expect(state.quickFilter.query).toBe("");
    expect(state.quickFilterDraft?.query).toBe("level:erro");
    // The text is still the operator's, as typed.
    expect(captureCriteria(state).onLoad.search).toBe("provider:");
  });

  it("leaves the transient criteria alone: that is the caller's decision", () => {
    const timeRange = { startMs: 1, endMs: 2 };
    useEvtxStore.setState({ timeRange });
    applyCriteria(CRITERIA);
    expect(useEvtxStore.getState().timeRange).toEqual(timeRange);
  });
});

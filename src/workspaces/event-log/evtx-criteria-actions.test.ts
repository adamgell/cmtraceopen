import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { applyCriteria, applyView } from "./evtx-criteria-actions";
import { DEFAULT_QUICK_FILTER, type EvtxQuickFilter } from "./evtx-filter";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { captureCriteria, sanitizeCriteria, type EvtxFilterCriteria } from "./evtx-saved-filters";
import { useEvtxStore } from "./evtx-store";
import type { EvtxRecordScope } from "./evtx-filter";
import { EVTX_BUILT_IN_VIEWS, type EvtxViewBody } from "./evtx-views";

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

describe("applyView", () => {
  const SCOPE: EvtxRecordScope = {
    kind: "finding",
    title: "A finding",
    records: new Set(),
    counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
  };
  const TIME_RANGE = { startMs: 1_700_000_000_000, endMs: 1_700_000_060_000 };
  const view = (layout: EvtxViewBody["layout"]): EvtxViewBody => ({ name: "V", criteria: CRITERIA, layout });

  /**
   * The source first, the criteria second: a change of source clears the transient criteria in the
   * same update (6a), so one setState that did both would seed nothing.
   */
  function seedTransients(mode: "files" | "live") {
    useEvtxStore.setState({ sourceMode: mode });
    useEvtxStore.setState({ timeRange: TIME_RANGE, recordScope: SCOPE });
    expect(useEvtxStore.getState().timeRange).toEqual(TIME_RANGE);
    expect(useEvtxStore.getState().recordScope).toBe(SCOPE);
  }

  beforeEach(() => {
    useEvtxStore.getState().reset();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
  });

  it("applies the criteria", () => {
    applyView(view(null));
    expect(captureCriteria(useEvtxStore.getState())).toEqual(CRITERIA);
  });

  it.each(["files", "live"] as const)("clears both transient criteria on a %s source, whether or not it refetches", (mode) => {
    seedTransients(mode);
    applyView(view(null));
    const state = useEvtxStore.getState();
    expect(state.timeRange).toBeNull();
    expect(state.recordScope).toBeNull();
  });

  it("clears them even when the view changes nothing the source would be asked for", () => {
    applyView(view(null));
    seedTransients("files");
    applyView(view(null));
    expect(useEvtxStore.getState().timeRange).toBeNull();
    expect(useEvtxStore.getState().recordScope).toBeNull();
  });

  it("applies a layout when the view has one, and leaves the panels it cannot show off", () => {
    useEvtxLayoutStore.setState({ activeView: "table", panels: { channels: true, insights: true, dock: false } });
    applyView(view({ activeView: "grouped", panels: { channels: false, insights: false, dock: true } }));
    const layout = useEvtxLayoutStore.getState();
    expect(layout.activeView).toBe("grouped");
    expect(layout.panels).toEqual({ channels: false, insights: false, dock: false });
  });

  it("leaves the layout alone when the view has none", () => {
    useEvtxLayoutStore.setState({ activeView: "timeline", panels: { channels: false, insights: true, dock: false } });
    applyView(view(null));
    const layout = useEvtxLayoutStore.getState();
    expect(layout.activeView).toBe("timeline");
    expect(layout.panels).toEqual({ channels: false, insights: true, dock: false });
  });

  it("applies the built-in as the filter it is", () => {
    applyView(EVTX_BUILT_IN_VIEWS[0]);
    const state = useEvtxStore.getState();
    expect(state.timeWindow).toBe("all");
    expect([...state.selectedChannels]).toEqual(EVTX_BUILT_IN_VIEWS[0].criteria.beforeLoad.selectedChannels);
    expect(state.filterSearch).toBe(EVTX_BUILT_IN_VIEWS[0].criteria.onLoad.search);
    expect(state.quickFilter.query).toBe("");
  });
});

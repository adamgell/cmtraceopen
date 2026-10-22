import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_DOCK_HEIGHT,
  DEFAULT_RAIL_WIDTH,
  EVTX_LAYOUT_STORAGE_KEY,
  MAX_RAIL_WIDTH,
  MIN_DOCK_HEIGHT,
  MIN_RAIL_WIDTH,
  clampDockHeight,
  maxDockHeightFor,
  sanitizeLayout,
  useEvtxLayoutStore,
  type EvtxViewId,
} from "./evtx-layout-store";

function reset() {
  localStorage.clear();
  useEvtxLayoutStore.setState(sanitizeLayout(undefined));
}

async function rehydrateFrom(stored: unknown) {
  localStorage.setItem(
    EVTX_LAYOUT_STORAGE_KEY,
    JSON.stringify({ state: stored, version: 1 }),
  );
  await useEvtxLayoutStore.persist.rehydrate();
}

describe("evtx-layout-store", () => {
  beforeEach(reset);

  it("starts on the table with only the channel pane shown", () => {
    const state = useEvtxLayoutStore.getState();
    expect(state.activeView).toBe("table");
    expect(state.panels).toEqual({ channels: true, insights: false, dock: false });
    expect(state.railTab).toBe("insights");
    expect(state.railWidth).toBe(DEFAULT_RAIL_WIDTH);
    expect(state.dockHeight).toBe(DEFAULT_DOCK_HEIGHT);
  });

  it("sets the view, the rail tab and individual panels", () => {
    const store = useEvtxLayoutStore.getState();
    store.setActiveView("correlation");
    store.setRailTab("details");
    store.togglePanel("channels");
    const state = useEvtxLayoutStore.getState();
    expect(state.activeView).toBe("correlation");
    expect(state.railTab).toBe("details");
    expect(state.panels).toEqual({ channels: false, insights: false, dock: false });
  });

  it("refuses to show a panel that has no content yet", () => {
    const store = useEvtxLayoutStore.getState();
    store.setPanel("insights", true);
    store.setPanel("dock", true);
    store.togglePanel("dock");
    expect(useEvtxLayoutStore.getState().panels).toEqual({
      channels: true,
      insights: false,
      dock: false,
    });
  });

  it("ignores an unknown view or tab", () => {
    const store = useEvtxLayoutStore.getState();
    store.setActiveView("nope" as EvtxViewId);
    store.setRailTab("nope" as never);
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
  });

  it("clamps the rail width to 280 through 480", () => {
    const store = useEvtxLayoutStore.getState();
    store.setRailWidth(100);
    expect(useEvtxLayoutStore.getState().railWidth).toBe(MIN_RAIL_WIDTH);
    store.setRailWidth(9000);
    expect(useEvtxLayoutStore.getState().railWidth).toBe(MAX_RAIL_WIDTH);
    store.setRailWidth(400);
    expect(useEvtxLayoutStore.getState().railWidth).toBe(400);
    store.setRailWidth(Number.NaN);
    expect(useEvtxLayoutStore.getState().railWidth).toBe(DEFAULT_RAIL_WIDTH);
  });

  it("keeps the dock ceiling an integer, so the dock handle never sees a fractional value", () => {
    expect(Number.isInteger(maxDockHeightFor(901))).toBe(true);
    expect(Number.isInteger(maxDockHeightFor(1003.7))).toBe(true);
    expect(Number.isInteger(clampDockHeight(333.4, 901))).toBe(true);
  });

  it("clamps the dock height to 160 px through half the viewport, in pixels at use time", () => {
    expect(maxDockHeightFor(900)).toBe(450);
    expect(maxDockHeightFor(200)).toBe(MIN_DOCK_HEIGHT);
    const store = useEvtxLayoutStore.getState();
    store.setDockHeight(50, 900);
    expect(useEvtxLayoutStore.getState().dockHeight).toBe(MIN_DOCK_HEIGHT);
    store.setDockHeight(800, 900);
    expect(useEvtxLayoutStore.getState().dockHeight).toBe(450);
    store.setDockHeight(300, 900);
    expect(useEvtxLayoutStore.getState().dockHeight).toBe(300);
    expect(clampDockHeight("x")).toBe(DEFAULT_DOCK_HEIGHT);
  });

  it("persists exactly the five layout keys and nothing else", () => {
    useEvtxLayoutStore.getState().setPanel("channels", false);
    const stored = JSON.parse(localStorage.getItem(EVTX_LAYOUT_STORAGE_KEY) ?? "{}");
    expect(stored.version).toBe(1);
    expect(Object.keys(stored.state).sort()).toEqual(
      ["activeView", "dockHeight", "panels", "railTab", "railWidth"],
    );
    expect(stored.state.panels.channels).toBe(false);
  });

  it("restores a valid persisted layout", async () => {
    await rehydrateFrom({
      activeView: "charts",
      panels: { channels: false, insights: true, dock: true },
      railTab: "chains",
      railWidth: 400,
      dockHeight: 250,
    });
    const state = useEvtxLayoutStore.getState();
    expect(state.activeView).toBe("charts");
    // Insights and the dock have no content yet, so a persisted true is forced back to false.
    expect(state.panels).toEqual({ channels: false, insights: false, dock: false });
    expect(state.railTab).toBe("chains");
    expect(state.railWidth).toBe(400);
    expect(state.dockHeight).toBe(250);
  });

  it("sanitizes bad persisted values and drops unknown keys", async () => {
    await rehydrateFrom({
      activeView: "heatmap",
      panels: { channels: "yes", insights: false, dock: 1, extra: true },
      railTab: 7,
      railWidth: 99999,
      dockHeight: -4,
      records: [{ message: "secret" }],
    });
    const state = useEvtxLayoutStore.getState() as unknown as Record<string, unknown>;
    expect(state.activeView).toBe("table");
    expect(state.panels).toEqual({ channels: true, insights: false, dock: false });
    expect(state.railTab).toBe("insights");
    expect(state.railWidth).toBe(MAX_RAIL_WIDTH);
    expect(state.dockHeight).toBe(MIN_DOCK_HEIGHT);
    expect(state).not.toHaveProperty("records");
  });

  it("survives a non-object persisted state", async () => {
    await rehydrateFrom("garbage");
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    expect(useEvtxLayoutStore.getState().railWidth).toBe(DEFAULT_RAIL_WIDTH);
  });

  // Guard for the ship-a-panel rule (see EVTX_PANELS_AVAILABLE): flip the availability and the
  // default together and bump the persist version, with no migrate. A version-1 envelope holding
  // `false` must then resolve to the current default. If a phase flips a default without bumping
  // the version, the stored `false` survives and this fails; with the bump, the old envelope is
  // dropped and this passes.
  it("resolves a stored version-1 false to the current default for every panel", async () => {
    await rehydrateFrom({
      panels: { channels: true, insights: false, dock: false },
    });
    const defaults = sanitizeLayout(undefined).panels;
    const panels = useEvtxLayoutStore.getState().panels;
    expect(panels.insights).toBe(defaults.insights);
    expect(panels.dock).toBe(defaults.dock);
    expect(panels).toEqual(defaults);
  });
});

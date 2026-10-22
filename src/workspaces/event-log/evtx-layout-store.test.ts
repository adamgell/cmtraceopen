import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_DOCK_HEIGHT,
  DEFAULT_RAIL_WIDTH,
  EVTX_DOCK_WINDOW_OPTIONS_MS,
  EVTX_PANELS_AVAILABLE,
  EVTX_RAIL_TAB_IDS,
  EVTX_VIEW_IDS,
  EVTX_LAYOUT_STORAGE_KEY,
  EVTX_LAYOUT_VERSION,
  MAX_RAIL_WIDTH,
  MIN_DOCK_HEIGHT,
  MIN_RAIL_WIDTH,
  chainsTabShown,
  clampDockHeight,
  correlationItemsNeeded,
  evtxPanelToggleId,
  maxDockHeightFor,
  sanitizeLayout,
  useEvtxLayoutStore,
  type EvtxViewId,
} from "./evtx-layout-store";

function reset() {
  localStorage.clear();
  useEvtxLayoutStore.setState({ ...sanitizeLayout(undefined), dockCollapsed: false });
}

async function rehydrateFrom(stored: unknown, version = EVTX_LAYOUT_VERSION) {
  localStorage.setItem(
    EVTX_LAYOUT_STORAGE_KEY,
    JSON.stringify({ state: stored, version }),
  );
  await useEvtxLayoutStore.persist.rehydrate();
}

describe("evtx-layout-store", () => {
  beforeEach(reset);

  it("starts on the table with the channel pane and the Insights rail shown", () => {
    const state = useEvtxLayoutStore.getState();
    expect(state.activeView).toBe("table");
    expect(state.panels).toEqual({ channels: true, insights: true, dock: false });
    expect(state.railTab).toBe("insights");
    expect(state.railWidth).toBe(DEFAULT_RAIL_WIDTH);
    expect(state.dockHeight).toBe(DEFAULT_DOCK_HEIGHT);
    expect(state.dockWindowMs).toBe(75_000);
    expect(state.dockCollapsed).toBe(false);
    // The store as created, not as `reset` leaves it.
    expect(useEvtxLayoutStore.getInitialState().dockCollapsed).toBe(false);
    expect(useEvtxLayoutStore.getInitialState().dockWindowMs).toBe(75_000);
  });

  it("sets the view, the rail tab and individual panels", () => {
    const store = useEvtxLayoutStore.getState();
    store.setActiveView("correlation");
    store.setRailTab("details");
    store.togglePanel("channels");
    const state = useEvtxLayoutStore.getState();
    expect(state.activeView).toBe("correlation");
    expect(state.railTab).toBe("details");
    expect(state.panels).toEqual({ channels: false, insights: true, dock: false });
  });

  it("shows and hides the dock like any panel, and it starts off", () => {
    const store = useEvtxLayoutStore.getState();
    expect(EVTX_PANELS_AVAILABLE.dock).toBe(true);
    store.setPanel("dock", true);
    expect(useEvtxLayoutStore.getState().panels.dock).toBe(true);
    store.togglePanel("dock");
    expect(useEvtxLayoutStore.getState().panels.dock).toBe(false);
    store.togglePanel("dock");
    expect(useEvtxLayoutStore.getState().panels).toEqual({ channels: true, insights: true, dock: true });
    store.setPanel("dock", false);
    expect(useEvtxLayoutStore.getState().panels.dock).toBe(false);
  });

  it("shows a dock that was collapsed expanded again, by either way of showing it", () => {
    const store = useEvtxLayoutStore.getState();
    store.setPanel("dock", true);
    store.setDockCollapsed(true);
    store.setPanel("dock", false);
    expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(true);
    store.setPanel("dock", true);
    expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(false);
    store.setDockCollapsed(true);
    store.togglePanel("dock");
    store.togglePanel("dock");
    expect(useEvtxLayoutStore.getState().panels.dock).toBe(true);
    expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(false);
    // Another panel's toggle leaves the dock's collapse alone.
    store.setDockCollapsed(true);
    store.togglePanel("insights");
    store.togglePanel("insights");
    store.setPanel("channels", false);
    store.setPanel("channels", true);
    store.setPanel("insights", true);
    expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(true);
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

  it("persists exactly the six layout keys and nothing else, and not whether the dock is collapsed", () => {
    useEvtxLayoutStore.getState().setPanel("channels", false);
    useEvtxLayoutStore.getState().setDockCollapsed(true);
    const stored = JSON.parse(localStorage.getItem(EVTX_LAYOUT_STORAGE_KEY) ?? "{}");
    // The correlation dock shipped without a version bump: it is off by default (R4).
    expect(EVTX_LAYOUT_VERSION).toBe(2);
    expect(stored.version).toBe(2);
    expect(Object.keys(stored.state).sort()).toEqual(
      ["activeView", "dockHeight", "dockWindowMs", "panels", "railTab", "railWidth"],
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
      dockWindowMs: 120_000,
    });
    const state = useEvtxLayoutStore.getState();
    expect(state.activeView).toBe("charts");
    // The dock is available, so a persisted true is the user's own choice.
    expect(state.panels).toEqual({ channels: false, insights: true, dock: true });
    expect(state.railTab).toBe("chains");
    expect(state.railWidth).toBe(400);
    expect(state.dockHeight).toBe(250);
    expect(state.dockWindowMs).toBe(120_000);
  });

  it("sanitizes bad persisted values and drops unknown keys", async () => {
    await rehydrateFrom({
      activeView: "heatmap",
      panels: { channels: "yes", insights: "no", dock: 1, extra: true },
      railTab: 7,
      railWidth: 99999,
      dockHeight: -4,
      dockWindowMs: 45_000,
      dockCollapsed: true,
      records: [{ message: "secret" }],
    });
    const state = useEvtxLayoutStore.getState() as unknown as Record<string, unknown>;
    expect(state.activeView).toBe("table");
    expect(state.panels).toEqual({ channels: true, insights: true, dock: false });
    expect(state.railTab).toBe("insights");
    expect(state.railWidth).toBe(MAX_RAIL_WIDTH);
    expect(state.dockHeight).toBe(MIN_DOCK_HEIGHT);
    expect(state.dockWindowMs).toBe(75_000);
    // A collapsed dock is not something an envelope can set.
    expect(state.dockCollapsed).toBe(false);
    expect(state).not.toHaveProperty("records");
  });

  it("survives a non-object persisted state", async () => {
    await rehydrateFrom("garbage");
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    expect(useEvtxLayoutStore.getState().railWidth).toBe(DEFAULT_RAIL_WIDTH);
  });

  describe("the correlation dock's window and collapse", () => {
    it("offers 30 s, 75 s, 2 min and 5 min, with 75 s the default", () => {
      expect([...EVTX_DOCK_WINDOW_OPTIONS_MS]).toEqual([30_000, 75_000, 120_000, 300_000]);
    });

    it("takes each of the four widths and ignores any other", () => {
      const store = useEvtxLayoutStore.getState();
      for (const windowMs of EVTX_DOCK_WINDOW_OPTIONS_MS) {
        store.setDockWindowMs(windowMs);
        expect(useEvtxLayoutStore.getState().dockWindowMs).toBe(windowMs);
      }
      store.setDockWindowMs(30_000);
      for (const bad of [0, 45_000, -75_000, Number.NaN, Number.POSITIVE_INFINITY, 75_000.5, "75000", null, undefined]) {
        store.setDockWindowMs(bad as never);
        expect(useEvtxLayoutStore.getState().dockWindowMs, String(bad)).toBe(30_000);
      }
    });

    it("persists the width, and restores it after a reload", async () => {
      useEvtxLayoutStore.getState().setDockWindowMs(300_000);
      const raw = localStorage.getItem(EVTX_LAYOUT_STORAGE_KEY) ?? "{}";
      expect(JSON.parse(raw).state.dockWindowMs).toBe(300_000);
      // A reload: another value in memory, the stored envelope back in storage.
      useEvtxLayoutStore.setState({ dockWindowMs: 30_000 });
      localStorage.setItem(EVTX_LAYOUT_STORAGE_KEY, raw);
      await useEvtxLayoutStore.persist.rehydrate();
      expect(useEvtxLayoutStore.getState().dockWindowMs).toBe(300_000);
    });

    it("sanitizes a stored width that is not one of the four, whatever its type", () => {
      for (const bad of [0, 45_000, "120000", null, {}, [], Number.NaN, -1]) {
        expect(sanitizeLayout({ dockWindowMs: bad }).dockWindowMs, JSON.stringify(bad)).toBe(75_000);
      }
      for (const windowMs of EVTX_DOCK_WINDOW_OPTIONS_MS) {
        expect(sanitizeLayout({ dockWindowMs: windowMs }).dockWindowMs).toBe(windowMs);
      }
    });

    it("keeps a version 2 envelope written before the width existed: its layout stays, the width is 75 s", async () => {
      await rehydrateFrom(
        {
          activeView: "grouped",
          panels: { channels: false, insights: false, dock: false },
          railTab: "details",
          railWidth: 400,
          dockHeight: 250,
        },
        2,
      );
      const state = useEvtxLayoutStore.getState();
      expect(state.activeView).toBe("grouped");
      expect(state.panels).toEqual({ channels: false, insights: false, dock: false });
      expect(state.railWidth).toBe(400);
      expect(state.dockWindowMs).toBe(75_000);
    });

    it("collapses and expands the dock, and starts expanded", () => {
      const store = useEvtxLayoutStore.getState();
      expect(store.dockCollapsed).toBe(false);
      store.setDockCollapsed(true);
      expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(true);
      store.setDockCollapsed(false);
      expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(false);
      store.setDockCollapsed("yes" as never);
      expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(false);
    });

    it("does not restore a collapsed dock from storage: a reload shows the dock expanded", async () => {
      useEvtxLayoutStore.getState().setDockCollapsed(true);
      localStorage.setItem(
        EVTX_LAYOUT_STORAGE_KEY,
        JSON.stringify({ state: { dockCollapsed: true }, version: EVTX_LAYOUT_VERSION }),
      );
      useEvtxLayoutStore.setState({ dockCollapsed: false });
      await useEvtxLayoutStore.persist.rehydrate();
      expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(false);
    });

    it("gives each panel toggle its own id, so Close can return focus to the dock's", () => {
      expect(evtxPanelToggleId("dock")).toBe("evtx-panel-toggle-dock");
      expect(new Set((["channels", "insights", "dock"] as const).map(evtxPanelToggleId)).size).toBe(3);
    });
  });

  describe("persist version 2", () => {
    const stored = (insights: boolean, dock = false) => ({
      activeView: "grouped",
      panels: { channels: false, insights, dock },
      railTab: "details",
      railWidth: 400,
      dockHeight: 250,
    });

    it("discards a version 1 envelope: the layout resets to the defaults, Insights on", async () => {
      await rehydrateFrom(stored(false), 1);
      const state = useEvtxLayoutStore.getState();
      expect(state.panels).toEqual({ channels: true, insights: true, dock: false });
      expect(state.activeView).toBe("table");
      expect(state.railWidth).toBe(DEFAULT_RAIL_WIDTH);
    });

    it("keeps a version 2 Insights false, which is the user's own choice", async () => {
      await rehydrateFrom(stored(false), 2);
      expect(useEvtxLayoutStore.getState().panels.insights).toBe(false);
      expect(useEvtxLayoutStore.getState().activeView).toBe("grouped");
    });

    it("keeps a version 2 dock choice, and still resets a version 1 envelope to the dock off", async () => {
      await rehydrateFrom(stored(true, true), 2);
      expect(useEvtxLayoutStore.getState().panels.dock).toBe(true);
      await rehydrateFrom(stored(true, true), 1);
      expect(useEvtxLayoutStore.getState().panels.dock).toBe(false);
    });
  });

  // Guard for the ship-a-panel rule (see EVTX_PANELS_AVAILABLE): flip the availability and the
  // default together and bump the persist version, with no migrate. A version-1 envelope holding
  // `false` must then resolve to the current default. If a phase flips a default without bumping
  // the version, the stored `false` survives and this fails; with the bump, the old envelope is
  // dropped and this passes.
  it("resolves a stored version-1 false to the current default for every panel", async () => {
    await rehydrateFrom(
      { panels: { channels: true, insights: false, dock: false } },
      1,
    );
    const defaults = sanitizeLayout(undefined).panels;
    const panels = useEvtxLayoutStore.getState().panels;
    expect(panels.insights).toBe(defaults.insights);
    expect(panels.dock).toBe(defaults.dock);
    expect(panels).toEqual(defaults);
  });
});

describe("when the Chains tab is shown, and when the correlation entries must be read (#841)", () => {
  const rail = (insights: boolean, railTab: (typeof EVTX_RAIL_TAB_IDS)[number]) => ({
    panels: { channels: true, insights, dock: false },
    railTab,
  });

  it("shows the Chains tab only when the rail is visible and on that tab", () => {
    expect(chainsTabShown(rail(true, "chains"))).toBe(true);
    expect(chainsTabShown(rail(false, "chains"))).toBe(false);
    expect(chainsTabShown(rail(true, "insights"))).toBe(false);
    expect(chainsTabShown(rail(true, "details"))).toBe(false);
  });

  it.each(EVTX_VIEW_IDS)("needs the entries on the %s view only when it is Correlation, with the Chains tab not shown", (view) => {
    expect(correlationItemsNeeded({ activeView: view, ...rail(true, "insights") })).toBe(view === "correlation");
  });

  it.each(EVTX_VIEW_IDS)("needs the entries on the %s view when the Chains tab is shown", (view) => {
    expect(correlationItemsNeeded({ activeView: view, ...rail(true, "chains") })).toBe(true);
  });

  it.each(EVTX_VIEW_IDS)("does not need them on the %s view when the rail is hidden, unless that is Correlation", (view) => {
    expect(correlationItemsNeeded({ activeView: view, ...rail(false, "chains") })).toBe(view === "correlation");
  });

  it("reads the live store through a selector", () => {
    useEvtxLayoutStore.setState({ activeView: "table", railTab: "chains", panels: { channels: true, insights: true, dock: false } });
    expect(correlationItemsNeeded(useEvtxLayoutStore.getState())).toBe(true);
    useEvtxLayoutStore.getState().setPanel("insights", false);
    expect(correlationItemsNeeded(useEvtxLayoutStore.getState())).toBe(false);
  });
});

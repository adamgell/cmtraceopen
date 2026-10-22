import { beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_DOCK_HEIGHT,
  DEFAULT_RAIL_WIDTH,
  EVTX_LAYOUT_STORAGE_KEY,
  EVTX_LAYOUT_VERSION,
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

  it("refuses to show a panel that has no content yet", () => {
    const store = useEvtxLayoutStore.getState();
    store.setPanel("dock", true);
    store.togglePanel("dock");
    store.togglePanel("insights");
    store.togglePanel("insights");
    expect(useEvtxLayoutStore.getState().panels).toEqual({
      channels: true,
      insights: true,
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
    expect(stored.version).toBe(2);
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
    // The dock has no content yet, so a persisted true is forced back to false.
    expect(state.panels).toEqual({ channels: false, insights: true, dock: false });
    expect(state.railTab).toBe("chains");
    expect(state.railWidth).toBe(400);
    expect(state.dockHeight).toBe(250);
  });

  it("sanitizes bad persisted values and drops unknown keys", async () => {
    await rehydrateFrom({
      activeView: "heatmap",
      panels: { channels: "yes", insights: "no", dock: 1, extra: true },
      railTab: 7,
      railWidth: 99999,
      dockHeight: -4,
      records: [{ message: "secret" }],
    });
    const state = useEvtxLayoutStore.getState() as unknown as Record<string, unknown>;
    expect(state.activeView).toBe("table");
    expect(state.panels).toEqual({ channels: true, insights: true, dock: false });
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

    it("keeps the dock unavailable, whatever the envelope says", async () => {
      await rehydrateFrom(stored(true, true), 2);
      expect(useEvtxLayoutStore.getState().panels.dock).toBe(false);
      await rehydrateFrom(stored(true, true), 1);
      expect(useEvtxLayoutStore.getState().panels.dock).toBe(false);
    });
  });

  // Guard for the ship-a-panel rule (see EVTX_PANELS_AVAILABLE): the phase that ships a panel flips
  // its availability and its default together AND bumps EVTX_LAYOUT_VERSION, with no migrate. The
  // bump is what makes a stored layout forget the old `false`. This writes an envelope at the
  // CURRENT version that holds `false` for the one panel not shipped yet (dock). The store accepts
  // that envelope, so it reaches `merge` and must come back as the current default. If a phase
  // flips the dock's two flags without the bump, `false` is still a valid stored choice and
  // survives, which fails here.
  //
  // `activeView` and `channels` are the positive control. Neither equals its default, so they
  // prove the envelope was applied and not dropped. `dock: false` alone proves nothing: it equals
  // today's default, which is how an envelope at version 1 (dropped by a version 2 store) once let
  // this test compare the defaults with themselves.
  //
  // When the dock ships, aim this case at the next unshipped panel, or remove it, in the same
  // change that edits the pin below.
  it("resolves a current-version stored false to the current default for a panel not yet shipped", async () => {
    await rehydrateFrom({
      activeView: "grouped",
      panels: { channels: false, insights: true, dock: false },
    });
    const state = useEvtxLayoutStore.getState();
    expect(state.activeView).toBe("grouped");
    expect(state.panels.channels).toBe(false);
    expect(state.panels.dock).toBe(sanitizeLayout(undefined).panels.dock);
  });

  // Written out in full on purpose, not read from the store: flipping a default or the version has
  // to be an edit to this line, beside the other half of the pair.
  it("pins the persist version together with the default panels", () => {
    expect([EVTX_LAYOUT_VERSION, sanitizeLayout(undefined).panels]).toEqual([
      2,
      { channels: true, insights: true, dock: false },
    ]);
  });
});

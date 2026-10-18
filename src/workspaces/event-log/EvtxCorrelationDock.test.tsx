/**
 * The correlation dock (spec 8.12, #842) as an operator meets it: its header, what it says in each
 * state, when it reads, what its controls do, and what a click on a marker does. What it may CLAIM
 * is evtx-correlation-dock-model.test.ts's; the colors are EvtxCorrelationDock.contrast.test.tsx's.
 * The window reader's timing is useEvtxCorrelationWindow.test.tsx's; here the dock is shown to
 * use it (no read while collapsed, one read for a burst of selections).
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from "vitest";
import type { EventLogAnalysisTimelineWindow } from "../../lib/commands";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const modelBuilds = vi.hoisted(() => vi.fn());
vi.mock("./evtx-correlation-dock-model", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-correlation-dock-model")>();
  return {
    ...actual,
    buildDockModel: (...args: Parameters<typeof actual.buildDockModel>) => {
      modelBuilds();
      return actual.buildDockModel(...args);
    },
  };
});

import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../stores/ui-store";
import EvtxCorrelationDock from "./EvtxCorrelationDock";
import { EvtxAnalysisSessionProvider } from "./evtx-analysis-session";
import dockSource from "./EvtxCorrelationDock.tsx?raw";
import dockWindowSource from "./useEvtxCorrelationWindow.ts?raw";
import {
  NO_SELECTION_TEXT,
  NO_SESSION_TEXT,
  READING_WINDOW_TEXT,
  UNTIMED_TEXT,
  openDisabledText,
  windowFailureText,
} from "./evtx-correlation-copy";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import {
  EVTX_PANELS_AVAILABLE,
  evtxPanelToggleId,
  evtxViewTabId,
  sanitizeLayout,
  useEvtxLayoutStore,
} from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import {
  T0,
  eventItem,
  fixtureEdges,
  makeData,
  recordFor,
  rid,
  synthetic,
  type DataOptions,
} from "./evtx-correlation-test-fixtures";
import type { CorrelationWindowDeps } from "./evtx-correlation-window";
import { EvtxCorrelationProvider, type EvtxCorrelationData } from "./useEvtxCorrelation";
import type { EvtxRecord } from "./types";
import type { TimelineItem } from "./unified-timeline";

type QueryWindow = CorrelationWindowDeps["queryWindow"];

/** A coverage gap that loses records: a channel that needs elevation. */
const UNREAD_GAP = { source: "Security", kind: "accessDenied", reason: "needs elevation" } as const;
const setUnreadSources = (unread: boolean) =>
  useEvtxStore.setState({ coverageDetails: unread ? [UNREAD_GAP] : [] });

const STATUS = { sessionId: "session", revision: 1 };
const RECORD = recordFor(1);
const T = RECORD.timestampEpoch;

/** The selected event (1), its chain partner (2), a stray (9) and another chain's member (10). */
const scene = (): TimelineItem[] => [
  eventItem(1, T, "error", "the selected event failed"),
  eventItem(2, T + 6_000),
  eventItem(9, T + 3_000, "warning", "context"),
  eventItem(10, T + 4_000),
];
const sceneEdges = () => [...fixtureEdges("exactPair"), synthetic("o", rid(10), rid(11))];

function windowReply(items: readonly TimelineItem[], startMs: number, endMs: number): EventLogAnalysisTimelineWindow {
  // The engine answers in time order, and the loader refuses a reply that is not.
  const inside = items
    .filter((item) => item.timestampMs >= startMs && item.timestampMs <= endMs)
    .sort((a, b) => a.timestampMs - b.timestampMs);
  return {
    sessionId: STATUS.sessionId,
    revision: STATUS.revision,
    startMs,
    endMs,
    offset: 0,
    nextOffset: null,
    totalItems: items.length,
    windowItems: inside.length,
    omittedItems: 0,
    items: inside,
    serializedBytes: 1_000,
  };
}

interface Harness {
  data: EvtxCorrelationData;
  queryWindow: Mock<QueryWindow>;
  rerender: (next?: Partial<{ data: EvtxCorrelationData; status: typeof STATUS | null; unreadSources: boolean }>) => void;
}

function renderDock(
  options: {
    items?: TimelineItem[];
    data?: Partial<DataOptions>;
    status?: typeof STATUS | null;
    unreadSources?: boolean;
    settle?: number;
    sessionSettle?: number;
    queryWindow?: Mock<QueryWindow>;
  } = {},
): Harness {
  const items = options.items ?? scene();
  const queryWindow =
    options.queryWindow ??
    vi.fn<QueryWindow>(async (_session, startMs, endMs) => windowReply(items, startMs, endMs));
  let data = makeData({ items, edges: sceneEdges(), ...options.data });
  let status = options.status === undefined ? STATUS : options.status;
  let unreadSources = options.unreadSources ?? false;
  const tree = () => (
    <EvtxAnalysisSessionProvider value={status}>
      <EvtxCorrelationProvider value={data}>
        <EvtxCorrelationDock
          windowDeps={{ queryWindow, sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }}
          selectionSettleMs={options.settle ?? 0}
          sessionSettleMs={options.sessionSettle ?? options.settle ?? 0}
        />
      </EvtxCorrelationProvider>
    </EvtxAnalysisSessionProvider>
  );
  setUnreadSources(unreadSources);
  const view = render(tree());
  return {
    get data() {
      return data;
    },
    queryWindow,
    rerender: (next = {}) => {
      if (next.data !== undefined) data = next.data;
      if (next.status !== undefined) status = next.status;
      if (next.unreadSources !== undefined) {
        unreadSources = next.unreadSources;
        act(() => setUnreadSources(unreadSources));
      }
      view.rerender(tree());
    },
  };
}

function seedRecords(records: EvtxRecord[], selectedRecordId: number | null) {
  useEvtxStore.getState().reset();
  useEvtxStore.setState({ records, selectedRecordId, isLoading: false, timeZoneMode: "utc" });
}

const allRecords = () => [1, 2, 9, 10].map(recordFor);
const dock = () => screen.getByRole("region", { name: "Correlation dock" });
const markers = () => Array.from(document.querySelectorAll<HTMLButtonElement>("button[data-marker]"));
const markerFor = (n: number) => document.querySelector<HTMLButtonElement>(`[data-marker="${rid(n)}"]`)!;
const ready = () => screen.findByRole("figure");
/** Real time to pass, for a test that says something did NOT happen: the reads here settle in 0 ms. */
const idle = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 40));
  });

let originalDockAvailability: boolean;
beforeEach(() => {
  modelBuilds.mockClear();
  localStorage.clear();
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false, openedCount: 0 });
  useEvtxLayoutStore.setState({
    ...sanitizeLayout(undefined),
    dockCollapsed: false,
    activeView: "table",
    panels: { channels: true, insights: true, dock: true },
  });
  // The dock is unavailable until the enable commit; Close needs the panel to be settable.
  originalDockAvailability = EVTX_PANELS_AVAILABLE.dock;
  EVTX_PANELS_AVAILABLE.dock = true;
  seedRecords(allRecords(), 1);
});
afterEach(() => {
  EVTX_PANELS_AVAILABLE.dock = originalDockAvailability;
  cleanup();
  vi.useRealTimers();
});

describe("the header (spec 8.12)", () => {
  it("is a labelled region with the title, the window, Open, collapse and close", async () => {
    renderDock();
    await ready();
    expect(dock()).toBeInTheDocument();
    expect(within(dock()).getByText("Correlation")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Correlation window" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Open in Correlation view" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Collapse correlation" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Close correlation dock" })).toBeInTheDocument();
  });

  it("says what the dock is around: the event, its time, the window and the source count", async () => {
    renderDock();
    await ready();
    expect(screen.getByTestId("correlation-dock-subtitle")).toHaveTextContent(
      "around Event 101 · 10:20:01 · window ±75 s · 1 source",
    );
  });

  it("offers the four widths and writes the choice to the layout store, which reads again after the settle", async () => {
    const { queryWindow } = renderDock();
    await ready();
    expect(queryWindow).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("combobox", { name: "Correlation window" }));
    const options = screen.getAllByRole("option").map((option) => option.textContent);
    expect(options).toEqual(["±30 s", "±75 s", "±2 min", "±5 min"]);
    fireEvent.click(screen.getByRole("option", { name: "±2 min" }));
    expect(useEvtxLayoutStore.getState().dockWindowMs).toBe(120_000);
    await waitFor(() => expect(queryWindow).toHaveBeenCalledTimes(2));
    expect(queryWindow.mock.calls[1]).toEqual([STATUS.sessionId, T - 120_000, T + 120_000, 1000]);
    await waitFor(() =>
      expect(screen.getByTestId("correlation-dock-subtitle")).toHaveTextContent("window ±2 min"),
    );
  });
});

describe("what it says before there is a window to draw", () => {
  it("asks for a selection when there is none", async () => {
    seedRecords(allRecords(), null);
    const { queryWindow } = renderDock();
    expect(screen.getByTestId("correlation-dock-message")).toHaveTextContent(NO_SELECTION_TEXT);
    await idle();
    expect(queryWindow).not.toHaveBeenCalled();
    expect(screen.queryByTestId("correlation-dock-subtitle")).toBeNull();
  });

  it("says an event with no timestamp cannot be placed, and reads nothing", async () => {
    seedRecords([{ ...recordFor(1), timestampEpoch: 0 }], 1);
    const { queryWindow } = renderDock();
    expect(screen.getByTestId("correlation-dock-message")).toHaveTextContent(UNTIMED_TEXT);
    await idle();
    expect(queryWindow).not.toHaveBeenCalled();
  });

  it("says there is no analysis when there is no session", async () => {
    const { queryWindow } = renderDock({ status: null });
    expect(screen.getByTestId("correlation-dock-message")).toHaveTextContent(NO_SESSION_TEXT);
    await idle();
    expect(queryWindow).not.toHaveBeenCalled();
  });

  it("says it is reading until the window is in", async () => {
    vi.useFakeTimers();
    renderDock({ settle: 150 });
    expect(screen.getByTestId("correlation-dock-message")).toHaveTextContent(READING_WINDOW_TEXT);
    expect(dock()).toHaveAttribute("aria-busy", "true");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(150);
    });
    expect(screen.queryByTestId("correlation-dock-message")).toBeNull();
    expect(screen.getByRole("figure")).toBeInTheDocument();
    expect(dock()).not.toHaveAttribute("aria-busy");
  });

  it("shows a failed first read as an alert with the reason, and Retry reads again", async () => {
    const queryWindow = vi.fn<QueryWindow>(async () => {
      throw new Error("event-log analysis session was not found");
    });
    renderDock({ queryWindow });
    const alert = await screen.findByRole("alert", undefined, { timeout: 5_000 });
    expect(alert).toHaveTextContent(windowFailureText("event-log analysis session was not found"));
    const calls = queryWindow.mock.calls.length;
    queryWindow.mockImplementation(async (_s, startMs, endMs) => windowReply(scene(), startMs, endMs));
    fireEvent.click(within(alert).getByRole("button", { name: "Retry" }));
    await ready();
    expect(queryWindow.mock.calls.length).toBeGreaterThan(calls);
    expect(screen.queryByRole("alert")).toBeNull();
  }, 10_000);
});

describe("where it gets the session and the unread sources", () => {
  it("reads the session from the workspace's provider: a new revision is a new read, after the settle", async () => {
    vi.useFakeTimers();
    const { queryWindow, rerender } = renderDock({ settle: 150, sessionSettle: 500 });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(150);
    });
    expect(queryWindow).toHaveBeenCalledTimes(1);
    expect(queryWindow.mock.calls[0]![0]).toBe(STATUS.sessionId);
    rerender({ status: { sessionId: "session", revision: 2 } });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(150);
    });
    expect(queryWindow).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(350);
    });
    expect(queryWindow).toHaveBeenCalledTimes(2);
  });

  it("says there is no analysis when the provider holds none, and reads again when one is published", async () => {
    const { queryWindow, rerender } = renderDock({ status: null });
    expect(screen.getByTestId("correlation-dock-message")).toHaveTextContent(NO_SESSION_TEXT);
    rerender({ status: STATUS });
    await ready();
    expect(queryWindow).toHaveBeenCalledTimes(1);
  });

  it("reads the unread sources from the store's coverage, and follows it", async () => {
    const { rerender } = renderDock();
    await ready();
    const notices = () => screen.queryByTestId("correlation-dock-notices")?.textContent ?? "";
    expect(notices()).not.toMatch(/not fully read/);
    rerender({ unreadSources: true });
    expect(notices()).toContain("Some sources were not fully read");
    rerender({ unreadSources: false });
    expect(notices()).not.toMatch(/not fully read/);
  });

  it("does not call a source with no events, or an unresolved provider message, unread", async () => {
    renderDock();
    await ready();
    act(() =>
      useEvtxStore.setState({
        coverageDetails: [
          { source: "Setup", kind: "empty", reason: "no events" },
          { source: "System", kind: "provider", reason: "message text unavailable" },
        ],
      }),
    );
    expect(screen.queryByTestId("correlation-dock-notices")?.textContent ?? "").not.toMatch(/not fully read/);
  });
});

describe("when it reads (R5)", () => {
  it("reads nothing while collapsed, shows only its header, and reads when it is expanded", async () => {
    useEvtxLayoutStore.setState({ dockCollapsed: true });
    const { queryWindow } = renderDock();
    await idle();
    expect(queryWindow).not.toHaveBeenCalled();
    expect(screen.queryByRole("figure")).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Correlation window" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Open in Correlation view" })).toBeNull();
    // The header names the event and the window, and says nothing about sources it did not read.
    expect(screen.getByTestId("correlation-dock-subtitle").textContent).toBe(
      "around Event 101 · 10:20:01 · window ±75 s",
    );
    const expand = screen.getByRole("button", { name: "Expand correlation" });
    expect(expand).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(expand);
    await ready();
    expect(queryWindow).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Collapse correlation" })).toHaveAttribute("aria-expanded", "true");
  });

  it("recenters on the selection it finds when it is reopened, with one read", async () => {
    const { queryWindow } = renderDock();
    await ready();
    expect(queryWindow).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Collapse correlation" }));
    act(() => useEvtxStore.getState().setSelectedRecordId(2));
    act(() => useEvtxStore.getState().setSelectedRecordId(9));
    await idle();
    expect(queryWindow).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: "Expand correlation" }));
    await waitFor(() => expect(queryWindow).toHaveBeenCalledTimes(2));
    expect(queryWindow.mock.calls[1]![1]).toBe(recordFor(9).timestampEpoch - 75_000);
  });

  it("reads once for a burst of selection changes, for the last one", async () => {
    vi.useFakeTimers();
    const { queryWindow } = renderDock({ settle: 150 });
    for (const id of [2, 9, 10, 2, 9]) {
      act(() => useEvtxStore.getState().setSelectedRecordId(id));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(40);
      });
    }
    expect(queryWindow).not.toHaveBeenCalled();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(150);
    });
    expect(queryWindow).toHaveBeenCalledTimes(1);
    expect(queryWindow.mock.calls[0]![1]).toBe(recordFor(9).timestampEpoch - 75_000);
  });

  it("reads nothing when only the record ids move but the selected event is the same instant", async () => {
    const { queryWindow } = renderDock();
    await ready();
    // A merge renumbers ids: the same event, a new object, the same timestamp.
    act(() => {
      useEvtxStore.setState({ records: allRecords().map((record) => ({ ...record })) });
    });
    await idle();
    expect(queryWindow).toHaveBeenCalledTimes(1);
  });
});

describe("the lanes and the summary", () => {
  it("draws the selected event's lane and the context, with the dock's markers", async () => {
    renderDock();
    const figure = await ready();
    expect(figure).toHaveAttribute("data-variant", "dock");
    expect(markers()).toHaveLength(4);
    expect(document.querySelector("[data-center-rule]")).not.toBeNull();
    expect(document.querySelectorAll("[data-marker-label]")).toHaveLength(0);
  });

  it("shows the chain: its badge, its title, its key and its steps", async () => {
    renderDock();
    await ready();
    const summary = screen.getByTestId("correlation-dock-summary");
    expect(summary.querySelector('[data-strength-badge="exact"]')).not.toBeNull();
    expect(summary).toHaveTextContent("101 · the selected event failed");
    expect(summary).toHaveTextContent("key ActivityId");
    const steps = within(screen.getByTestId("correlation-dock-steps")).getAllByRole("listitem");
    expect(steps).toHaveLength(2);
    expect(steps[0]).toHaveTextContent("10:20:01 \u00b7 101 \u00b7 the selected event failed");
    expect(steps[1]).toHaveTextContent("10:20:07");
    expect(steps[1]).toHaveTextContent("message 2");
  });

  it("names context by time only, in the 'Also nearby' line", async () => {
    renderDock();
    await ready();
    const nearby = screen.getByTestId("correlation-dock-nearby");
    expect(nearby).toHaveTextContent("Also nearby:");
    expect(nearby).toHaveTextContent("time only, not linked");
    expect(nearby).toHaveTextContent("time only; in another chain");
    expect(nearby.textContent).not.toMatch(/caused|because of|led to/i);
  });

  it("draws the legend only when a dotted marker is drawn", async () => {
    renderDock();
    await ready();
    expect(screen.getByTestId("correlation-legend")).toBeInTheDocument();
    cleanup();
    renderDock({ items: scene().slice(0, 2) });
    await ready();
    expect(markers()).toHaveLength(2);
    expect(screen.queryByTestId("correlation-legend")).toBeNull();
  });

  it("says a window that was not read whole, with exact numbers, and counts sources as 'at least'", async () => {
    const items = scene();
    const queryWindow = vi.fn<QueryWindow>(async (_s, startMs, endMs) => ({
      ...windowReply(items, startMs, endMs),
      items: items.slice(0, 2),
      windowItems: 4,
      omittedItems: 2,
      nextOffset: 2,
    }));
    // The continuation pages fail, so the read stops at an error with 2 of 4 entries.
    const pageFails = vi.fn(async () => {
      throw new Error("page failed");
    });
    render(
      <EvtxAnalysisSessionProvider value={STATUS}>
        <EvtxCorrelationProvider value={makeData({ items, edges: sceneEdges() })}>
          <EvtxCorrelationDock
            windowDeps={{ queryWindow, queryTimelinePage: pageFails, sleep: async () => undefined }}
            selectionSettleMs={0}
            sessionSettleMs={0}
          />
        </EvtxCorrelationProvider>
      </EvtxAnalysisSessionProvider>,
    );
    await ready();
    expect(screen.getByTestId("correlation-dock-notices")).toHaveTextContent(
      "Showing 2 of 4 entries within ±75 s; reading stopped at an error (page failed), so entries and sources may be missing.",
    );
    expect(screen.getByTestId("correlation-dock-subtitle")).toHaveTextContent("at least 1 source");
  });

  it("says it is updating when the pair shown is an earlier session's", async () => {
    const { rerender } = renderDock();
    await ready();
    expect(screen.queryByTestId("correlation-dock-updating")).toBeNull();
    // The newest counts are for another session: the window read stays paired with nothing newer.
    rerender({ data: makeData({ items: scene(), edges: sceneEdges(), builtFor: "session:1", updating: true }) });
    expect(screen.getByTestId("correlation-dock-updating")).toHaveTextContent("Updating correlation...");
    expect(dock()).toHaveAttribute("aria-busy", "true");
  });

  it("states the narrowed and unread-source limits among its notices", async () => {
    renderDock({ unreadSources: true });
    await ready();
    expect(screen.getByTestId("correlation-dock-notices")).toHaveTextContent("Some sources were not fully read");
  });
});

describe("Open in Correlation view", () => {
  it("opens the row through the store, counts it as an open, and moves focus to the Correlation tab", async () => {
    const tab = document.createElement("button");
    tab.id = evtxViewTabId("correlation");
    document.body.appendChild(tab);
    renderDock();
    await ready();
    const open = screen.getByRole("button", { name: "Open in Correlation view" });
    expect(open).not.toHaveAttribute("aria-disabled", "true");
    fireEvent.click(open);
    const row = useEvtxCorrelationStore.getState().selectedChainId;
    expect(row).not.toBeNull();
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(1);
    expect(tab).toHaveFocus();
    tab.remove();
  });

  it("is aria-disabled with its reason in view when the event is in no loaded chain, and does nothing", async () => {
    seedRecords(allRecords(), 9);
    renderDock({ items: scene() });
    await ready();
    const open = screen.getByRole("button", { name: "Open in Correlation view" });
    expect(open).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByTestId("correlation-dock-open-reason")).toHaveTextContent(openDisabledText("notInChain"));
    expect(open).toHaveAccessibleDescription(openDisabledText("notInChain"));
    fireEvent.click(open);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBeNull();
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(0);
  });

  it("states why while the correlation links are still loading", async () => {
    renderDock({ data: { counts: null } });
    await ready();
    expect(screen.getByTestId("correlation-dock-open-reason")).toHaveTextContent(openDisabledText("loading"));
    expect(screen.getByRole("button", { name: "Open in Correlation view" })).toHaveAttribute("aria-disabled", "true");
  });
});

describe("layout: nothing in the dock can be squeezed to a sliver", () => {
  it("lays its body out in max-content rows, so the lane plot (a scroll container) keeps its content height", async () => {
    renderDock();
    const figure = await ready();
    const grid = figure.parentElement as HTMLElement;
    expect(grid.style.display).toBe("grid");
    expect(grid.style.gridAutoRows).toBe("max-content");
    // The dock variant has no cap of its own: its content height is its height.
    expect(figure.style.maxHeight).toBe("");
  });

  it("keeps the header in reach while the slot scrolls, and keeps the subtitle from vanishing", async () => {
    renderDock();
    await ready();
    const header = screen.getByTestId("correlation-dock-header");
    expect(header.style.position).toBe("sticky");
    expect(header.style.top).toBe("0px");
    expect(header.style.backgroundColor).toBe(tokens.colorNeutralBackground2);
    expect(screen.getByTestId("correlation-dock-subtitle").style.minWidth).toBe("10ch");
  });
});

describe("collapse and close", () => {
  it("collapses to the header row and expands again, each button naming what it does next", async () => {
    renderDock();
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Collapse correlation" }));
    expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(true);
    expect(screen.queryByRole("figure")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Expand correlation" }));
    expect(useEvtxLayoutStore.getState().dockCollapsed).toBe(false);
    await ready();
  });

  it("closes the dock and moves focus to the 'Correlation dock' toggle", async () => {
    const toggle = document.createElement("button");
    toggle.id = evtxPanelToggleId("dock");
    document.body.appendChild(toggle);
    renderDock();
    await ready();
    fireEvent.click(screen.getByRole("button", { name: "Close correlation dock" }));
    expect(useEvtxLayoutStore.getState().panels.dock).toBe(false);
    expect(toggle).toHaveFocus();
    toggle.remove();
  });
});

describe("a click on a marker (A1 ruling 6)", () => {
  it("selects the record when exactly one loaded record matches, and the dock recenters on it", async () => {
    const { queryWindow } = renderDock();
    await ready();
    expect(markerFor(9)).toHaveAccessibleName(/activate to select this event$/);
    fireEvent.click(markerFor(9));
    expect(useEvtxStore.getState().selectedRecordId).toBe(recordFor(9).id);
    // Like a row click in any view: the Details tab is shown.
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    await waitFor(() => expect(queryWindow).toHaveBeenCalledTimes(2));
    expect(queryWindow.mock.calls[1]![1]).toBe(recordFor(9).timestampEpoch - 75_000);
  });

  it("does nothing for the selected event itself", async () => {
    renderDock();
    await ready();
    expect(markerFor(1)).toHaveAccessibleName(/the selected event$/);
    fireEvent.click(markerFor(1));
    expect(useEvtxStore.getState().selectedRecordId).toBe(1);
    // Not even the rail's Details tab is brought forward: nothing was selected.
    expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
  });

  it("selects nothing when no loaded record matches, and its name says why afterwards", async () => {
    seedRecords([recordFor(1), recordFor(2), recordFor(10)], 1);
    renderDock();
    await ready();
    expect(markerFor(9)).toHaveAccessibleName(/activate to select this event$/);
    fireEvent.click(markerFor(9));
    expect(useEvtxStore.getState().selectedRecordId).toBe(1);
    expect(markerFor(9)).toHaveAccessibleName(/no loaded record matches, so activating it selects nothing$/);
    // The other markers keep their own names.
    expect(markerFor(10)).toHaveAccessibleName(/activate to select this event$/);
  });

  it("selects nothing when several loaded records match, and says so", async () => {
    const twin: EvtxRecord = { ...recordFor(9), id: 90 };
    seedRecords([...allRecords(), twin], 1);
    renderDock();
    await ready();
    fireEvent.click(markerFor(9));
    expect(useEvtxStore.getState().selectedRecordId).toBe(1);
    expect(markerFor(9)).toHaveAccessibleName(/more than one loaded record matches, so activating it selects nothing$/);
  });

  it("forgets what a click found when the window it was made in is replaced", async () => {
    seedRecords([recordFor(1), recordFor(2)], 1);
    renderDock();
    await ready();
    fireEvent.click(markerFor(9));
    expect(markerFor(9)).toHaveAccessibleName(/no loaded record matches/);
    act(() => useEvtxStore.getState().setSelectedRecordId(2));
    await waitFor(() => expect(markerFor(9)).toBeInTheDocument());
    await waitFor(() => expect(markerFor(9)).toHaveAccessibleName(/activate to select this event$/));
  });

  it("hands Escape to the window dropdown and keeps the browser from clearing the time range", async () => {
    renderDock();
    await ready();
    markerFor(9).focus();
    const workspaceEscape = vi.fn();
    window.addEventListener("keydown", workspaceEscape);
    const notCancelled = fireEvent.keyDown(markerFor(9), { key: "Escape" });
    window.removeEventListener("keydown", workspaceEscape);
    expect(notCancelled).toBe(false);
    expect(workspaceEscape.mock.calls[0]?.[0].defaultPrevented).toBe(true);
    expect(screen.getByRole("combobox", { name: "Correlation window" })).toHaveFocus();
  });
});

describe("no live region of its own (R7)", () => {
  it("has no role=status in any state it can be in", async () => {
    const states: (() => void)[] = [
      () => seedRecords(allRecords(), null),
      () => seedRecords([{ ...recordFor(1), timestampEpoch: 0 }], 1),
      () => seedRecords(allRecords(), 1),
    ];
    for (const seed of states) {
      cleanup();
      seed();
      renderDock();
      await idle();
      expect(document.querySelectorAll('[role="status"]')).toHaveLength(0);
      expect(document.querySelectorAll("[aria-live]")).toHaveLength(0);
    }
    cleanup();
    seedRecords(allRecords(), 1);
    renderDock({ status: null });
    expect(document.querySelectorAll('[role="status"]')).toHaveLength(0);
    cleanup();
    // An earlier session's pair, shown as updating, and an incomplete window with every notice.
    renderDock({ data: { updating: true }, unreadSources: true });
    await ready();
    expect(screen.getByTestId("correlation-dock-updating")).toBeInTheDocument();
    expect(document.querySelectorAll('[role="status"]')).toHaveLength(0);
    expect(document.querySelectorAll("[aria-live]")).toHaveLength(0);
    cleanup();
    const failing = vi.fn<QueryWindow>(async () => {
      throw new Error("no");
    });
    renderDock({ queryWindow: failing });
    await screen.findByRole("alert", undefined, { timeout: 5_000 });
    expect(document.querySelectorAll('[role="status"]')).toHaveLength(0);
  }, 15_000);
});

describe("text follows the log list font size (spec 7.1)", () => {
  it("sets the title at f - 1, the subtitle and summary at f - 2, from the setting, with no fixed pixel size", async () => {
    useUiStore.setState({ logListFontSize: 13 });
    renderDock();
    await ready();
    const title = within(dock()).getByText("Correlation");
    expect(title.style.fontSize).toBe("12px");
    expect(screen.getByTestId("correlation-dock-subtitle").style.fontSize).toBe("11px");
    expect(screen.getByTestId("correlation-dock-summary").style.fontSize).toBe("11px");
    cleanup();
    useUiStore.setState({ logListFontSize: 20 });
    renderDock();
    await ready();
    expect(within(dock()).getByText("Correlation").style.fontSize).toBe("19px");
    expect(screen.getByTestId("correlation-dock-subtitle").style.fontSize).toBe("18px");
    expect((document.querySelector("[data-lane-label]") as HTMLElement).style.fontSize).toBe("17px");
  });

  it("has no fixed pixel font size in its source", () => {
    expect(dockSource).not.toMatch(/fontSize:\s*"\d/);
    expect(dockSource).not.toMatch(/fontSize:\s*\d/);
  });
});

describe("what it imports and how it is colored", () => {
  const runtimeImports = (source: string) =>
    [...source.matchAll(/^import (?!type\b)[^;]*?from\s+"([^"]+)";/gms)].map((match) => match[1] as string);

  it("imports nothing from the lazily loaded Correlation view, in the dock or its reader", () => {
    for (const source of [dockSource, dockWindowSource]) {
      expect(runtimeImports(source).filter((module) => /EvtxCorrelationView(\.tsx?)?$/.test(module))).toEqual([]);
    }
  });

  it("has no color literal", () => {
    // Comments name issues ("#842"), which look like hex colors.
    const code = dockSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    expect(code).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(code).not.toMatch(/\brgba?\(/);
    expect(code).not.toMatch(/\bhsla?\(/);
  });
});

describe("work per render", () => {
  it("does not read again, nor rebuild its model, for a scan-progress tick that changes only the counts object", async () => {
    const { rerender, queryWindow, data } = renderDock();
    await ready();
    const before = screen.getByTestId("correlation-dock-summary");
    const counts = data.counts!;
    const builds = modelBuilds.mock.calls.length;
    expect(builds).toBeGreaterThan(0);
    // A new counts object with the same parts, as the hook publishes on every tick.
    for (let tick = 0; tick < 3; tick += 1) rerender({ data: { ...data, counts: { ...counts } } });
    await idle();
    expect(queryWindow).toHaveBeenCalledTimes(1);
    expect(modelBuilds.mock.calls.length).toBe(builds);
    expect(screen.getByTestId("correlation-dock-summary")).toBe(before);
    // A part that did change is a new model.
    rerender({ data: { ...data, counts: { ...counts, updating: true } } });
    expect(modelBuilds.mock.calls.length).toBe(builds + 1);
  });
});

describe("the dock never queries more than the selection and the width ask for", () => {
  it("makes no call at all while the dock only re-renders", async () => {
    const { rerender, queryWindow } = renderDock();
    await ready();
    for (let i = 0; i < 5; i += 1) rerender({ unreadSources: false });
    await idle();
    expect(queryWindow).toHaveBeenCalledTimes(1);
    expect(T0).toBeGreaterThan(0);
  });
});

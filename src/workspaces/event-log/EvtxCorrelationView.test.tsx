/**
 * The Correlation view. The shapes come from the parser crate's own reducer
 * (`__fixtures__/correlation-edges.json`); synthetic edges cover what the engine cannot yet produce
 * (a long exact chain, a candidate chain, a missing edge total). The shared data is built with the
 * real chain model and handed to the view through its provider, so the hook is not under test here
 * (useEvtxCorrelation.test.tsx has it).
 */
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { tokens } from "@fluentui/react-components";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

const indexBuilds = vi.hoisted(() => vi.fn());
vi.mock("./evtx-insights-data", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-insights-data")>();
  return {
    ...actual,
    buildEvidenceIndex: (...args: Parameters<typeof actual.buildEvidenceIndex>) => {
      indexBuilds();
      return actual.buildEvidenceIndex(...args);
    },
  };
});

const plotBuilds = vi.hoisted(() => vi.fn());
vi.mock("./evtx-correlation-view-model", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-correlation-view-model")>();
  return {
    ...actual,
    buildChainPlot: (...args: Parameters<typeof actual.buildChainPlot>) => {
      plotBuilds(...args);
      return actual.buildChainPlot(...args);
    },
  };
});

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import EvtxCorrelationView, { CORRELATION_ANNOUNCE_MS, scopeFailureText } from "./EvtxCorrelationView";
import viewSource from "./EvtxCorrelationView.tsx?raw";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import { openUnplacedList, useEvtxCorrelationStore } from "./evtx-correlation-store";
import { evtxViewTabId, useEvtxLayoutStore } from "./evtx-layout-store";
import { pickRailTextColors } from "./evtx-rail-text";
import { useEvtxStore } from "./evtx-store";
import { TIME_RANGE_SEPARATOR } from "./evtx-time";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import {
  EvtxCorrelationProvider,
  UNAVAILABLE_CORRELATION,
  type EvtxCorrelationData,
} from "./useEvtxCorrelation";
import {
  T0,
  eventItem,
  fixtureEdges,
  idsOf,
  makeData,
  numberOf,
  recordFor,
  rid,
  synthetic,
  type DataOptions,
} from "./evtx-correlation-test-fixtures";
import type { TimeWindow } from "./evtx-correlation-view-model";
import type { EvtxRecord } from "./types";
import { timelineOriginId, type TimelineCorrelationEdge, type TimelineItem, type UnplacedItem } from "./unified-timeline";

const NO_UNPROVEN_CLAIM = /not placed|no timeline position|without a timeline position|no timestamp/i;

function show(data: EvtxCorrelationData, nearby?: readonly TimelineItem[]) {
  const view = (value: EvtxCorrelationData) => (
    <EvtxCorrelationProvider value={value}>
      <EvtxCorrelationView nearby={nearby} />
    </EvtxCorrelationProvider>
  );
  const result = render(view(data));
  return { ...result, update: (next: EvtxCorrelationData) => result.rerender(view(next)) };
}

/** An exact pair (1, 2), an ambiguous group of three (3 to 5), a candidate pair and a blocked pair. */
function mixedData(extra: Partial<DataOptions> = {}): EvtxCorrelationData {
  const edges = [
    ...fixtureEdges("pairAndGroupDisjoint"),
    ...fixtureEdges("secondaryPair", 10),
    ...fixtureEdges("gappedPair", 20),
  ];
  const items = idsOf(edges).map((id) => eventItem(numberOf(id), T0 + numberOf(id) * 1_000));
  return makeData({ items, edges, ...extra });
}

function pairData(extra: Partial<DataOptions> = {}): EvtxCorrelationData {
  const edges = fixtureEdges("exactPair");
  return makeData({
    items: [eventItem(1, T0, "error", "first failed"), eventItem(2, T0 + 6_000, "info", "second ok")],
    edges,
    ...extra,
  });
}

function seedStore(records: EvtxRecord[] = []) {
  useEvtxStore.getState().reset();
  useEvtxStore.setState({ records, isLoading: false, timeZoneMode: "utc" });
}

const rows = () => screen.getAllByRole("option");
const rowTitles = () => rows().map((row) => row.getAttribute("data-chain-id"));
const status = () => screen.getByTestId("correlation-action-status");
const announcer = () => screen.getByTestId("correlation-announcer");
const alertText = () => screen.getByTestId("correlation-action-alert");

beforeEach(() => {
  localStorage.clear();
  useUiStore.setState({ themeId: "light" });
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false });
  useEvtxLayoutStore.setState({ activeView: "correlation" });
  seedStore();
  vi.mocked(writeText).mockReset();
  plotBuilds.mockClear();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("without a model", () => {
  it("says there is no analysis when none exists, and claims nothing", () => {
    show(UNAVAILABLE_CORRELATION);
    expect(screen.getByTestId("correlation-view")).toHaveTextContent("No event analysis is available");
    expect(announcer()).toHaveTextContent("No event analysis is available");
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(document.body.textContent).not.toMatch(/\b0 chains\b/);
  });

  it("says edges are being read while a session is built, never '0 chains'", () => {
    show({ ...UNAVAILABLE_CORRELATION, stage: "pending" });
    expect(screen.getByTestId("correlation-view")).toHaveTextContent("Reading correlation edges");
    expect(announcer()).toHaveTextContent("Reading correlation edges");
    expect(document.body.textContent).not.toMatch(/\b0 chains\b/);
  });

  it("shows a failure that is not a load result as an alert", () => {
    show({ ...UNAVAILABLE_CORRELATION, stage: "pending", error: "boom" });
    expect(screen.getByRole("alert")).toHaveTextContent("Correlation could not be built: boom");
  });
});

describe("the chain list (spec 8.11)", () => {
  it("lists the rows in the model's own order, strongest first, in a labelled listbox", () => {
    const data = mixedData();
    show(data);
    const listbox = screen.getByRole("listbox", { name: "Correlation chains, strongest first" });
    expect(listbox).toBeInTheDocument();
    expect(rowTitles()).toEqual(data.model!.chains.map((chain) => chain.id));
    const strengths = rows().map((row) => row.querySelector("[data-strength-badge]")?.getAttribute("data-strength-badge"));
    expect(strengths).toEqual(data.model!.chains.map((chain) => chain.strength));
    expect(strengths).toEqual([...strengths].sort((a, b) => order(a) - order(b)));
    expect(screen.getByText(/Chains . strongest first/i)).toBeInTheDocument();
  });

  it("does not re-sort what the model ordered", () => {
    const data = mixedData();
    const reversedTitles = [...data.model!.chains].map((chain) => chain.title).sort().reverse();
    show(data);
    const shown = rows().map((row) => row.getAttribute("data-chain-id"));
    expect(shown).toEqual(data.model!.chains.map((chain) => chain.id));
    // The model's order is by strength, which is not the alphabetical order of the titles.
    expect(data.model!.chains.map((chain) => chain.title)).not.toEqual(reversedTitles);
  });

  it("shows each row's badge, entry count from ALL members, title and span", () => {
    show(pairData());
    const row = rows()[0]!;
    expect(within(row).getByText("Exact")).toBeInTheDocument();
    expect(within(row).getByText("2 entries")).toBeInTheDocument();
    expect(within(row).getByText("101 · first failed")).toBeInTheDocument();
    expect(within(row).getByText(/^10:20:00.10:20:06$/)).toBeInTheDocument();
  });

  it("names each option from its title, strength and entry count, and tells two untitled rows apart (P7)", () => {
    // Counts-only: no item was read, so both exact pairs are untitled.
    const edges = [...fixtureEdges("exactPair"), ...fixtureEdges("exactPair", 10)];
    const data = makeData({ items: [], edges, hasItems: false, stage: "edgesOnly" });
    show(data);
    const names = rows().map((row) => row.getAttribute("aria-label"));
    expect(rows().map((row) => row.textContent)).toEqual([expect.stringContaining("Untitled chain"), expect.stringContaining("Untitled chain")]);
    expect(new Set(names).size).toBe(2);
    const [first, second] = data.model!.chains;
    expect(names).toEqual([
      `Exact, Untitled chain ${first!.id}, 2 entries, partial`,
      `Exact, Untitled chain ${second!.id}, 2 entries, partial`,
    ]);
    // The accessible name is what a screen reader reads, and what getByRole finds.
    expect(screen.getByRole("option", { name: names[1]! })).toBe(rows()[1]);
  });

  it("names a titled option by its title, and a partial one as partial", () => {
    show(pairData());
    expect(rows()[0]!.getAttribute("aria-label")).toBe("Exact, 101 · first failed, 2 entries");
    cleanup();
    show(makeData({ items: [eventItem(1, T0)], edges: fixtureEdges("exactPair") }));
    expect(rows()[0]!.getAttribute("aria-label")).toBe("Exact, 101 · message 1, 2 entries, partial");
  });

  it("selects the first chain by default and writes it to the transient store", async () => {
    const data = mixedData();
    show(data);
    expect(rows()[0]).toHaveAttribute("aria-selected", "true");
    expect(rows().filter((row) => row.getAttribute("aria-selected") === "true")).toHaveLength(1);
    await waitFor(() => expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(data.model!.chains[0]!.id));
  });

  it("honours a chain selected from outside the view", () => {
    const data = mixedData();
    const wanted = data.model!.chains[2]!.id;
    useEvtxCorrelationStore.setState({ selectedChainId: wanted });
    show(data);
    expect(rows()[2]).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("listbox")).toHaveAttribute("aria-activedescendant", rows()[2]!.id);
  });

  it("selects on click and moves the selection with the arrow keys, Home and End", () => {
    const data = mixedData();
    show(data);
    const ids = data.model!.chains.map((chain) => chain.id);
    fireEvent.click(rows()[1]!);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(ids[1]);
    const listbox = screen.getByRole("listbox");
    fireEvent.keyDown(listbox, { key: "ArrowDown" });
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(ids[2]);
    fireEvent.keyDown(listbox, { key: "ArrowUp" });
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(ids[1]);
    fireEvent.keyDown(listbox, { key: "End" });
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(ids[ids.length - 1]);
    fireEvent.keyDown(listbox, { key: "Home" });
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(ids[0]);
    expect(rows()[0]).toHaveAttribute("aria-selected", "true");
  });

  it("is one tab stop, and its Escape is spent here so the workspace does not clear the time range", () => {
    show(mixedData());
    const listbox = screen.getByRole("listbox");
    expect(listbox.tabIndex).toBe(0);
    for (const row of rows()) expect(row.tabIndex).toBeLessThan(0);
    expect(fireEvent.keyDown(listbox, { key: "Escape" })).toBe(false);
  });

  it("caps at 100 rows and says how many the cap left out, apart from edges that were never loaded", () => {
    const edges: TimelineCorrelationEdge[] = [];
    const items: TimelineItem[] = [];
    for (let i = 0; i < 120; i += 1) {
      const a = 1 + i * 2;
      const b = 2 + i * 2;
      edges.push(synthetic(`e${i}`, rid(a), rid(b)));
      items.push(eventItem(a, T0 + i * 1_000), eventItem(b, T0 + i * 1_000 + 500));
    }
    show(makeData({ items, edges }));
    expect(rows()).toHaveLength(100);
    const notices = screen.getByTestId("correlation-notices").textContent ?? "";
    expect(notices).toContain("Showing the first 100 of 120; 20 omitted.");
    expect(notices).not.toMatch(/paged and bounded/);
  });

  describe("a selected row the cap dropped (#842, ruling 3)", () => {
    function manyData(extra: Partial<DataOptions> = {}, without: ReadonlySet<string> = new Set()) {
      const edges: TimelineCorrelationEdge[] = [];
      const items: TimelineItem[] = [];
      for (let i = 0; i < 120; i += 1) {
        const pair = [eventItem(1 + i * 2, T0 + i * 1_000), eventItem(2 + i * 2, T0 + i * 1_000 + 500)];
        if (pair.some((item) => without.has(timelineOriginId(item.origin)))) continue;
        edges.push(synthetic(`e${i}`, rid(1 + i * 2), rid(2 + i * 2)));
        items.push(...pair);
      }
      const data = makeData({ items, edges, ...extra });
      const shown = new Set((data.model?.chains ?? []).map((row) => row.id));
      const pastCap = [...(data.model?.rowsByMember.values() ?? [])]
        .map((list) => list[0]!)
        .find((row) => !shown.has(row.id));
      return { data, pastCap: pastCap as NonNullable<typeof pastCap> };
    }
    const chainRows = () => Array.from(document.querySelectorAll<HTMLElement>("[data-chain-id]"));
    const notPlacedOption = () => document.querySelector<HTMLElement>("[data-unplaced-option]")!;
    const notes = () => screen.getByTestId("correlation-notices").textContent ?? "";

    it("lists it after the 100, selected, and says why it is there", () => {
      const { data, pastCap } = manyData();
      useEvtxCorrelationStore.setState({ selectedChainId: pastCap.id });
      show(data);
      expect(rows()).toHaveLength(101);
      const last = rows()[100]!;
      expect(last).toHaveAttribute("data-chain-id", pastCap.id);
      expect(last).toHaveAttribute("aria-selected", "true");
      expect(rows().filter((row) => row.getAttribute("aria-selected") === "true")).toHaveLength(1);
      expect(notes()).toContain("The selected chain is past the first 100 rows, so it is listed after them.");
      expect(notes()).toContain("Showing the first 100 of 120; 20 omitted.");
      // Not read as lost: no loss notice, and the store still holds the id it was given.
      expect(notes()).not.toContain("no longer present");
      expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(pastCap.id);
      expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent(pastCap.title ?? "");
    });

    it("leaves the first 100 rows where they were", () => {
      const { data, pastCap } = manyData();
      show(data);
      const before = rowTitles();
      cleanup();
      useEvtxCorrelationStore.setState({ selectedChainId: pastCap.id });
      show(data);
      expect(rowTitles().slice(0, 100)).toEqual(before.slice(0, 100));
    });

    it("drops the extra row again when the selection moves back among the 100", () => {
      const { data, pastCap } = manyData();
      useEvtxCorrelationStore.setState({ selectedChainId: pastCap.id });
      show(data);
      fireEvent.keyDown(screen.getByRole("listbox"), { key: "ArrowUp" });
      expect(rows()).toHaveLength(100);
      expect(rows()[99]).toHaveAttribute("aria-selected", "true");
      expect(notes()).not.toContain("past the first");
    });

    it("says nothing about it when the selection is among the 100, or an id no row has is selected", () => {
      const { data } = manyData();
      useEvtxCorrelationStore.setState({ selectedChainId: data.model!.chains[5]!.id });
      show(data);
      expect(rows()).toHaveLength(100);
      expect(notes()).not.toContain("past the first");
      cleanup();
      useEvtxCorrelationStore.setState({ selectedChainId: "chain-that-never-was" });
      show(data);
      expect(rows()).toHaveLength(100);
      expect(notes()).not.toContain("past the first");
    });

    it("puts the Not placed option one past the listed rows, with an id of its own, and walks to it", () => {
      const { data, pastCap } = manyData({ unplacedList: { items: unplacedItems(3), total: 3 } });
      useEvtxCorrelationStore.setState({ selectedChainId: pastCap.id });
      show(data);
      const listbox = screen.getByRole("listbox");
      expect(chainRows()).toHaveLength(101);
      expect(rows()).toHaveLength(102);
      const ids = rows().map((row) => row.id);
      // The option after row 100 (the dropped one) is not row 100's id again.
      expect(new Set(ids).size).toBe(ids.length);
      expect(rows()[101]).toBe(notPlacedOption());
      expect(listbox.getAttribute("aria-activedescendant")).toBe(rows()[100]!.id);
      fireEvent.keyDown(listbox, { key: "End" });
      expect(notPlacedOption()).toHaveAttribute("aria-selected", "true");
      expect(listbox.getAttribute("aria-activedescendant")).toBe(notPlacedOption().id);
      expect(document.getElementById(listbox.getAttribute("aria-activedescendant")!)).toBe(notPlacedOption());
      // Up returns to the listed row, which the cap had dropped, and closes the pane.
      fireEvent.keyDown(listbox, { key: "ArrowUp" });
      expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(false);
      expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(pastCap.id);
      expect(chainRows()[100]).toHaveAttribute("aria-selected", "true");
    });

    it("draws the dropped row in the overview strip, selected, with the others", () => {
      const { data, pastCap } = manyData();
      useEvtxCorrelationStore.setState({ selectedChainId: pastCap.id });
      show(data);
      expect(document.querySelectorAll("[data-bar]")).toHaveLength(101);
      expect(document.querySelectorAll('[data-bar][data-selected="true"]')).toHaveLength(1);
    });

    it("stops saying a chain is lost once an outside selection brings it back as a dropped row", () => {
      const full = manyData();
      const missing = new Set([...full.pastCap.memberIds, ...full.pastCap.unresolvedMemberIds]);
      const without = manyData({}, missing);
      expect(without.data.model?.rowsByMember.has([...missing][0]!)).toBe(false);
      useEvtxCorrelationStore.setState({ selectedChainId: full.pastCap.id });
      const view = show(without.data);
      expect(notes()).toContain("The chain that was selected is no longer present.");
      // The chain is back in the data, past the cap. The operator has not selected it: still said.
      view.update(full.data);
      expect(notes()).toContain("The chain that was selected is no longer present.");
      act(() => useEvtxCorrelationStore.getState().selectChain(full.pastCap.id));
      expect(chainRows()[100]).toHaveAttribute("aria-selected", "true");
      expect(notes()).not.toContain("no longer present");
    });
  });

  it("keeps the cap line and the paged-and-bounded line apart when both apply", () => {
    const edges: TimelineCorrelationEdge[] = [];
    const items: TimelineItem[] = [];
    for (let i = 0; i < 120; i += 1) {
      edges.push(synthetic(`e${i}`, rid(1 + i * 2), rid(2 + i * 2)));
      items.push(eventItem(1 + i * 2, T0 + i * 1_000), eventItem(2 + i * 2, T0 + i * 1_000 + 500));
    }
    show(makeData({ items, edges, totalEdges: 150 }));
    const lines = Array.from(screen.getByTestId("correlation-notices").querySelectorAll("li")).map((li) => li.textContent);
    expect(lines).toContain("Correlation details are paged and bounded: 30 correlation edges were not loaded, so chains may be incomplete.");
    expect(lines).toContain("Showing the first 100 of 120; 20 omitted.");
    expect(lines).toHaveLength(2 + 0 + (lines.length - 2));
  });

  it("says no chain was found without claiming the session has none when edges were not all loaded", () => {
    show(makeData({ items: [], edges: [], totalEdges: 5 }));
    expect(screen.getByText("No chains were found among the edges that were loaded.")).toBeInTheDocument();
    show(makeData({ items: [], edges: [], totalEdges: 0 }));
    expect(screen.getAllByText("No correlation chains were found in this session.").length).toBe(1);
  });

  it("marks a partial chain and counts its entries from every member (acceptance 11)", () => {
    // Member 2's item was never read: it is unresolved, not absent.
    const edges = fixtureEdges("exactPair");
    show(makeData({ items: [eventItem(1, T0)], edges }));
    const row = rows()[0]!;
    expect(within(row).getByText("2 entries (partial)")).toBeInTheDocument();
    expect(screen.getByTestId("partial-notice")).toHaveTextContent(
      "1 of 2 entries have no loaded timeline position, so they are not drawn on the plot.",
    );
  });

  it("says an entry carries no timestamp only when the session proves it", () => {
    const edges = fixtureEdges("exactPair");
    const proven = { scanComplete: true, unplacedListComplete: true, unplacedIds: new Set([rid(2)]) };
    show(makeData({ items: [eventItem(1, T0)], edges, unplaced: proven }));
    expect(screen.getByTestId("partial-notice")).toHaveTextContent(
      "1 of 2 entries carry no timestamp, so they are not placed on the plot.",
    );
    cleanup();
    show(makeData({ items: [eventItem(1, T0)], edges, unplaced: { ...proven, scanComplete: false } }));
    expect(screen.getByTestId("partial-notice").textContent).not.toMatch(NO_UNPROVEN_CLAIM);
  });
});

const order = (strength: string | null | undefined) =>
  ["exact", "candidate", "ambiguous", "coverageBlocked"].indexOf(strength ?? "");

describe("the selected chain's header and plot", () => {
  it("shows the title, strength, key kind and value, span and time zone", () => {
    show(pairData());
    expect(screen.getByRole("heading", { level: 2 })).toHaveTextContent("101 · first failed");
    expect(screen.getByText(/^key ActivityId/)).toBeInTheDocument();
    expect(document.body.textContent).toContain(`10:20:00${TIME_RANGE_SEPARATOR}10:20:06 (UTC)`);
  });

  it("shows the key kind even for a user or device id, and the full value in a tooltip", () => {
    const edge = synthetic("e1", rid(1), rid(2));
    edge.key = { kind: "userId", value: "S-1-5-21-1111111111-2222222222-3333333333-1001" };
    edge.evidence = edge.evidence.map((row) => ({ ...row, field: "userId", value: edge.key.value }));
    show(makeData({ items: [eventItem(1, T0), eventItem(2, T0 + 1_000)], edges: [edge] }));
    const header = screen.getByText(/^key UserId/);
    expect(header).toBeInTheDocument();
    const value = header.querySelector("span") as HTMLElement;
    expect(value.title).toBe("S-1-5-21-1111111111-2222222222-3333333333-1001");
    expect(value.textContent).toContain("…");
    expect(value.textContent!.length).toBeLessThanOrEqual(12);
  });

  it("draws the plot with a legend and one connector for a backed exact edge", () => {
    show(pairData());
    expect(screen.getByRole("figure", { name: /^Lane plot for 101 · first failed: 2 entries across 1 sources/ })).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Legend" })).toBeInTheDocument();
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(1);
  });

  it("gives an ambiguous row markers and no connector, headed as not a link", () => {
    const data = mixedData();
    const ambiguous = data.model!.chains.findIndex((chain) => chain.strength === "ambiguous");
    useEvtxCorrelationStore.setState({ selectedChainId: data.model!.chains[ambiguous]!.id });
    show(data);
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(0);
    expect(document.querySelectorAll("[data-marker]").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Why this is not a link" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Why these are linked" })).toBeNull();
  });

  it("names each marker by lane, entry, level, time, message, and how it is linked", () => {
    show(pairData());
    const first = document.querySelector<HTMLElement>(`[data-marker="${rid(1)}"]`)!;
    expect(first.getAttribute("aria-label")).toBe(
      "System, 101 · System, Error, 2026-10-06 10:20:00.000, first failed, linked by ActivityId (exact)",
    );
  });

  it("never reads a context marker's label as proof: production draws none", () => {
    show(pairData());
    expect(document.querySelectorAll('[data-role="nearby"]')).toHaveLength(0);
    expect(document.body.textContent).not.toMatch(/Not linked/);
  });

  it("explains in the plot area when the entries were not read, instead of drawing an empty plot", () => {
    show(pairData({ hasItems: false, stage: "edgesOnly" }));
    expect(screen.getByText("The entries of this chain were not read, so there is no plot or evidence table.")).toBeInTheDocument();
    expect(screen.queryByTestId("lane-plot")).toBeNull();
  });
});

describe("a 'Not linked' context marker through the view (decision A on #838, acceptance 2)", () => {
  const stray = () => eventItem(9, T0 + 3_000, "warning");
  const data = (extra: Partial<DataOptions> = {}) =>
    pairData({ items: [eventItem(1, T0), eventItem(2, T0 + 6_000), stray()], ...extra });
  const strayName = () => document.querySelector<HTMLElement>('[data-role="nearby"]')?.getAttribute("aria-label");

  it("says 'Not linked' only when every edge is loaded, nothing is narrowed and no gap names a limit", () => {
    show(data(), [stray()]);
    expect(strayName()).toContain("Not linked");
    expect(screen.getByRole("group", { name: "Legend" })).toHaveTextContent("not linked (no line)");
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(1);
  });

  it.each([
    ["edges were not all loaded", () => data({ totalEdges: 8 })],
    ["the view is narrowed", () => data({ scope: { visibleCount: 3, loadedCount: 9, textLogCount: 0 } })],
    ["the scope of the model is not known", () => data({ scope: null })],
    ["the engine limited correlation", () => data({ gaps: classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1) })],
    ["a gap names the entry's own origin", () => data({ gaps: classifyCoverageGaps([{ source: rid(9), reason: "x" }], 1) })],
    ["a gap names a member of the chain", () => data({ gaps: classifyCoverageGaps([{ source: rid(1), reason: "alias" }], 1) })],
  ])("says 'No loaded link' instead when %s", (_why, makeDataFor) => {
    show(makeDataFor(), [stray()]);
    expect(strayName()).toContain("No loaded link");
    expect(strayName()).not.toContain("Not linked");
    expect(screen.getByRole("group", { name: "Legend" })).toHaveTextContent("no loaded link (no line)");
  });

  it("draws none by default, which is what the workspace passes", () => {
    show(data());
    expect(document.querySelectorAll('[data-role="nearby"]')).toHaveLength(0);
  });
});

describe("the notices", () => {
  it("states the paged-and-bounded shortfall as a count when edges were not all loaded", () => {
    show(pairData({ totalEdges: 12 }));
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
      "Correlation details are paged and bounded: 11 correlation edges were not loaded, so chains may be incomplete.",
    );
  });

  it.each([
    ["not a number", Number.NaN],
    ["negative", -3],
    ["fractional", 1.5],
  ])("says the edge total is not known when it is %s, never 0 omitted (acceptance 5)", (_why, total) => {
    show(pairData({ totalEdges: total }));
    const text = screen.getByTestId("correlation-notices").textContent ?? "";
    expect(text).toContain("the number of correlation edges in this session is not known");
    expect(text).not.toMatch(/\b0 (correlation )?edges|0 omitted/);
  });

  it("is silent about edges when all were loaded", () => {
    show(pairData());
    expect(screen.queryByTestId("correlation-notices")).toBeNull();
  });

  it("shows the coverage-gap notice whenever the gaps clear completeness, and not otherwise", () => {
    show(pairData({ gaps: classifyCoverageGaps([{ source: "correlation", reason: "edge budget" }], 1) }));
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
      "The engine limited correlation, so some entries may not have been correlated and chains may be incomplete.",
    );
    cleanup();
    show(pairData({ gaps: classifyCoverageGaps([], 40) }));
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent("More coverage gaps may exist than are listed");
    cleanup();
    show(pairData({ gaps: classifyCoverageGaps([{ source: rid(1), reason: "alias conflict" }], 1) }));
    expect(screen.queryByTestId("correlation-notices")).toBeNull();
  });

  it("shows a stopped read and an edge failure, each with a Retry that calls the hook's retry", () => {
    const retry = vi.fn();
    show(
      pairData({
        scan: { state: "incomplete", stoppedBy: "budget" },
        edgeState: { error: "edges down", complete: false },
        retry,
      }),
    );
    const text = screen.getByTestId("correlation-notices").textContent ?? "";
    expect(text).toContain("Reading the timeline stopped at its memory limit");
    expect(text).toContain("Loading correlation edges stopped on an error (edges down).");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalledTimes(1);
  });

  it("shows no Retry when nothing failed", () => {
    show(pairData());
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });
});

describe("the scope (decision 10, acceptance 15)", () => {
  it("states the visible count and that text logs are not scoped, under the rail's condition", () => {
    show(pairData({ scope: { visibleCount: 3, loadedCount: 9, textLogCount: 4 } }));
    const text = screen.getByTestId("correlation-notices").textContent ?? "";
    expect(text).toContain("Links and strengths are computed over the 3 events visible. Events outside the view can make an Exact link ambiguous.");
    expect(text).toContain("Text logs are not scoped.");
  });

  it("leaves out the text-log line when there are none, and both lines when nothing is narrowed", () => {
    show(pairData({ scope: { visibleCount: 3, loadedCount: 9, textLogCount: 0 } }));
    expect(screen.getByTestId("correlation-notices").textContent).not.toContain("Text logs are not scoped.");
    cleanup();
    show(pairData({ scope: { visibleCount: 9, loadedCount: 9, textLogCount: 4 } }));
    expect(screen.queryByTestId("correlation-notices")).toBeNull();
  });

  it("states the scope the shown model carries, which is the one of its own session (P5)", () => {
    show(pairData({ builtFor: "old:3", updating: true, scope: { visibleCount: 2, loadedCount: 9, textLogCount: 0 } }));
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent("computed over the 2 events visible");
  });

  it("says the scope is not known when it is not, instead of showing no disclosure", () => {
    show(pairData({ scope: null }));
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
      "The events this model was built from are not known here, so events outside them may make an Exact link ambiguous.",
    );
  });
});

describe("the evidence and the sequence", () => {
  it("lists the entry and the key for every evidence row, which is what each connector is traced to", () => {
    show(pairData());
    const table = screen.getByRole("table");
    expect(within(table).getByRole("columnheader", { name: "Entry" })).toBeInTheDocument();
    expect(within(table).getByRole("columnheader", { name: "Where the key appears" })).toBeInTheDocument();
    const body = within(table).getAllByRole("row").slice(1);
    expect(body.map((row) => row.textContent)).toEqual([
      expect.stringMatching(/^101 · System\s*activityId =/),
      expect.stringMatching(/^102 · System\s*activityId =/),
    ]);
    expect(screen.getByRole("heading", { name: "Why these are linked" })).toBeInTheDocument();
    // Both endpoints have a row in the table, and the one connector is drawn.
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(1);
    expect(body).toHaveLength(2);
  });

  it("orders the sequence by recorded time with the first absolute and later ones as offsets", () => {
    show(pairData());
    const entries = Array.from(document.querySelectorAll<HTMLElement>("[data-sequence-entry]"));
    expect(entries.map((li) => li.getAttribute("data-sequence-entry"))).toEqual([rid(1), rid(2)]);
    expect(entries[0]!.textContent).toContain("2026-10-06 10:20:00.000");
    expect(entries[1]!.textContent).toContain("+6 s");
    expect(screen.getByText("Ordered by recorded time. Order is not evidence of cause.")).toBeInTheDocument();
  });

  it("weights the highest-severity entry 600, with the level as a word and an icon", () => {
    show(pairData());
    const [first, second] = Array.from(document.querySelectorAll<HTMLElement>("[data-sequence-entry]")) as [HTMLElement, HTMLElement];
    expect(first.style.fontWeight).toBe("600");
    expect(second.style.fontWeight).toBe("400");
    expect(first).toHaveTextContent("Error");
    expect(first.querySelector("svg[aria-hidden='true']")).not.toBeNull();
  });

  it("flags entries with the same timestamp and says their order is not established", () => {
    const edges = fixtureEdges("exactPair");
    show(makeData({ items: [eventItem(1, T0), eventItem(2, T0)], edges }));
    expect(screen.getByText(/same timestamp as the entry above; their order is not established/)).toBeInTheDocument();
  });

  it("shows the first 200 entries and the rest after 'Show all'", () => {
    const items: TimelineItem[] = [];
    const edges: TimelineCorrelationEdge[] = [];
    for (let i = 1; i <= 220; i += 1) {
      items.push(eventItem(i, T0 + i * 1_000));
      if (i > 1) edges.push(synthetic(`e${i}`, rid(i - 1), rid(i)));
    }
    show(makeData({ items, edges }));
    expect(document.querySelectorAll("[data-sequence-entry]")).toHaveLength(200);
    fireEvent.click(screen.getByRole("button", { name: "Show all 220" }));
    expect(document.querySelectorAll("[data-sequence-entry]")).toHaveLength(220);
    expect(screen.queryByRole("button", { name: "Show all 220" })).toBeNull();
  });

  it("says how many entries the plot's marker cap left undrawn, listed in Sequence (acceptance 22)", () => {
    const items: TimelineItem[] = [];
    const edges: TimelineCorrelationEdge[] = [];
    for (let i = 1; i <= 160; i += 1) {
      items.push(eventItem(i, T0 + i * 1_000));
      if (i > 1) edges.push(synthetic(`e${i}`, rid(i - 1), rid(i)));
    }
    show(makeData({ items, edges }));
    expect(screen.getByTestId("plot-omission").textContent).toContain("10 entries are listed in Sequence but not drawn");
    expect(document.querySelectorAll('[data-role="member"]')).toHaveLength(150);
  });
});

describe("Filter table to chain (acceptance 6 to 8)", () => {
  function armTable() {
    const tab = document.createElement("button");
    tab.id = evtxViewTabId("table");
    document.body.appendChild(tab);
    return tab;
  }

  it("applies a chain scope with its title, references and counts, then switches to Table and focuses its tab", () => {
    seedStore([recordFor(1), recordFor(2), recordFor(3)]);
    const tab = armTable();
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    const scope = useEvtxStore.getState().recordScope;
    expect(scope?.kind).toBe("chain");
    expect(scope?.title).toBe("101 · first failed");
    expect([...(scope?.records ?? [])].map((record) => record.eventRecordId).sort()).toEqual([1, 2]);
    expect(scope?.references).toHaveLength(2);
    expect(scope?.references?.every((reference) => reference.length === 1)).toBe(true);
    expect(scope?.counts).toMatchObject({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    expect(tab).toHaveFocus();
    tab.remove();
  });

  it("passes the references, so a pruned reference is counted by reference (6a record 24)", () => {
    seedStore([recordFor(1), recordFor(2)]);
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    const scope = useEvtxStore.getState().recordScope!;
    expect(scope.references).toBeDefined();
    // One member's record leaves: the scope keeps its other reference and counts the one that left.
    act(() => useEvtxStore.setState({ records: [recordFor(1)] }));
    const kept = useEvtxStore.getState().recordScope;
    expect(kept?.references).toHaveLength(2);
  });

  it("marks a chain scope bounded when its edges were not all loaded, in the chain's words", () => {
    seedStore([recordFor(1), recordFor(2)]);
    show(pairData({ totalEdges: 40 }));
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    expect(useEvtxStore.getState().recordScope?.counts.bounded).toBe(true);
  });

  it("stays on the Correlation view, and says why, when the scope could not be applied", () => {
    seedStore([]);
    const tab = armTable();
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    expect(useEvtxStore.getState().recordScope).toBeNull();
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(tab).not.toHaveFocus();
    // A table that was not filtered is a failure of the operator's action: an alert, not a status.
    expect(alertText()).toHaveTextContent("2 events of this chain are not loaded.");
    expect(status()).toHaveTextContent("");
    tab.remove();
  });

  it("does not say 'no loaded events' when entries could not be looked for", () => {
    seedStore([recordFor(1), recordFor(2)]);
    // Neither member's item was read: they are unresolved, so nothing is known about their records.
    show(makeData({ items: [], edges: fixtureEdges("exactPair"), hasItems: true }));
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    expect(useEvtxStore.getState().recordScope).toBeNull();
    const text = alertText().textContent ?? "";
    expect(text).toContain("2 entries of this chain could not be matched to a record because their timeline items were not read.");
    expect(text).not.toMatch(/no loaded events?/i);
    expect(text).not.toMatch(/not loaded/i);
  });

  it("says events are still loading rather than that the chain has none", () => {
    seedStore([recordFor(1), recordFor(2)]);
    useEvtxStore.setState({ isLoading: true });
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    expect(alertText()).toHaveTextContent("events are still loading");
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
  });

  it("cannot be used before the entries are read, or while the model is being rebuilt", () => {
    seedStore([recordFor(1), recordFor(2)]);
    show(pairData({ hasItems: false, stage: "edgesOnly" }));
    const filter = screen.getByRole("button", { name: "Filter table to chain" });
    expect(filter).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(filter);
    expect(useEvtxStore.getState().recordScope).toBeNull();
    cleanup();
    show(pairData({ updating: true }));
    expect(screen.getByRole("button", { name: "Filter table to chain" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("button", { name: "Copy as text" })).toHaveAttribute("aria-disabled", "true");
  });

  describe("scopeFailureText", () => {
    const counts = { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false };
    it("never says 'no loaded events' for any counts", () => {
      for (const unresolved of [0, 1, 4]) {
        for (const notLoaded of [0, 2]) {
          const text = scopeFailureText({ ...counts, unresolved, notLoaded }, false);
          expect(text).not.toMatch(/no loaded events?/i);
        }
      }
    });
    it("keeps unresolved apart from not loaded", () => {
      expect(scopeFailureText({ ...counts, unresolved: 2 }, false)).not.toMatch(/not loaded/);
      expect(scopeFailureText({ ...counts, notLoaded: 2 }, false)).toMatch(/not loaded/);
    });
    it("has a reason even when every count is 0", () => {
      expect(scopeFailureText(counts, false)).toBe("The table was not filtered: this chain names no event it can show.");
    });
  });
});

describe("Copy as text", () => {
  it("copies the selected chain's text and says so", async () => {
    vi.mocked(writeText).mockResolvedValue(undefined);
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const text = vi.mocked(writeText).mock.calls[0]![0];
    expect(text).toContain("Exact: 101 · first failed");
    expect(text).toContain("Sequence (ordered by recorded time; order is not evidence of cause)");
    await waitFor(() => expect(status()).toHaveTextContent("Copied the chain as text."));
    expect(screen.queryByTestId("correlation-action-alert")).toBeNull();
  });

  it("includes the scope and edge notices in the copy, so a paste cannot read as more certain", async () => {
    vi.mocked(writeText).mockResolvedValue(undefined);
    show(pairData({ totalEdges: 30, scope: { visibleCount: 3, loadedCount: 9, textLogCount: 0 } }));
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const text = vi.mocked(writeText).mock.calls[0]![0];
    expect(text).toContain("computed over the 3 events visible");
    expect(text).toContain("Correlation details are paged and bounded");
  });

  it("reports a failed copy visibly", async () => {
    vi.mocked(writeText).mockRejectedValue(new Error("clipboard denied"));
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(alertText()).toHaveTextContent("Copy failed: clipboard denied"));
    expect(status()).toHaveTextContent("");
  });
});

describe("the evidence index (P8)", () => {
  beforeEach(() => indexBuilds.mockClear());

  it("is not built while the view is open, nor when loaded records change under it", () => {
    seedStore([recordFor(1), recordFor(2)]);
    show(pairData());
    expect(indexBuilds).not.toHaveBeenCalled();
    for (let batch = 3; batch <= 8; batch += 1) {
      act(() => useEvtxStore.setState({ records: [recordFor(1), recordFor(2), recordFor(batch)] }));
    }
    expect(indexBuilds).not.toHaveBeenCalled();
  });

  it("is built once for a marker click, from the records loaded at that moment", () => {
    seedStore([recordFor(1)]);
    show(pairData());
    act(() => useEvtxStore.setState({ records: [recordFor(1), recordFor(2)] }));
    expect(indexBuilds).not.toHaveBeenCalled();
    fireEvent.click(document.querySelector(`[data-marker="${rid(2)}"]`)!);
    expect(indexBuilds).toHaveBeenCalledTimes(1);
    // Record 2 arrived after the view was shown, and the click finds it.
    expect(useEvtxStore.getState().selectedRecordId).toBe(2);
  });

  it("is built once for Filter table to chain, from the records loaded at that moment", () => {
    seedStore([recordFor(1)]);
    show(pairData());
    act(() => useEvtxStore.setState({ records: [recordFor(1), recordFor(2)] }));
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    expect(indexBuilds).toHaveBeenCalledTimes(1);
    expect([...(useEvtxStore.getState().recordScope?.records ?? [])].map((r) => r.eventRecordId).sort()).toEqual([1, 2]);
  });
});

describe("selecting an entry's record from the plot", () => {
  it("selects the one loaded record the marker names, and opens Details", () => {
    seedStore([recordFor(1), recordFor(2)]);
    useEvtxLayoutStore.setState({ railTab: "insights" });
    show(pairData());
    fireEvent.click(document.querySelector(`[data-marker="${rid(2)}"]`)!);
    expect(useEvtxStore.getState().selectedRecordId).toBe(2);
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
  });

  it("selects nothing and says why when no loaded record matches, or several do", () => {
    seedStore([]);
    show(pairData());
    fireEvent.click(document.querySelector(`[data-marker="${rid(1)}"]`)!);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    expect(status()).toHaveTextContent("No loaded event matches this entry, so no record is selected.");
    act(() => seedStore([recordFor(1), { ...recordFor(1), id: 77 }]));
    fireEvent.click(document.querySelector(`[data-marker="${rid(1)}"]`)!);
    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    expect(status()).toHaveTextContent("2 loaded events match this entry, so none is selected.");
  });

  it("moves focus back to the chain list on Escape, without clearing a time range", () => {
    useEvtxStore.setState({ timeRange: { startMs: T0, endMs: T0 + 10_000 } });
    show(pairData());
    const marker = document.querySelector<HTMLElement>(`[data-marker="${rid(1)}"]`)!;
    marker.focus();
    const notCancelled = fireEvent.keyDown(marker, { key: "Escape" });
    expect(notCancelled).toBe(false);
    expect(screen.getByRole("listbox")).toHaveFocus();
    expect(useEvtxStore.getState().timeRange).not.toBeNull();
  });
});

/**
 * Spec 10: one polite status, throttled to 5 s. The view has exactly two live regions in every
 * state: the throttled announcer, which says everything unsolicited, and one reply to the
 * operator's own action (which expects an answer at once). A failure is an alert. The scan's
 * progress line is a plain line: it changes with every page read.
 */
describe("the live regions (spec 10)", () => {
  const regions = () => screen.getAllByRole("status").map((node) => node.getAttribute("data-testid"));
  const TWO = ["correlation-announcer", "correlation-action-status"];
  const running = {
    state: "running" as const,
    progress: { scannedItems: 500, totalItems: 2_000, retainedItems: 10 },
    stoppedBy: null,
    error: null,
  };

  it.each([
    ["no session", () => UNAVAILABLE_CORRELATION],
    ["a session being built", () => ({ ...UNAVAILABLE_CORRELATION, stage: "pending" as const })],
    ["a failure with no model", () => ({ ...UNAVAILABLE_CORRELATION, stage: "pending" as const, error: "boom" })],
    ["a full model", () => pairData()],
    ["a model with no chain", () => makeData({ items: [], edges: [], totalEdges: 0 })],
    ["a counts-only model", () => pairData({ hasItems: false, stage: "edgesOnly" })],
    ["a scan in flight", () => pairData({ stage: "scanning", nextScan: running, updating: true })],
    ["a stopped read and an edge failure", () => pairData({ scan: { state: "incomplete", stoppedBy: "budget" }, edgeState: { error: "edges down" } })],
    ["a model with a failure that is not a load result", () => pairData({ error: "boom" })],
  ])("has exactly the announcer and the action reply as status regions with %s", (_why, makeFor) => {
    show(makeFor());
    expect([...regions()].sort()).toEqual([...TWO].sort());
    expect(document.querySelectorAll('[aria-live]').length).toBeLessThanOrEqual(2);
  });

  it("keeps both regions after an action failed, which adds an alert and no third status", async () => {
    vi.mocked(writeText).mockRejectedValue(new Error("clipboard denied"));
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(alertText()).toBeInTheDocument());
    expect([...regions()].sort()).toEqual([...TWO].sort());
  });

  it("does not make the progress line a live region, nor put it inside one", () => {
    show(pairData({ stage: "scanning", nextScan: running, updating: true }));
    const line = screen.getByTestId("correlation-updating");
    expect(line).toHaveTextContent("Reading 500 of 2,000 timeline items...");
    expect(line.getAttribute("role")).toBeNull();
    expect(line.getAttribute("aria-live")).toBeNull();
    expect(line.closest('[role="status"], [role="alert"], [role="log"], [aria-live]')).toBeNull();
  });

  it("announces at most once inside 5 s however many pages the scan reads", () => {
    vi.useFakeTimers();
    const data = (scannedItems: number) =>
      pairData({
        stage: "scanning",
        updating: true,
        nextScan: { ...running, progress: { scannedItems, totalItems: 100_000, retainedItems: 10 } },
      });
    const view = show(data(1_000));
    const live = '[role="status"], [role="alert"], [role="log"], [aria-live]';
    const observer = new MutationObserver(() => undefined);
    observer.observe(screen.getByTestId("correlation-view"), { subtree: true, childList: true, characterData: true });
    let announcements = 0;
    for (let page = 2; page <= 101; page += 1) {
      view.update(data(page * 1_000));
      act(() => {
        vi.advanceTimersByTime(40);
      });
      announcements += observer
        .takeRecords()
        .filter((record) => {
          const element = record.target instanceof Element ? record.target : record.target.parentElement;
          return element?.closest(live) != null;
        }).length;
    }
    observer.disconnect();
    expect(screen.getByTestId("correlation-updating")).toHaveTextContent("Reading 101,000 of 100,000");
    expect(announcements).toBeLessThanOrEqual(1);
  });

  it("announces that the view is updating, not how far the scan has got", () => {
    show(pairData({ stage: "scanning", nextScan: running, updating: true }));
    expect(announcer().textContent).toBe("1 chain. Updating");
  });

  it("says an action's reply in the action region and nothing else of it", async () => {
    vi.mocked(writeText).mockResolvedValue(undefined);
    show(pairData());
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(status()).toHaveTextContent("Copied the chain as text."));
    expect(announcer().textContent).not.toContain("Copied");
  });
});

describe("a model that is being rebuilt (acceptance 18)", () => {
  it("shows the previous model as updating and never pairs it with a newer session's numbers", () => {
    show(pairData({ builtFor: "old:1", updating: true, scope: { visibleCount: 2, loadedCount: 2, textLogCount: 0 }, nextScan: { state: "running", progress: { scannedItems: 500, totalItems: 2000, retainedItems: 10 }, stoppedBy: null, error: null } }));
    expect(screen.getByTestId("correlation-updating")).toHaveTextContent("Updating correlation...");
    expect(screen.getByTestId("correlation-updating")).toHaveTextContent("Reading 500 of 2,000 timeline items...");
    expect(screen.getByTestId("correlation-view")).toHaveAttribute("aria-busy", "true");
    expect(rows()).toHaveLength(1);
  });

  it("keeps a chain selected in the store while a rebuild is under way, even if it is not in the old model", () => {
    useEvtxCorrelationStore.setState({ selectedChainId: "elsewhere" });
    show(pairData({ updating: true }));
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe("elsewhere");
  });

  it("replaces a selection that is gone once the model is current, and says so", async () => {
    useEvtxCorrelationStore.setState({ selectedChainId: "gone" });
    const data = pairData();
    show(data);
    expect(rows()[0]).toHaveAttribute("aria-selected", "true");
    await waitFor(() => expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(data.model!.chains[0]!.id));
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent(
      "The chain that was selected is no longer present. Another chain is shown.",
    );
  });
});

describe("the live region (acceptance 22)", () => {
  it("announces the chain count, then not again for 5 s whatever changes", () => {
    vi.useFakeTimers();
    const one = pairData();
    const view = show(one);
    const announcer = () => screen.getByTestId("correlation-announcer");
    expect(announcer()).toHaveTextContent("1 chain");
    expect(announcer()).toHaveAttribute("aria-live", "polite");
    expect(announcer()).toHaveAttribute("role", "status");
    view.update(mixedData());
    act(() => {
      vi.advanceTimersByTime(CORRELATION_ANNOUNCE_MS - 1);
    });
    expect(announcer()).toHaveTextContent("1 chain");
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(announcer().textContent).toMatch(/^4 chains/);
  });

  it("says when the edges are partial", () => {
    show(pairData({ totalEdges: 9 }));
    expect(screen.getByTestId("correlation-announcer")).toHaveTextContent("1 chain. Correlation edges are partial");
  });
});

describe("text and colors", () => {
  it("makes no statement that an entry is not placed without proof", () => {
    show(mixedData({ unplaced: { scanComplete: false } }));
    expect(document.body.textContent).not.toMatch(NO_UNPROVEN_CLAIM);
  });

  it("takes every size from the log list font size", () => {
    useUiStore.setState({ logListFontSize: 20 });
    show(pairData());
    const title = screen.getByRole("heading", { level: 2 });
    expect(title.style.fontSize).toBe("21px");
    useUiStore.setState({ logListFontSize: 13 });
  });

  it("has no color literal, and uses no tertiary text color where it can miss 4.5:1", () => {
    expect(viewSource).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(viewSource).not.toMatch(/\brgba?\(|\bhsla?\(/);
    expect(viewSource).not.toMatch(/colorNeutralForeground3\b/);
  });
});

/**
 * Contrast in all seven themes (spec 10). Pairs are measured on resolved theme colors and the
 * painted element's own color is compared with the same token. A selected row's own fill is read
 * back too; the list surface and the card surface a pair sits on are not.
 */
describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "chain list contrast in the %s theme",
  (id, theme) => {
    const r = (token: string) => resolveToken(token, theme);
    const atLeast = (label: string, a: string, b: string, minimum: number) => {
      expect(contrastRatio(r(a), r(b)), `${id}: ${label}`).toBeGreaterThanOrEqual(minimum);
    };

    beforeEach(() => {
      useUiStore.setState({ themeId: theme.id });
    });

    it("reads a selected row at 4.5:1 in the selection foreground, and its Exact badge on the surface fill", () => {
      const visuals = buildEvtxVisualTokens(theme);
      atLeast("selected row text", visuals.selection.foreground, visuals.selection.background, 4.5);
      atLeast("exact badge text on the surface", visuals.strengths.exact.foreground, tokens.colorNeutralBackground1, 4.5);
      atLeast("exact badge border on the surface", visuals.strengths.exact.border, tokens.colorNeutralBackground1, 3);
      atLeast("selection edge on the surface", visuals.selection.border, tokens.colorNeutralBackground1, 3);
      // On an unselected row the Exact badge keeps its own fill on the list surface (Background2).
      atLeast("exact badge border on the list surface", visuals.strengths.exact.border, tokens.colorNeutralBackground2, 3);
      atLeast("exact badge text on its own fill", visuals.strengths.exact.foreground, visuals.strengths.exact.background, 4.5);
      // The badge on its own fill is 1.00:1 against the selection fill, which is why it is not used there.
      expect(contrastRatio(r(visuals.strengths.exact.background), r(visuals.selection.background))).toBeLessThan(1.1);
      show(mixedData());
      const selected = rows()[0]!;
      expect(selected.style.color).toBe(visuals.selection.foreground);
      expect(selected.style.backgroundColor).toBe(visuals.selection.background);
      const badge = selected.querySelector<HTMLElement>("[data-strength-badge]")!;
      expect(badge.getAttribute("data-strength-badge")).toBe("exact");
      expect(badge.style.backgroundColor).toBe(tokens.colorNeutralBackground1);
      expect(badge.style.color).toBe(visuals.strengths.exact.foreground);
    });

    it("keeps every other badge readable on its own fill and on both list surfaces", () => {
      const visuals = buildEvtxVisualTokens(theme);
      for (const strength of ["candidate", "ambiguous", "coverageBlocked"] as const) {
        const badge = visuals.strengths[strength];
        atLeast(`${strength} text`, badge.foreground, badge.background, 4.5);
        atLeast(`${strength} border on the list`, badge.border, tokens.colorNeutralBackground2, 3);
        atLeast(`${strength} border on a selected row`, badge.border, visuals.selection.background, 3);
      }
      // The rows the first test cannot reach: every badge not on a selected row keeps its own text
      // color and border, read back below. Its fill is not read back for these rows.
      show(mixedData());
      const unselected = rows().filter((row) => row.getAttribute("aria-selected") === "false");
      expect(unselected.length).toBeGreaterThan(0);
      for (const row of unselected) {
        const badge = row.querySelector<HTMLElement>("[data-strength-badge]")!;
        const strength = badge.getAttribute("data-strength-badge") as keyof typeof visuals.strengths;
        const asPainted = (color: string) => {
          const probe = document.createElement("span");
          probe.style.color = color;
          return probe.style.color;
        };
        expect(badge.style.color).toBe(asPainted(visuals.strengths[strength].foreground));
        // The whole border, read back the way the browser normalizes a shorthand.
        const probe = document.createElement("span");
        probe.style.border = `1px ${visuals.strengths[strength].borderStyle} ${visuals.strengths[strength].border}`;
        expect(badge.style.border).toBe(probe.style.border);
      }
    });

    it("reads the level word of a Sequence entry at 4.5:1 on its card, in the level's own text color", () => {
      const visuals = buildEvtxVisualTokens(theme);
      for (const level of ["Critical", "Error", "Warning", "Information", "Verbose"] as const) {
        atLeast(`${level} word`, visuals.levels[level].textColor, tokens.colorNeutralBackground1, 4.5);
      }
      show(pairData());
      const entries = Array.from(document.querySelectorAll<HTMLElement>("[data-sequence-entry]"));
      const word = (entry: HTMLElement, text: string) =>
        Array.from(entry.querySelectorAll<HTMLElement>("span")).find((span) => span.textContent?.trim() === text)!;
      // The browser reads a hex color back as rgb(), so the token is read back the same way.
      const asPainted = (color: string) => {
        const probe = document.createElement("span");
        probe.style.color = color;
        return probe.style.color;
      };
      expect(word(entries[0]!, "Error").style.color).toBe(asPainted(visuals.levels.Error.textColor));
      expect(word(entries[1]!, "Information").style.color).toBe(asPainted(visuals.levels.Information.textColor));
    });

    it("reads the list's titles and captions at 4.5:1 on the list surface", () => {
      const rail = pickRailTextColors(theme);
      atLeast("title", rail.primary, tokens.colorNeutralBackground2, 4.5);
      atLeast("caption and eyebrow", rail.secondary, tokens.colorNeutralBackground2, 4.5);
      atLeast("detail caption", rail.cardSecondary, tokens.colorNeutralBackground1, 4.5);
      show(mixedData());
      const unselected = rows().find((row) => row.getAttribute("aria-selected") === "false")!;
      expect(unselected.style.color).toBe(rail.primary);
    });
  },
);

// ---- the overview strip and the Not placed pane (Phase 10b, #840) --------------------------------

/** Log lines with no timestamp, as the engine lists them. */
function unplacedLog(n: number): UnplacedItem {
  return {
    reason: "missingTimestamp",
    origin: {
      kind: "log",
      file: "C:\\Logs\\IntuneManagementExtension.log",
      component: null,
      line: n,
      source: "writer.cpp",
      machine: null,
      bundle: null,
      recordId: n,
    },
  };
}
const unplacedItems = (count: number) => Array.from({ length: count }, (_, i) => unplacedLog(i + 1));
const slider = () => screen.getByRole("slider", { name: "Zoom window of the lane plot" });
const axisLabels = () =>
  Array.from((document.querySelector("[data-axis]") as HTMLElement).children).map((node) => node.textContent);
const pinned = () => document.querySelectorAll("[data-pinned]").length;

describe("the overview strip in the view (spec 8.11)", () => {
  it("sits between the header (with its legend) and the lane plot, above the plot", () => {
    show(mixedData());
    const legend = screen.getByTestId("correlation-legend");
    const overview = screen.getByTestId("correlation-overview");
    const plot = screen.getByTestId("lane-plot");
    expect(legend.compareDocumentPosition(overview) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(overview.compareDocumentPosition(plot) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // The marker-shape legend is in the detail header, as spec 8.11 places it.
    expect(legend).toHaveTextContent("Event");
    expect(legend).toHaveTextContent("Log line");
  });

  it("is not drawn before the entries are read, where there is no plot either", () => {
    show(pairData({ hasItems: false, stage: "edgesOnly" }));
    expect(screen.queryByTestId("correlation-overview")).toBeNull();
    expect(screen.queryByRole("slider")).toBeNull();
  });

  it("draws a bar for every chain with a position, and the selected chain's solid", () => {
    show(mixedData());
    const bars = document.querySelectorAll("[data-bar]");
    expect(bars).toHaveLength(rows().length);
    expect(document.querySelectorAll('[data-bar][data-selected="true"]')).toHaveLength(1);
  });

  it("starts at the chain's default window, which the plot also uses", () => {
    show(mixedData());
    const before = axisLabels();
    expect(slider().getAttribute("aria-valuetext")).toMatch(/ to .*, 10 s wide$/);
    expect(before).toHaveLength(5);
    expect(screen.getByTestId("lane-plot")).toBeInTheDocument();
  });

  it("sets the lane window: moving the band pins the entries it leaves outside, and Home brings them back", () => {
    show(mixedData());
    const initial = axisLabels();
    expect(pinned()).toBe(0);
    for (let press = 0; press < 5; press += 1) fireEvent.keyDown(slider(), { key: "ArrowRight" });
    expect(axisLabels()).not.toEqual(initial);
    expect(pinned()).toBeGreaterThan(0);
    fireEvent.keyDown(slider(), { key: "Home" });
    expect(axisLabels()).toEqual(initial);
    expect(pinned()).toBe(0);
  });

  it("widens the lane window with Shift+Right, which the plot's ticks show, and cannot narrow below 10 s", () => {
    show(mixedData());
    const initial = axisLabels();
    fireEvent.keyDown(slider(), { key: "ArrowLeft", shiftKey: true });
    expect(slider().getAttribute("aria-valuetext")).toMatch(/, 10 s wide$/);
    expect(axisLabels()).toEqual(initial);
    fireEvent.keyDown(slider(), { key: "ArrowRight", shiftKey: true });
    // The first chain's window starts at the strip's start, so only its end can grow: 11 s.
    expect(slider().getAttribute("aria-valuetext")).toMatch(/, 11 s wide$/);
    expect(axisLabels()).not.toEqual(initial);
  });

  it("never turns the default window into null, which would draw nothing", () => {
    show(mixedData());
    expect(screen.getByTestId("lane-plot")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/nothing to plot/);
    fireEvent.keyDown(slider(), { key: "ArrowRight" });
    fireEvent.keyDown(slider(), { key: "Home" });
    expect(screen.getByTestId("lane-plot")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/nothing to plot/);
  });

  describe("a window equal to the default is the default, so the plot goes on following it", () => {
    const lastBuiltWindow = () => {
      const calls = plotBuilds.mock.calls;
      return (calls[calls.length - 1]![0] as { window?: TimeWindow | null }).window;
    };
    const LEFT = 100;
    const WIDTH = 720;
    /** The band's own press target, with the strip's geometry stubbed (jsdom has no layout). */
    const bandAndBox = () => {
      screen.getByTestId("overview-box").getBoundingClientRect = () =>
        ({ left: LEFT, top: 0, right: LEFT + WIDTH, bottom: 48, width: WIDTH, height: 48, x: LEFT, y: 0, toJSON: () => ({}) }) as DOMRect;
      const wash = document.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
      return { box: slider(), wash, startX: LEFT + (parseFloat(wash.style.left) / 100) * WIDTH + 2 };
    };

    it("hands the plot undefined before anything is done, and after a drag cancelled with Escape", () => {
      show(mixedData());
      expect(lastBuiltWindow()).toBeUndefined();
      const { box, wash, startX } = bandAndBox();
      fireEvent.pointerDown(wash, { clientX: startX, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
      fireEvent.pointerMove(box, { clientX: startX + 60, buttons: 1, pointerId: 1 });
      // Mid-drag the band is somewhere else, so the plot has a concrete window.
      expect(lastBuiltWindow()).toBeDefined();
      expect(fireEvent.keyDown(box, { key: "Escape" })).toBe(false);
      // Back where it was pressed, which is the default: no override is kept.
      expect(lastBuiltWindow()).toBeUndefined();
    });

    // Only a window equal at BOTH ends is the default. The first chain's default starts at the strip's
    // start, so its end handle is the one that can move on its own; the second chain sits in the middle
    // of the strip, so there the start handle can.
    it.each([
      { chainRow: 0, side: "end", dx: 40 },
      { chainRow: 1, side: "start", dx: -40 },
    ] as const)("hands the plot a concrete window when only the $side edge of chain $chainRow's default moves", ({ chainRow, side, dx }) => {
      show(mixedData());
      if (chainRow !== 0) fireEvent.click(rows()[chainRow]!);
      const { box } = bandAndBox();
      const wash = document.querySelector<HTMLElement>('[data-evtx-layer="wash"]')!;
      const left = parseFloat(wash.style.left) / 100;
      const right = left + parseFloat(wash.style.width) / 100;
      const edgeX = LEFT + (side === "start" ? left : right) * WIDTH;
      const handle = document.querySelector<HTMLElement>(`[data-part="${side}"]`)!;
      fireEvent.pointerDown(handle, { clientX: edgeX, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
      fireEvent.pointerMove(box, { clientX: edgeX + dx, buttons: 1, pointerId: 1 });
      expect(lastBuiltWindow()).toBeDefined();
    });

    it("hands the plot undefined when a key move lands exactly back on the default", () => {
      show(mixedData());
      fireEvent.keyDown(slider(), { key: "ArrowRight" });
      expect(lastBuiltWindow()).toBeDefined();
      fireEvent.keyDown(slider(), { key: "ArrowLeft" });
      expect(lastBuiltWindow()).toBeUndefined();
    });

    it("follows the new default when a live rebuild changes it after a cancelled drag", () => {
      const view = show(mixedData());
      const { box, wash, startX } = bandAndBox();
      fireEvent.pointerDown(wash, { clientX: startX, button: 0, buttons: 1, isPrimary: true, pointerId: 1 });
      fireEvent.pointerMove(box, { clientX: startX + 60, buttons: 1, pointerId: 1 });
      fireEvent.keyDown(box, { key: "Escape" });
      const before = axisLabels();
      // A live rebuild in which the selected chain's first entry is 1 s earlier: its default moves, and
      // the strip only grows, so the old window is still legal there and nothing clamps it.
      const edges = [
        ...fixtureEdges("pairAndGroupDisjoint"),
        ...fixtureEdges("secondaryPair", 10),
        ...fixtureEdges("gappedPair", 20),
      ];
      const earlier = idsOf(edges).map((id) => eventItem(numberOf(id), T0 + numberOf(id) * 1_000 - (numberOf(id) === 1 ? 1_000 : 0)));
      view.update(makeData({ items: earlier, edges, builtFor: "session:2" }));
      expect(axisLabels()).not.toEqual(before);
    });
  });

  it("starts the next chain from its own default, and so does coming back", () => {
    show(mixedData());
    const first = slider().getAttribute("aria-valuetext");
    for (let press = 0; press < 3; press += 1) fireEvent.keyDown(slider(), { key: "ArrowRight" });
    const moved = slider().getAttribute("aria-valuetext");
    expect(moved).not.toBe(first);
    fireEvent.click(rows()[1]!);
    const second = slider().getAttribute("aria-valuetext");
    expect(second).not.toBe(moved);
    fireEvent.click(rows()[0]!);
    expect(slider().getAttribute("aria-valuetext")).toBe(first);
  });

  it("keeps the band, in absolute time, through a live rebuild of the same chain", () => {
    const view = show(mixedData());
    for (let press = 0; press < 3; press += 1) fireEvent.keyDown(slider(), { key: "ArrowRight" });
    const moved = slider().getAttribute("aria-valuetext");
    view.update(mixedData({ builtFor: "session:2" }));
    expect(slider().getAttribute("aria-valuetext")).toBe(moved);
  });

  it("writes nothing to the time range, whatever is done on the band", () => {
    const original = useEvtxStore.getState().setTimeRange;
    const spy = vi.fn(original);
    useEvtxStore.setState({ setTimeRange: spy as typeof original });
    try {
      show(mixedData());
      for (const key of ["ArrowRight", "ArrowLeft", "Home", "Escape"]) fireEvent.keyDown(slider(), { key });
      expect(spy).not.toHaveBeenCalled();
    } finally {
      useEvtxStore.setState({ setTimeRange: original });
    }
  });

  it("is untouched by the unplaced items, which are never positioned on any timeline", () => {
    const without = show(mixedData());
    const barsWithout = Array.from(document.querySelectorAll("[data-bar]")).map((bar) => bar.outerHTML);
    const markersWithout = Array.from(document.querySelectorAll("[data-marker]")).map((marker) => marker.getAttribute("data-marker"));
    without.unmount();
    show(mixedData({ unplacedList: { items: unplacedItems(5), total: 5 } }));
    expect(Array.from(document.querySelectorAll("[data-bar]")).map((bar) => bar.outerHTML)).toEqual(barsWithout);
    expect(Array.from(document.querySelectorAll("[data-marker]")).map((marker) => marker.getAttribute("data-marker"))).toEqual(markersWithout);
    expect(screen.getByTestId("lane-plot").textContent).not.toMatch(/IntuneManagementExtension/);
  });
});

describe("the Not placed option (spec 8.11, 8.11a)", () => {
  const options = () => screen.getAllByRole("option");
  const notPlaced = () => document.querySelector("[data-unplaced-option]") as HTMLElement;

  it("is the last option of the same listbox, labelled from the engine's count", () => {
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    const all = options();
    expect(all[all.length - 1]).toBe(notPlaced());
    expect(notPlaced()).toHaveAccessibleName(
      "Not placed (3). Text-log lines without timestamps are listed, never guessed onto the timeline.",
    );
    expect(screen.getByRole("listbox")).toContainElement(notPlaced());
    expect(screen.getByRole("listbox")).toHaveAccessibleName(
      "Correlation chains, strongest first, and items that are not placed",
    );
  });

  it("has no row for a session that counted none", () => {
    show(mixedData());
    expect(notPlaced()).toBeNull();
    expect(screen.getByRole("listbox")).toHaveAccessibleName("Correlation chains, strongest first");
  });

  it("labels an unknown count as unknown, never as 0, even with nothing listed", () => {
    show(mixedData({ unplacedList: { items: [], total: null } }));
    expect(notPlaced()).toHaveTextContent("Not placed (count unknown)");
    expect(notPlaced().textContent).not.toMatch(/\b0\b/);
  });

  it("uses the count, not the preview's length, and the neutral caption for a partial list", () => {
    show(mixedData({ unplacedList: { items: unplacedItems(100), total: 5_000 } }));
    expect(notPlaced()).toHaveTextContent("Not placed (5,000)");
    expect(notPlaced()).toHaveTextContent("Entries without timestamps are listed, never guessed onto the timeline.");
  });

  it("is there when the session has no chain at all", () => {
    show(makeData({ items: [], edges: [], totalEdges: 0, unplacedList: { items: unplacedItems(2), total: 2 } }));
    expect(screen.getByTestId("correlation-view")).toHaveTextContent("No correlation chains were found in this session.");
    expect(options()).toHaveLength(1);
    expect(notPlaced()).toHaveTextContent("Not placed (2)");
  });

  it("is there in the counts-only stage, before any entry is read", () => {
    show(pairData({ hasItems: false, stage: "edgesOnly", unplacedList: { items: unplacedItems(4), total: 4 } }));
    expect(notPlaced()).toHaveTextContent("Not placed (4)");
  });

  it("is reached by the arrow keys, Home and End, and selecting it replaces the detail with the list", () => {
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    const listbox = screen.getByRole("listbox");
    const chainCount = options().length - 1;
    fireEvent.keyDown(listbox, { key: "End" });
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
    expect(notPlaced()).toHaveAttribute("aria-selected", "true");
    expect(listbox.getAttribute("aria-activedescendant")).toBe(notPlaced().id);
    expect(options().filter((row) => row.getAttribute("aria-selected") === "true")).toHaveLength(1);
    // The detail is the list: no chain header, no overview, no plot, no cards.
    expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
    expect(screen.queryByTestId("lane-plot")).toBeNull();
    expect(screen.queryByTestId("correlation-overview")).toBeNull();
    expect(screen.queryByRole("heading", { name: /Why these are linked|Sequence/ })).toBeNull();
    // ArrowDown at the end stays; ArrowUp returns to the last chain, closing the pane.
    fireEvent.keyDown(listbox, { key: "ArrowDown" });
    expect(notPlaced()).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(listbox, { key: "ArrowUp" });
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(false);
    expect(options()[chainCount - 1]).toHaveAttribute("aria-selected", "true");
    expect(screen.getByTestId("lane-plot")).toBeInTheDocument();
    fireEvent.keyDown(listbox, { key: "Home" });
    expect(options()[0]).toHaveAttribute("aria-selected", "true");
  });

  it("is selected by a click, and a chain click leaves it", () => {
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    fireEvent.click(notPlaced());
    expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
    fireEvent.click(options()[0]!);
    expect(screen.queryByTestId("unplaced-pane")).toBeNull();
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(false);
  });

  it("stays open when 'Review unplaced lines' opens it before any chain is selected (the reconcile does not call selectChain)", () => {
    useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
    // No chain was chosen for the operator, who asked for this pane.
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBeNull();
    expect(notPlaced()).toHaveAttribute("aria-selected", "true");
  });

  it("leaves the pane for a chain, and says so once, when nothing is left to list", () => {
    vi.useFakeTimers();
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    const view = show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
    view.update(mixedData({ unplacedList: { items: [], total: 0 }, builtFor: "session:2" }));
    expect(screen.queryByTestId("unplaced-pane")).toBeNull();
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(false);
    expect(notPlaced()).toBeNull();
    act(() => {
      vi.advanceTimersByTime(CORRELATION_ANNOUNCE_MS + 100);
    });
    expect(announcer().textContent).toContain("Nothing is listed under Not placed any more, showing a chain");
  });

  it("keeps showing the model's own list while a newer session is rebuilt", () => {
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 }, updating: true, builtFor: "old:1" }));
    expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
  });

  it("holds exactly two status regions with the pane open, and its replies use the action region", async () => {
    vi.mocked(writeText).mockResolvedValue(undefined);
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    const regions = () => screen.getAllByRole("status").map((node) => node.getAttribute("data-testid")).sort();
    expect(regions()).toEqual(["correlation-action-status", "correlation-announcer"]);
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(status()).toHaveTextContent("Copied the unplaced list as text."));
    expect(announcer().textContent).not.toContain("Copied");
    expect(regions()).toEqual(["correlation-action-status", "correlation-announcer"]);
  });

  it("copies nothing from the pane while the data is updating, as the chain's Copy does not either", () => {
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 }, updating: true, builtFor: "old:1" }));
    const paneCopy = screen.getByRole("button", { name: "Copy as text" });
    expect(paneCopy).toHaveAttribute("aria-disabled", "true");
    expect(paneCopy).toHaveAttribute("title", "Wait for the update to finish.");
    fireEvent.click(paneCopy);
    expect(vi.mocked(writeText)).not.toHaveBeenCalled();
    cleanup();
    useEvtxCorrelationStore.setState({ unplacedOpen: false });
    show(mixedData({ updating: true, builtFor: "old:1" }));
    const chainCopy = screen.getByRole("button", { name: "Copy as text" });
    expect(chainCopy).toHaveAttribute("aria-disabled", "true");
    expect(chainCopy).toHaveAttribute("title", paneCopy.getAttribute("title"));
  });

  it("reports a failed copy from the pane as an alert, with no third status", async () => {
    vi.mocked(writeText).mockRejectedValue(new Error("clipboard denied"));
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    fireEvent.click(screen.getByRole("button", { name: "Copy as text" }));
    await waitFor(() => expect(alertText()).toHaveTextContent("Copy failed: clipboard denied"));
    expect(screen.getAllByRole("status")).toHaveLength(2);
  });

  it("does not announce a lost chain while the pane is the thing shown", () => {
    vi.useFakeTimers();
    useEvtxCorrelationStore.setState({ selectedChainId: "a-chain-that-is-gone", unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    act(() => {
      vi.advanceTimersByTime(CORRELATION_ANNOUNCE_MS + 100);
    });
    expect(announcer().textContent).not.toContain("no longer present");
    expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
  });

  it("holds exactly two status regions with the pane open and no chain at all", () => {
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    show(makeData({ items: [], edges: [], totalEdges: 0, unplacedList: { items: unplacedItems(2), total: 2 } }));
    expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
    expect(screen.getAllByRole("status").map((node) => node.getAttribute("data-testid")).sort()).toEqual([
      "correlation-action-status",
      "correlation-announcer",
    ]);
  });

  it("spends Escape in the pane and returns focus to the list, never reaching the time range", () => {
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    const copy = screen.getByRole("button", { name: "Copy as text" });
    expect(fireEvent.keyDown(copy, { key: "Escape" })).toBe(false);
    expect(document.activeElement).toBe(screen.getByRole("listbox"));
  });

  it("does not build the plot while the pane is shown, and builds it for a chain", () => {
    useEvtxCorrelationStore.setState({ unplacedOpen: true });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    expect(document.querySelectorAll("[data-marker]")).toHaveLength(0);
    expect(plotBuilds).not.toHaveBeenCalled();
    cleanup();
    useEvtxCorrelationStore.setState({ unplacedOpen: false });
    show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
    expect(plotBuilds).toHaveBeenCalled();
  });
});

describe("a lost selection is an event, said once and by what exists (the sticky flags of #840 review F1)", () => {
  const NOTHING_LISTED = "Nothing is listed under Not placed any more";
  const CHAIN_GONE = "The selected chain is no longer present";
  const settle = () =>
    act(() => {
      vi.advanceTimersByTime(CORRELATION_ANNOUNCE_MS + 100);
    });
  /** No chain at all in the session, so no selection can be shown. */
  const zeroChains = (extra: Partial<DataOptions> = {}) =>
    makeData({ items: [], edges: [], totalEdges: 0, ...extra });
  const none = { items: [], total: 0 };
  const three = () => ({ items: unplacedItems(3), total: 3 });
  const spokenCount = (heard: string[], sentence: string) => heard.filter((text) => text.includes(sentence)).length;

  describe("the Not placed pane that is left", () => {
    it("names no chain when there are none, and is said once, not again after a later model or update", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ unplacedOpen: true });
      const view = show(zeroChains({ unplacedList: three() }));
      const heard: string[] = [];
      view.update(zeroChains({ unplacedList: none, builtFor: "session:2" }));
      settle();
      heard.push(announcer().textContent ?? "");
      expect(announcer().textContent).toContain(NOTHING_LISTED);
      expect(announcer().textContent).not.toMatch(/showing/);
      view.update(zeroChains({ unplacedList: none, builtFor: "session:3" }));
      settle();
      heard.push(announcer().textContent ?? "");
      view.update(zeroChains({ unplacedList: none, builtFor: "session:3", updating: true }));
      settle();
      heard.push(announcer().textContent ?? "");
      view.update(zeroChains({ unplacedList: none, builtFor: "session:4" }));
      settle();
      heard.push(announcer().textContent ?? "");
      expect(spokenCount(heard, NOTHING_LISTED)).toBe(1);
      expect(announcer().textContent).not.toContain(NOTHING_LISTED);
    });

    it("says a chain is shown only when one is", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ unplacedOpen: true });
      const view = show(mixedData({ unplacedList: three() }));
      view.update(mixedData({ unplacedList: none, builtFor: "session:2" }));
      settle();
      expect(announcer().textContent).toContain(`${NOTHING_LISTED}, showing a chain`);
    });

    it("is gone when the rail's Review unplaced lines shows the pane again", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ unplacedOpen: true });
      const view = show(mixedData({ unplacedList: three() }));
      // The list goes (the sentence is waiting for the region), and a later session lists items again.
      view.update(mixedData({ unplacedList: none, builtFor: "session:2" }));
      view.update(mixedData({ unplacedList: { items: unplacedItems(2), total: 2 }, builtFor: "session:3" }));
      act(() => openUnplacedList());
      settle();
      expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
      expect(announcer().textContent).not.toContain(NOTHING_LISTED);
      // Leaving the pane by another route does not bring it back.
      act(() => useEvtxCorrelationStore.getState().selectChain(null));
      settle();
      expect(announcer().textContent).not.toContain(NOTHING_LISTED);
    });

    it("is gone when a later session lists items again before anything is picked", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ unplacedOpen: true });
      const view = show(mixedData({ unplacedList: three() }));
      view.update(mixedData({ unplacedList: none, builtFor: "session:2" }));
      view.update(mixedData({ unplacedList: { items: unplacedItems(2), total: 2 }, builtFor: "session:3" }));
      settle();
      expect(document.querySelector("[data-unplaced-option]")).not.toBeNull();
      expect(announcer().textContent).not.toContain(NOTHING_LISTED);
    });

    it("does not come back when the items go away again with the pane closed", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ unplacedOpen: true });
      const view = show(mixedData({ unplacedList: three() }));
      view.update(mixedData({ unplacedList: none, builtFor: "session:2" }));
      view.update(mixedData({ unplacedList: { items: unplacedItems(2), total: 2 }, builtFor: "session:3" }));
      view.update(mixedData({ unplacedList: none, builtFor: "session:4" }));
      settle();
      // The pane was not open when the items went the second time, so nothing was lost.
      expect(announcer().textContent).not.toContain(NOTHING_LISTED);
    });
  });

  describe("the receipt: said by a publication made after the record, never by an earlier one", () => {
    const ZERO = "The selected chain is no longer present";
    const SHOWN = `${ZERO}, showing another`;
    /** Time passes in quarter seconds; every distinct text the region holds is kept, in order. */
    const heard: string[] = [];
    const hear = () => {
      const text = announcer().textContent ?? "";
      if (heard[heard.length - 1] !== text) heard.push(text);
    };
    const advance = (ms: number) => {
      for (let elapsed = 0; elapsed < ms; elapsed += 250) {
        act(() => {
          vi.advanceTimersByTime(250);
        });
        hear();
      }
    };
    const saidCount = (sentence: string) => heard.filter((text) => text.includes(sentence)).length;
    /** One secondary pair only: a model that does not hold the mixed model's first chain. */
    const secondaryOnly = (extra: Partial<DataOptions> = {}) => {
      const edges = fixtureEdges("secondaryPair", 10);
      return makeData({
        items: idsOf(edges).map((id) => eventItem(numberOf(id), T0 + numberOf(id) * 1_000)),
        edges,
        ...extra,
      });
    };
    beforeEach(() => {
      heard.length = 0;
    });

    it("speaks a second loss of the same kind recorded inside the window after the first was published", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone-1" });
      const view = show(mixedData());
      hear();
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard[heard.length - 1]).toBe(`4 chains. ${SHOWN}`);
      // The next tail rebuild drops the chain the operator was moved to, before the first publication is replaced.
      view.update(secondaryOnly({ builtFor: "session:2" }));
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard).toContain(`1 chain. ${SHOWN}`);
      expect(saidCount(SHOWN)).toBe(2);
      // Each is said once: a later model and an update do not say either again.
      view.update(secondaryOnly({ builtFor: "session:3", updating: true }));
      advance(CORRELATION_ANNOUNCE_MS + 100);
      view.update(secondaryOnly({ builtFor: "session:4" }));
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(saidCount(SHOWN)).toBe(2);
      expect(announcer().textContent).not.toContain(ZERO);
    });

    it("speaks a zero-chain loss after a chain-shown one of the same kind, whose sentence contains it", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone-1" });
      const view = show(mixedData());
      hear();
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard[heard.length - 1]).toBe(`4 chains. ${SHOWN}`);
      // The operator's selection goes again, and now there is no chain at all.
      act(() => {
        useEvtxCorrelationStore.setState({ selectedChainId: "gone-2" });
        view.update(makeData({ items: [], edges: [], totalEdges: 0, builtFor: "session:2" }));
      });
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard).toContain(`0 chains. ${ZERO}`);
      expect(saidCount(SHOWN)).toBe(1);
      expect(saidCount(ZERO)).toBe(2);
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(announcer().textContent).not.toContain(ZERO);
    });

    it("speaks a chain-shown loss after a zero-chain one of the same kind", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone-1" });
      const view = show(makeData({ items: [], edges: [], totalEdges: 0 }));
      hear();
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard[heard.length - 1]).toBe(`0 chains. ${ZERO}`);
      act(() => {
        useEvtxCorrelationStore.setState({ selectedChainId: "gone-2" });
        view.update(mixedData({ builtFor: "session:2" }));
      });
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard).toContain(`4 chains. ${SHOWN}`);
      expect(saidCount(SHOWN)).toBe(1);
    });

    it("speaks a second Not placed loss recorded inside the window after the first was published", () => {
      vi.useFakeTimers();
      const NOTHING = "Nothing is listed under Not placed any more, showing a chain";
      useEvtxCorrelationStore.setState({ unplacedOpen: true });
      const view = show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
      view.update(mixedData({ unplacedList: { items: [], total: 0 }, builtFor: "session:2" }));
      hear();
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard[heard.length - 1]).toBe(`4 chains. ${NOTHING}`);
      // Items are listed again and the operator opens the pane from the rail; then they go again.
      view.update(mixedData({ unplacedList: { items: unplacedItems(2), total: 2 }, builtFor: "session:3" }));
      act(() => openUnplacedList());
      expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
      view.update(secondaryOnly({ unplacedList: { items: [], total: 0 }, builtFor: "session:4" }));
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard).toContain(`1 chain. ${NOTHING}`);
      expect(heard.filter((text) => text.includes(NOTHING))).toHaveLength(2);
    });

    it("says it once when the announcement changes in the same step as the publication that carries it", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone-1" });
      const view = show(mixedData());
      hear();
      advance(CORRELATION_ANNOUNCE_MS - 250);
      expect(announcer().textContent).toBe("4 chains");
      // The timer fires and the data starts updating in one step, so the announcement composed with the
      // sentence is no longer the text that was published. The publication still said it.
      act(() => {
        vi.advanceTimersByTime(300);
        view.update(mixedData({ builtFor: "session:2", updating: true }));
      });
      hear();
      expect(heard).toContain(`4 chains. ${SHOWN}`);
      advance(3 * (CORRELATION_ANNOUNCE_MS + 100));
      expect(saidCount(SHOWN)).toBe(1);
    });

    // Every branch of the announcement that is composed WITHOUT the sentence while a loss is true: no
    // model, in its three texts. The region then holds text that never carries the sentence, so the
    // loss stays unsaid until the first later publication that does.
    it.each([
      ["no analysis", () => UNAVAILABLE_CORRELATION, "No event analysis is available. Load events to see correlation."],
      [
        "the edges being read",
        () => ({ ...UNAVAILABLE_CORRELATION, stage: "pending" as const }),
        "Reading correlation edges...",
      ],
      ["a failure with no model", () => ({ ...UNAVAILABLE_CORRELATION, stage: "pending" as const, error: "boom" }), ""],
    ])("is still spoken when the model goes away inside the window and a session returns: %s", (_name, noModel, held) => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone-1" });
      const view = show(mixedData());
      hear();
      advance(1_000);
      // The end of the data, before the sentence was published: the region publishes the no-model text.
      view.update(noModel());
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(announcer().textContent).toBe(held);
      expect(saidCount(SHOWN)).toBe(0);
      // A session returns with the replacement shown. No new loss is recorded: the first is still unsaid.
      view.update(mixedData({ builtFor: "session:2" }));
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard).toContain(`4 chains. ${SHOWN}`);
      expect(saidCount(SHOWN)).toBe(1);
      // Said once: nothing later says it again.
      view.update(mixedData({ builtFor: "session:3", updating: true }));
      advance(2 * (CORRELATION_ANNOUNCE_MS + 100));
      expect(saidCount(SHOWN)).toBe(1);
      expect(announcer().textContent).not.toContain(ZERO);
    });

    it("speaks a Not placed loss too when the model goes away inside the window", () => {
      vi.useFakeTimers();
      const NOTHING = "Nothing is listed under Not placed any more, showing a chain";
      useEvtxCorrelationStore.setState({ unplacedOpen: true });
      const view = show(mixedData({ unplacedList: { items: unplacedItems(3), total: 3 } }));
      view.update(mixedData({ unplacedList: { items: [], total: 0 }, builtFor: "session:2" }));
      hear();
      advance(1_000);
      view.update(UNAVAILABLE_CORRELATION);
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard.filter((text) => text.includes(NOTHING))).toHaveLength(0);
      view.update(mixedData({ unplacedList: { items: [], total: 0 }, builtFor: "session:3" }));
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard).toContain(`4 chains. ${NOTHING}`);
      expect(heard.filter((text) => text.includes(NOTHING))).toHaveLength(1);
    });

    it("counts an announcement identical to what the region holds as said, and does not publish it again", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone-1" });
      show(mixedData());
      hear();
      advance(CORRELATION_ANNOUNCE_MS + 100);
      expect(heard[heard.length - 1]).toBe(`4 chains. ${SHOWN}`);
      // A second loss of the same kind in the same model composes exactly the text the region holds.
      act(() => useEvtxCorrelationStore.setState({ selectedChainId: "gone-2" }));
      hear();
      expect(announcer().textContent).toBe(`4 chains. ${SHOWN}`);
      advance(2 * (CORRELATION_ANNOUNCE_MS + 100));
      // The region held the sentence once, then dropped it. It did not stay in every later announcement,
      // and it was not published a second time.
      expect(heard).toEqual(["4 chains", `4 chains. ${SHOWN}`, "4 chains"]);
    });
  });

  describe("the chain that was selected", () => {
    const notice = () => screen.queryByTestId("correlation-notices")?.textContent ?? "";
    const GONE_VISIBLE = "The chain that was selected is no longer present.";

    it("names no other chain when there are none, and is said once, not again after a later model or update", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone" });
      const view = show(zeroChains({ unplacedList: none }));
      const heard: string[] = [];
      settle();
      heard.push(announcer().textContent ?? "");
      expect(announcer().textContent).toContain(CHAIN_GONE);
      expect(announcer().textContent).not.toMatch(/showing|another/i);
      expect(notice()).toContain(GONE_VISIBLE);
      expect(notice()).not.toMatch(/another/i);
      view.update(zeroChains({ unplacedList: none, builtFor: "session:2" }));
      settle();
      heard.push(announcer().textContent ?? "");
      view.update(zeroChains({ unplacedList: none, builtFor: "session:2", updating: true }));
      settle();
      heard.push(announcer().textContent ?? "");
      view.update(zeroChains({ unplacedList: none, builtFor: "session:3" }));
      settle();
      heard.push(announcer().textContent ?? "");
      expect(spokenCount(heard, CHAIN_GONE)).toBe(1);
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
    });

    it("says another chain is shown when one is, and says it once", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone" });
      const view = show(mixedData());
      settle();
      expect(announcer().textContent).toContain(`${CHAIN_GONE}, showing another`);
      expect(notice()).toContain(`${GONE_VISIBLE} Another chain is shown.`);
      view.update(mixedData({ builtFor: "session:2" }));
      settle();
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
      view.update(mixedData({ builtFor: "session:2", updating: true }));
      settle();
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
    });

    it("is gone when the rail's Review unplaced lines shows the pane", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone" });
      show(mixedData({ unplacedList: three() }));
      act(() => openUnplacedList());
      settle();
      expect(screen.getByTestId("unplaced-pane")).toBeInTheDocument();
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
      expect(document.body.textContent).not.toContain(GONE_VISIBLE);
      // And leaving the pane by another route does not bring it back.
      act(() => useEvtxCorrelationStore.getState().selectChain(null));
      settle();
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
      expect(document.body.textContent).not.toContain(GONE_VISIBLE);
    });

    it("is dropped by a pick of a chain or of Not placed, before it was spoken", () => {
      vi.useFakeTimers();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone" });
      const view = show(mixedData({ unplacedList: three() }));
      expect(notice()).toContain(GONE_VISIBLE);
      fireEvent.click(rows()[1]!);
      settle();
      expect(notice()).not.toContain(GONE_VISIBLE);
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
      view.unmount();
      cleanup();
      useEvtxCorrelationStore.setState({ selectedChainId: "gone", unplacedOpen: false });
      show(mixedData({ unplacedList: three() }));
      expect(notice()).toContain(GONE_VISIBLE);
      fireEvent.click(document.querySelector("[data-unplaced-option]")!);
      settle();
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
      expect(document.body.textContent).not.toContain(GONE_VISIBLE);
    });

    it("is gone when a later session has the chain again", () => {
      vi.useFakeTimers();
      const later = mixedData();
      const returning = later.model!.chains[1]!.id;
      useEvtxCorrelationStore.setState({ selectedChainId: returning });
      const view = show(pairData());
      expect(notice()).toContain(GONE_VISIBLE);
      view.update(later);
      settle();
      expect(announcer().textContent).not.toContain(CHAIN_GONE);
      expect(notice()).not.toContain(GONE_VISIBLE);
    });
  });
});

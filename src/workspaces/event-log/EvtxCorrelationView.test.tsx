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

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import EvtxCorrelationView, {
  CORRELATION_ANNOUNCE_MS,
  scopeFailureText,
  type CorrelationSessionScope,
} from "./EvtxCorrelationView";
import viewSource from "./EvtxCorrelationView.tsx?raw";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
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
import type { EvtxRecord } from "./types";
import type { TimelineCorrelationEdge, TimelineItem } from "./unified-timeline";

const NO_UNPROVEN_CLAIM = /not placed|no timeline position|without a timeline position|no timestamp/i;

const SCOPE: CorrelationSessionScope = { visibleCount: 9, loadedCount: 9, textLogCount: 0 };

function show(
  data: EvtxCorrelationData,
  sessionScope: (builtFor: string | null) => CorrelationSessionScope | null = () => SCOPE,
  nearby?: readonly TimelineItem[],
) {
  const view = (value: EvtxCorrelationData) => (
    <EvtxCorrelationProvider value={value}>
      <EvtxCorrelationView sessionScope={sessionScope} nearby={nearby} />
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
  useEvtxCorrelationStore.setState({ selectedChainId: null });
  useEvtxLayoutStore.setState({ activeView: "correlation" });
  seedStore();
  vi.mocked(writeText).mockReset();
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
    show(data(), () => SCOPE, [stray()]);
    expect(strayName()).toContain("Not linked");
    expect(screen.getByRole("group", { name: "Legend" })).toHaveTextContent("not linked (no line)");
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(1);
  });

  it.each([
    ["edges were not all loaded", () => data({ totalEdges: 8 }), () => SCOPE],
    ["the view is narrowed", () => data(), () => ({ visibleCount: 3, loadedCount: 9, textLogCount: 0 })],
    ["the scope of the model is not known", () => data(), () => null],
    ["the engine limited correlation", () => data({ gaps: classifyCoverageGaps([{ source: "correlation", reason: "x" }], 1) }), () => SCOPE],
    ["a gap names the entry's own origin", () => data({ gaps: classifyCoverageGaps([{ source: rid(9), reason: "x" }], 1) }), () => SCOPE],
    ["a gap names a member of the chain", () => data({ gaps: classifyCoverageGaps([{ source: rid(1), reason: "alias" }], 1) }), () => SCOPE],
  ])("says 'No loaded link' instead when %s", (_why, makeDataFor, scopeFor) => {
    show(makeDataFor(), scopeFor, [stray()]);
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
    show(pairData(), () => ({ visibleCount: 3, loadedCount: 9, textLogCount: 4 }));
    const text = screen.getByTestId("correlation-notices").textContent ?? "";
    expect(text).toContain("Links and strengths are computed over the 3 events visible. Events outside the view can make an Exact link ambiguous.");
    expect(text).toContain("Text logs are not scoped.");
  });

  it("leaves out the text-log line when there are none, and both lines when nothing is narrowed", () => {
    show(pairData(), () => ({ visibleCount: 3, loadedCount: 9, textLogCount: 0 }));
    expect(screen.getByTestId("correlation-notices").textContent).not.toContain("Text logs are not scoped.");
    cleanup();
    show(pairData(), () => ({ visibleCount: 9, loadedCount: 9, textLogCount: 4 }));
    expect(screen.queryByTestId("correlation-notices")).toBeNull();
  });

  it("reads the scope of the session the model was built for, not the newest one", () => {
    const seen: (string | null)[] = [];
    show(pairData({ builtFor: "old:3" }), (builtFor) => {
      seen.push(builtFor);
      return builtFor === "old:3" ? { visibleCount: 2, loadedCount: 9, textLogCount: 0 } : null;
    });
    expect(new Set(seen)).toEqual(new Set(["old:3"]));
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent("computed over the 2 events visible");
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
    // A connector exists only where the table shows a row for both its endpoints.
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
    show(pairData({ totalEdges: 30 }), () => ({ visibleCount: 3, loadedCount: 9, textLogCount: 0 }));
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
    const seen: (string | null)[] = [];
    show(pairData({ builtFor: "old:1", updating: true, nextScan: { state: "running", progress: { scannedItems: 500, totalItems: 2000, retainedItems: 10 }, stoppedBy: null, error: null } }), (builtFor) => {
      seen.push(builtFor);
      return { visibleCount: 2, loadedCount: 2, textLogCount: 0 };
    });
    expect(screen.getByTestId("correlation-updating")).toHaveTextContent("Updating correlation...");
    expect(screen.getByTestId("correlation-updating")).toHaveTextContent("Reading 500 of 2,000 timeline items...");
    expect(screen.getByTestId("correlation-view")).toHaveAttribute("aria-busy", "true");
    expect(rows()).toHaveLength(1);
    expect(new Set(seen)).toEqual(new Set(["old:1"]));
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
 * painted element is pinned to the same token.
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
      show(mixedData());
      const unselected = rows().find((row) => row.getAttribute("aria-selected") === "false")!;
      expect(unselected.querySelector<HTMLElement>("[data-strength-badge]")!.style.backgroundColor).not.toBe("");
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

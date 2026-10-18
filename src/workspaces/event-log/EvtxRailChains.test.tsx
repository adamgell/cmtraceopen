/**
 * The rail's Chains tab (spec 8.13, #841) as the rail mounts it: the rows, the steps, the legend, the
 * nearby group, the Not placed card, the empty states and the actions. Every decision is
 * `buildRailChains`'s and is tested in evtx-rail-chains-model.test.ts; this file protects that the
 * tab draws what it is given, that its two actions go through the shared actions (and so move focus
 * and clear the view's loss record), that it speaks no live region, and that it is the same list the
 * Correlation view shows. Real chain models are built with `makeData`.
 */
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { tokens } from "@fluentui/react-components";
import { MAX_LOG_LIST_FONT_SIZE, MIN_LOG_LIST_FONT_SIZE } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import EvtxCorrelationView from "./EvtxCorrelationView";
import EvtxRailChains from "./EvtxRailChains";
import cardSource from "./EvtxRailChainCard.tsx?raw";
import tabSource from "./EvtxRailChains.tsx?raw";
import { CORRELATION_CHAIN_RENDER_LIMIT } from "./evtx-correlation-chains";
import {
  CHAIN_STEPS_NOT_READ_TEXT,
  NO_ANALYSIS_TEXT,
  NO_LINKED_EVENTS_TEXT,
  READING_EDGES_TEXT,
  SAME_TIME_NOTE,
  SEQUENCE_ORDER_NOTE,
  WAIT_FOR_ENTRIES_REASON,
} from "./evtx-correlation-copy";
import { classifyCoverageGaps } from "./evtx-correlation-gaps";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
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
import { evtxViewTabId, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import { WAIT_FOR_UPDATE_REASON } from "./evtx-unplaced";
import type { EvtxRecord } from "./types";
import { timelineOriginId, type TimelineItem, type UnplacedItem } from "./unified-timeline";
import { EvtxCorrelationProvider, UNAVAILABLE_CORRELATION, type EvtxCorrelationData } from "./useEvtxCorrelation";

const { logListFontSize: INITIAL_FONT_SIZE } = useUiStore.getState();

function show(data: EvtxCorrelationData, nearby?: readonly TimelineItem[]) {
  const tree = (value: EvtxCorrelationData) => (
    <EvtxCorrelationProvider value={value}>
      <EvtxRailChains nearby={nearby} />
    </EvtxCorrelationProvider>
  );
  const result = render(tree(data));
  return { ...result, update: (next: EvtxCorrelationData) => result.rerender(tree(next)) };
}

function seedStore(records: EvtxRecord[] = []) {
  useEvtxStore.getState().reset();
  useEvtxStore.setState({ records, isLoading: false, timeZoneMode: "utc" });
}

function itemsFor(edges: ReturnType<typeof fixtureEdges>) {
  return idsOf(edges).map((id) => eventItem(numberOf(id), T0 + numberOf(id) * 1_000));
}

/** An exact pair (1, 2), an ambiguous group of three (3 to 5), a candidate pair and a blocked pair. */
function mixed(extra: Partial<DataOptions> = {}) {
  const edges = [
    ...fixtureEdges("pairAndGroupDisjoint"),
    ...fixtureEdges("secondaryPair", 10),
    ...fixtureEdges("gappedPair", 20),
  ];
  return makeData({ items: itemsFor(edges), edges, ...extra });
}

function pair(extra: Partial<DataOptions> = {}) {
  return makeData({
    items: [eventItem(1, T0, "error", "first failed"), eventItem(2, T0 + 6_000, "info", "second ok")],
    edges: fixtureEdges("exactPair"),
    ...extra,
  });
}

function manyPairs(count: number, extra: Partial<DataOptions> = {}) {
  const edges = Array.from({ length: count }, (_, i) => synthetic(`e${i}`, rid(2 * i + 1), rid(2 * i + 2)));
  const items = Array.from({ length: count * 2 }, (_, i) => eventItem(i + 1, T0 + i * 1_000));
  return makeData({ items, edges, ...extra });
}

function logItem(line: number, timestampMs: number): TimelineItem {
  const file = "C:\\Logs\\AppEnforce.log";
  return {
    timestampMs,
    severity: "warning",
    message: `log line ${line}`,
    origin: { kind: "log", file, component: null, line, source: file, machine: null, bundle: null, recordId: line },
  };
}

const rowsOf = () => Array.from(document.querySelectorAll<HTMLElement>("[data-rail-chain]"));
const ids = () => rowsOf().map((row) => row.getAttribute("data-rail-chain"));
const card = (index = 0) => rowsOf()[index]!;
const armTab = (view: "table" | "correlation") => {
  const tab = document.createElement("button");
  tab.id = evtxViewTabId(view);
  document.body.appendChild(tab);
  return tab;
};

beforeEach(() => {
  localStorage.clear();
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false, openedCount: 0 });
  useEvtxLayoutStore.setState({ activeView: "table", railTab: "chains" });
  seedStore();
});
afterEach(() => {
  cleanup();
  document.body.innerHTML = "";
  vi.useRealTimers();
  useUiStore.setState({ logListFontSize: INITIAL_FONT_SIZE });
});

describe("without a model", () => {
  it("says there is no analysis when none exists, claims nothing, and draws no list", () => {
    show(UNAVAILABLE_CORRELATION);
    expect(screen.getByTestId("rail-chains")).toHaveTextContent(NO_ANALYSIS_TEXT);
    expect(screen.queryByRole("list")).toBeNull();
    expect(document.body.textContent).not.toMatch(/\b0 chains\b/);
  });

  it("says the edges are being read while a session is built, never that there is no analysis", () => {
    show({ ...UNAVAILABLE_CORRELATION, stage: "pending" });
    expect(screen.getByTestId("rail-chains")).toHaveTextContent(READING_EDGES_TEXT);
  });

  it("shows a failure that is not a load result as an alert", () => {
    show({ ...UNAVAILABLE_CORRELATION, stage: "pending", error: "boom" });
    expect(screen.getByRole("alert")).toHaveTextContent("Correlation could not be built: boom");
  });
});

describe("the rows are the Correlation view's rows", () => {
  it("lists the same chains in the same order, strongest first, as the view lists them", () => {
    const data = mixed();
    const view = render(
      <EvtxCorrelationProvider value={data}>
        <EvtxCorrelationView />
      </EvtxCorrelationProvider>,
    );
    const inView = screen.getAllByRole("option").map((option) => option.getAttribute("data-chain-id"));
    view.unmount();
    show(data);
    expect(ids()).toEqual(inView);
    expect(ids()).toEqual(data.model!.chains.map((chain) => chain.id));
  });

  it("does not re-sort what the model ordered: a card for each exact or candidate chain, then the rest", () => {
    show(mixed());
    expect(rowsOf().map((row) => row.getAttribute("data-rail-kind"))).toEqual(["card", "card", "compact", "compact"]);
    const strengths = rowsOf().map((row) => row.querySelector("[data-strength-badge]")?.getAttribute("data-strength-badge"));
    expect(strengths).toEqual(["exact", "candidate", "ambiguous", "coverageBlocked"]);
  });

  it("caps at the render limit with the view's line, and the view says the same", () => {
    const data = manyPairs(CORRELATION_CHAIN_RENDER_LIMIT + 5);
    show(data);
    expect(rowsOf()).toHaveLength(CORRELATION_CHAIN_RENDER_LIMIT);
    expect(screen.getByTestId("rail-chains-notices")).toHaveTextContent("Showing the first 100 of 105; 5 omitted.");
    cleanup();
    render(
      <EvtxCorrelationProvider value={data}>
        <EvtxCorrelationView />
      </EvtxCorrelationProvider>,
    );
    expect(screen.getByTestId("correlation-notices")).toHaveTextContent("Showing the first 100 of 105; 5 omitted.");
  });

  it("names each row as the view's option is named, and tells two untitled rows apart", () => {
    const edges = [...fixtureEdges("exactPair"), ...fixtureEdges("exactPair", 10)];
    show(makeData({ items: [], edges, hasItems: false, stage: "edgesOnly" }));
    const names = rowsOf().map((row) => row.getAttribute("aria-label"));
    expect(new Set(names).size).toBe(2);
    expect(names.every((name) => name!.startsWith("Exact, Untitled chain "))).toBe(true);
  });
});

describe("a card", () => {
  it("shows the badge, the span, the title and the key", () => {
    show(pair());
    const one = card();
    expect(within(one).getByText("Exact")).toBeInTheDocument();
    expect(one.querySelector('[data-rail-part="title"]')).toHaveTextContent("101 \u00b7 first failed");
    expect(one.querySelector('[data-rail-part="span"]')).toHaveTextContent(/^10:20:00.10:20:06$/);
    expect(one.querySelector('[data-rail-part="key"]')).toHaveTextContent(/^key: ActivityId /);
  });

  it("lists the steps in time order with the clock, the level, the kind chip and the message", () => {
    const line = logItem(9, T0 + 3_000);
    const items = [eventItem(1, T0, "error", "first failed"), line, eventItem(3, T0 + 6_000, "info", "last ok")];
    const edges = [synthetic("e1", rid(1), timelineOriginId(line.origin)), synthetic("e2", timelineOriginId(line.origin), rid(3))];
    show(makeData({ items, edges }));
    const steps = Array.from(card().querySelectorAll<HTMLElement>("[data-step]"));
    expect(steps.map((step) => step.querySelector('[data-step-part="time"]')!.textContent)).toEqual([
      "10:20:00",
      "10:20:03",
      "10:20:06",
    ]);
    expect(steps.map((step) => step.querySelector('[data-step-part="message"]')!.textContent)).toEqual([
      "first failed",
      "log line 9",
      "last ok",
    ]);
    expect(steps.map((step) => step.querySelector("[data-chip]")!.getAttribute("data-chip"))).toEqual(["EVT", "LOG", "EVT"]);
    expect(steps.map((step) => step.querySelector('[data-step-part="dot"]')!.getAttribute("aria-label"))).toEqual([
      "Error",
      "Warning",
      "Information",
    ]);
    expect(within(steps[1]!).getByRole("img", { name: "Text log line" })).toBeInTheDocument();
    expect(within(steps[0]!).getByRole("img", { name: "Windows event" })).toBeInTheDocument();
    // Never the words themselves outside the chip: the step's own text carries none.
    expect(steps[0]!.querySelector('[data-step-part="message"]')!.textContent).not.toMatch(/EVT|LOG/);
  });

  it("collapses further steps into '+n more', and lists exactly six", () => {
    const ids9 = Array.from({ length: 9 }, (_, i) => i + 1);
    const edges = ids9.slice(1).map((n) => synthetic(`e${n}`, rid(n - 1), rid(n)));
    show(makeData({ items: ids9.map((n) => eventItem(n, T0 + n * 1_000)), edges }));
    expect(card().querySelectorAll("[data-step]")).toHaveLength(6);
    expect(card().querySelector('[data-rail-part="more"]')).toHaveTextContent("+3 more");
  });

  it("says the order is not evidence of cause once, and marks an entry at the same instant as the one above", () => {
    show(makeData({ items: [eventItem(1, T0), eventItem(2, T0)], edges: fixtureEdges("exactPair") }));
    expect(screen.getAllByText(SEQUENCE_ORDER_NOTE)).toHaveLength(1);
    expect(card().textContent).toContain(SAME_TIME_NOTE);
    const withoutTheNote = screen.getByTestId("rail-chains").textContent!.replace(SEQUENCE_ORDER_NOTE, "");
    expect(withoutTheNote).not.toMatch(/\bcaus|\bfollow|\blead/i);
  });

  it("lists a message in full in its tooltip, however long", () => {
    const long = "x".repeat(300);
    show(makeData({ items: [eventItem(1, T0, "error", long), eventItem(2, T0 + 1_000)], edges: fixtureEdges("exactPair") }));
    expect(card().querySelector('[data-step-part="message"]')).toHaveAttribute("title", long);
  });

  it("without the entries has no steps and says why", () => {
    show(pair({ hasItems: false, stage: "edgesOnly" }));
    expect(card().querySelector("ol")).toBeNull();
    expect(card().querySelector('[data-rail-part="steps-text"]')).toHaveTextContent(CHAIN_STEPS_NOT_READ_TEXT);
    expect(card().querySelector('[data-rail-part="title"]')).toHaveTextContent("Untitled chain");
  });

  it("explains members that are not listed as steps, without claiming they have no timestamp unless proven", () => {
    show(makeData({ items: [eventItem(1, T0)], edges: fixtureEdges("exactPair") }));
    expect(card().querySelector('[data-rail-part="partial"]')).toHaveTextContent(
      "1 of 2 entries have no loaded timeline position, so they are not listed as steps.",
    );
    expect(document.body.textContent).not.toMatch(/no timestamp|not placed/i);
  });
});

describe("a compact row", () => {
  it("has a badge, a title, a span and the reason it is not a link, and no steps and no Show in table", () => {
    show(mixed());
    const compact = rowsOf().filter((row) => row.getAttribute("data-rail-kind") === "compact");
    expect(compact).toHaveLength(2);
    for (const row of compact) {
      expect(row.querySelector("ol")).toBeNull();
      expect(row.querySelector("[data-step]")).toBeNull();
      expect(within(row).queryByRole("button", { name: /^Show in table/ })).toBeNull();
      expect(row.querySelector('[data-rail-part="description"]')).not.toBeNull();
      expect(within(row).getByRole("button", { name: /^Open in correlation view: / })).toBeInTheDocument();
    }
    expect(compact[0]!.querySelector('[data-rail-part="description"]')!.textContent).toMatch(/no single link/);
    expect(compact[1]!.querySelector('[data-rail-part="description"]')!.textContent).toMatch(/coverage gap stops a link/);
  });

  it("draws no connector, anywhere, for a row that is not a link", () => {
    show(mixed());
    expect(document.querySelectorAll("line[data-connector]")).toHaveLength(0);
    const compact = rowsOf().filter((row) => row.getAttribute("data-rail-kind") === "compact");
    for (const row of compact) expect(row.querySelector("line")).toBeNull();
  });
});

describe("the legend", () => {
  it("names exact and candidate in the spec's words, with a solid and a dashed line", () => {
    show(mixed());
    const legend = screen.getByRole("group", { name: "Legend" });
    expect(within(legend).getByText("Exact match")).toBeInTheDocument();
    expect(within(legend).getByText("Candidate identity")).toBeInTheDocument();
    const lines = legend.querySelectorAll("line");
    expect(lines).toHaveLength(2);
    expect(lines[0]!.getAttribute("stroke-dasharray")).toBeNull();
    expect(lines[1]!.getAttribute("stroke-dasharray")).toBe("5 4");
    expect(legend.textContent).not.toMatch(/not linked|no loaded link/i);
    // And no dotted swatch either: the entry is the swatch and its word together.
    const dotted = Array.from(legend.querySelectorAll<HTMLElement>("span[aria-hidden='true']")).filter((node) =>
      node.style.border.includes("dotted"),
    );
    expect(dotted).toHaveLength(0);
    expect(legend.children).toHaveLength(2);
  });

  it("adds the dotted entry only when a nearby entry is listed, in the word the session can say", () => {
    const stray = eventItem(8, T0 + 2_000);
    show(pair(), [stray]);
    const legend = screen.getByRole("group", { name: "Legend" });
    expect(within(legend).getByText("Not linked")).toBeInTheDocument();
    const swatch = Array.from(legend.querySelectorAll<HTMLElement>("span[aria-hidden='true']")).find((node) =>
      node.style.border.includes("dotted"),
    );
    expect(swatch).toBeDefined();
    cleanup();
    show(pair({ totalEdges: 12 }), [stray]);
    expect(within(screen.getByRole("group", { name: "Legend" })).getByText("No loaded link")).toBeInTheDocument();
    expect(screen.getByRole("group", { name: "Legend" }).textContent).not.toMatch(/not linked/i);
  });

  it("is not drawn when there is nothing to key", () => {
    show(makeData({ items: [], edges: [] }));
    expect(screen.queryByRole("group", { name: "Legend" })).toBeNull();
  });
});

describe("the nearby group", () => {
  const stray = eventItem(8, T0 + 2_000);

  it("is not drawn without a nearby entry, which is every production session", () => {
    show(pair());
    expect(screen.queryByText(/^Nearby,/)).toBeNull();
  });

  it("is a collapsed disclosure, named by the one word its entries may carry, with the reason for each", () => {
    show(pair(), [stray, eventItem(9, T0 + 3_000)]);
    const summary = screen.getByText("Nearby, not linked (2)");
    const details = summary.closest("details") as HTMLDetailsElement;
    expect(details.open).toBe(false);
    fireEvent.click(summary);
    expect(details.open).toBe(true);
    const entries = Array.from(details.querySelectorAll("[data-nearby]"));
    expect(entries).toHaveLength(2);
    expect(entries[0]).toHaveTextContent("time only, not linked");
    expect(entries[0]!.querySelector("[data-strength-badge]")).toBeNull();
    expect(details.querySelector("line")).toBeNull();
  });

  it("never says 'not linked' when the session cannot vouch for it", () => {
    show(pair({ updating: true }), [stray]);
    expect(screen.getByText("Nearby, no loaded link (1)")).toBeInTheDocument();
    expect(screen.getByTestId("rail-chains").textContent).not.toMatch(/not linked/i);
  });

  it("adds no row and no count to the chains", () => {
    show(pair(), [stray]);
    expect(rowsOf()).toHaveLength(1);
  });
});

describe("the empty states", () => {
  it("says the spec's sentence when the session can speak for an absence of links", () => {
    show(makeData({ items: [], edges: [] }));
    expect(screen.getByTestId("rail-chains-empty")).toHaveTextContent(NO_LINKED_EVENTS_TEXT);
  });

  it("does not, while it cannot", () => {
    show(makeData({ items: [], edges: [], gaps: classifyCoverageGaps([{ source: "correlation", reason: "limit" }], 1) }));
    expect(screen.getByTestId("rail-chains-empty").textContent).not.toMatch(/no linked events/i);
  });

  it("has none beside rows, and qualifies the line above rows that are not links", () => {
    show(makeData({ items: itemsFor(fixtureEdges("group3")), edges: fixtureEdges("group3") }));
    expect(screen.queryByTestId("rail-chains-empty")).toBeNull();
    expect(screen.getByTestId("rail-chains-rows-line")).toHaveTextContent("No exact or candidate chains were found.");
  });
});

describe("what it says about what it did not cover", () => {
  it("lists the notices, and offers Retry for a stopped read that runs the hook's retry", () => {
    const retry = vi.fn();
    show(pair({ totalEdges: 40, scan: { state: "incomplete", stoppedBy: "budget", error: null }, retry }));
    expect(screen.getByTestId("rail-chains-notices")).toHaveTextContent("paged and bounded");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(retry).toHaveBeenCalledTimes(1);
  });

  it("says the update and the read as plain text, marks the tab busy, and dims the rows", () => {
    show(
      pair({
        updating: true,
        nextScan: { state: "running", progress: { scannedItems: 3, totalItems: 9, retainedItems: 1 }, stoppedBy: null, error: null },
      }),
    );
    expect(screen.getByTestId("rail-chains-status")).toHaveTextContent("Updating correlation... Reading 3 of 9 timeline items...");
    expect(screen.getByTestId("rail-chains")).toHaveAttribute("aria-busy", "true");
    expect(card().style.opacity).toBe("0.6");
    expect(card()).toHaveAttribute("aria-busy", "true");
  });

  it("speaks no live region of its own, in any state", () => {
    for (const data of [UNAVAILABLE_CORRELATION, pair(), mixed({ updating: true }), pair({ hasItems: false, stage: "scanning" })]) {
      const view = show(data);
      expect(view.container.querySelector("[role='status'], [aria-live]")).toBeNull();
      view.unmount();
    }
  });
});

describe("Show in table", () => {
  const filter = (name = /^Show in table: /) => screen.getByRole("button", { name });

  it("applies the chain's record scope through the shared action, switches to Table and focuses its tab", () => {
    seedStore([recordFor(1), recordFor(2), recordFor(3)]);
    const tab = armTab("table");
    useEvtxLayoutStore.setState({ activeView: "correlation" });
    show(pair());
    fireEvent.click(filter());
    const scope = useEvtxStore.getState().recordScope;
    expect(scope?.kind).toBe("chain");
    expect(scope?.title).toBe("101 \u00b7 first failed");
    expect([...(scope?.records ?? [])].map((record) => record.eventRecordId).sort()).toEqual([1, 2]);
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    expect(tab).toHaveFocus();
  });

  it("applies the same scope the Correlation view's Filter table to chain applies", () => {
    seedStore([recordFor(1), recordFor(2)]);
    const data = pair();
    const view = render(
      <EvtxCorrelationProvider value={data}>
        <EvtxCorrelationView />
      </EvtxCorrelationProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Filter table to chain" }));
    const fromView = useEvtxStore.getState().recordScope!;
    view.unmount();
    seedStore([recordFor(1), recordFor(2)]);
    show(data);
    fireEvent.click(filter());
    const fromRail = useEvtxStore.getState().recordScope!;
    expect({ ...fromRail, records: [...fromRail.records].map((r) => r.id) }).toEqual({
      ...fromView,
      records: [...fromView.records].map((r) => r.id),
    });
  });

  it("stays, moves no focus and says why in an alert on that card, when the scope could not be applied", () => {
    seedStore([]);
    const tab = armTab("table");
    useEvtxLayoutStore.setState({ activeView: "correlation" });
    show(mixed());
    fireEvent.click(screen.getAllByRole("button", { name: /^Show in table: / })[0]!);
    expect(useEvtxStore.getState().recordScope).toBeNull();
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(tab).not.toHaveFocus();
    const alert = within(card(0)).getByRole("alert");
    expect(alert).toHaveTextContent("The table was not filtered");
    expect(within(card(1)).queryByRole("alert")).toBeNull();
  });

  it("does not say 'no loaded events' when the entries could not be looked for", () => {
    seedStore([recordFor(1), recordFor(2)]);
    show(makeData({ items: [], edges: fixtureEdges("exactPair"), hasItems: true }));
    fireEvent.click(filter());
    const text = screen.getByRole("alert").textContent ?? "";
    expect(text).toContain("could not be matched to a record because their timeline items were not read");
    expect(text).not.toMatch(/no loaded events?|not loaded/i);
  });

  it.each([
    ["the model is an earlier session's", () => pair({ updating: true }), WAIT_FOR_UPDATE_REASON],
    ["the entries were not read", () => pair({ hasItems: false, stage: "edgesOnly" }), WAIT_FOR_ENTRIES_REASON],
  ])("waits, focusably and with its reason, while %s", (_why, data, reason) => {
    seedStore([recordFor(1), recordFor(2)]);
    show(data());
    const button = filter();
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).toHaveAttribute("title", reason);
    fireEvent.click(button);
    expect(useEvtxStore.getState().recordScope).toBeNull();
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
  });
});

describe("Open in correlation view", () => {
  const openButton = (index = 0) => screen.getAllByRole("button", { name: /^Open in correlation view: / })[index]!;

  it("opens that chain through openChain, shows the view and focuses the Correlation tab", () => {
    const tab = armTab("correlation");
    const data = mixed();
    show(data);
    fireEvent.click(openButton(1));
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(data.model!.chains[1]!.id);
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(1);
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(useEvtxLayoutStore.getState().railTab).toBe("chains");
    expect(tab).toHaveFocus();
  });

  it("opens a compact row too", () => {
    const data = mixed();
    show(data);
    fireEvent.click(openButton(2));
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe(data.model!.chains[2]!.id);
  });

  it("drops the lost-selection notice the view holds, and never speaks it (the Open path clears the record)", () => {
    vi.useFakeTimers();
    const data = mixed();
    useEvtxCorrelationStore.setState({ selectedChainId: "a-chain-that-is-gone" });
    render(
      <EvtxCorrelationProvider value={data}>
        <EvtxCorrelationView />
        <EvtxRailChains />
      </EvtxCorrelationProvider>,
    );
    const notices = () => screen.queryByTestId("correlation-notices")?.textContent ?? "";
    expect(notices()).toContain("The chain that was selected is no longer present.");
    fireEvent.click(openButton(1));
    act(() => {
      vi.advanceTimersByTime(20_000);
    });
    expect(notices()).not.toContain("no longer present");
    expect(screen.getByTestId("correlation-announcer").textContent).not.toMatch(/no longer present/);
  });

  it.each([
    ["the model is an earlier session's", () => pair({ updating: true })],
    ["the entries were not read", () => pair({ hasItems: false, stage: "edgesOnly" })],
  ])("waits while %s", (_why, data) => {
    show(data());
    const button = openButton();
    expect(button).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(button);
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(0);
  });
});

describe("the Not placed card", () => {
  const unplaced = (n: number): UnplacedItem => ({ reason: "missingTimestamp", origin: logItem(n, 0).origin });
  const notPlaced = () => screen.queryByTestId("rail-chains-not-placed");

  it("is absent with no run or a counted zero", () => {
    show(pair({ unplacedList: { items: [], total: 0 } }));
    expect(notPlaced()).toBeNull();
  });

  it("states the engine's count and opens the list in the Correlation view, focusing its tab", () => {
    const tab = armTab("correlation");
    useEvtxCorrelationStore.setState({ selectedChainId: "kept" });
    show(pair({ unplacedList: { items: [unplaced(1), unplaced(2)], total: 5 } }));
    expect(notPlaced()).toHaveTextContent("Not placed (5)");
    expect(notPlaced()).toHaveTextContent("5 items carry no timestamp. Placing them would invent an order the evidence does not support.");
    fireEvent.click(within(notPlaced()!).getByRole("button", { name: /^Review unplaced lines/ }));
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe("kept");
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(tab).toHaveFocus();
  });

  it("says the count is unknown, never 0", () => {
    show(pair({ unplacedList: { items: [], total: null } }));
    expect(notPlaced()).toHaveTextContent("Not placed (count unknown)");
    expect(notPlaced()!.textContent).not.toMatch(/\(0\)/);
  });

  it("sits on Background3 with Foreground2 text and an underlined link: Background4 misses 4.5:1 in three themes", () => {
    show(pair({ unplacedList: { items: [], total: 3 } }));
    expect(notPlaced()!.style.backgroundColor).toBe(tokens.colorNeutralBackground3);
    const link = within(notPlaced()!).getByRole("button", { name: /^Review unplaced lines/ });
    expect(link.style.color).toBe(tokens.colorNeutralForeground2);
    expect(link.style.textDecorationLine).toBe("underline");
  });
});

describe("the chain of the selected event", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  it("marks that card with the selection triplet, says so in its name, and no other", () => {
    seedStore([recordFor(1), recordFor(2)]);
    useEvtxStore.setState({ selectedRecordId: 1 });
    const data = pair();
    show(data);
    expect(card()).toHaveAttribute("aria-current", "true");
    expect(card().getAttribute("aria-label")).toMatch(/, contains the selected event$/);
    expect(card().style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    expect(card().style.boxShadow).toContain(tokens.colorPaletteBlueBorderActive);
    expect(card().querySelector("[data-strength-badge]")).not.toBeNull();
  });

  it("marks none for a record no chain holds, and follows a selection that changes", () => {
    seedStore([recordFor(1), recordFor(2), recordFor(9)]);
    useEvtxStore.setState({ selectedRecordId: 9 });
    show(pair());
    expect(card()).not.toHaveAttribute("aria-current");
    act(() => useEvtxStore.setState({ selectedRecordId: 2 }));
    act(() => {
      vi.advanceTimersByTime(200);
    });
    expect(card()).toHaveAttribute("aria-current", "true");
  });
});

describe("text sizes come from the log list font size", () => {
  const sizeOf = (selector: string) => (card().querySelector(selector) as HTMLElement).style.fontSize;

  it.each([
    [MIN_LOG_LIST_FONT_SIZE, { title: "11px", label: "10px", message: "10px" }],
    [13, { title: "13px", label: "10px", message: "11px" }],
    [MAX_LOG_LIST_FONT_SIZE, { title: "20px", label: "17px", message: "18px" }],
  ])("at %s px: title f, captions max(10, f - 3), messages max(10, f - 2)", (fontSize, expected) => {
    useUiStore.setState({ logListFontSize: fontSize });
    show(pair());
    expect(sizeOf('[data-rail-part="title"]')).toBe(expected.title);
    expect(sizeOf('[data-rail-part="span"]')).toBe(expected.label);
    expect(sizeOf('[data-step-part="time"]')).toBe(expected.label);
    expect(sizeOf('[data-step-part="message"]')).toBe(expected.message);
  });

  it("gives the time column the width of eight digits of its own size, so it never clips", () => {
    useUiStore.setState({ logListFontSize: MAX_LOG_LIST_FONT_SIZE });
    show(pair());
    expect((card().querySelector('[data-step-part="time"]') as HTMLElement).style.minWidth).toBe("8ch");
  });
});

describe("it cannot collapse a card, and holds nothing it should not import", () => {
  it("lays its rows out in max-content tracks, so a card is as tall as its own content", () => {
    show(pair());
    expect(screen.getByTestId("rail-chains").style.gridAutoRows).toBe("max-content");
    expect(screen.getByRole("list", { name: "Chains in this session, strongest first" }).style.gridAutoRows).toBe("max-content");
    expect(card().style.overflow).toBe("");
  });

  it("imports nothing from the lazily loaded view or the lane plot", () => {
    for (const source of [tabSource, cardSource]) {
      expect(source).not.toMatch(/from "\.\/EvtxCorrelationView"|from "\.\/EvtxCorrelationLanes"/);
    }
  });

  it("writes no color literal and no pixel font size, and not the chip's two words", () => {
    for (const source of [tabSource, cardSource]) {
      expect(source).not.toMatch(/["'`]#[0-9a-fA-F]{3,8}["'`]|\brgba?\(|\bhsla?\(/);
      expect(source).not.toMatch(/fontSize:\s*["'`]?\d+px/);
    }
  });

  it("does not sum the strengths itself", () => {
    for (const source of [tabSource, cardSource]) expect(source).not.toMatch(/\.exact\s*\+/);
  });
});

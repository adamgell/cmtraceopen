/**
 * The actions a chain offers outside the lazy Correlation view (#841): filter the table to it, open it
 * in the Correlation view, and whether either may act. The view, the dock, the Details context list
 * and the rail's Chains tab all call these, so the rules are tested here once; the view's own tests
 * (EvtxCorrelationView.test.tsx) keep driving them through its buttons.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import {
  filterTableToChain,
  loadedEvidenceIndex,
  openChainInCorrelationView,
  openUnplacedInCorrelationView,
  scopeFailureText,
} from "./evtx-correlation-actions";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import { eventItem, fixtureEdges, makeData, recordFor, T0, type DataOptions } from "./evtx-correlation-test-fixtures";
import { evtxViewTabId, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import type { EvtxRecord } from "./types";

const sources = Object.fromEntries(
  Object.entries(
    import.meta.glob("./**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>,
  )
    .filter(([path]) => !/\.test\.tsx?$|-test-helpers\.|-test-fixtures\.|\/__fixtures__\//.test(path))
    .map(([path, source]) => [path.replace(/^\.\//, ""), source]),
);

function seedStore(records: EvtxRecord[] = []) {
  useEvtxStore.getState().reset();
  useEvtxStore.setState({ records, isLoading: false, timeZoneMode: "utc" });
}

function pair(extra: Partial<DataOptions> = {}) {
  const data = makeData({
    items: [eventItem(1, T0, "error", "first failed"), eventItem(2, T0 + 6_000, "info", "second ok")],
    edges: fixtureEdges("exactPair"),
    ...extra,
  });
  return { data, chain: data.model!.chains[0]!, origins: data.origins, model: data.model! };
}

/** A tab the layout would render, so a call that focuses it can be seen. */
function arm(view: "table" | "correlation") {
  const tab = document.createElement("button");
  tab.id = evtxViewTabId(view);
  document.body.appendChild(tab);
  return tab;
}

beforeEach(() => {
  localStorage.clear();
  useEvtxCorrelationStore.setState({ selectedChainId: null, unplacedOpen: false, openedCount: 0 });
  useEvtxLayoutStore.setState({ activeView: "correlation" });
  seedStore();
});
afterEach(() => {
  document.body.innerHTML = "";
});

describe("filterTableToChain", () => {
  it("applies a chain scope with the chain's title, records, references and counts", () => {
    seedStore([recordFor(1), recordFor(2), recordFor(3)]);
    const { chain, origins, model } = pair();
    const result = filterTableToChain({ chain, origins, edgeInputComplete: model.edgeInputComplete });
    expect(result).toEqual({ applied: true });
    const scope = useEvtxStore.getState().recordScope;
    expect(scope?.kind).toBe("chain");
    expect(scope?.title).toBe("101 · first failed");
    expect([...(scope?.records ?? [])].map((record) => record.eventRecordId).sort()).toEqual([1, 2]);
    expect(scope?.references).toHaveLength(2);
    expect(scope?.counts).toMatchObject({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("switches to Table and moves focus to its tab, only when the scope was applied", () => {
    seedStore([recordFor(1), recordFor(2)]);
    const tab = arm("table");
    const { chain, origins } = pair();
    filterTableToChain({ chain, origins, edgeInputComplete: true });
    expect(useEvtxLayoutStore.getState().activeView).toBe("table");
    expect(tab).toHaveFocus();
  });

  it("marks the scope bounded when the edges were not all loaded", () => {
    seedStore([recordFor(1), recordFor(2)]);
    const { chain, origins } = pair({ totalEdges: 40 });
    filterTableToChain({ chain, origins, edgeInputComplete: false });
    expect(useEvtxStore.getState().recordScope?.counts.bounded).toBe(true);
  });

  it("stays where it is, moves no focus and says why, when the scope could not be applied", () => {
    seedStore([]);
    const tab = arm("table");
    const { chain, origins } = pair();
    const result = filterTableToChain({ chain, origins, edgeInputComplete: true });
    expect(result.applied).toBe(false);
    expect(result.applied === false && result.text).toContain("2 events of this chain are not loaded.");
    expect(useEvtxStore.getState().recordScope).toBeNull();
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(tab).not.toHaveFocus();
  });

  it("says events are still loading, rather than that the chain has none, while they are", () => {
    seedStore([recordFor(1), recordFor(2)]);
    useEvtxStore.setState({ isLoading: true });
    const { chain, origins } = pair();
    const result = filterTableToChain({ chain, origins, edgeInputComplete: true });
    expect(result.applied === false && result.text).toContain("events are still loading");
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
  });

  it("does not say 'no loaded events' when entries could not be looked for", () => {
    seedStore([recordFor(1), recordFor(2)]);
    const { chain, origins } = pair({ items: [] });
    const result = filterTableToChain({ chain, origins, edgeInputComplete: true });
    const text = result.applied === false ? result.text : "";
    expect(text).toContain("2 entries of this chain could not be matched to a record because their timeline items were not read.");
    expect(text).not.toMatch(/no loaded events?|not loaded/i);
  });

  it("looks in the records loaded at the moment of the call, not in a copy made earlier", () => {
    seedStore([]);
    const { chain, origins } = pair();
    seedStore([recordFor(1), recordFor(2)]);
    expect(filterTableToChain({ chain, origins, edgeInputComplete: true })).toEqual({ applied: true });
  });
});

describe("loadedEvidenceIndex", () => {
  it("indexes the records the store holds now", () => {
    seedStore([recordFor(1)]);
    const first = loadedEvidenceIndex();
    seedStore([recordFor(1), recordFor(2)]);
    expect(loadedEvidenceIndex()).not.toBe(first);
  });
});

describe("scopeFailureText", () => {
  const counts = { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false };

  it("never says 'no loaded events' for any counts", () => {
    for (const unresolved of [0, 1, 4]) {
      for (const notLoaded of [0, 2]) {
        expect(scopeFailureText({ ...counts, unresolved, notLoaded }, false)).not.toMatch(/no loaded events?/i);
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

  it("says events are still loading first", () => {
    expect(scopeFailureText({ ...counts, notLoaded: 2 }, true)).toBe(
      "The table was not filtered: events are still loading. Try again when loading has finished.",
    );
  });
});

describe("openChainInCorrelationView", () => {
  it("opens the chain through openChain, so the view drops a loss it holds, shows the view and focuses its tab", () => {
    const tab = arm("correlation");
    useEvtxLayoutStore.setState({ activeView: "table" });
    openChainInCorrelationView("chain-a");
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe("chain-a");
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(1);
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(tab).toHaveFocus();
  });

  it("counts every open, the same chain twice included", () => {
    openChainInCorrelationView("chain-a");
    openChainInCorrelationView("chain-a");
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(2);
  });

  it("leaves the selection alone and counts no open when it is given no chain, but still shows the view and focuses its tab", () => {
    const tab = arm("correlation");
    useEvtxCorrelationStore.setState({ selectedChainId: "kept" });
    useEvtxLayoutStore.setState({ activeView: "table" });
    openChainInCorrelationView();
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe("kept");
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(0);
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(tab).toHaveFocus();
  });
});

describe("openUnplacedInCorrelationView", () => {
  it("shows the Not placed list, keeps the chain selection, shows the view and focuses its tab", () => {
    const tab = arm("correlation");
    useEvtxLayoutStore.setState({ activeView: "table" });
    useEvtxCorrelationStore.setState({ selectedChainId: "kept", unplacedOpen: false });
    openUnplacedInCorrelationView();
    expect(useEvtxCorrelationStore.getState().unplacedOpen).toBe(true);
    expect(useEvtxCorrelationStore.getState().selectedChainId).toBe("kept");
    expect(useEvtxCorrelationStore.getState().openedCount).toBe(0);
    expect(useEvtxLayoutStore.getState().activeView).toBe("correlation");
    expect(tab).toHaveFocus();
  });
});

describe("one definition of opening and focusing a view tab", () => {
  const FOCUS_A_VIEW_TAB = /getElementById\(\s*evtxViewTabId\(\s*"(?:correlation|table)"\s*\)\s*\)/;

  it("sees the workspace and the module", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    expect(sources["evtx-correlation-actions.ts"]).toBeDefined();
    expect(FOCUS_A_VIEW_TAB.test(sources["evtx-correlation-actions.ts"]!)).toBe(true);
  });

  it("recognises a component that focuses a view tab itself", () => {
    expect(FOCUS_A_VIEW_TAB.test('document.getElementById(evtxViewTabId("correlation"))?.focus();')).toBe(true);
    expect(FOCUS_A_VIEW_TAB.test('id={evtxViewTabId(view)}')).toBe(false);
  });

  it("is written by the actions module alone: no component focuses the Table or Correlation tab itself", () => {
    const writers = Object.entries(sources)
      .filter(([file, source]) => file !== "evtx-correlation-actions.ts" && FOCUS_A_VIEW_TAB.test(source))
      .map(([file]) => file);
    expect(writers).toEqual([]);
  });

  it.each([
    ["EvtxCorrelationView.tsx", /\bfilterTableToChain\(/],
    ["EvtxCorrelationDock.tsx", /\bopenChainInCorrelationView\(/],
    ["EvtxDetailContext.tsx", /\bopenChainInCorrelationView\(/],
    ["EventDiagnosisPanel.tsx", /\bopenChainInCorrelationView\(/],
    ["EventDiagnosisPanel.tsx", /\bopenUnplacedInCorrelationView\(/],
  ])("is called by %s", (file, call) => {
    expect(sources[file], file).toMatch(call);
  });

  describe("is the only way in: nothing but the actions module reaches the store's openers, which do not move focus", () => {
    // `openCorrelationView` and `openUnplacedList` switch the view and nothing else; every Open in the
    // workspace goes through the actions module, which also moves focus to the Correlation tab. The
    // openers are module functions, so a component reaches one by naming it: in a call, as a handler
    // reference (`onClick={openUnplacedList}`, which a call-only pattern misses), in an import under
    // an alias, or as a member of the module. Comments that name them say nothing and are left out.
    const OPENER = /\b(?:openCorrelationView|openUnplacedList)\b/;
    const withoutComments = (source: string) =>
      source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
    const reachesAnOpener = (source: string) => OPENER.test(withoutComments(source));

    it("sees every spelling of a reach, and not a comment or the actions that wrap them", () => {
      expect(reachesAnOpener("openCorrelationView(id);")).toBe(true);
      expect(reachesAnOpener("<Link onClick={openUnplacedList}>Review</Link>")).toBe(true);
      expect(reachesAnOpener("const open = openCorrelationView;")).toBe(true);
      expect(reachesAnOpener('import { openUnplacedList } from "./evtx-correlation-store";')).toBe(true);
      expect(reachesAnOpener('import {\n  openCorrelationView as open,\n} from "./evtx-correlation-store";')).toBe(true);
      expect(reachesAnOpener("store.openUnplacedList()")).toBe(true);
      expect(reachesAnOpener("onClick={useCallback(openUnplacedList, [])}")).toBe(true);
      expect(reachesAnOpener("// openUnplacedList opens the list")).toBe(false);
      expect(reachesAnOpener("/** `openCorrelationView` switches the view. */\nconst x = 1;")).toBe(false);
      expect(reachesAnOpener("openChainInCorrelationView(id); openUnplacedInCorrelationView();")).toBe(false);
      expect(reachesAnOpener('const url = "http://x"; const y = openUnplacedList;')).toBe(true);
    });

    it("is reached by no source of the workspace but the store and the actions module", () => {
      const reaching = Object.entries(sources)
        .filter(([file]) => file !== "evtx-correlation-store.ts" && file !== "evtx-correlation-actions.ts")
        .filter(([, source]) => reachesAnOpener(source))
        .map(([file]) => file);
      expect(reaching).toEqual([]);
      // And the actions module does reach them, or this would pass over a workspace that moved on.
      expect(reachesAnOpener(sources["evtx-correlation-actions.ts"]!)).toBe(true);
      expect(reachesAnOpener(sources["evtx-correlation-store.ts"]!)).toBe(true);
    });
  });

  it("is not imported from the lazy view by anything", () => {
    const importers = Object.entries(sources)
      .filter(([, source]) => /from "\.\/EvtxCorrelationView"/.test(source))
      .map(([file]) => file);
    expect(importers).toEqual([]);
  });
});

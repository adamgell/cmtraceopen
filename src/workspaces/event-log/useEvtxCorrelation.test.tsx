/**
 * The shared correlation data: when it loads, what it keeps, what it throws away.
 *
 * `FakeSession` answers the paged queries from arrays and records every call. A gate lets a test
 * hold one reply open while the session changes underneath it.
 */
import { act, cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type {
  EventLogAnalysisEdgePage,
  EventLogAnalysisSessionStatus,
  EventLogAnalysisTimelinePage,
} from "../../lib/commands";
import type { CorrelationLoadDeps } from "./evtx-correlation-load";
import {
  CORRELATION_SETTLE_MS,
  EvtxCorrelationProvider,
  NO_FINDINGS,
  UNAVAILABLE_CORRELATION,
  useEvtxCorrelation,
  useEvtxCorrelationData,
  type UseEvtxCorrelationOptions,
} from "./useEvtxCorrelation";
import type { TimelineCorrelationEdge, TimelineItem } from "./unified-timeline";

afterEach(cleanup);

function itemAt(index: number): TimelineItem {
  return {
    timestampMs: 1_000_000 + 1_000 * index,
    severity: index % 7 === 0 ? "error" : "info",
    message: `message ${index}`,
    origin: {
      kind: "event",
      stableId: `item-${index}`,
      source: "Live",
      machine: "HOST",
      bundle: null,
      channel: "System",
      provider: "P",
      processId: null,
      eventId: 100 + (index % 50),
      recordId: index + 1,
    },
  };
}

function edgeBetween(index: number, from: number, to: number): TimelineCorrelationEdge {
  const a = `item-${from}`;
  const b = `item-${to}`;
  return {
    id: `edge-${index}`,
    fromId: a,
    toId: b,
    key: { kind: "activityId", value: `k${index}` },
    strength: "exact",
    confidence: "high",
    candidateIds: [],
    evidence: [
      { originId: a, field: "activityId", value: `k${index}` },
      { originId: b, field: "activityId", value: `k${index}` },
    ],
    coverage: { state: "covered" },
  };
}

interface Gate {
  promise: Promise<void>;
  open: () => void;
}
function gate(): Gate {
  let open!: () => void;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

interface SessionOptions {
  id?: string;
  revision?: number;
  itemCount: number;
  /** Pairs (from, to) of item indices. */
  pairs: [number, number][];
  previewEdges?: number;
  unplacedCount?: number;
  totalUnplaced?: number;
}

class FakeSession {
  readonly id: string;
  readonly revision: number;
  readonly items: TimelineItem[];
  readonly edges: TimelineCorrelationEdge[];
  readonly previewEdges: number;
  readonly timelineCalls: { offset: number; limit: number }[] = [];
  readonly edgeCalls: { offset: number; limit: number }[] = [];
  readonly failEdgePages = { remaining: 0 };
  readonly failTimelinePages = { remaining: 0 };
  edgeGate: Gate | null = null;
  timelineGate: Gate | null = null;
  totalEdgesOverride: number | undefined;
  private readonly options: SessionOptions;

  constructor(options: SessionOptions) {
    this.options = options;
    this.id = options.id ?? "00000000-0000-4000-8000-0000000008a1";
    this.revision = options.revision ?? 1;
    this.items = Array.from({ length: options.itemCount }, (_, i) => itemAt(i));
    this.edges = options.pairs.map(([from, to], i) => edgeBetween(i, from, to));
    this.previewEdges = options.previewEdges ?? this.edges.length;
  }

  status(): EventLogAnalysisSessionStatus {
    return {
      sessionId: this.id,
      revision: this.revision,
      totalItems: this.items.length,
      eventItems: this.items.length,
      logItems: 0,
      totalUnplaced: this.options.totalUnplaced ?? this.options.unplacedCount ?? 0,
      totalEdges: this.edges.length,
      totalCoverageGaps: 0,
      finalized: true,
    };
  }

  page(offset = 0, limit = 1_000): EventLogAnalysisTimelinePage {
    const slice = this.items.slice(offset, offset + limit);
    const end = offset + slice.length;
    const { finalized: _finalized, ...status } = this.status();
    return {
      ...status,
      totalEdges: this.totalEdgesOverride ?? this.edges.length,
      offset,
      nextOffset: end < this.items.length ? end : null,
      serializedBytes: Math.max(1, slice.length * 100),
      items: slice,
      unplacedPreview: Array.from({ length: this.options.unplacedCount ?? 0 }, (_, i) => ({
        origin: itemAt(10_000 + i).origin,
        reason: "missingTimestamp" as const,
      })),
      edgesPreview: offset === 0 ? this.edges.slice(0, this.previewEdges) : [],
      coverageGapsPreview: [],
    };
  }

  readonly sleeps: number[] = [];
  sleepGate: Gate | null = null;

  deps(): Partial<CorrelationLoadDeps> {
    return {
      sleep: async (ms) => {
        this.sleeps.push(ms);
        if (ms > 0 && this.sleepGate !== null) await this.sleepGate.promise;
      },
      queryTimelinePage: async (_sessionId, offset, limit) => {
        this.timelineCalls.push({ offset, limit });
        if (this.timelineGate !== null) await this.timelineGate.promise;
        if (this.failTimelinePages.remaining > 0) {
          this.failTimelinePages.remaining -= 1;
          throw new Error("timeline down");
        }
        return this.page(offset, limit);
      },
      queryEdgePage: async (_sessionId, offset, limit) => {
        this.edgeCalls.push({ offset, limit });
        if (this.edgeGate !== null) await this.edgeGate.promise;
        if (this.failEdgePages.remaining > 0) {
          this.failEdgePages.remaining -= 1;
          throw new Error("edges down");
        }
        const slice = this.edges.slice(offset, offset + limit);
        const end = offset + slice.length;
        const page: EventLogAnalysisEdgePage = {
          sessionId: this.id,
          revision: this.revision,
          offset,
          nextOffset: end < this.edges.length ? end : null,
          totalEdges: this.edges.length,
          edges: slice,
          serializedBytes: Math.max(1, slice.length * 50),
        };
        return page;
      },
    };
  }

  props(overrides: Partial<UseEvtxCorrelationOptions> = {}): UseEvtxCorrelationOptions {
    return {
      status: this.status(),
      initialPage: this.page(),
      pending: false,
      needItems: false,
      settleMs: CORRELATION_SETTLE_MS,
      deps: this.deps(),
      ...overrides,
    };
  }
}

const NONE: UseEvtxCorrelationOptions = {
  status: null,
  initialPage: null,
  pending: false,
  needItems: false,
};

describe("with no session", () => {
  it("reads as unavailable: no model, an unknown total, no call", () => {
    const { result } = renderHook(() => useEvtxCorrelation(NONE));
    expect(result.current.stage).toBe("unavailable");
    expect(result.current.model).toBeNull();
    expect(result.current.edges.totalEdges).toBeNull();
    expect(result.current.hasItems).toBe(false);
    expect(result.current.updating).toBe(false);
  });

  it("reads as pending while a session is being built, still with no model", () => {
    const { result } = renderHook(() => useEvtxCorrelation({ ...NONE, pending: true }));
    expect(result.current.stage).toBe("pending");
    expect(result.current.model).toBeNull();
  });

  it("is unavailable outside a provider", () => {
    const { result } = renderHook(() => useEvtxCorrelationData());
    expect(result.current).toBe(UNAVAILABLE_CORRELATION);
  });

  it("gives what the provider gives", () => {
    const seen: string[] = [];
    function Probe() {
      seen.push(useEvtxCorrelationData().stage);
      return <span>probe</span>;
    }
    render(
      <EvtxCorrelationProvider value={{ ...UNAVAILABLE_CORRELATION, stage: "ready" }}>
        <Probe />
      </EvtxCorrelationProvider>,
    );
    expect(screen.getByText("probe")).toBeInTheDocument();
    expect(seen).toEqual(["ready"]);
  });
});

describe("edges only (the Insights card, which needs counts and no scan)", () => {
  it("builds a counts-only model from a complete preview with no call at all", async () => {
    const session = new FakeSession({ itemCount: 3_000, pairs: [[1, 2], [3, 4], [5, 6], [7, 8]] });
    const props = session.props();
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    expect(result.current.model?.counts).toEqual({
      exact: 4,
      candidate: 0,
      ambiguous: 0,
      coverageBlocked: 0,
    });
    expect(result.current.model?.edgeInputComplete).toBe(true);
    expect(result.current.hasItems).toBe(false);
    expect(result.current.model?.chains.every((chain) => chain.title === null)).toBe(true);
    expect(result.current.edges).toEqual({ loaded: 4, totalEdges: 4, complete: true, error: null });
    expect(session.timelineCalls).toEqual([]);
    expect(session.edgeCalls).toEqual([]);
    expect(session.sleeps).not.toContain(CORRELATION_SETTLE_MS);
  });

  it("never scans the timeline for a consumer that does not need items", async () => {
    const session = new FakeSession({ itemCount: 5_000, pairs: [[1, 2000]] });
    const props = session.props({ needItems: false });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    expect(session.timelineCalls).toEqual([]);
  });

  it("exposes link partners from the uncapped pairs, past the 100 row cap", async () => {
    const pairs: [number, number][] = Array.from({ length: 150 }, (_, i) => [i * 2, i * 2 + 1]);
    const session = new FakeSession({ itemCount: 400, pairs });
    const props = session.props();
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    expect(result.current.model?.chains).toHaveLength(100);
    expect(result.current.model?.linkedPairs).toHaveLength(150);
    expect(result.current.linkPartners.size).toBe(300);
    expect(result.current.linkPartners.get("item-299")).toBe(1);
  });

  it("uses no finding title: the join is undecided (decision B on #838)", () => {
    expect(NO_FINDINGS).toEqual([]);
  });
});

describe("paging a short preview", () => {
  it("waits for the settle delay before the first call, then reads the rest", async () => {
    const pairs: [number, number][] = Array.from({ length: 50 }, (_, i) => [i * 2, i * 2 + 1]);
    const session = new FakeSession({ itemCount: 200, pairs, previewEdges: 10 });
    const props = session.props();
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    expect(session.sleeps[0]).toBe(CORRELATION_SETTLE_MS);
    expect(session.edgeCalls).toEqual([{ offset: 10, limit: 1_000 }]);
    expect(result.current.model?.edgeInputComplete).toBe(true);
    expect(result.current.model?.counts.exact).toBe(50);
    expect(result.current.edges).toMatchObject({ loaded: 50, totalEdges: 50, complete: true });
  });

  it("holds no call open while the settle delay runs, so a session replaced inside it costs nothing", async () => {
    const pairs: [number, number][] = Array.from({ length: 50 }, (_, i) => [i * 2, i * 2 + 1]);
    const first = new FakeSession({ itemCount: 200, pairs, previewEdges: 10, id: "00000000-0000-4000-8000-0000000008a1" });
    const second = new FakeSession({ itemCount: 200, pairs, previewEdges: 10, id: "00000000-0000-4000-8000-0000000008a2" });
    first.sleepGate = gate();
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: first.props(),
    });
    await waitFor(() => expect(first.sleeps).toContain(CORRELATION_SETTLE_MS));
    rerender(second.props());
    await waitFor(() => expect(result.current.builtFor).toBe(`${second.id}:1`));
    act(() => first.sleepGate?.open());
    await act(async () => undefined);
    expect(first.edgeCalls).toEqual([]);
    expect(second.edgeCalls).toHaveLength(1);
    expect(result.current.builtFor).toBe(`${second.id}:1`);
  });

  it("builds an incomplete model when the pages fail, and says how many edges were left out", async () => {
    const pairs: [number, number][] = Array.from({ length: 50 }, (_, i) => [i * 2, i * 2 + 1]);
    const session = new FakeSession({ itemCount: 200, pairs, previewEdges: 10 });
    session.failEdgePages.remaining = 99;
    const props = session.props();
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    expect(result.current.model?.edgeInputComplete).toBe(false);
    expect(result.current.model?.unloadedEdgeCount).toBe(40);
    expect(result.current.edges).toMatchObject({
      loaded: 10,
      totalEdges: 50,
      complete: false,
      error: "edges down",
    });
  });

  it("treats a total that is not a count as unknown, never as 0, and the model as incomplete", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2], [3, 4]] });
    session.totalEdgesOverride = Number.NaN;
    const props = session.props();
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    expect(result.current.edges.totalEdges).toBeNull();
    expect(result.current.edges.complete).toBe(false);
    expect(result.current.model?.edgeInputComplete).toBe(false);
    expect(result.current.model?.unloadedEdgeCount).toBe(0);
    expect(session.edgeCalls).toEqual([]);
  });
});

describe("items (the Correlation view and the Chains tab)", () => {
  it("builds the full model straight from a one-page timeline, with no call", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2], [3, 4]] });
    const props = session.props({ needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    expect(result.current.hasItems).toBe(true);
    expect(result.current.model?.chains.every((chain) => chain.title !== null)).toBe(true);
    expect(result.current.model?.chains.every((chain) => chain.unresolvedMemberIds.length === 0)).toBe(true);
    expect(result.current.scan.state).toBe("complete");
    expect(session.timelineCalls).toEqual([]);
    expect([...result.current.itemsById.keys()].sort()).toEqual(["item-1", "item-2", "item-3", "item-4"]);
  });

  it("scans the following pages for the items the edges name and keeps only those", async () => {
    const session = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200], [2_400, 7]] });
    const props = session.props({ needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    expect(session.timelineCalls).toEqual([
      { offset: 1_000, limit: 1_000 },
      { offset: 2_000, limit: 1_000 },
    ]);
    expect([...result.current.itemsById.keys()].sort()).toEqual([
      "item-1200",
      "item-2400",
      "item-5",
      "item-7",
    ]);
    expect(result.current.scan).toMatchObject({
      state: "complete",
      progress: { scannedItems: 2_500, totalItems: 2_500, retainedItems: 4 },
      stoppedBy: null,
      error: null,
    });
    expect(result.current.model?.chains.every((chain) => chain.unresolvedMemberIds.length === 0)).toBe(true);
    expect(result.current.unplaced.scanComplete).toBe(true);
  });

  it("shows the counts first, then the scan running, then the full model", async () => {
    const session = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]] });
    session.timelineGate = gate();
    const props = session.props({ needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("scanning"));
    expect(result.current.model?.counts.exact).toBe(1);
    expect(result.current.hasItems).toBe(false);
    expect(result.current.scan.state).toBe("running");
    expect(result.current.model?.chains[0]?.title).toBeNull();
    act(() => session.timelineGate?.open());
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    expect(result.current.model?.chains[0]?.title).not.toBeNull();
  });

  it("reports an incomplete scan, and builds from what was read", async () => {
    const session = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]] });
    session.failTimelinePages.remaining = 99;
    const props = session.props({ needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    expect(result.current.scan).toMatchObject({ state: "incomplete", stoppedBy: "error", error: "timeline down" });
    expect(result.current.unplaced.scanComplete).toBe(false);
    // item-5 was on the first page; item-1200 was not read, so it is unresolved, not "unplaced".
    expect(result.current.model?.chains[0]?.unresolvedMemberIds).toEqual(["item-1200"]);
  });

  it("runs the failed step again on retry and then completes", async () => {
    const session = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]] });
    session.failTimelinePages.remaining = 3;
    const props = session.props({ needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.scan.state).toBe("incomplete"));
    const callsBefore = session.timelineCalls.length;
    act(() => result.current.retry());
    await waitFor(() => expect(result.current.scan.state).toBe("complete"));
    expect(session.timelineCalls.length).toBeGreaterThan(callsBefore);
    expect(result.current.model?.chains[0]?.unresolvedMemberIds).toEqual([]);
  });

  it("reuses the edges and the model when a consumer starts and stops needing items", async () => {
    const pairs: [number, number][] = Array.from({ length: 30 }, (_, i) => [i * 2, i * 2 + 1]);
    const session = new FakeSession({ itemCount: 2_500, pairs, previewEdges: 10 });
    // One session keeps one status and one first page; only what the consumers need changes.
    const base = session.props({ needItems: false });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: base,
    });
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    expect(session.edgeCalls).toHaveLength(1);
    rerender({ ...base, needItems: true });
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    expect(session.edgeCalls).toHaveLength(1);
    const full = result.current.model;
    rerender({ ...base, needItems: false });
    await act(async () => undefined);
    // The full model is kept, not rebuilt as a counts-only one.
    expect(result.current.model).toBe(full);
    expect(result.current.hasItems).toBe(true);
    rerender({ ...base, needItems: true });
    await act(async () => undefined);
    expect(result.current.model).toBe(full);
    expect(session.edgeCalls).toHaveLength(1);
    expect(session.timelineCalls).toHaveLength(2);
  });

  it("proves an unplaced list complete only when the preview holds every unplaced item", async () => {
    const complete = new FakeSession({ itemCount: 10, pairs: [[1, 2]], unplacedCount: 2 });
    const completeProps = complete.props({ needItems: true });
    const first = renderHook(() => useEvtxCorrelation(completeProps));
    await waitFor(() => expect(first.result.current.stage).toBe("ready"));
    expect(first.result.current.unplaced.unplacedListComplete).toBe(true);
    expect(first.result.current.unplaced.unplacedIds.size).toBe(2);

    const cut = new FakeSession({ itemCount: 10, pairs: [[1, 2]], unplacedCount: 2, totalUnplaced: 5 });
    const cutProps = cut.props({ needItems: true });
    const second = renderHook(() => useEvtxCorrelation(cutProps));
    await waitFor(() => expect(second.result.current.stage).toBe("ready"));
    expect(second.result.current.unplaced.unplacedListComplete).toBe(false);
  });
});

describe("a session that changes", () => {
  const pairsOf = (count: number): [number, number][] =>
    Array.from({ length: count }, (_, i) => [i * 2, i * 2 + 1]);

  it("keeps the previous model, marked updating, while the next session is built, and replaces it when it is in", async () => {
    const a = new FakeSession({ itemCount: 100, pairs: pairsOf(3), id: "00000000-0000-4000-8000-0000000008a1" });
    const b = new FakeSession({ itemCount: 100, pairs: pairsOf(7), id: "00000000-0000-4000-8000-0000000008a2" });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: a.props(),
    });
    await waitFor(() => expect(result.current.model?.counts.exact).toBe(3));

    rerender({ ...NONE, pending: true, deps: a.deps() });
    await act(async () => undefined);
    expect(result.current.stage).toBe("pending");
    expect(result.current.model?.counts.exact).toBe(3);
    expect(result.current.updating).toBe(true);

    rerender(b.props());
    await waitFor(() => expect(result.current.model?.counts.exact).toBe(7));
    expect(result.current.updating).toBe(false);
    expect(result.current.builtFor).toBe(`${b.id}:1`);
  });

  it("marks the previous model updating when a new session arrives with a short preview, never pairing the old model with the new session", async () => {
    const a = new FakeSession({ itemCount: 100, pairs: pairsOf(3), id: "00000000-0000-4000-8000-0000000008a1" });
    const b = new FakeSession({ itemCount: 100, pairs: pairsOf(40), previewEdges: 5, id: "00000000-0000-4000-8000-0000000008a2" });
    b.edgeGate = gate();
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: a.props(),
    });
    await waitFor(() => expect(result.current.model?.counts.exact).toBe(3));
    rerender(b.props());
    await waitFor(() => expect(b.edgeCalls).toHaveLength(1));
    expect(result.current.updating).toBe(true);
    expect(result.current.stage).toBe("pending");
    expect(result.current.model?.counts.exact).toBe(3);
    act(() => b.edgeGate?.open());
    await waitFor(() => expect(result.current.model?.counts.exact).toBe(40));
    expect(result.current.updating).toBe(false);
  });

  it("clears the model when the data ends and no session is being built", async () => {
    const a = new FakeSession({ itemCount: 100, pairs: pairsOf(3) });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: a.props(),
    });
    await waitFor(() => expect(result.current.model).not.toBeNull());
    rerender({ ...NONE, pending: false });
    await waitFor(() => expect(result.current.stage).toBe("unavailable"));
    expect(result.current.model).toBeNull();
    expect(result.current.edges.totalEdges).toBeNull();
  });

  it("throws away a run the session outlived: its late reply is never shown", async () => {
    const stale = new FakeSession({
      itemCount: 100,
      pairs: pairsOf(40),
      previewEdges: 5,
      id: "00000000-0000-4000-8000-0000000008a1",
    });
    const fresh = new FakeSession({ itemCount: 100, pairs: pairsOf(2), id: "00000000-0000-4000-8000-0000000008a2" });
    stale.edgeGate = gate();
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: stale.props(),
    });
    await waitFor(() => expect(stale.edgeCalls).toHaveLength(1));
    rerender(fresh.props());
    await waitFor(() => expect(result.current.builtFor).toBe(`${fresh.id}:1`));
    act(() => stale.edgeGate?.open());
    await act(async () => undefined);
    expect(result.current.builtFor).toBe(`${fresh.id}:1`);
    expect(result.current.model?.counts.exact).toBe(2);
    expect(result.current.edges.totalEdges).toBe(2);
  });

  it("starts a new scan for a new revision of the same session", async () => {
    const one = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 1 });
    const two = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 2 });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: one.props({ needItems: true }),
    });
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    rerender(two.props({ needItems: true }));
    await waitFor(() => expect(result.current.builtFor).toBe(`${two.id}:2`));
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    expect(two.timelineCalls).toHaveLength(2);
  });

  it("stops quietly when unmounted in the middle of a scan", async () => {
    const session = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]] });
    session.timelineGate = gate();
    const props = session.props({ needItems: true });
    const { result, unmount } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("scanning"));
    unmount();
    session.timelineGate.open();
    await act(async () => undefined);
    expect(session.timelineCalls).toHaveLength(1);
  });
});

describe("a failure that is not a load result", () => {
  it("is shown, not swallowed", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2]] });
    const deps = session.deps();
    const props = session.props({
      deps: {
        ...deps,
        sleep: async () => {
          throw new Error("boom");
        },
      },
    });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.error).toBe("boom"));
  });
});

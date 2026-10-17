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
import { buildCorrelationChains } from "./evtx-correlation-chains";
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
import type { TimelineCorrelationEdge, TimelineCoverageGap, TimelineItem } from "./unified-timeline";

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
  /** The coverage gaps the first page's preview carries. */
  gaps?: TimelineCoverageGap[];
  /** What the session counts, when it is not the preview's length. */
  totalCoverageGaps?: number;
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
      totalCoverageGaps: this.options.totalCoverageGaps ?? this.options.gaps?.length ?? 0,
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
      coverageGapsPreview: offset === 0 ? (this.options.gaps ?? []) : [],
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

  it("publishes the chain model's own rows in its own order, with and without items", async () => {
    // More than the 100 row cap, so the order decides which rows are shown at all.
    const pairs: [number, number][] = Array.from({ length: 120 }, (_, i) => [(119 - i) * 2, (119 - i) * 2 + 1]);
    const session = new FakeSession({ itemCount: 300, pairs });
    const expected = (withItems: boolean) =>
      buildCorrelationChains({
        items: withItems ? session.items : [],
        timelineEdges: session.edges,
        totalTimelineEdges: session.edges.length,
        findings: NO_FINDINGS,
      });
    const countsProps = session.props();
    const counts = renderHook(() => useEvtxCorrelation(countsProps));
    await waitFor(() => expect(counts.result.current.stage).toBe("edgesOnly"));
    expect(counts.result.current.model).toEqual(expected(false));
    expect(counts.result.current.model?.chains).toHaveLength(100);
    expect(counts.result.current.model?.omittedCount).toBe(20);

    const itemProps = session.props({ needItems: true });
    const full = renderHook(() => useEvtxCorrelation(itemProps));
    await waitFor(() => expect(full.result.current.stage).toBe("ready"));
    expect(full.result.current.model).toEqual(expected(true));
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
    expect(result.current.nextScan?.state).toBe("running");
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

  it("scans again for the whole edge set after a retry loaded more edges, and the scan state is true to that scan (G3)", async () => {
    // 50 pairs; each one's second endpoint is on the third timeline page, so a scan has to read it.
    const pairs: [number, number][] = Array.from({ length: 50 }, (_, i) => [i, 1_500 + i]);
    const session = new FakeSession({ itemCount: 2_500, pairs, previewEdges: 10 });
    session.failEdgePages.remaining = 3;
    const props = session.props({ needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    // The edge paging failed: 10 of 50 edges, and a scan that completed for those 20 endpoints.
    expect(result.current.edges).toMatchObject({ loaded: 10, totalEdges: 50, complete: false, error: "edges down" });
    expect(result.current.scan.state).toBe("complete");
    expect(result.current.itemsById.size).toBe(20);
    const scansBefore = session.timelineCalls.length;

    act(() => result.current.retry());
    await waitFor(() => expect(result.current.edges.complete).toBe(true));
    await waitFor(() => expect(result.current.itemsById.size).toBe(100));
    expect(session.timelineCalls.length).toBeGreaterThan(scansBefore);
    expect(result.current.scan.state).toBe("complete");
    expect(result.current.model?.counts.exact).toBe(50);
    // Every member of every chain was searched for: none is left unresolved.
    expect(result.current.model?.chains.every((chain) => chain.unresolvedMemberIds.length === 0)).toBe(true);
    expect(result.current.model?.chains.every((chain) => chain.title !== null)).toBe(true);
  });

  it("keeps the previous FULL model, marked updating, while a new revision's scan runs, and offers the newest counts apart (G6)", async () => {
    const one = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 1 });
    const two = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200], [7, 1_300], [9, 1_400]], revision: 2 });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: one.props({ needItems: true }),
    });
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    const fullOne = result.current.model;
    expect(fullOne?.chains[0]?.title).not.toBeNull();

    two.timelineGate = gate();
    rerender(two.props({ needItems: true }));
    await waitFor(() => expect(result.current.nextScan?.state).toBe("running"));
    // The view still has revision 1's full model: titles, spans and positions are not dropped.
    expect(result.current.model).toBe(fullOne);
    expect(result.current.hasItems).toBe(true);
    expect(result.current.builtFor).toBe(`${one.id}:1`);
    expect(result.current.updating).toBe(true);
    expect(result.current.stage).toBe("scanning");
    // A counts-only consumer has revision 2's counts at once.
    expect(result.current.counts).toMatchObject({ builtFor: `${two.id}:2`, updating: false });
    expect(result.current.counts?.model.counts.exact).toBe(3);

    act(() => two.timelineGate?.open());
    await waitFor(() => expect(result.current.builtFor).toBe(`${two.id}:2`));
    expect(result.current.updating).toBe(false);
    expect(result.current.hasItems).toBe(true);
    expect(result.current.model?.counts.exact).toBe(3);
    expect(result.current.nextScan).toBeNull();
  });

  it("never replaces a full model with a counts-only one, even when no scan finishes", async () => {
    const one = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 1 });
    const two = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200], [7, 1_300]], revision: 2 });
    two.failTimelinePages.remaining = 0;
    two.timelineGate = gate();
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: one.props({ needItems: true }),
    });
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    rerender(two.props({ needItems: true }));
    await waitFor(() => expect(result.current.counts?.builtFor).toBe(`${two.id}:2`));
    for (let tick = 0; tick < 3; tick += 1) {
      await act(async () => undefined);
      expect(result.current.hasItems).toBe(true);
      expect(result.current.builtFor).toBe(`${one.id}:1`);
    }
  });

  it("keeps the unplaced evidence of the model on show when a newer status arrives (G5)", async () => {
    const one = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 1, unplacedCount: 2 });
    const two = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 2, unplacedCount: 5 });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: one.props({ needItems: true }),
    });
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    const shown = result.current.unplaced;
    expect(shown).toMatchObject({ scanComplete: true, unplacedListComplete: true });
    expect(shown.unplacedIds.size).toBe(2);

    two.timelineGate = gate();
    rerender(two.props({ needItems: true }));
    await waitFor(() => expect(result.current.nextScan?.state).toBe("running"));
    expect(result.current.updating).toBe(true);
    // Revision 2's list has 5 unplaced origins; revision 1's model must not be read against it.
    expect(result.current.unplaced).toBe(shown);
    expect(result.current.unplaced.unplacedIds.size).toBe(2);
    expect(result.current.origins.size).toBeGreaterThan(0);
    expect([...result.current.origins.keys()].filter((id) => id.startsWith("item-1000"))).toHaveLength(2);

    act(() => two.timelineGate?.open());
    await waitFor(() => expect(result.current.builtFor).toBe(`${two.id}:2`));
    expect(result.current.unplaced.unplacedIds.size).toBe(5);
  });

  describe("the engine's correlation coverage gaps (J1)", () => {
    const fanOut = (id: string): TimelineCoverageGap => ({
      source: id,
      reason: "exact UserId identity group exceeds the 256-member correlation limit",
    });

    it("exposes the classified gaps of the model's own first reply, with no scan needed", async () => {
      const session = new FakeSession({
        itemCount: 50,
        pairs: [[1, 2]],
        gaps: [fanOut("item-30"), { source: "correlation", reason: "edge budget" }],
        totalCoverageGaps: 2,
      });
      const props = session.props();
      const { result } = renderHook(() => useEvtxCorrelation(props));
      await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
      expect(result.current.gaps).toEqual({
        originIds: new Set(["item-30"]),
        global: true,
        previewCut: false,
      });
    });

    it.each([
      ["more gaps than the preview holds", [fanOut("item-30")], 301],
      ["a count that is not a count, over a gap", [fanOut("item-30")], Number.NaN],
      ["a count that is not a count, over no gaps at all", [], Number.NaN],
    ])("is cut for %s", async (_why, gaps, total) => {
      const session = new FakeSession({ itemCount: 50, pairs: [[1, 2]], gaps, totalCoverageGaps: total });
      const props = session.props();
      const { result } = renderHook(() => useEvtxCorrelation(props));
      await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
      expect(result.current.gaps.previewCut).toBe(true);
    });

    it("says nothing is known before any session: the safe value claims a cut preview", () => {
      const { result } = renderHook(() => useEvtxCorrelation(NONE));
      expect(result.current.gaps.previewCut).toBe(true);
    });

    it("reads the items of the origins the gaps name, though no edge has them, so the join can place them", async () => {
      // The edge is between items on page 0 and page 2; the gap names an item on page 1.
      const session = new FakeSession({
        itemCount: 2_500,
        pairs: [[5, 2_400]],
        gaps: [fanOut("item-1200")],
        totalCoverageGaps: 1,
      });
      const props = session.props({ needItems: true });
      const { result } = renderHook(() => useEvtxCorrelation(props));
      await waitFor(() => expect(result.current.stage).toBe("ready"));
      expect(result.current.origins.has("item-1200")).toBe(true);
      expect(result.current.itemsById.has("item-1200")).toBe(true);
      // And the chain is unaffected by the extra item.
      expect(result.current.model?.counts.exact).toBe(1);
      expect(result.current.scan.progress?.retainedItems).toBe(3);
    });

    describe("the scan for the origins the gaps name is worth its cost only while it can matter", () => {
      it("scans a session with no edge for the origins a complete gap list names", async () => {
        // The only reason to read pages is the gap's origin, and the gap list is whole.
        const session = new FakeSession({
          itemCount: 2_500,
          pairs: [],
          gaps: [fanOut("item-1200")],
          totalCoverageGaps: 1,
        });
        const props = session.props({ needItems: true });
        const { result } = renderHook(() => useEvtxCorrelation(props));
        await waitFor(() => expect(result.current.stage).toBe("ready"));
        expect(session.timelineCalls.length).toBeGreaterThan(0);
        expect(result.current.itemsById.has("item-1200")).toBe(true);
        expect(result.current.gaps.previewCut).toBe(false);
      });

      it.each([
        ["a global limit", [{ source: "correlation", reason: "edge budget" }, fanOut("item-1200")], 2],
        ["a preview that does not show every gap", [fanOut("item-1200")], 301],
        ["a gap count that is not known", [fanOut("item-1200")], Number.NaN],
      ])("makes no scan for a session with no edge once %s already clears completeness", async (_why, gaps, total) => {
        const session = new FakeSession({ itemCount: 2_500, pairs: [], gaps, totalCoverageGaps: total });
        const props = session.props({ needItems: true });
        const { result } = renderHook(() => useEvtxCorrelation(props));
        await waitFor(() => expect(result.current.stage).toBe("ready"));
        // Attribution cannot make the answer complete, so no page is read for it.
        expect(session.timelineCalls).toEqual([]);
        expect(session.sleeps.filter((ms) => ms > 0)).toEqual([]);
        expect(result.current.itemsById.size).toBe(0);
        expect(result.current.gaps.originIds.has("item-1200")).toBe(true);
      });

      it("still reads the pages the edges need when the gaps already clear completeness", async () => {
        const session = new FakeSession({
          itemCount: 2_500,
          pairs: [[5, 2_400]],
          gaps: [{ source: "correlation", reason: "edge budget" }, fanOut("item-1200")],
          totalCoverageGaps: 2,
        });
        const props = session.props({ needItems: true });
        const { result } = renderHook(() => useEvtxCorrelation(props));
        await waitFor(() => expect(result.current.stage).toBe("ready"));
        expect(session.timelineCalls.length).toBeGreaterThan(0);
        expect(result.current.itemsById.has("item-5")).toBe(true);
        expect(result.current.itemsById.has("item-2400")).toBe(true);
        // The gap's own origin is not asked for: it could not change the answer.
        expect(result.current.itemsById.has("item-1200")).toBe(false);
      });
    });

    it("keeps the gaps of the model on show while a newer session loads", async () => {
      const one = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 1, gaps: [fanOut("item-7")], totalCoverageGaps: 1 });
      const two = new FakeSession({ itemCount: 2_500, pairs: [[5, 1_200]], revision: 2, gaps: [], totalCoverageGaps: 0 });
      const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
        initialProps: one.props({ needItems: true }),
      });
      await waitFor(() => expect(result.current.stage).toBe("ready"));
      const shown = result.current.gaps;
      expect(shown.originIds.has("item-7")).toBe(true);
      two.timelineGate = gate();
      rerender(two.props({ needItems: true }));
      await waitFor(() => expect(result.current.nextScan?.state).toBe("running"));
      expect(result.current.updating).toBe(true);
      expect(result.current.gaps).toBe(shown);
      act(() => two.timelineGate?.open());
      await waitFor(() => expect(result.current.builtFor).toBe(`${two.id}:2`));
      expect(result.current.gaps.originIds.size).toBe(0);
      expect(result.current.gaps.previewCut).toBe(false);
    });
  });

  it("gives the join the unplaced origins of the model's own page", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2]], unplacedCount: 3 });
    const props = session.props({ needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    const unplacedIds = [...result.current.unplaced.unplacedIds];
    expect(unplacedIds).toHaveLength(3);
    for (const id of unplacedIds) expect(result.current.origins.has(id)).toBe(true);
    // And the placed items' origins, for the members that were read.
    expect(result.current.origins.has("item-1")).toBe(true);
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
  /** Deps whose sleep throws on the given 1-based calls and otherwise returns at once. */
  function throwing(session: FakeSession, ...calls: number[]): Partial<CorrelationLoadDeps> {
    let count = 0;
    return {
      ...session.deps(),
      sleep: async () => {
        count += 1;
        if (calls.includes(count)) throw new Error("boom");
      },
    };
  }

  it("is shown, not swallowed", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2]] });
    const props = session.props({ deps: throwing(session, 1) });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.error).toBe("boom"));
  });

  it("is gone once a retry with only counts consumers publishes fresh counts (J2)", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2], [3, 4]] });
    const props = session.props({ deps: throwing(session, 1), needItems: false });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.error).toBe("boom"));
    expect(result.current.counts).toBeNull();

    act(() => result.current.retry());
    await waitFor(() => expect(result.current.counts?.model.counts.exact).toBe(2));
    expect(result.current.error).toBeNull();
    expect(result.current.stage).toBe("edgesOnly");
  });

  it("is gone when a live-tail revision publishes its counts (J2)", async () => {
    const one = new FakeSession({ itemCount: 50, pairs: [[1, 2]], revision: 1 });
    const two = new FakeSession({ itemCount: 50, pairs: [[1, 2], [3, 4], [5, 6]], revision: 2 });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: one.props({ deps: throwing(one, 1) }),
    });
    await waitFor(() => expect(result.current.error).toBe("boom"));
    rerender(two.props());
    await waitFor(() => expect(result.current.counts?.builtFor).toBe(`${two.id}:2`));
    expect(result.current.counts?.model.counts.exact).toBe(3);
    expect(result.current.error).toBeNull();
  });

  it("is gone when the counts of the session are reused after it (J2)", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2]] });
    // Call 1 builds the counts, call 2 is the scan's yield: it throws, so the error is set after
    // the counts are already cached.
    const base = session.props({ deps: throwing(session, 2), needItems: false });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: base,
    });
    await waitFor(() => expect(result.current.stage).toBe("edgesOnly"));
    rerender({ ...base, needItems: true });
    await waitFor(() => expect(result.current.error).toBe("boom"));
    expect(result.current.counts).not.toBeNull();

    rerender({ ...base, needItems: false });
    await waitFor(() => expect(result.current.error).toBeNull());
    expect(result.current.stage).toBe("edgesOnly");
  });

  it("is gone when the session ends and the next is being built (J2)", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2]] });
    const base = session.props({ deps: throwing(session, 2), needItems: true });
    const { result, rerender } = renderHook((props: UseEvtxCorrelationOptions) => useEvtxCorrelation(props), {
      initialProps: base,
    });
    await waitFor(() => expect(result.current.error).toBe("boom"));
    expect(result.current.counts).not.toBeNull();
    rerender({ ...NONE, pending: true });
    await waitFor(() => expect(result.current.stage).toBe("pending"));
    // The models of the old session stay, marked updating; the old run's message does not.
    expect(result.current.model).not.toBeNull();
    expect(result.current.updating).toBe(true);
    expect(result.current.error).toBeNull();
  });

  it("is replaced by a full model's success too", async () => {
    const session = new FakeSession({ itemCount: 50, pairs: [[1, 2]] });
    const props = session.props({ deps: throwing(session, 2), needItems: true });
    const { result } = renderHook(() => useEvtxCorrelation(props));
    await waitFor(() => expect(result.current.error).toBe("boom"));
    act(() => result.current.retry());
    await waitFor(() => expect(result.current.stage).toBe("ready"));
    expect(result.current.error).toBeNull();
  });
});

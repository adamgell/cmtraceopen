/**
 * Loading edges and linked items from an analysis session.
 *
 * `FakeSession` answers the two paged queries from in-memory arrays with the same shapes and
 * invariants the decoders in lib/commands.ts enforce (nextOffset, offsets, per-page totals), and
 * records every call, so a test can say what was NOT asked as well as what was.
 */
import { describe, expect, it, vi } from "vitest";
import type {
  EventLogAnalysisEdgePage,
  EventLogAnalysisSessionStatus,
  EventLogAnalysisTimelinePage,
} from "../../lib/commands";
import { buildCorrelationChains } from "./evtx-correlation-chains";
import {
  CORRELATION_EDGE_PAGE_SIZE,
  CorrelationLoadCancelled,
  edgeEndpointIds,
  knownTotal,
  loadAnalysisEdges,
  loadLinkedItems,
  modelEdgeTotal,
  type CorrelationLoadDeps,
} from "./evtx-correlation-load";
import {
  EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT,
  EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT,
  EVENT_LOG_TIMELINE_PAGE_SIZE,
} from "./evtx-timeline-paging";
import type { TimelineCorrelationEdge, TimelineItem } from "./unified-timeline";

const SESSION = "00000000-0000-4000-8000-000000000839";

function itemAt(index: number): TimelineItem {
  return {
    timestampMs: 1_000 * index,
    severity: "info",
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
      eventId: 100,
      recordId: index + 1,
    },
  };
}

function edgeAt(index: number, from = `item-${index * 2}`, to = `item-${index * 2 + 1}`): TimelineCorrelationEdge {
  return {
    id: `edge-${index}`,
    fromId: from,
    toId: to,
    key: { kind: "activityId", value: `k${index}` },
    strength: "exact",
    confidence: "high",
    candidateIds: [],
    evidence: [
      { originId: from, field: "activityId", value: `k${index}` },
      { originId: to, field: "activityId", value: `k${index}` },
    ],
    coverage: { state: "covered" },
  };
}

interface FakeOptions {
  itemCount: number;
  edgeCount: number;
  /** How many edges the first page's preview carries. */
  previewEdges?: number;
  revision?: number;
}

class FakeSession {
  readonly items: TimelineItem[];
  readonly edges: TimelineCorrelationEdge[];
  readonly timelineCalls: { offset: number; limit: number }[] = [];
  readonly edgeCalls: { offset: number; limit: number }[] = [];
  /** Reply tampering, by call index (0-based among that query's calls). */
  failTimeline = new Map<number, Error | ((page: EventLogAnalysisTimelinePage) => EventLogAnalysisTimelinePage)>();
  failEdges = new Map<number, Error | ((page: EventLogAnalysisEdgePage) => EventLogAnalysisEdgePage)>();
  readonly revision: number;
  readonly previewEdges: number;

  constructor(options: FakeOptions) {
    this.items = Array.from({ length: options.itemCount }, (_, i) => itemAt(i));
    this.edges = Array.from({ length: options.edgeCount }, (_, i) => edgeAt(i));
    this.revision = options.revision ?? 1;
    this.previewEdges = options.previewEdges ?? options.edgeCount;
  }

  status(): EventLogAnalysisSessionStatus {
    return {
      sessionId: SESSION,
      revision: this.revision,
      totalItems: this.items.length,
      eventItems: this.items.length,
      logItems: 0,
      totalUnplaced: 0,
      totalEdges: this.edges.length,
      totalCoverageGaps: 0,
      finalized: true,
    };
  }

  page(offset: number, limit: number): EventLogAnalysisTimelinePage {
    const slice = this.items.slice(offset, offset + limit);
    const end = offset + slice.length;
    const { finalized: _finalized, ...status } = this.status();
    return {
      ...status,
      offset,
      nextOffset: end < this.items.length ? end : null,
      serializedBytes: Math.max(1, slice.length * 100),
      items: slice,
      unplacedPreview: [],
      edgesPreview: offset === 0 ? this.edges.slice(0, this.previewEdges) : [],
      coverageGapsPreview: [],
    };
  }

  deps(): CorrelationLoadDeps {
    return {
      queryTimelinePage: async (sessionId, offset, limit) => {
        const call = this.timelineCalls.length;
        this.timelineCalls.push({ offset, limit });
        const tamper = this.failTimeline.get(call);
        if (tamper instanceof Error) throw tamper;
        expect(sessionId).toBe(SESSION);
        const page = this.page(offset, limit);
        return tamper ? tamper(page) : page;
      },
      queryEdgePage: async (sessionId, offset, limit) => {
        const call = this.edgeCalls.length;
        this.edgeCalls.push({ offset, limit });
        const tamper = this.failEdges.get(call);
        if (tamper instanceof Error) throw tamper;
        expect(sessionId).toBe(SESSION);
        const slice = this.edges.slice(offset, offset + limit);
        const end = offset + slice.length;
        const page: EventLogAnalysisEdgePage = {
          sessionId: SESSION,
          revision: this.revision,
          offset,
          nextOffset: end < this.edges.length ? end : null,
          totalEdges: this.edges.length,
          edges: slice,
          serializedBytes: Math.max(1, slice.length * 50),
        };
        return tamper ? tamper(page) : page;
      },
      sleep: this.sleep,
    };
  }

  readonly sleeps: number[] = [];
  readonly sleep = async (ms: number) => {
    this.sleeps.push(ms);
  };
}

const never = () => false;

describe("knownTotal and modelEdgeTotal", () => {
  it("trusts only a non-negative safe integer", () => {
    expect(knownTotal(0)).toBe(0);
    expect(knownTotal(7)).toBe(7);
    for (const bad of [-1, 1.5, Number.NaN, Infinity, Number.MAX_SAFE_INTEGER + 2, "3", null, undefined]) {
      expect(knownTotal(bad), String(bad)).toBeNull();
    }
  });

  it("gives the model a non-finite total for an unknown one, never 0", () => {
    expect(modelEdgeTotal(null)).toBeNaN();
    expect(modelEdgeTotal(0)).toBe(0);
    expect(modelEdgeTotal(5)).toBe(5);
  });
});

describe("edgeEndpointIds", () => {
  it("names both endpoints and every candidate of an ambiguous relation, once", () => {
    const ids = edgeEndpointIds([
      edgeAt(0, "a", "b"),
      { ...edgeAt(1, "a", "c"), candidateIds: ["b", "d"] },
      { ...edgeAt(2, "e", "f"), toId: null },
    ]);
    // The third relation has no second endpoint, so only "e" is named.
    expect([...ids].sort()).toEqual(["a", "b", "c", "d", "e"]);
  });
});

describe("loadAnalysisEdges", () => {
  it("makes no call when the preview holds every edge the same reply counts", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 4 });
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.edgeCalls).toEqual([]);
    expect(loaded).toMatchObject({ totalEdges: 4, complete: true, error: null });
    expect(loaded.edges).toEqual(session.edges);
  });

  it("is complete with no edges when the session holds none, which is a total of 0 it was told", async () => {
    const session = new FakeSession({ itemCount: 3, edgeCount: 0 });
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded).toEqual({ edges: [], totalEdges: 0, complete: true, error: null });
  });

  it("treats a missing session as unknown, with no total and no call", async () => {
    const session = new FakeSession({ itemCount: 3, edgeCount: 5, previewEdges: 2 });
    for (const [status, initialPage] of [
      [null, session.page(0, 1000)],
      [session.status(), null],
      [null, null],
    ] as const) {
      const loaded = await loadAnalysisEdges({
        status,
        initialPage,
        isCancelled: never,
        deps: session.deps(),
      });
      expect(loaded).toEqual({ edges: [], totalEdges: null, complete: false, error: null });
      // The model reads that as an incomplete input, not as a complete empty one.
      const model = buildCorrelationChains({
        items: [],
        timelineEdges: loaded.edges,
        totalTimelineEdges: modelEdgeTotal(loaded.totalEdges),
        findings: [],
      });
      expect(model.edgeInputComplete).toBe(false);
    }
    expect(session.edgeCalls).toEqual([]);
  });

  it("does not use a first page that belongs to another revision", async () => {
    const session = new FakeSession({ itemCount: 3, edgeCount: 2 });
    const loaded = await loadAnalysisEdges({
      status: { ...session.status(), revision: 2 },
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded).toEqual({ edges: [], totalEdges: null, complete: false, error: null });
  });

  it("reads a total that is not a count as unknown and never as complete or as 0", async () => {
    const session = new FakeSession({ itemCount: 3, edgeCount: 2 });
    for (const bad of [Number.NaN, -3, 2.5, Infinity]) {
      const loaded = await loadAnalysisEdges({
        status: session.status(),
        initialPage: { ...session.page(0, 1000), totalEdges: bad },
        isCancelled: never,
        deps: session.deps(),
      });
      expect(loaded.totalEdges, String(bad)).toBeNull();
      expect(loaded.complete, String(bad)).toBe(false);
      expect(session.edgeCalls).toEqual([]);
      const model = buildCorrelationChains({
        items: [],
        timelineEdges: loaded.edges,
        totalTimelineEdges: modelEdgeTotal(loaded.totalEdges),
        findings: [],
      });
      expect(model.edgeInputComplete, String(bad)).toBe(false);
      expect(model.unloadedEdgeCount, String(bad)).toBe(0);
    }
  });

  it("pages the rest from the end of the preview, in order, until the reply says it is done", async () => {
    const session = new FakeSession({
      itemCount: 10,
      edgeCount: CORRELATION_EDGE_PAGE_SIZE * 2 + 110,
      previewEdges: 100,
    });
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.edgeCalls).toEqual([
      { offset: 100, limit: CORRELATION_EDGE_PAGE_SIZE },
      { offset: 1100, limit: CORRELATION_EDGE_PAGE_SIZE },
      { offset: 2100, limit: CORRELATION_EDGE_PAGE_SIZE },
    ]);
    expect(loaded.edges).toEqual(session.edges);
    expect(loaded).toMatchObject({ complete: true, totalEdges: session.edges.length, error: null });
  });

  it("pages from 0 when the preview came back empty but the session counts edges", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 5, previewEdges: 0 });
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.edgeCalls).toEqual([{ offset: 0, limit: CORRELATION_EDGE_PAGE_SIZE }]);
    expect(loaded.complete).toBe(true);
  });

  describe("takes each total from the reply it arrived with (#839 comment 1)", () => {
    const load = async (total: number) => {
      const session = new FakeSession({ itemCount: 10, edgeCount: 50, previewEdges: 10 });
      session.failEdges.set(0, (page) => ({ ...page, totalEdges: total }));
      const loaded = await loadAnalysisEdges({
        status: session.status(),
        initialPage: session.page(0, 1000),
        isCancelled: never,
        deps: session.deps(),
      });
      return { loaded, session };
    };
    const modelOf = (loaded: { edges: TimelineCorrelationEdge[]; totalEdges: number | null }) =>
      buildCorrelationChains({
        items: [],
        timelineEdges: loaded.edges,
        totalTimelineEdges: modelEdgeTotal(loaded.totalEdges),
        findings: [],
      });

    it("replaces the preview's total with a different finite one from a later reply", async () => {
      const { loaded } = await load(52);
      expect(loaded.edges).toHaveLength(50);
      // 52 is the reply's own count, not the preview's 50: two edges are still missing.
      expect(loaded.totalEdges).toBe(52);
      expect(loaded.complete).toBe(false);
      const model = modelOf(loaded);
      expect(model.edgeInputComplete).toBe(false);
      expect(model.unloadedEdgeCount).toBe(2);
    });

    it("takes a total below what was loaded as it is, and is not complete", async () => {
      const { loaded } = await load(45);
      expect(loaded.totalEdges).toBe(45);
      expect(loaded.complete).toBe(false);
      expect(modelOf(loaded).edgeInputComplete).toBe(false);
    });

    it.each([Number.NaN, Infinity, -1, 3.5])(
      "does not keep the preview's total over a reply whose total is %s: it is unknown",
      async (total) => {
        const { loaded } = await load(total);
        expect(loaded.edges).toHaveLength(50);
        expect(loaded.totalEdges).toBeNull();
        expect(loaded.complete).toBe(false);
        const model = modelOf(loaded);
        expect(model.edgeInputComplete).toBe(false);
        expect(model.unloadedEdgeCount).toBe(0);
      },
    );

    it("is complete when the reply's total equals what was loaded", async () => {
      const { loaded } = await load(50);
      expect(loaded).toMatchObject({ totalEdges: 50, complete: true });
    });
  });

  it("stops on a reply for another revision, keeps what it had, and is not complete", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 50, previewEdges: 10 });
    session.failEdges.set(0, (page) => ({ ...page, revision: 9 }));
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded.edges).toHaveLength(10);
    expect(loaded.complete).toBe(false);
    expect(loaded.error).toBe("The event-log analysis session changed while paging.");
    // The total is the one the preview came with, not 0 and not the stale reply's.
    expect(loaded.totalEdges).toBe(50);
  });

  it("stops on a reply for another offset", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 50, previewEdges: 10 });
    session.failEdges.set(0, (page) => ({ ...page, offset: 0 }));
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded.error).toBe("The event-log analysis returned the wrong page.");
    expect(loaded.edges).toHaveLength(10);
  });

  it("retries a failed page with the unified timeline's backoff and then succeeds", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 50, previewEdges: 10 });
    session.failEdges.set(0, new Error("busy"));
    session.failEdges.set(1, new Error("busy"));
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.sleeps).toEqual([100, 200]);
    expect(session.edgeCalls).toHaveLength(3);
    expect(loaded).toMatchObject({ complete: true, error: null });
  });

  it("gives up after the retry limit, returns what it has, and says why", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 50, previewEdges: 10 });
    for (let call = 0; call <= EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT; call += 1) {
      session.failEdges.set(call, new Error("gone"));
    }
    const loaded = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.edgeCalls).toHaveLength(EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT + 1);
    expect(loaded.edges).toHaveLength(10);
    expect(loaded).toMatchObject({ complete: false, error: "gone", totalEdges: 50 });
  });

  it("feeds the model so a short preview reads as paged and bounded, and a full load as complete", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 50, previewEdges: 10 });
    const shortOnly = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: { ...session.deps(), queryEdgePage: async () => Promise.reject(new Error("down")) },
    });
    const short = buildCorrelationChains({
      items: [],
      timelineEdges: shortOnly.edges,
      totalTimelineEdges: modelEdgeTotal(shortOnly.totalEdges),
      findings: [],
    });
    expect(short.edgeInputComplete).toBe(false);
    expect(short.unloadedEdgeCount).toBe(40);

    const full = await loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: never,
      deps: session.deps(),
    });
    const whole = buildCorrelationChains({
      items: [],
      timelineEdges: full.edges,
      totalTimelineEdges: modelEdgeTotal(full.totalEdges),
      findings: [],
    });
    expect(whole.edgeInputComplete).toBe(true);
    expect(whole.unloadedEdgeCount).toBe(0);
  });

  it("throws as cancelled, before any call and between pages", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 3000, previewEdges: 10 });
    await expect(
      loadAnalysisEdges({
        status: session.status(),
        initialPage: session.page(0, 1000),
        isCancelled: () => true,
        deps: session.deps(),
      }),
    ).rejects.toBeInstanceOf(CorrelationLoadCancelled);
    expect(session.edgeCalls).toEqual([]);

    let cancelled = false;
    const deps = session.deps();
    const result = loadAnalysisEdges({
      status: session.status(),
      initialPage: session.page(0, 1000),
      isCancelled: () => cancelled,
      deps: {
        ...deps,
        queryEdgePage: async (...args) => {
          const page = await deps.queryEdgePage(...args);
          cancelled = true;
          return page;
        },
      },
    });
    await expect(result).rejects.toBeInstanceOf(CorrelationLoadCancelled);
    expect(session.edgeCalls).toHaveLength(1);
  });
});

describe("a reply that arrives after the load was superseded is never returned", () => {
  it("rejects when edges are cancelled during their last call", async () => {
    const session = new FakeSession({ itemCount: 10, edgeCount: 50, previewEdges: 10 });
    let cancelled = false;
    const deps = session.deps();
    await expect(
      loadAnalysisEdges({
        status: session.status(),
        initialPage: session.page(0, 1000),
        isCancelled: () => cancelled,
        deps: {
          ...deps,
          queryEdgePage: async (...args) => {
            const page = await deps.queryEdgePage(...args);
            cancelled = true;
            return page;
          },
        },
      }),
    ).rejects.toBeInstanceOf(CorrelationLoadCancelled);
  });

  it("rejects when the scan is cancelled during its last call", async () => {
    const session = new FakeSession({ itemCount: 1_500, edgeCount: 0 });
    let cancelled = false;
    const deps = session.deps();
    await expect(
      loadLinkedItems({
        status: session.status(),
        initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
        wantedIds: new Set(["item-1"]),
        isCancelled: () => cancelled,
        deps: {
          ...deps,
          queryTimelinePage: async (...args) => {
            const page = await deps.queryTimelinePage(...args);
            cancelled = true;
            return page;
          },
        },
      }),
    ).rejects.toBeInstanceOf(CorrelationLoadCancelled);
  });
});

describe("loadLinkedItems", () => {
  const ids = (...indices: number[]) => new Set(indices.map((i) => `item-${i}`));

  it("reads a one-page timeline from the first page and makes no call", async () => {
    const session = new FakeSession({ itemCount: 50, edgeCount: 0 });
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(3, 7, 999),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.timelineCalls).toEqual([]);
    expect(loaded.items.map((item) => item.message)).toEqual(["message 3", "message 7"]);
    expect(loaded).toMatchObject({ complete: true, scannedItems: 50, totalItems: 50, error: null });
  });

  it("scans every following page in order and keeps only the wanted items", async () => {
    const session = new FakeSession({ itemCount: 2_500, edgeCount: 0 });
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(5, 1_200, 2_499),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.timelineCalls).toEqual([
      { offset: 1_000, limit: EVENT_LOG_TIMELINE_PAGE_SIZE },
      { offset: 2_000, limit: EVENT_LOG_TIMELINE_PAGE_SIZE },
    ]);
    expect(loaded.items.map((item) => item.message)).toEqual([
      "message 5",
      "message 1200",
      "message 2499",
    ]);
    expect(loaded).toMatchObject({ complete: true, scannedItems: 2_500, stoppedBy: null });
    // Only wanted items are kept: the rest of the 2,500 were dropped as they were read.
    expect(loaded.items).toHaveLength(3);
  });

  it("does not claim an id that is missing is unplaced unless the scan completed", async () => {
    const session = new FakeSession({ itemCount: 2_500, edgeCount: 0 });
    session.failTimeline.set(0, new Error("down"));
    session.failTimeline.set(1, new Error("down"));
    session.failTimeline.set(2, new Error("down"));
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(5, 1_200),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded.complete).toBe(false);
    expect(loaded.stoppedBy).toBe("error");
    expect(loaded.error).toBe("down");
    // The first page was read; the second was not, so item 1200 is simply not read yet.
    expect(loaded.items.map((item) => item.message)).toEqual(["message 5"]);
    expect(loaded.scannedItems).toBe(1_000);
  });

  it("stops at the byte budget and says so, without calling further", async () => {
    const session = new FakeSession({ itemCount: 4_000, edgeCount: 0 });
    // Every item is wanted; 100 bytes each, so 1,000 items is 100,000 bytes a page.
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: new Set(session.items.map((item) => (item.origin as { stableId: string }).stableId)),
      byteBudget: 150_000,
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.timelineCalls).toEqual([{ offset: 1_000, limit: EVENT_LOG_TIMELINE_PAGE_SIZE }]);
    expect(loaded.stoppedBy).toBe("budget");
    expect(loaded.complete).toBe(false);
    expect(loaded.retainedBytes).toBe(200_000);
    expect(loaded.items).toHaveLength(2_000);
  });

  it("stops on the first page when that alone is over budget", async () => {
    const session = new FakeSession({ itemCount: 2_000, edgeCount: 0 });
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: new Set(session.items.map((item) => (item.origin as { stableId: string }).stableId)),
      byteBudget: 10,
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.timelineCalls).toEqual([]);
    expect(loaded.stoppedBy).toBe("budget");
  });

  it("bounds what it keeps by the shared cache limit when no budget is given", async () => {
    const session = new FakeSession({ itemCount: 2_000, edgeCount: 0 });
    // One page whose kept share alone is one byte over the limit every timeline consumer shares.
    const heavy = { ...session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE), serializedBytes: EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT + 1 };
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: heavy,
      wantedIds: new Set(session.items.map((item) => (item.origin as { stableId: string }).stableId)),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded.stoppedBy).toBe("budget");
    expect(session.timelineCalls).toEqual([]);
    // And just under the limit it goes on reading.
    const light = { ...session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE), serializedBytes: EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT / 2 };
    const more = await loadLinkedItems({
      status: session.status(),
      initialPage: light,
      wantedIds: ids(5),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(more.stoppedBy).toBeNull();
  });

  it("estimates kept bytes from the share of each page that was kept", async () => {
    const session = new FakeSession({ itemCount: 1_000, edgeCount: 0 });
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(1, 2, 3, 4),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded.retainedBytes).toBe(400);
  });

  it("makes no call and keeps nothing when nothing is wanted, which is complete", async () => {
    const session = new FakeSession({ itemCount: 5_000, edgeCount: 0 });
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: new Set(),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(session.timelineCalls).toEqual([]);
    expect(loaded).toMatchObject({ items: [], complete: true, scannedItems: 0 });
  });

  it("is incomplete, with nothing read, when there is no usable session", async () => {
    const session = new FakeSession({ itemCount: 50, edgeCount: 0 });
    for (const [status, initialPage] of [
      [null, session.page(0, 1000)],
      [session.status(), null],
      [{ ...session.status(), revision: 4 }, session.page(0, 1000)],
    ] as const) {
      const loaded = await loadLinkedItems({
        status,
        initialPage,
        wantedIds: ids(1),
        isCancelled: never,
        deps: session.deps(),
      });
      expect(loaded.complete).toBe(false);
      expect(loaded.items).toEqual([]);
    }
    expect(session.timelineCalls).toEqual([]);
  });

  it("reports progress after every page, ending at the total", async () => {
    const session = new FakeSession({ itemCount: 2_500, edgeCount: 0 });
    const progress = vi.fn();
    await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(5),
      isCancelled: never,
      onProgress: progress,
      deps: session.deps(),
    });
    expect(progress.mock.calls.map(([p]) => p.scannedItems)).toEqual([1_000, 2_000, 2_500]);
    expect(progress.mock.lastCall?.[0]).toEqual({
      scannedItems: 2_500,
      totalItems: 2_500,
      retainedItems: 1,
    });
  });

  it("stops at once when cancelled between pages, and makes no further call", async () => {
    const session = new FakeSession({ itemCount: 5_000, edgeCount: 0 });
    let cancelled = false;
    const deps = session.deps();
    const run = loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(5),
      isCancelled: () => cancelled,
      deps: {
        ...deps,
        queryTimelinePage: async (...args) => {
          const page = await deps.queryTimelinePage(...args);
          cancelled = true;
          return page;
        },
      },
    });
    await expect(run).rejects.toBeInstanceOf(CorrelationLoadCancelled);
    expect(session.timelineCalls).toHaveLength(1);
  });

  it("does not start when already cancelled", async () => {
    const session = new FakeSession({ itemCount: 5_000, edgeCount: 0 });
    await expect(
      loadLinkedItems({
        status: session.status(),
        initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
        wantedIds: ids(5),
        isCancelled: () => true,
        deps: session.deps(),
      }),
    ).rejects.toBeInstanceOf(CorrelationLoadCancelled);
    expect(session.timelineCalls).toEqual([]);
  });

  it("stops on a page from another session revision or offset, and is not complete", async () => {
    for (const tamper of [
      (page: EventLogAnalysisTimelinePage) => ({ ...page, revision: 9 }),
      (page: EventLogAnalysisTimelinePage) => ({ ...page, offset: 0 }),
    ]) {
      const session = new FakeSession({ itemCount: 2_500, edgeCount: 0 });
      session.failTimeline.set(0, tamper);
      const loaded = await loadLinkedItems({
        status: session.status(),
        initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
        wantedIds: ids(5, 1_200),
        isCancelled: never,
        deps: session.deps(),
      });
      expect(loaded.complete).toBe(false);
      expect(loaded.stoppedBy).toBe("error");
      expect(loaded.items.map((item) => item.message)).toEqual(["message 5"]);
    }
  });

  it("is not complete when the pages add up to fewer items than the session counts", async () => {
    const session = new FakeSession({ itemCount: 2_500, edgeCount: 0 });
    session.failTimeline.set(1, (page) => ({ ...page, nextOffset: null, items: page.items.slice(0, 10) }));
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(5),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded.complete).toBe(false);
    expect(loaded.error).toMatch(/read 2010 of 2500 items/);
  });

  it("refuses a page that makes no progress", async () => {
    const session = new FakeSession({ itemCount: 2_500, edgeCount: 0 });
    session.failTimeline.set(0, (page) => ({ ...page, nextOffset: page.offset }));
    const loaded = await loadLinkedItems({
      status: session.status(),
      initialPage: session.page(0, EVENT_LOG_TIMELINE_PAGE_SIZE),
      wantedIds: ids(5),
      isCancelled: never,
      deps: session.deps(),
    });
    expect(loaded.stoppedBy).toBe("error");
    expect(session.timelineCalls).toHaveLength(1);
  });
});

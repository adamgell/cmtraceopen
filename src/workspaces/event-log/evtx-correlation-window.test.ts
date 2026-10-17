/**
 * Reading the items around one instant from an analysis session.
 *
 * `FakeEngine` answers the window and page queries from one sorted array, with the replies the
 * real engine gives (analysis_session.rs `window` and `page`, and the invariants the decoders in
 * lib/commands.ts enforce): a closed interval, a limit, a per-reply cap that stands for the byte
 * budget, `windowItems`, `omittedItems` and `nextOffset`. It records every call, so a test can say
 * what was NOT asked as well as what was.
 */
import { describe, expect, it } from "vitest";
import type {
  EventLogAnalysisTimelinePage,
  EventLogAnalysisTimelineWindow,
} from "../../lib/commands";
import {
  queryEventLogAnalysisTimeline,
  queryEventLogAnalysisTimelineWindow,
} from "../../lib/commands";
import { CorrelationLoadCancelled } from "./evtx-correlation-load";
import {
  CORRELATION_WINDOW_LIMIT,
  CORRELATION_WINDOW_MAX_CALLS,
  DEFAULT_CORRELATION_WINDOW_DEPS,
  loadCorrelationWindow,
  type CorrelationWindowDeps,
  type LoadCorrelationWindowInput,
} from "./evtx-correlation-window";
import { EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT } from "./evtx-timeline-paging";
import type { TimelineItem } from "./unified-timeline";

const SESSION = "00000000-0000-4000-8000-000000000842";
const STATUS = { sessionId: SESSION, revision: 2 };
const CENTER = 1_000_000;

function itemAt(id: number, timestampMs: number): TimelineItem {
  return {
    timestampMs,
    severity: "info",
    message: `message ${id}`,
    origin: {
      kind: "event",
      stableId: `item-${id}`,
      source: "Live",
      machine: "HOST",
      bundle: null,
      channel: "System",
      provider: "P",
      processId: null,
      eventId: 100,
      recordId: id + 1,
    },
  };
}
const idOf = (item: TimelineItem) =>
  item.origin.kind === "event" ? item.origin.stableId : "log";

interface EngineOptions {
  /** Timestamps in ascending order; item `i` is `itemAt(i, timestamps[i])`. */
  timestamps: number[];
  /** Most rows any one reply carries: the byte budget, in rows. */
  replyCap?: number;
  revision?: number;
}

class FakeEngine {
  readonly items: TimelineItem[];
  readonly windowCalls: { startMs: number; endMs: number; limit: number }[] = [];
  readonly pageCalls: { offset: number; limit: number }[] = [];
  readonly sleeps: number[] = [];
  readonly revision: number;
  private readonly cap: number;
  /** Tampers with the reply to a window call, by 0-based call index. */
  tamperWindow = new Map<
    number,
    Error | ((reply: EventLogAnalysisTimelineWindow) => EventLogAnalysisTimelineWindow)
  >();
  /** Tampers with the reply to a page call, by 0-based call index. */
  tamperPage = new Map<
    number,
    Error | ((reply: EventLogAnalysisTimelinePage) => EventLogAnalysisTimelinePage)
  >();
  /** Bytes each reply reports. */
  bytesPerReply = 1_000;

  constructor(options: EngineOptions) {
    this.items = options.timestamps.map((timestamp, i) => itemAt(i, timestamp));
    this.cap = options.replyCap ?? Number.MAX_SAFE_INTEGER;
    this.revision = options.revision ?? STATUS.revision;
  }

  window(startMs: number, endMs: number, limit: number): EventLogAnalysisTimelineWindow {
    const first = this.items.findIndex((item) => item.timestampMs >= startMs);
    const afterLast = this.items.filter((item) => item.timestampMs <= endMs).length;
    const begin = first < 0 ? this.items.length : first;
    const inWindow = Math.max(0, afterLast - begin);
    const taken = Math.min(limit, inWindow, this.cap);
    const end = begin + taken;
    return {
      sessionId: SESSION,
      revision: this.revision,
      startMs,
      endMs,
      offset: begin,
      nextOffset: taken < inWindow ? end : null,
      totalItems: this.items.length,
      windowItems: inWindow,
      omittedItems: inWindow - taken,
      items: this.items.slice(begin, end),
      serializedBytes: this.bytesPerReply,
    };
  }

  page(offset: number, limit: number): EventLogAnalysisTimelinePage {
    const taken = Math.min(limit, this.cap);
    const slice = this.items.slice(offset, offset + taken);
    const end = offset + slice.length;
    return {
      sessionId: SESSION,
      revision: this.revision,
      offset,
      nextOffset: end < this.items.length ? end : null,
      totalItems: this.items.length,
      eventItems: this.items.length,
      logItems: 0,
      totalUnplaced: 0,
      totalEdges: 0,
      totalCoverageGaps: 0,
      items: slice,
      unplacedPreview: [],
      edgesPreview: [],
      coverageGapsPreview: [],
      serializedBytes: this.bytesPerReply,
    };
  }

  deps(): Partial<CorrelationWindowDeps> {
    return {
      sleep: async (ms) => {
        this.sleeps.push(ms);
      },
      queryWindow: async (_sessionId, startMs, endMs, limit) => {
        const index = this.windowCalls.length;
        this.windowCalls.push({ startMs, endMs, limit });
        const tamper = this.tamperWindow.get(index);
        if (tamper instanceof Error) throw tamper;
        const reply = this.window(startMs, endMs, limit);
        return tamper === undefined ? reply : tamper(reply);
      },
      queryTimelinePage: async (_sessionId, offset, limit) => {
        const index = this.pageCalls.length;
        this.pageCalls.push({ offset, limit });
        const tamper = this.tamperPage.get(index);
        if (tamper instanceof Error) throw tamper;
        const reply = this.page(offset, limit);
        return tamper === undefined ? reply : tamper(reply);
      },
    };
  }

  load(overrides: Partial<LoadCorrelationWindowInput> = {}) {
    return loadCorrelationWindow({
      status: STATUS,
      centerMs: CENTER,
      halfWidthMs: 75_000,
      isCancelled: () => false,
      deps: this.deps(),
      ...overrides,
    });
  }
}

/** `count` timestamps, one per second, starting `before` seconds before the center. */
function everySecond(count: number, before = 0): number[] {
  return Array.from({ length: count }, (_, i) => CENTER - before * 1_000 + i * 1_000);
}

describe("what it asks for", () => {
  it("asks the closed interval around the center, with the most rows one call can return", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(10) });
    await engine.load({ halfWidthMs: 30_000 });
    expect(engine.windowCalls).toEqual([
      { startMs: CENTER - 30_000, endMs: CENTER + 30_000, limit: CORRELATION_WINDOW_LIMIT },
    ]);
    expect(CORRELATION_WINDOW_LIMIT).toBe(1_000);
  });

  it("passes a smaller limit through, for a reader that wants only the nearest few", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(10) });
    await engine.load({ limit: 4 });
    expect(engine.windowCalls[0]?.limit).toBe(4);
  });

  it("uses the commands' own queries by default", () => {
    expect(DEFAULT_CORRELATION_WINDOW_DEPS.queryWindow).toBe(queryEventLogAnalysisTimelineWindow);
    expect(DEFAULT_CORRELATION_WINDOW_DEPS.queryTimelinePage).toBe(queryEventLogAnalysisTimeline);
  });

  it("is keyed by the session and revision it read, with the window it answered", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(3) });
    const loaded = await engine.load({ halfWidthMs: 120_000 });
    expect(loaded).toMatchObject({
      sessionKey: `${SESSION}:2`,
      centerMs: CENTER,
      halfWidthMs: 120_000,
      startMs: CENTER - 120_000,
      endMs: CENTER + 120_000,
    });
  });
});

describe("a window the first reply holds whole", () => {
  it("returns every item with one call, complete, and its exact count", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(10, 5) });
    const loaded = await engine.load();
    expect(loaded.items.map(idOf)).toEqual(engine.items.map(idOf));
    expect(loaded).toMatchObject({
      windowItems: 10,
      omittedItems: 0,
      complete: true,
      stoppedBy: null,
      error: null,
      calls: 1,
    });
    expect(engine.pageCalls).toEqual([]);
  });

  it("includes an item exactly on either bound, and none just outside", async () => {
    const engine = new FakeEngine({
      timestamps: [CENTER - 75_001, CENTER - 75_000, CENTER, CENTER + 75_000, CENTER + 75_001],
    });
    const loaded = await engine.load();
    expect(loaded.items.map(idOf)).toEqual(["item-1", "item-2", "item-3"]);
    expect(loaded.windowItems).toBe(3);
  });

  it("says an empty window is empty, with a count of 0 the engine gave, and complete", async () => {
    const engine = new FakeEngine({ timestamps: [CENTER - 900_000, CENTER + 900_000] });
    const loaded = await engine.load();
    expect(loaded).toMatchObject({ items: [], windowItems: 0, omittedItems: 0, complete: true, calls: 1 });
  });
});

describe("a window the first reply cut short", () => {
  it("continues from nextOffset with the rows still remaining, until none is", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(2_500) });
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(loaded.items.map(idOf)).toEqual(engine.items.map(idOf));
    expect(engine.pageCalls).toEqual([
      { offset: 1_000, limit: 1_000 },
      { offset: 2_000, limit: 500 },
    ]);
    expect(loaded).toMatchObject({ windowItems: 2_500, omittedItems: 0, complete: true, calls: 3 });
  });

  it("clips the last page to the rows remaining, so nothing past the window is read", async () => {
    // 1,300 in-window rows, then 600 after the window ends. A page asked for 1,000 would reach them.
    const inWindow = everySecond(1_300);
    const after = Array.from({ length: 600 }, (_, i) => CENTER + 5_000_000 + i);
    const engine = new FakeEngine({ timestamps: [...inWindow, ...after] });
    const loaded = await engine.load({ halfWidthMs: 2_000_000 });
    expect(engine.pageCalls).toEqual([{ offset: 1_000, limit: 300 }]);
    expect(loaded.items).toHaveLength(1_300);
    expect(loaded.complete).toBe(true);
    expect(loaded.items.every((item) => item.timestampMs <= CENTER + 2_000_000)).toBe(true);
  });

  it("reads rows tied on the cut timestamp exactly once each, never by windowing again", async () => {
    // Twelve rows share one timestamp and the first reply cuts through them.
    const tied = Array.from({ length: 12 }, () => CENTER);
    const engine = new FakeEngine({
      timestamps: [...everySecond(5, 10).map((t) => t - 20_000), ...tied, CENTER + 1_000, CENTER + 2_000],
      replyCap: 9,
    });
    const loaded = await engine.load();
    expect(loaded.items.map(idOf)).toEqual(engine.items.map(idOf));
    expect(new Set(loaded.items.map(idOf)).size).toBe(loaded.items.length);
    expect(engine.windowCalls).toHaveLength(1);
  });

  it("keeps going when a byte-cut page is shorter than the rows asked for", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(700, 300), replyCap: 250 });
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(loaded.items.map(idOf)).toEqual(engine.items.map(idOf));
    expect(loaded).toMatchObject({ complete: true, windowItems: 700, calls: 3 });
    expect(engine.pageCalls.map((call) => call.offset)).toEqual([250, 500]);
    expect(engine.pageCalls.map((call) => call.limit)).toEqual([450, 200]);
  });
});

describe("a read that stops before it has the window", () => {
  it("stops at the call limit and says exactly how many in-window items it did not read", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(2_500), replyCap: 100 });
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(CORRELATION_WINDOW_MAX_CALLS).toBe(6);
    expect(engine.windowCalls).toHaveLength(1);
    expect(engine.pageCalls).toHaveLength(CORRELATION_WINDOW_MAX_CALLS - 1);
    expect(loaded).toMatchObject({
      complete: false,
      stoppedBy: "callLimit",
      error: null,
      windowItems: 2_500,
      omittedItems: 1_900,
      calls: 6,
    });
    expect(loaded.items).toHaveLength(600);
    expect(loaded.items.map(idOf)).toEqual(engine.items.slice(0, 600).map(idOf));
  });

  it("is complete, not stopped, when the last allowed call finishes the window", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(600), replyCap: 100 });
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(loaded).toMatchObject({ complete: true, stoppedBy: null, calls: 6, omittedItems: 0 });
  });

  it("stops at the byte budget before the next call, and keeps what it read", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(500), replyCap: 100 });
    engine.bytesPerReply = 600;
    const loaded = await engine.load({ halfWidthMs: 5_000_000, byteBudget: 1_000 });
    expect(loaded).toMatchObject({
      complete: false,
      stoppedBy: "budget",
      windowItems: 500,
      omittedItems: 300,
      retainedBytes: 1_200,
      calls: 2,
    });
    expect(loaded.items).toHaveLength(200);
  });

  it("is complete when the page that crosses the budget also finishes the window", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(200), replyCap: 100 });
    engine.bytesPerReply = 600;
    const loaded = await engine.load({ halfWidthMs: 5_000_000, byteBudget: 1_000 });
    expect(loaded).toMatchObject({ complete: true, stoppedBy: null, omittedItems: 0 });
  });

  it("stops on a failed page after the retries, keeps the items it read, and keeps the count", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperPage.set(0, new Error("timeline down"));
    engine.tamperPage.set(1, new Error("timeline down"));
    engine.tamperPage.set(2, new Error("timeline down"));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(loaded).toMatchObject({
      complete: false,
      stoppedBy: "error",
      error: "timeline down",
      windowItems: 300,
      omittedItems: 200,
    });
    expect(loaded.items).toHaveLength(100);
    expect(engine.pageCalls).toHaveLength(EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT + 1);
  });

  it("retries a transient failure with the unified timeline's backoff, and then completes", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperWindow.set(0, new Error("one"));
    engine.tamperPage.set(0, new Error("two"));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(loaded).toMatchObject({ complete: true, windowItems: 300 });
    expect(engine.sleeps).toEqual([100, 100]);
  });

  it("refuses a page that makes no progress instead of asking for it again", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperPage.set(0, (reply) => ({ ...reply, items: [], nextOffset: reply.offset }));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(loaded.complete).toBe(false);
    expect(loaded.stoppedBy).toBe("error");
    expect(loaded.error).toMatch(/no progress/);
    expect(engine.pageCalls).toHaveLength(1);
    expect(loaded.items).toHaveLength(100);
  });

  it("refuses a page whose nextOffset does not follow its rows", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperPage.set(0, (reply) => ({ ...reply, nextOffset: reply.offset }));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    expect(loaded.stoppedBy).toBe("error");
    expect(loaded.error).toMatch(/no progress/);
    expect(engine.pageCalls).toHaveLength(1);
  });
});

describe("a reply for a session that is not the one asked about", () => {
  const dropped = (loaded: Awaited<ReturnType<FakeEngine["load"]>>) => {
    expect(loaded.items).toEqual([]);
    expect(loaded.windowItems).toBeNull();
    expect(loaded.omittedItems).toBeNull();
    expect(loaded.complete).toBe(false);
    expect(loaded.stoppedBy).toBe("error");
  };

  it("drops the read when the window reply is for another revision, and asks for nothing more", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperWindow.set(0, (reply) => ({ ...reply, revision: 3 }));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    dropped(loaded);
    expect(loaded.error).toBe("The event-log analysis session changed while paging.");
    expect(engine.pageCalls).toEqual([]);
  });

  it("drops the read when the window reply is for another session", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(5) });
    engine.tamperWindow.set(0, (reply) => ({ ...reply, sessionId: "00000000-0000-4000-8000-0000000000ff" }));
    dropped(await engine.load());
  });

  it("drops the read when the window reply answers another window", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(5) });
    engine.tamperWindow.set(0, (reply) => ({ ...reply, endMs: reply.endMs + 1 }));
    const loaded = await engine.load();
    dropped(loaded);
    expect(loaded.error).toBe("The event-log analysis returned another window.");
  });

  it("drops everything read, including the first reply's items, when a later page is for another revision", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperPage.set(0, (reply) => ({ ...reply, revision: 9 }));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    dropped(loaded);
    expect(loaded.error).toBe("The event-log analysis session changed while paging.");
  });

  it("drops everything read when a later page is for another offset", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperPage.set(0, (reply) => ({ ...reply, offset: reply.offset + 1 }));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    dropped(loaded);
    expect(loaded.error).toBe("The event-log analysis returned the wrong page.");
  });

  it("drops everything read when a page returns an entry past the end of the window", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperPage.set(0, (reply) => ({
      ...reply,
      items: [...reply.items.slice(0, -1), itemAt(999, CENTER + 99_000_000)],
    }));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    dropped(loaded);
    expect(loaded.error).toMatch(/outside the window or out of order/);
  });

  it("drops everything read when a page goes back in time", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    engine.tamperPage.set(0, (reply) => ({
      ...reply,
      items: [itemAt(998, CENTER - 4_000_000), ...reply.items.slice(1)],
    }));
    dropped(await engine.load({ halfWidthMs: 5_000_000 }));
  });

  it("drops everything read when a page carries more rows than were asked for", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(1_200), replyCap: 1_000 });
    engine.tamperPage.set(0, (reply) => ({ ...reply, items: [...reply.items, ...engine.items.slice(0, 5)] }));
    const loaded = await engine.load({ halfWidthMs: 5_000_000 });
    dropped(loaded);
  });
});

describe("a read that cannot start, or that fails at once", () => {
  it("reports a failed first call as an error with an UNKNOWN count, never a count of 0", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(5) });
    for (let i = 0; i <= EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT; i += 1) {
      engine.tamperWindow.set(i, new Error("session was not found"));
    }
    const loaded = await engine.load();
    expect(loaded).toMatchObject({
      items: [],
      windowItems: null,
      omittedItems: null,
      complete: false,
      stoppedBy: "error",
      error: "session was not found",
    });
  });

  it.each([
    ["a center that is not a whole number", { centerMs: CENTER + 0.5 }],
    ["a center that is not finite", { centerMs: Number.NaN }],
    ["a center and half width that are not whole numbers but give whole bounds", { centerMs: 1_000.5, halfWidthMs: 0.5 }],
    ["a negative half width", { halfWidthMs: -1 }],
    ["a half width that is not a whole number", { halfWidthMs: 1.5 }],
    ["a window whose end is not a safe integer", { centerMs: Number.MAX_SAFE_INTEGER, halfWidthMs: 5 }],
    ["a limit of 0", { limit: 0 }],
    ["a limit past what a call can return", { limit: 1_001 }],
    ["a limit that is not a whole number", { limit: 2.5 }],
    ["no call allowed", { maxCalls: 0 }],
  ])("returns an error and makes no call for %s", async (_why, overrides) => {
    const engine = new FakeEngine({ timestamps: everySecond(5) });
    const loaded = await engine.load(overrides);
    expect(loaded.error).not.toBeNull();
    expect(loaded.windowItems).toBeNull();
    expect(loaded.complete).toBe(false);
    expect(engine.windowCalls).toEqual([]);
    expect(engine.pageCalls).toEqual([]);
  });
});

describe("a read the caller has moved on from", () => {
  it("throws as cancelled, with no call, when already cancelled", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(5) });
    await expect(engine.load({ isCancelled: () => true })).rejects.toBeInstanceOf(CorrelationLoadCancelled);
    expect(engine.windowCalls).toEqual([]);
  });

  it("makes no further call once cancelled between pages", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(500), replyCap: 100 });
    let cancelled = false;
    const deps = engine.deps();
    const pageQuery = deps.queryTimelinePage!;
    deps.queryTimelinePage = async (...args) => {
      const reply = await pageQuery(...args);
      cancelled = true;
      return reply;
    };
    await expect(
      engine.load({ halfWidthMs: 5_000_000, isCancelled: () => cancelled, deps }),
    ).rejects.toBeInstanceOf(CorrelationLoadCancelled);
    expect(engine.pageCalls).toHaveLength(1);
  });

  it("never returns a window whose last reply arrived after the caller moved on", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(5) });
    let cancelled = false;
    const deps = engine.deps();
    const windowQuery = deps.queryWindow!;
    deps.queryWindow = async (...args) => {
      const reply = await windowQuery(...args);
      cancelled = true;
      return reply;
    };
    await expect(engine.load({ isCancelled: () => cancelled, deps })).rejects.toBeInstanceOf(
      CorrelationLoadCancelled,
    );
  });

  it("throws as cancelled, and does not report it, when the session was closed by the caller's own supersession", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    let cancelled = false;
    const deps = engine.deps();
    deps.queryTimelinePage = async () => {
      cancelled = true;
      throw new Error("event-log analysis session was not found");
    };
    await expect(
      engine.load({ halfWidthMs: 5_000_000, isCancelled: () => cancelled, deps }),
    ).rejects.toBeInstanceOf(CorrelationLoadCancelled);
  });

  it("throws as cancelled rather than returning a result that finished after the caller moved on", async () => {
    const engine = new FakeEngine({ timestamps: everySecond(300), replyCap: 100 });
    let cancelled = false;
    const deps = engine.deps();
    const pageQuery = deps.queryTimelinePage!;
    let pages = 0;
    deps.queryTimelinePage = async (...args) => {
      pages += 1;
      if (pages === 2) cancelled = true;
      return pageQuery(...args);
    };
    await expect(
      engine.load({ halfWidthMs: 5_000_000, isCancelled: () => cancelled, deps }),
    ).rejects.toBeInstanceOf(CorrelationLoadCancelled);
  });
});

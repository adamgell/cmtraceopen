/**
 * When the dock reads its window (R5, #842): never while it is collapsed or hidden, a true debounce
 * after a selection change (150 ms) and after a session change (CORRELATION_SETTLE_MS), one read per
 * request, and a superseded read never overwrites a newer one. The loader's own rules (the closed
 * interval, the continuation, the byte budget) are evtx-correlation-window.test.ts's.
 */
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EventLogAnalysisTimelineWindow } from "../../lib/commands";
import { sessionKeyOf } from "./evtx-correlation-load";
import type { CorrelationWindowDeps } from "./evtx-correlation-window";
import {
  DOCK_SELECTION_SETTLE_MS,
  useCorrelationDockWindow,
  type UseCorrelationDockWindowOptions,
} from "./useEvtxCorrelationDockWindow";
import { CORRELATION_SETTLE_MS } from "./useEvtxCorrelation";

const SESSION = "00000000-0000-4000-8000-000000000842";
const STATUS = { sessionId: SESSION, revision: 2 };
const CENTER = 1_000_000;
const HALF = 75_000;

function replyFor(
  sessionId: string,
  revision: number,
  startMs: number,
  endMs: number,
): EventLogAnalysisTimelineWindow {
  return {
    sessionId,
    revision,
    startMs,
    endMs,
    offset: 0,
    nextOffset: null,
    totalItems: 1,
    windowItems: 1,
    omittedItems: 0,
    items: [
      {
        timestampMs: startMs + 1,
        severity: "info",
        message: "entry",
        origin: {
          kind: "event",
          stableId: "item-1",
          source: "Live",
          machine: "HOST",
          bundle: null,
          channel: "System",
          provider: "P",
          processId: null,
          eventId: 100,
          recordId: 1,
        },
      },
    ],
    serializedBytes: 100,
  };
}

/** A queryWindow that answers at once (`mode: "now"`) or when the test says so. */
function engine() {
  const calls: { startMs: number; endMs: number; sessionId: string }[] = [];
  const pending: { resolve: () => void; reject: (error: Error) => void }[] = [];
  let mode: "now" | "held" | "fail" = "now";
  let revision = STATUS.revision;
  const queryWindow = vi.fn(
    (sessionId: string, startMs: number, endMs: number): Promise<EventLogAnalysisTimelineWindow> => {
      calls.push({ sessionId, startMs, endMs });
      if (mode === "fail") return Promise.reject(new Error("event-log analysis session was not found"));
      const answer = replyFor(sessionId, revision, startMs, endMs);
      if (mode === "now") return Promise.resolve(answer);
      return new Promise((resolve, reject) => {
        pending.push({ resolve: () => resolve(answer), reject });
      });
    },
  );
  const deps: Partial<CorrelationWindowDeps> = { queryWindow };
  return {
    calls,
    pending,
    deps,
    hold: () => (mode = "held"),
    fail: () => (mode = "fail"),
    answerNow: () => (mode = "now"),
    setRevision: (next: number) => (revision = next),
    queryWindow,
  };
}

function setup(initial: Partial<UseCorrelationDockWindowOptions> = {}) {
  const fake = engine();
  const props: UseCorrelationDockWindowOptions = {
    status: STATUS,
    centerMs: CENTER,
    halfWidthMs: HALF,
    active: true,
    deps: fake.deps,
    ...initial,
  };
  const view = renderHook((current: UseCorrelationDockWindowOptions) => useCorrelationDockWindow(current), {
    initialProps: props,
  });
  const update = (next: Partial<UseCorrelationDockWindowOptions>) => {
    Object.assign(props, next);
    view.rerender({ ...props });
  };
  return { fake, view, update, props };
}

const advance = (ms: number) =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("a collapsed or hidden dock (R5)", () => {
  it("reads nothing, however long it waits and whatever the selection does", async () => {
    const { fake, update, view } = setup({ active: false });
    await advance(CORRELATION_SETTLE_MS * 4);
    update({ centerMs: CENTER + 1_000 });
    update({ halfWidthMs: 30_000 });
    update({ status: { sessionId: SESSION, revision: 3 } });
    await advance(CORRELATION_SETTLE_MS * 4);
    expect(fake.queryWindow).not.toHaveBeenCalled();
    expect(view.result.current.window).toBeNull();
    expect(view.result.current.reading).toBe(false);
  });

  it("recenters when it is reopened: one read, of the selection as it is then", async () => {
    const { fake, update, view } = setup({ active: false });
    update({ centerMs: CENTER + 5_000 });
    update({ centerMs: CENTER + 9_000 });
    update({ active: true });
    expect(view.result.current.reading).toBe(true);
    await advance(DOCK_SELECTION_SETTLE_MS);
    expect(fake.calls).toHaveLength(1);
    expect(fake.calls[0]).toMatchObject({ startMs: CENTER + 9_000 - HALF, endMs: CENTER + 9_000 + HALF });
    expect(view.result.current.window?.centerMs).toBe(CENTER + 9_000);
    expect(view.result.current.reading).toBe(false);
  });

  it("stops a read that is waiting or under way when the dock is collapsed, and delivers nothing", async () => {
    const { fake, update, view } = setup();
    fake.hold();
    await advance(DOCK_SELECTION_SETTLE_MS);
    expect(fake.calls).toHaveLength(1);
    update({ active: false });
    await act(async () => fake.pending.forEach((entry) => entry.resolve()));
    await advance(CORRELATION_SETTLE_MS);
    expect(view.result.current.window).toBeNull();
    expect(view.result.current.reading).toBe(false);
    // And a wait that has not finished is not started.
    update({ active: true });
    update({ active: false });
    await advance(CORRELATION_SETTLE_MS);
    expect(fake.calls).toHaveLength(1);
  });

  it("keeps what it last read while it is closed", async () => {
    const { update, view } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS);
    const first = view.result.current.window;
    expect(first).not.toBeNull();
    update({ active: false });
    expect(view.result.current.window).toBe(first);
  });
});

describe("the debounce (150 ms for a selection, the session settle for a session)", () => {
  it("reads once after the last of a burst of selection changes, for the last one", async () => {
    const { fake, update, view } = setup();
    for (let step = 1; step <= 5; step += 1) {
      await advance(DOCK_SELECTION_SETTLE_MS - 50);
      update({ centerMs: CENTER + step * 1_000 });
    }
    expect(fake.queryWindow).not.toHaveBeenCalled();
    await advance(DOCK_SELECTION_SETTLE_MS);
    expect(fake.calls).toHaveLength(1);
    expect(fake.calls[0]).toMatchObject({ startMs: CENTER + 5_000 - HALF, endMs: CENTER + 5_000 + HALF });
    expect(view.result.current.window?.centerMs).toBe(CENTER + 5_000);
  });

  it("waits the full 150 ms before the first read, not less", async () => {
    const { fake } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS - 1);
    expect(fake.queryWindow).not.toHaveBeenCalled();
    await advance(1);
    expect(fake.queryWindow).toHaveBeenCalledTimes(1);
  });

  it("reads again for a new width, after the same wait", async () => {
    const { fake, update } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS);
    update({ halfWidthMs: 30_000 });
    await advance(DOCK_SELECTION_SETTLE_MS - 1);
    expect(fake.calls).toHaveLength(1);
    await advance(1);
    expect(fake.calls).toHaveLength(2);
    expect(fake.calls[1]).toMatchObject({ startMs: CENTER - 30_000, endMs: CENTER + 30_000 });
  });

  it("waits the session settle after the session changed, so a live tail does not issue IPC per rebuild", async () => {
    const { fake, update } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS);
    expect(fake.calls).toHaveLength(1);
    fake.setRevision(3);
    update({ status: { sessionId: SESSION, revision: 3 } });
    await advance(DOCK_SELECTION_SETTLE_MS + 50);
    expect(fake.calls).toHaveLength(1);
    await advance(CORRELATION_SETTLE_MS - DOCK_SELECTION_SETTLE_MS - 50 - 1);
    expect(fake.calls).toHaveLength(1);
    await advance(1);
    expect(fake.calls).toHaveLength(2);
  });

  it("reads only the newest of several session changes", async () => {
    const { fake, update } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS);
    for (const revision of [3, 4, 5]) {
      fake.setRevision(revision);
      update({ status: { sessionId: SESSION, revision } });
      await advance(CORRELATION_SETTLE_MS - 100);
    }
    expect(fake.calls).toHaveLength(1);
    await advance(100);
    expect(fake.calls).toHaveLength(2);
    expect(sessionKeyOf({ sessionId: fake.calls[1]!.sessionId, revision: 5 })).toBe(`${SESSION}:5`);
  });
});

describe("one read per request", () => {
  it("does not read again for a new status object of the same session and revision", async () => {
    const { fake, update } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS);
    update({ status: { ...STATUS } });
    update({ deps: { ...fake.deps } });
    await advance(CORRELATION_SETTLE_MS * 2);
    expect(fake.calls).toHaveLength(1);
  });

  it("does not read again when the dock is closed and reopened with nothing changed", async () => {
    const { fake, update, view } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS);
    const first = view.result.current.window;
    update({ active: false });
    update({ active: true });
    await advance(CORRELATION_SETTLE_MS * 2);
    expect(fake.calls).toHaveLength(1);
    expect(view.result.current.window).toBe(first);
    expect(view.result.current.reading).toBe(false);
  });

  it("reads again on reopening when the session changed while it was closed", async () => {
    const { fake, update } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS);
    update({ active: false });
    fake.setRevision(3);
    update({ status: { sessionId: SESSION, revision: 3 } });
    update({ active: true });
    await advance(CORRELATION_SETTLE_MS);
    expect(fake.calls).toHaveLength(2);
  });

  it("reads nothing when there is nothing to read around: no selection, an untimed event, no session", async () => {
    const { fake, update, view } = setup({ centerMs: null });
    await advance(CORRELATION_SETTLE_MS * 2);
    update({ centerMs: CENTER, status: null });
    await advance(CORRELATION_SETTLE_MS * 2);
    expect(fake.queryWindow).not.toHaveBeenCalled();
    expect(view.result.current.reading).toBe(false);
    // Not even a failed read to show: there was nothing to ask.
    expect(view.result.current.window).toBeNull();
  });
});

describe("a superseded read", () => {
  it("never overwrites a newer one, whichever reply arrives last", async () => {
    const { fake, update, view } = setup();
    fake.hold();
    await advance(DOCK_SELECTION_SETTLE_MS);
    expect(fake.calls).toHaveLength(1);
    update({ centerMs: CENTER + 20_000 });
    await advance(DOCK_SELECTION_SETTLE_MS);
    expect(fake.calls).toHaveLength(2);
    // The newer reply arrives first, then the older one.
    await act(async () => fake.pending[1]!.resolve());
    expect(view.result.current.window?.centerMs).toBe(CENTER + 20_000);
    await act(async () => fake.pending[0]!.resolve());
    await advance(CORRELATION_SETTLE_MS);
    expect(view.result.current.window?.centerMs).toBe(CENTER + 20_000);
    expect(view.result.current.reading).toBe(false);
  });

  it("drops the error of a session its own caller closed, instead of showing it as a failed read", async () => {
    const { fake, update, view } = setup();
    fake.fail();
    await advance(DOCK_SELECTION_SETTLE_MS);
    // The first call has failed and is backing off; the selection moves on before it gives up.
    update({ centerMs: CENTER + 20_000 });
    fake.answerNow();
    await advance(DOCK_SELECTION_SETTLE_MS + 10_000);
    expect(view.result.current.window?.centerMs).toBe(CENTER + 20_000);
    expect(view.result.current.window?.windowItems).toBe(1);
    expect(view.result.current.window?.error).toBeNull();
  });

  it("stops at unmount: no read is made and nothing is delivered", async () => {
    const { fake, view } = setup();
    await advance(DOCK_SELECTION_SETTLE_MS - 10);
    view.unmount();
    await advance(CORRELATION_SETTLE_MS * 2);
    expect(fake.queryWindow).not.toHaveBeenCalled();
  });
});

describe("a failed read and Retry", () => {
  it("is asked again when the dock is reopened, since a failure answers nothing", async () => {
    const { fake, update, view } = setup();
    fake.fail();
    await advance(DOCK_SELECTION_SETTLE_MS + 10_000);
    expect(view.result.current.window?.windowItems).toBeNull();
    const callsBefore = fake.calls.length;
    fake.answerNow();
    update({ active: false });
    update({ active: true });
    await advance(DOCK_SELECTION_SETTLE_MS);
    expect(fake.calls.length).toBe(callsBefore + 1);
    expect(view.result.current.window?.windowItems).toBe(1);
  });

  it("keeps the failure, with the request it answered, and Retry reads again at once", async () => {
    const { fake, view } = setup();
    fake.fail();
    await advance(DOCK_SELECTION_SETTLE_MS + 10_000);
    const failed = view.result.current.window;
    expect(failed?.windowItems).toBeNull();
    expect(failed?.error).toMatch(/not found/);
    expect(failed?.centerMs).toBe(CENTER);
    expect(view.result.current.reading).toBe(false);
    const callsBefore = fake.calls.length;
    fake.answerNow();
    act(() => view.result.current.retry());
    // No settle: the read is started in the same turn, not 150 ms later.
    await advance(0);
    expect(fake.calls.length).toBeGreaterThan(callsBefore);
    expect(view.result.current.window?.windowItems).toBe(1);
  });
});

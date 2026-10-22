/**
 * The window of timeline items around one instant of an analysis session, read for a surface that
 * shows what was recorded around an event: the correlation dock (spec 8.12, #842) and the Details
 * context list (#843). One reader, so there is one place that knows when a window is asked for.
 *
 * It takes the session (`status`), the instant (`centerMs`), the half width and whether the surface
 * is `active`; it knows nothing of the surface. Rules, all enforced here:
 * - R5, no query while the surface is collapsed or hidden (`active` false). Nothing is asked for,
 *   and what was last read is kept; reactivating re-reads only if the selection, the width or the
 *   session is not what the kept read answered.
 * - A read answers ONE request: the session and revision, the center, the half width. The same
 *   request is never asked twice, so a live-tail batch that renumbers record ids but keeps the
 *   selected event's instant costs no query.
 * - A true debounce, in the generation-guard sleep pattern the correlation hook uses: a request
 *   waits `selectionSettleMs` (150 ms) after a selection or width change, and `sessionSettleMs`
 *   (the hook's `CORRELATION_SETTLE_MS`, 500 ms) after the session changed, so a held arrow key and
 *   a live tail rebuilding the session do not issue IPC per step. A request that is superseded
 *   during its wait, or in flight, is dropped: a late reply never overwrites a newer one.
 * - The kept window is not cleared when the session changes: a consumer pairs it with the counts of
 *   its own session (`buildDockModel` does, and shows an earlier pair as updating).
 * - A retry asks again now, with no settle.
 *
 * `evtx-throttle.ts` is not used: it is a throttle, not a debounce, and stays as it is.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type { EventLogAnalysisSessionStatus } from "../../lib/commands";
import { CorrelationLoadCancelled, messageOf, sessionKeyOf } from "./evtx-correlation-load";
import {
  DEFAULT_CORRELATION_WINDOW_DEPS,
  loadCorrelationWindow,
  type CorrelationWindowDeps,
  type LoadedCorrelationWindow,
} from "./evtx-correlation-window";
import { CORRELATION_SETTLE_MS } from "./useEvtxCorrelation";

/** Wait after a selection or width change before the window is read. */
const CORRELATION_SELECTION_SETTLE_MS = 150;

interface UseEvtxCorrelationWindowOptions {
  /** The published session, or null while none is. */
  status: Pick<EventLogAnalysisSessionStatus, "sessionId" | "revision"> | null;
  /** The selected event's instant, or null when there is nothing to read around (none, or untimed). */
  centerMs: number | null;
  halfWidthMs: number;
  /** The surface is shown and expanded. A collapsed or hidden one reads nothing. */
  active: boolean;
  selectionSettleMs?: number;
  sessionSettleMs?: number;
  deps?: Partial<CorrelationWindowDeps>;
}

interface EvtxCorrelationWindowState {
  /** The last read, whatever it answered; the model decides whether it answers the selection. */
  window: LoadedCorrelationWindow | null;
  /** A read is waiting or under way. */
  reading: boolean;
  /** Asks again now. */
  retry: () => void;
}

function answers(
  read: LoadedCorrelationWindow | null,
  key: string,
  centerMs: number,
  halfWidthMs: number,
): boolean {
  return (
    read !== null &&
    read.windowItems !== null &&
    read.sessionKey === key &&
    read.centerMs === centerMs &&
    read.halfWidthMs === halfWidthMs
  );
}

export function useEvtxCorrelationWindow(options: UseEvtxCorrelationWindowOptions): EvtxCorrelationWindowState {
  const { status, centerMs, halfWidthMs, active } = options;
  const selectionSettleMs = options.selectionSettleMs ?? CORRELATION_SELECTION_SETTLE_MS;
  const sessionSettleMs = options.sessionSettleMs ?? CORRELATION_SETTLE_MS;
  const key = sessionKeyOf(status);
  const statusRef = useRef(status);
  statusRef.current = status;
  const depsRef = useRef(options.deps);
  depsRef.current = options.deps;

  const [read, setRead] = useState<LoadedCorrelationWindow | null>(null);
  const [reading, setReading] = useState(false);
  const [retryNonce, setRetryNonce] = useState(0);
  const generationRef = useRef(0);
  const readRef = useRef<LoadedCorrelationWindow | null>(null);
  const requestedKeyRef = useRef<string | null>(null);
  const retryRef = useRef(false);

  useEffect(() => {
    const generation = (generationRef.current += 1);
    const cancelled = () => generationRef.current !== generation;
    const stop = () => {
      generationRef.current += 1;
    };
    const current = statusRef.current;
    if (!active || key === null || current === null || centerMs === null) {
      setReading(false);
      return stop;
    }
    const retrying = retryRef.current;
    retryRef.current = false;
    if (!retrying && answers(readRef.current, key, centerMs, halfWidthMs)) {
      setReading(false);
      return stop;
    }

    const sessionChanged = requestedKeyRef.current !== null && requestedKeyRef.current !== key;
    const settle = retrying ? 0 : sessionChanged ? sessionSettleMs : selectionSettleMs;
    const deps = { ...DEFAULT_CORRELATION_WINDOW_DEPS, ...depsRef.current };
    setReading(true);
    void (async () => {
      try {
        await deps.sleep(settle);
        if (cancelled()) return;
        requestedKeyRef.current = key;
        const result = await loadCorrelationWindow({
          status: current,
          centerMs,
          halfWidthMs,
          isCancelled: cancelled,
          deps,
        });
        if (cancelled()) return;
        readRef.current = result;
        setRead(result);
        setReading(false);
      } catch (error) {
        // Cancellation is the only expected throw: the read was superseded, and says nothing.
        if (cancelled() || error instanceof CorrelationLoadCancelled) return;
        const failed: LoadedCorrelationWindow = {
          sessionKey: key,
          centerMs,
          halfWidthMs,
          startMs: centerMs - halfWidthMs,
          endMs: centerMs + halfWidthMs,
          items: [],
          windowItems: null,
          omittedItems: null,
          complete: false,
          stoppedBy: "error",
          error: messageOf(error),
          retainedBytes: 0,
          calls: 0,
        };
        readRef.current = failed;
        setRead(failed);
        setReading(false);
      }
    })();
    return stop;
    // `status` is read through its key: a new object for the same session and revision is the same
    // session, and the settle constants and deps are read when the request starts.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, key, centerMs, halfWidthMs, retryNonce]);

  const retry = useCallback(() => {
    retryRef.current = true;
    setRetryNonce((nonce) => nonce + 1);
  }, []);

  return { window: read, reading, retry };
}

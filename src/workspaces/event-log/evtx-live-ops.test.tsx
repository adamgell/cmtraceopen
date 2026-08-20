import { fireEvent, render, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxRecord } from "./types";

const invoke = vi.hoisted(() => vi.fn());
const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => {});
  }),
}));

const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");

describe("event-log live operations", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      sourceMode: "live",
      remoteMachine: null,
      channels: [
        { name: "Application", eventCount: 1, sourceType: "live" },
        { name: "System", eventCount: 1, sourceType: "live" },
      ],
      records: [],
      loadedChannels: new Set(["Application", "System"]),
      selectedChannels: new Set(["Application", "System"]),
      coverageGaps: [],
      tailCoverageGaps: [],
      tailMode: null,
      tailRequestId: null,
      tailChannels: new Set<string>(),
      isLoading: false,
      loadError: null,
    });
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: args.channel === "Application" ? "subscription" : "polling",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: false,
          nextSequence: 1,
          coverageGaps: [],
        };
      }
      if (name === "evtx_clear_channel") {
        return { channel: args.channel, result: { status: "cleared" } };
      }
      return undefined;
    });
  });
  function tailRecord(eventRecordId: number): EvtxRecord {
    return {
      id: 0,
      eventRecordId,
      timestamp: "2026-01-01T00:00:00Z",
      timestampEpoch: eventRecordId,
      provider: "Test",
      channel: "Application",
      eventId: 1,
      level: "Information",
      computer: "TEST",
      message: "event",
      eventData: [],
      rawXml: `<Event><EventRecordID>${eventRecordId}</EventRecordID></Event>`,
      sourceLabel: "Live",
    };
  }

  it("returns the nested clear status and forwards the selected remote host", async () => {
    useEvtxStore.setState({ remoteMachine: "lab-host" });

    const result = await useEvtxStore.getState().clearChannel("Application", true);

    expect(result).toEqual({ status: "cleared" });
    expect(invoke).toHaveBeenCalledWith("evtx_clear_channel", {
      channel: "Application",
      confirmed: true,
      remoteMachine: "lab-host",
    });
  });

  it("removes cleared channel tail gaps without hiding other-channel gaps", async () => {
    await useEvtxStore.getState().startLiveTail();
    useEvtxStore.setState({
      tailCoverageGaps: ["Application: stale gap", "System: keep gap"],
    });

    const result = await useEvtxStore.getState().clearChannel("Application", true);

    expect(result).toEqual({ status: "cleared" });
    expect(useEvtxStore.getState().tailCoverageGaps).toEqual(["System: keep gap"]);
  });


  it("exposes subscription and polling transitions and stops both channels", async () => {
    const statuses = await useEvtxStore.getState().startLiveTail();
    expect(statuses.map((status) => status.mode)).toEqual(["subscription", "polling"]);
    expect(useEvtxStore.getState().tailMode).toBe("mixed");
    expect(invoke).toHaveBeenCalledWith(
      "evtx_start_tail",
      expect.objectContaining({ channel: "Application" })
    );

    await useEvtxStore.getState().stopLiveTail();
    expect(invoke).toHaveBeenCalledWith(
      "evtx_stop_tail",
      expect.objectContaining({ channel: "Application" })
    );
    expect(invoke).toHaveBeenCalledWith(
      "evtx_stop_tail",
      expect.objectContaining({ channel: "System" })
    );
    expect(useEvtxStore.getState().tailMode).toBeNull();
  });
  it("preserves a coverage gap when stopping a live tail fails", async () => {
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail") {
        throw new Error("tail registry is unavailable");
      }
      return undefined;
    });

    await useEvtxStore.getState().startLiveTail();
    await useEvtxStore.getState().stopLiveTail();

    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail stop failed (tail registry is unavailable)"
    );
  });

  it("does not apply a stale stop rejection to a newer request", async () => {
    useEvtxStore.setState({ loadedChannels: new Set(["Application"]) });
    const rejectStops = new Map<string, (error: Error) => void>();
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail") {
        return new Promise<never>((_, reject) => {
          rejectStops.set(String(args.requestId), reject);
        });
      }
      if (name === "evtx_enumerate_channels") {
        return [];
      }
      return undefined;
    });

    await useEvtxStore.getState().startLiveTail();
    const staleRequestId = useEvtxStore.getState().tailRequestId!;
    const staleStop = useEvtxStore.getState().stopLiveTail();
    await Promise.resolve();
    await Promise.resolve();
    await useEvtxStore.getState().enumerateChannels();
    rejectStops.get(staleRequestId)?.(new Error("stale tail registry failure"));
    await staleStop;

    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail stop failed (stale tail registry failure)"
    );
  });
  it("does not let stale stop recovery clear a current same-message failure", async () => {
    useEvtxStore.setState({
      loadedChannels: new Set(["Application"]),
      selectedChannels: new Set(["Application"]),
    });
    let staleReject!: (error: Error) => void;
    let retryResolve!: (status: unknown) => void;
    let currentReject!: (error: Error) => void;
    let queryResolve!: (value: unknown) => void;
    let queryRequestId: string | undefined;
    let staleTailRequestId: string | undefined;
    let currentTailRequestId: string | undefined;
    let staleStopAttempts = 0;
    invoke.mockImplementation((name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        const requestId = String(args.requestId);
        if (!staleTailRequestId) staleTailRequestId = requestId;
        else currentTailRequestId = requestId;
        return {
          requestId,
          channel: args.channel,
          mode: "subscription",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail") {
        const requestId = String(args.requestId);
        if (requestId === staleTailRequestId) {
          staleStopAttempts += 1;
          if (staleStopAttempts === 1) {
            return new Promise((_, reject) => {
              staleReject = reject;
            });
          }
          return new Promise((resolve) => {
            retryResolve = resolve;
          });
        }
        if (requestId === currentTailRequestId) {
          return new Promise((_, reject) => {
            currentReject = reject;
          });
        }
        return {
          requestId,
          channel: args.channel,
          mode: "subscription",
          active: false,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_query_channels") {
        queryRequestId = String(args.requestId);
        return new Promise((resolve) => {
          queryResolve = resolve;
        });
      }
      return undefined;
    });

    await useEvtxStore.getState().startLiveTail();
    const sourceQuery = useEvtxStore.getState().queryChannels(["Application"]);
    await Promise.resolve();
    await Promise.resolve();
    expect(staleReject).toBeDefined();

    staleReject(new Error("same failure"));
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail stop failed (same failure)"
    );

    const nextTail = useEvtxStore.getState().startLiveTail();
    await nextTail;
    expect(useEvtxStore.getState().tailRequestId).toBe(currentTailRequestId);

    const stopCurrent = useEvtxStore.getState().stopLiveTail();
    await Promise.resolve();
    await Promise.resolve();
    expect(currentReject).toBeDefined();
    currentReject(new Error("same failure"));
    await stopCurrent;

    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail stop failed (same failure)"
    );

    retryResolve({
      requestId: staleTailRequestId,
      channel: "Application",
      mode: "subscription",
      active: false,
      nextSequence: 0,
      coverageGaps: [],
    });
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
    await new Promise<void>((resolve) => setTimeout(resolve, 0));
    await Promise.resolve();

    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail stop failed (same failure)"
    );

    listeners.get("evtx-record-stream-complete")?.({
      payload: {
        requestId: queryRequestId,
        channel: "Application",
        sequenceCount: 0,
        totalRecords: 0,
      },
    });
    queryResolve({
      records: [],
      channels: [{ name: "Application", eventCount: 0, sourceType: "live" as const }],
      totalRecords: 0,
      parseErrors: 0,
      errorMessages: [],
    });
    await sourceQuery;
  });

  it("retains a failed channel stop for retry", async () => {
    useEvtxStore.setState({ loadedChannels: new Set(["Application"]) });
    let failStop = true;
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail" && failStop) {
        throw new Error("tail registry is unavailable");
      }
      if (name === "evtx_stop_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: false,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      return undefined;
    });

    await useEvtxStore.getState().startLiveTail();
    const requestId = useEvtxStore.getState().tailRequestId;
    await useEvtxStore.getState().stopLiveTail();

    expect(useEvtxStore.getState().tailRequestId).toBe(requestId);
    expect(useEvtxStore.getState().tailChannels).toEqual(new Set(["Application"]));
    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail stop failed (tail registry is unavailable)"
    );

    failStop = false;
    await useEvtxStore.getState().stopLiveTail();
    expect(useEvtxStore.getState().tailRequestId).toBeNull();
  });

  it("does not clear a channel when stopping its live tail fails", async () => {
    useEvtxStore.setState({ loadedChannels: new Set(["Application"]) });
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail") {
        throw new Error("tail registry is unavailable");
      }
      if (name === "evtx_clear_channel") {
        return { channel: args.channel, result: { status: "cleared" } };
      }
      return undefined;
    });

    await useEvtxStore.getState().startLiveTail();
    const requestId = useEvtxStore.getState().tailRequestId;
    const result = await useEvtxStore.getState().clearChannel("Application", true);

    expect(result).toEqual({
      status: "unavailable",
      detail: "Application: live tail stop failed (tail registry is unavailable)",
    });
    expect(invoke).not.toHaveBeenCalledWith("evtx_clear_channel", expect.anything());
    expect(useEvtxStore.getState().tailRequestId).toBe(requestId);
    expect(useEvtxStore.getState().tailChannels).toEqual(new Set(["Application"]));
    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail stop failed (tail registry is unavailable)"
    );
  });
  it("aborts a clear when its tail stop becomes stale", async () => {
    useEvtxStore.setState({ loadedChannels: new Set(["Application"]) });
    let resolveStop!: (status: unknown) => void;
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail") {
        return new Promise((resolve) => {
          resolveStop = resolve;
        });
      }
      if (name === "evtx_clear_channel") {
        return { channel: args.channel, result: { status: "cleared" } };
      }
      return undefined;
    });

    await useEvtxStore.getState().startLiveTail();
    const clear = useEvtxStore.getState().clearChannel("Application", true);
    await Promise.resolve();
    await Promise.resolve();
    expect(resolveStop).toBeDefined();

    useEvtxStore.getState().reset();
    resolveStop({
      requestId: "stale",
      channel: "Application",
      mode: "subscription",
      active: false,
      nextSequence: 0,
      coverageGaps: [],
    });
    const result = await clear;

    expect(result.status).toBe("unavailable");
    expect("detail" in result ? result.detail : "").toContain("clear cancelled");
    expect(useEvtxStore.getState().sourceMode).toBeNull();
  });
  it("stops a tail whose pending startup is superseded by a newer start", async () => {
    useEvtxStore.setState({ loadedChannels: new Set(["Application"]) });
    const startResolvers = new Map<string, (status: unknown) => void>();
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return new Promise((resolve) => {
          startResolvers.set(String(args.requestId), resolve);
        });
      }
      if (name === "evtx_stop_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: false,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      return undefined;
    });

    const firstStart = useEvtxStore.getState().startLiveTail();
    await Promise.resolve();
    const firstRequestId = [...startResolvers.keys()][0];
    expect(firstRequestId).toBeDefined();

    const secondStart = useEvtxStore.getState().startLiveTail();
    await Promise.resolve();
    const secondRequestId = [...startResolvers.keys()].find((id) => id !== firstRequestId);
    expect(secondRequestId).toBeDefined();
    if (secondRequestId === undefined) throw new Error("second tail start did not invoke backend");

    startResolvers.get(firstRequestId)!({
      requestId: firstRequestId,
      channel: "Application",
      mode: "subscription",
      active: true,
      nextSequence: 0,
      coverageGaps: [],
    });
    await firstStart;
    await Promise.resolve();
    await Promise.resolve();

    const stopRequestIds = invoke.mock.calls
      .filter(([name]) => name === "evtx_stop_tail")
      .map(([, args]) => String((args as Record<string, unknown>).requestId));
    expect(stopRequestIds).toContain(firstRequestId);
    expect(stopRequestIds).not.toContain(secondRequestId);

    startResolvers.get(secondRequestId)!({
      requestId: secondRequestId,
      channel: "Application",
      mode: "subscription",
      active: true,
      nextSequence: 0,
      coverageGaps: [],
    });
    const statuses = await secondStart;
    expect(statuses).toHaveLength(1);
    expect(useEvtxStore.getState().tailRequestId).toBe(secondRequestId);
  });

  it("accepts sequence zero after restarting the live tail with a fresh request", async () => {
    await useEvtxStore.getState().startLiveTail();
    const handler = listeners.get("evtx-tail-batch");
    const firstRequestId = useEvtxStore.getState().tailRequestId;
    handler?.({
      payload: {
        requestId: firstRequestId,
        channel: "Application",
        sequence: 0,
        mode: "subscription",
        records: [tailRecord(11)],
        coverageGaps: [],
      },
    });
    await useEvtxStore.getState().stopLiveTail();

    await useEvtxStore.getState().startLiveTail();
    const secondRequestId = useEvtxStore.getState().tailRequestId;
    expect(secondRequestId).not.toBe(firstRequestId);
    handler?.({
      payload: {
        requestId: secondRequestId,
        channel: "Application",
        sequence: 0,
        mode: "subscription",
        records: [tailRecord(12)],
        coverageGaps: [],
      },
    });

    expect(useEvtxStore.getState().records.map((record) => record.eventRecordId)).toContain(12);
  });

  it("records final sequence gaps reported when stopping a live tail", async () => {
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_start_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: true,
          nextSequence: 0,
          coverageGaps: [],
        };
      }
      if (name === "evtx_stop_tail") {
        return {
          requestId: args.requestId,
          channel: args.channel,
          mode: "subscription",
          active: false,
          nextSequence: 2,
          coverageGaps: ["Application: backend tail batch was not delivered"],
        };
      }
      return undefined;
    });
    await useEvtxStore.getState().startLiveTail();
    const handler = listeners.get("evtx-tail-batch");
    const requestId = useEvtxStore.getState().tailRequestId;
    handler?.({
      payload: {
        requestId,
        channel: "Application",
        sequence: 0,
        mode: "subscription",
        records: [tailRecord(21)],
        coverageGaps: [],
      },
    });

    await useEvtxStore.getState().stopLiveTail();

    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail batch 1 was not received"
    );
    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: backend tail batch was not delivered"
    );
  });

  it("keeps the selected record when an earlier tail row shifts numeric ids", async () => {
    const selected = tailRecord(100);
    useEvtxStore.setState({ records: [selected], selectedRecordId: 0 });
    await useEvtxStore.getState().startLiveTail();
    const handler = listeners.get("evtx-tail-batch");
    const requestId = useEvtxStore.getState().tailRequestId;
    handler?.({
      payload: {
        requestId,
        channel: "Application",
        sequence: 0,
        mode: "subscription",
        records: [tailRecord(1)],
        coverageGaps: [],
      },
    });

    const state = useEvtxStore.getState();
    expect(state.records[state.selectedRecordId ?? -1]?.eventRecordId).toBe(100);
  });

  it("reports a dropped sequence and rejects stale source-generation batches", async () => {
    await useEvtxStore.getState().startLiveTail();
    const handler = listeners.get("evtx-tail-batch");
    expect(handler).toBeDefined();
    const requestId = useEvtxStore.getState().tailRequestId!;
    const record = {
      id: 0,
      eventRecordId: 42,
      timestamp: "2026-01-01T00:00:00Z",
      timestampEpoch: 1,
      provider: "Test",
      channel: "Application",
      eventId: 1,
      level: "Information",
      computer: "TEST",
      message: "event",
      eventData: [],
      rawXml: "",
      sourceLabel: "Live",
    } as const;

    handler!({
      payload: {
        requestId,
        channel: "Application",
        sequence: 0,
        mode: "subscription",
        records: [record],
        coverageGaps: [],
      },
    });
    handler!({
      payload: {
        requestId,
        channel: "Application",
        sequence: 2,
        mode: "subscription",
        records: [],
        coverageGaps: [],
      },
    });
    expect(useEvtxStore.getState().tailCoverageGaps).toContain(
      "Application: live tail batch 1 was not received"
    );

    useEvtxStore.getState().reset();
    handler!({
      payload: {
        requestId,
        channel: "Application",
        sequence: 3,
        mode: "subscription",
        records: [record],
        coverageGaps: [],
      },
    });
    expect(useEvtxStore.getState().records).toHaveLength(0);
  });

  it("does not invoke a clear when confirmation is cancelled", async () => {
    render(<ChannelPicker />);
    const channelSelect = document.querySelector('select[aria-label="Channel to clear"]');
    expect(channelSelect).not.toBeNull();
    fireEvent.change(channelSelect!, { target: { value: "Application" } });
    const clearButton = Array.from(document.querySelectorAll("button")).find((button) =>
      button.textContent?.trim() === "Clear"
    );
    expect(clearButton).not.toBeUndefined();
    fireEvent.click(clearButton!);
    expect(document.querySelector('[role="dialog"]')).not.toBeNull();
    const cancelButton = Array.from(document.querySelectorAll("button")).find((button) =>
      button.textContent?.trim() === "Cancel"
    );
    expect(cancelButton).not.toBeUndefined();
    fireEvent.click(cancelButton!);
    await waitFor(() => expect(document.querySelector('[role="dialog"]')).toBeNull());
    expect(invoke).not.toHaveBeenCalledWith("evtx_clear_channel", expect.anything());
  });
});

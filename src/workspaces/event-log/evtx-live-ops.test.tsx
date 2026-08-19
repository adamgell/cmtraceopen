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
          coverageGaps: [],
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

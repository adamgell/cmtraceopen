import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
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
const { AboutDialog } = await import("../../components/dialogs/AboutDialog");
const { useUiStore } = await import("../../stores/ui-store");

function AboutAndChannelPicker() {
  const showAboutDialog = useUiStore((state) => state.showAboutDialog);
  const setShowAboutDialog = useUiStore((state) => state.setShowAboutDialog);
  return (
    <>
      <AboutDialog
        isOpen={showAboutDialog}
        onClose={() => setShowAboutDialog(false)}
      />
      <ChannelPicker />
    </>
  );
}

function confirmChannelClear(channel = "Application") {
  const channelSelect = document.querySelector<HTMLSelectElement>(
    'select[aria-label="Channel to clear"]',
  )!;
  fireEvent.change(channelSelect, { target: { value: channel } });
  const clearButton = Array.from(document.querySelectorAll("button")).find(
    (button) => button.textContent?.trim() === "Clear",
  )!;
  fireEvent.click(clearButton);
  const confirmButton = Array.from(document.querySelectorAll("button")).find(
    (button) => button.textContent?.trim() === "Clear channel",
  )!;
  confirmButton.focus();
  fireEvent.click(confirmButton);
  return { channelSelect, clearButton };
}

describe("event-log live operations", () => {
  beforeEach(() => {
    invoke.mockReset();
    useUiStore.setState(useUiStore.getInitialState(), true);
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
      selectedRecordId: null,
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

  it("allows a channel clear after a live tail stops successfully", async () => {
    await useEvtxStore.getState().startLiveTail();
    await useEvtxStore.getState().stopLiveTail();

    const result = await useEvtxStore.getState().clearChannel("Application", true);

    expect(result).toEqual({ status: "cleared" });
    expect(invoke).toHaveBeenCalledWith("evtx_clear_channel", {
      channel: "Application",
      confirmed: true,
      remoteMachine: null,
    });
  });

  it("releases live-tail ownership after clearing its last channel", async () => {
    useEvtxStore.setState({
      loadedChannels: new Set(["Application"]),
      selectedChannels: new Set(["Application"]),
    });
    await useEvtxStore.getState().startLiveTail();

    expect(await useEvtxStore.getState().clearChannel("Application", true)).toEqual({
      status: "cleared",
    });
    expect(await useEvtxStore.getState().clearChannel("System", true)).toEqual({
      status: "cleared",
    });
    expect(invoke).toHaveBeenCalledWith("evtx_clear_channel", {
      channel: "System",
      confirmed: true,
      remoteMachine: null,
    });
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
    await waitFor(() => expect(staleReject).toBeDefined());

    staleReject(new Error("same failure"));
    await waitFor(() =>
      expect(useEvtxStore.getState().tailCoverageGaps).toContain(
        "Application: live tail stop failed (same failure)"
      )
    );

    const nextTail = useEvtxStore.getState().startLiveTail();
    await nextTail;
    expect(useEvtxStore.getState().tailRequestId).toBe(currentTailRequestId);

    const stopCurrent = useEvtxStore.getState().stopLiveTail();
    await waitFor(() => expect(currentReject).toBeDefined());
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
    await new Promise<void>((resolve) => setTimeout(resolve, 0));

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

  it("keeps a lossy tail's gap through Pause and Resume, so the row stays partial", async () => {
    useEvtxStore.setState({ records: [tailRecord(1)] });
    render(<ChannelPicker />);
    const rowState = () =>
      document
        .querySelector('[data-channel-row="Application"]')
        ?.getAttribute("data-channel-state");
    expect(rowState()).toBe("read");

    await act(async () => {
      await useEvtxStore.getState().startLiveTail();
    });
    const handler = listeners.get("evtx-tail-batch")!;
    const requestId = useEvtxStore.getState().tailRequestId;
    // Sequence 0 arrives, then 3: batches 1 and 2 were never received.
    act(() => {
      handler({
        payload: {
          requestId,
          channel: "Application",
          sequence: 0,
          mode: "subscription",
          records: [tailRecord(2)],
          coverageGaps: [],
        },
      });
      handler({
        payload: {
          requestId,
          channel: "Application",
          sequence: 3,
          mode: "subscription",
          records: [tailRecord(3)],
          coverageGaps: [],
        },
      });
    });
    expect(rowState()).toBe("partial");

    fireEvent.click(await screen.findByRole("button", { name: "Pause live tail" }));
    await waitFor(() => expect(useEvtxStore.getState().tailMode).toBeNull());
    expect(rowState()).toBe("partial");

    fireEvent.click(await screen.findByRole("button", { name: "Resume live tail" }));
    await waitFor(() => expect(useEvtxStore.getState().tailMode).not.toBeNull());
    // Resume resets the tail's own list, yet the events with the hole are still in the view.
    expect(useEvtxStore.getState().tailCoverageGaps).toEqual([]);
    expect(rowState()).toBe("partial");
    expect(
      document.getElementById(
        document
          .querySelector('[data-channel-row="Application"] input[type="checkbox"]')!
          .getAttribute("aria-describedby")!,
      )?.textContent,
    ).toContain("live tail batch 1 was not received");
  });

  describe.each([
    ["the local machine", null],
    ["a remote machine", "SRV01"],
  ] as const)("on %s", (_where, machine) => {
    const deliverLostBatch = () => {
      const handler = listeners.get("evtx-tail-batch")!;
      const requestId = useEvtxStore.getState().tailRequestId;
      act(() => {
        for (const sequence of [0, 3]) {
          handler({
            payload: {
              requestId,
              channel: "Application",
              sequence,
              mode: "subscription",
              records: [tailRecord(10 + sequence)],
              coverageGaps: [],
            },
          });
        }
      });
    };
    const row = () => document.querySelector('[data-channel-row="Application"]');
    const description = () =>
      document.getElementById(
        row()!.querySelector('input[type="checkbox"]')!.getAttribute("aria-describedby")!,
      )?.textContent ?? "";

    it("drops a lost batch the tail carried when the channel is cleared, and when it is loaded again", async () => {
      useEvtxStore.setState({ remoteMachine: machine, records: [tailRecord(1)] });
      render(<ChannelPicker />);
      await act(async () => {
        await useEvtxStore.getState().startLiveTail();
      });
      deliverLostBatch();
      expect(row()?.getAttribute("data-channel-state")).toBe("partial");

      fireEvent.click(await screen.findByRole("button", { name: "Pause live tail" }));
      await waitFor(() => expect(useEvtxStore.getState().tailMode).toBeNull());
      fireEvent.click(await screen.findByRole("button", { name: "Resume live tail" }));
      await waitFor(() => expect(useEvtxStore.getState().tailMode).not.toBeNull());
      expect(row()?.getAttribute("data-channel-state")).toBe("partial");
      // The carried copy is filed under the name the store's own filters match.
      const carried = useEvtxStore
        .getState()
        .coverageGaps.filter((gap) => gap.includes("live tail batch 1 was not received"));
      expect(carried).toEqual([
        `${machine === null ? "" : `${machine}/`}Application: live tail batch 1 was not received`,
      ]);

      await act(async () => {
        await useEvtxStore.getState().clearChannel("Application", true);
      });
      // Cleared: no stale reason survives for it, on the row or in the coverage. System was tailing
      // too and its own gap, filed the same way, is not Application's to lose.
      expect(
        useEvtxStore.getState().coverageGaps.filter((gap) => gap.includes("Application")),
      ).toEqual([]);
      expect(useEvtxStore.getState().coverageGaps.join("\n")).toContain(
        `${machine === null ? "" : `${machine}/`}System: live tail batch 0 was not received`,
      );
      // The pane's numbers follow a running tail through a 75 ms throttle, so the row settles.
      await waitFor(() => expect(row()?.getAttribute("data-channel-state")).toBe("notLoaded"));
      expect(description()).not.toContain("live tail batch");
    });
  });

  describe("a tail's stop that fails after the source was replaced", () => {
    // The request id is in the message so a test can tell its own failure from the retries of
    // earlier tails that no stop can ever reach (module state outlives a test).
    const stopFailure = (requestId: unknown, channel: unknown) =>
      `live tail ${String(channel)} for request ${String(requestId)} was not found`;
    const startReply = (args: Record<string, unknown>) => ({
      requestId: args.requestId,
      channel: args.channel,
      mode: "subscription",
      active: true,
      nextSequence: 0,
      coverageGaps: [],
    });
    /** An empty read that succeeds, with the terminal stream event the store waits for. */
    const emptyRead = (args: Record<string, unknown>) => {
      const channel = (args.channels as string[])[0];
      queueMicrotask(() =>
        listeners.get("evtx-record-stream-complete")?.({
          payload: { channel, sequenceCount: 0, totalRecords: 0, requestId: args.requestId },
        }),
      );
      return {
        records: [],
        channels: [{ name: channel, eventCount: 0, sourceType: "live", enabledState: "enabled" }],
        totalRecords: 0,
        parseErrors: 0,
        errorMessages: [],
      };
    };
    const gapsOf = (requestId: string) =>
      useEvtxStore
        .getState()
        .tailCoverageGaps.filter((gap) => gap.includes(`request ${requestId}`));

    it("is logged, not written into a stable live view of the other machine", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      // The old tail's stop is held until SRV01 is on screen, then fails.
      const stop = deferred<never>();
      let tailRequestId = "";
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_start_tail") return startReply(args);
        if (name === "evtx_stop_tail") {
          if (args.requestId === tailRequestId) return stop.promise;
          return { ...startReply(args), active: false, nextSequence: 1 };
        }
        if (name === "evtx_enumerate_remote_channels") {
          return [{ name: "System", eventCount: 0, sourceType: { remote: { machine: "SRV01" } }, enabledState: "enabled" }];
        }
        if (name === "evtx_query_remote_channels") return emptyRead(args);
        return undefined;
      });

      await useEvtxStore.getState().startLiveTail();
      tailRequestId = useEvtxStore.getState().tailRequestId!;
      await useEvtxStore.getState().enumerateRemoteChannels("SRV01");
      await waitFor(() => {
        const state = useEvtxStore.getState();
        expect(state.sourceMode).toBe("live");
        expect(state.isLoading).toBe(false);
        expect(state.loadedChannels.has("System")).toBe(true);
      });
      expect(useEvtxStore.getState().remoteMachine).toBe("SRV01");
      render(<ChannelPicker />);
      const systemRow = () => document.querySelector('[data-channel-row="System"]');
      expect(systemRow()?.getAttribute("data-channel-state")).toBe("read");

      // Now, with SRV01 live, the old local tail's stop fails.
      stop.reject(new Error(stopFailure(tailRequestId, "Application")));
      await waitFor(() =>
        expect(warn).toHaveBeenCalledWith(
          expect.stringContaining(`request ${tailRequestId} was not found`),
        ),
      );

      expect(gapsOf(tailRequestId)).toEqual([]);
      expect(useEvtxStore.getState().tailCoverageGaps).toEqual([]);
      expect(useEvtxStore.getState().coverageGaps.join("\n")).not.toContain(tailRequestId);
      // SRV01's own System row is untouched by another machine's tail.
      expect(systemRow()?.getAttribute("data-channel-state")).toBe("read");
      warn.mockRestore();
    });

    it("is still written when the load that superseded the tail is on the same source", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_start_tail") return startReply(args);
        if (name === "evtx_stop_tail") throw new Error(stopFailure(args.requestId, args.channel));
        if (name === "evtx_query_channels") return emptyRead(args);
        return undefined;
      });
      await useEvtxStore.getState().startLiveTail();
      const tailRequestId = useEvtxStore.getState().tailRequestId!;

      void useEvtxStore.getState().queryChannels(["System"]);
      await waitFor(() => expect(gapsOf(tailRequestId).length).toBeGreaterThan(0));
      expect(warn).not.toHaveBeenCalledWith(
        expect.stringContaining(`request ${tailRequestId} was not found`),
      );
      warn.mockRestore();
    });

    it("survives more than 64 later supersessions: never in another source's view, still in its own", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      let doomedRequestId = "";
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_start_tail") return startReply(args);
        if (name === "evtx_stop_tail") {
          // One tail can never be stopped; every other stop succeeds.
          if (args.requestId === doomedRequestId) {
            throw new Error(stopFailure(args.requestId, args.channel));
          }
          return { ...startReply(args), active: false, nextSequence: 1 };
        }
        if (name === "evtx_enumerate_remote_channels") return [];
        if (name === "evtx_query_channels" || name === "evtx_query_remote_channels") {
          return emptyRead(args);
        }
        return undefined;
      });

      // Local tail whose stop never succeeds, then a switch to SRV01.
      await useEvtxStore.getState().startLiveTail();
      doomedRequestId = useEvtxStore.getState().tailRequestId!;
      await useEvtxStore.getState().enumerateRemoteChannels("SRV01");
      await waitFor(() =>
        expect(warn).toHaveBeenCalledWith(
          expect.stringContaining(`request ${doomedRequestId} was not found`),
        ),
      );

      // Far more supersessions than any bound: each starts a tail on SRV01 and a load replaces it,
      // and each load retries the doomed stop again.
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        channels: [{ name: "System", eventCount: 0, sourceType: "live", enabledState: "enabled" }],
      });
      for (let i = 0; i < 70; i += 1) {
        await useEvtxStore.getState().startLiveTail();
        await useEvtxStore.getState().queryChannels(["System"]);
        useEvtxStore.setState({ sourceMode: "live", loadedChannels: new Set(["System"]) });
      }
      await new Promise((resolve) => setTimeout(resolve, 20));

      expect(useEvtxStore.getState().remoteMachine).toBe("SRV01");
      expect(gapsOf(doomedRequestId)).toEqual([]);
      expect(useEvtxStore.getState().coverageGaps.join("\n")).not.toContain(doomedRequestId);

      // Back on the machine the tail belonged to, once that view is stable, the same doomed stop is
      // retried by the next load and its failure belongs here: the origin outlived all of that.
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_stop_tail") {
          if (args.requestId === doomedRequestId) {
            throw new Error(stopFailure(args.requestId, args.channel));
          }
          return { ...startReply(args), active: false, nextSequence: 1 };
        }
        if (name === "evtx_enumerate_channels") {
          return [{ name: "System", eventCount: 0, sourceType: "live", enabledState: "enabled" }];
        }
        if (name === "evtx_query_channels") return emptyRead(args);
        return undefined;
      });
      await useEvtxStore.getState().enumerateLocalChannels();
      await waitFor(() => {
        const state = useEvtxStore.getState();
        expect(state.sourceMode).toBe("live");
        expect(state.isLoading).toBe(false);
        expect(state.loadedChannels.has("System")).toBe(true);
      });
      expect(useEvtxStore.getState().remoteMachine).toBeNull();
      await useEvtxStore.getState().queryChannels(["System"]);
      await waitFor(() => expect(gapsOf(doomedRequestId).length).toBeGreaterThan(0));
      warn.mockRestore();
    });

    it("keeps the origin of a stop that is still pending when the tail is no longer active", async () => {
      // Two loads on one live source: the first supersedes the tail, so by the second prune the tail
      // is neither active nor starting, and only its pending stop says its origin is still needed.
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const stop = deferred<never>();
      let requestId = "";
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_start_tail") return startReply(args);
        if (name === "evtx_stop_tail") {
          if (args.requestId === requestId) return stop.promise;
          return { ...startReply(args), active: false, nextSequence: 1 };
        }
        if (name === "evtx_query_channels") return emptyRead(args);
        return undefined;
      });
      await useEvtxStore.getState().startLiveTail();
      requestId = useEvtxStore.getState().tailRequestId!;

      await useEvtxStore.getState().queryChannels(["System"]);
      await useEvtxStore.getState().queryChannels(["System"]);
      stop.reject(new Error(stopFailure(requestId, "Application")));

      await waitFor(() => expect(gapsOf(requestId).length).toBeGreaterThan(0));
      expect(warn).not.toHaveBeenCalledWith(
        expect.stringContaining(`request ${requestId} was not found`),
      );
      warn.mockRestore();
    });

    it("keeps the origin of a start that is still pending when the tail is no longer active", async () => {
      // The first load detaches a start that has not answered; the second prune finds it neither
      // active nor stopping, and only its pending start says its origin is still needed. When the
      // start answers it is stopped, and that stop fails.
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const startGate = deferred<void>();
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_start_tail") {
          await startGate.promise;
          return startReply(args);
        }
        if (name === "evtx_stop_tail") throw new Error(stopFailure(args.requestId, args.channel));
        if (name === "evtx_query_channels") return emptyRead(args);
        return undefined;
      });
      const starting = useEvtxStore.getState().startLiveTail();
      const startCall = invoke.mock.calls.find(([name]) => name === "evtx_start_tail");
      const requestId = String((startCall?.[1] as Record<string, unknown>).requestId);

      await useEvtxStore.getState().queryChannels(["System"]);
      await useEvtxStore.getState().queryChannels(["System"]);
      startGate.resolve();
      expect(await starting).toEqual([]);

      await waitFor(() => expect(gapsOf(requestId).length).toBeGreaterThan(0));
      expect(warn).not.toHaveBeenCalledWith(
        expect.stringContaining(`request ${requestId} was not found`),
      );
      warn.mockRestore();
    });

    it("never writes an outcome whose source it does not know", async () => {
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      let requestId = "";
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_start_tail") return startReply(args);
        if (name === "evtx_stop_tail") {
          if (args.requestId === requestId) {
            throw new Error(stopFailure(args.requestId, args.channel));
          }
          return { ...startReply(args), active: false, nextSequence: 1 };
        }
        return undefined;
      });
      await useEvtxStore.getState().startLiveTail();
      requestId = useEvtxStore.getState().tailRequestId!;

      // reset() forgets where every tail came from and tears the active tail down.
      useEvtxStore.getState().reset();
      await waitFor(() =>
        expect(warn).toHaveBeenCalledWith(expect.stringContaining("has no recorded source")),
      );
      expect(gapsOf(requestId)).toEqual([]);
      warn.mockRestore();
    });
  });

  it("does not carry a gap that lost nothing across a restart", async () => {
    useEvtxStore.setState({ tailCoverageGaps: ["Application: live tail unavailable (not supported)"] });

    await useEvtxStore.getState().startLiveTail();

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
  });

  it("clears the carried gap when its channel is cleared", async () => {
    useEvtxStore.setState({
      records: [tailRecord(1)],
      tailCoverageGaps: ["Application: live tail batch 4 was not received"],
    });
    await useEvtxStore.getState().startLiveTail();
    expect(useEvtxStore.getState().coverageGaps).toContain(
      "Application: live tail batch 4 was not received",
    );

    await useEvtxStore.getState().clearChannel("Application", true);

    expect(useEvtxStore.getState().coverageGaps).toEqual([]);
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
    const channelSelect = document.querySelector<HTMLSelectElement>(
      'select[aria-label="Channel to clear"]',
    );
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
    cancelButton!.focus();
    fireEvent.click(cancelButton!);
    await waitFor(() => {
      expect(document.querySelector('[role="dialog"]')).toBeNull();
      expect(channelSelect).toHaveFocus();
    });
    expect(invoke).not.toHaveBeenCalledWith("evtx_clear_channel", expect.anything());
  });

  it("returns focus after dismissing clear confirmation with Escape", async () => {
    render(<ChannelPicker />);
    const channelSelect = document.querySelector<HTMLSelectElement>(
      'select[aria-label="Channel to clear"]',
    )!;
    fireEvent.change(channelSelect, { target: { value: "Application" } });
    fireEvent.click(
      Array.from(document.querySelectorAll("button")).find(
        (button) => button.textContent?.trim() === "Clear",
      )!,
    );
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]')!;
    dialog.focus();

    fireEvent.keyDown(dialog, { key: "Escape" });

    await waitFor(() => {
      expect(document.querySelector('[role="dialog"]')).toBeNull();
      expect(channelSelect).toHaveFocus();
    });
    expect(invoke).not.toHaveBeenCalledWith("evtx_clear_channel", expect.anything());
  });

  it("keeps one confirmed channel clear pending until its result settles", async () => {
    const clearResult = deferred<{
      channel: string;
      result: { status: "unavailable"; detail: string };
    }>();
    invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
      if (name === "evtx_clear_channel") return clearResult.promise;
      return { requestId: args.requestId };
    });
    render(<ChannelPicker />);

    const { channelSelect, clearButton } = confirmChannelClear();

    expect(document.querySelector('[role="dialog"]')).toBeNull();
    expect(channelSelect).toBeDisabled();
    expect(clearButton).toBeDisabled();
    const clearStatus = document.querySelector('[role="status"]');
    expect(clearStatus).toHaveTextContent("Clearing Application…");
    await waitFor(() => expect(clearStatus).toHaveFocus());
    fireEvent.click(clearButton);
    expect(invoke.mock.calls.filter(([name]) => name === "evtx_clear_channel")).toHaveLength(1);

    clearResult.resolve({
      channel: "Application",
      result: { status: "unavailable", detail: "Access denied" },
    });
    await waitFor(() => {
      expect(channelSelect).not.toBeDisabled();
      const alert = document.querySelector('[role="alert"]');
      expect(alert).toHaveTextContent("Access denied");
      expect(alert).toHaveFocus();
    });
    expect(channelSelect.value).toBe("Application");
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it("releases the clear controls and selection after a successful clear", async () => {
    const clearResult = deferred<{
      channel: string;
      result: { status: "cleared" };
    }>();
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_clear_channel") return clearResult.promise;
      return undefined;
    });
    render(<ChannelPicker />);

    const { channelSelect } = confirmChannelClear();

    expect(channelSelect).toBeDisabled();
    clearResult.resolve({ channel: "Application", result: { status: "cleared" } });

    await waitFor(() => {
      expect(channelSelect).not.toBeDisabled();
      expect(channelSelect.value).toBe("");
      expect(channelSelect).toHaveFocus();
    });
    expect(document.querySelector('[role="dialog"]')).toBeNull();
    // The Also correlating section keeps its own empty live regions mounted for the Add log source
    // report, so the clear's regions are the ones outside it.
    const outsideAlsoCorrelating = (role: string) =>
      [...document.querySelectorAll(`[role="${role}"]`)].filter(
        (element) => !element.closest('[aria-label="Also correlating"]'),
      );
    expect(outsideAlsoCorrelating("status")).toEqual([]);
    expect(outsideAlsoCorrelating("alert")).toEqual([]);
  });

  it("does not steal focus when a background clear settles", async () => {
    const clearResult = deferred<{
      channel: string;
      result: { status: "unavailable"; detail: string };
    }>();
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_clear_channel") return clearResult.promise;
      return undefined;
    });
    render(<ChannelPicker />);

    confirmChannelClear();
    const filter = document.querySelector<HTMLInputElement>(
      'input[placeholder="Filter channels..."]',
    )!;
    await waitFor(() => expect(document.querySelector('[role="status"]')).toHaveFocus());
    filter.focus();
    expect(filter).toHaveFocus();

    clearResult.resolve({
      channel: "Application",
      result: { status: "unavailable", detail: "Access denied" },
    });

    await waitFor(() => {
      expect(document.querySelector('[role="alert"]')).toHaveTextContent("Access denied");
    });
    expect(filter).toHaveFocus();
  });

  it("recovers focus when a successful clear removes the focused live control", async () => {
    const clearResult = deferred<{
      channel: string;
      result: { status: "cleared" };
    }>();
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_clear_channel") return clearResult.promise;
      return undefined;
    });
    useEvtxStore.setState({
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
      selectedChannels: new Set(["Application"]),
    });
    render(<ChannelPicker />);

    confirmChannelClear();
    const filter = document.querySelector<HTMLInputElement>(
      'input[placeholder="Filter channels..."]',
    )!;
    // The live tail control is the footer's Resume (tail off) / Pause (tail on) link-button.
    const liveTailButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Resume",
    )!;
    await waitFor(() => expect(document.querySelector('[role="status"]')).toHaveFocus());
    liveTailButton.focus();
    expect(liveTailButton).toHaveFocus();

    clearResult.resolve({ channel: "Application", result: { status: "cleared" } });

    await waitFor(() => {
      expect(liveTailButton.isConnected).toBe(false);
      expect(filter).toHaveFocus();
    });
  });

  it.each([
    ["cancelled", "Clear was cancelled."],
    ["empty", "Application is already empty."],
  ] as const)(
    "announces a %s clear result without reopening confirmation",
    async (status, message) => {
      invoke.mockImplementation(async (name: string, args: Record<string, unknown>) => {
        if (name === "evtx_clear_channel") {
          return { channel: args.channel, result: { status } };
        }
        return undefined;
      });
      render(<ChannelPicker />);

      const { channelSelect } = confirmChannelClear();

      await waitFor(() => {
        const alert = document.querySelector('[role="alert"]');
        expect(alert).toHaveTextContent(message);
        expect(alert).toHaveFocus();
      });
      expect(channelSelect).not.toBeDisabled();
      expect(channelSelect.value).toBe("Application");
      expect(document.querySelector('[role="dialog"]')).toBeNull();
    },
  );

  it("announces a rejected clear without reopening confirmation", async () => {
    invoke.mockImplementation(async (name: string) => {
      if (name === "evtx_clear_channel") throw new Error("Remote RPC unavailable");
      return undefined;
    });
    render(<ChannelPicker />);

    const { channelSelect } = confirmChannelClear();

    await waitFor(() => {
      const alert = document.querySelector('[role="alert"]');
      expect(alert).toHaveTextContent("Command 'evtx_clear_channel' failed.");
      expect(alert).toHaveFocus();
    });
    expect(channelSelect).not.toBeDisabled();
    expect(channelSelect.value).toBe("Application");
    expect(document.querySelector('[role="dialog"]')).toBeNull();
  });

  it("queues the channel-clear confirmation behind the active app modal", async () => {
    useUiStore.getState().setShowAboutDialog(true);
    render(<AboutAndChannelPicker />);

    fireEvent.change(document.querySelector('select[aria-label="Channel to clear"]')!, {
      target: { value: "Application" },
    });
    const clearButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Clear",
    );
    fireEvent.click(clearButton!);

    expect(document.querySelectorAll('[aria-modal="true"]')).toHaveLength(1);
    expect(useUiStore.getState().modalOwner).toBe("about");
    expect(useUiStore.getState().modalQueue).toEqual(["eventLogChannelClear"]);
    expect(document.body.textContent).not.toContain("Clear event channel?");

    act(() => {
      useUiStore.getState().setShowAboutDialog(false);
    });

    await waitFor(() => {
      expect(document.body.textContent).toContain("Clear event channel?");
      expect(document.querySelectorAll('[aria-modal="true"]')).toHaveLength(1);
    });
  });
});

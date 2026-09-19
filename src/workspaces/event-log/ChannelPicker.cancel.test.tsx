/**
 * The stop control in the channel picker.
 *
 * An explicit Load is unbounded by design, so on a channel the size of the measured Security log
 * it runs for minutes. While it runs the picker offers Stop instead of Load, and pressing it asks
 * the backend to cancel the current request. The load button returns when the load settles.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxChannelInfo } from "./types";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

// The store subscribes to backend events at module scope, so it is imported after the mock that
// stands in for that bridge; a static import would be evaluated first.
const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");

function channel(name: string, eventCount = 0): EvtxChannelInfo {
  return { name, eventCount, sourceType: "live", enabledState: "enabled" };
}

describe("the stop control while a load runs", () => {
  beforeEach(() => {
    invoke.mockReset();
    useEvtxStore.setState({
      records: [],
      channels: [channel("Security", 200_000)],
      selectedChannels: new Set(["Security"]),
      loadedChannels: new Set<string>(),
      sourceMode: "live",
      remoteMachine: null,
      coverageGaps: [],
      coverageDetails: [],
      loadError: null,
      isLoading: true,
    });
  });

  it("shows Stop instead of Load while a load is in flight", () => {
    render(<ChannelPicker />);

    expect(screen.getByRole("button", { name: "Stop load" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Load/ })).not.toBeInTheDocument();
  });

  it("sends the cancel command when Stop is pressed", () => {
    invoke.mockResolvedValue(undefined);
    render(<ChannelPicker />);

    fireEvent.click(screen.getByRole("button", { name: "Stop load" }));

    expect(invoke).toHaveBeenCalledWith("evtx_cancel_channel_query", {
      requestId: expect.any(String) as string,
    });
  });

  it("returns the Load button when the load settles", () => {
    useEvtxStore.setState({ isLoading: false });
    render(<ChannelPicker />);

    expect(screen.getByRole("button", { name: "Load 1" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Stop load" })).not.toBeInTheDocument();
  });
});

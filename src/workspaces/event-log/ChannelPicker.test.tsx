/**
 * The channel picker's half of channel eligibility.
 *
 * The machine's configuration is not a hole in the view. A channel the service reports as switched
 * off holds nothing to read, so the picker says so and leaves it out of the bulk paths that would
 * otherwise ask for it and collect a refusal as a coverage gap. It stays listed: an operator
 * looking for a channel has to find it, and "not recording" is what they need to know about it.
 *
 * The state travels as `enabled` on the channel DTO in the change these tests describe. It is
 * written here through a local alias so the RED tests typecheck against the tree before it exists.
 */
import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxChannelInfo } from "./types";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

// The store subscribes to backend events at module scope, so it is imported after the mock that
// stands in for that bridge; a static import would be evaluated first.
const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");

type ChannelRecordingState = { enabled?: boolean };

function channel(
  name: string,
  state: ChannelRecordingState = {},
  eventCount = 0
): EvtxChannelInfo {
  return { name, eventCount, sourceType: "live" as const, ...state } as EvtxChannelInfo;
}

/** The service tree is collapsed by default, so a non-Windows-Logs channel has to be revealed. */
function revealServiceChannels() {
  fireEvent.click(
    screen.getByRole("button", { name: "Expand Applications and Services Logs" })
  );
}

function rowFor(name: string): HTMLElement {
  return screen.getByText(name).closest("label") as HTMLElement;
}

describe("channels the service reports as switched off", () => {
  beforeEach(() => {
    useEvtxStore.setState({
      records: [],
      channels: [
        channel("Application", { enabled: true }, 152),
        channel("AirSpaceChannel", { enabled: false }),
        channel("UnprobedChannel"),
      ],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      sourceMode: "live",
      remoteMachine: null,
      coverageGaps: [],
      loadError: null,
      isLoading: false,
    });
  });

  it("keeps a switched-off channel listed and says why it will not be read", () => {
    render(<ChannelPicker />);
    revealServiceChannels();

    const row = rowFor("AirSpaceChannel");
    expect(row).toHaveTextContent("AirSpaceChannel");
    expect(within(row).getByText("disabled")).toBeInTheDocument();
  });

  it("does not mark a channel whose recording state could not be read", () => {
    // Only the service saying "switched off" earns the mark. A probe that failed says nothing about
    // the channel, and calling it disabled would hide a live channel from the operator.
    render(<ChannelPicker />);
    revealServiceChannels();

    expect(within(rowFor("UnprobedChannel")).queryByText("disabled")).toBeNull();
    expect(screen.getAllByText("disabled")).toHaveLength(1);
    expect(rowFor("AirSpaceChannel")).toHaveTextContent("disabled");
  });

  it("leaves a switched-off channel out of Select all", () => {
    render(<ChannelPicker />);

    fireEvent.click(screen.getByRole("button", { name: "Select all" }));

    expect([...useEvtxStore.getState().selectedChannels].sort()).toEqual([
      "Application",
      "UnprobedChannel",
    ]);
  });

  it("does not offer a switched-off channel for selection", () => {
    render(<ChannelPicker />);
    revealServiceChannels();

    const switchedOff = within(rowFor("AirSpaceChannel")).getByRole("checkbox");
    expect(switchedOff).toBeDisabled();

    fireEvent.click(switchedOff);
    expect(useEvtxStore.getState().selectedChannels.has("AirSpaceChannel")).toBe(false);
  });
});

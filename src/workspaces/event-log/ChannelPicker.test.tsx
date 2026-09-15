/**
 * The channel picker's half of channel eligibility.
 *
 * The machine's configuration is not a hole in the view. A channel the service reports as switched
 * off holds nothing to read, so the picker says so and leaves it out of the bulk paths that would
 * otherwise ask for it and collect a refusal as a coverage gap. It stays listed: an operator
 * looking for a channel has to find it, and "not recording" is what they need to know about it.
 *
 * The state travels as `enabledState` on the channel DTO in the change these tests describe, as one
 * of three named states rather than a flag. It is written here through a local alias until the DTO
 * carries it.
 */
import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxChannelEnabledState, EvtxChannelInfo } from "./types";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

// The store subscribes to backend events at module scope, so it is imported after the mock that
// stands in for that bridge; a static import would be evaluated first.
const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");

function channel(
  name: string,
  enabledState: EvtxChannelEnabledState,
  eventCount = 0
): EvtxChannelInfo {
  return { name, eventCount, sourceType: "live", enabledState };
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

function checkboxFor(name: string): HTMLElement {
  return within(rowFor(name)).getByRole("checkbox");
}

describe("channels the service reports as switched off", () => {
  beforeEach(() => {
    useEvtxStore.setState({
      records: [],
      channels: [
        channel("Application", "enabled", 152),
        channel("AirSpaceChannel", "disabled"),
        channel("UnprobedChannel", "unknown"),
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

  it("lists a switched-off channel and marks it as such", () => {
    // Listed and marked rather than hidden: the channel exists on the machine, it is simply not
    // recording, and that is why the bulk paths leave it out. Nothing in it is missing from the
    // view, so it is not a hole in the view.
    render(<ChannelPicker />);
    revealServiceChannels();

    expect(rowFor("AirSpaceChannel")).toHaveTextContent("disabled");
  });

  it("does not offer a switched-off channel for selection", () => {
    // Its own control cannot select it either. Offering the control and then refusing the
    // selection in the store would leave a checkbox that does nothing.
    render(<ChannelPicker />);
    revealServiceChannels();

    const switchedOff = checkboxFor("AirSpaceChannel");
    expect(switchedOff).toBeDisabled();

    fireEvent.click(switchedOff);

    expect(useEvtxStore.getState().selectedChannels.has("AirSpaceChannel")).toBe(false);
  });

  it("refuses only the channel the service reported as switched off", () => {
    // Fail open at the surface too. Only the service saying "switched off" earns the mark and the
    // refused control; an unreadable configuration says nothing, and treating that silence as
    // "switched off" would hide a live channel from the operator. Asserted through what the
    // controls do, so a rule written as "not known to be recording" fails here.
    render(<ChannelPicker />);
    revealServiceChannels();

    expect(rowFor("UnprobedChannel")).not.toHaveTextContent("disabled");

    fireEvent.click(checkboxFor("UnprobedChannel"));
    fireEvent.click(checkboxFor("AirSpaceChannel"));

    expect([...useEvtxStore.getState().selectedChannels]).toEqual(["UnprobedChannel"]);
  });

  it("does not mark a channel from an entry that has no state field", () => {
    // The field arrived with this change, so an entry written before it carries no state, and the
    // picker is where an operator would first see it treated as switched off. Absence follows the
    // same rule `unknown` does: listed, unmarked, selectable.
    useEvtxStore.setState({
      channels: [{ name: "LegacyChannel", eventCount: 3, sourceType: "live" }],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
    });

    render(<ChannelPicker />);
    revealServiceChannels();

    expect(rowFor("LegacyChannel")).not.toHaveTextContent("disabled");

    fireEvent.click(checkboxFor("LegacyChannel"));

    expect(useEvtxStore.getState().selectedChannels.has("LegacyChannel")).toBe(true);
  });

  it("leaves a switched-off channel out of Select all", () => {
    render(<ChannelPicker />);

    fireEvent.click(screen.getByRole("button", { name: "Select all" }));

    expect([...useEvtxStore.getState().selectedChannels].sort()).toEqual([
      "Application",
      "UnprobedChannel",
    ]);
  });
});

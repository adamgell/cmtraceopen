/**
 * The channel pane's resize handle wiring (spec 5.2): a 1 px border with an `EvtxResizeHandle`
 * overlaid. Kept apart from `ChannelPicker.test.tsx`, which covers channel eligibility.
 */
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");

describe("channel pane resize handle", () => {
  beforeEach(() => {
    useEvtxStore.setState({
      records: [],
      channels: [{ name: "Application", eventCount: 1, sourceType: "live", enabledState: "enabled" }],
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      sourceMode: "live",
      remoteMachine: null,
      coverageGaps: [],
      loadError: null,
      isLoading: false,
    });
  });
  afterEach(cleanup);

  it("starts at 250, grows with ArrowRight, reaches 500 with End and 200 with Home", () => {
    render(<ChannelPicker />);
    const handle = screen.getByRole("separator", { name: "Resize channel pane" });
    expect(handle).toHaveAttribute("aria-valuenow", "250");
    expect(handle).toHaveAttribute("aria-valuemin", "200");
    expect(handle).toHaveAttribute("aria-valuemax", "500");

    fireEvent.keyDown(handle, { key: "ArrowRight" });
    expect(handle).toHaveAttribute("aria-valuenow", "266");
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    expect(handle).toHaveAttribute("aria-valuenow", "250");
    fireEvent.keyDown(handle, { key: "End" });
    expect(handle).toHaveAttribute("aria-valuenow", "500");
    fireEvent.keyDown(handle, { key: "Home" });
    expect(handle).toHaveAttribute("aria-valuenow", "200");
  });

  it("points aria-controls at the pane it sizes, which is the handle's positioned parent", () => {
    render(<ChannelPicker />);
    const handle = screen.getByRole("separator", { name: "Resize channel pane" });
    const pane = document.getElementById(handle.getAttribute("aria-controls") ?? "");
    expect(pane).not.toBeNull();
    expect(pane).toBe(handle.parentElement);
    expect(pane).toHaveStyle({ width: "250px" });
    fireEvent.keyDown(handle, { key: "ArrowRight" });
    expect(pane).toHaveStyle({ width: "266px" });
  });

  it("caps the pane at 40% of the row so a narrow window cannot squeeze the main view to nothing", () => {
    render(<ChannelPicker />);
    const handle = screen.getByRole("separator", { name: "Resize channel pane" });
    const pane = handle.parentElement as HTMLElement;
    expect(pane).toHaveStyle({ maxWidth: "40%", minWidth: "0px" });
    expect(pane).toHaveStyle({ flexShrink: "0" });
  });
});

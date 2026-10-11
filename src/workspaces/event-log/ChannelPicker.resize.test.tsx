/**
 * The channel pane's resize handle wiring (spec 5.2): a 1 px border with an `EvtxResizeHandle`
 * overlaid. Kept apart from `ChannelPicker.test.tsx`, which covers channel eligibility.
 */
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { requireElement, stubLayout } from "./evtx-test-dom";

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

  it("reports the rendered width and caps the maximum when the row is too narrow for the stored width", () => {
    // A 500 px row caps the pane at 200 px; the stored width stays at its 250 px default.
    const restore = stubLayout({ "evtx-channel-pane": 200 }, 500);
    try {
      render(<ChannelPicker />);
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
      const handle = screen.getByRole("separator", { name: "Resize channel pane" });
      expect(handle).toHaveAttribute("aria-valuenow", "200");
      expect(handle).toHaveAttribute("aria-valuemin", "200");
      expect(handle).toHaveAttribute("aria-valuemax", "200");
      // Steps start from what is on screen and cannot move the reported value past the cap.
      fireEvent.keyDown(handle, { key: "ArrowRight" });
      expect(handle).toHaveAttribute("aria-valuenow", "200");
      fireEvent.keyDown(handle, { key: "End" });
      expect(handle).toHaveAttribute("aria-valuenow", "200");
      // Neither changed the visible pane, so the requested 250 px must survive.
      const pane = requireElement(handle.parentElement, "the channel pane");
      expect(pane).toHaveStyle({ width: "250px" });
      // The row widens: the pane returns to the requested width.
      restore.set({ "evtx-channel-pane": 250 }, 1440);
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
      expect(handle).toHaveAttribute("aria-valuenow", "250");
      expect(handle).toHaveAttribute("aria-valuemax", "500");
    } finally {
      restore();
    }
  });

  it("keeps the nominal 200 to 500 range when the cap is not binding", () => {
    const restore = stubLayout({ "evtx-channel-pane": 250 }, 1440);
    try {
      render(<ChannelPicker />);
      act(() => {
        window.dispatchEvent(new Event("resize"));
      });
      const handle = screen.getByRole("separator", { name: "Resize channel pane" });
      expect(handle).toHaveAttribute("aria-valuenow", "250");
      expect(handle).toHaveAttribute("aria-valuemin", "200");
      expect(handle).toHaveAttribute("aria-valuemax", "500");
    } finally {
      restore();
    }
  });

  it("does not cap itself by percentage: that would resolve against its own shrink-to-fit wrapper", () => {
    render(<ChannelPicker />);
    const pane = requireElement(
      screen.getByRole("separator", { name: "Resize channel pane" }).parentElement,
      "the channel pane",
    );
    expect(pane.style.maxWidth).toBe("");
    expect(pane).toHaveStyle({ width: "250px", minWidth: "0px", flexShrink: "1" });
  });
});

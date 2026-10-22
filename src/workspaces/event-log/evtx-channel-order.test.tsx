import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { orderChannelNames } from "./evtx-channel-order";
import type { EvtxChannelInfo } from "./types";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");

const NAMES = [
  "Microsoft-Windows-Kernel-Power/Thermal-Operational",
  "System",
  "Microsoft-Windows-AAD/Operational",
  "Setup",
  "Application",
  "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
  "Microsoft-Windows-AAD/Analytic",
  "ForwardedEvents",
  "Security",
  "Microsoft-Windows-Kernel-Power",
  "OAlerts",
  "Microsoft-Windows-Kernel-Boot/Operational",
];

describe("orderChannelNames", () => {
  it("puts Windows Logs first in the pane's fixed order", () => {
    expect(
      orderChannelNames(["Setup", "System", "ForwardedEvents", "Application", "Security"]),
    ).toEqual(["Application", "Security", "System", "Setup", "ForwardedEvents"]);
  });

  it("sorts the services tree by name after the Windows Logs", () => {
    const ordered = orderChannelNames(["Zeta/Operational", "System", "Alpha/Operational"]);
    expect(ordered).toEqual(["System", "Alpha/Operational", "Zeta/Operational"]);
  });

  it("is independent of the input order and keeps every name once", () => {
    const forward = orderChannelNames(NAMES);
    expect(orderChannelNames([...NAMES].reverse())).toEqual(forward);
    expect([...forward].sort()).toEqual([...NAMES].sort());
  });

  it("returns an empty list for no channels", () => {
    expect(orderChannelNames([])).toEqual([]);
  });
});

describe("orderChannelNames against the real channel pane", () => {
  beforeEach(() => {
    const channels: EvtxChannelInfo[] = NAMES.map((name) => ({
      name,
      eventCount: 1,
      sourceType: "live",
      enabledState: "enabled",
    }));
    useEvtxStore.setState({
      records: [],
      channels,
      selectedChannels: new Set<string>(),
      loadedChannels: new Set<string>(),
      sourceMode: "live",
      remoteMachine: null,
      coverageGaps: [],
      loadError: null,
      isLoading: false,
    });
  });

  it("matches the order the pane lists them in once every folder is open", () => {
    const { container } = render(<ChannelPicker />);
    // Every disclosure button reads "Expand X"; opening one reveals more of them.
    for (let guard = 0; guard < 100; guard += 1) {
      const next = screen.queryAllByRole("button", { name: /^Expand / })[0];
      if (!next) break;
      fireEvent.click(next);
    }
    const shown = [
      ...container.querySelectorAll<HTMLElement>('label[title], input[aria-label^="Select "]'),
    ]
      .map((el) =>
        el.tagName === "LABEL" ? el.getAttribute("title")! : el.getAttribute("aria-label")!.slice("Select ".length),
      )
      .filter((name) => NAMES.includes(name));
    expect(shown).toEqual(orderChannelNames(NAMES));
  });
});

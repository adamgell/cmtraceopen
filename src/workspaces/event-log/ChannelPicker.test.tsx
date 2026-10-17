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
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tokens } from "@fluentui/react-components";
import { contrastRatio } from "../../lib/color-contrast";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getAllThemes } from "../../lib/themes";
import { deferred } from "../../test-utils/deferred";
import type { CMTraceTheme } from "../../lib/themes/types";
import type { LogEntry } from "../../types/log";
import type {
  EvtxChannelEnabledState,
  EvtxChannelInfo,
  EvtxCoverageGap,
  EvtxLevel,
  EvtxRecord,
} from "./types";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

// The helper has its own tests against the real loaders; the pane's tests need only what it says.
const addLogSourceMock = vi.hoisted(() => vi.fn());
vi.mock("./add-log-source", () => ({ addLogSource: addLogSourceMock }));

// The store subscribes to backend events at module scope, so it is imported after the mock that
// stands in for that bridge; a static import would be evaluated first.
const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");
const { buildEvtxVisualTokens, resolveToken } = await import("./evtx-visual-tokens");
const { orderChannelNames } = await import("./evtx-channel-order");
const { WILDCARD_MISSING_REASON } = await import("./evtx-channel-stats");
const { useLogStore } = await import("../../stores/log-store");
const { useUiStore } = await import("../../stores/ui-store");

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

// ── The restyled pane (spec 8.6, issue #837) ────────────────────────────────

const NOW = Date.UTC(2026, 9, 10, 12, 0, 0);
const HOUR = 60 * 60 * 1000;
/** U+2014, the spec's dash for a total that is not known. */
const DASH = "\u2014";

function evtxRecord(
  channel: string,
  timestampEpoch: number,
  level: EvtxLevel = "Information",
): EvtxRecord {
  return {
    id: 0,
    eventRecordId: 1,
    timestamp: "",
    timestampEpoch,
    provider: "Provider",
    channel,
    eventId: 1,
    level,
    computer: "HOST",
    message: "",
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
  };
}

function textLog(filePath: string, line: number): LogEntry {
  return {
    id: line,
    lineNumber: line,
    message: "",
    component: null,
    timestamp: NOW,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: "ccmutillib.cpp",
    format: "Ccm",
    filePath,
    timezoneOffset: null,
  };
}

const gapRecord = (
  source: string,
  kind: EvtxCoverageGap["kind"],
  reason: string,
): EvtxCoverageGap => ({ source, kind, reason });

function resetPane(over: Record<string, unknown> = {}) {
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
  useLogStore.setState({ entries: [], activeSource: null, sourceOpenMode: null });
  useEvtxStore.setState({
    records: [],
    channels: [],
    selectedChannels: new Set<string>(),
    loadedChannels: new Set<string>(),
    sourceMode: "live",
    remoteMachine: null,
    timeWindow: "24h",
    coverageGaps: [],
    coverageDetails: [],
    sourceManifest: null,
    archiveMembers: [],
    tailMode: null,
    tailChannels: new Set<string>(),
    tailCoverageGaps: [],
    loadError: null,
    isLoading: false,
    ...over,
  });
}

function paneRow(name: string): HTMLElement {
  const row = document.querySelector<HTMLElement>(`[data-channel-row="${name}"]`);
  if (!row) throw new Error(`No pane row for ${name}`);
  return row;
}

function rowSparkline(name: string): SVGElement {
  return paneRow(name).querySelector("svg") as SVGElement;
}

/** What a screen reader gets for a row: the text the checkbox is described by. */
function rowDescription(name: string): string {
  const box = within(paneRow(name)).getByRole("checkbox");
  return document.getElementById(box.getAttribute("aria-describedby")!)!.textContent ?? "";
}

function plottedBins(name: string): number[] {
  return [...rowSparkline(name).querySelectorAll("rect[data-bin]")].map((rect) =>
    Number(rect.getAttribute("data-bin")),
  );
}

describe("the channel pane header and rows", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    resetPane({
      channels: [
        channel("Application", "enabled"),
        channel("System", "enabled"),
        channel("Setup", "enabled"),
      ],
      loadedChannels: new Set(["Application", "System"]),
      selectedChannels: new Set(["System"]),
      records: [
        evtxRecord("System", NOW - 30 * 60 * 1000, "Error"),
        evtxRecord("System", NOW - 3 * HOUR, "Critical"),
        evtxRecord("System", NOW - 5 * HOUR, "Warning"),
        evtxRecord("System", NOW - 6 * HOUR),
      ],
    });
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("reads '{read} of {total} read' with the activity window", () => {
    render(<ChannelPicker />);
    expect(screen.getByText("2 of 3 read \u00B7 24 h activity")).toBeInTheDocument();

    cleanup();
    useEvtxStore.setState({ timeWindow: "all" });
    render(<ChannelPicker />);
    expect(screen.getByText("2 of 3 read \u00B7 all-time activity")).toBeInTheDocument();
  });

  it("shows the total, errors and warnings of a read channel, counting Critical as an error", () => {
    render(<ChannelPicker />);
    const row = paneRow("System");
    expect(within(row).getByText("4")).toBeInTheDocument();
    expect(within(row).getByText("2 err")).toBeInTheDocument();
    expect(within(row).getByText("1 warn")).toBeInTheDocument();
  });

  it("plots each event in its hour bin and leaves the other bins empty", () => {
    render(<ChannelPicker />);
    // 30 min, 3 h, 5 h and 6 h before now fall in bins 23, 21, 19 and 18 of the 24 h window.
    expect(plottedBins("System")).toEqual([18, 19, 21, 23]);
  });

  it("hides the sparkline from assistive technology and puts its numbers in the row's description", () => {
    render(<ChannelPicker />);
    expect(rowSparkline("System")).toHaveAttribute("aria-hidden", "true");
    expect(within(paneRow("System")).queryByRole("img")).toBeNull();
    const description = rowDescription("System");
    expect(description).toContain("4 events, 2 errors, 1 warning");
    expect(description).toContain("24 h activity: 4 of 24 intervals had events, busiest 1");
    // The checkbox's own name says which channel; the description does not repeat it.
    expect(description).not.toContain("System");
  });

  it("describes the total, or that there is none, so the number is not only in the label", () => {
    render(<ChannelPicker />);
    expect(rowDescription("System")).toMatch(/^4 events,/);
    expect(rowDescription("Setup")).toMatch(/^No count\./);
    expect(rowDescription("Application")).toMatch(/^0 events, 0 errors, 0 warnings\./);
  });

  it("hides the visible counts line from assistive technology, since the description says it once", () => {
    render(<ChannelPicker />);
    const counts = within(paneRow("System")).getByText("2 err").parentElement!;
    expect(counts).toHaveAttribute("aria-hidden", "true");
  });

  it("says how many events the sparkline leaves out, and never draws them in bin 0", () => {
    useEvtxStore.setState({
      records: [
        evtxRecord("System", 0, "Error"),
        evtxRecord("System", NOW - 48 * HOUR),
        evtxRecord("System", NOW - HOUR),
      ],
    });
    render(<ChannelPicker />);
    // One hour before now is the start of the last bin.
    expect(plottedBins("System")).toEqual([23]);
    expect(rowDescription("System")).toContain(
      "24 h activity: 1 of 24 intervals had events, busiest 1; 2 not plotted (1 without a timestamp, 1 outside the window)",
    );
    // They still count where the channel's events are counted.
    expect(within(paneRow("System")).getByText("3")).toBeInTheDocument();
    expect(within(paneRow("System")).getByText("1 err")).toBeInTheDocument();
  });

  it("shows a real zero for a channel that was read and held nothing", () => {
    render(<ChannelPicker />);
    const row = paneRow("Application");
    expect(within(row).getByText("0")).toBeInTheDocument();
    expect(within(row).getByText("0 err")).toBeInTheDocument();
    expect(plottedBins("Application")).toEqual([]);
    expect(rowDescription("Application")).toContain("24 h activity: no events");
  });

  it("gives a channel nobody has loaded a dash and a flat line, never a zero", () => {
    render(<ChannelPicker />);
    const row = paneRow("Setup");
    expect(row).toHaveAttribute("data-channel-state", "notLoaded");
    expect(row).toHaveTextContent(DASH);
    expect(row).toHaveTextContent("not loaded");
    expect(row).not.toHaveTextContent(/\b0\b/);
    expect(plottedBins("Setup")).toEqual([]);
    expect(rowDescription("Setup")).toBe(
      "No count. Not loaded. 24 h activity: no data, the channel was not read.",
    );
  });

  it("describes the checkbox by the row's counts so the numbers reach a screen reader", () => {
    render(<ChannelPicker />);
    const box = within(paneRow("System")).getByRole("checkbox", { name: "Select System" });
    const description = document.getElementById(box.getAttribute("aria-describedby")!)!;
    expect(description).toHaveTextContent("2 err");
    expect(description).toHaveTextContent("1 warn");
  });

  it("marks the live tail on the channels it covers", () => {
    useEvtxStore.setState({ tailMode: "subscription", tailChannels: new Set(["System"]) });
    render(<ChannelPicker />);
    expect(paneRow("System")).toHaveTextContent("\u00B7 live");
    expect(paneRow("Application")).not.toHaveTextContent("live");
  });

  it("does not let a tail gap change what was read", () => {
    useEvtxStore.setState({ tailCoverageGaps: ["System: live tail unavailable (not supported)"] });
    render(<ChannelPicker />);
    expect(paneRow("System")).toHaveAttribute("data-channel-state", "read");
  });

  it("uses the selection triplet and the selection data color on a selected row only", () => {
    render(<ChannelPicker />);
    const selected = paneRow("System");
    expect(selected.style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    expect(selected.style.boxShadow).toContain(tokens.colorPaletteBlueBorderActive);
    expect(selected.style.boxShadow).toContain("inset 3px 0 0");
    const selectedBar = selected.querySelector<SVGElement>("rect[data-bin]")!;
    expect(selectedBar.style.fill).toBe(tokens.colorPaletteBlueForeground2);

    const plain = paneRow("Application");
    expect(plain.style.backgroundColor).toBe("");
    expect(plain.style.boxShadow).toBe("");
  });

  it("keeps a channel's color across the tree and a filtered list", () => {
    useEvtxStore.setState({
      records: [evtxRecord("System", NOW - HOUR), evtxRecord("Application", NOW - HOUR)],
    });
    render(<ChannelPicker />);
    const swatch = (name: string) =>
      paneRow(name).querySelector<HTMLElement>('span[aria-hidden="true"][style*="border-radius"]')!;
    const inTree = swatch("System").style.backgroundColor;
    expect(inTree).not.toBe("");
    // Application and System are Windows Logs 0 and 2, so their colors differ.
    expect(swatch("Application").style.backgroundColor).not.toBe(inTree);

    fireEvent.change(screen.getByPlaceholderText("Filter channels..."), {
      target: { value: "system" },
    });
    expect(document.querySelector('[data-channel-row="Application"]')).toBeNull();
    expect(swatch("System").style.backgroundColor).toBe(inTree);
  });

  it("collapses a group from its header, with a chevron icon rather than a text glyph", () => {
    render(<ChannelPicker />);
    const disclosure = screen.getByRole("button", { name: "Collapse Windows Logs" });
    expect(disclosure).toHaveAttribute("aria-expanded", "true");
    expect(disclosure.querySelector("svg")).not.toBeNull();
    expect(disclosure.textContent).toBe("");

    fireEvent.click(disclosure);
    expect(screen.getByRole("button", { name: "Expand Windows Logs" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
    expect(document.querySelector('[data-channel-row="System"]')).toBeNull();

    fireEvent.click(screen.getByText("Windows Logs"));
    expect(document.querySelector('[data-channel-row="System"]')).not.toBeNull();
  });

  it("sizes the first line, captions and groups from the list font size", () => {
    for (const size of [11, 13, 20]) {
      cleanup();
      useUiStore.setState({ logListFontSize: size });
      const metrics = getLogListMetrics(size);
      render(<ChannelPicker />);
      const label = paneRow("System").querySelector("label")!;
      expect(label.style.height).toBe(`${metrics.rowHeight}px`);
      expect(label.parentElement!.style.fontSize).toBe(`${metrics.fontSize}px`);
      expect(screen.getByText("2 err").style.color).not.toBe("");
      expect(screen.getByText("2 err").parentElement!.style.fontSize).toBe(
        `${Math.max(10, metrics.fontSize - 3)}px`,
      );
      expect(screen.getByText("Windows Logs").style.fontSize).toBe(
        `${Math.max(10, metrics.fontSize - 2)}px`,
      );
    }
  });

  it("keeps the pane exactly as wide as the layout sets it, with its border and resize handle", () => {
    render(<ChannelPicker />);
    const pane = document.getElementById("evtx-channel-pane")!;
    expect(pane.style.width).toBe("250px");
    expect(pane.style.borderRight).toBe(`1px solid ${tokens.colorNeutralStroke2}`);
    expect(screen.getByRole("separator", { name: "Resize channel pane" })).toBeInTheDocument();
  });
});

describe("which groups start open", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    resetPane({
      channels: [
        channel("System", "enabled"),
        channel("Contoso-AAD/Operational", "enabled"),
        channel("Fabrikam-Other/Operational", "enabled"),
      ],
      loadedChannels: new Set(["System", "Contoso-AAD/Operational", "Fabrikam-Other/Operational"]),
      records: [evtxRecord("Contoso-AAD/Operational", NOW - HOUR)],
    });
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  const rowExists = (name: string) =>
    document.querySelector(`[data-channel-row="${name}"]`) !== null;

  it("opens the groups on the path to a loaded channel that holds events and leaves the rest closed", () => {
    render(<ChannelPicker />);
    expect(rowExists("Contoso-AAD/Operational")).toBe(true);
    expect(screen.getByRole("button", { name: "Collapse Applications and Services Logs" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Collapse Contoso-AAD" })).toBeInTheDocument();
    // Loaded but empty: its group stays closed, so its channel is not listed.
    expect(screen.getByRole("button", { name: "Expand Fabrikam-Other" })).toBeInTheDocument();
    expect(rowExists("Fabrikam-Other/Operational")).toBe(false);
  });

  it("opens nothing beyond Windows Logs when no channel holds events", () => {
    useEvtxStore.setState({ records: [] });
    render(<ChannelPicker />);
    expect(screen.getByRole("button", { name: "Collapse Windows Logs" })).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Expand Applications and Services Logs" }),
    ).toBeInTheDocument();
    expect(rowExists("Contoso-AAD/Operational")).toBe(false);
  });

  it("opens a group when its first events arrive, but not one the operator closed", () => {
    useEvtxStore.setState({ records: [] });
    render(<ChannelPicker />);
    expect(rowExists("Contoso-AAD/Operational")).toBe(false);

    act(() =>
      useEvtxStore.setState({ records: [evtxRecord("Contoso-AAD/Operational", NOW - HOUR)] }),
    );
    expect(rowExists("Contoso-AAD/Operational")).toBe(true);

    // Close the group by hand, then let more events arrive: the choice holds.
    fireEvent.click(screen.getByRole("button", { name: "Collapse Contoso-AAD" }));
    expect(rowExists("Contoso-AAD/Operational")).toBe(false);
    act(() =>
      useEvtxStore.setState({
        records: [
          evtxRecord("Contoso-AAD/Operational", NOW - HOUR),
          evtxRecord("Contoso-AAD/Operational", NOW - 2 * HOUR),
        ],
      }),
    );
    expect(rowExists("Contoso-AAD/Operational")).toBe(false);

    // A group opened by hand stays open when the data would not have opened it.
    fireEvent.click(screen.getByRole("button", { name: "Expand Fabrikam-Other" }));
    expect(rowExists("Fabrikam-Other/Operational")).toBe(true);
  });
});

describe("channels that could not be read are coverage gaps", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  /** The shape the screenshot fixture feeds the pane: Security.evtx has a gap and no channel. */
  function openFilesWithUnreadableSecurity() {
    const path = "C:\\logs\\Security.evtx";
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [
        { name: "System", eventCount: 1, sourceType: { file: { path: "C:\\logs\\System.evtx" } } },
      ],
      selectedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
      coverageDetails: [gapRecord(path, "accessDenied", "source metadata access was denied")],
      sourceManifest: {
        entries: [],
        coverage: [{ kind: "accessDenied", path, reason: "source metadata access was denied" }],
      },
      coverageGaps: [`${path}: source metadata access was denied`],
    });
  }

  it("renders an accessDenied channel as needs elevation, a dash and a flat sparkline", () => {
    openFilesWithUnreadableSecurity();
    render(<ChannelPicker />);

    const row = paneRow("Security");
    expect(row).toHaveAttribute("data-channel-state", "needsElevation");
    expect(row).toHaveTextContent("needs elevation");
    expect(row).toHaveTextContent(DASH);
    expect(plottedBins("Security")).toEqual([]);
    // Never a zero: not the total, and not an "0 err" that would say the channel is clean.
    expect(row).not.toHaveTextContent(/\b0\b/);
    expect(row).not.toHaveTextContent(/\d+ err/);
    expect(rowDescription("Security")).toContain("No count. Needs elevation.");
  });

  it("lists the unreadable source in the tree, counts it as a channel and not as read", () => {
    openFilesWithUnreadableSecurity();
    render(<ChannelPicker />);
    expect(screen.getByText("1 of 2 read \u00B7 all-time activity")).toBeInTheDocument();
  });

  it("cannot select a source that was never opened", () => {
    openFilesWithUnreadableSecurity();
    render(<ChannelPicker />);
    const box = within(paneRow("Security")).getByRole("checkbox", { name: "Select Security" });
    expect(box).toBeDisabled();
    fireEvent.click(box);
    expect(useEvtxStore.getState().selectedChannels.has("Security")).toBe(false);
  });

  it("recognizes the live refusal the backend files as a record gap", () => {
    const refusal =
      "the Event Log service refused the channel query (Windows error 5: Access is denied)";
    resetPane({
      channels: [channel("Security", "enabled"), channel("System", "enabled")],
      loadedChannels: new Set(["System"]),
      coverageDetails: [gapRecord("Security", "record", refusal)],
      coverageGaps: [`Security: ${refusal}`],
    });
    render(<ChannelPicker />);
    expect(paneRow("Security")).toHaveTextContent("needs elevation");
    expect(paneRow("System")).toHaveAttribute("data-channel-state", "read");
  });

  it("does not suggest elevating this app for a refusal from a remote machine", () => {
    resetPane({
      remoteMachine: "SRV01",
      channels: [channel("Security", "enabled")],
      coverageGaps: [
        "SRV01/Security: the Event Log service refused the channel query (Windows error 5: Access is denied)",
      ],
    });
    render(<ChannelPicker />);
    expect(paneRow("Security")).toHaveTextContent("access denied");
    expect(paneRow("Security")).not.toHaveTextContent("elevation");
  });

  it("reports a channel whose query threw as not read", () => {
    resetPane({
      channels: [channel("System", "enabled")],
      coverageGaps: ["System: not read (the RPC server is unavailable)"],
    });
    render(<ChannelPicker />);
    expect(paneRow("System")).toHaveTextContent("not read");
    expect(paneRow("System")).toHaveTextContent(DASH);
  });

  it("calls a read with a gap partial and keeps its numbers", () => {
    resetPane({
      channels: [channel("System", "enabled")],
      loadedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
      coverageDetails: [gapRecord("System", "record", "record 7 could not be decoded")],
    });
    render(<ChannelPicker />);
    const row = paneRow("System");
    expect(row).toHaveAttribute("data-channel-state", "partial");
    expect(row).toHaveTextContent("partial");
    expect(within(row).getByText("1")).toBeInTheDocument();
    expect(screen.getByText("1 of 1 read \u00B7 24 h activity")).toBeInTheDocument();
  });
});

describe("the Also correlating section", () => {
  beforeEach(() => {
    resetPane({ channels: [channel("System", "enabled")] });
  });
  afterEach(cleanup);

  it("renders with no text log open: the eyebrow and the link, no rows and no note", () => {
    // The Add log source link lives here, so the section cannot wait for a first source.
    render(<ChannelPicker />);
    const section = screen.getByRole("region", { name: "Also correlating" });
    expect(within(section).getByText("Also correlating")).toBeInTheDocument();
    expect(within(section).getByRole("button", { name: "Add log source\u2026" })).toBeInTheDocument();
    expect(within(section).queryByText(/entr/)).not.toBeInTheDocument();
    expect(within(section).queryByText(/^Correlating:/)).not.toBeInTheDocument();
  });

  it("lists each open text log by file with its entry count", () => {
    useLogStore.setState({
      sourceOpenMode: "merged",
      entries: [
        textLog("C:\\logs\\ccmexec.log", 1),
        textLog("C:\\logs\\ccmexec.log", 2),
        textLog("C:\\logs\\AppEnforce.log", 3),
      ],
    });
    render(<ChannelPicker />);
    const section = screen.getByRole("region", { name: "Also correlating" });
    const items = within(section).getAllByText(/entr/);
    expect(items.map((item) => item.textContent)).toEqual(["1 entry", "2 entries"]);
    // Labelled by the log file, not by the code file each line names (sourceFile).
    expect(within(section).getByText("AppEnforce.log")).toBeInTheDocument();
    expect(within(section).getByText("ccmexec.log")).toBeInTheDocument();
    expect(within(section).queryByText("ccmutillib.cpp")).not.toBeInTheDocument();
  });

  it("lists only what the workspace sends to the session when one source is active", () => {
    useLogStore.setState({
      sourceOpenMode: "aggregate-folder",
      activeSource: { kind: "file", path: "C:\\logs\\ccmexec.log" },
      entries: [textLog("C:\\logs\\ccmexec.log", 1), textLog("C:\\other\\Other.log", 2)],
    });
    useUiStore.setState({ currentPlatform: "windows" });
    render(<ChannelPicker />);
    const section = screen.getByRole("region", { name: "Also correlating" });
    expect(within(section).getByText("ccmexec.log")).toBeInTheDocument();
    expect(within(section).queryByText("Other.log")).not.toBeInTheDocument();
  });

  it("shows the first fifty sources and says how many more there are", () => {
    useLogStore.setState({
      sourceOpenMode: "merged",
      entries: Array.from({ length: 53 }, (_, i) => textLog(`C:\\logs\\f${i}.log`, i)),
    });
    render(<ChannelPicker />);
    const section = screen.getByRole("region", { name: "Also correlating" });
    expect(within(section).getAllByText(/\bentry\b/)).toHaveLength(50);
    expect(within(section).getByText("and 3 more")).toBeInTheDocument();
  });

  it("ends the list with the Add log source link", () => {
    useLogStore.setState({ sourceOpenMode: "merged", entries: [textLog("C:\\logs\\a.log", 1)] });
    render(<ChannelPicker />);
    const section = screen.getByRole("region", { name: "Also correlating" });
    const link = within(section).getByRole("button", { name: "Add log source\u2026" });
    const row = within(section).getByText("a.log");
    expect(row.compareDocumentPosition(link) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  describe("the note says what the session is given, from the live mode", () => {
    const FILE = "C:\\logs\\a.log";
    const scoped = (mode: "single-file" | "aggregate-folder" | "diff") => {
      useUiStore.setState({ currentPlatform: "windows" });
      useLogStore.setState({
        sourceOpenMode: mode,
        activeSource: { kind: "file", path: FILE },
        entries: [textLog(FILE, 1)],
      });
    };

    it.each(["single-file", "aggregate-folder", "diff"] as const)(
      "says only the active source is correlated in %s mode",
      (mode) => {
        scoped(mode);
        render(<ChannelPicker />);
        expect(screen.getByText("Correlating: active log source only")).toBeInTheDocument();
        expect(screen.queryByText("Correlating: all open logs")).not.toBeInTheDocument();
      },
    );

    it("says every open log is correlated in merged mode", () => {
      useLogStore.setState({ sourceOpenMode: "merged", entries: [textLog(FILE, 1)] });
      render(<ChannelPicker />);
      expect(screen.getByText("Correlating: all open logs")).toBeInTheDocument();
      expect(screen.queryByText("Correlating: active log source only")).not.toBeInTheDocument();
    });

    it("follows the mode as it changes, without a remount", () => {
      scoped("single-file");
      render(<ChannelPicker />);
      expect(screen.getByText("Correlating: active log source only")).toBeInTheDocument();

      act(() => useLogStore.setState({ sourceOpenMode: "merged" }));
      expect(screen.getByText("Correlating: all open logs")).toBeInTheDocument();

      act(() => useLogStore.setState({ sourceOpenMode: "single-file" }));
      expect(screen.getByText("Correlating: active log source only")).toBeInTheDocument();
    });

    it("is not shown while no source is listed, whatever the mode", () => {
      useLogStore.setState({ sourceOpenMode: "merged", entries: [] });
      render(<ChannelPicker />);
      expect(screen.queryByText(/^Correlating:/)).not.toBeInTheDocument();
    });
  });
});

describe("the Add log source link", () => {
  const link = () => screen.getByRole("button", { name: "Add log source\u2026" });
  const openMenu = () => fireEvent.click(link());

  beforeEach(() => {
    resetPane({ channels: [channel("System", "enabled")] });
    addLogSourceMock.mockReset().mockResolvedValue({ status: "cancelled" });
  });
  afterEach(cleanup);

  it("offers a file and a folder, each labelled with the spec's ellipsis", () => {
    render(<ChannelPicker />);
    openMenu();
    expect(screen.getByRole("menuitem", { name: "Add log file\u2026" })).toBeInTheDocument();
    expect(screen.getByRole("menuitem", { name: "Add log folder\u2026" })).toBeInTheDocument();
  });

  it.each([
    ["Add log file\u2026", "file"],
    ["Add log folder\u2026", "folder"],
  ])("runs the helper for %s", async (label, kind) => {
    render(<ChannelPicker />);
    openMenu();
    await act(async () => {
      fireEvent.click(screen.getByRole("menuitem", { name: label }));
    });
    expect(addLogSourceMock).toHaveBeenCalledTimes(1);
    expect(addLogSourceMock).toHaveBeenCalledWith(kind);
  });

  it("is disabled while an add runs, so a second one cannot start, and gives focus back after", async () => {
    const pending = deferred<{ status: "cancelled" }>();
    addLogSourceMock.mockReturnValue(pending.promise);
    render(<ChannelPicker />);
    openMenu();
    await act(async () => {
      fireEvent.click(screen.getByRole("menuitem", { name: "Add log file\u2026" }));
    });

    expect(link()).toHaveAttribute("aria-disabled", "true");
    // A click on the disabled link opens no menu, so no second add can be chosen.
    fireEvent.click(link());
    expect(screen.queryByRole("menuitem", { name: "Add log file\u2026" })).not.toBeInTheDocument();
    expect(addLogSourceMock).toHaveBeenCalledTimes(1);

    // The native dialog and the menu item are gone by the time the add finishes: focus has fallen
    // to the page, and has to be put back on the link.
    (document.activeElement as HTMLElement).blur();
    expect(document.body).toHaveFocus();

    await act(async () => {
      pending.resolve({ status: "cancelled" });
      await pending.promise;
    });
    expect(link()).not.toHaveAttribute("aria-disabled", "true");
    expect(link()).toHaveFocus();
  });

  it("leaves focus where the user moved it while the add ran", async () => {
    const pending = deferred<{ status: "cancelled" }>();
    addLogSourceMock.mockReturnValue(pending.promise);
    render(
      <>
        <ChannelPicker />
        <button type="button">elsewhere</button>
      </>,
    );
    openMenu();
    await act(async () => {
      fireEvent.click(screen.getByRole("menuitem", { name: "Add log file\u2026" }));
    });

    screen.getByRole("button", { name: "elsewhere" }).focus();
    await act(async () => {
      pending.resolve({ status: "cancelled" });
      await pending.promise;
    });

    expect(screen.getByRole("button", { name: "elsewhere" })).toHaveFocus();
    expect(link()).not.toHaveFocus();
  });

  const section = () => screen.getByRole("region", { name: "Also correlating" });
  const alertRegion = () => within(section()).getByRole("alert");
  const statusRegion = () => within(section()).getByRole("status");
  const addFile = async () => {
    openMenu();
    await act(async () => {
      fireEvent.click(screen.getByRole("menuitem", { name: "Add log file\u2026" }));
    });
  };

  describe("the report's live regions", () => {
    it("are mounted before any add, empty, and Dismiss is not there yet", () => {
      render(<ChannelPicker />);
      expect(statusRegion()).toBeEmptyDOMElement();
      expect(alertRegion()).toBeEmptyDOMElement();
      expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
    });

    it("are the same elements when the text arrives, so it is a change and not an insertion", async () => {
      addLogSourceMock.mockResolvedValue({ status: "failed", message: "Could not add b.log: boom." });
      render(<ChannelPicker />);
      const alert = alertRegion();
      const status = statusRegion();

      await addFile();

      expect(alertRegion()).toBe(alert);
      expect(statusRegion()).toBe(status);
      expect(alert).toHaveTextContent("Could not add b.log: boom.");
    });

    it("keep Dismiss outside, so it is not read out as part of the message", async () => {
      addLogSourceMock.mockResolvedValue({ status: "failed", message: "Could not add b.log: boom." });
      render(<ChannelPicker />);
      await addFile();

      const dismiss = screen.getByRole("button", { name: "Dismiss" });
      expect(alertRegion()).not.toContainElement(dismiss);
      expect(statusRegion()).not.toContainElement(dismiss);
      expect(alertRegion()).not.toHaveTextContent("Dismiss");
    });

    it("are emptied by Dismiss, not removed, and focus returns to the link", async () => {
      addLogSourceMock.mockResolvedValue({ status: "failed", message: "Could not add b.log: boom." });
      render(<ChannelPicker />);
      await addFile();
      const alert = alertRegion();

      fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));

      expect(alertRegion()).toBe(alert);
      expect(alert).toBeEmptyDOMElement();
      expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
      expect(link()).toHaveFocus();
    });
  });

  it.each([
    ["failed", "Could not add b.log: The file is locked."],
    ["rejected", "Not added: x.reg is a registry file, which opens in the Log workspace."],
    ["notAdded", "Not added: b.log holds no entries."],
  ] as const)("shows a %s add as an alert that ends with how many text logs are correlated", async (status, message) => {
    addLogSourceMock.mockResolvedValue({ status, message });
    render(<ChannelPicker />);

    await addFile();

    expect(alertRegion()).toHaveTextContent(`${message} No text log is now correlated.`);
    expect(statusRegion()).toBeEmptyDOMElement();
    expect(link()).toHaveFocus();
  });

  it("shows what a successful add could not cover as a status, not an alert", async () => {
    addLogSourceMock.mockResolvedValue({ status: "added", notice: "Not read: b.log." });
    useLogStore.setState({ sourceOpenMode: "merged", entries: [textLog("C:\\logs\\a.log", 1)] });
    render(<ChannelPicker />);

    await addFile();

    expect(statusRegion()).toHaveTextContent("Not read: b.log. 1 text log is now correlated.");
    expect(alertRegion()).toBeEmptyDOMElement();
  });

  it.each([
    [{ status: "cancelled" }],
    [{ status: "added", notice: null }],
  ])("says nothing for %o", async (outcome) => {
    addLogSourceMock.mockResolvedValue(outcome);
    render(<ChannelPicker />);

    await addFile();

    expect(alertRegion()).toBeEmptyDOMElement();
    expect(statusRegion()).toBeEmptyDOMElement();
    expect(screen.queryByRole("button", { name: "Dismiss" })).not.toBeInTheDocument();
  });

  it("keeps the sentence true when the correlated set changes under a report that is still showing", async () => {
    addLogSourceMock.mockResolvedValue({ status: "failed", message: "Could not add b.log: boom." });
    render(<ChannelPicker />);
    await addFile();
    expect(alertRegion()).toHaveTextContent("Could not add b.log: boom. No text log is now correlated.");

    act(() =>
      useLogStore.setState({ sourceOpenMode: "merged", entries: [textLog("C:\\logs\\a.log", 1)] }),
    );
    expect(alertRegion()).toHaveTextContent("Could not add b.log: boom. 1 text log is now correlated.");

    act(() =>
      useLogStore.setState({
        sourceOpenMode: "merged",
        entries: [textLog("C:\\logs\\a.log", 1), textLog("C:\\logs\\c.log", 2)],
      }),
    );
    expect(alertRegion()).toHaveTextContent("Could not add b.log: boom. 2 text logs are now correlated.");
    // The historical part is not rewritten.
    expect(alertRegion().textContent).toMatch(/^Could not add b\.log: boom\. /);
  });

  it("clears an earlier report when the next add starts", async () => {
    addLogSourceMock.mockResolvedValueOnce({ status: "failed", message: "Could not add b.log: boom." });
    render(<ChannelPicker />);
    await addFile();
    expect(alertRegion()).not.toBeEmptyDOMElement();

    const pending = deferred<{ status: "cancelled" }>();
    addLogSourceMock.mockReturnValue(pending.promise);
    openMenu();
    await act(async () => {
      fireEvent.click(screen.getByRole("menuitem", { name: "Add log folder\u2026" }));
    });
    expect(alertRegion()).toBeEmptyDOMElement();
    await act(async () => {
      pending.resolve({ status: "cancelled" });
      await pending.promise;
    });
  });

  it("takes its text sizes from the pane, which takes them from the list font size", async () => {
    addLogSourceMock.mockResolvedValue({ status: "failed", message: "Could not add b.log: boom." });
    useUiStore.setState({ logListFontSize: 20 });
    render(<ChannelPicker />);
    await addFile();

    const fontSize = getLogListMetrics(20).fontSize;
    expect(link().style.fontSize).toBe(`${Math.max(10, fontSize - 2)}px`);
    expect(alertRegion().style.fontSize).toBe(`${Math.max(10, fontSize - 3)}px`);
    expect(screen.getByRole("button", { name: "Dismiss" }).style.fontSize).toBe(
      `${Math.max(10, fontSize - 3)}px`,
    );
  });
});

describe("a row that is not complete says why in text", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("puts the state and the reasons in the description, not only in the tooltip", () => {
    resetPane({
      channels: [channel("System", "enabled")],
      loadedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
      coverageDetails: [
        gapRecord("System", "record", "record 7 could not be decoded"),
        gapRecord("System", "chunk", "chunk 2 was zero-filled"),
      ],
    });
    render(<ChannelPicker />);
    const description = rowDescription("System");
    expect(description).toContain("Partial: some events may be missing");
    expect(description).toContain("Why: record 7 could not be decoded; chunk 2 was zero-filled");
    // The tooltip says the same, but it is not the only carrier.
    expect(paneRow("System").querySelector("label")!.getAttribute("title")).toContain(
      "record 7 could not be decoded",
    );
  });

  it("says a live tail is running in the description", () => {
    resetPane({
      channels: [channel("System", "enabled")],
      loadedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
      tailMode: "subscription",
      tailChannels: new Set(["System"]),
    });
    render(<ChannelPicker />);
    expect(rowDescription("System")).toContain("Live tail running");
  });
});

describe("the description is read once, and reads cleanly", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("hides the description node from browse mode while the checkbox still resolves it", () => {
    resetPane({
      channels: [channel("System", "enabled")],
      loadedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
    });
    render(<ChannelPicker />);
    const box = within(paneRow("System")).getByRole("checkbox");
    const node = document.getElementById(box.getAttribute("aria-describedby")!)!;
    expect(node).toHaveAttribute("aria-hidden", "true");
    expect(node.textContent).toMatch(/^1 event, 0 errors, 0 warnings\./);
    // aria-describedby still names it, so the checkbox is described by it.
    expect(box).toHaveAccessibleDescription(node.textContent!);
  });

  it("does not speak a sha256 digest, but keeps it in the tooltip", () => {
    const digest = "a".repeat(64);
    const reason = `member could not be parsed (sha256:${digest})`;
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [
        { name: "System", eventCount: 1, sourceType: { file: { path: "C:\\logs\\System.evtx" } } },
      ],
      selectedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
      coverageDetails: [gapRecord("C:\\cases\\bundle.zip::logs/Corrupt.evtx", "file", reason)],
    });
    render(<ChannelPicker />);
    // A service-tree row sits in a group that starts closed: nothing in it holds events.
    fireEvent.click(screen.getByRole("button", { name: "Expand Applications and Services Logs" }));
    const description = document
      .getElementById(
        within(paneRow("Corrupt")).getByRole("checkbox").getAttribute("aria-describedby")!,
      )!
      .textContent!;
    expect(description).toContain("Why: member could not be parsed");
    expect(description).not.toContain("sha256");
    expect(description).not.toContain(digest);
    expect(paneRow("Corrupt").querySelector("label")!.getAttribute("title")).toContain(digest);
  });
});

describe("gaps that reach no row", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [
        { name: "System", eventCount: 1, sourceType: { file: { path: "C:\\logs\\System.evtx" } } },
      ],
      selectedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
    });
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("claims k of k read when every gap belongs to a row", () => {
    render(<ChannelPicker />);
    expect(screen.getByText("1 of 1 read \u00B7 all-time activity")).toBeInTheDocument();
    expect(screen.queryByText(/could not be attributed/)).not.toBeInTheDocument();
  });

  it("prints no read ratio while a gap is unattributed, and says how many are", () => {
    useEvtxStore.setState({
      coverageDetails: [
        gapRecord("<coverage>", "limit", "4096 further coverage gaps were coalesced"),
        gapRecord("C:\\logs\\Sys*.evtx", "missing", WILDCARD_MISSING_REASON),
      ],
    });
    render(<ChannelPicker />);
    expect(screen.getByText("1 channel \u00B7 2 not attributed to a channel")).toBeInTheDocument();
    // No "k of k read", and the window label gives way to the disclosure.
    expect(screen.queryByText(/\d+ of \d+ read/)).not.toBeInTheDocument();
    expect(screen.queryByText("1 of 1 read \u00B7 all-time activity")).not.toBeInTheDocument();
    const disclosure = screen.getByText(/2 gaps could not be attributed to a channel/);
    expect(disclosure).toHaveTextContent("<coverage>: 4096 further coverage gaps were coalesced");
    expect(disclosure).toHaveTextContent(`C:\\logs\\Sys*.evtx: ${WILDCARD_MISSING_REASON}`);
    // The wildcard is not a row.
    expect(document.querySelectorAll("[data-channel-row]")).toHaveLength(1);
  });

  it("counts a repeated gap once, and lists at most five reasons before 'and N more'", () => {
    useEvtxStore.setState({
      coverageGaps: Array.from({ length: 7 }, (_, i) => `Elsewhere${i}: not read (gone)`),
      tailCoverageGaps: ["Elsewhere0: not read (gone)"],
    });
    render(<ChannelPicker />);
    expect(screen.getByText("1 channel \u00B7 7 not attributed to a channel")).toBeInTheDocument();
    const disclosure = screen.getByText(/7 gaps could not be attributed to a channel/);
    expect(disclosure.textContent).toContain("Elsewhere4: not read (gone)");
    expect(disclosure.textContent).not.toContain("Elsewhere5: not read (gone)");
    expect(disclosure.textContent).toMatch(/ and 2 more\.$/);
  });

  it("speaks no digest in the disclosure, and keeps it in the header's tooltip", () => {
    const digest = "b".repeat(64);
    useEvtxStore.setState({
      coverageDetails: [
        gapRecord("C:\\cases\\bundle.zip::logs/Odd.cab", "file", `could not be parsed (sha256:${digest})`),
      ],
    });
    render(<ChannelPicker />);
    const disclosure = screen.getByText(/1 gap could not be attributed to a channel/);
    expect(disclosure.textContent).not.toContain(digest);
    const header = screen.getByText("1 channel \u00B7 1 not attributed to a channel");
    expect(header.getAttribute("title")).toContain(digest);
  });

  it("keeps the activity label for an archive whose only gaps are about inventory members", () => {
    // A registry hive and a trace file can never be channels, so their gaps are not unattributed.
    const reg = "C:\\cases\\bundle.zip::logs/Profile.reg";
    const etl = "C:\\cases\\bundle.zip::logs/Boot.etl";
    useEvtxStore.setState({
      archiveMembers: [
        { path: reg, kind: "registry", outcome: "unsupported" },
        { path: etl, kind: "binary", outcome: "unsupported" },
      ],
      coverageDetails: [
        gapRecord(reg, "unsupported", "registry hives are listed but not parsed"),
        gapRecord(etl, "unsupported", "binary members are listed but not parsed"),
      ],
    });
    render(<ChannelPicker />);
    expect(screen.getByText("1 of 1 read \u00B7 all-time activity")).toBeInTheDocument();
    expect(screen.queryByText(/not attributed/)).not.toBeInTheDocument();
  });

  it("lists a member the archive skipped for a limit as a row, not as an unattributed gap", () => {
    useEvtxStore.setState({
      coverageDetails: [
        gapRecord(
          "C:\\cases\\bundle.zip::logs/Security.evtx",
          "limit",
          "archive record budget of 1000000 records was exhausted",
        ),
      ],
    });
    render(<ChannelPicker />);
    expect(paneRow("Security")).toHaveAttribute("data-channel-state", "notRead");
    expect(screen.getByText("1 of 2 read \u00B7 all-time activity")).toBeInTheDocument();
  });
});

describe("a pane with no source mode", () => {
  afterEach(cleanup);

  it("does not call enumerated channels read when nothing was queried", () => {
    // A remote load whose queries all fail clears the source mode but keeps the channel list.
    resetPane({
      sourceMode: null,
      channels: [channel("System", "enabled"), channel("Application", "enabled")],
    });
    render(<ChannelPicker />);
    expect(screen.getByText("0 of 2 read \u00B7 24 h activity")).toBeInTheDocument();
    expect(paneRow("System")).toHaveAttribute("data-channel-state", "notLoaded");
    expect(paneRow("System")).toHaveTextContent(DASH);
    expect(paneRow("System")).not.toHaveTextContent(/\b0\b/);
  });
});

describe("live tail gaps", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  const tailing = (tailCoverageGaps: string[]) =>
    resetPane({
      channels: [channel("System", "enabled")],
      loadedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
      tailMode: "subscription",
      tailChannels: new Set(["System"]),
      tailCoverageGaps,
    });

  it.each([
    "System: live tail batch 12 was not received",
    "System: subscription callback reported an error",
    "System: 3 events could not be read and are missing from this view",
  ])("marks the row partial for %s", (gapText) => {
    tailing([gapText]);
    render(<ChannelPicker />);
    expect(paneRow("System")).toHaveAttribute("data-channel-state", "partial");
    expect(paneRow("System")).toHaveTextContent("partial");
    expect(rowDescription("System")).toContain(gapText.replace("System: ", ""));
  });

  it("leaves the row read for a tail that was unavailable, not one that lost events", () => {
    tailing(["System: live tail unavailable (not supported)"]);
    render(<ChannelPicker />);
    expect(paneRow("System")).toHaveAttribute("data-channel-state", "read");
  });
});

describe("text logs from archives", () => {
  const MEMBER = "C:\\cases\\bundle.zip::logs/IntuneManagementExtension.log";

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [
        {
          name: "System",
          eventCount: 1,
          sourceType: { file: { path: "C:\\cases\\bundle.zip::System.evtx" } },
        },
        // The archive reader lists a text member under its own label, which is also its path.
        { name: MEMBER, eventCount: 2, sourceType: { file: { path: MEMBER } } },
      ],
      selectedChannels: new Set(["System", MEMBER]),
      records: [
        evtxRecord("System", NOW - HOUR),
        { ...evtxRecord(MEMBER, NOW - 2 * HOUR, "Error"), originKind: "log" as const },
        { ...evtxRecord(MEMBER, NOW - 3 * HOUR), originKind: "log" as const },
      ],
    });
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  // The name holds backslashes, which a CSS attribute selector would read as escapes.
  const textLogRow = () =>
    [...document.querySelectorAll<HTMLElement>("[data-text-log-row]")].find(
      (row) => row.getAttribute("data-text-log-row") === MEMBER,
    ) ?? null;

  it("lists the member under 'Text logs in sources', not among the channels", () => {
    render(<ChannelPicker />);
    expect(screen.getByRole("button", { name: "Collapse Text logs in sources" })).toBeInTheDocument();
    expect(textLogRow()).not.toBeNull();
    expect(document.querySelectorAll("[data-channel-row]")).toHaveLength(1);
    expect(textLogRow()).toHaveTextContent("IntuneManagementExtension.log");
  });

  it("shows an entry count and none of an event channel's marks", () => {
    render(<ChannelPicker />);
    const row = textLogRow()!;
    expect(row).toHaveTextContent("2 entries");
    // No swatch, no sparkline, no error or warning counts, no read state.
    expect(row.querySelector("svg")).toBeNull();
    expect(row.querySelector('span[aria-hidden="true"][style*="border-radius"]')).toBeNull();
    expect(row).not.toHaveTextContent(/\d+ (err|warn)/);
    expect(row).not.toHaveAttribute("data-channel-state");
  });

  it("leaves it out of the read count and the total", () => {
    render(<ChannelPicker />);
    expect(screen.getByText("1 of 1 read \u00B7 all-time activity")).toBeInTheDocument();
  });

  it("keeps its checkbox, which gates whether the records are shown", () => {
    render(<ChannelPicker />);
    const box = within(textLogRow()!).getByRole("checkbox", { name: `Select ${MEMBER}` });
    expect(box).toBeChecked();
    fireEvent.click(box);
    expect(useEvtxStore.getState().selectedChannels.has(MEMBER)).toBe(false);
    expect(useEvtxStore.getState().selectedChannels.has("System")).toBe(true);
    expect(document.getElementById(box.getAttribute("aria-describedby")!)).toHaveTextContent(
      "2 entries. A text log from an archive, not an event channel.",
    );
  });

  it("is found by the channel filter", () => {
    render(<ChannelPicker />);
    fireEvent.change(screen.getByPlaceholderText("Filter channels..."), {
      target: { value: "intune" },
    });
    expect(textLogRow()).not.toBeNull();
    expect(document.querySelector('[data-channel-row="System"]')).toBeNull();
    expect(screen.queryByText("No channels match filter")).not.toBeInTheDocument();
  });

  it("does not change the color of an event channel", () => {
    // The member label begins "C:\\", so it sorts ahead of every Microsoft-* service channel: were
    // it ordered with the channels it would push this one from index 1 to 2.
    const AAD = "Microsoft-Windows-AAD/Operational";
    const aad = {
      name: AAD,
      eventCount: 1,
      sourceType: { file: { path: "C:\\cases\\bundle.zip::logs/AAD.evtx" } },
    };
    const swatch = (name: string) =>
      paneRow(name).querySelector<HTMLElement>('span[aria-hidden="true"][style*="border-radius"]')!;
    const channels = (extra: EvtxChannelInfo[]) => [
      {
        name: "System",
        eventCount: 1,
        sourceType: { file: { path: "C:\\cases\\bundle.zip::System.evtx" } },
      },
      aad,
      ...extra,
    ];
    const records = [evtxRecord("System", NOW - HOUR), evtxRecord(AAD, NOW - HOUR)];

    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: channels([]),
      selectedChannels: new Set(["System", AAD]),
      records,
    });
    render(<ChannelPicker />);
    const without = swatch(AAD).style.backgroundColor;
    cleanup();

    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: channels([
        { name: MEMBER, eventCount: 2, sourceType: { file: { path: MEMBER } } },
      ]),
      selectedChannels: new Set(["System", AAD, MEMBER]),
      records: [
        ...records,
        { ...evtxRecord(MEMBER, NOW - 2 * HOUR), originKind: "log" as const },
      ],
    });
    render(<ChannelPicker />);
    expect(swatch(AAD).style.backgroundColor).toBe(without);
  });
});

describe("text-log members carry their coverage", () => {
  const MEMBER = "C:\\cases\\bundle.zip::logs/IntuneManagementExtension.log";
  const member = (name: string) => ({
    name,
    eventCount: 0,
    sourceType: { file: { path: name } },
  });
  const logRecord = (at: number) => ({
    ...evtxRecord(MEMBER, at),
    originKind: "log" as const,
  });
  const textLogRow = () =>
    [...document.querySelectorAll<HTMLElement>("[data-text-log-row]")].find(
      (row) => row.getAttribute("data-text-log-row") === MEMBER,
    )!;
  const describedBy = (row: HTMLElement) =>
    document.getElementById(
      row.querySelector('input[type="checkbox"]')!.getAttribute("aria-describedby")!,
    )!;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("marks a member cut off at the archive's line limit as partial, with the reason in text", () => {
    const reason = "text member parsing stopped after 25000 lines; later records were not parsed";
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [member(MEMBER)],
      selectedChannels: new Set([MEMBER]),
      records: [logRecord(NOW - HOUR), logRecord(NOW - 2 * HOUR)],
      coverageDetails: [gapRecord(MEMBER, "limit", reason)],
    });
    render(<ChannelPicker />);
    const row = textLogRow();
    expect(row).toHaveAttribute("data-text-log-state", "partial");
    expect(row).toHaveTextContent("partial");
    expect(row).toHaveTextContent("2 entries");
    const description = describedBy(row).textContent!;
    expect(description).toContain("Partial: some entries may be missing");
    expect(description).toContain(`Why: ${reason}`);
    expect(row.querySelector("label")!.getAttribute("title")).toContain(reason);
  });

  it("shows a member nothing was kept from as not read, with a dash and no zero", () => {
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [member(MEMBER)],
      selectedChannels: new Set([MEMBER]),
      archiveMembers: [{ path: MEMBER, kind: "text", outcome: "malformed" }],
      records: [],
      coverageDetails: [gapRecord(MEMBER, "record", "12 text records could not be parsed")],
    });
    render(<ChannelPicker />);
    const row = textLogRow();
    expect(row).toHaveAttribute("data-text-log-state", "notRead");
    expect(row).toHaveTextContent("not read");
    expect(row).toHaveTextContent(DASH);
    expect(row).not.toHaveTextContent(/\b0\b/);
    expect(describedBy(row).textContent).toMatch(/^No count\. Not read\. Why: 12 text records/);
  });

  it("lists an empty member as a text log, not as an event channel", () => {
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [member(MEMBER)],
      selectedChannels: new Set([MEMBER]),
      archiveMembers: [{ path: MEMBER, kind: "text", outcome: "parsed" }],
      records: [],
      coverageDetails: [gapRecord(MEMBER, "empty", "text member is empty")],
    });
    render(<ChannelPicker />);
    expect(document.querySelectorAll("[data-channel-row]")).toHaveLength(0);
    expect(textLogRow()).toHaveAttribute("data-text-log-state", "read");
    expect(textLogRow()).toHaveTextContent("0 entries");
    expect(screen.getByText("0 of 0 read \u00B7 all-time activity")).toBeInTheDocument();
  });
});

describe("the pane's rows follow orderChannelNames", () => {
  const NAMES = [
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "System",
    "Contoso/Operational",
    "Microsoft-Windows-AAD/Operational",
    "Application",
    "Contoso",
    "Security",
  ];

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    resetPane({
      channels: NAMES.map((name) => channel(name, "enabled")),
      loadedChannels: new Set(NAMES),
      records: NAMES.map((name) => evtxRecord(name, NOW - HOUR)),
    });
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("lists the channels in the order Phase 14's charts will color them in", () => {
    render(<ChannelPicker />);
    const shown = [...document.querySelectorAll("[data-channel-row]")].map((row) =>
      row.getAttribute("data-channel-row"),
    );
    expect(shown).toEqual(orderChannelNames(NAMES));
  });

  it("draws each row's swatch in channelColor(i) for its place in that order", () => {
    render(<ChannelPicker />);
    const light = getAllThemes().find((theme) => theme.id === "light")!;
    const visual = buildEvtxVisualTokens(light);
    orderChannelNames(NAMES).forEach((name, index) => {
      const swatch = paneRow(name).querySelector<HTMLElement>(
        'span[aria-hidden="true"][style*="border-radius"]',
      )!;
      expect(toHex(swatch.style.backgroundColor)).toBe(visual.channelColor(index));
    });
  });
});

describe("the dim cue and the eyebrow keep the designed color where it reads", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    const path = "C:\\logs\\Security.evtx";
    resetPane({
      sourceMode: "files",
      timeWindow: "all",
      channels: [
        { name: "System", eventCount: 1, sourceType: { file: { path: "C:\\logs\\System.evtx" } } },
      ],
      selectedChannels: new Set<string>(),
      records: [evtxRecord("System", NOW - HOUR)],
      coverageDetails: [gapRecord(path, "accessDenied", "source metadata access was denied")],
    });
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  const colors = () => ({
    eyebrow: screen.getByText("Channels").style.color,
    headerCount: screen.getByText(/ read \u00B7 /).style.color,
    unavailableName: paneRow("Security").querySelector("label")!.style.color,
    name: paneRow("System").querySelector("label")!.style.color,
  });

  it("uses Foreground3 for the eyebrow, the header count and an unavailable name where it passes 4.5:1", () => {
    // Light: Foreground3 on Background2 is 5.93:1.
    useUiStore.setState({ themeId: "light" });
    render(<ChannelPicker />);
    const found = colors();
    expect(found.eyebrow).toBe(tokens.colorNeutralForeground3);
    expect(found.headerCount).toBe(tokens.colorNeutralForeground3);
    expect(found.unavailableName).toBe(tokens.colorNeutralForeground3);
    // The dim cue: an unavailable name is not drawn like a normal one.
    expect(found.name).toBe(tokens.colorNeutralForeground1);
  });

  it.each(["solarized-dark", "dracula"] as const)(
    "falls back to Foreground2 in %s, where Foreground3 misses 4.5:1",
    (themeId) => {
      useUiStore.setState({ themeId });
      render(<ChannelPicker />);
      const found = colors();
      expect(found.eyebrow).toBe(tokens.colorNeutralForeground2);
      expect(found.headerCount).toBe(tokens.colorNeutralForeground2);
      expect(found.unavailableName).toBe(tokens.colorNeutralForeground2);
    },
  );
});

describe("the live tail footer", () => {
  let startLiveTail: ReturnType<typeof vi.fn>;
  let stopLiveTail: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    startLiveTail = vi.fn().mockResolvedValue([]);
    stopLiveTail = vi.fn().mockResolvedValue(undefined);
    resetPane({
      channels: [channel("Application", "enabled"), channel("System", "enabled")],
      loadedChannels: new Set(["Application", "System"]),
      startLiveTail,
      stopLiveTail,
    });
  });
  afterEach(cleanup);

  it("reads 'Live tail \u00B7 {n} channels' with Pause while the tail runs, and Pause stops it", () => {
    useEvtxStore.setState({
      tailMode: "subscription",
      tailChannels: new Set(["Application", "System"]),
    });
    render(<ChannelPicker />);
    expect(screen.getByText("Live tail \u00B7 2 channels")).toBeInTheDocument();
    expect(screen.getByLabelText("Live tail mode: subscription")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Pause live tail" }));
    expect(stopLiveTail).toHaveBeenCalledTimes(1);
    expect(startLiveTail).not.toHaveBeenCalled();
  });

  it("offers Resume while the tail is off, and Resume starts it", () => {
    render(<ChannelPicker />);
    expect(screen.getByText("Live tail off")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Resume live tail" }));
    expect(startLiveTail).toHaveBeenCalledTimes(1);
    expect(stopLiveTail).not.toHaveBeenCalled();
  });

  it("does not call an unsupported tail live, and offers Stop rather than Pause", () => {
    useEvtxStore.setState({ tailMode: "unsupported", tailChannels: new Set<string>() });
    render(<ChannelPicker />);
    expect(screen.getByText("Live tail \u00B7 not tailing")).toBeInTheDocument();
    expect(screen.getByLabelText("Live tail mode: unsupported")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Pause live tail" })).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Stop live tail" }));
    expect(stopLiveTail).toHaveBeenCalledTimes(1);
    expect(startLiveTail).not.toHaveBeenCalled();
  });

  it("is the only live tail control", () => {
    render(<ChannelPicker />);
    expect(screen.queryByRole("button", { name: /start live tail|stop live tail/i })).toBeNull();
    expect(screen.getAllByRole("button", { name: /live tail/i })).toHaveLength(1);
  });

  it("is disabled while a load runs", () => {
    useEvtxStore.setState({ isLoading: true });
    render(<ChannelPicker />);
    expect(screen.getByRole("button", { name: "Resume live tail" })).toHaveAttribute(
      "disabled",
    );
  });

  it("is hidden for files and when nothing is loaded to tail", () => {
    useEvtxStore.setState({ sourceMode: "files" });
    render(<ChannelPicker />);
    expect(screen.queryByText(/Live tail/)).not.toBeInTheDocument();

    cleanup();
    useEvtxStore.setState({ sourceMode: "live", loadedChannels: new Set<string>() });
    render(<ChannelPicker />);
    expect(screen.queryByText(/Live tail/)).not.toBeInTheDocument();
  });
});

describe("numbers while a live tail runs", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    resetPane({
      channels: [channel("System", "enabled")],
      loadedChannels: new Set(["System"]),
      records: [evtxRecord("System", NOW - HOUR)],
    });
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  const totalOf = () => within(paneRow("System")).getByText(/^\d+$/).textContent;

  it("republishes at most every 75 ms while tailing, however many batches arrive", () => {
    useEvtxStore.setState({ tailMode: "subscription", tailChannels: new Set(["System"]) });
    render(<ChannelPicker />);
    expect(totalOf()).toBe("1");

    const batch = (count: number) =>
      Array.from({ length: count }, () => evtxRecord("System", NOW - HOUR));
    act(() => useEvtxStore.setState({ records: batch(2) }));
    act(() => vi.advanceTimersByTime(40));
    act(() => useEvtxStore.setState({ records: batch(3) }));
    expect(totalOf()).toBe("1");

    act(() => vi.advanceTimersByTime(35));
    // The newest value won, and the intermediate batch never rendered.
    expect(totalOf()).toBe("3");

    act(() => useEvtxStore.setState({ records: batch(4) }));
    act(() => vi.advanceTimersByTime(74));
    expect(totalOf()).toBe("3");
    act(() => vi.advanceTimersByTime(1));
    expect(totalOf()).toBe("4");
  });

  it("starts a tail from the current records, not from an older publication", () => {
    render(<ChannelPicker />);
    act(() =>
      useEvtxStore.setState({
        records: [evtxRecord("System", NOW - HOUR), evtxRecord("System", NOW - 2 * HOUR)],
      }),
    );
    expect(totalOf()).toBe("2");

    act(() =>
      useEvtxStore.setState({ tailMode: "subscription", tailChannels: new Set(["System"]) }),
    );
    expect(totalOf()).toBe("2");
  });

  it("follows the records immediately when no tail is running", () => {
    render(<ChannelPicker />);
    act(() =>
      useEvtxStore.setState({
        records: [evtxRecord("System", NOW - HOUR), evtxRecord("System", NOW - 2 * HOUR)],
      }),
    );
    expect(totalOf()).toBe("2");
  });
});

// ── Contrast (Adam's criterion): every pair the pane renders, in all seven themes ──────────────

function toHex(color: string): string {
  const match = /^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/.exec(color.trim());
  if (!match) return color.trim();
  return `#${[match[1], match[2], match[3]]
    .map((channelValue) => Number(channelValue).toString(16).padStart(2, "0"))
    .join("")}`;
}

function inlineStyle(
  element: Element,
  property: "color" | "backgroundColor" | "fill",
  stop: Element,
): string | null {
  for (let node: Element | null = element; node; node = node.parentElement) {
    const value = (node as HTMLElement).style?.[property];
    if (value) return value;
    if (node === stop) break;
  }
  return null;
}

interface MeasuredPair {
  what: string;
  ratio: number;
  minimum: number;
}

/**
 * Reads the colors the pane really renders (inline styles), resolves Fluent token references in
 * `theme`, and measures each text and graphic pair against the surface it sits on.
 */
function measurePane(container: HTMLElement, theme: CMTraceTheme): MeasuredPair[] {
  const resolve = (value: string) => toHex(resolveToken(value, theme));
  const pairs: MeasuredPair[] = [];
  const surface = (element: Element) =>
    resolve(inlineStyle(element, "backgroundColor", container) ?? tokens.colorNeutralBackground2);

  for (const element of container.querySelectorAll("*")) {
    const own = [...element.childNodes]
      .filter((node) => node.nodeType === Node.TEXT_NODE)
      .map((node) => node.textContent ?? "")
      .join("")
      .trim();
    if (own === "" || own === "no count") continue;
    const color = inlineStyle(element, "color", container);
    // Fluent controls take their color from a class; only the pane's own inline colors are read.
    if (color === null) continue;
    pairs.push({
      what: `text "${own}"`,
      ratio: contrastRatio(resolve(color), surface(element)),
      minimum: 4.5,
    });
  }

  for (const swatch of container.querySelectorAll<HTMLElement>(
    'span[aria-hidden="true"][style*="border-radius"]',
  )) {
    const background = swatch.style.backgroundColor;
    const onto = surface(swatch.parentElement!);
    if (background === "" || background === "transparent") {
      // A hollow mark (the idle live-tail ring) is drawn by its border alone.
      const ring = /solid (.+)$/.exec(swatch.style.border)?.[1];
      if (ring && ring !== "transparent") {
        pairs.push({ what: `ring ${ring}`, ratio: contrastRatio(resolve(ring), onto), minimum: 3 });
      }
      continue;
    }
    const outline = /solid (.+)$/.exec(swatch.style.border)?.[1];
    if (outline && outline !== "transparent" && toHex(outline) !== toHex(background)) {
      // A mark on the selection background cannot promise 3:1 for its fill (spec 6.3), so it
      // draws a 1 px outline, and the outline carries the contrast.
      pairs.push({
        what: `swatch outline ${outline}`,
        ratio: contrastRatio(resolve(outline), onto),
        minimum: 3,
      });
    } else {
      pairs.push({
        what: `mark ${toHex(background)}`,
        ratio: contrastRatio(resolve(background), onto),
        minimum: 3,
      });
    }
  }

  for (const bar of container.querySelectorAll<SVGElement>("rect[data-bin]")) {
    pairs.push({
      what: `sparkline bar ${bar.style.fill}`,
      ratio: contrastRatio(resolve(bar.style.fill), surface(bar.parentElement!)),
      minimum: 3,
    });
  }
  return pairs;
}

describe("contrast of everything the pane renders", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
  });
  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  function populate() {
    const refusal =
      "the Event Log service refused the channel query (Windows error 5: Access is denied)";
    resetPane({
      channels: [
        channel("Application", "enabled"),
        channel("Security", "enabled"),
        channel("System", "enabled"),
        channel("Setup", "enabled"),
        channel("Microsoft-Windows-AAD/Operational", "enabled"),
        channel("AirSpaceChannel", "disabled"),
      ],
      loadedChannels: new Set(["Application", "System", "Microsoft-Windows-AAD/Operational"]),
      selectedChannels: new Set(["System", "Microsoft-Windows-AAD/Operational"]),
      records: [
        evtxRecord("Application", NOW - HOUR, "Error"),
        evtxRecord("Application", NOW - 2 * HOUR, "Warning"),
        evtxRecord("System", NOW - HOUR, "Critical"),
        evtxRecord("System", NOW - 4 * HOUR, "Warning"),
        evtxRecord("Microsoft-Windows-AAD/Operational", NOW - 3 * HOUR, "Error"),
      ],
      coverageDetails: [
        gapRecord("Security", "record", refusal),
        gapRecord("Application", "record", "record 7 could not be decoded"),
      ],
      tailMode: "subscription",
      tailChannels: new Set(["System"]),
    });
    useLogStore.setState({
      sourceOpenMode: "merged",
      entries: [textLog("C:\\logs\\ccmexec.log", 1)],
    });
  }

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "meets 4.5:1 for text and 3:1 for marks in %s",
    (_id, theme) => {
      populate();
      useUiStore.setState({ themeId: theme.id });
      const { container } = render(<ChannelPicker />);
      // The service tree is open by default because a loaded channel in it holds events, so its
      // nested row is measured too.
      expect(paneRow("Microsoft-Windows-AAD/Operational")).toBeInTheDocument();

      const pairs = measurePane(container, theme);
      // The scenario must actually exercise selected, unselected, gap and live rows.
      expect(pairs.length).toBeGreaterThan(40);
      expect(pairs.some((pair) => pair.what.startsWith('text "needs elevation"'))).toBe(true);
      expect(pairs.some((pair) => pair.what.startsWith("sparkline bar"))).toBe(true);
      expect(pairs.some((pair) => pair.what.startsWith("swatch outline"))).toBe(true);
      // The Also correlating note (merged mode here) is measured like every other inline text.
      expect(pairs.some((pair) => pair.what === 'text "Correlating: all open logs"')).toBe(true);

      const failures = pairs.filter((pair) => pair.ratio < pair.minimum);
      expect(
        failures.map((pair) => `${pair.what}: ${pair.ratio.toFixed(2)}:1 (needs ${pair.minimum})`),
      ).toEqual([]);
    },
  );

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "meets the same floors for the idle footer ring and an empty filter result in %s",
    (_id, theme) => {
      resetPane({
        channels: [channel("System", "enabled")],
        loadedChannels: new Set(["System"]),
        records: [evtxRecord("System", NOW - HOUR)],
      });
      useUiStore.setState({ themeId: theme.id });
      const { container } = render(<ChannelPicker />);
      fireEvent.change(screen.getByPlaceholderText("Filter channels..."), {
        target: { value: "no such channel" },
      });
      expect(screen.getByText("No channels match filter")).toBeInTheDocument();
      expect(screen.getByText("Live tail off")).toBeInTheDocument();

      const pairs = measurePane(container, theme);
      expect(pairs.some((pair) => pair.what.startsWith("ring "))).toBe(true);
      expect(pairs.some((pair) => pair.what === 'text "No channels match filter"')).toBe(true);
      const failures = pairs.filter((pair) => pair.ratio < pair.minimum);
      expect(
        failures.map((pair) => `${pair.what}: ${pair.ratio.toFixed(2)}:1 (needs ${pair.minimum})`),
      ).toEqual([]);
    },
  );

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "meets the same floors for text-log rows, complete, partial and not read, selected and not, in %s",
    (_id, theme) => {
      const member = (name: string, at: number) => ({
        ...evtxRecord(name, at),
        originKind: "log" as const,
      });
      const listed = (name: string) => ({
        name,
        eventCount: 1,
        sourceType: { file: { path: name } },
      });
      resetPane({
        sourceMode: "files",
        timeWindow: "all",
        channels: [
          listed("bundle.zip::a.log"),
          listed("bundle.zip::b.log"),
          listed("bundle.zip::c.log"),
        ],
        // a is selected and cut off; b is complete and not selected; c kept nothing.
        selectedChannels: new Set(["bundle.zip::a.log"]),
        archiveMembers: [{ path: "bundle.zip::c.log", kind: "text", outcome: "malformed" }],
        records: [member("bundle.zip::a.log", NOW - HOUR), member("bundle.zip::b.log", NOW - HOUR)],
        coverageDetails: [
          gapRecord("bundle.zip::a.log", "limit", "text member parsing stopped after 25000 lines"),
          gapRecord("bundle.zip::c.log", "record", "9 text records could not be parsed"),
        ],
      });
      useUiStore.setState({ themeId: theme.id });
      const { container } = render(<ChannelPicker />);
      expect(container.querySelectorAll("[data-text-log-row]")).toHaveLength(3);

      const pairs = measurePane(container, theme);
      expect(pairs.some((pair) => pair.what === 'text "a.log"')).toBe(true);
      expect(pairs.some((pair) => pair.what === 'text "1 entry"')).toBe(true);
      expect(pairs.some((pair) => pair.what === 'text "partial"')).toBe(true);
      expect(pairs.some((pair) => pair.what === 'text "not read"')).toBe(true);
      const failures = pairs.filter((pair) => pair.ratio < pair.minimum);
      expect(
        failures.map((pair) => `${pair.what}: ${pair.ratio.toFixed(2)}:1 (needs ${pair.minimum})`),
      ).toEqual([]);
    },
  );

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "meets the same floors for the Add log source link and a failed add's report in %s",
    async (_id, theme) => {
      const reported = "Could not add b.log: The file is locked.";
      const message = `${reported} No text log is now correlated.`;
      resetPane({ channels: [channel("System", "enabled")] });
      useUiStore.setState({ themeId: theme.id });
      addLogSourceMock.mockReset().mockResolvedValue({ status: "failed", message: reported });
      const { container } = render(<ChannelPicker />);
      fireEvent.click(screen.getByRole("button", { name: "Add log source\u2026" }));
      await act(async () => {
        fireEvent.click(screen.getByRole("menuitem", { name: "Add log file\u2026" }));
      });
      expect(screen.getByRole("alert")).toHaveTextContent(message);

      // The report's text sets its own color, so the harness reads it.
      const pairs = measurePane(container, theme);
      expect(pairs.some((pair) => pair.what === `text "${message}"`)).toBe(true);
      const failures = pairs.filter((pair) => pair.ratio < pair.minimum);
      expect(
        failures.map((pair) => `${pair.what}: ${pair.ratio.toFixed(2)}:1 (needs ${pair.minimum})`),
      ).toEqual([]);

      // Both links take Fluent's link color from their class, the pair the footer's link is
      // measured with, so neither may override it inline.
      const surface = resolveToken(tokens.colorNeutralBackground2, theme);
      expect(
        contrastRatio(resolveToken(tokens.colorBrandForegroundLink, theme), surface),
      ).toBeGreaterThanOrEqual(4.5);
      expect(screen.getByRole("button", { name: "Add log source\u2026" }).style.color).toBe("");
      expect(screen.getByRole("button", { name: "Dismiss" }).style.color).toBe("");
    },
  );

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "keeps the Add log source menu legible in %s",
    (_id, theme) => {
      // Fluent draws a menu item in Foreground2 on the popover's Background1, and in the Hover and
      // Pressed variants of both. The items set only their font size inline, so these are the pairs
      // that reach the screen; the harness above cannot read class-based colors.
      const ratio = (foreground: string, background: string) =>
        contrastRatio(resolveToken(foreground, theme), resolveToken(background, theme));
      expect(
        ratio(tokens.colorNeutralForeground2, tokens.colorNeutralBackground1),
      ).toBeGreaterThanOrEqual(4.5);
      expect(
        ratio(tokens.colorNeutralForeground2Hover, tokens.colorNeutralBackground1Hover),
      ).toBeGreaterThanOrEqual(4.5);
      expect(
        ratio(tokens.colorNeutralForeground2Pressed, tokens.colorNeutralBackground1Pressed),
      ).toBeGreaterThanOrEqual(4.5);

      resetPane({ channels: [channel("System", "enabled")] });
      useUiStore.setState({ themeId: theme.id });
      render(<ChannelPicker />);
      fireEvent.click(screen.getByRole("button", { name: "Add log source\u2026" }));
      for (const item of screen.getAllByRole("menuitem")) {
        expect(item.style.color).toBe("");
        expect(item.style.backgroundColor).toBe("");
      }
    },
  );

  it.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
    "keeps the footer's dot and link legible in %s",
    (_id, theme) => {
      const visual = buildEvtxVisualTokens(theme);
      const surface = resolveToken(tokens.colorNeutralBackground2, theme);
      // The live dot is a mark: 3:1. The Pause / Resume link takes Fluent's link color: 4.5:1.
      expect(contrastRatio(resolveToken(visual.liveSource.foreground, theme), surface)).toBeGreaterThanOrEqual(3);
      expect(contrastRatio(resolveToken(tokens.colorBrandForegroundLink, theme), surface)).toBeGreaterThanOrEqual(4.5);
    },
  );
});

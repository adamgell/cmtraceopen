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

// The store subscribes to backend events at module scope, so it is imported after the mock that
// stands in for that bridge; a static import would be evaluated first.
const { useEvtxStore } = await import("./evtx-store");
const { ChannelPicker } = await import("./ChannelPicker");
const { buildEvtxVisualTokens, resolveToken } = await import("./evtx-visual-tokens");
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
  return within(paneRow(name)).getByRole("img") as unknown as SVGElement;
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

  it("names the sparkline with the numbers it shows and never repeats the channel name", () => {
    render(<ChannelPicker />);
    const chart = rowSparkline("System");
    expect(chart).toHaveAccessibleName("24 h activity: 4 of 24 intervals had events, busiest 1");
    expect(chart.getAttribute("aria-label")).not.toContain("System");
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
    expect(rowSparkline("System")).toHaveAccessibleName(
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
    expect(rowSparkline("Application")).toHaveAccessibleName("24 h activity: no events");
  });

  it("gives a channel nobody has loaded a dash and a flat line, never a zero", () => {
    render(<ChannelPicker />);
    const row = paneRow("Setup");
    expect(row).toHaveAttribute("data-channel-state", "notLoaded");
    expect(row).toHaveTextContent(DASH);
    expect(row).toHaveTextContent("not loaded");
    expect(row).not.toHaveTextContent(/\b0\b/);
    expect(plottedBins("Setup")).toEqual([]);
    expect(rowSparkline("Setup")).toHaveAccessibleName(
      "24 h activity: no data, the channel was not read",
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
    expect(row).not.toHaveTextContent("err");
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

  it("is absent when no text log is open", () => {
    render(<ChannelPicker />);
    expect(screen.queryByText("Also correlating")).not.toBeInTheDocument();
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

  it("has no Add log source link yet (Phase 19)", () => {
    useLogStore.setState({ sourceOpenMode: "merged", entries: [textLog("C:\\logs\\a.log", 1)] });
    render(<ChannelPicker />);
    expect(screen.queryByText(/add log source/i)).not.toBeInTheDocument();
  });
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

  it("does not call an unsupported tail live", () => {
    useEvtxStore.setState({ tailMode: "unsupported", tailChannels: new Set<string>() });
    render(<ChannelPicker />);
    expect(screen.getByText("Live tail \u00B7 not tailing")).toBeInTheDocument();
    expect(screen.getByLabelText("Live tail mode: unsupported")).toBeInTheDocument();
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
    if (background === "" || background === "transparent") continue;
    const onto = surface(swatch.parentElement!);
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

      const failures = pairs.filter((pair) => pair.ratio < pair.minimum);
      expect(
        failures.map((pair) => `${pair.what}: ${pair.ratio.toFixed(2)}:1 (needs ${pair.minimum})`),
      ).toEqual([]);
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

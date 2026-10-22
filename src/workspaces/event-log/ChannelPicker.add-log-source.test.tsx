/**
 * The channel pane, the Add log source menu, the helper, the real loaders and the real stores
 * together. Only the Tauri bridge and the native dialog are replaced.
 *
 * This is the acceptance path of spec 8.19: a text log opened from the pane shows up in "Also
 * correlating" with its count, and the note says what the session is given.
 */
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LogEntry, ParseResult } from "../../types/log";

const commands = vi.hoisted(() => ({ overrides: {} as Record<string, ReturnType<typeof vi.fn>> }));
const dialog = vi.hoisted(() => ({ open: vi.fn() }));

vi.mock("../../lib/commands", async (importOriginal) => {
  const original = await importOriginal<typeof import("../../lib/commands")>();
  commands.overrides = {
    getKnownLogSources: vi.fn().mockResolvedValue([]),
    inspectPathKind: vi.fn().mockResolvedValue("file"),
    listLogSourceFolder: vi.fn(),
    openLogFile: vi.fn(),
    openLogSourceFile: vi.fn(),
    parseFilesBatch: vi.fn(),
    parseRegistryFile: vi.fn(),
    stopTail: vi.fn().mockResolvedValue(undefined),
  };
  return { ...original, ...commands.overrides };
});
vi.mock("@tauri-apps/plugin-dialog", () => dialog);
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(() => Promise.resolve(() => {})),
}));

const { ChannelPicker } = await import("./ChannelPicker");
const { useEvtxStore } = await import("./evtx-store");
const { useLogStore } = await import("../../stores/log-store");
const { useUiStore } = await import("../../stores/ui-store");
const { clearAllTabSnapshots } = await import("../../lib/tab-snapshot-cache");

function entry(filePath: string, line: number): LogEntry {
  return {
    id: line,
    lineNumber: line,
    message: `line ${line}`,
    component: null,
    timestamp: 1_000 + line,
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

function parsed(filePath: string, lines: number): ParseResult {
  return {
    entries: Array.from({ length: lines }, (_, index) => entry(filePath, index + 1)),
    formatDetected: "Ccm",
    parserSelection: {
      parser: "ccm",
      implementation: "ccm",
      provenance: "dedicated",
      parseQuality: "structured",
      recordFraming: "physicalLine",
      dateOrder: null,
    },
    totalLines: lines,
    parseErrors: 0,
    filePath,
    fileSize: 1,
    modifiedUnixMs: null,
    byteOffset: 0,
  };
}

const IME = "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log";
const MSI = "C:\\Windows\\Temp\\msi-verbose.log";
const CBS = "D:\\bundle\\CBS.log";

/** Counts per file, in the section's own words. */
const LINES: Record<string, number> = { [IME]: 3, [MSI]: 1, [CBS]: 2 };

async function add(label: "Add log file\u2026" | "Add log folder\u2026", picked: unknown) {
  dialog.open.mockResolvedValueOnce(picked);
  fireEvent.click(screen.getByRole("button", { name: "Add log source\u2026" }));
  await act(async () => {
    fireEvent.click(screen.getByRole("menuitem", { name: label }));
  });
}

const section = () => screen.getByRole("region", { name: "Also correlating" });

beforeEach(() => {
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe() {}
      disconnect() {}
      unobserve() {}
    },
  );
  useEvtxStore.setState({
    records: [],
    channels: [{ name: "System", eventCount: 0, sourceType: "live", enabledState: "enabled" }],
    selectedChannels: new Set<string>(),
    loadedChannels: new Set<string>(),
    sourceMode: "live",
    timeWindow: "24h",
    isLoading: false,
    loadError: null,
  } as never);
  useLogStore.getState().clear();
  clearAllTabSnapshots();
  useUiStore.setState(useUiStore.getInitialState(), true);
  useUiStore.setState({ currentPlatform: "windows", themeId: "light" });
  commands.overrides.openLogSourceFile.mockImplementation(async (source: { path: string }) =>
    parsed(source.path, LINES[source.path] ?? 1),
  );
  commands.overrides.parseFilesBatch.mockImplementation(async (paths: string[]) =>
    paths.map((path) => parsed(path, LINES[path] ?? 1)),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  clearAllTabSnapshots();
});

describe("adding a text log from the channel pane", () => {
  it("lists the new log with its entry count", async () => {
    render(<ChannelPicker />);
    expect(within(section()).queryByText(/entr/)).not.toBeInTheDocument();

    await add("Add log file\u2026", [IME]);

    expect(within(section()).getByText("IntuneManagementExtension.log")).toBeInTheDocument();
    expect(within(section()).getByText("3 entries")).toBeInTheDocument();
    expect(within(section()).getByText("Correlating: active log source only")).toBeInTheDocument();
  });

  it("makes a second log the active source: the first leaves the list, and the note says why", async () => {
    render(<ChannelPicker />);
    await add("Add log file\u2026", [IME]);
    await add("Add log file\u2026", [MSI]);

    // Spec 8.19 as written. Merging the two is a separate decision, so this pins the literal model.
    expect(within(section()).getByText("msi-verbose.log")).toBeInTheDocument();
    expect(within(section()).getByText("1 entry")).toBeInTheDocument();
    expect(within(section()).queryByText("IntuneManagementExtension.log")).not.toBeInTheDocument();
    expect(within(section()).getByText("Correlating: active log source only")).toBeInTheDocument();
  });

  it("lists every file of a multi-select, including one from another drive", async () => {
    render(<ChannelPicker />);

    await add("Add log file\u2026", [IME, MSI, CBS]);

    const list = within(section());
    expect(list.getByText("IntuneManagementExtension.log")).toBeInTheDocument();
    expect(list.getByText("msi-verbose.log")).toBeInTheDocument();
    expect(list.getByText("CBS.log")).toBeInTheDocument();
    expect(list.getAllByText(/entr/).map((node) => node.textContent)).toEqual([
      "2 entries",
      "3 entries",
      "1 entry",
    ]);
  });

  it("says no text log is correlated after a failed add, and lists none", async () => {
    commands.overrides.openLogSourceFile.mockRejectedValueOnce(new Error("The file is locked."));
    render(<ChannelPicker />);

    await add("Add log file\u2026", [MSI]);

    expect(screen.getByRole("alert")).toHaveTextContent(
      "Could not add msi-verbose.log: The file is locked. No text log is now correlated.",
    );
    expect(within(section()).queryByText(/entr/)).not.toBeInTheDocument();
    expect(within(section()).queryByText(/^Correlating:/)).not.toBeInTheDocument();
  });

  it("refuses a registry file before anything loads", async () => {
    render(<ChannelPicker />);

    await add("Add log file\u2026", ["C:\\exports\\Policy.reg"]);

    expect(screen.getByRole("alert")).toHaveTextContent("Policy.reg is a registry file");
    expect(commands.overrides.openLogSourceFile).not.toHaveBeenCalled();
    expect(useLogStore.getState().entries).toEqual([]);
  });
});

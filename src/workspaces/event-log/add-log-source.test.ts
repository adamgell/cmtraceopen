/**
 * "Add log source..." against the real loaders and the real stores; only the Tauri bridge and the
 * native dialog are replaced. The loaders decide what the store looks like afterwards, and that is
 * what Event Logs correlates, so a mocked loader would prove nothing about it.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { LogEntry, ParseResult } from "../../types/log";

const commands = vi.hoisted(() => ({
  getKnownLogSources: vi.fn(),
  listLogSourceFolder: vi.fn(),
  inspectPathKind: vi.fn(),
  openLogFile: vi.fn(),
  openLogSourceFile: vi.fn(),
  parseFilesBatch: vi.fn(),
  parseRegistryFile: vi.fn(),
  stopTail: vi.fn(),
}));
const dialog = vi.hoisted(() => ({ open: vi.fn() }));

vi.mock("../../lib/commands", () => commands);
vi.mock("@tauri-apps/plugin-dialog", () => dialog);

import { clearAllTabSnapshots } from "../../lib/tab-snapshot-cache";
import { useFilterStore } from "../../stores/filter-store";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { logWorkspace } from "../log";
import { addLogSource } from "./add-log-source";
import { summarizeLogSources } from "./evtx-channel-stats";
import { scopeLogEntries } from "./unified-timeline";

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
    sourceFile: null,
    format: "Ccm",
    filePath,
    timezoneOffset: null,
  };
}

function parsed(filePath: string, lines = 2): ParseResult {
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

/** The text logs Event Logs would correlate, computed here rather than through the helper. */
function correlated(platform: "windows" | "macos" | "linux" = "windows") {
  const log = useLogStore.getState();
  return summarizeLogSources(
    scopeLogEntries(log.entries, log.activeSource, log.sourceOpenMode, platform),
  );
}

const A = "C:\\logs\\a.log";
const B = "C:\\logs\\b.log";

beforeEach(() => {
  vi.resetAllMocks();
  commands.stopTail.mockResolvedValue(undefined);
  commands.openLogSourceFile.mockImplementation(async (source: { path: string }) =>
    parsed(source.path),
  );
  commands.parseFilesBatch.mockImplementation(async (paths: string[]) =>
    paths.map((path) => parsed(path)),
  );
  useLogStore.getState().clear();
  clearAllTabSnapshots();
  useUiStore.setState(useUiStore.getInitialState(), true);
  useUiStore.setState({ currentPlatform: "windows" });
  useFilterStore.getState().clearFilter();
});

describe("the dialogs", () => {
  it("offers the Log workspace's file filters without the registry viewer's", async () => {
    dialog.open.mockResolvedValue(null);
    await addLogSource("file");

    expect(dialog.open).toHaveBeenCalledTimes(1);
    const options = dialog.open.mock.calls[0][0];
    expect(options.multiple).toBe(true);
    expect(options.filters.length).toBeGreaterThan(0);
    const extensions = options.filters.flatMap((filter: { extensions: string[] }) => filter.extensions);
    expect(extensions).toContain("log");
    expect(extensions).not.toContain("reg");
    // Everything else the Log workspace offers is kept.
    const logFilters = logWorkspace.fileFilters ?? [];
    expect(options.filters).toEqual(
      logFilters.filter((filter) => !filter.extensions.includes("reg")),
    );
  });

  it("asks for one folder for a folder", async () => {
    dialog.open.mockResolvedValue(null);
    await addLogSource("folder");
    expect(dialog.open).toHaveBeenCalledWith({ directory: true, multiple: false });
  });

  it("reports a dismissed dialog as cancelled and loads nothing", async () => {
    dialog.open.mockResolvedValue(null);
    await expect(addLogSource("file")).resolves.toEqual({ status: "cancelled" });
    expect(commands.openLogSourceFile).not.toHaveBeenCalled();
    expect(commands.parseFilesBatch).not.toHaveBeenCalled();
  });

  it("turns a dialog that cannot open into an outcome instead of a throw", async () => {
    dialog.open.mockRejectedValue(new Error("no window"));
    const outcome = await addLogSource("file");
    expect(outcome).toEqual({
      status: "failed",
      message: "Could not open the file dialog: no window. No text log is now correlated.",
    });
  });
});

describe("a single file", () => {
  it("becomes the active source and is correlated with its entries", async () => {
    dialog.open.mockResolvedValue([A]);
    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: null });
    expect(commands.openLogSourceFile).toHaveBeenCalledWith({ kind: "file", path: A });
    const log = useLogStore.getState();
    expect(log.sourceOpenMode).toBe("single-file");
    expect(log.activeSource).toEqual({ kind: "file", path: A });
    expect(correlated()).toEqual([{ path: A, label: "a.log", entries: 2 }]);
  });

  it("clears the Log workspace's filter, as every other open does", async () => {
    useFilterStore.getState().addQuickFilter("Message", "enrollment", "Contains");
    expect(useFilterStore.getState().clauses).toHaveLength(1);
    dialog.open.mockResolvedValue([A]);
    await addLogSource("file");
    expect(useFilterStore.getState().clauses).toEqual([]);
  });

  it("replaces the previous source: the earlier log stays a tab but is no longer correlated", async () => {
    dialog.open.mockResolvedValueOnce([A]).mockResolvedValueOnce([B]);
    await addLogSource("file");
    await addLogSource("file");

    expect(useLogStore.getState().sourceOpenMode).toBe("single-file");
    expect(correlated().map((source) => source.path)).toEqual([B]);
    // Spec 8.19 as written: the Log workspace keeps both tabs and no merge state is created.
    expect(useUiStore.getState().openTabs.map((tab) => tab.filePath)).toEqual([A, B]);
    expect(useLogStore.getState().mergedTabState).toBeNull();
  });

  it("deduplicates repeated paths from the dialog", async () => {
    dialog.open.mockResolvedValue([A, A, B]);
    await addLogSource("file");
    expect(commands.parseFilesBatch).toHaveBeenCalledWith([A, B], expect.any(Number), 0);
  });
});

describe("several files", () => {
  // The multi-file loader makes the common parent directory the active source, and
  // `scopeLogEntries` keeps what is under it. These are the shapes that decide whether a file from
  // a different directory survives, so each is pinned with the platform it runs on.
  it.each([
    ["two directories on one drive", "windows", ["C:\\logs\\a.log", "C:\\other\\b.log"]],
    ["two drives", "windows", ["C:\\logs\\a.log", "D:\\other\\b.log"]],
    ["two UNC servers", "windows", ["\\\\one\\share\\a.log", "\\\\two\\share\\b.log"]],
    ["one UNC share", "windows", ["\\\\one\\share\\a.log", "\\\\one\\share\\sub\\b.log"]],
    ["two directories", "macos", ["/Users/me/a.log", "/var/log/b.log"]],
    ["a directory and a child of it", "linux", ["/var/log/a.log", "/var/log/sub/b.log"]],
  ] as const)("keeps every selected file for %s", async (_name, platform, paths) => {
    useUiStore.setState({ currentPlatform: platform });
    dialog.open.mockResolvedValue([...paths]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: null });
    const log = useLogStore.getState();
    expect(log.sourceOpenMode).toBe("aggregate-folder");
    expect(log.entries).toHaveLength(paths.length * 2);
    expect(correlated(platform).map((source) => source.path).sort()).toEqual([...paths].sort());
  });

  it("names a file the batch parse skipped, rather than reporting every file as read", async () => {
    commands.parseFilesBatch.mockResolvedValue([parsed(A)]);
    dialog.open.mockResolvedValue([A, B]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: "Not read: b.log." });
    expect(correlated().map((source) => source.path)).toEqual([A]);
  });

  it("fails, and says so, when the batch parse reads none of them", async () => {
    commands.parseFilesBatch.mockResolvedValue([]);
    dialog.open.mockResolvedValue([A, B]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "failed",
      message: "Could not add a.log, b.log: no text log could be read. No text log is now correlated.",
    });
  });
});

describe("a long selection", () => {
  it("names the first few files and counts the rest", async () => {
    const many = ["a", "b", "c", "d", "e"].map((name) => `C:\\logs\\${name}.log`);
    commands.parseFilesBatch.mockRejectedValue(new Error("The parse service stopped."));
    dialog.open.mockResolvedValue(many);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "failed",
      message:
        "Could not add a.log, b.log, c.log and 2 more: The parse service stopped. No text log is now correlated.",
    });
  });
});

describe("a folder", () => {
  const folder = "C:\\logs\\bundle";
  const files = ["one.log", "two.log"].map((name) => `${folder}\\${name}`);

  function listing(paths: string[]) {
    return {
      sourceKind: "folder",
      source: { kind: "folder", path: folder },
      entries: paths.map((path) => ({
        name: getName(path),
        path,
        isDir: false,
        sizeBytes: 1,
        modifiedUnixMs: null,
      })),
      bundleMetadata: null,
    };
  }
  const getName = (path: string) => path.split("\\").pop()!;

  it("loads every readable file as one aggregate source", async () => {
    commands.listLogSourceFolder.mockResolvedValue(listing(files));
    dialog.open.mockResolvedValue(folder);

    const outcome = await addLogSource("folder");

    expect(outcome).toEqual({ status: "added", notice: null });
    expect(useLogStore.getState().sourceOpenMode).toBe("aggregate-folder");
    expect(correlated().map((source) => source.path)).toEqual(files);
  });

  it("names the files of the folder that could not be read", async () => {
    commands.listLogSourceFolder.mockResolvedValue(listing(files));
    commands.parseFilesBatch.mockResolvedValue([parsed(files[0])]);
    dialog.open.mockResolvedValue(folder);

    const outcome = await addLogSource("folder");

    expect(outcome).toEqual({ status: "added", notice: "Not read: two.log." });
  });

  it("says so when the folder holds no log file", async () => {
    commands.listLogSourceFolder.mockResolvedValue(listing([]));
    dialog.open.mockResolvedValue(folder);

    const outcome = await addLogSource("folder");

    expect(outcome).toEqual({
      status: "failed",
      message: "Could not add folder bundle: no readable log file was found. No text log is now correlated.",
    });
  });
});

describe("registry files", () => {
  it("are refused before anything is loaded, naming the file", async () => {
    dialog.open.mockResolvedValue(["C:\\exports\\Policy.REG"]);
    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "rejected",
      message:
        "Not added: Policy.REG is a registry file, which opens in the Log workspace. No text log is now correlated.",
    });
    expect(commands.openLogSourceFile).not.toHaveBeenCalled();
    expect(commands.parseFilesBatch).not.toHaveBeenCalled();
  });

  it("refuse the whole selection, and leave the log that was correlated alone", async () => {
    dialog.open.mockResolvedValueOnce([A]).mockResolvedValueOnce([B, "C:\\exports\\Policy.reg"]);
    await addLogSource("file");
    const outcome = await addLogSource("file");

    expect(outcome.status).toBe("rejected");
    expect(outcome.status === "rejected" && outcome.message).toContain("1 text log is now correlated.");
    expect(correlated().map((source) => source.path)).toEqual([A]);
  });
});

describe("a failed load", () => {
  it("names the file and reads the state the loader left, which is empty after a single-file failure", async () => {
    dialog.open.mockResolvedValueOnce([A]).mockResolvedValueOnce([B]);
    await addLogSource("file");
    commands.openLogSourceFile.mockRejectedValueOnce(new Error("The file is locked."));

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "failed",
      message: "Could not add b.log: The file is locked. No text log is now correlated.",
    });
    // loadLogSource clears the active log when it fails; the message reports that, not a guess.
    expect(useLogStore.getState().entries).toEqual([]);
    expect(correlated()).toEqual([]);
  });

  it("reads the state the loader left, which is unchanged after a failed multi-file parse", async () => {
    dialog.open
      .mockResolvedValueOnce([A])
      .mockResolvedValueOnce(["C:\\logs\\c.log", "C:\\logs\\d.log"]);
    await addLogSource("file");
    commands.parseFilesBatch.mockRejectedValueOnce(new Error("The parse service stopped."));

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "failed",
      message: "Could not add c.log, d.log: The parse service stopped. 1 text log is now correlated.",
    });
    expect(correlated().map((source) => source.path)).toEqual([A]);
  });
});

describe("a log with nothing to correlate", () => {
  it("is reported as read but empty, not as one more source", async () => {
    commands.openLogSourceFile.mockResolvedValue(parsed(A, 0));
    dialog.open.mockResolvedValue([A]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: "Read but holds no entries: a.log." });
    expect(correlated()).toEqual([]);
  });
});

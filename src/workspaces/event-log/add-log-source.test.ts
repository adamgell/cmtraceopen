/**
 * "Add log source..." against the real loaders and the real stores; only the Tauri bridge and the
 * native dialog are replaced. The loaders decide what the store looks like afterwards, and that is
 * what Event Logs correlates, so a mocked loader would prove nothing about it.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
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

import { loadSelectedLogFile } from "../../lib/log-source";
import { clearAllTabSnapshots, setCachedTabSnapshot } from "../../lib/tab-snapshot-cache";
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

/** What the parser returns for a registry export: the parser says so, and there are no entries. */
function registryExport(filePath: string): ParseResult {
  const result = parsed(filePath, 0);
  return {
    ...result,
    formatDetected: "Plain",
    parserSelection: { ...result.parserSelection!, parser: "registry" },
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
  it("offers the Log workspace's file filters without the registry viewer's, and keeps All Files", async () => {
    dialog.open.mockResolvedValue(null);
    await addLogSource("file");

    expect(dialog.open).toHaveBeenCalledTimes(1);
    const options = dialog.open.mock.calls[0][0];
    expect(options.multiple).toBe(true);
    expect(options.filters.length).toBeGreaterThan(0);
    const extensions = options.filters.flatMap((filter: { extensions: string[] }) => filter.extensions);
    expect(extensions).toContain("log");
    expect(extensions).toContain("*");
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
      message: "Could not open the file dialog: no window.",
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

  it("is read as a file even when the path now names a folder", async () => {
    // fallbackToFolder: false keeps the caller's declared scope. Without it the kind probe would
    // send this to the folder lane, which lists a directory the user picked as a file.
    commands.inspectPathKind.mockResolvedValue("folder");
    dialog.open.mockResolvedValue([A]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: null });
    expect(commands.openLogSourceFile).toHaveBeenCalledWith({ kind: "file", path: A });
    expect(commands.listLogSourceFolder).not.toHaveBeenCalled();
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

  it("is reported as cancelled, and writes nothing, when a newer load supersedes it", async () => {
    const pending = deferred<ParseResult>();
    commands.openLogSourceFile.mockReturnValueOnce(pending.promise);
    dialog.open.mockResolvedValue([A]);
    const add = addLogSource("file");
    await vi.waitFor(() => expect(commands.openLogSourceFile).toHaveBeenCalled());

    // The sidebar's click on a file that is already parsed takes the generation.
    setCachedTabSnapshot(B, {
      entries: [entry(B, 1)],
      formatDetected: "Ccm",
      parserSelection: null,
      totalLines: 1,
      byteOffset: 0,
      selectedSourceFilePath: B,
      sourceOpenMode: "single-file",
      activeColumns: [],
    });
    await loadSelectedLogFile(B, { kind: "file", path: B });
    pending.resolve(parsed(A));

    await expect(add).resolves.toEqual({ status: "cancelled" });
    expect(useLogStore.getState().entries.map((e) => e.filePath)).toEqual([B]);
  });
});

describe("the Log workspace's filter", () => {
  const withFilter = () => {
    useFilterStore.getState().addQuickFilter("Message", "enrollment", "Contains");
    expect(useFilterStore.getState().clauses).toHaveLength(1);
  };

  it("is cleared after an add that took, as every other open does", async () => {
    withFilter();
    dialog.open.mockResolvedValue([A]);
    await addLogSource("file");
    expect(useFilterStore.getState().clauses).toEqual([]);
  });

  // It only changes the Log view (filteredIds, never the store's entries), so an add that did not
  // take leaves it alone.
  it.each([
    ["a registry file", ["C:\\exports\\Policy.reg"]],
    ["an event log", ["C:\\Windows\\System32\\winevt\\Logs\\Security.evtx"]],
  ])("is left alone when %s is refused", async (_name, picked) => {
    withFilter();
    dialog.open.mockResolvedValue(picked);

    const outcome = await addLogSource("file");

    expect(outcome.status).toBe("rejected");
    expect(useFilterStore.getState().clauses).toHaveLength(1);
  });

  it("is left alone when the load fails", async () => {
    withFilter();
    commands.openLogSourceFile.mockRejectedValueOnce(new Error("The file is locked."));
    dialog.open.mockResolvedValue([A]);

    expect((await addLogSource("file")).status).toBe("failed");
    expect(useFilterStore.getState().clauses).toHaveLength(1);
  });

  // The multi-file loader clears the filter itself, before it parses (log-source.ts), so the
  // helper has to give it back when the add does not take.
  describe("after the multi-file loader has cleared it", () => {
    it("is given back when the parse fails", async () => {
      withFilter();
      const before = useFilterStore.getState().clauses;
      commands.parseFilesBatch.mockRejectedValueOnce(new Error("The parse service stopped."));
      dialog.open.mockResolvedValue([A, B]);

      expect((await addLogSource("file")).status).toBe("failed");
      expect(useFilterStore.getState().clauses).toEqual(before);
    });

    it("is given back when nothing could be read", async () => {
      withFilter();
      commands.parseFilesBatch.mockResolvedValue([]);
      dialog.open.mockResolvedValue([A, B]);

      expect((await addLogSource("file")).status).toBe("failed");
      expect(useFilterStore.getState().clauses).toHaveLength(1);
    });

    it("is given back when every file is empty", async () => {
      withFilter();
      commands.parseFilesBatch.mockResolvedValue([parsed(A, 0), parsed(B, 0)]);
      dialog.open.mockResolvedValue([A, B]);

      expect((await addLogSource("file")).status).toBe("notAdded");
      expect(useFilterStore.getState().clauses).toHaveLength(1);
    });

    it("is still given back when the Log view only recomputed its rows meanwhile", async () => {
      withFilter();
      commands.parseFilesBatch.mockImplementationOnce(async () => {
        // The shell recomputes filteredIds as entries change; the clauses are not touched.
        useFilterStore.getState().setIsFiltering(true);
        useFilterStore.getState().setFilteredIds(new Set([1, 2]));
        useFilterStore.getState().setIsFiltering(false);
        throw new Error("The parse service stopped.");
      });
      dialog.open.mockResolvedValue([A, B]);

      await addLogSource("file");
      expect(useFilterStore.getState().clauses).toHaveLength(1);
    });

    it("is not given back over a deliberate clear after the loader's own", async () => {
      withFilter();
      commands.parseFilesBatch.mockImplementationOnce(async () => {
        // The user clears the Log filter while the parse runs. The clauses are empty, as they are
        // after the loader's clear, and that is the case an emptiness check cannot tell apart.
        useFilterStore.getState().clearFilter();
        throw new Error("The parse service stopped.");
      });
      dialog.open.mockResolvedValue([A, B]);

      await addLogSource("file");
      expect(useFilterStore.getState().clauses).toEqual([]);
    });

    it("is not given back over a deliberate clear that came before the loader's", async () => {
      withFilter();
      // An earlier log is open, so the loader stops its tail first, and the user clears the filter
      // while that runs: the loader's clear then finds nothing to clear.
      useLogStore.setState({ openFilePath: "C:\\logs\\open.log", sourceOpenMode: "single-file" });
      commands.stopTail.mockImplementationOnce(async () => {
        useFilterStore.getState().clearFilter();
      });
      commands.parseFilesBatch.mockRejectedValueOnce(new Error("The parse service stopped."));
      dialog.open.mockResolvedValue([A, B]);

      await addLogSource("file");
      expect(commands.stopTail).toHaveBeenCalled();
      expect(useFilterStore.getState().clauses).toEqual([]);
    });

    it("is not given back over a filter someone set since", async () => {
      withFilter();
      commands.parseFilesBatch.mockImplementationOnce(async () => {
        useFilterStore.getState().clearFilter();
        useFilterStore.getState().addQuickFilter("Component", "other", "Equals");
        throw new Error("The parse service stopped.");
      });
      dialog.open.mockResolvedValue([A, B]);

      await addLogSource("file");
      expect(useFilterStore.getState().clauses).toEqual([
        { field: "Component", value: "other", op: "Equals" },
      ]);
    });

    it("is cleared, as every open does, when the add takes", async () => {
      withFilter();
      dialog.open.mockResolvedValue([A, B]);

      expect((await addLogSource("file")).status).toBe("added");
      expect(useFilterStore.getState().clauses).toEqual([]);
    });
  });

  // The single-file and folder loaders never clear the filter, so there is nothing to give back,
  // and a clear that someone made meanwhile is theirs.
  it("is never given back after a single-file failure, whatever happened to it meanwhile", async () => {
    withFilter();
    commands.openLogSourceFile.mockImplementationOnce(async () => {
      useFilterStore.getState().clearFilter();
      throw new Error("The file is locked.");
    });
    dialog.open.mockResolvedValue([A]);

    expect((await addLogSource("file")).status).toBe("failed");
    expect(useFilterStore.getState().clauses).toEqual([]);
  });

  it("is never given back after a folder failure, whatever happened to it meanwhile", async () => {
    withFilter();
    commands.listLogSourceFolder.mockImplementationOnce(async () => {
      useFilterStore.getState().clearFilter();
      throw new Error("The folder could not be listed.");
    });
    dialog.open.mockResolvedValue("C:\\logs\\bundle");

    expect((await addLogSource("folder")).status).toBe("failed");
    expect(useFilterStore.getState().clauses).toEqual([]);
  });

  it("is left alone when the add leaves none of its files correlated", async () => {
    withFilter();
    commands.openLogSourceFile.mockResolvedValue(parsed(A, 0));
    dialog.open.mockResolvedValue([A]);

    expect((await addLogSource("file")).status).toBe("notAdded");
    expect(useFilterStore.getState().clauses).toHaveLength(1);
  });

  it("is left alone when the dialog is dismissed", async () => {
    withFilter();
    dialog.open.mockResolvedValue(null);
    await addLogSource("file");
    expect(useFilterStore.getState().clauses).toHaveLength(1);
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
      message: "Could not add a.log, b.log: no text log could be read.",
    });
  });

  it("is added when one file is correlated, and says the others are not", async () => {
    commands.parseFilesBatch.mockResolvedValue([parsed(A, 2), parsed(B, 0)]);
    dialog.open.mockResolvedValue([A, B]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: "b.log holds no entries." });
    expect(correlated().map((source) => source.path)).toEqual([A]);
  });

  it("compares paths the way the platform does: a POSIX pair that differs only in case is two files", async () => {
    useUiStore.setState({ currentPlatform: "linux" });
    // Only a.log came back. On a case-sensitive file system A.log is a different file, so it was
    // not read, and folding case would count it as read.
    commands.parseFilesBatch.mockResolvedValue([parsed("/logs/a.log")]);
    dialog.open.mockResolvedValue(["/logs/A.log", "/logs/a.log"]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: "Not read: A.log." });
  });

  it("compares Windows paths without regard to case or separator", async () => {
    // The parser hands the path back as it was given, but the platform treats these as one file.
    commands.parseFilesBatch.mockResolvedValue([parsed("c:/logs/a.log"), parsed(B)]);
    dialog.open.mockResolvedValue(["C:\\Logs\\A.log", B]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: null });
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
      message: "Could not add a.log, b.log, c.log and 2 more: The parse service stopped.",
    });
  });

  it("names a single skipped file with the singular, and a run of them with the plural and a count", async () => {
    const many = ["a", "b", "c", "d", "e"].map((name) => `C:\\logs\\${name}.log`);
    commands.parseFilesBatch.mockResolvedValue([parsed(many[0])]);
    dialog.open.mockResolvedValue(many);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "added", notice: "Not read: b.log, c.log, d.log and 1 more." });
  });
});

describe("a folder", () => {
  const folder = "C:\\logs\\bundle";
  const files = ["one.log", "two.log"].map((name) => `${folder}\\${name}`);
  const getName = (path: string) => path.split("\\").pop()!;

  function listing(
    paths: string[],
    extra: {
      dirs?: string[];
      childErrors?: { path: string; reason: string }[];
      bundle?: boolean;
    } = {},
  ) {
    return {
      sourceKind: "folder",
      source: { kind: "folder", path: folder },
      entries: [
        ...(extra.dirs ?? []).map((name) => ({
          name,
          path: `${folder}\\${name}`,
          isDir: true,
          sizeBytes: null,
          modifiedUnixMs: null,
        })),
        ...paths.map((path) => ({
          name: getName(path),
          path,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        })),
      ],
      childErrors: extra.childErrors,
      bundleMetadata: extra.bundle ? ({ bundleId: "CMTRACE-20260822-120000-HOST" } as never) : null,
    };
  }

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
      message: "Could not add folder bundle: no readable log file was found.",
    });
  });

  // soul.md rule 4: a folder add never presents partial coverage as complete. The loader reads the
  // top level only, so what sits below it, and what the listing could not include, is named.
  describe("coverage", () => {
    it("names the subfolders it did not read, as a count and up to three names", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, { dirs: ["CBS", "DISM", "Panther", "Logs", "winevt"] }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome).toEqual({
        status: "added",
        notice: "5 subfolders not read: CBS, DISM, Panther and 2 more.",
      });
    });

    it("uses the singular for one subfolder", async () => {
      commands.listLogSourceFolder.mockResolvedValue(listing(files, { dirs: ["CBS"] }));
      dialog.open.mockResolvedValue(folder);

      expect(await addLogSource("folder")).toEqual({
        status: "added",
        notice: "1 subfolder not read: CBS.",
      });
    });

    it("names the items that could not be listed, without counting them as entries", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, {
          childErrors: [
            { path: `${folder}\\locked.log`, reason: "entry is not readable" },
            { path: `${folder}\\sub`, reason: "symbolic link or reparse point is not followed" },
          ],
        }),
      );
      dialog.open.mockResolvedValue(folder);

      expect(await addLogSource("folder")).toEqual({
        status: "added",
        notice:
          "Could not list: locked.log (entry is not readable), sub (symbolic link or reparse point is not followed).",
      });
    });

    it("names a bundle subdirectory it could not enter, and claims no count of entries or files", async () => {
      // collect_files_recursive records a subdirectory it cannot read under the subdirectory's own
      // path, and the record has no kind: it cannot be told from a file, and what the directory held
      // is unknown.
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, {
          bundle: true,
          childErrors: [{ path: `${folder}\\Intune\\Logs`, reason: "Access is denied." }],
        }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome).toEqual({
        status: "added",
        notice:
          "Could not list: Logs (Access is denied). Binary and oversized files in an evidence bundle are not read.",
      });
      const notice = outcome.status === "added" ? (outcome.notice ?? "") : "";
      expect(notice).not.toMatch(/entr/i);
      expect(notice).not.toMatch(/\d+\s+(files?|entr)/i);
    });

    it("counts the records beyond the first three only as 'more', not as entries or files", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, {
          childErrors: ["a", "b", "c", "d", "e"].map((name) => ({
            path: `${folder}\\${name}`,
            reason: "entry is not readable",
          })),
        }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome).toEqual({
        status: "added",
        notice:
          "Could not list: a (entry is not readable), b (entry is not readable), c (entry is not readable) and 2 more.",
      });
    });

    it("reports a limit on the listing itself without a count, because it stands for entries never listed", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, {
          childErrors: [{ path: folder, reason: "folder listing reached the 4096-entry limit" }],
        }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome).toEqual({
        status: "added",
        notice:
          "The folder listing itself reported: folder listing reached the 4096-entry limit. How many entries that left out is unknown.",
      });
      // No quantity of entries is claimed anywhere in it.
      expect(outcome.status === "added" && outcome.notice).not.toMatch(/\b1 entr/);
    });

    it("names the items and keeps the listing's own limits uncounted when both are reported", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, {
          childErrors: [
            { path: `${folder}\\locked.log`, reason: "entry is not readable" },
            { path: folder, reason: "folder listing reached the 4096-entry limit" },
            { path: folder, reason: "folder listing reached the 16384-entry work limit" },
          ],
        }),
      );
      dialog.open.mockResolvedValue(folder);

      expect(await addLogSource("folder")).toEqual({
        status: "added",
        notice:
          "Could not list: locked.log (entry is not readable). " +
          "The folder listing itself reported: folder listing reached the 4096-entry limit, " +
          "folder listing reached the 16384-entry work limit. How many entries that left out is unknown.",
      });
    });

    it("recognizes the listed folder by its path as the platform compares it, not by its spelling", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, {
          // The backend echoes the path it was given; case and separators are the platform's business.
          childErrors: [{ path: "C:/LOGS/bundle/", reason: "combined diagnostics exceeded the limit" }],
        }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome.status === "added" && outcome.notice).toBe(
        "The folder listing itself reported: combined diagnostics exceeded the limit. How many entries that left out is unknown.",
      );
    });

    it("tells a limit from an entry by the record's path, not its message", async () => {
      // A message that says "limit" about a child is still one entry; one about the folder that
      // does not say it is still the listing.
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, {
          childErrors: [
            { path: `${folder}\\huge.log`, reason: "file exceeds the 1048576 byte bundle limit" },
            { path: folder, reason: "a diagnostic worded some other way" },
          ],
        }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome.status === "added" && outcome.notice).toBe(
        "Could not list: huge.log (file exceeds the 1048576 byte bundle limit). " +
          "The folder listing itself reported: a diagnostic worded some other way. How many entries that left out is unknown.",
      );
    });

    it("keeps a long reason short", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, { childErrors: [{ path: `${folder}\\x`, reason: "r".repeat(400) }] }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome.status === "added" && outcome.notice).toBe(
        `Could not list: x (${"r".repeat(117)}...).`,
      );
    });

    it("keeps a long listing-level reason short too", async () => {
      commands.listLogSourceFolder.mockResolvedValue(
        listing(files, { childErrors: [{ path: folder, reason: "r".repeat(400) }] }),
      );
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome.status === "added" && outcome.notice).toBe(
        `The folder listing itself reported: ${"r".repeat(117)}.... How many entries that left out is unknown.`,
      );
    });

    it("says what an evidence bundle's collector skips, instead of counting subfolders", async () => {
      commands.listLogSourceFolder.mockResolvedValue(listing(files, { bundle: true }));
      dialog.open.mockResolvedValue(folder);

      const outcome = await addLogSource("folder");

      expect(outcome).toEqual({
        status: "added",
        notice: "Binary and oversized files in an evidence bundle are not read.",
      });
    });

    it("names the coverage with the files that were not read, and in the failure", async () => {
      commands.listLogSourceFolder.mockResolvedValue(listing(files, { dirs: ["CBS"] }));
      commands.parseFilesBatch.mockResolvedValue([parsed(files[0])]);
      dialog.open.mockResolvedValue(folder);

      expect(await addLogSource("folder")).toEqual({
        status: "added",
        notice: "Not read: two.log. 1 subfolder not read: CBS.",
      });

      commands.listLogSourceFolder.mockResolvedValue(listing([], { dirs: ["CBS"] }));
      expect(await addLogSource("folder")).toEqual({
        status: "failed",
        message: "Could not add folder bundle: no readable log file was found. 1 subfolder not read: CBS.",
      });
    });
  });
});

describe("a selection that cannot be a text log", () => {
  it("refuses a registry file before anything loads, naming it", async () => {
    dialog.open.mockResolvedValue(["C:\\exports\\Policy.REG"]);
    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "rejected",
      message: "Not added: Policy.REG is a registry file, which opens in the Log workspace.",
    });
    expect(commands.openLogSourceFile).not.toHaveBeenCalled();
    expect(commands.parseFilesBatch).not.toHaveBeenCalled();
  });

  it.each([
    "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
    "C:\\Windows\\System32\\winevt\\Logs\\SECURITY.EVTX",
    "C:\\Backups\\Security.evtx.bak",
    "C:\\Backups\\Archive-Security-2026.evtx.1",
    "C:\\Backups\\Security.evtx~",
  ])("refuses the event log %s, and says where EVTX is opened", async (path) => {
    dialog.open.mockResolvedValue([path]);
    const name = path.split("\\").pop();

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "rejected",
      message: `Not added: ${name} is an event log file; Event Logs opens EVTX files through its source picker.`,
    });
    expect(commands.openLogSourceFile).not.toHaveBeenCalled();
  });

  it("does not mistake a log that merely mentions evtx for an event log", async () => {
    dialog.open.mockResolvedValue(["C:\\logs\\evtx-export.log", "C:\\logs\\events.evtxlog"]);

    const outcome = await addLogSource("file");

    expect(outcome.status).toBe("added");
  });

  it("refuses the whole selection, naming each kind, and leaves the log that was correlated alone", async () => {
    dialog.open.mockResolvedValueOnce([A]).mockResolvedValueOnce([
      B,
      "C:\\exports\\Policy.reg",
      "C:\\exports\\Other.reg",
      "C:\\Windows\\Security.evtx",
    ]);
    await addLogSource("file");
    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "rejected",
      message:
        "Not added: Policy.reg, Other.reg are registry files, which open in the Log workspace. " +
        "Security.evtx is an event log file; Event Logs opens EVTX files through its source picker.",
    });
    expect(correlated().map((source) => source.path)).toEqual([A]);
  });
});

describe("a failed load", () => {
  it("names the file, and the loader has left nothing correlated after a single-file failure", async () => {
    dialog.open.mockResolvedValueOnce([A]).mockResolvedValueOnce([B]);
    await addLogSource("file");
    commands.openLogSourceFile.mockRejectedValueOnce(new Error("The file is locked."));

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "failed",
      message: "Could not add b.log: The file is locked.",
    });
    // loadLogSource clears the active log when it fails; the pane's live sentence reports that.
    expect(useLogStore.getState().entries).toEqual([]);
    expect(correlated()).toEqual([]);
  });

  it("leaves the earlier log correlated after a failed multi-file parse", async () => {
    dialog.open
      .mockResolvedValueOnce([A])
      .mockResolvedValueOnce(["C:\\logs\\c.log", "C:\\logs\\d.log"]);
    await addLogSource("file");
    commands.parseFilesBatch.mockRejectedValueOnce(new Error("The parse service stopped."));

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "failed",
      message: "Could not add c.log, d.log: The parse service stopped.",
    });
    expect(correlated().map((source) => source.path)).toEqual([A]);
  });
});

describe("an add that leaves none of its files correlated", () => {
  it("is not added when the log holds no entries, and the earlier correlation is gone", async () => {
    dialog.open.mockResolvedValueOnce([A]).mockResolvedValueOnce([B]);
    await addLogSource("file");
    commands.openLogSourceFile.mockResolvedValue(parsed(B, 0));

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({ status: "notAdded", message: "Not added: b.log holds no entries." });
    expect(correlated()).toEqual([]);
  });

  it("is not added when the parser classifies the file as a registry export by its content", async () => {
    commands.openLogSourceFile.mockResolvedValue(registryExport("C:\\exports\\policy-export.txt"));
    dialog.open.mockResolvedValue(["C:\\exports\\policy-export.txt"]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "notAdded",
      message: "Not added: policy-export.txt is a registry export; registry files are not correlated.",
    });
    expect(useLogStore.getState().entries).toEqual([]);
  });

  it("names a registry export in a multi-file add that still correlated something", async () => {
    const registry = "C:\\logs\\policy-export.txt";
    commands.parseFilesBatch.mockResolvedValue([parsed(A), registryExport(registry)]);
    dialog.open.mockResolvedValue([A, registry]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "added",
      notice: "policy-export.txt is a registry export; registry files are not correlated.",
    });
  });

  it("is not added when every file of a multi-file add is empty or a registry export", async () => {
    const registry = "C:\\logs\\policy-export.txt";
    commands.parseFilesBatch.mockResolvedValue([parsed(A, 0), registryExport(registry)]);
    dialog.open.mockResolvedValue([A, registry]);

    const outcome = await addLogSource("file");

    expect(outcome).toEqual({
      status: "notAdded",
      message:
        "Not added: policy-export.txt is a registry export; registry files are not correlated. a.log holds no entries.",
    });
  });
});

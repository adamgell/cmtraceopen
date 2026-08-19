import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  FolderEntry,
  KnownSourceMetadata,
  LogEntry,
  LogSource,
  ParseResult,
} from "../types/log";
import type { EvidenceBundleMetadata } from "../types/evidence";
import { useLogStore, setCachedTabSnapshot, clearAllTabSnapshots } from "../stores/log-store";
import type { TabEntrySnapshot } from "./tab-snapshot-cache";
import { useUiStore } from "../stores/ui-store";
import { loadLogSource, loadSelectedLogFile, switchToTab } from "./log-source";

const commands = vi.hoisted(() => ({
  getKnownLogSources: vi.fn(),
  listLogSourceFolder: vi.fn(),
  openLogFile: vi.fn(),
  openLogSourceFile: vi.fn(),
  parseFilesBatch: vi.fn(),
  parseRegistryFile: vi.fn(),
  stopTail: vi.fn(),
}));

vi.mock("./commands", () => commands);

const deviceInventoryFolder: LogSource = {
  kind: "known",
  sourceId: "windows-intune-device-inventory-logs",
  defaultPath: "C:\\Program Files\\Microsoft Device Inventory Agent\\Logs",
  pathKind: "folder",
};

const deviceInventoryFiles: LogSource[] = [
  {
    kind: "known",
    sourceId: "windows-intune-device-inventory-harvester-log",
    defaultPath:
      "C:\\Program Files\\Microsoft Device Inventory Agent\\Logs\\IntuneInventoryHarvesterLog.log",
    pathKind: "file",
  },
  {
    kind: "known",
    sourceId: "windows-intune-device-inventory-adaptor-log",
    defaultPath:
      "C:\\Program Files\\Microsoft Device Inventory Agent\\Logs\\InventoryAdaptor.log",
    pathKind: "file",
  },
];

const folderEntries: FolderEntry[] = [
  {
    name: "IntuneInventoryHarvesterLog.log",
    path: `${deviceInventoryFolder.defaultPath}\\IntuneInventoryHarvesterLog.log`,
    isDir: false,
    sizeBytes: 1,
    modifiedUnixMs: 0,
  },
];

const parseResult: ParseResult = {
  entries: [],
  formatDetected: "Plain",
  parserSelection: {
    parser: "plain",
    implementation: "plainText",
    provenance: "fallback",
    parseQuality: "textFallback",
    recordFraming: "physicalLine",
    dateOrder: null,
  },
  totalLines: 0,
  parseErrors: 0,
  filePath: folderEntries[0].path,
  fileSize: 1,
  byteOffset: 0,
};

describe("Device Inventory known-source routing", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    useLogStore.getState().clear();
    useLogStore.setState({
      knownSources: [deviceInventoryFolder, ...deviceInventoryFiles].map((source) => ({
          id: source.kind === "known" ? source.sourceId : "",
          label: source.kind === "known" ? source.sourceId : "",
          description: "Device Inventory source",
          platform: "windows",
          sourceKind: "known",
          source,
          filePatterns: ["*.log", "*.log_"],
        })) satisfies KnownSourceMetadata[],
    });
    commands.listLogSourceFolder.mockResolvedValue({
      sourceKind: "known",
      source: deviceInventoryFolder,
      entries: folderEntries,
      bundleMetadata: null,
    });
    commands.parseFilesBatch.mockResolvedValue([parseResult]);
    commands.openLogSourceFile.mockResolvedValue(parseResult);
    commands.stopTail.mockResolvedValue(undefined);
  });

  it("loads the Device Inventory folder through the batch loader without a selected file", async () => {
    const result = await loadLogSource(deviceInventoryFolder);

    expect(result.selectedFilePath).toBeNull();
    expect(commands.listLogSourceFolder).toHaveBeenCalledWith(deviceInventoryFolder);
    expect(commands.parseFilesBatch).toHaveBeenCalledWith([folderEntries[0].path]);
    expect(commands.openLogSourceFile).not.toHaveBeenCalled();
  });

  it.each(deviceInventoryFiles)(
    "opens direct Device Inventory file source $sourceId",
    async (source) => {
      const result = await loadLogSource(source);

      expect(result.selectedFilePath).toBe(parseResult.filePath);
      expect(commands.openLogSourceFile).toHaveBeenCalledWith(source);
      expect(commands.listLogSourceFolder).not.toHaveBeenCalled();
    }
  );
});

function makeEntry(id: number, filePath: string, message: string): LogEntry {
  return {
    id,
    lineNumber: id,
    message,
    component: "AppEnforce",
    timestamp: id,
    timestampDisplay: `2026-07-26 12:00:0${id}.000`,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Ccm",
    filePath,
    timezoneOffset: null,
  };
}

function snapshotFor(filePath: string, message: string): TabEntrySnapshot {
  return {
    entries: [makeEntry(1, filePath, message)],
    formatDetected: "Ccm",
    parserSelection: {
      parser: "ccm",
      implementation: "ccm",
      provenance: "dedicated",
      parseQuality: "structured",
      recordFraming: "physicalLine",
      dateOrder: null,
    },
    totalLines: 1,
    byteOffset: 0,
    selectedSourceFilePath: filePath,
    sourceOpenMode: "single-file",
    activeColumns: ["severity", "dateTime", "message"],
  };
}
function evidenceBundleMetadata(): EvidenceBundleMetadata {
  return {
    manifestPath: "C:/Evidence/manifest.json",
    notesPath: "C:/Evidence/notes.md",
    evidenceRoot: "C:/Evidence",
    primaryEntryPoints: ["evidence/ime.log"],
    availablePrimaryEntryPoints: ["evidence/ime.log"],
    bundleId: "bundle-fixture",
    bundleLabel: "Fixture bundle",
    createdUtc: "2026-08-18T12:00:00Z",
    caseReference: "CASE-018",
    summary: "Fixture bundle",
    collectorProfile: "quick",
    collectorVersion: "1.0.0",
    collectedUtc: "2026-08-18T12:00:00Z",
    deviceName: "TEST-PC",
    primaryUser: "analyst",
    platform: "windows",
    osVersion: "10.0.26100",
    tenant: "contoso",
    artifactCounts: {
      collected: 1,
      missing: 0,
      failed: 0,
      skipped: 0,
    },
  };
}

type FolderListing = {
  sourceKind: "folder";
  source: LogSource;
  entries: FolderEntry[];
  bundleMetadata: null;
};

function deferred<T>() {
  let resolvePromise: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });

  return {
    promise,
    resolve(value: T) {
      if (!resolvePromise) {
        throw new Error("Deferred promise resolver was not initialized");
      }
      resolvePromise(value);
    },
  };
}

describe("switchToTab", () => {
  const fileA = "C:/Windows/CCM/Logs/AppEnforce.log";
  const fileB = "C:/Windows/CCM/Logs/CIAgent.log";
  const folderSource: LogSource = { kind: "folder", path: "C:/Windows/CCM/Logs" };

  beforeEach(() => {
    vi.resetAllMocks();
    useLogStore.getState().clear();
    useUiStore.getState().clearTabs();
    clearAllTabSnapshots();
    commands.listLogSourceFolder.mockResolvedValue({
      sourceKind: "folder",
      source: folderSource,
      entries: [],
      bundleMetadata: null,
    });
    commands.stopTail.mockResolvedValue(undefined);
  });
  it("propagates registry parse failures from selected-file loads", async () => {
    const source: LogSource = { kind: "file", path: fileB };
    const registryResult: ParseResult = {
      ...parseResult,
      filePath: fileB,
      parserSelection: {
        ...parseResult.parserSelection,
        parser: "registry",
        implementation: "registry",
      },
    };
    const parseError = new Error("registry fixture is unreadable");
    commands.openLogFile.mockResolvedValueOnce(registryResult);
    commands.parseRegistryFile.mockRejectedValueOnce(parseError);

    await expect(loadSelectedLogFile(fileB, source)).rejects.toThrow(
      "registry fixture is unreadable",
    );
    expect(useLogStore.getState().isLoading).toBe(false);
  });

  it("restores a cached migrated tab as a standalone file", async () => {
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      activeSource: folderSource,
      sourceEntries: folderEntries,
      bundleMetadata: evidenceBundleMetadata(),
    });

    await switchToTab(fileB, null);

    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().activeSource).toEqual({
      kind: "file",
      path: fileB,
    });
    expect(useLogStore.getState().sourceEntries).toEqual([]);
    expect(useLogStore.getState().bundleMetadata).toBeNull();
  });
  it("swaps the list to the cached file before folder restore finishes", async () => {
    setCachedTabSnapshot(fileA, snapshotFor(fileA, "AppEnforce line"));
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      activeSource: { kind: "file", path: fileA },
      sourceOpenMode: "aggregate-folder",
    });

    const listing = deferred<FolderListing>();
    commands.listLogSourceFolder.mockReturnValue(listing.promise);

    const pending = switchToTab(fileB, {
      sourceKind: "folder",
      sourcePath: folderSource.path,
      source: folderSource,
    });

    await vi.waitFor(() => {
      expect(useLogStore.getState().openFilePath).toBe(fileB);
      expect(useLogStore.getState().selectedSourceFilePath).toBe(fileB);
      expect(useLogStore.getState().entries.map((entry) => entry.message)).toEqual([
        "CIAgent line",
      ]);
    });
    expect(useLogStore.getState().sourceOpenMode).toBe("single-file");

    listing.resolve({
      sourceKind: "folder",
      source: folderSource,
      entries: [],
      bundleMetadata: null,
    });
    await pending;
    expect(commands.openLogFile).not.toHaveBeenCalled();
  });

  it("restores each cached file when switching back and forth", async () => {
    setCachedTabSnapshot(fileA, snapshotFor(fileA, "AppEnforce line"));
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      activeSource: folderSource,
    });
    const ctx = {
      sourceKind: "folder" as const,
      sourcePath: folderSource.path,
      source: folderSource,
    };

    await switchToTab(fileB, ctx);
    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().entries[0]?.message).toBe("CIAgent line");

    await switchToTab(fileA, ctx);
    expect(useLogStore.getState().openFilePath).toBe(fileA);
    expect(useLogStore.getState().entries[0]?.message).toBe("AppEnforce line");
  });

  it("does not apply a stale folder listing after a later tab switch", async () => {
    const otherFolder: LogSource = { kind: "folder", path: "C:/Windows/CCM/Logs/Other" };
    const fileC = "C:/Windows/CCM/Logs/Start.log";
    setCachedTabSnapshot(fileA, snapshotFor(fileA, "AppEnforce line"));
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    setCachedTabSnapshot(fileC, snapshotFor(fileC, "Start line"));
    useLogStore.setState({
      openFilePath: fileC,
      selectedSourceFilePath: fileC,
      entries: snapshotFor(fileC, "Start line").entries,
      activeSource: { kind: "folder", path: "C:/Windows/CCM/Logs/Start" },
    });
    const firstListing = deferred<FolderListing>();
    commands.listLogSourceFolder.mockReturnValueOnce(firstListing.promise);
    commands.listLogSourceFolder.mockResolvedValueOnce({
      sourceKind: "folder",
      source: otherFolder,
      entries: [
        {
          name: "CIAgent.log",
          path: fileB,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
      ],
      bundleMetadata: null,
    });

    const first = switchToTab(fileA, {
      sourceKind: "folder",
      sourcePath: folderSource.path,
      source: folderSource,
    });
    const second = switchToTab(fileB, {
      sourceKind: "folder",
      sourcePath: otherFolder.path,
      source: otherFolder,
    });

    await second;
    expect(useLogStore.getState().activeSource).toEqual(otherFolder);

    firstListing.resolve({
      sourceKind: "folder",
      source: folderSource,
      entries: [
        {
          name: "AppEnforce.log",
          path: fileA,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
      ],
      bundleMetadata: null,
    });
    await first;
    expect(useLogStore.getState().activeSource).toEqual(otherFolder);
    expect(useLogStore.getState().sourceEntries.map((entry) => entry.path)).toEqual([fileB]);
  });

  it("discards a folder restore when switching to a cached standalone file", async () => {
    const fileC = "C:/Windows/CCM/Logs/Start.log";
    const fileSource: LogSource = { kind: "file", path: fileB };
    setCachedTabSnapshot(fileA, snapshotFor(fileA, "AppEnforce line"));
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    setCachedTabSnapshot(fileC, snapshotFor(fileC, "Start line"));
    useLogStore.setState({
      openFilePath: fileC,
      selectedSourceFilePath: fileC,
      entries: snapshotFor(fileC, "Start line").entries,
      activeSource: { kind: "file", path: fileC },
    });

    const staleListing = deferred<FolderListing>();
    commands.listLogSourceFolder.mockReturnValueOnce(staleListing.promise);

    const folderSwitch = switchToTab(fileA, {
      sourceKind: "folder",
      sourcePath: folderSource.path,
      source: folderSource,
    });
    const standaloneSwitch = switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSource,
    });

    await standaloneSwitch;
    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().activeSource).toEqual(fileSource);
    expect(useLogStore.getState().sourceEntries).toEqual([]);

    staleListing.resolve({
      sourceKind: "folder",
      source: folderSource,
      entries: [
        {
          name: "AppEnforce.log",
          path: fileA,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
      ],
      bundleMetadata: null,
    });
    await folderSwitch;

    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().activeSource).toEqual(fileSource);
    expect(useLogStore.getState().sourceEntries).toEqual([]);
    expect(useLogStore.getState().bundleMetadata).toBeNull();
  });
  it("does not apply a stale cache-miss file load after a later tab switch", async () => {
    const fileC = "C:/Windows/CCM/Logs/Start.log";
    const fileSource: LogSource = { kind: "file", path: fileB };
    const fileASnapshot = snapshotFor(fileA, "AppEnforce line");
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    useLogStore.setState({
      openFilePath: fileC,
      selectedSourceFilePath: fileC,
      entries: snapshotFor(fileC, "Start line").entries,
      activeSource: { kind: "file", path: fileC },
    });

    const listing = deferred<FolderListing>();
    const parsed = deferred<ParseResult>();
    commands.listLogSourceFolder.mockReturnValueOnce(listing.promise);
    commands.openLogFile.mockReturnValueOnce(parsed.promise);

    const folderSwitch = switchToTab(fileA, {
      sourceKind: "folder",
      sourcePath: folderSource.path,
      source: folderSource,
    });

    listing.resolve({
      sourceKind: "folder",
      source: folderSource,
      entries: [
        {
          name: "AppEnforce.log",
          path: fileA,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
      ],
      bundleMetadata: null,
    });
    await vi.waitFor(() => {
      expect(commands.openLogFile).toHaveBeenCalledWith(fileA);
    });

    const standaloneSwitch = switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSource,
    });
    await standaloneSwitch;
    expect(useLogStore.getState().openFilePath).toBe(fileB);

    parsed.resolve({
      ...parseResult,
      filePath: fileA,
      entries: fileASnapshot.entries,
      parserSelection: fileASnapshot.parserSelection ?? parseResult.parserSelection,
    });
    await folderSwitch;

    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().entries[0]?.message).toBe("CIAgent line");
    expect(useLogStore.getState().activeSource).toEqual(fileSource);
  });
  it("clears folder context after an uncached standalone switch", async () => {
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      activeSource: folderSource,
      sourceEntries: folderEntries,
      bundleMetadata: evidenceBundleMetadata(),
    });
    commands.openLogFile.mockResolvedValueOnce({
      ...parseResult,
      filePath: fileB,
      entries: [makeEntry(2, fileB, "CIAgent line")],
    });

    await switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });

    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().activeSource).toEqual(fileSourceB);
    expect(useLogStore.getState().sourceEntries).toEqual([]);
    expect(useLogStore.getState().bundleMetadata).toBeNull();
  });
  it("invalidates a pending switch when reselecting the displayed tab", async () => {
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    const fileASnapshot = snapshotFor(fileA, "AppEnforce line");
    setCachedTabSnapshot(fileA, fileASnapshot);
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: fileASnapshot.entries,
      activeSource: fileSourceA,
    });

    const parsed = deferred<ParseResult>();
    commands.openLogFile.mockReturnValueOnce(parsed.promise);

    const pendingSwitch = switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });
    await vi.waitFor(() => {
      expect(commands.openLogFile).toHaveBeenCalledWith(fileB);
    });

    await switchToTab(fileA, {
      sourceKind: "file",
      sourcePath: fileA,
      source: fileSourceA,
    });
    expect(useLogStore.getState().openFilePath).toBe(fileA);
    expect(useLogStore.getState().entries[0]?.message).toBe("AppEnforce line");

    parsed.resolve({
      ...parseResult,
      filePath: fileB,
      entries: [makeEntry(2, fileB, "CIAgent line")],
    });
    await pendingSwitch;

    expect(useLogStore.getState().openFilePath).toBe(fileA);
    expect(useLogStore.getState().entries[0]?.message).toBe("AppEnforce line");
    expect(useLogStore.getState().activeSource).toEqual(fileSourceA);
    expect(useLogStore.getState().isLoading).toBe(false);
  });
  it("invalidates a pending tab switch when opening a new source", async () => {
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    const staleResult = deferred<ParseResult>();
    const sourceResult: ParseResult = {
      ...parseResult,
      filePath: fileA,
      entries: [makeEntry(1, fileA, "AppEnforce line")],
    };

    commands.openLogFile.mockReturnValueOnce(staleResult.promise);
    commands.openLogSourceFile.mockResolvedValueOnce(sourceResult);

    const staleSwitch = switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });
    await vi.waitFor(() => {
      expect(commands.openLogFile).toHaveBeenCalledWith(fileB);
    });

    await loadLogSource(fileSourceA);

    staleResult.resolve({
      ...parseResult,
      filePath: fileB,
      entries: [makeEntry(2, fileB, "CIAgent line")],
    });
    await staleSwitch;

    expect(useLogStore.getState().openFilePath).toBe(fileA);
    expect(useLogStore.getState().entries[0]?.message).toBe("AppEnforce line");
    expect(useLogStore.getState().activeSource).toEqual(fileSourceA);
  });
  it("ignores stale loads from overlapping migrated-tab switches", async () => {
    const fileC = "C:/Windows/CCM/Logs/Start.log";
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      activeSource: fileSourceA,
      sourceEntries: folderEntries,
      bundleMetadata: evidenceBundleMetadata(),
    });

    const staleResult = deferred<ParseResult>();
    commands.openLogFile
      .mockReturnValueOnce(staleResult.promise)
      .mockResolvedValueOnce({
        ...parseResult,
        filePath: fileC,
        entries: [makeEntry(2, fileC, "Start line")],
      });

    const staleSwitch = switchToTab(fileB, null);
    await vi.waitFor(() => {
      expect(commands.openLogFile).toHaveBeenCalledWith(fileB);
    });

    await switchToTab(fileC, null);
    expect(useLogStore.getState().sourceEntries).toEqual([]);
    expect(useLogStore.getState().bundleMetadata).toBeNull();
    expect(useLogStore.getState().openFilePath).toBe(fileC);
    expect(useLogStore.getState().entries[0]?.message).toBe("Start line");

    staleResult.resolve({
      ...parseResult,
      filePath: fileB,
      entries: [makeEntry(2, fileB, "CIAgent line")],
    });
    await staleSwitch;

    expect(useLogStore.getState().openFilePath).toBe(fileC);
    expect(useLogStore.getState().entries[0]?.message).toBe("Start line");
    expect(useLogStore.getState().activeSource).toEqual({
      kind: "file",
      path: fileC,
    });
  });
});

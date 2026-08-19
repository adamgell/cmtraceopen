import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  FolderEntry,
  FolderListingResult,
  KnownSourceMetadata,
  LogEntry,
  LogSource,
  ParseResult,
} from "../types/log";
import type { EvidenceBundleMetadata } from "../types/evidence";
import type { RegistryParseResult } from "../types/registry";
import { useLogStore, setCachedTabSnapshot, clearAllTabSnapshots } from "../stores/log-store";
import type { TabEntrySnapshot } from "./tab-snapshot-cache";
import { useUiStore } from "../stores/ui-store";
import {
  loadFilesAsLogSource,
  loadLogSource,
  loadPathAsLogSource,
  loadSelectedLogFile,
  switchToTab,
} from "./log-source";

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

    expect(result).not.toBeNull();
    expect(result?.selectedFilePath).toBeNull();
    expect(commands.listLogSourceFolder).toHaveBeenCalledWith(deviceInventoryFolder);
    expect(commands.parseFilesBatch).toHaveBeenCalledWith(
      [folderEntries[0].path],
      expect.any(Number),
      expect.any(Number),
    );
    expect(commands.openLogSourceFile).not.toHaveBeenCalled();
  });

  it.each(deviceInventoryFiles)(
    "opens direct Device Inventory file source $sourceId",
    async (source) => {
      const result = await loadLogSource(source);

      expect(result).not.toBeNull();
      expect(result?.selectedFilePath).toBe(parseResult.filePath);
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


function deferred<T>() {
  let resolvePromise: ((value: T) => void) | undefined;
  let rejectPromise: ((reason?: unknown) => void) | undefined;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  return {
    promise,
    resolve(value: T) {
      if (!resolvePromise) {
        throw new Error("Deferred promise resolver was not initialized");
      }
      resolvePromise(value);
    },
    reject(reason: unknown) {
      if (!rejectPromise) {
        throw new Error("Deferred promise rejecter was not initialized");
      }
      rejectPromise(reason);
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
  it("returns null when a stale registry parse rejects", async () => {
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    const registryResult: ParseResult = {
      ...parseResult,
      filePath: fileA,
      parserSelection: {
        ...parseResult.parserSelection,
        parser: "registry",
        implementation: "registry",
      },
    };
    const parseError = new Error("registry fixture is unreadable");
    const pendingRegistry = deferred<RegistryParseResult>();
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    commands.openLogFile.mockResolvedValueOnce(registryResult);
    commands.parseRegistryFile.mockReturnValueOnce(pendingRegistry.promise);

    const pendingLoad = loadSelectedLogFile(fileA, fileSourceA);
    await vi.waitFor(() => {
      expect(commands.parseRegistryFile).toHaveBeenCalledWith(fileA);
    });

    await switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });
    pendingRegistry.reject(parseError);

    await expect(pendingLoad).resolves.toBeNull();
  });
  it("returns null when registry application becomes stale", async () => {
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    const registryResult: ParseResult = {
      ...parseResult,
      filePath: fileA,
      parserSelection: {
        ...parseResult.parserSelection,
        parser: "registry",
        implementation: "registry",
      },
    };
    const registryData: RegistryParseResult = {
      keys: [],
      filePath: fileA,
      fileSize: 1,
      totalKeys: 0,
      totalValues: 0,
      parseErrors: 0,
    };
    const pendingRegistry = deferred<RegistryParseResult>();
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    commands.openLogFile.mockResolvedValueOnce(registryResult);
    commands.parseRegistryFile.mockReturnValueOnce(pendingRegistry.promise);

    const pendingLoad = loadSelectedLogFile(fileA, fileSourceA);
    await vi.waitFor(() => {
      expect(commands.parseRegistryFile).toHaveBeenCalledWith(fileA);
    });

    await switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });
    pendingRegistry.resolve(registryData);

    await expect(pendingLoad).resolves.toBeNull();
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

    const listing = deferred<FolderListingResult>();
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
    const firstListing = deferred<FolderListingResult>();
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

    const staleListing = deferred<FolderListingResult>();
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

    const listing = deferred<FolderListingResult>();
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
  it("returns null when a selected-file load becomes stale", async () => {
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));

    const staleResult = deferred<ParseResult>();
    commands.openLogFile.mockReturnValueOnce(staleResult.promise);

    const pendingLoad = loadSelectedLogFile(fileA, fileSourceA);
    await vi.waitFor(() => {
      expect(commands.openLogFile).toHaveBeenCalledWith(fileA);
    });

    await switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });

    staleResult.resolve({
      ...parseResult,
      filePath: fileA,
      entries: [makeEntry(1, fileA, "AppEnforce line")],
    });

    await expect(pendingLoad).resolves.toBeNull();
    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().activeSource).toEqual(fileSourceB);
  });
  it("returns null when a stale selected-file load rejects", async () => {
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));

    const staleResult = deferred<ParseResult>();
    commands.openLogFile.mockReturnValueOnce(staleResult.promise);

    const pendingLoad = loadSelectedLogFile(fileA, fileSourceA);
    await vi.waitFor(() => {
      expect(commands.openLogFile).toHaveBeenCalledWith(fileA);
    });

    await switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });

    staleResult.reject(new Error("selected file failed"));

    await expect(pendingLoad).resolves.toBeNull();
    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().activeSource).toEqual(fileSourceB);
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
  it("clears stale folder progress when switching tabs", async () => {
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    useLogStore.setState({
      openFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      folderLoadProgress: 0.5,
    });

    await switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });

    expect(useLogStore.getState().folderLoadProgress).toBeNull();
  });
  it("ignores a stale source load after a later tab switch", async () => {
    const fileSourceA: LogSource = { kind: "file", path: fileA };
    const fileSourceB: LogSource = { kind: "file", path: fileB };
    const fileBSnapshot = snapshotFor(fileB, "CIAgent line");
    setCachedTabSnapshot(fileB, fileBSnapshot);
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      activeSource: fileSourceA,
    });

    const sourceResult = deferred<ParseResult>();
    commands.openLogSourceFile.mockReturnValueOnce(sourceResult.promise);

    const pendingLoad = loadLogSource(fileSourceA);
    await vi.waitFor(() => {
      expect(commands.openLogSourceFile).toHaveBeenCalledWith(fileSourceA);
    });

    await switchToTab(fileB, {
      sourceKind: "file",
      sourcePath: fileB,
      source: fileSourceB,
    });
    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().entries[0]?.message).toBe("CIAgent line");

    sourceResult.resolve({
      ...parseResult,
      filePath: fileA,
      entries: [makeEntry(1, fileA, "AppEnforce line")],
    });
    await expect(pendingLoad).resolves.toBeNull();

    expect(useLogStore.getState().openFilePath).toBe(fileB);
    expect(useLogStore.getState().entries[0]?.message).toBe("CIAgent line");
    expect(useLogStore.getState().activeSource).toEqual(fileSourceB);
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

describe("source loading progress ownership", () => {
  const folderSource: LogSource = { kind: "folder", path: "C:/Windows/CCM/Logs" };
  const sourceEntries: FolderEntry[] = [
    {
      name: "AppEnforce.log",
      path: "C:/Windows/CCM/Logs/AppEnforce.log",
      isDir: false,
      sizeBytes: 1,
      modifiedUnixMs: null,
    },
  ];

  beforeEach(() => {
    vi.resetAllMocks();
    useLogStore.getState().clear();
    useUiStore.getState().clearTabs();
    clearAllTabSnapshots();
    commands.stopTail.mockResolvedValue(undefined);
    commands.listLogSourceFolder.mockResolvedValue({
      sourceKind: "folder",
      source: folderSource,
      entries: sourceEntries,
      bundleMetadata: null,
    });
  });

  it("clears progress when a progressive source load fails", async () => {
    commands.parseFilesBatch.mockRejectedValueOnce(new Error("batch failed"));

    await expect(loadLogSource(folderSource)).rejects.toThrow("batch failed");

    expect(useLogStore.getState().folderLoadProgress).toBeNull();
    expect(useLogStore.getState().sourceStatus.kind).toBe("error");
  });
  it("returns null when selected-file recovery becomes stale", async () => {
    const selectedPath = sourceEntries[0].path;
    const currentPath = "C:/Windows/CCM/Logs/Current.log";
    const pendingOpenLogFile = deferred<ParseResult>();
    commands.openLogFile.mockReturnValueOnce(pendingOpenLogFile.promise);
    const staleLoad = loadLogSource(folderSource, {
      selectedFilePath: selectedPath,
    });
    await vi.waitFor(() => {
      expect(commands.openLogFile).toHaveBeenCalledWith(selectedPath);
    });

    commands.openLogSourceFile.mockResolvedValueOnce({
      ...parseResult,
      filePath: currentPath,
    });
    await loadLogSource({ kind: "file", path: currentPath });
    pendingOpenLogFile.reject(new Error("selected file failed"));

    await expect(staleLoad).resolves.toBeNull();
  });

  it("ignores a path probe superseded by a newer source load", async () => {
    useLogStore.setState({
      folderLoadProgress: 0.5,
      folderLoadRequestId: 123,
    });
    const pathKind = deferred<"file" | "folder" | "unknown">();
    commands.inspectPathKind.mockReturnValueOnce(pathKind.promise);
    const stalePathLoad = loadPathAsLogSource(
      "C:/Windows/CCM/Logs/Stale.log",
    );
    expect(useLogStore.getState().folderLoadProgress).toBeNull();
    expect(useLogStore.getState().folderLoadRequestId).toBeNull();
    await vi.waitFor(() => {
      expect(commands.inspectPathKind).toHaveBeenCalledWith(
        "C:/Windows/CCM/Logs/Stale.log",
      );
    });

    commands.openLogSourceFile.mockResolvedValueOnce({
      ...parseResult,
      filePath: "C:/Windows/CCM/Logs/Current.log",
    });
    await loadLogSource({
      kind: "file",
      path: "C:/Windows/CCM/Logs/Current.log",
    });

    pathKind.resolve("file");

    await expect(stalePathLoad).resolves.toBeNull();
    expect(commands.openLogSourceFile).toHaveBeenCalledTimes(1);
  });

  it("returns null when a progressive folder load is superseded", async () => {
    const pendingBatch = deferred<ParseResult[]>();
    commands.parseFilesBatch.mockReturnValueOnce(pendingBatch.promise);

    const staleFolderLoad = loadLogSource(folderSource);
    await vi.waitFor(() => {
      expect(commands.parseFilesBatch).toHaveBeenCalledWith(
        [sourceEntries[0].path],
        expect.any(Number),
        expect.any(Number),
      );
    });

    commands.openLogSourceFile.mockResolvedValueOnce({
      ...parseResult,
      filePath: "C:/Windows/CCM/Logs/Current.log",
    });
    await loadLogSource({
      kind: "file",
      path: "C:/Windows/CCM/Logs/Current.log",
    });

    pendingBatch.resolve([]);
    await expect(staleFolderLoad).resolves.toBeNull();
  });

  it("falls back to the folder lane after a current file load fails", async () => {
    commands.inspectPathKind.mockResolvedValue("file");
    commands.openLogSourceFile.mockRejectedValueOnce(new Error("is a directory"));
    commands.parseFilesBatch.mockResolvedValueOnce([]);

    const result = await loadPathAsLogSource("C:/Windows/CCM/Logs");

    expect(result?.source).toEqual(folderSource);
    expect(commands.listLogSourceFolder).toHaveBeenCalledWith(folderSource);
  });

  it("clears prior progress before starting a multi-file load", async () => {
    const stopTailRequest = deferred<void>();
    useLogStore.setState({
      openFilePath: "C:/Windows/CCM/Logs/Current.log",
      folderLoadProgress: 0.5,
    });
    commands.stopTail.mockReturnValueOnce(stopTailRequest.promise);
    commands.parseFilesBatch.mockResolvedValueOnce([]);

    const pendingLoad = loadFilesAsLogSource([
      "C:/Windows/CCM/Logs/AppEnforce.log",
      "C:/Windows/CCM/Logs/CIAgent.log",
    ]);
    await vi.waitFor(() => {
      expect(commands.stopTail).toHaveBeenCalledWith(
        "C:/Windows/CCM/Logs/Current.log",
      );
    });

    expect(useLogStore.getState().folderLoadProgress).toBeNull();

    stopTailRequest.resolve();
    await pendingLoad;
  });
});

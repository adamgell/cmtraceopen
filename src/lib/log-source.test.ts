import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  FolderEntry,
  KnownSourceMetadata,
  LogEntry,
  LogSource,
  ParseResult,
} from "../types/log";
import { useLogStore, setCachedTabSnapshot, clearAllTabSnapshots } from "../stores/log-store";
import type { TabEntrySnapshot } from "./tab-snapshot-cache";
import { useUiStore } from "../stores/ui-store";
import { loadLogSource, switchToTab } from "./log-source";

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
  });

  it("swaps the list to the cached file before folder restore finishes", async () => {
    setCachedTabSnapshot(fileA, snapshotFor(fileA, "AppEnforce line"));
    setCachedTabSnapshot(fileB, snapshotFor(fileB, "CIAgent line"));
    useLogStore.setState({
      openFilePath: fileA,
      selectedSourceFilePath: fileA,
      entries: snapshotFor(fileA, "AppEnforce line").entries,
      activeSource: { kind: "file", path: fileA },
    });

    let resolveListing!: (value: {
      sourceKind: "folder";
      source: LogSource;
      entries: FolderEntry[];
      bundleMetadata: null;
    }) => void;
    const listingPromise = new Promise<{
      sourceKind: "folder";
      source: LogSource;
      entries: FolderEntry[];
      bundleMetadata: null;
    }>((resolve) => {
      resolveListing = resolve;
    });
    commands.listLogSourceFolder.mockReturnValue(listingPromise);

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

    resolveListing({
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
    let resolveFirst!: (value: {
      sourceKind: "folder";
      source: LogSource;
      entries: FolderEntry[];
      bundleMetadata: null;
    }) => void;
    const firstListing = new Promise<{
      sourceKind: "folder";
      source: LogSource;
      entries: FolderEntry[];
      bundleMetadata: null;
    }>((resolve) => {
      resolveFirst = resolve;
    });
    commands.listLogSourceFolder.mockReturnValueOnce(firstListing);
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

    resolveFirst({
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

});

import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  FolderEntry,
  KnownSourceMetadata,
  LogSource,
  ParseResult,
} from "../types/log";
import { useLogStore } from "../stores/log-store";
import { loadLogSource } from "./log-source";

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

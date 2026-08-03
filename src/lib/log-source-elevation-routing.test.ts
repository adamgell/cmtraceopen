/**
 * Pins the two frontend halves of "a source failure must not become a UAC
 * prompt that cannot succeed".
 *
 * Both cases route into `loadLogSource`, which is the only place in the
 * application allowed to raise the elevation offer, so both belong here rather
 * than at their individual call sites.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  inspectPathKind,
  listLogSourceFolder,
  openLogFile,
  openLogSourceFile,
} from "./commands";
import { offerElevationForSourceFailure } from "./elevation-recovery";
import { loadPathAsLogSource, loadLogSource } from "./log-source";
import { recordAccessDenied } from "./source-error";
import { useLogStore } from "../stores/log-store";
import type { ParseResult } from "../types/log";

vi.mock("./commands", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./commands")>();
  return {
    ...actual,
    inspectPathKind: vi.fn(),
    listLogSourceFolder: vi.fn(),
    openLogFile: vi.fn(),
    openLogSourceFile: vi.fn(),
  };
});

vi.mock("./elevation-recovery", () => ({
  offerElevationForSourceFailure: vi.fn().mockResolvedValue(true),
}));

const inspectPathKindMock = vi.mocked(inspectPathKind);
const listLogSourceFolderMock = vi.mocked(listLogSourceFolder);
const openLogFileMock = vi.mocked(openLogFile);
const openLogSourceFileMock = vi.mocked(openLogSourceFile);
const offerElevationMock = vi.mocked(offerElevationForSourceFailure);

const FOLDER_PATH = "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs";

const parsedFile: ParseResult = {
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
  filePath: "C:\\logs\\a.log",
  fileSize: 0,
  byteOffset: 0,
};

function deniedError(path: string): Error {
  const error = new Error("Access to this file was denied by the operating system.");
  recordAccessDenied(error, {
    kind: "accessDenied",
    operation: "readFile",
    path,
    message: "Access to this file was denied by the operating system.",
  });
  return error;
}

describe("path lane selection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useLogStore.getState().clear();
    listLogSourceFolderMock.mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: FOLDER_PATH },
      entries: [],
      bundleMetadata: null,
    });
  });

  it("sends a directory down the folder lane instead of the file lane", async () => {
    // The file lane ends at `open_log_file`. On Windows a directory opened
    // without FILE_FLAG_BACKUP_SEMANTICS fails with ERROR_ACCESS_DENIED, so a
    // dropped folder raised "Restart as administrator?" and the elevated retry
    // re-attempted the same folder as a file. Establishing the kind first is
    // what removes the loop.
    inspectPathKindMock.mockResolvedValue("folder");

    await loadPathAsLogSource(FOLDER_PATH);

    expect(openLogSourceFileMock).not.toHaveBeenCalled();
    expect(listLogSourceFolderMock).toHaveBeenCalledWith({
      kind: "folder",
      path: FOLDER_PATH,
    });
  });

  it("still opens a file through the file lane", async () => {
    inspectPathKindMock.mockResolvedValue("file");
    openLogSourceFileMock.mockResolvedValue(parsedFile);

    await loadPathAsLogSource("C:\\logs\\a.log");

    expect(openLogSourceFileMock).toHaveBeenCalled();
    expect(listLogSourceFolderMock).not.toHaveBeenCalled();
  });

  it("stays optimistic about the file lane when the kind cannot be determined", async () => {
    // An unreadable parent, a race, or a probe failure must not turn a file
    // open into a folder listing: unknown keeps today's behaviour.
    inspectPathKindMock.mockResolvedValue("unknown");
    openLogSourceFileMock.mockResolvedValue({
      ...parsedFile,
      filePath: "C:\\logs\\b.log",
    });

    await loadPathAsLogSource("C:\\logs\\b.log");

    expect(openLogSourceFileMock).toHaveBeenCalled();
    expect(listLogSourceFolderMock).not.toHaveBeenCalled();
  });

  it("does not widen an explicit file-only retry into a folder source", async () => {
    inspectPathKindMock.mockResolvedValue("folder");
    openLogSourceFileMock.mockResolvedValue(parsedFile);

    await loadPathAsLogSource(FOLDER_PATH, { fallbackToFolder: false });

    expect(openLogSourceFileMock).toHaveBeenCalled();
    expect(listLogSourceFolderMock).not.toHaveBeenCalled();
  });
});

describe("selected file recovery inside a folder source", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useLogStore.getState().clear();
    listLogSourceFolderMock.mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: FOLDER_PATH },
      entries: [
        {
          name: "AgentExecutor.log",
          path: `${FOLDER_PATH}\\AgentExecutor.log`,
          isDir: false,
          sizeBytes: 10,
          modifiedUnixMs: 0,
        },
      ],
      bundleMetadata: null,
    });
  });

  it("keeps the Access Denied verdict when the selected file is refused", async () => {
    // The folder listing succeeded, so the failure is recovered rather than
    // rethrown. That recovery used to drop the verdict on the floor, which left
    // a protected file reported as a generic load failure with no way to
    // elevate — the same misreport the folder lane was fixed for.
    const selected = `${FOLDER_PATH}\\AgentExecutor.log`;
    openLogFileMock.mockRejectedValue(deniedError(selected));

    await loadLogSource(
      { kind: "folder", path: FOLDER_PATH },
      { selectedFilePath: selected },
    );

    expect(offerElevationMock).toHaveBeenCalled();

    const status = useLogStore.getState().sourceStatus;
    expect(`${status?.message ?? ""} ${status?.detail ?? ""}`).toMatch(/denied/i);
  });

  it("does not offer elevation when the selected file merely fails to parse", async () => {
    openLogFileMock.mockRejectedValue(new Error("unsupported format"));

    await loadLogSource(
      { kind: "folder", path: FOLDER_PATH },
      { selectedFilePath: `${FOLDER_PATH}\\AgentExecutor.log` },
    );

    expect(offerElevationMock).not.toHaveBeenCalled();
  });
});

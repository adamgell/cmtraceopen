import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  getInitialElevationRestore,
  getInitialFilePaths,
  getInitialWorkspace,
} from "../lib/commands";
import { markElevationRetryAttempted } from "../lib/elevation";
import {
  getKnownSourceMetadataById,
  loadFilesAsLogSource,
  loadLogSource,
  loadPathAsLogSource,
} from "../lib/log-source";
import { useUiStore } from "../stores/ui-store";
import type { RestoreTicket } from "../types/elevation";
import { useFileAssociation } from "./use-file-association";

vi.mock("../lib/commands", () => ({
  getInitialElevationRestore: vi.fn(),
  getInitialFilePaths: vi.fn(),
  getInitialWorkspace: vi.fn(),
}));

vi.mock("../lib/elevation", () => ({
  markElevationRetryAttempted: vi.fn(),
}));

vi.mock("../lib/log-source", () => ({
  getKnownSourceMetadataById: vi.fn(),
  loadFilesAsLogSource: vi.fn(),
  loadLogSource: vi.fn(),
  loadPathAsLogSource: vi.fn(),
}));

const getInitialElevationRestoreMock = vi.mocked(getInitialElevationRestore);
const getInitialFilePathsMock = vi.mocked(getInitialFilePaths);
const getInitialWorkspaceMock = vi.mocked(getInitialWorkspace);
const markElevationRetryAttemptedMock = vi.mocked(markElevationRetryAttempted);
const getKnownSourceMetadataByIdMock = vi.mocked(getKnownSourceMetadataById);
const loadFilesAsLogSourceMock = vi.mocked(loadFilesAsLogSource);
const loadLogSourceMock = vi.mocked(loadLogSource);
const loadPathAsLogSourceMock = vi.mocked(loadPathAsLogSource);

function ticket(overrides: Partial<RestoreTicket> = {}): RestoreTicket {
  return {
    schemaVersion: 1,
    ticketId: "1487dc30-3bb0-46bf-98ee-76771bd9953e",
    createdAtMs: 1_760_000_000_000,
    originPid: 1234,
    workspace: "log",
    target: { kind: "workspace" },
    reason: "accessDenied",
    retryAttempted: true,
    ...overrides,
  };
}

describe("useFileAssociation startup routing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
      enabledWorkspaces: null,
    });
    getInitialFilePathsMock.mockResolvedValue([]);
    getInitialWorkspaceMock.mockResolvedValue(null);
    getInitialElevationRestoreMock.mockResolvedValue(null);
    loadPathAsLogSourceMock.mockImplementation(async (path) => ({
      source: { kind: "file", path },
      entries: [],
      selectedFilePath: null,
      parseResult: null,
    }));
    loadFilesAsLogSourceMock.mockResolvedValue(undefined);
  });

  it("opens ESP Diagnostics when the elevated launch requests its workspace", async () => {
    getInitialWorkspaceMock.mockResolvedValue("esp-diagnostics");

    renderHook(() => useFileAssociation());

    await waitFor(() => expect(getInitialWorkspaceMock).toHaveBeenCalledOnce());
    expect(useUiStore.getState().activeView).toBe("esp-diagnostics");
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
  });

  it("gives an explicit file-open request precedence over the workspace flag", async () => {
    getInitialWorkspaceMock.mockResolvedValue("esp-diagnostics");
    getInitialFilePathsMock.mockResolvedValue(["C:\\Logs\\ime.log"]);

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(loadPathAsLogSourceMock).toHaveBeenCalledWith(
        "C:\\Logs\\ime.log",
        { fallbackToFolder: false },
      ),
    );
    expect(useUiStore.getState().activeView).toBe("log");
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
  });

  it("gives an explicit file-open request precedence over a restore ticket", async () => {
    getInitialFilePathsMock.mockResolvedValue(["C:\\Logs\\ime.log"]);
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "file", path: "C:\\Windows\\protected.log" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(loadPathAsLogSourceMock).toHaveBeenCalledWith(
        "C:\\Logs\\ime.log",
        { fallbackToFolder: false },
      ),
    );
    expect(loadPathAsLogSourceMock).toHaveBeenCalledOnce();
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalledWith(
      "C:\\Windows\\protected.log",
      expect.anything(),
    );

    // The ticket lost the precedence contest, so no restore was attempted.
    // Latching the loop guard here would suppress legitimate elevation offers
    // for the rest of the session over a retry that never ran.
    expect(markElevationRetryAttemptedMock).not.toHaveBeenCalled();
  });

  it("restores only the workspace a workspace-only ticket names", async () => {
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ workspace: "esp-diagnostics" }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(useUiStore.getState().activeView).toBe("esp-diagnostics"),
    );
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
    expect(loadLogSourceMock).not.toHaveBeenCalled();
  });

  it("reopens the exact file a ticket names, without folder fallback", async () => {
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "file", path: "C:\\Windows\\protected.log" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(loadPathAsLogSourceMock).toHaveBeenCalledWith(
        "C:\\Windows\\protected.log",
        { fallbackToFolder: false },
      ),
    );
  });

  it("restores a source ticket into the workspace that asked for elevation", async () => {
    // An Access Denied raised inside ESP carries that workspace alongside the
    // file that failed. Forcing the log view would reopen the right source on
    // the wrong screen.
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({
        workspace: "esp-diagnostics",
        target: { kind: "file", path: "C:\\Windows\\protected.log" },
      }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(loadPathAsLogSourceMock).toHaveBeenCalledWith(
        "C:\\Windows\\protected.log",
        { fallbackToFolder: false },
      ),
    );
    expect(useUiStore.getState().activeView).toBe("esp-diagnostics");
  });

  it("reopens a folder ticket through the folder source path", async () => {
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "folder", path: "C:\\Windows\\Logs" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(loadPathAsLogSourceMock).toHaveBeenCalledWith(
        "C:\\Windows\\Logs",
        { fallbackToFolder: true },
      ),
    );
  });

  it("resolves a known source by id rather than a persisted path", async () => {
    const source = { kind: "folder" as const, path: "C:\\Windows\\CCM\\Logs" };
    getKnownSourceMetadataByIdMock.mockResolvedValue({
      id: "ccm-client-logs",
      label: "ConfigMgr Client Logs",
      description: "",
      platform: "windows",
      sourceKind: "folder",
      source,
      filePatterns: [],
    });
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "knownSource", sourceId: "ccm-client-logs" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() => expect(loadLogSourceMock).toHaveBeenCalledWith(source));
    expect(getKnownSourceMetadataByIdMock).toHaveBeenCalledWith(
      "ccm-client-logs",
    );
  });

  it("degrades to a warning when a restored known source no longer exists", async () => {
    getKnownSourceMetadataByIdMock.mockResolvedValue(null);
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "knownSource", sourceId: "retired-source" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(getKnownSourceMetadataByIdMock).toHaveBeenCalledOnce(),
    );
    expect(loadLogSourceMock).not.toHaveBeenCalled();
  });

  it("marks the retry so a second denial cannot start an elevation loop", async () => {
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "file", path: "C:\\Windows\\protected.log" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(markElevationRetryAttemptedMock).toHaveBeenCalledOnce(),
    );
  });

  it("starts normally when the restore ticket cannot be read", async () => {
    getInitialElevationRestoreMock.mockRejectedValue(new Error("no state dir"));
    getInitialWorkspaceMock.mockResolvedValue("esp-diagnostics");

    renderHook(() => useFileAssociation());

    // The unreadable ticket is ignored and the workspace flag still applies.
    await waitFor(() =>
      expect(useUiStore.getState().activeView).toBe("esp-diagnostics"),
    );
    expect(markElevationRetryAttemptedMock).not.toHaveBeenCalled();
  });

  it("does not restore anything when there is no ticket", async () => {
    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(getInitialElevationRestoreMock).toHaveBeenCalledOnce(),
    );
    expect(markElevationRetryAttemptedMock).not.toHaveBeenCalled();
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
    expect(loadLogSourceMock).not.toHaveBeenCalled();
  });
});

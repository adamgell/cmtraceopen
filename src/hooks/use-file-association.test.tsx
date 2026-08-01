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
import type { WorkspaceId } from "../types/log";
import { useFileAssociation } from "./use-file-association";

const { workspaceOpenSourceMock } = vi.hoisted(() => ({
  workspaceOpenSourceMock: vi.fn(),
}));

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

vi.mock("../workspaces/registry", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../workspaces/registry")>();
  return {
    ...actual,
    getWorkspace: (id: WorkspaceId) => {
      const workspace = actual.getWorkspace(id);
      return id === "intune" || id === "esp-diagnostics"
        ? { ...workspace, onOpenSource: workspaceOpenSourceMock }
        : workspace;
    },
  };
});

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

  it("routes a non-ESP workspace when a cross-account ticket cannot be read", async () => {
    getInitialWorkspaceMock.mockResolvedValue("intune");
    // The backend converts an unreadable or other-account ticket into absence;
    // the closed workspace argv fallback remains available independently.
    getInitialElevationRestoreMock.mockResolvedValue(null);

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(useUiStore.getState().activeView).toBe("intune"),
    );
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

  it("reopens the exact typed file a ticket names", async () => {
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "file", path: "C:\\Windows\\protected.log" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(loadLogSourceMock).toHaveBeenCalledWith({
        kind: "file",
        path: "C:\\Windows\\protected.log",
      }),
    );
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
  });

  it("restores a source through the workspace that asked for elevation", async () => {
    // An Access Denied raised inside ESP carries that workspace alongside the
    // file that failed. Forcing the log view would reopen the right source on
    // the wrong screen.
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({
        workspace: "esp-diagnostics",
        target: { kind: "file", path: "C:\\Windows\\protected.zip" },
      }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(workspaceOpenSourceMock).toHaveBeenCalledWith(
        { kind: "file", path: "C:\\Windows\\protected.zip" },
        "startup.elevation-restore",
      ),
    );
    expect(useUiStore.getState().activeView).toBe("esp-diagnostics");
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
  });

  it("reruns an Intune source through its analysis handler after elevation", async () => {
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({
        workspace: "intune",
        target: {
          kind: "file",
          path: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
        },
      }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(workspaceOpenSourceMock).toHaveBeenCalledWith(
        {
          kind: "file",
          path: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
        },
        "startup.elevation-restore",
      ),
    );
    expect(useUiStore.getState().activeView).toBe("intune");
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
  });

  it("does not replay a source in a different workspace when the requested one is unavailable", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
      enabledWorkspaces: ["log"],
    });
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({
        workspace: "intune",
        target: {
          kind: "file",
          path: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
        },
      }),
    );

    renderHook(() => useFileAssociation());

    try {
      await waitFor(() =>
        expect(warn).toHaveBeenCalledWith(
          "[elevation] requested workspace is unavailable; source restore skipped",
          { workspace: "intune" },
        ),
      );
      expect(useUiStore.getState().activeView).toBe("log");
      expect(workspaceOpenSourceMock).not.toHaveBeenCalled();
      expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
      expect(loadLogSourceMock).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("does not load hidden generic log state for a workspace without a source handler", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    useUiStore.setState({ currentPlatform: "windows" });
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({
        workspace: "event-log",
        target: { kind: "file", path: "C:\\Windows\\protected.evtx" },
      }),
    );

    renderHook(() => useFileAssociation());

    try {
      await waitFor(() =>
        expect(warn).toHaveBeenCalledWith(
          "[elevation] requested workspace cannot restore sources; source restore skipped",
          { workspace: "event-log" },
        ),
      );
      expect(useUiStore.getState().activeView).toBe("event-log");
      expect(workspaceOpenSourceMock).not.toHaveBeenCalled();
      expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
      expect(loadLogSourceMock).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("reopens the exact typed folder a ticket names", async () => {
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "folder", path: "C:\\Windows\\Logs" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(loadLogSourceMock).toHaveBeenCalledWith({
        kind: "folder",
        path: "C:\\Windows\\Logs",
      }),
    );
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
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

  it("reasserts the requested workspace after asynchronous source resolution", async () => {
    const source = { kind: "file" as const, path: "C:\\Windows\\protected.log" };
    let resolveMetadata!: (
      value: Awaited<ReturnType<typeof getKnownSourceMetadataById>>,
    ) => void;
    getKnownSourceMetadataByIdMock.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveMetadata = resolve;
        }),
    );
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({ target: { kind: "knownSource", sourceId: "protected-log" } }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(getKnownSourceMetadataByIdMock).toHaveBeenCalledOnce(),
    );
    useUiStore.getState().setActiveWorkspace("intune");
    resolveMetadata({
      id: "protected-log",
      label: "Protected synthetic log",
      description: "",
      platform: "windows",
      sourceKind: "file",
      source,
      filePatterns: [],
    });

    await waitFor(() => expect(loadLogSourceMock).toHaveBeenCalledWith(source));
    expect(useUiStore.getState().activeView).toBe("log");
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

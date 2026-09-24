import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  getInitialElevationRestore,
  getInitialFilePaths,
  getInitialWorkspace,
  takeSecondLaunchPaths,
} from "../lib/commands";
import { markElevationRetryAttempted } from "../lib/elevation";
import {
  getKnownSourceMetadataById,
  loadFilesAsLogSource,
  loadLogSource,
  loadPathAsLogSource,
} from "../lib/log-source";
import { useUiStore } from "../stores/ui-store";
import { deferred } from "../test-utils/deferred";
import type { RestoreTicket } from "../types/elevation";
import type { WorkspaceId } from "../types/log";
import { useFileAssociation } from "./use-file-association";

const {
  workspaceOpenSourceMock,
  openPathForActiveWorkspaceMock,
  eventListenMock,
} = vi.hoisted(() => ({
  workspaceOpenSourceMock: vi.fn(),
  openPathForActiveWorkspaceMock: vi.fn(),
  eventListenMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: eventListenMock,
}));

vi.mock("./use-app-actions", () => ({
  useAppActions: () => ({
    openPathForActiveWorkspace: openPathForActiveWorkspaceMock,
  }),
}));

vi.mock("../lib/commands", () => ({
  getInitialElevationRestore: vi.fn(),
  getInitialFilePaths: vi.fn(),
  getInitialWorkspace: vi.fn(),
  takeSecondLaunchPaths: vi.fn(),
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
      return id === "intune" || id === "esp-diagnostics" || id === "event-log"
        ? { ...workspace, onOpenSource: workspaceOpenSourceMock }
        : workspace;
    },
  };
});

const getInitialElevationRestoreMock = vi.mocked(getInitialElevationRestore);
const getInitialFilePathsMock = vi.mocked(getInitialFilePaths);
const getInitialWorkspaceMock = vi.mocked(getInitialWorkspace);
const takeSecondLaunchPathsMock = vi.mocked(takeSecondLaunchPaths);
const markElevationRetryAttemptedMock = vi.mocked(markElevationRetryAttempted);
const getKnownSourceMetadataByIdMock = vi.mocked(getKnownSourceMetadataById);
const loadFilesAsLogSourceMock = vi.mocked(loadFilesAsLogSource);
const loadLogSourceMock = vi.mocked(loadLogSource);
const loadPathAsLogSourceMock = vi.mocked(loadPathAsLogSource);

/** Handler the second-launch event registered, if one was registered at all. */
type BackendEventHandler = (event: { payload: unknown }) => void;
let secondLaunchHandler: BackendEventHandler | null = null;

/**
 * Wakes the hook the way the backend does after a second launch.
 *
 * The announcement carries no paths: it says that a launch handed paths over,
 * and the window claims them. Registration is asynchronous, so a test must wait
 * for the handler; this fails with that contract instead of tripping over a null
 * handler at the delivery site.
 */
function announceSecondLaunch(): void {
  if (secondLaunchHandler === null) {
    throw new Error(
      "nothing is registered for the second-launch event, so the announcement was not delivered",
    );
  }

  secondLaunchHandler({ payload: null });
}

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

describe("useFileAssociation launch intent routing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    secondLaunchHandler = null;
    eventListenMock.mockImplementation(
      (eventName: string, handler: BackendEventHandler) => {
        if (eventName === "second-launch-open") {
          secondLaunchHandler = handler;
        }
        return Promise.resolve(() => {});
      },
    );
    openPathForActiveWorkspaceMock.mockResolvedValue(undefined);
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
      enabledWorkspaces: null,
    });
    getInitialFilePathsMock.mockResolvedValue([]);
    getInitialWorkspaceMock.mockResolvedValue(null);
    getInitialElevationRestoreMock.mockResolvedValue(null);
    // Reset rather than clear: these tests queue one response per claim, and
    // clearAllMocks keeps a leftover queue that would answer the next test's
    // first claim.
    takeSecondLaunchPathsMock.mockReset();
    takeSecondLaunchPathsMock.mockResolvedValue([]);
    loadPathAsLogSourceMock.mockImplementation(async (path) => ({
      source: { kind: "file", path },
      entries: [],
      selectedFilePath: null,
      parseResult: null,
    }));
    loadFilesAsLogSourceMock.mockResolvedValue(true);
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

  it("restores an Event Log source through the workspace handler", async () => {
    useUiStore.setState({ currentPlatform: "windows" });
    getInitialElevationRestoreMock.mockResolvedValue(
      ticket({
        workspace: "event-log",
        target: { kind: "file", path: "C:\\Windows\\protected.evtx" },
      }),
    );

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(workspaceOpenSourceMock).toHaveBeenCalledWith(
        { kind: "file", path: "C:\\Windows\\protected.evtx" },
        "startup.elevation-restore",
      ),
    );
    expect(useUiStore.getState().activeView).toBe("event-log");
    expect(loadPathAsLogSourceMock).not.toHaveBeenCalled();
    expect(loadLogSourceMock).not.toHaveBeenCalled();
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

  it("opens the path a second launch handed over when the window is woken", async () => {
    const forwarded = "C:\\Windows\\CCM\\Logs\\ccmexec.log";
    takeSecondLaunchPathsMock
      .mockResolvedValueOnce([]) // what is waiting when the window mounts
      .mockResolvedValueOnce([forwarded]); // what the announcement wakes

    renderHook(() => useFileAssociation());
    await waitFor(() =>
      expect(takeSecondLaunchPathsMock).toHaveBeenCalledOnce(),
    );

    // The announcement carries no paths; it is what makes the window claim them.
    expect(eventListenMock).toHaveBeenCalledWith(
      "second-launch-open",
      expect.any(Function),
    );
    announceSecondLaunch();

    await waitFor(() =>
      expect(openPathForActiveWorkspaceMock).toHaveBeenCalledWith(
        forwarded,
        "second-launch.path-open",
      ),
    );
    expect(openPathForActiveWorkspaceMock).toHaveBeenCalledOnce();
    // Startup retrieval is untouched by a forwarded launch.
    expect(getInitialFilePathsMock).toHaveBeenCalledOnce();
  });

  it("opens a path handed over before the window was listening, and only once", async () => {
    const forwarded = "C:\\Windows\\CCM\\Logs\\ime.log";
    const registration = deferred<() => void>();
    eventListenMock.mockImplementation(
      (eventName: string, handler: BackendEventHandler) => {
        if (eventName === "second-launch-open") {
          secondLaunchHandler = handler;
        }
        return registration.promise;
      },
    );
    takeSecondLaunchPathsMock
      .mockResolvedValueOnce([forwarded]) // handed over before the window listened
      .mockResolvedValue([]);

    renderHook(() => useFileAssociation());
    await waitFor(() => expect(eventListenMock).toHaveBeenCalledOnce());

    // The claim waits for registration to land, so nothing is opened into a
    // window that is not listening yet...
    expect(takeSecondLaunchPathsMock).not.toHaveBeenCalled();

    registration.resolve(() => {});

    await waitFor(() =>
      expect(openPathForActiveWorkspaceMock).toHaveBeenCalledOnce(),
    );
    expect(openPathForActiveWorkspaceMock).toHaveBeenCalledWith(
      forwarded,
      "second-launch.path-open",
    );

    // ...and the announcement that follows does not replay what was claimed.
    announceSecondLaunch();
    await waitFor(() =>
      expect(takeSecondLaunchPathsMock).toHaveBeenCalledTimes(2),
    );
    expect(openPathForActiveWorkspaceMock).toHaveBeenCalledOnce();
  });

  it("opens forwarded paths one at a time so none is superseded", async () => {
    const order: string[] = [];
    let inFlight = 0;
    let peakInFlight = 0;
    openPathForActiveWorkspaceMock.mockImplementation(async (path: string) => {
      inFlight += 1;
      peakInFlight = Math.max(peakInFlight, inFlight);
      // A real open awaits IPC, and a superseded open is dropped rather than
      // queued, so the second path must not start before the first finishes.
      await Promise.resolve();
      order.push(path);
      inFlight -= 1;
    });
    takeSecondLaunchPathsMock.mockResolvedValueOnce([
      "C:\\Windows\\CCM\\Logs\\ccmexec.log",
      "C:\\Windows\\CCM\\Logs\\InventoryAgent.log",
    ]);

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(openPathForActiveWorkspaceMock).toHaveBeenCalledTimes(2),
    );
    expect(peakInFlight).toBe(1);
    expect(order).toEqual([
      "C:\\Windows\\CCM\\Logs\\ccmexec.log",
      "C:\\Windows\\CCM\\Logs\\InventoryAgent.log",
    ]);
  });

  it("opens both paths when two launches arrive back to back", async () => {
    const order: string[] = [];
    let inFlight = 0;
    let peakInFlight = 0;
    openPathForActiveWorkspaceMock.mockImplementation(async (path: string) => {
      inFlight += 1;
      peakInFlight = Math.max(peakInFlight, inFlight);
      // A real open awaits IPC, so overlapping launches would overlap here.
      await Promise.resolve();
      order.push(path);
      inFlight -= 1;
    });
    takeSecondLaunchPathsMock
      .mockResolvedValueOnce([]) // the mount claim
      .mockResolvedValueOnce(["C:\\Logs\\first.log"])
      .mockResolvedValueOnce(["C:\\Logs\\second.log"]);

    renderHook(() => useFileAssociation());
    await waitFor(() =>
      expect(takeSecondLaunchPathsMock).toHaveBeenCalledOnce(),
    );

    announceSecondLaunch();
    announceSecondLaunch();

    await waitFor(() =>
      expect(openPathForActiveWorkspaceMock).toHaveBeenCalledTimes(2),
    );
    // The second launch is a second open, not a replacement: both files open,
    // in arrival order, one at a time.
    expect(order).toEqual(["C:\\Logs\\first.log", "C:\\Logs\\second.log"]);
    expect(peakInFlight).toBe(1);
  });

  it("holds a forwarded launch behind a startup open that is still in flight", async () => {
    const order: string[] = [];
    let inFlight = 0;
    let peakInFlight = 0;
    const startupOpen = deferred<void>();

    getInitialFilePathsMock.mockResolvedValue(["C:\\Logs\\startup.log"]);
    loadPathAsLogSourceMock.mockImplementation(async (path: string) => {
      inFlight += 1;
      peakInFlight = Math.max(peakInFlight, inFlight);
      await startupOpen.promise;
      order.push(path);
      inFlight -= 1;
      return {
        source: { kind: "file", path },
        entries: [],
        selectedFilePath: null,
        parseResult: null,
      };
    });
    openPathForActiveWorkspaceMock.mockImplementation(async (path: string) => {
      inFlight += 1;
      peakInFlight = Math.max(peakInFlight, inFlight);
      await Promise.resolve();
      order.push(path);
      inFlight -= 1;
    });
    takeSecondLaunchPathsMock
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce(["C:\\Logs\\forwarded.log"]);

    renderHook(() => useFileAssociation());
    await waitFor(() =>
      expect(loadPathAsLogSourceMock).toHaveBeenCalledOnce(),
    );

    // The startup launch's file is still parsing when the second launch lands.
    announceSecondLaunch();
    // Drain everything already scheduled. The startup slot is held until its
    // file is open, so the forwarded claim has not even been made yet.
    const drained = deferred<void>();
    setTimeout(() => drained.resolve(), 0);
    await drained.promise;

    expect(takeSecondLaunchPathsMock).not.toHaveBeenCalled();
    expect(openPathForActiveWorkspaceMock).not.toHaveBeenCalled();

    startupOpen.resolve();

    await waitFor(() =>
      expect(openPathForActiveWorkspaceMock).toHaveBeenCalledOnce(),
    );
    // Both files are opened, the startup one first: the forwarded launch waits
    // for the open already in flight instead of superseding it.
    expect(order).toEqual(["C:\\Logs\\startup.log", "C:\\Logs\\forwarded.log"]);
    expect(peakInFlight).toBe(1);
  });

  it("reserves the startup slot before a forwarded launch can take it", async () => {
    const order: string[] = [];
    const startupReads = deferred<string[]>();
    const startupOpen = deferred<void>();

    // The startup launch's reads are still in flight when the second launch
    // arrives: the forwarded open must not start ahead of the startup open.
    getInitialFilePathsMock.mockReturnValue(startupReads.promise);
    loadPathAsLogSourceMock.mockImplementation(async (path: string) => {
      await startupOpen.promise;
      order.push(path);
      return {
        source: { kind: "file", path },
        entries: [],
        selectedFilePath: null,
        parseResult: null,
      };
    });
    openPathForActiveWorkspaceMock.mockImplementation(async (path: string) => {
      order.push(path);
    });
    takeSecondLaunchPathsMock
      .mockResolvedValueOnce([]) // what is waiting when the window mounts
      .mockResolvedValueOnce(["C:\\Logs\\forwarded.log"]);

    renderHook(() => useFileAssociation());
    await waitFor(() => expect(eventListenMock).toHaveBeenCalledOnce());

    announceSecondLaunch();
    // Drain everything scheduled while the reads are pending: the forwarded
    // launch has to wait for the startup slot, not run beside it.
    const drained = deferred<void>();
    setTimeout(() => drained.resolve(), 0);
    await drained.promise;

    expect(takeSecondLaunchPathsMock).not.toHaveBeenCalled();
    expect(openPathForActiveWorkspaceMock).not.toHaveBeenCalled();

    startupReads.resolve(["C:\\Logs\\startup.log"]);
    await waitFor(() =>
      expect(loadPathAsLogSourceMock).toHaveBeenCalledOnce(),
    );
    startupOpen.resolve();

    await waitFor(() =>
      expect(openPathForActiveWorkspaceMock).toHaveBeenCalledOnce(),
    );
    // Startup opens first, and the forwarded launch follows it rather than
    // being superseded by it.
    expect(order).toEqual(["C:\\Logs\\startup.log", "C:\\Logs\\forwarded.log"]);
  });

  it("still opens the next launch when a claim fails", async () => {
    const failed = vi.spyOn(console, "error").mockImplementation(() => undefined);
    takeSecondLaunchPathsMock
      .mockRejectedValueOnce(new Error("ipc unavailable"))
      .mockResolvedValueOnce(["C:\\Logs\\later.log"]);

    renderHook(() => useFileAssociation());

    await waitFor(() =>
      expect(failed).toHaveBeenCalledWith(
        "[file-association] failed to claim a forwarded launch",
        { error: expect.any(Error) },
      ),
    );

    try {
      // The paths are still waiting in the handoff, so the next announcement
      // opens them rather than the failure stalling the window.
      announceSecondLaunch();

      await waitFor(() =>
        expect(openPathForActiveWorkspaceMock).toHaveBeenCalledWith(
          "C:\\Logs\\later.log",
          "second-launch.path-open",
        ),
      );
    } finally {
      failed.mockRestore();
    }
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  offerElevationForSourceFailure,
  resetElevationRecoveryForTests,
} from "./elevation-recovery";
import { recordAccessDenied } from "./source-error";
import {
  markElevationRetryAttempted,
  readElevationState,
  resetElevationCoordinatorForTests,
} from "./elevation";
import { useUiStore } from "../stores/ui-store";

vi.mock("./elevation", async () => {
  const actual = await vi.importActual<typeof import("./elevation")>("./elevation");
  return { ...actual, readElevationState: vi.fn() };
});

const readElevationStateMock = vi.mocked(readElevationState);

/** A rejection carrying a confirmed backend Access Denied verdict. */
function accessDeniedError(path = "C:\\Windows\\Logs\\CBS.log"): Error {
  const error = new Error("Access to this file was denied by Windows.");
  recordAccessDenied(error, {
    kind: "accessDenied",
    operation: "readFile",
    path,
    message: "Access to this file was denied by Windows.",
  });
  return error;
}

describe("offerElevationForSourceFailure", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetElevationRecoveryForTests();
    resetElevationCoordinatorForTests();
    useUiStore.getState().setElevationPrompt(null);
    useUiStore.setState({ activeWorkspace: "log" });
    readElevationStateMock.mockResolvedValue({
      platformSupported: true,
      isElevated: false,
    });
  });

  it("pins the workspace that failed, not the one switched to mid-probe", async () => {
    useUiStore.setState({ activeWorkspace: "intune" });
    // The probe is an IPC round trip. Switching workspaces while it is in
    // flight must not repoint the restore at whatever is on screen when it
    // answers: the denied source belonged to Intune, whose handler reopens it.
    readElevationStateMock.mockImplementation(async () => {
      useUiStore.setState({ activeWorkspace: "log" });
      return { platformSupported: true, isElevated: false };
    });

    await expect(
      offerElevationForSourceFailure({
        error: accessDeniedError(),
        source: { kind: "file", path: "C:\\Windows\\Logs\\CBS.log" },
      }),
    ).resolves.toBe(true);

    expect(useUiStore.getState().elevationPrompt?.request.workspace).toBe("intune");
  });

  describe("the workspace the ticket names", () => {
    const FILE = "C:\\Windows\\CCM\\Logs\\AppEnforce.log";
    const FOLDER = "C:\\Windows\\CCM\\Logs";

    it.each([
      ["file", { kind: "file", path: FILE }],
      ["folder", { kind: "folder", path: FOLDER }],
    ] as const)(
      "names the Log workspace for a denied %s load from Event Logs, whose handler would open EVTX",
      async (_label, source) => {
        useUiStore.setState({ activeWorkspace: "event-log" });
        expect(useUiStore.getState().activeWorkspace).toBe("event-log");

        await expect(
          offerElevationForSourceFailure({ error: accessDeniedError(), source }),
        ).resolves.toBe(true);

        expect(useUiStore.getState().elevationPrompt?.request).toEqual({
          reason: "accessDenied",
          workspace: "log",
          target:
            source.kind === "file"
              ? { kind: "file", path: FILE }
              : { kind: "folder", path: FOLDER },
        });
      },
    );

    it.each(["log", "intune", "new-intune"] as const)(
      "keeps the %s ticket for a denied file",
      async (workspace) => {
        useUiStore.setState({ activeWorkspace: workspace });

        await offerElevationForSourceFailure({
          error: accessDeniedError(),
          source: { kind: "file", path: FILE },
        });

        expect(useUiStore.getState().elevationPrompt?.request.workspace).toBe(workspace);
      },
    );

    it.each(["intune", "new-intune"] as const)(
      "names the Log workspace for a denied folder in %s, whose handler only analyzes a folder",
      async (workspace) => {
        useUiStore.setState({ activeWorkspace: workspace });

        await offerElevationForSourceFailure({
          error: accessDeniedError(),
          source: { kind: "folder", path: FOLDER },
        });

        expect(useUiStore.getState().elevationPrompt?.request).toEqual({
          reason: "accessDenied",
          workspace: "log",
          target: { kind: "folder", path: FOLDER },
        });
      },
    );

    it.each(["macos-jamf", "macos-diag", "sccm"] as const)(
      "names the Log workspace for a denied file in %s, which has no handler to reopen it (SCCM is not even in the backend's list)",
      async (workspace) => {
        useUiStore.setState({ activeWorkspace: workspace });

        await offerElevationForSourceFailure({
          error: accessDeniedError(),
          source: { kind: "file", path: FILE },
        });

        expect(useUiStore.getState().elevationPrompt?.request.workspace).toBe("log");
      },
    );
  });

  it("offers elevation for a confirmed Access Denied", async () => {
    await expect(
      offerElevationForSourceFailure({
        error: accessDeniedError(),
        source: { kind: "file", path: "C:\\Windows\\Logs\\CBS.log" },
      }),
    ).resolves.toBe(true);

    expect(useUiStore.getState().elevationPrompt?.request).toEqual({
      reason: "accessDenied",
      workspace: "log",
      target: { kind: "file", path: "C:\\Windows\\Logs\\CBS.log" },
    });
  });

  it("restores the source that failed, not the currently selected one", async () => {
    await offerElevationForSourceFailure({
      error: accessDeniedError(),
      source: { kind: "folder", path: "C:\\ProgramData\\Logs" },
    });

    expect(useUiStore.getState().elevationPrompt?.request.target).toEqual({
      kind: "folder",
      path: "C:\\ProgramData\\Logs",
    });
  });

  it("does not offer elevation for a missing file", async () => {
    // No recorded verdict: this is what an ENOENT rejection looks like.
    const error = new Error("Source path is missing: os error 2");

    await expect(
      offerElevationForSourceFailure({ error }),
    ).resolves.toBe(false);
    expect(useUiStore.getState().elevationPrompt).toBeNull();
  });

  it("does not offer elevation for a parse failure", async () => {
    const error = new Error("Parse error in CBS.log: unexpected token");

    await expect(
      offerElevationForSourceFailure({ error }),
    ).resolves.toBe(false);
    expect(useUiStore.getState().elevationPrompt).toBeNull();
  });

  it("is not fooled by an error that merely mentions permission denied", async () => {
    // The old regex would have matched this. Without a backend verdict it must
    // not produce a UAC offer.
    const error = new Error("upstream service replied: permission denied");

    await expect(
      offerElevationForSourceFailure({ error }),
    ).resolves.toBe(false);
    expect(useUiStore.getState().elevationPrompt).toBeNull();
  });

  it("does not offer elevation on an unsupported platform", async () => {
    readElevationStateMock.mockResolvedValue({
      platformSupported: false,
      isElevated: false,
    });

    await expect(
      offerElevationForSourceFailure({ error: accessDeniedError() }),
    ).resolves.toBe(false);
    expect(useUiStore.getState().elevationPrompt).toBeNull();
  });

  it("does not offer elevation when already running elevated", async () => {
    readElevationStateMock.mockResolvedValue({
      platformSupported: true,
      isElevated: true,
    });

    await expect(
      offerElevationForSourceFailure({ error: accessDeniedError() }),
    ).resolves.toBe(false);
  });

  it("cannot loop: a restored retry that fails again makes no second offer", async () => {
    markElevationRetryAttempted();

    await expect(
      offerElevationForSourceFailure({ error: accessDeniedError() }),
    ).resolves.toBe(false);
    expect(useUiStore.getState().elevationPrompt).toBeNull();
  });

  it("asks once when many files in one folder load fail together", async () => {
    const results = await Promise.all([
      offerElevationForSourceFailure({ error: accessDeniedError("a.log") }),
      offerElevationForSourceFailure({ error: accessDeniedError("b.log") }),
      offerElevationForSourceFailure({ error: accessDeniedError("c.log") }),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("does not stack a second prompt on an open confirmation", async () => {
    await offerElevationForSourceFailure({ error: accessDeniedError() });
    const first = useUiStore.getState().elevationPrompt;

    await expect(
      offerElevationForSourceFailure({ error: accessDeniedError("other.log") }),
    ).resolves.toBe(false);
    expect(useUiStore.getState().elevationPrompt).toBe(first);
  });

  it("returns false instead of throwing when the elevation probe fails", async () => {
    readElevationStateMock.mockRejectedValue(new Error("probe exploded"));

    await expect(
      offerElevationForSourceFailure({ error: accessDeniedError() }),
    ).resolves.toBe(false);
  });
});

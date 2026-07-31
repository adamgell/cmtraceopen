import { beforeEach, describe, expect, it, vi } from "vitest";
import { getSourceAccessDenial } from "./commands";
import {
  markElevationRetryAttempted,
  readElevationState,
  requestElevatedRestart,
  resetElevationCoordinatorForTests,
} from "./elevation";
import {
  evaluateRecovery,
  recoveryPrompt,
  runRecovery,
} from "./elevation-recovery";
import { useUiStore } from "../stores/ui-store";
import type { SourceAccessDenied } from "../types/elevation";

vi.mock("./commands", () => ({
  getSourceAccessDenial: vi.fn(),
}));

vi.mock("./elevation", async () => {
  const actual =
    await vi.importActual<typeof import("./elevation")>("./elevation");
  return {
    ...actual,
    readElevationState: vi.fn(),
    requestElevatedRestart: vi.fn(),
  };
});

const getSourceAccessDenialMock = vi.mocked(getSourceAccessDenial);
const readElevationStateMock = vi.mocked(readElevationState);
const requestElevatedRestartMock = vi.mocked(requestElevatedRestart);

function denial(
  overrides: Partial<SourceAccessDenied> = {},
): SourceAccessDenied {
  return {
    kind: "accessDenied",
    operation: "readFile",
    context: { kind: "path", path: "C:\\Windows\\CCM\\Logs\\ccmexec.log" },
    message: "CMTrace Open does not have permission to read this file.",
    ...overrides,
  };
}

describe("access denied recovery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetElevationCoordinatorForTests();
    useUiStore.setState({ activeWorkspace: "log", activeView: "log" });
    readElevationStateMock.mockResolvedValue({
      platformSupported: true,
      isElevated: false,
    });
  });

  it("offers recovery for a confirmed access-denied classification", async () => {
    getSourceAccessDenialMock.mockReturnValue(denial());

    const offer = await evaluateRecovery(new Error("boom"));

    expect(offer.kind).toBe("offer");
  });

  it("does not offer recovery for an unclassified failure", async () => {
    // A missing file, a parse error, and a timeout all arrive here as plain
    // errors with no classification. Elevation would not fix any of them.
    getSourceAccessDenialMock.mockReturnValue(null);

    expect(await evaluateRecovery(new Error("file not found"))).toEqual({
      kind: "none",
    });
    expect(await evaluateRecovery(new Error("unexpected end of file"))).toEqual({
      kind: "none",
    });
    expect(await evaluateRecovery("Access is denied")).toEqual({
      kind: "none",
    });
  });

  it("does not offer recovery when already elevated", async () => {
    getSourceAccessDenialMock.mockReturnValue(denial());
    readElevationStateMock.mockResolvedValue({
      platformSupported: true,
      isElevated: true,
    });

    expect(await evaluateRecovery(new Error("boom"))).toEqual({ kind: "none" });
  });

  it("does not offer recovery on a platform without UAC", async () => {
    getSourceAccessDenialMock.mockReturnValue(denial());
    readElevationStateMock.mockResolvedValue({
      platformSupported: false,
      isElevated: false,
    });

    expect(await evaluateRecovery(new Error("boom"))).toEqual({ kind: "none" });
  });

  it("does not offer recovery once a restored retry already failed", async () => {
    getSourceAccessDenialMock.mockReturnValue(denial());

    expect((await evaluateRecovery(new Error("boom"))).kind).toBe("offer");

    markElevationRetryAttempted();

    // The loop guard: the restored source is still denied, so the user gets
    // troubleshooting rather than a second UAC prompt.
    expect(await evaluateRecovery(new Error("boom"))).toEqual({ kind: "none" });
  });

  it("names the exact failed source in the prompt", () => {
    const prompt = recoveryPrompt(denial());

    expect(prompt).toContain("permission to read this file");
    expect(prompt).toContain("ccmexec.log");
    expect(prompt).toContain(
      "Other tabs, filters, and searches are not restored.",
    );
  });

  it("retries a folder denial as a folder, not a file", async () => {
    requestElevatedRestartMock.mockResolvedValue({ status: "launched" });

    await runRecovery(
      denial({
        operation: "listFolder",
        context: { kind: "path", path: "C:\\Windows\\CCM\\Logs" },
      }),
      async () => true,
    );

    expect(requestElevatedRestartMock).toHaveBeenCalledWith({
      reason: "accessDenied",
      workspace: "log",
      target: { kind: "folder", path: "C:\\Windows\\CCM\\Logs", aggregate: true },
    });
  });

  it("retries a known source by id rather than a path", async () => {
    requestElevatedRestartMock.mockResolvedValue({ status: "launched" });

    await runRecovery(
      denial({
        operation: "openKnownSource",
        context: { kind: "knownSource", sourceId: "ccm-client-logs" },
      }),
      async () => true,
    );

    expect(requestElevatedRestartMock).toHaveBeenCalledWith(
      expect.objectContaining({
        target: { kind: "knownSource", sourceId: "ccm-client-logs" },
      }),
    );
  });

  it("retries the exact failed source, not the active tab", async () => {
    requestElevatedRestartMock.mockResolvedValue({ status: "launched" });

    await runRecovery(denial(), async () => true);

    expect(requestElevatedRestartMock).toHaveBeenCalledWith(
      expect.objectContaining({
        target: {
          kind: "file",
          path: "C:\\Windows\\CCM\\Logs\\ccmexec.log",
        },
      }),
    );
  });

  it("requests no elevation when the user declines", async () => {
    const outcome = await runRecovery(denial(), async () => false);

    expect(outcome).toEqual({ status: "declined" });
    expect(requestElevatedRestartMock).not.toHaveBeenCalled();
  });

  it("falls back to a workspace restore when no context was supplied", async () => {
    requestElevatedRestartMock.mockResolvedValue({ status: "launched" });

    await runRecovery(
      denial({ operation: "workspaceAction", context: undefined }),
      async () => true,
    );

    expect(requestElevatedRestartMock).toHaveBeenCalledWith(
      expect.objectContaining({ target: { kind: "workspace" } }),
    );
  });
});

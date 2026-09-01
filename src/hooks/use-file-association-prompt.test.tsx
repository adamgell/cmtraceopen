import { act, cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getFileAssociationPromptStatus } from "../lib/commands";
import { useUiStore } from "../stores/ui-store";
import { useFileAssociationPrompt } from "./use-file-association-prompt";

vi.mock("../lib/commands", () => ({
  getFileAssociationPromptStatus: vi.fn(),
}));

describe("useFileAssociationPrompt", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
    useUiStore.setState(useUiStore.getInitialState(), true);
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  it("queues an eligible startup prompt until the active user dialog closes", async () => {
    vi.mocked(getFileAssociationPromptStatus).mockResolvedValue({
      supported: true,
      shouldPrompt: true,
      isRegistered: false,
    });
    useUiStore.getState().setShowAboutDialog(true);
    renderHook(() => useFileAssociationPrompt());

    await act(async () => {
      vi.advanceTimersByTime(350);
      await Promise.resolve();
    });

    expect(getFileAssociationPromptStatus).toHaveBeenCalledTimes(1);
    expect(useUiStore.getState().showAboutDialog).toBe(true);
    expect(useUiStore.getState().showFileAssociationPrompt).toBe(true);
    expect(useUiStore.getState().modalOwner).toBe("about");
    expect(useUiStore.getState().modalQueue).toEqual(["fileAssociationPrompt"]);

    await act(async () => {
      useUiStore.getState().setShowAboutDialog(false);
      await Promise.resolve();
    });

    expect(useUiStore.getState().showFileAssociationPrompt).toBe(true);
    expect(useUiStore.getState().modalOwner).toBe("fileAssociationPrompt");
    expect(getFileAssociationPromptStatus).toHaveBeenCalledTimes(1);
  });

  it("preserves an eligible prompt behind elevation and collection results", async () => {
    vi.mocked(getFileAssociationPromptStatus).mockResolvedValue({
      supported: true,
      shouldPrompt: true,
      isRegistered: false,
    });
    useUiStore.getState().setElevationPrompt({
      request: {
        reason: "explicitMenu",
        workspace: "log",
        target: { kind: "workspace" },
      },
    });
    useUiStore.getState().setCollectionResult({
      bundlePath: "C:/Temp/diagnostics.zip",
      bundleId: "startup-collection",
      artifactCounts: { collected: 4, missing: 0, failed: 0, total: 4 },
      durationMs: 100,
      gaps: [],
    });

    renderHook(() => useFileAssociationPrompt());

    await act(async () => {
      vi.advanceTimersByTime(350);
      await Promise.resolve();
    });

    expect(useUiStore.getState().modalOwner).toBe("elevationPrompt");
    expect(useUiStore.getState().modalQueue).toEqual([
      "collectionResult",
      "fileAssociationPrompt",
    ]);
    expect(useUiStore.getState().showFileAssociationPrompt).toBe(true);

    act(() => {
      useUiStore.getState().setElevationPrompt(null);
    });
    expect(useUiStore.getState().modalOwner).toBe("collectionResult");

    act(() => {
      useUiStore.getState().setCollectionResult(null);
    });
    expect(useUiStore.getState().modalOwner).toBe("fileAssociationPrompt");
  });

  it("does not reopen an Ask Later prompt after another modal opens and closes", async () => {
    vi.mocked(getFileAssociationPromptStatus).mockResolvedValue({
      supported: true,
      shouldPrompt: true,
      isRegistered: false,
    });
    renderHook(() => useFileAssociationPrompt());

    await act(async () => {
      vi.advanceTimersByTime(350);
      await Promise.resolve();
    });
    expect(useUiStore.getState().showFileAssociationPrompt).toBe(true);

    await act(async () => {
      useUiStore.getState().setShowFileAssociationPrompt(false);
      useUiStore.getState().setShowSettingsDialog(true);
      await Promise.resolve();
    });
    await act(async () => {
      useUiStore.getState().setShowSettingsDialog(false);
      await Promise.resolve();
    });

    expect(useUiStore.getState().showFileAssociationPrompt).toBe(false);
    expect(getFileAssociationPromptStatus).toHaveBeenCalledTimes(1);
  });
});

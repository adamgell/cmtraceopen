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

  it("defers an eligible startup prompt until the active user dialog closes", async () => {
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
    expect(useUiStore.getState().showFileAssociationPrompt).toBe(false);

    await act(async () => {
      useUiStore.getState().setShowAboutDialog(false);
      await Promise.resolve();
    });

    expect(useUiStore.getState().showFileAssociationPrompt).toBe(true);
    expect(getFileAssociationPromptStatus).toHaveBeenCalledTimes(1);
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

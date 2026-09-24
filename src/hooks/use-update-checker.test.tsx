import { act, renderHook } from "@testing-library/react";
import { getVersion } from "@tauri-apps/api/app";
import { platform } from "@tauri-apps/plugin-os";
import { check } from "@tauri-apps/plugin-updater";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getFileAssociationPromptStatus,
  getUpdatePolicy,
} from "../lib/commands";
import { useUiStore } from "../stores/ui-store";
import { useFileAssociationPrompt } from "./use-file-association-prompt";
import { useUpdateChecker } from "./use-update-checker";

vi.mock("@tauri-apps/api/app", () => ({
  getVersion: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-os", () => ({
  platform: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-process", () => ({
  relaunch: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-updater", () => ({
  check: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  getFileAssociationPromptStatus: vi.fn(),
  getUpdatePolicy: vi.fn(),
}));

const checkMock = vi.mocked(check);
const getFileAssociationPromptStatusMock = vi.mocked(
  getFileAssociationPromptStatus,
);
const getUpdatePolicyMock = vi.mocked(getUpdatePolicy);
const getVersionMock = vi.mocked(getVersion);
const platformMock = vi.mocked(platform);

describe("useUpdateChecker", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    useUiStore.setState({
      autoUpdateEnabled: false,
      showUpdateDialog: false,
    });
    checkMock.mockResolvedValue(null);
    getUpdatePolicyMock.mockResolvedValue({
      updateChecksDisabledByPolicy: false,
    });
    getVersionMock.mockResolvedValue("1.3.1");
    platformMock.mockResolvedValue("windows");
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not call the updater when policy disables manual checks", async () => {
    getUpdatePolicyMock.mockResolvedValue({
      updateChecksDisabledByPolicy: true,
    });

    const { result } = renderHook(() => useUpdateChecker());
    const info = await act(async () => result.current.checkForUpdates());

    expect(checkMock).not.toHaveBeenCalled();
    expect(info).toEqual({
      available: false,
      currentVersion: "1.3.1",
      updateChannel: "stable",
      canAutoUpdate: true,
      error: "Update checks are disabled by policy.",
    });
  });

  it("marks nightly update checks and opens the nightly release page", async () => {
    const openMock = vi.fn(() => ({ opener: null }));
    vi.stubGlobal("open", openMock);
    getVersionMock.mockResolvedValue("1.3.2-nightly.20260514.42.gabc123def456");
    checkMock.mockResolvedValue({
      version: "1.3.2-nightly.20260515.43.gdef456abc123",
      body: "Nightly build",
      downloadAndInstall: vi.fn(),
    } as never);

    const { result } = renderHook(() => useUpdateChecker());
    const info = await act(async () => result.current.checkForUpdates());

    expect(info?.updateChannel).toBe("nightly");

    act(() => {
      result.current.openReleasePage();
    });

    expect(openMock).toHaveBeenCalledWith(
      "https://github.com/adamgell/cmtraceopen/releases/tag/nightly",
      "_blank",
      "noopener,noreferrer"
    );
  });

  it("does not lose the association prompt when the startup update arrives later", async () => {
    vi.useFakeTimers();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ autoUpdateEnabled: true });
    getFileAssociationPromptStatusMock.mockResolvedValue({
      supported: true,
      shouldPrompt: true,
      isRegistered: false,
    });
    checkMock.mockResolvedValue({
      version: "1.3.2",
      body: "Stable update",
      downloadAndInstall: vi.fn(),
    } as never);

    renderHook(() => {
      useFileAssociationPrompt();
      return useUpdateChecker();
    });

    await act(async () => {
      await vi.advanceTimersByTimeAsync(350);
    });

    expect(useUiStore.getState().showFileAssociationPrompt).toBe(true);
    expect(useUiStore.getState().modalOwner).toBe("fileAssociationPrompt");

    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_650);
    });

    const queued = useUiStore.getState();
    expect(queued.showFileAssociationPrompt).toBe(true);
    expect(queued.showUpdateDialog).toBe(true);
    expect(queued.modalOwner).toBe("fileAssociationPrompt");
    expect(queued.modalQueue).toEqual(["update"]);

    act(() => {
      useUiStore.getState().setShowFileAssociationPrompt(false);
    });

    expect(useUiStore.getState().modalOwner).toBe("update");
  });
});

import { act, renderHook } from "@testing-library/react";
import { getVersion } from "@tauri-apps/api/app";
import { platform } from "@tauri-apps/plugin-os";
import { check } from "@tauri-apps/plugin-updater";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getUpdatePolicy } from "../lib/commands";
import { useUiStore } from "../stores/ui-store";
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
  getUpdatePolicy: vi.fn(),
}));

const checkMock = vi.mocked(check);
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
});

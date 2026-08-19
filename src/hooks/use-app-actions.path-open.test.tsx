import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../stores/ui-store";

const analyzeDsregcmdPath = vi.hoisted(() => vi.fn());
const recordRecentPath = vi.hoisted(() => vi.fn());
const inspectPathKind = vi.hoisted(() => vi.fn());
const openEventLogSource = vi.hoisted(() => vi.fn());
const setLoadError = vi.hoisted(() => vi.fn());

vi.mock("../lib/dsregcmd-source", () => ({
  analyzeDsregcmdPath,
  analyzeDsregcmdSource: vi.fn(),
  refreshCurrentDsregcmdSource: vi.fn(),
}));

vi.mock("../lib/recent-entries", () => ({
  recordRecentPath,
  recordRecentSource: vi.fn(),
}));

vi.mock("../lib/commands", () => ({
  inspectPathKind,
}));

vi.mock("../workspaces/event-log/open-event-log-source", () => ({
  openEventLogSource,
}));
vi.mock("../workspaces/event-log/evtx-store", () => ({
  useEvtxStore: {
    getState: () => ({ setLoadError }),
  },
}));

import { useAppActions } from "./use-app-actions";

describe("openPathForActiveWorkspace dsregcmd", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    analyzeDsregcmdPath.mockResolvedValue({});
    recordRecentPath.mockResolvedValue(undefined);
    inspectPathKind.mockRejectedValue(new Error("inspect failed"));
    useUiStore.setState({
      activeWorkspace: "dsregcmd",
      activeView: "dsregcmd",
      currentPlatform: "windows",
      enabledWorkspaces: null,
    });
  });

  it("retries an uninspectable drop as a folder and records Recent", async () => {
    const { result } = renderHook(() => useAppActions());
    await result.current.openPathForActiveWorkspace("C:/Evidence/dsregcmd");

    expect(analyzeDsregcmdPath).toHaveBeenCalledWith("C:/Evidence/dsregcmd", {
      fallbackToFolder: true,
    });
    expect(recordRecentPath).toHaveBeenCalledWith("C:/Evidence/dsregcmd", "dsregcmd");
  });
});

describe("openPathForActiveWorkspace event-log", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    inspectPathKind.mockRejectedValue(new Error("inspect failed"));
    openEventLogSource
      .mockRejectedValueOnce(new Error("not a file"))
      .mockResolvedValueOnce(undefined);
    useUiStore.setState({
      activeWorkspace: "event-log",
      activeView: "event-log",
      currentPlatform: "windows",
      enabledWorkspaces: null,
    });
  });

  it("retries an uninspectable drop as a folder after a file open fails", async () => {
    const { result } = renderHook(() => useAppActions());
    await result.current.openPathForActiveWorkspace("C:/Windows/System32/winevt/Logs");

    expect(openEventLogSource).toHaveBeenNthCalledWith(1, {
      kind: "file",
      path: "C:/Windows/System32/winevt/Logs",
    });
    expect(openEventLogSource).toHaveBeenNthCalledWith(2, {
      kind: "folder",
      path: "C:/Windows/System32/winevt/Logs",
    });
    expect(setLoadError).toHaveBeenCalledWith("not a file");
  });
});

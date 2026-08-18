import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../stores/ui-store";

const analyzeDsregcmdPath = vi.hoisted(() => vi.fn());
const recordRecentPath = vi.hoisted(() => vi.fn());
const inspectPathKind = vi.hoisted(() => vi.fn());

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

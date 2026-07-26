import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getInitialFilePaths, getInitialWorkspace } from "../lib/commands";
import { loadFilesAsLogSource, loadPathAsLogSource } from "../lib/log-source";
import { useUiStore } from "../stores/ui-store";
import { useFileAssociation } from "./use-file-association";

vi.mock("../lib/commands", () => ({
  getInitialFilePaths: vi.fn(),
  getInitialWorkspace: vi.fn(),
}));

vi.mock("../lib/log-source", () => ({
  loadFilesAsLogSource: vi.fn(),
  loadPathAsLogSource: vi.fn(),
}));

const getInitialFilePathsMock = vi.mocked(getInitialFilePaths);
const getInitialWorkspaceMock = vi.mocked(getInitialWorkspace);
const loadFilesAsLogSourceMock = vi.mocked(loadFilesAsLogSource);
const loadPathAsLogSourceMock = vi.mocked(loadPathAsLogSource);

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
});

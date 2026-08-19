import { renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../stores/ui-store";
import { useDragDrop } from "./use-drag-drop";

const {
  openPathForActiveWorkspaceMock,
  loadFilesAsLogSourceMock,
  onDragDropEventMock,
} = vi.hoisted(() => ({
  openPathForActiveWorkspaceMock: vi.fn(),
  loadFilesAsLogSourceMock: vi.fn(),
  onDragDropEventMock: vi.fn(),
}));

vi.mock("@tauri-apps/api/webviewWindow", () => ({
  getCurrentWebviewWindow: () => ({
    onDragDropEvent: onDragDropEventMock,
  }),
}));

vi.mock("./use-app-actions", () => ({
  useAppActions: () => ({
    openPathForActiveWorkspace: openPathForActiveWorkspaceMock,
  }),
}));

vi.mock("../lib/log-source", () => ({
  loadFilesAsLogSource: loadFilesAsLogSourceMock,
}));

// Static imports are safe: app actions and log-source are mocked above.

type DropHandler = (event: {
  payload: { type: string; paths: string[] };
}) => Promise<void> | void;

function latestHandler(): DropHandler {
  const calls = onDragDropEventMock.mock.calls;
  const handler = calls[calls.length - 1]?.[0] as DropHandler | undefined;
  if (!handler) {
    throw new Error("onDragDropEvent was not registered");
  }
  return handler;
}

describe("useDragDrop", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    onDragDropEventMock.mockResolvedValue(() => undefined);
    openPathForActiveWorkspaceMock.mockResolvedValue(undefined);
    loadFilesAsLogSourceMock.mockResolvedValue(undefined);
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
    });
  });

  it("opens a single dropped path on the active workspace", async () => {
    renderHook(() => useDragDrop());

    await latestHandler()({
      payload: { type: "drop", paths: ["/tmp/AppSetup.log"] },
    });

    expect(openPathForActiveWorkspaceMock).toHaveBeenCalledWith("/tmp/AppSetup.log");
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
  });

  it("loads multiple dropped paths as a log source in the log workspace", async () => {
    renderHook(() => useDragDrop());

    await latestHandler()({
      payload: {
        type: "drop",
        paths: ["/tmp/a.log", "/tmp/b.log"],
      },
    });

    expect(loadFilesAsLogSourceMock).toHaveBeenCalledWith([
      "/tmp/a.log",
      "/tmp/b.log",
    ]);
    expect(openPathForActiveWorkspaceMock).not.toHaveBeenCalled();
  });

  it("opens only the first path for multi-file drops outside the log workspace", async () => {
    useUiStore.setState({
      activeWorkspace: "intune",
      activeView: "intune",
    });
    renderHook(() => useDragDrop());

    await latestHandler()({
      payload: {
        type: "drop",
        paths: ["/tmp/ime.log", "/tmp/agentexecutor.log"],
      },
    });

    expect(openPathForActiveWorkspaceMock).toHaveBeenCalledWith("/tmp/ime.log");
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
  });

  it("routes every timeline drop through the active workspace opener", async () => {
    useUiStore.setState({
      activeWorkspace: "timeline",
      activeView: "timeline",
    });
    renderHook(() => useDragDrop());

    await latestHandler()({
      payload: {
        type: "drop",
        paths: ["/tmp/ime.log", "/tmp/empty-folder"],
      },
    });

    expect(openPathForActiveWorkspaceMock).toHaveBeenNthCalledWith(
      1,
      "/tmp/ime.log",
    );
    expect(openPathForActiveWorkspaceMock).toHaveBeenNthCalledWith(
      2,
      "/tmp/empty-folder",
    );
    expect(openPathForActiveWorkspaceMock).toHaveBeenCalledTimes(2);
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
  });
  it("continues opening timeline drops after one path fails", async () => {
    useUiStore.setState({
      activeWorkspace: "timeline",
      activeView: "timeline",
    });
    openPathForActiveWorkspaceMock
      .mockRejectedValueOnce(new Error("unreadable"))
      .mockResolvedValue(undefined);
    renderHook(() => useDragDrop());

    await latestHandler()({
      payload: {
        type: "drop",
        paths: ["/tmp/unreadable.log", "/tmp/readable.log"],
      },
    });

    expect(openPathForActiveWorkspaceMock).toHaveBeenNthCalledWith(
      1,
      "/tmp/unreadable.log",
    );
    expect(openPathForActiveWorkspaceMock).toHaveBeenNthCalledWith(
      2,
      "/tmp/readable.log",
    );
  });

  it("ignores non-drop drag events and empty path lists", async () => {
    renderHook(() => useDragDrop());
    const handler = latestHandler();

    await handler({ payload: { type: "enter", paths: ["/tmp/a.log"] } });
    await handler({ payload: { type: "drop", paths: [] } });

    expect(openPathForActiveWorkspaceMock).not.toHaveBeenCalled();
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
  });
});

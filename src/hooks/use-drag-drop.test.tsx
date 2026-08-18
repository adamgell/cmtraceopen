import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useTimelineStore } from "../stores/timeline-store";
import { useUiStore } from "../stores/ui-store";
import { useDragDrop } from "./use-drag-drop";

const {
  openPathForActiveWorkspaceMock,
  loadFilesAsLogSourceMock,
  buildTimelineFromSourcesMock,
  onDragDropEventMock,
} = vi.hoisted(() => ({
  openPathForActiveWorkspaceMock: vi.fn(),
  loadFilesAsLogSourceMock: vi.fn(),
  buildTimelineFromSourcesMock: vi.fn(),
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

vi.mock("../components/timeline/hooks/useTimelineBundle", () => ({
  buildTimelineFromSources: buildTimelineFromSourcesMock,
}));

// Static import is safe: use-app-actions, log-source, and timeline bundle are mocked above.

type DropHandler = (event: {
  payload: { type: string; paths: string[] };
}) => Promise<void> | void;

function latestHandler(): DropHandler {
  const handler = onDragDropEventMock.mock.calls.at(-1)?.[0] as DropHandler | undefined;
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
    buildTimelineFromSourcesMock.mockResolvedValue(undefined);
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
    });
    useTimelineStore.getState().reset();
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

  it("unions dropped paths into the timeline workspace", async () => {
    useUiStore.setState({
      activeWorkspace: "timeline",
      activeView: "timeline",
    });
    useTimelineStore.getState().setBundle({
      sources: [{ path: "/tmp/existing.log" }],
    } as never);
    renderHook(() => useDragDrop());

    await latestHandler()({
      payload: {
        type: "drop",
        paths: ["/tmp/existing.log", "/tmp/new.log"],
      },
    });

    await waitFor(() => {
      expect(buildTimelineFromSourcesMock).toHaveBeenCalledWith([
        { path: "/tmp/existing.log" },
        { path: "/tmp/new.log" },
      ]);
    });
    expect(openPathForActiveWorkspaceMock).not.toHaveBeenCalled();
    expect(loadFilesAsLogSourceMock).not.toHaveBeenCalled();
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

import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useLogStore } from "../stores/log-store";
import { useParseProgressListener } from "./use-parse-progress-listener";

const eventMocks = vi.hoisted(() => ({
  listener: null as ((event: { payload: unknown }) => void) | null,
  unlisten: vi.fn(),
  listen: vi.fn(
    async (
      _event: string,
      listener: (event: { payload: unknown }) => void,
    ) => {
      eventMocks.listener = listener;
      return eventMocks.unlisten;
    },
  ),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: eventMocks.listen,
}));

interface ProgressFixture {
  requestId: number;
  filePath: string;
  fileName: string;
  completed: number;
  total: number;
  globalCompleted: number;
  entries: number;
  fileSize: number;
  parseMs: number;
}

function progress(overrides: Partial<ProgressFixture> = {}): ProgressFixture {
  return {
    requestId: 7,
    filePath: "C:/Logs/App.log",
    fileName: "App.log",
    completed: 1,
    total: 3,
    globalCompleted: 1,
    entries: 2,
    fileSize: 100,
    parseMs: 4,
    ...overrides,
  };
}

function activateProgress(requestId = 7, total = 3): void {
  useLogStore.setState({
    folderLoadRequestId: requestId,
    folderLoadProgress: 0,
    folderLoadTotalFiles: total,
    folderLoadCompletedFiles: 0,
    folderLoadCurrentFile: "",
  });
}

describe("useParseProgressListener", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    eventMocks.listener = null;
    useLogStore.getState().clear();
  });

  afterEach(() => cleanup());

  it("updates active progress from a valid event", async () => {
    activateProgress();
    renderHook(() => useParseProgressListener());
    await waitFor(() => expect(eventMocks.listener).not.toBeNull());

    act(() => {
      eventMocks.listener?.({
        payload: progress({ completed: 2, globalCompleted: 2 }),
      });
    });

    const state = useLogStore.getState();
    expect(state.folderLoadProgress).toBeCloseTo(2 / 3);
    expect(state.folderLoadCompletedFiles).toBe(2);
    expect(state.folderLoadCurrentFile).toBe("App.log");
  });

  it("ignores malformed, inactive, mismatched, and out-of-range events", async () => {
    activateProgress();
    renderHook(() => useParseProgressListener());
    await waitFor(() => expect(eventMocks.listener).not.toBeNull());

    const malformed: unknown[] = [
      null,
      "not an object",
      { ...progress(), completed: Number.NaN },
      { ...progress(), fileName: 42 },
      { ...progress(), total: 0 },
      { ...progress(), globalCompleted: 4 },
      { ...progress(), requestId: 8 },
    ];
    for (const payload of malformed) {
      act(() => {
        eventMocks.listener?.({ payload });
      });
    }

    expect(useLogStore.getState().folderLoadCompletedFiles).toBe(0);
    expect(useLogStore.getState().folderLoadCurrentFile).toBe("");
    expect(useLogStore.getState().folderLoadProgress).toBe(0);

    act(() => {
      useLogStore.getState().setFolderLoadProgress(null);
      eventMocks.listener?.({ payload: progress() });
    });
    expect(useLogStore.getState().folderLoadCompletedFiles).toBeNull();
    expect(useLogStore.getState().folderLoadProgress).toBeNull();
  });

  it("keeps progress monotonic when Rayon events arrive out of order", async () => {
    activateProgress();
    renderHook(() => useParseProgressListener());
    await waitFor(() => expect(eventMocks.listener).not.toBeNull());

    act(() => {
      eventMocks.listener?.({
        payload: progress({ completed: 2, globalCompleted: 2 }),
      });
      eventMocks.listener?.({
        payload: progress({ completed: 1, globalCompleted: 1 }),
      });
    });
    expect(useLogStore.getState().folderLoadCompletedFiles).toBe(2);

    act(() => {
      eventMocks.listener?.({
        payload: progress({ completed: 3, globalCompleted: 3 }),
      });
    });
    expect(useLogStore.getState().folderLoadCompletedFiles).toBe(3);
  });

  it("resets the monotonic counter for a new request", async () => {
    activateProgress(7);
    renderHook(() => useParseProgressListener());
    await waitFor(() => expect(eventMocks.listener).not.toBeNull());

    act(() => {
      eventMocks.listener?.({ payload: progress({ globalCompleted: 3 }) });
      useLogStore.setState({
        folderLoadRequestId: 8,
        folderLoadProgress: 0,
        folderLoadTotalFiles: 3,
        folderLoadCompletedFiles: 0,
        folderLoadCurrentFile: "",
      });
    });

    act(() => {
      eventMocks.listener?.({
        payload: progress({ requestId: 8, globalCompleted: 1 }),
      });
    });
    expect(useLogStore.getState().folderLoadCompletedFiles).toBe(1);
  });
});

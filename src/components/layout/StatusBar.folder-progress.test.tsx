import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type ProgressPayload = {
  requestId: number;
  filePath: string;
  fileName: string;
  completed: number;
  total: number;
  entries: number;
  fileSize: number;
  parseMs: number;
};
type ProgressEvent = { payload: ProgressPayload };
const progressEvents = vi.hoisted(() => ({
  listener: null as ((event: ProgressEvent) => void) | null,
  listen: vi.fn(),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: progressEvents.listen,
}));

vi.mock("../../workspaces/event-log/evtx-store", () => ({
  useEvtxStore: (selector: (state: {
    records: unknown[];
    sourceMode: string;
    isLoading: boolean;
    loadedChannels: Set<string>;
    loadElapsedMs: number;
  }) => unknown) =>
    selector({
      records: [],
      sourceMode: "idle",
      isLoading: false,
      loadedChannels: new Set(),
      loadElapsedMs: 0,
    }),
}));

import { StatusBar } from "./StatusBar";
import { useParseProgressListener } from "../../hooks/use-parse-progress-listener";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { useFilterStore } from "../../stores/filter-store";

function ParseProgressListenerHarness() {
  useParseProgressListener();
  return null;
}

describe("StatusBar folder parse progress", () => {
  beforeEach(() => {
    progressEvents.listener = null;
    progressEvents.listen.mockReset();
    progressEvents.listen.mockImplementation(
      (_event: string, callback: (event: ProgressEvent) => void) => {
        progressEvents.listener = callback;
        return Promise.resolve(() => undefined);
      },
    );
    useLogStore.getState().clear();
    useFilterStore.setState(useFilterStore.getInitialState(), true);
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({ activeView: "log", activeWorkspace: "log" });
    useLogStore.getState().setFolderLoadProgress({
      current: 3,
      total: 10,
      currentFile: "AppEnforce.log",
    });
    useLogStore.getState().setFolderLoadRequestId(42);
  });

  afterEach(() => {
    cleanup();
  });

  it("ignores progress events from a different folder-load request", async () => {
    render(<ParseProgressListenerHarness />);
    await vi.waitFor(() => expect(progressEvents.listener).not.toBeNull());

    act(() => {
      progressEvents.listener?.({
        payload: {
          requestId: 41,
          filePath: "stale.log",
          fileName: "stale.log",
          completed: 9,
          total: 10,
          entries: 1,
          fileSize: 1,
          parseMs: 1,
        },
      });
    });
    expect(useLogStore.getState().folderLoadCompletedFiles).toBe(3);
    expect(useLogStore.getState().folderLoadCurrentFile).toBe("AppEnforce.log");

    act(() => {
      progressEvents.listener?.({
        payload: {
          requestId: 42,
          filePath: "Accepted.log",
          fileName: "Accepted.log",
          completed: 4,
          total: 10,
          entries: 1,
          fileSize: 1,
          parseMs: 1,
        },
      });
    });
    expect(useLogStore.getState().folderLoadCompletedFiles).toBe(4);
    expect(useLogStore.getState().folderLoadCurrentFile).toBe("Accepted.log");
  });

  it("shows N of M and the current file while a folder load is in progress", () => {
    render(<StatusBar />);
    expect(screen.getByText(/Parsing 3 of 10 files — AppEnforce.log/)).toBeInTheDocument();
  });
});

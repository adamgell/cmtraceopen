import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startTail } from "../lib/commands";
import { useLogStore } from "../stores/log-store";
import type { LogEntry, TailPayload } from "../types/log";
import { useFileWatcher } from "./use-file-watcher";

const eventMocks = vi.hoisted(() => ({
  tailListener: null as ((event: { payload: TailPayload }) => void) | null,
  listen: vi.fn(async (_event: string, listener: (event: { payload: TailPayload }) => void) => {
    eventMocks.tailListener = listener;
    return vi.fn();
  }),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: eventMocks.listen,
}));

vi.mock("../lib/commands", () => ({
  startTail: vi.fn(async () => undefined),
  stopTail: vi.fn(async () => undefined),
  pauseTail: vi.fn(async () => undefined),
  resumeTail: vi.fn(async () => undefined),
}));

const startTailMock = vi.mocked(startTail);

function multilineEntry(): LogEntry {
  return {
    id: 0,
    lineNumber: 1,
    message: "[Sync] started\ncontinuation one\ncontinuation two",
    component: "Sync",
    timestamp: 1_731_689_407_285,
    timestampDisplay: "2024-11-15 16:50:07.285",
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped",
    filePath: "/logs/Log_1.log",
    timezoneOffset: 0,
  };
}

describe("useFileWatcher tail start state", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    eventMocks.tailListener = null;
    useLogStore.getState().clear();
  });

  afterEach(() => {
    cleanup();
  });

  it("starts a single-file tail after the authoritative physical line count", async () => {
    useLogStore.setState({
      openFilePath: "/logs/Log_1.log",
      sourceOpenMode: "single-file",
      formatDetected: "Timestamped",
      byteOffset: 512,
      totalLines: 3,
      entries: [multilineEntry()],
    });

    renderHook(() => useFileWatcher());

    await waitFor(() =>
      expect(startTailMock).toHaveBeenCalledWith(
        "/logs/Log_1.log",
        "Timestamped",
        512,
        1,
        4,
      ),
    );
  });

  it("applies a duplicate logical-record amendment only once", async () => {
    useLogStore.setState({
      openFilePath: "/logs/Log_1.log",
      sourceOpenMode: "single-file",
      formatDetected: "Timestamped",
      byteOffset: 512,
      totalLines: 1,
      entries: [
        {
          ...multilineEntry(),
          message: "[Sync] started",
        },
      ],
    });

    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());

    const payload: TailPayload = {
      entries: [],
      amendments: [
        {
          entryId: 0,
          entryLineNumber: 1,
          continuationStartLine: 2,
          continuationEndLine: 2,
          messageUtf16Start: 14,
          messageSuffix: "\ncontinuation",
          errorCodeSpans: [],
        },
      ],
      filePath: "/logs/Log_1.log",
      parseErrors: 0,
      observedThroughLine: 2,
      reset: false,
    };

    act(() => {
      eventMocks.tailListener?.({ payload });
      eventMocks.tailListener?.({ payload });
    });

    expect(useLogStore.getState().entries[0].message).toBe(
      "[Sync] started\ncontinuation",
    );
    expect(useLogStore.getState().totalLines).toBe(2);
  });

  it("keeps aggregate file counts authoritative and ignores untracked payloads", async () => {
    useLogStore.setState({
      sourceOpenMode: "aggregate-folder",
      formatDetected: "Timestamped",
      totalLines: 2,
      aggregateFiles: [
        {
          filePath: "/logs/a.log",
          totalLines: 1,
          parseErrors: 0,
          fileSize: 512,
          byteOffset: 512,
        },
        {
          filePath: "/logs/b.log",
          totalLines: 1,
          parseErrors: 0,
          fileSize: 256,
          byteOffset: 256,
        },
      ],
      entries: [
        { ...multilineEntry(), filePath: "/logs/a.log", message: "[Sync] started" },
        {
          ...multilineEntry(),
          id: 10,
          filePath: "/logs/b.log",
          message: "unrelated",
        },
      ],
    });

    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());

    const payload: TailPayload = {
      entries: [
        {
          ...multilineEntry(),
          id: 1,
          lineNumber: 3,
          filePath: "/logs/a.log",
          message: "[Sync] finished",
        },
      ],
      amendments: [
        {
          entryId: 0,
          entryLineNumber: 1,
          continuationStartLine: 2,
          continuationEndLine: 2,
          messageUtf16Start: 14,
          messageSuffix: "\ncontinuation",
          errorCodeSpans: [],
        },
      ],
      filePath: "/logs/a.log",
      parseErrors: 0,
      observedThroughLine: 3,
      reset: false,
    };

    act(() => eventMocks.tailListener?.({ payload }));

    expect(useLogStore.getState().aggregateFiles).toMatchObject([
      { filePath: "/logs/a.log", totalLines: 3 },
      { filePath: "/logs/b.log", totalLines: 1 },
    ]);
    expect(useLogStore.getState().totalLines).toBe(4);
    expect(
      useLogStore.getState().entries.find((entry) => entry.filePath === "/logs/a.log")
        ?.message,
    ).toBe("[Sync] started\ncontinuation");

    const beforeUntracked = structuredClone(useLogStore.getState().entries);
    act(() =>
      eventMocks.tailListener?.({
        payload: {
          ...payload,
          amendments: [],
          entries: [
            {
              ...multilineEntry(),
              id: 99,
              lineNumber: 99,
              filePath: "/logs/untracked.log",
            },
          ],
          filePath: "/logs/untracked.log",
          observedThroughLine: 99,
        },
      }),
    );

    expect(useLogStore.getState().entries).toEqual(beforeUntracked);
    expect(useLogStore.getState().totalLines).toBe(4);
  });
});

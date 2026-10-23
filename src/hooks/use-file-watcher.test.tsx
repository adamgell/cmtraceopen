import { firewallSnapshot, firewallPayload } from "../test-utils/firewall";
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startTail, stopTail, pauseTail, resumeTail } from "../lib/commands";
import { useLogStore } from "../stores/log-store";
import type {
  AggregateSourceFile,
  LogEntry,
  ParserSelectionInfo,
  TailPayload,
} from "../types/log";
import { useFileWatcher } from "./use-file-watcher";
import { setCachedTabSnapshot } from "../lib/tab-snapshot-cache";

const PLAIN_SELECTION: ParserSelectionInfo = {
  parser: "plain",
  implementation: "plainText",
  provenance: "fallback",
  parseQuality: "textFallback",
  recordFraming: "physicalLine",
  dateOrder: null,
};

const eventMocks = vi.hoisted(() => ({
  tailListener: null as ((event: { payload: unknown }) => void) | null,
  unlisten: vi.fn(),
  listen: vi.fn(
    async (
      _event: string,
      listener: (event: { payload: unknown }) => void,
    ) => {
      eventMocks.tailListener = listener;
      return eventMocks.unlisten;
    },
  ),
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
const stopTailMock = vi.mocked(stopTail);

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

function emptyTailPayload(overrides: Partial<TailPayload> = {}): TailPayload {
  return {
    entries: [],
    amendments: [],
    filePath: "/logs/Log_1.log",
    parseErrors: 0,
    observedThroughLine: null,
    reset: false,
    ...overrides,
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
      eventMocks.tailListener?.({ payload: structuredClone(payload) });
    });

    expect(useLogStore.getState().entries[0].message).toBe(
      "[Sync] started\ncontinuation",
    );
    expect(useLogStore.getState().totalLines).toBe(2);
  });

  it("unlistens from tail events when the hook unmounts", async () => {
    const { unmount } = renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());

    unmount();

    await waitFor(() => expect(eventMocks.unlisten).toHaveBeenCalledOnce());
  });

  it("clears stale single-file rows on an empty reset while retaining physical coverage", async () => {
    const staleEntry = multilineEntry();
    useLogStore.setState({
      openFilePath: "/logs/Log_1.log",
      sourceOpenMode: "single-file",
      formatDetected: "Timestamped",
      byteOffset: 512,
      totalLines: 5,
      entries: [staleEntry],
    });

    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());

    act(() =>
      eventMocks.tailListener?.({
        payload: emptyTailPayload({
          observedThroughLine: 2,
          reset: true,
        }),
      }),
    );

    expect(useLogStore.getState().entries).toEqual([]);
    expect(useLogStore.getState().totalLines).toBe(2);
  });

  it("rejects malformed tail line and amendment coordinates at the event boundary", async () => {
    const entry = { ...multilineEntry(), message: "[Sync] started" };
    useLogStore.setState({
      openFilePath: "/logs/Log_1.log",
      sourceOpenMode: "single-file",
      formatDetected: "Timestamped",
      byteOffset: 512,
      totalLines: 1,
      entries: [entry],
    });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());

    act(() => {
      eventMocks.tailListener?.({
        payload: {
          ...emptyTailPayload(),
          observedThroughLine: -1,
        },
      });
      eventMocks.tailListener?.({
        payload: {
          ...emptyTailPayload(),
          amendments: [
            {
              entryId: 0,
              entryLineNumber: 1,
              continuationStartLine: 0,
              continuationEndLine: 2,
              messageUtf16Start: 14,
              messageSuffix: "\ninvalid",
              errorCodeSpans: [],
            },
          ],
        },
      });
    });

    expect(errorSpy).toHaveBeenCalledTimes(2);
    expect(useLogStore.getState().entries).toEqual([entry]);
    expect(useLogStore.getState().totalLines).toBe(1);
    errorSpy.mockRestore();
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
          formatDetected: "Plain",
          parserSelection: PLAIN_SELECTION,
        },
        {
          filePath: "/logs/b.log",
          totalLines: 1,
          parseErrors: 0,
          fileSize: 256,
          byteOffset: 256,
          formatDetected: "Plain",
          parserSelection: PLAIN_SELECTION,
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
          observedThroughLine: 101,
        },
      }),
    );

    expect(useLogStore.getState().entries).toEqual(beforeUntracked);
    expect(useLogStore.getState().totalLines).toBe(4);
  });

  it("keeps aggregate tails running when batch accounting changes", async () => {
    useLogStore.setState({
      sourceOpenMode: "aggregate-folder",
      formatDetected: "Timestamped",
      totalLines: 1,
      aggregateFiles: [
        {
          filePath: "/logs/a.log",
          totalLines: 1,
          parseErrors: 0,
          fileSize: 512,
          byteOffset: 512,
          formatDetected: "Plain",
          parserSelection: PLAIN_SELECTION,
        },
      ],
      entries: [
        {
          ...multilineEntry(),
          filePath: "/logs/a.log",
          message: "[Sync] started",
        },
      ],
    });

    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());
    expect(startTailMock).toHaveBeenCalledOnce();

    act(() =>
      eventMocks.tailListener?.({
        payload: emptyTailPayload({
          filePath: "/logs/a.log",
          observedThroughLine: 2,
        }),
      }),
    );

    expect(startTailMock).toHaveBeenCalledOnce();
    expect(stopTailMock).not.toHaveBeenCalled();
  });

  it("restarts aggregate tails when the same files are explicitly reloaded", async () => {
    const aggregateFiles: AggregateSourceFile[] = [
      {
        filePath: "/logs/a.log",
        totalLines: 1,
        parseErrors: 0,
        fileSize: 512,
        byteOffset: 512,
        formatDetected: "Plain",
        parserSelection: PLAIN_SELECTION,
      },
    ];
    useLogStore.setState({
      sourceOpenMode: "aggregate-folder",
      formatDetected: "Timestamped",
      totalLines: 1,
      aggregateFiles,
      entries: [
        {
          ...multilineEntry(),
          filePath: "/logs/a.log",
          message: "[Sync] started",
        },
      ],
    });

    renderHook(() => useFileWatcher());
    await waitFor(() => expect(startTailMock).toHaveBeenCalledOnce());

    act(() => useLogStore.getState().setAggregateFiles(structuredClone(aggregateFiles)));

    await waitFor(() => expect(startTailMock).toHaveBeenCalledTimes(2));
    expect(stopTailMock).toHaveBeenCalledWith("/logs/a.log");
  });

  it("retains aggregate parse gaps and empty-reset physical coverage", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    useLogStore.setState({
      sourceOpenMode: "aggregate-folder",
      formatDetected: "Timestamped",
      totalLines: 6,
      aggregateFiles: [
        {
          filePath: "/logs/a.log",
          totalLines: 4,
          parseErrors: 1,
          fileSize: 512,
          byteOffset: 512,
          formatDetected: "Plain",
          parserSelection: PLAIN_SELECTION,
        },
        {
          filePath: "/logs/b.log",
          totalLines: 2,
          parseErrors: 0,
          fileSize: 256,
          byteOffset: 256,
          formatDetected: "Plain",
          parserSelection: PLAIN_SELECTION,
        },
      ],
      entries: [
        { ...multilineEntry(), filePath: "/logs/a.log", message: "stale" },
        { ...multilineEntry(), id: 2, filePath: "/logs/b.log", message: "keep" },
      ],
    });

    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());

    act(() =>
      eventMocks.tailListener?.({
        payload: emptyTailPayload({
          filePath: "/logs/a.log",
          observedThroughLine: 3,
          parseErrors: 2,
          reset: true,
        }),
      }),
    );

    expect(useLogStore.getState().entries).toMatchObject([
      { filePath: "/logs/b.log", message: "keep" },
    ]);
    expect(useLogStore.getState().aggregateFiles).toMatchObject([
      { filePath: "/logs/a.log", totalLines: 3, parseErrors: 3 },
      { filePath: "/logs/b.log", totalLines: 2, parseErrors: 0 },
    ]);
    expect(useLogStore.getState().totalLines).toBe(5);
    warnSpy.mockRestore();
  });
});

describe("firewall watch epochs", () => {
  beforeEach(() => { vi.clearAllMocks(); useLogStore.getState().clear(); });
  afterEach(cleanup);
  function install() {
    const snapshot = firewallSnapshot();
    useLogStore.getState().registerFirewallSource(snapshot);
    useLogStore.setState({ openFilePath: snapshot.filePath, sourceOpenMode: "single-file", formatDetected: "Timestamped", entries: snapshot.entries });
    return snapshot;
  }
  it("passes the current token through pause/resume and ignores a delayed cancelled start", async () => {
    const snapshot = install();
    let finish!: () => void;
    startTailMock.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
    const first = renderHook(() => useFileWatcher());
    const oldToken = startTailMock.mock.calls[0][5];
    act(() => useLogStore.setState({ isPaused: true }));
    await waitFor(() => expect(pauseTail).toHaveBeenCalledWith(snapshot.filePath, oldToken));
    first.unmount();
    renderHook(() => useFileWatcher());
    const token = startTailMock.mock.calls[1][5];
    await waitFor(() => expect(pauseTail).toHaveBeenCalledWith(snapshot.filePath, token));
    vi.mocked(pauseTail).mockClear(); vi.mocked(resumeTail).mockClear();
    await act(async () => finish());
    expect(pauseTail).not.toHaveBeenCalled(); expect(resumeTail).not.toHaveBeenCalled();
    act(() => useLogStore.setState({ isPaused: false }));
    await waitFor(() => expect(resumeTail).toHaveBeenCalledWith(snapshot.filePath, token));
  });
  it("ignores same-path events from an old native session or watch epoch", async () => {
    const snapshot = install();
    renderHook(() => useFileWatcher());
    const current = startTailMock.mock.calls[0][5]!;
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    act(() => {
      eventMocks.tailListener?.({ payload: firewallPayload({ reset: true, firewallControl: { ...current, sourceSessionId: "old-session" } }) });
      eventMocks.tailListener?.({ payload: firewallPayload({ reset: true, firewallControl: { ...current, watchEpoch: current.watchEpoch + 1 } }) });
      eventMocks.tailListener?.({ payload: emptyTailPayload({ reset: true, filePath: snapshot.filePath }) });
    });
    expect(useLogStore.getState().entries).toEqual(snapshot.entries);
    act(() => eventMocks.tailListener?.({ payload: firewallPayload({ reset: true, observedThroughLine: 0, firewallControl: current }) }));
    expect(useLogStore.getState().entries).toEqual([]);
    error.mockRestore();
  });
  it("allocates a new source-owned epoch after remount and stops the captured epoch", async () => {
    const snapshot = firewallSnapshot();
    useLogStore.getState().registerFirewallSource(snapshot);
    useLogStore.setState({ openFilePath: snapshot.filePath, sourceOpenMode: "single-file", formatDetected: "Timestamped", entries: snapshot.entries });
    const first = renderHook(() => useFileWatcher());
    await waitFor(() => expect(startTailMock).toHaveBeenCalledTimes(1));
    const firstToken = startTailMock.mock.calls[0][5];
    expect(firstToken).toMatchObject({ sourceSessionId: snapshot.firewallSessionId, watchEpoch: 1 });
    first.unmount();
    expect(stopTailMock).toHaveBeenCalledWith(snapshot.filePath, firstToken);
    renderHook(() => useFileWatcher());
    await waitFor(() => expect(startTailMock).toHaveBeenCalledTimes(2));
    expect(startTailMock.mock.calls[1][5]).toMatchObject({ watchEpoch: 2 });
  });
});

describe("merged tab live tailing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    eventMocks.tailListener = null;
    useLogStore.getState().clear();
  });

  afterEach(() => {
    cleanup();
  });

  function seedMergedTab(options: { firewallPaths?: string[] } = {}) {
    const at = (filePath: string, id: number, lineNumber: number, timestamp: number, message: string): LogEntry => ({
      ...multilineEntry(), id, lineNumber, timestamp, message, filePath,
    });
    for (const [filePath, entries] of [
      ["/logs/IntuneManagementExtension.log", [at("/logs/IntuneManagementExtension.log", 0, 1, 1_000, "ime start"), at("/logs/IntuneManagementExtension.log", 1, 2, 4_000, "ime later")]],
      ["/logs/AgentExecutor.log", [at("/logs/AgentExecutor.log", 0, 1, 2_000, "agent start")]],
    ] as const) {
      setCachedTabSnapshot(filePath, {
        entries: [...entries], totalLines: entries.length, byteOffset: 100, formatDetected: "Timestamped",
        parserSelection: PLAIN_SELECTION, sourceOpenMode: "single-file", selectedSourceFilePath: filePath, activeColumns: ["message"],
      });
    }
    useLogStore.setState({
      openFilePath: "/logs/IntuneManagementExtension.log",
      formatDetected: "Timestamped",
      // Only presence matters to merged tabs; the firewall session shape is owned elsewhere.
      firewallSources: Object.fromEntries(
        (options.firewallPaths ?? []).map((path) => [path, { sessionId: "fw", watchEpoch: 0, active: false }]),
      ) as never,
    });
    useLogStore.getState().createMergedTab(["/logs/IntuneManagementExtension.log", "/logs/AgentExecutor.log"]);
  }

  it("tails every source file of a merged tab", async () => {
    seedMergedTab();
    renderHook(() => useFileWatcher());

    await waitFor(() => {
      const watched = startTailMock.mock.calls.map((call) => call[0]);
      expect(watched).toEqual(expect.arrayContaining(["/logs/IntuneManagementExtension.log", "/logs/AgentExecutor.log"]));
    });
  });

  it("inserts tailed lines into the merged timeline in timestamp order", async () => {
    seedMergedTab();
    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());

    act(() => {
      eventMocks.tailListener?.({
        payload: emptyTailPayload({
          filePath: "/logs/AgentExecutor.log",
          entries: [{ ...multilineEntry(), id: 1, lineNumber: 2, timestamp: 3_000, message: "agent finished", filePath: "/logs/AgentExecutor.log" }],
          observedThroughLine: 2,
        }),
      });
    });

    const state = useLogStore.getState();
    expect(state.entries.map((e) => e.message)).toEqual(["ime start", "agent start", "agent finished", "ime later"]);
    expect(state.mergedTabState?.mergedEntries.map((e) => e.message)).toContain("agent finished");
  });

  const IME = "/logs/IntuneManagementExtension.log";
  const AGENT = "/logs/AgentExecutor.log";
  const tailed = (filePath: string, lineNumber: number, timestamp: number | null, message: string): LogEntry => ({
    ...multilineEntry(), id: 0, lineNumber, timestamp, message, filePath,
  });
  async function mountMerged() {
    seedMergedTab();
    renderHook(() => useFileWatcher());
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());
  }
  // The watcher only accepts batches that report having read through their
  // highest line, so report exactly that unless a test says otherwise.
  const throughLine = (payload: Partial<TailPayload>) =>
    Math.max(
      0,
      ...(payload.entries ?? []).map((e) => e.lineNumber + e.message.split("\n").length - 1),
      ...(payload.amendments ?? []).map((a) => a.continuationEndLine),
    ) || null;
  const emit = (payload: Partial<TailPayload>) =>
    act(() => {
      eventMocks.tailListener?.({
        payload: emptyTailPayload({ observedThroughLine: throughLine(payload), ...payload }),
      });
    });
  const messages = () => useLogStore.getState().entries.map((e) => e.message);
  function entryWithMessage(message: string): LogEntry {
    const found = useLogStore.getState().entries.find((e) => e.message === message);
    if (!found) throw new Error(`fixture row "${message}" is missing from the merged view`);
    return found;
  }

  it("starts each source's tail where its tab snapshot left off", async () => {
    seedMergedTab();
    renderHook(() => useFileWatcher());

    await waitFor(() => expect(startTailMock).toHaveBeenCalledWith(AGENT, "Timestamped", 100, 0, 2));
    expect(startTailMock).toHaveBeenCalledWith(IME, "Timestamped", 100, 0, 3);
  });

  it("keeps a stack-trace line under its record when it arrives in a later batch", async () => {
    await mountMerged();

    emit({ filePath: AGENT, entries: [tailed(AGENT, 2, 3_000, "agent error")] });
    emit({ filePath: AGENT, entries: [tailed(AGENT, 3, null, "   at Foo.Bar()")] });

    expect(messages()).toEqual(["ime start", "agent start", "agent error", "   at Foo.Bar()", "ime later"]);
  });

  it("replaces only the rotated source's lines on a reset", async () => {
    await mountMerged();

    emit({ filePath: AGENT, reset: true, entries: [tailed(AGENT, 1, 5_000, "agent rotated")] });

    expect(messages()).toEqual(["ime start", "ime later", "agent rotated"]);
  });

  it("applies a continuation amendment to the merged record", async () => {
    await mountMerged();

    emit({
      filePath: AGENT,
      amendments: [{
        entryId: 0,
        entryLineNumber: 1,
        continuationStartLine: 2,
        continuationEndLine: 2,
        messageUtf16Start: "agent start".length,
        messageSuffix: "\ncontinued",
        errorCodeSpans: [],
      }],
    });

    expect(messages()).toContain("agent start\ncontinued");
    expect(useLogStore.getState().mergedTabState?.mergedEntries.map((e) => e.message)).toContain("agent start\ncontinued");
  });

  it("keeps tailing a hidden source so it is current when shown again", async () => {
    await mountMerged();
    act(() => useLogStore.getState().setFileVisibility(AGENT, false));

    emit({ filePath: AGENT, entries: [tailed(AGENT, 2, 3_000, "agent finished")] });
    expect(messages()).toEqual(["ime start", "ime later"]);

    act(() => useLogStore.getState().setFileVisibility(AGENT, true));
    expect(messages()).toEqual(["ime start", "agent start", "agent finished", "ime later"]);
  });

  it("ignores tail events for files outside the merged tab", async () => {
    await mountMerged();
    const before = useLogStore.getState().entries;

    emit({ filePath: "/logs/Other.log", entries: [tailed("/logs/Other.log", 1, 3_000, "unrelated")] });

    expect(useLogStore.getState().entries).toBe(before);
  });

  it("pauses every merged source", async () => {
    await mountMerged();

    act(() => useLogStore.getState().togglePause());

    await waitFor(() => {
      expect(pauseTail).toHaveBeenCalledWith(IME);
      expect(pauseTail).toHaveBeenCalledWith(AGENT);
    });
  });

  it("clears the selection when the selected row's source is reset", async () => {
    await mountMerged();
    const selected = entryWithMessage("agent start");
    act(() => {
      useLogStore.setState({ selectedId: selected.id, autoCorrelate: true, correlationWindowMs: 5_000 });
      useLogStore.getState().updateCorrelation();
    });
    expect(useLogStore.getState().correlatedEntries).not.toHaveLength(0);

    emit({ filePath: AGENT, reset: true, entries: [tailed(AGENT, 1, 2_000, "agent rotated")] });

    const state = useLogStore.getState();
    expect(state.selectedId).toBeNull();
    expect(state.correlatedEntries).toEqual([]);
    expect(state.entries.find((e) => e.message === "agent rotated")?.id).not.toBe(selected.id);
  });

  it("keeps the selection and refreshes correlation when another source is reset", async () => {
    await mountMerged();
    const selected = entryWithMessage("ime start");
    act(() => {
      useLogStore.setState({ selectedId: selected.id, autoCorrelate: true, correlationWindowMs: 5_000 });
      useLogStore.getState().updateCorrelation();
    });
    expect(useLogStore.getState().correlatedEntries.map((c) => c.entry.message)).toEqual(["agent start"]);

    emit({ filePath: AGENT, reset: true, entries: [tailed(AGENT, 1, 60_000, "agent rotated")] });

    const state = useLogStore.getState();
    expect(state.selectedId).toBe(selected.id);
    expect(state.correlatedEntries).toEqual([]);
  });

  it("leaves firewall sources as a snapshot and ignores their tail events", async () => {
    seedMergedTab({ firewallPaths: [AGENT] });
    renderHook(() => useFileWatcher());
    await waitFor(() => expect(startTailMock).toHaveBeenCalledWith(IME, "Timestamped", 100, 0, 3));
    await waitFor(() => expect(eventMocks.tailListener).not.toBeNull());
    expect(startTailMock.mock.calls.map((call) => call[0])).not.toContain(AGENT);
    const before = useLogStore.getState().entries;

    emit({ filePath: AGENT, entries: [tailed(AGENT, 2, 3_000, "firewall row")] });

    expect(useLogStore.getState().entries).toBe(before);
    expect(messages()).toContain("agent start");
  });

  it("drops lines a restarted watcher replays from the snapshot offset", async () => {
    await mountMerged();
    const batch = { filePath: AGENT, entries: [tailed(AGENT, 2, 3_000, "agent finished")] };
    emit(batch);

    // Any change to the start effect's inputs restarts every merged tail from
    // its original snapshot offset, so the native reader re-sends line 2.
    act(() => useLogStore.setState({ formatDetected: "Plain" }));
    await waitFor(() =>
      expect(startTailMock.mock.calls.filter((call) => call[0] === AGENT)).toHaveLength(2),
    );
    emit(batch);
    emit({ filePath: AGENT, entries: [tailed(AGENT, 3, 3_500, "agent next")] });

    expect(messages()).toEqual(["ime start", "agent start", "agent finished", "agent next", "ime later"]);
  });

  it("accepts low line numbers again after a source resets", async () => {
    await mountMerged();
    emit({ filePath: AGENT, entries: [tailed(AGENT, 2, 3_000, "agent finished")] });

    emit({ filePath: AGENT, reset: true, entries: [tailed(AGENT, 1, 5_000, "agent rotated")] });
    emit({ filePath: AGENT, entries: [tailed(AGENT, 2, 6_000, "agent after rotation")] });

    expect(messages()).toEqual(["ime start", "ime later", "agent rotated", "agent after rotation"]);
  });

  it("stops every merged tail when the merged tab closes", async () => {
    await mountMerged();
    await waitFor(() => expect(startTailMock).toHaveBeenCalledTimes(2));

    act(() => useLogStore.getState().closeMergedTab());

    await waitFor(() => {
      expect(stopTailMock).toHaveBeenCalledWith(IME);
      expect(stopTailMock).toHaveBeenCalledWith(AGENT);
    });
  });
});

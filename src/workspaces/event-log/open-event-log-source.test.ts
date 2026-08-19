import { beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => undefined),
}));

vi.mock("../../lib/commands", () => ({
  listLogFolder: vi.fn(),
}));

const { listLogFolder } = await import("../../lib/commands");
const { openEventLogSource } = await import("./open-event-log-source");
const { useEvtxStore } = await import("./evtx-store");
const actualParseFiles = useEvtxStore.getState().parseFiles;

describe("openEventLogSource", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useEvtxStore.setState({
      parseFiles: vi.fn(async () => undefined),
      setLoadError: vi.fn(),
    });
  });

  it("parses a single evtx file", async () => {
    await openEventLogSource({ kind: "file", path: "/tmp/Application.evtx" });
    expect(useEvtxStore.getState().parseFiles).toHaveBeenCalledWith([
      "/tmp/Application.evtx",
    ]);
  });
  it("propagates file parse failures to the caller", async () => {
    const parseFiles = actualParseFiles;
    useEvtxStore.setState({
      parseFiles,
      setLoadError: vi.fn(),
    });
    invoke.mockRejectedValueOnce(new Error("not a file"));

    await expect(
      openEventLogSource({ kind: "file", path: "/tmp/not-a-file" }),
    ).rejects.toThrow("not a file");
    expect(useEvtxStore.getState().loadError).toBe("not a file");
  });
  it("parses a known file source using its default path", async () => {
    const defaultPath = "/tmp/Application.evtx";

    await openEventLogSource({
      kind: "known",
      sourceId: "known-application",
      defaultPath,
      pathKind: "file",
    });

    expect(useEvtxStore.getState().parseFiles).toHaveBeenCalledWith([defaultPath]);
    expect(listLogFolder).not.toHaveBeenCalled();
  });

  it("parses evtx files from a known folder source", async () => {
    const defaultPath = "/tmp/logs";
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: {
        kind: "known",
        sourceId: "known-logs",
        defaultPath,
        pathKind: "folder",
      },
      entries: [
        {
          name: "SYSTEM.EVTX",
          path: `${defaultPath}/SYSTEM.EVTX`,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
        {
          name: "notes.txt",
          path: `${defaultPath}/notes.txt`,
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
        {
          name: "nested.evtx",
          path: `${defaultPath}/nested.evtx`,
          isDir: true,
          sizeBytes: null,
          modifiedUnixMs: null,
        },
      ],
    });

    await openEventLogSource({
      kind: "known",
      sourceId: "known-logs",
      defaultPath,
      pathKind: "folder",
    });

    expect(listLogFolder).toHaveBeenCalledWith(defaultPath);
    expect(useEvtxStore.getState().parseFiles).toHaveBeenCalledWith([
      `${defaultPath}/SYSTEM.EVTX`,
    ]);
  });

  it("rejects a known folder with no evtx files", async () => {
    const defaultPath = "/tmp/empty";
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: {
        kind: "known",
        sourceId: "known-empty",
        defaultPath,
        pathKind: "folder",
      },
      entries: [],
    });

    await expect(
      openEventLogSource({
        kind: "known",
        sourceId: "known-empty",
        defaultPath,
        pathKind: "folder",
      }),
    ).rejects.toThrow("No .evtx files were found for that known source.");
    expect(useEvtxStore.getState().setLoadError).toHaveBeenCalledWith(
      "No .evtx files were found for that known source.",
    );
    expect(useEvtxStore.getState().parseFiles).not.toHaveBeenCalled();
  });

  it("parses evtx files from a folder and ignores other names", async () => {
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/logs" },
      entries: [
        {
          name: "Application.evtx",
          path: "/tmp/logs/Application.evtx",
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
        {
          name: "notes.txt",
          path: "/tmp/logs/notes.txt",
          isDir: false,
          sizeBytes: 1,
          modifiedUnixMs: null,
        },
        {
          name: "nested",
          path: "/tmp/logs/nested",
          isDir: true,
          sizeBytes: null,
          modifiedUnixMs: null,
        },
      ],
    });

    await openEventLogSource({ kind: "folder", path: "/tmp/logs" });
    expect(useEvtxStore.getState().parseFiles).toHaveBeenCalledWith([
      "/tmp/logs/Application.evtx",
    ]);
  });

  it("rejects a folder with no evtx files", async () => {
    vi.mocked(listLogFolder).mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/empty" },
      entries: [],
    });

    await expect(
      openEventLogSource({ kind: "folder", path: "/tmp/empty" }),
    ).rejects.toThrow(/No \.evtx files/);
    expect(useEvtxStore.getState().setLoadError).toHaveBeenCalledWith(
      "No .evtx files were found in that folder. Choose a folder that contains Windows Event Log files.",
    );
  });
});

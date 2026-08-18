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

describe("openEventLogSource", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useEvtxStore.setState({
      parseFiles: vi.fn(async () => undefined),
    } as never);
  });

  it("parses a single evtx file", async () => {
    await openEventLogSource({ kind: "file", path: "/tmp/Application.evtx" });
    expect(useEvtxStore.getState().parseFiles).toHaveBeenCalledWith([
      "/tmp/Application.evtx",
    ]);
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
  });
});

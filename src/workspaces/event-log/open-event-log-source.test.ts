import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EventLogSourceManifest } from "./types";

const expandEventLogSources = vi.hoisted(() => vi.fn());
const listLogFolder = vi.hoisted(() => vi.fn());
const parseManifest = vi.hoisted(() => vi.fn());
const parseFiles = vi.hoisted(() => vi.fn());
const setLoadError = vi.hoisted(() => vi.fn());

vi.mock("../../lib/commands", () => ({ expandEventLogSources, listLogFolder }));
vi.mock("./evtx-store", () => ({
  useEvtxStore: {
    getState: () => ({ parseManifest, parseFiles, setLoadError }),
  },
}));

// Dynamic import is intentional: Vitest mocks must be installed before this module evaluates.
const { openEventLogSource, openEventLogSources } =
  await import("./open-event-log-source");
beforeEach(() => {
  expandEventLogSources.mockReset();
  listLogFolder.mockReset();
  parseManifest.mockReset();
  parseFiles.mockReset();
  setLoadError.mockReset();
});

describe("openEventLogSources provenance", () => {
  it("keeps backend archive and VSS kinds when the picker reports a generic file", async () => {
    const manifest: EventLogSourceManifest = {
      entries: [
        { sourceId: "archive", path: "Archive-Application.evtx", kind: "archive" },
        { sourceId: "vss", path: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Application.evtx", kind: "vss" },
      ],
      coverage: [],
    };
    expandEventLogSources.mockResolvedValue(manifest);

    await openEventLogSources([
      { kind: "file", path: "Archive-Application.evtx" },
      { kind: "file", path: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Application.evtx" },
    ]);

    expect(parseManifest).toHaveBeenCalledWith(manifest);
    expect(parseManifest.mock.calls[0][0].entries.map((entry: { kind: string }) => entry.kind)).toEqual([
      "archive",
      "vss",
    ]);
  });
});

describe("openEventLogSource", () => {
  beforeEach(() => {
    parseFiles.mockResolvedValue(undefined);
  });

  it("parses a single evtx file", async () => {
    await openEventLogSource({ kind: "file", path: "/tmp/Application.evtx" });

    expect(parseFiles).toHaveBeenCalledWith(["/tmp/Application.evtx"]);
  });

  it("propagates file parse failures and records the error", async () => {
    parseFiles.mockRejectedValueOnce(new Error("not a file"));

    await expect(
      openEventLogSource({ kind: "file", path: "/tmp/not-a-file" })
    ).rejects.toThrow("not a file");
    expect(setLoadError).toHaveBeenCalledWith("not a file");
  });

  it("parses a known file source using its default path", async () => {
    const defaultPath = "/tmp/Application.evtx";

    await openEventLogSource({
      kind: "known",
      sourceId: "known-application",
      defaultPath,
      pathKind: "file",
    });

    expect(parseFiles).toHaveBeenCalledWith([defaultPath]);
    expect(listLogFolder).not.toHaveBeenCalled();
  });

  it("parses evtx files from a known folder source", async () => {
    const defaultPath = "/tmp/logs";
    listLogFolder.mockResolvedValue({
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
    expect(parseFiles).toHaveBeenCalledWith([`${defaultPath}/SYSTEM.EVTX`]);
  });

  it("rejects a known folder with no evtx files", async () => {
    listLogFolder.mockResolvedValue({ entries: [] });

    await expect(
      openEventLogSource({
        kind: "known",
        sourceId: "known-empty",
        defaultPath: "/tmp/empty",
        pathKind: "folder",
      })
    ).rejects.toThrow("No .evtx files were found for that known source.");
    expect(setLoadError).toHaveBeenCalledWith(
      "No .evtx files were found for that known source."
    );
    expect(parseFiles).not.toHaveBeenCalled();
  });

  it("parses evtx files from a folder and ignores other names", async () => {
    listLogFolder.mockResolvedValue({
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

    expect(parseFiles).toHaveBeenCalledWith(["/tmp/logs/Application.evtx"]);
  });

  it("rejects a folder with no evtx files", async () => {
    listLogFolder.mockResolvedValue({ entries: [] });

    await expect(
      openEventLogSource({ kind: "folder", path: "/tmp/empty" })
    ).rejects.toThrow(/No \.evtx files/);
    expect(setLoadError).toHaveBeenCalledWith(
      "No .evtx files were found in that folder. Choose a folder that contains Windows Event Log files."
    );
  });

  it("preserves child traversal details when they explain an empty folder", async () => {
    listLogFolder.mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/logs" },
      entries: [],
      childErrors: [
        {
          path: "/tmp/logs/protected.evtx",
          reason: "access denied",
        },
      ],
    });

    await expect(
      openEventLogSource({ kind: "folder", path: "/tmp/logs" })
    ).rejects.toThrow("/tmp/logs/protected.evtx: access denied");
    expect(setLoadError).toHaveBeenCalledWith(
      expect.stringContaining("/tmp/logs/protected.evtx: access denied")
    );
  });

  it("bounds empty-folder traversal diagnostics by count and message size", async () => {
    const longPath = `/tmp/${"a".repeat(500)}.evtx`;
    const longReason = `denied-${"b".repeat(500)}`;
    listLogFolder.mockResolvedValue({
      sourceKind: "folder",
      source: { kind: "folder", path: "/tmp/logs" },
      entries: [],
      childErrors: [
        { path: longPath, reason: longReason },
        { path: "/tmp/logs/second.evtx", reason: "second failure" },
        { path: "/tmp/logs/third.evtx", reason: "third failure" },
        { path: "/tmp/logs/fourth.evtx", reason: "fourth failure" },
        { path: "/tmp/logs/fifth.evtx", reason: "fifth failure" },
      ],
    });

    let message = "";
    try {
      await openEventLogSource({ kind: "folder", path: "/tmp/logs" });
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain(`/tmp/${"a".repeat(20)}`);
    expect(message).toContain(`denied-${"b".repeat(20)}`);
    expect(message).toContain("/tmp/logs/second.evtx: second failure");
    expect(message).toContain("/tmp/logs/third.evtx: third failure");
    expect(message).not.toContain("/tmp/logs/fourth.evtx");
    expect(message).not.toContain("/tmp/logs/fifth.evtx");
    expect(message).toContain("2 more");
    expect(message.length).toBeLessThanOrEqual(1_200);
  });
});

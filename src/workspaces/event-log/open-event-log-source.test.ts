import { beforeEach, describe, expect, it, vi } from "vitest";
import { deferred } from "../../test-utils/deferred";
import type { EventLogSourceManifest } from "./types";

const expandEventLogSources = vi.hoisted(() => vi.fn());
const parseManifest = vi.hoisted(() => vi.fn());
const parseFiles = vi.hoisted(() => vi.fn());
const setLoadError = vi.hoisted(() => vi.fn());
const supersedePendingLoad = vi.hoisted(() => vi.fn());

vi.mock("../../lib/commands", () => ({ expandEventLogSources }));
vi.mock("./evtx-store", () => ({
  useEvtxStore: {
    getState: () => ({
      parseManifest,
      parseFiles,
      setLoadError,
      supersedePendingLoad,
    }),
  },
}));

// Dynamic import is intentional: Vitest mocks must be installed before this module evaluates.
const { openEventLogSource, openEventLogSources } =
  await import("./open-event-log-source");
beforeEach(() => {
  expandEventLogSources.mockReset();
  parseManifest.mockReset();
  parseFiles.mockReset();
  setLoadError.mockReset();
  supersedePendingLoad.mockReset();
});

function manifestFor(path: string): EventLogSourceManifest {
  return {
    entries: [{ sourceId: path.toLowerCase(), path, kind: "file" }],
    coverage: [],
  };
}

describe("source-open generation", () => {
  it("does not let an older expansion replace a newer source", async () => {
    const olderExpansion = deferred<EventLogSourceManifest>();
    const newerManifest = manifestFor("/tmp/newer/Application.evtx");
    expandEventLogSources
      .mockReturnValueOnce(olderExpansion.promise)
      .mockResolvedValueOnce(newerManifest);
    parseManifest.mockResolvedValue(undefined);

    const olderOpen = openEventLogSources([
      { kind: "folder", path: "/tmp/older" },
    ]);
    await openEventLogSources([{ kind: "folder", path: "/tmp/newer" }]);
    olderExpansion.resolve(manifestFor("/tmp/older/Application.evtx"));
    await olderOpen;

    expect(parseManifest).toHaveBeenCalledTimes(1);
    expect(parseManifest).toHaveBeenCalledWith(newerManifest);
  });

  it("discards an older expansion failure after a newer error", async () => {
    const olderExpansion = deferred<EventLogSourceManifest>();
    expandEventLogSources
      .mockReturnValueOnce(olderExpansion.promise)
      .mockRejectedValueOnce(new Error("newer source failed"));

    const olderResult = openEventLogSources([
      { kind: "folder", path: "/tmp/older" },
    ]).then(
      () => null,
      (error: unknown) => error,
    );
    const newerResult = openEventLogSource({
      kind: "folder",
      path: "/tmp/newer",
    }).then(
      () => null,
      (error: unknown) => error,
    );

    expect(await newerResult).toEqual(new Error("newer source failed"));
    olderExpansion.reject(new Error("older source failed"));
    expect(await olderResult).toBeNull();
    expect(setLoadError).toHaveBeenCalledTimes(1);
    expect(setLoadError).toHaveBeenCalledWith("newer source failed");
  });
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
    parseManifest.mockResolvedValue(undefined);
  });

  it("parses a single evtx file", async () => {
    await openEventLogSource({ kind: "file", path: "/tmp/Application.evtx" });

    expect(parseFiles).toHaveBeenCalledWith(["/tmp/Application.evtx"]);
  });

  it.each([
    {
      label: "folder",
      source: { kind: "folder" as const, path: "/tmp/logs" },
    },
    {
      label: "known folder",
      source: {
        kind: "known" as const,
        sourceId: "known-logs",
        defaultPath: "/tmp/logs",
        pathKind: "folder" as const,
      },
    },
  ])(
    "loads usable EVTX and preserves partial coverage from one $label manifest expansion",
    async ({ source }) => {
      const manifest: EventLogSourceManifest = {
        entries: [
          {
            sourceId: "application",
            path: "/tmp/logs/Application.evtx",
            kind: "file",
          },
        ],
        coverage: [
          {
            kind: "accessDenied",
            path: "/tmp/logs/protected.evtx",
            reason: "access denied",
          },
        ],
      };
      expandEventLogSources.mockResolvedValue(manifest);
      parseManifest.mockResolvedValue(undefined);

      await openEventLogSource(source);

      expect(expandEventLogSources).toHaveBeenCalledWith([
        { kind: "folder", path: "/tmp/logs" },
      ]);
      expect(expandEventLogSources).toHaveBeenCalledTimes(1);
      expect(parseManifest).toHaveBeenCalledWith(manifest);
      expect(parseFiles).not.toHaveBeenCalled();
    },
  );

  it("loads EVTX files found only in a nested folder by the manifest expander", async () => {
    const manifest = manifestFor("/tmp/logs/nested/Application.evtx");
    expandEventLogSources.mockResolvedValue(manifest);

    await openEventLogSource({ kind: "folder", path: "/tmp/logs" });

    expect(expandEventLogSources).toHaveBeenCalledWith([
      { kind: "folder", path: "/tmp/logs" },
    ]);
    expect(expandEventLogSources).toHaveBeenCalledTimes(1);
    expect(parseManifest).toHaveBeenCalledWith(manifest);
  });

  it("uses manifest coverage to explain why a folder produced no usable EVTX entries", async () => {
    expandEventLogSources.mockResolvedValue({
      entries: [],
      coverage: [
        {
          kind: "accessDenied",
          path: "/tmp/logs/protected.evtx",
          reason: "access denied",
        },
      ],
    });

    await expect(
      openEventLogSource({ kind: "folder", path: "/tmp/logs" }),
    ).rejects.toThrow("/tmp/logs/protected.evtx: access denied");
    expect(expandEventLogSources).toHaveBeenCalledTimes(1);
    expect(parseManifest).not.toHaveBeenCalled();
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
    expect(expandEventLogSources).not.toHaveBeenCalled();
  });

  it("parses evtx files from a known folder source", async () => {
    const defaultPath = "/tmp/logs";
    const manifest = manifestFor(`${defaultPath}/SYSTEM.EVTX`);
    expandEventLogSources.mockResolvedValue(manifest);

    await openEventLogSource({
      kind: "known",
      sourceId: "known-logs",
      defaultPath,
      pathKind: "folder",
    });

    expect(expandEventLogSources).toHaveBeenCalledWith([
      { kind: "folder", path: defaultPath },
    ]);
    expect(parseManifest).toHaveBeenCalledWith(manifest);
    expect(parseFiles).not.toHaveBeenCalled();
  });

  it("rejects a known folder with no evtx files", async () => {
    expandEventLogSources.mockResolvedValue({
      entries: [],
      coverage: [
        {
          kind: "empty",
          path: "/tmp/empty",
          reason: "folder contains no EVTX files",
        },
      ],
    });

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
    expect(parseManifest).not.toHaveBeenCalled();
    expect(expandEventLogSources).toHaveBeenCalledTimes(1);
  });

  it("parses the manifest returned for a folder", async () => {
    const manifest = manifestFor("/tmp/logs/Application.evtx");
    expandEventLogSources.mockResolvedValue(manifest);

    await openEventLogSource({ kind: "folder", path: "/tmp/logs" });

    expect(expandEventLogSources).toHaveBeenCalledWith([
      { kind: "folder", path: "/tmp/logs" },
    ]);
    expect(parseManifest).toHaveBeenCalledWith(manifest);
    expect(parseFiles).not.toHaveBeenCalled();
  });

  it("rejects a folder with no evtx files", async () => {
    expandEventLogSources.mockResolvedValue({
      entries: [],
      coverage: [
        {
          kind: "empty",
          path: "/tmp/empty",
          reason: "folder contains no EVTX files",
        },
      ],
    });

    await expect(
      openEventLogSource({ kind: "folder", path: "/tmp/empty" })
    ).rejects.toThrow(/No \.evtx files/);
    expect(setLoadError).toHaveBeenCalledWith(
      "No .evtx files were found in that folder. Choose a folder that contains Windows Event Log files."
    );
    expect(parseManifest).not.toHaveBeenCalled();
    expect(expandEventLogSources).toHaveBeenCalledTimes(1);
  });

  it("preserves child traversal details when they explain an empty folder", async () => {
    expandEventLogSources.mockResolvedValue({
      entries: [],
      coverage: [
        {
          kind: "accessDenied",
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
    expandEventLogSources.mockResolvedValue({
      entries: [],
      coverage: [
        { kind: "accessDenied", path: longPath, reason: longReason },
        {
          kind: "accessDenied",
          path: "/tmp/logs/second.evtx",
          reason: "second failure",
        },
        {
          kind: "accessDenied",
          path: "/tmp/logs/third.evtx",
          reason: "third failure",
        },
        {
          kind: "accessDenied",
          path: "/tmp/logs/fourth.evtx",
          reason: "fourth failure",
        },
        {
          kind: "accessDenied",
          path: "/tmp/logs/fifth.evtx",
          reason: "fifth failure",
        },
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

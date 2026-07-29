import { beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.fn();
const inspectPathKindMock = vi.fn();

vi.mock("@tauri-apps/api/core", () => ({
  invoke: (...args: unknown[]) => invokeMock(...args),
}));

vi.mock("./commands", () => ({
  inspectPathKind: (...args: unknown[]) => inspectPathKindMock(...args),
}));

import {
  clearRecentEntries,
  recordRecentPath,
  recordRecentSource,
} from "./recent-entries";

describe("recent-entries", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    invokeMock.mockResolvedValue(undefined);
    inspectPathKindMock.mockReset();
  });

  it("records a file source", async () => {
    await recordRecentSource({ kind: "file", path: "/a.log" }, "log");

    expect(invokeMock).toHaveBeenCalledWith("push_recent_entry", {
      path: "/a.log",
      kind: "file",
      workspace: "log",
    });
  });

  it("records a folder source", async () => {
    await recordRecentSource({ kind: "folder", path: "/bundle" }, "intune");

    expect(invokeMock).toHaveBeenCalledWith("push_recent_entry", {
      path: "/bundle",
      kind: "folder",
      workspace: "intune",
    });
  });

  it("ignores known sources", async () => {
    await recordRecentSource(
      {
        kind: "known",
        sourceId: "windows-ime-log",
        defaultPath: "/a.log",
        pathKind: "file",
      },
      "log",
    );

    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("resolves the kind for a bare path", async () => {
    inspectPathKindMock.mockResolvedValue("folder");

    await recordRecentPath("/bundle", "log");

    expect(invokeMock).toHaveBeenCalledWith("push_recent_entry", {
      path: "/bundle",
      kind: "folder",
      workspace: "log",
    });
  });

  it("skips a path whose kind cannot be resolved", async () => {
    inspectPathKindMock.mockResolvedValue("unknown");

    await recordRecentPath("/gone", "log");

    expect(invokeMock).not.toHaveBeenCalled();
  });

  it("never rejects when the backend fails", async () => {
    invokeMock.mockRejectedValue(new Error("disk full"));

    await expect(
      recordRecentSource({ kind: "file", path: "/a.log" }, "log"),
    ).resolves.toBeUndefined();
  });

  it("clears entries", async () => {
    await clearRecentEntries();
    expect(invokeMock).toHaveBeenCalledWith("clear_recent_entries");
  });
});

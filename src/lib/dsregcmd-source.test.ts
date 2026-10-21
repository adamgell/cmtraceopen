import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { analyzeDsregcmdSource, analyzeDsregcmdText } from "./dsregcmd-source";
import { useDsregcmdStore } from "../workspaces/dsregcmd/dsregcmd-store";
import { analysisResult } from "../workspaces/dsregcmd/dsregcmd-test-fixtures";

const commands = vi.hoisted(() => ({
  analyzeDsregcmd: vi.fn(),
  captureDsregcmd: vi.fn(),
  loadDsregcmdSource: vi.fn(),
}));

vi.mock("./commands", () => commands);
vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  readText: vi.fn().mockResolvedValue("AzureAdJoined : YES"),
}));

const CAPTURE_TIME = new Date("2026-07-13T09:12:00.000Z");

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(CAPTURE_TIME);
  commands.analyzeDsregcmd.mockResolvedValue(analysisResult());
  commands.captureDsregcmd.mockResolvedValue({
    input: "AzureAdJoined : YES\nDomainJoined : NO",
    evidenceFilePath: "C:\\bundle\\evidence\\dsregcmd.txt",
    bundlePath: "C:\\bundle",
  });
  commands.loadDsregcmdSource.mockResolvedValue({
    input: "AzureAdJoined : YES",
    resolvedPath: "C:\\temp\\dsregcmd.txt",
    evidenceFilePath: "C:\\temp\\dsregcmd.txt",
    bundlePath: null,
  });
  useDsregcmdStore.getState().clear();
});

afterEach(() => {
  vi.useRealTimers();
  useDsregcmdStore.getState().clear();
});

describe("dsregcmd source capturedAt (DD13)", () => {
  it("records the client clock when a live capture completes", async () => {
    await analyzeDsregcmdSource({ kind: "capture" });

    expect(useDsregcmdStore.getState().sourceContext.capturedAt).toBe(
      CAPTURE_TIME.toISOString(),
    );
  });

  it.each([
    { name: "file", source: { kind: "file", path: "C:\\temp\\dsregcmd.txt" } },
    { name: "folder", source: { kind: "folder", path: "C:\\bundle" } },
    { name: "clipboard", source: { kind: "clipboard" } },
  ] as const)("never records a time for a $name source", async ({ source }) => {
    await analyzeDsregcmdSource(source);

    expect(useDsregcmdStore.getState().sourceContext.capturedAt).toBeNull();
  });

  it("never records a time for pasted text", async () => {
    await analyzeDsregcmdText("AzureAdJoined : YES");

    expect(useDsregcmdStore.getState().sourceContext.capturedAt).toBeNull();
  });
});

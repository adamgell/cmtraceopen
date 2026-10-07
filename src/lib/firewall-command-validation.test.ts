import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { openLogFile, openLogFolderAggregate, parseFilesBatch } from "./commands";
import { firewallSnapshot } from "../test-utils/firewall";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
beforeEach(() => vi.resetAllMocks());

describe.each(["open", "batch", "aggregate"] as const)("%s firewall response validation", mode => {
  function request(metadata: Record<string, unknown> = {}, entry: Record<string, unknown> = {}) {
    const snapshot = firewallSnapshot();
    const result = { ...snapshot, ...metadata, entries: [{ ...snapshot.entries[0], ...entry }] };
    if (mode === "aggregate") {
      vi.mocked(invoke).mockResolvedValueOnce({ entries: result.entries, totalLines: 4, parseErrors: 0,
        folderPath: "/synthetic", files: [{ ...result, entries: undefined }] });
      return openLogFolderAggregate("/synthetic");
    }
    vi.mocked(invoke).mockResolvedValueOnce(mode === "batch" ? [result] : result);
    return mode === "batch" ? parseFilesBatch([snapshot.filePath], 1, 0) : openLogFile(snapshot.filePath);
  }
  it.each([
    { firewallSessionId: "" }, { firewallSessionId: 4 }, { firewallSessionId: "x".repeat(129) },
    { firewallCoverage: { malformed: { count: "not a count", lines: [] } } },
    { firewallCoverage: { ...firewallSnapshot().firewallCoverage, malformed: { count: "18446744073709551616", lines: [] } } },
    { firewallDecoding: { kind: "gap", pendingBytes: 0, reason: null } },
    { firewallDecoding: { kind: "pending", pendingBytes: 4, reason: null } },
  ])("rejects malformed source metadata %j", async metadata => {
    await expect(request(metadata)).rejects.toThrow("invalid response");
  });
  it.each([{}, { rawLine: "invented" }, { ...firewallSnapshot().entries[0].firewall, fields: [] }])("rejects malformed row metadata %j", async firewall => {
    await expect(request({}, { firewall })).rejects.toThrow("invalid response");
  });
  it("accepts complete validated firewall data", async () => {
    await expect(request()).resolves.toBeDefined();
  });
  it.each([undefined, null])("preserves absent/null optional metadata (%s)", async absent => {
    await expect(request({ firewallSessionId: absent, firewallCoverage: absent, firewallDecoding: absent }, { firewall: absent })).resolves.toBeDefined();
  });
});

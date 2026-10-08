import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import { checkDnsLoggingStatus } from "./commands";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
const status = {
  dnsServerInstalled: true, dhcpServerInstalled: false,
  debugLoggingEnabled: true, logFilePath: null,
  canRestoreLogging: false, restoreError: null,
};
beforeEach(() => vi.mocked(invoke).mockReset());

describe("DNS recovery IPC", () => {
  it("preserves ownership separately from logging status", async () => {
    vi.mocked(invoke).mockResolvedValue(status);
    await expect(checkDnsLoggingStatus()).resolves.toEqual(status);
  });
  it.each([
    { ...status, canRestoreLogging: undefined },
    { ...status, canRestoreLogging: "true" },
    { ...status, restoreError: undefined },
    { ...status, restoreError: {} },
    { ...status, restoreError: "x".repeat(513) },
  ])("rejects missing or malformed recovery fields %#", async (value) => {
    vi.mocked(invoke).mockResolvedValue(value);
    await expect(checkDnsLoggingStatus()).rejects.toThrow("invalid response");
  });
});

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { LogEntry } from "../../types/log";
import { DnsDhcpWorkspace } from "./DnsDhcpWorkspace";
import { useDnsDhcpStore } from "./dns-dhcp-store";

const {
  checkDnsLoggingStatus,
  inspectPathKind,
  listLogFolder,
  openLogFile,
  collectDnsDhcpFromDomain,
  enableDnsDebugLogging,
  openDialog,
  confirmDialog,
} = vi.hoisted(() => ({
  checkDnsLoggingStatus: vi.fn(),
  inspectPathKind: vi.fn(),
  listLogFolder: vi.fn(),
  openLogFile: vi.fn(),
  collectDnsDhcpFromDomain: vi.fn(),
  enableDnsDebugLogging: vi.fn(),
  openDialog: vi.fn(),
  confirmDialog: vi.fn(),
}));

vi.mock("../../lib/commands", () => ({
  checkDnsLoggingStatus,
  inspectPathKind,
  listLogFolder,
  openLogFile,
  collectDnsDhcpFromDomain,
  enableDnsDebugLogging,
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: openDialog,
  confirm: confirmDialog,
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => {}),
}));

function entry(overrides: Partial<LogEntry> & { id: number }): LogEntry {
  return {
    lineNumber: overrides.id,
    message: `message ${overrides.id}`,
    component: null,
    timestamp: 1_700_000_000_000 + overrides.id,
    timestampDisplay: null,
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Plain",
    filePath: "/dns.log",
    timezoneOffset: null,
    ...overrides,
  };
}

describe("DnsDhcpWorkspace", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useDnsDhcpStore.getState().clear();
    inspectPathKind.mockRejectedValue(new Error("missing"));
    listLogFolder.mockRejectedValue(new Error("missing"));
    openLogFile.mockRejectedValue(new Error("missing"));
  });

  afterEach(() => {
    cleanup();
  });

  it("shows Scan this server, Collect from domain, and Open files on the empty state (DNS-001/002/003)", () => {
    render(<DnsDhcpWorkspace />);
    expect(screen.getByRole("button", { name: "Scan this server" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Collect from domain" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Open files..." })).toBeVisible();
  });

  it("scans this server, surfaces debug-logging status, and offers to enable it (DNS-001)", async () => {
    checkDnsLoggingStatus.mockResolvedValue({
      dnsServerInstalled: true,
      dhcpServerInstalled: false,
      debugLoggingEnabled: false,
      logFilePath: null,
    });

    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));

    await waitFor(() => {
      expect(screen.getByText("Server Status")).toBeVisible();
    });
    expect(screen.getByText("DNS Server")).toBeVisible();
    expect(screen.getByRole("button", { name: "Enable DNS debug logging" })).toBeEnabled();
    expect(checkDnsLoggingStatus).toHaveBeenCalled();
  });

  it("prompts before collecting from domain DCs (DNS-002)", async () => {
    confirmDialog.mockResolvedValue(false);

    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Collect from domain" }));

    await waitFor(() => {
      expect(confirmDialog).toHaveBeenCalled();
    });
    expect(collectDnsDhcpFromDomain).not.toHaveBeenCalled();
  });

  it("opens DNS/DHCP files and correlates devices by IP (DNS-003)", async () => {
    openDialog.mockResolvedValue(["C:\\\\logs\\\\dns.log", "C:\\\\logs\\\\DhcpSrvLog-Mon.log"]);
    openLogFile.mockImplementation(async (path: string) => {
      if (path.endsWith("dns.log")) {
        return {
          formatDetected: "DnsDebug",
          entries: [
            entry({
              id: 1,
              format: "DnsDebug",
              filePath: path,
              sourceIp: "10.0.0.8:53",
              queryName: "host.contoso.com",
              queryType: "A",
              responseCode: "NXDOMAIN",
            }),
          ],
        };
      }
      return {
        formatDetected: "Plain",
        entries: [
          entry({
            id: 2,
            filePath: path,
            ipAddress: "10.0.0.8",
            hostName: "PC01",
            macAddress: "aa:bb:cc:dd:ee:ff",
          }),
        ],
      };
    });

    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Open files..." }));

    await waitFor(() => {
      expect(screen.getAllByText("PC01").length).toBeGreaterThan(0);
    });
    expect(screen.getAllByText(/10\.0\.0\.8/).length).toBeGreaterThan(0);
    expect(useDnsDhcpStore.getState().devices).toHaveLength(1);
    expect(useDnsDhcpStore.getState().devices[0].isEnriched).toBe(true);
  });
});

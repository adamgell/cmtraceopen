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
  disableDnsDebugLogging,
  openDialog,
  confirmDialog,
} = vi.hoisted(() => ({
  checkDnsLoggingStatus: vi.fn(),
  inspectPathKind: vi.fn(),
  listLogFolder: vi.fn(),
  openLogFile: vi.fn(),
  collectDnsDhcpFromDomain: vi.fn(),
  enableDnsDebugLogging: vi.fn(),
  disableDnsDebugLogging: vi.fn(),
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
  disableDnsDebugLogging,
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
    checkDnsLoggingStatus.mockReset();
    enableDnsDebugLogging.mockReset();
    disableDnsDebugLogging.mockReset();
    useDnsDhcpStore.getState().clear();
    inspectPathKind.mockRejectedValue(new Error("missing"));
    listLogFolder.mockRejectedValue(new Error("missing"));
    openLogFile.mockRejectedValue(new Error("missing"));
  });

  afterEach(() => {
    cleanup();
  });

  it("does not offer Disable for logging configured outside this app", async () => {
    checkDnsLoggingStatus.mockResolvedValue({
      dnsServerInstalled: true, dhcpServerInstalled: false,
      debugLoggingEnabled: true, logFilePath: null,
      canRestoreLogging: false, restoreError: null,
    });
    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    await screen.findByText("Server Status");
    expect(screen.queryByRole("button", { name: "Disable DNS debug logging" })).toBeNull();
  });

  it("offers saved-state recovery when an interrupted enable left logging off", async () => {
    checkDnsLoggingStatus.mockResolvedValue({
      dnsServerInstalled: true, dhcpServerInstalled: false,
      debugLoggingEnabled: false, logFilePath: null,
      canRestoreLogging: true, restoreError: null,
    });
    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    await screen.findByText("Server Status");
    expect(screen.getByRole("button", { name: "Disable DNS debug logging" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Enable DNS debug logging" })).toBeNull();
  });

  it("shows an ownership error and suppresses changes even without DNS discovery", async () => {
    checkDnsLoggingStatus.mockResolvedValue({
      dnsServerInstalled: false, dhcpServerInstalled: false,
      debugLoggingEnabled: false, logFilePath: null,
      canRestoreLogging: false, restoreError: "Saved DNS settings need manual reconciliation.",
    });
    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    await screen.findByText("Server Status");
    expect(screen.getByText("Saved DNS settings need manual reconciliation.")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Enable DNS debug logging" })).toBeNull();
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
      canRestoreLogging: false, restoreError: null,
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

  it("says what enabling costs before the button is pressed (DNS-004)", async () => {
    checkDnsLoggingStatus.mockResolvedValue({
      dnsServerInstalled: true,
      dhcpServerInstalled: false,
      debugLoggingEnabled: false,
      canRestoreLogging: false, restoreError: null,
      logFilePath: "C:\\Windows\\System32\\dns\\dns.log",
    });

    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));

    await screen.findByText("Server Status");
    // The warning belongs before the click, and it has to name the file and the
    // growth rather than warn in the abstract.
    const warning = screen.getByText(/Review the server's file size and rollover settings/);
    expect(warning).toBeVisible();
    expect(warning.textContent).toContain("C:\\Windows\\System32\\dns\\dns.log");
    expect(
      screen.getByRole("button", { name: "Enable DNS debug logging" }),
    ).toBeEnabled();
  });

  it("offers restoration for logging enabled by this app (DNS-005)", async () => {
    checkDnsLoggingStatus.mockResolvedValue({
      dnsServerInstalled: true,
      dhcpServerInstalled: false,
      debugLoggingEnabled: true,
      canRestoreLogging: true, restoreError: null,
      logFilePath: "C:\\Windows\\System32\\dns\\dns.log",
    });
    disableDnsDebugLogging.mockResolvedValue("DNS debug logging disabled.");

    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));

    const disable = await screen.findByRole("button", {
      name: "Disable DNS debug logging",
    });
    fireEvent.click(disable);

    await waitFor(() => expect(disableDnsDebugLogging).toHaveBeenCalled());
    // A one-way switch was the defect: the enable must not still be offered.
    expect(
      screen.queryByRole("button", { name: "Enable DNS debug logging" }),
    ).toBeNull();
  });


  it("refreshes ownership after an enable fails after saving the baseline", async () => {
    checkDnsLoggingStatus
      .mockResolvedValueOnce({ dnsServerInstalled: true, dhcpServerInstalled: false,
        debugLoggingEnabled: false, logFilePath: null, canRestoreLogging: false, restoreError: null })
      .mockResolvedValueOnce({ dnsServerInstalled: true, dhcpServerInstalled: false,
        debugLoggingEnabled: false, logFilePath: null, canRestoreLogging: true, restoreError: null });
    enableDnsDebugLogging.mockRejectedValue(new Error("Change could not be verified."));
    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    fireEvent.click(await screen.findByRole("button", { name: "Enable DNS debug logging" }));
    expect(await screen.findByRole("button", { name: "Disable DNS debug logging" })).toBeEnabled();
    expect(screen.getByText("Failed: Change could not be verified.")).toBeVisible();
    expect(checkDnsLoggingStatus).toHaveBeenCalledTimes(2);
  });

  it("removes stale actionable status when refresh fails", async () => {
    checkDnsLoggingStatus
      .mockResolvedValueOnce({ dnsServerInstalled: true, dhcpServerInstalled: false,
        debugLoggingEnabled: true, logFilePath: null, canRestoreLogging: true, restoreError: null })
      .mockRejectedValueOnce(new Error("offline"));
    disableDnsDebugLogging.mockRejectedValue(new Error("restore failed"));
    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    fireEvent.click(await screen.findByRole("button", { name: "Disable DNS debug logging" }));
    expect(await screen.findByText(/status could not be refreshed/)).toBeVisible();
    expect(screen.queryByRole("button", { name: "Disable DNS debug logging" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Enable DNS debug logging" })).toBeNull();
    expect(screen.getByRole("button", { name: "Scan this server" })).toBeEnabled();
  });

  it("keeps recovery accessible after scan loads a log and after remount", async () => {
    checkDnsLoggingStatus.mockResolvedValue({ dnsServerInstalled: true, dhcpServerInstalled: false,
      debugLoggingEnabled: true, logFilePath: "C:\\Logs\\dns.log", canRestoreLogging: true, restoreError: null });
    inspectPathKind.mockResolvedValue("file");
    openLogFile.mockResolvedValue({ formatDetected: "DnsDebug", entries: [entry({ id: 1, format: "DnsDebug" })] });
    const view = render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    expect(await screen.findByRole("button", { name: "Disable DNS debug logging" })).toBeEnabled();
    expect(useDnsDhcpStore.getState().sources.length).toBeGreaterThan(0);
    view.unmount();
    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    expect(await screen.findByRole("button", { name: "Disable DNS debug logging" })).toBeEnabled();
  });

  it("refreshes a full enable/restore round trip and prevents overlapping actions", async () => {
    const off = { dnsServerInstalled: true, dhcpServerInstalled: false,
      debugLoggingEnabled: false, logFilePath: null, canRestoreLogging: false, restoreError: null };
    checkDnsLoggingStatus.mockResolvedValueOnce(off)
      .mockResolvedValueOnce({ ...off, debugLoggingEnabled: true, canRestoreLogging: true })
      .mockResolvedValueOnce(off);
    let finishEnable!: (value: string) => void;
    enableDnsDebugLogging.mockReturnValue(new Promise<string>((resolve) => { finishEnable = resolve; }));
    disableDnsDebugLogging.mockResolvedValue("Prior settings restored.");
    render(<DnsDhcpWorkspace />);
    fireEvent.click(screen.getByRole("button", { name: "Scan this server" }));
    fireEvent.click(await screen.findByRole("button", { name: "Enable DNS debug logging" }));
    expect(screen.getByRole("button", { name: "Scan this server" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Enabling..." })).toBeDisabled();
    finishEnable("Enabled with saved settings.");
    fireEvent.click(await screen.findByRole("button", { name: "Disable DNS debug logging" }));
    expect(await screen.findByRole("button", { name: "Enable DNS debug logging" })).toBeEnabled();
    expect(screen.getByText("Prior settings restored.")).toBeVisible();
    expect(enableDnsDebugLogging).toHaveBeenCalledTimes(1);
    expect(disableDnsDebugLogging).toHaveBeenCalledTimes(1);
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

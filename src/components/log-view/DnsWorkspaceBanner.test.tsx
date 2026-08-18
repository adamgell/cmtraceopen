import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DnsWorkspaceBanner } from "./DnsWorkspaceBanner";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { useDnsDhcpStore } from "../../workspaces/dns-dhcp/dns-dhcp-store";
import type { LogEntry, ParserSelectionInfo } from "../../types/log";

const parser: ParserSelectionInfo = {
  parser: "dnsDebug",
  implementation: "dnsDebug",
  provenance: "dedicated",
  parseQuality: "structured",
  recordFraming: "logicalRecord",
  dateOrder: null,
};

function dnsEntry(): LogEntry {
  return {
    id: 1,
    lineNumber: 1,
    message: "QUERY A contoso.local",
    component: null,
    timestamp: Date.parse("2026-07-26T12:00:00Z"),
    timestampDisplay: "2026-07-26 12:00:00.000",
    severity: "Info",
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "DnsDebug",
    filePath: "C:/Logs/DNSServer/DNSServer_debug.log",
    timezoneOffset: null,
    sourceIp: "192.168.2.9:54159",
    queryName: "contoso.local",
  };
}

describe("DnsWorkspaceBanner", () => {
  beforeEach(() => {
    useLogStore.getState().clear();
    useDnsDhcpStore.getState().clear();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({
      activeWorkspace: "log",
      activeView: "log",
      currentPlatform: "windows",
      enabledWorkspaces: null,
    });
    useLogStore.setState({
      openFilePath: "C:/Logs/DNSServer/DNSServer_debug.log",
      formatDetected: "DnsDebug",
      parserSelection: parser,
      entries: [dnsEntry()],
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("offers a DNS/DHCP handoff and dismisses for the session", () => {
    render(<DnsWorkspaceBanner />);
    expect(
      screen.getByText(/This looks like a DNS debug log/),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Open in workspace" }));
    expect(useUiStore.getState().activeWorkspace).toBe("dns-dhcp");
    expect(useDnsDhcpStore.getState().sources).toEqual([
      expect.objectContaining({
        path: "C:/Logs/DNSServer/DNSServer_debug.log",
        fileName: "DNSServer_debug.log",
        format: "DnsDebug",
      }),
    ]);

    cleanup();
    useUiStore.setState({ activeWorkspace: "log", activeView: "log" });
    render(<DnsWorkspaceBanner />);
    fireEvent.click(screen.getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText(/This looks like a DNS debug log/)).toBeNull();

    cleanup();
    render(<DnsWorkspaceBanner />);
    expect(screen.queryByText(/This looks like a DNS debug log/)).toBeNull();
});
});

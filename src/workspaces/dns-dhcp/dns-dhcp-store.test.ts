import { beforeEach, describe, expect, it } from "vitest";
import type { LogEntry } from "../../types/log";
import { useDnsDhcpStore } from "./dns-dhcp-store";

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

describe("dns-dhcp-store (DNS-003)", () => {
  beforeEach(() => {
    useDnsDhcpStore.getState().clear();
  });

  it("joins DNS queries and DHCP leases onto one device by IPv4, stripping the query port", () => {
    const dns = entry({
      id: 1,
      format: "DnsDebug",
      filePath: "C:\\\\Windows\\\\System32\\\\dns\\\\dns.log",
      sourceIp: "192.168.2.9:54159",
      queryName: "host.contoso.com",
      queryType: "A",
      responseCode: "NXDOMAIN",
    });
    const dhcp = entry({
      id: 2,
      format: "Plain",
      filePath: "C:\\\\Windows\\\\System32\\\\dhcp\\\\DhcpSrvLog-Mon.log",
      ipAddress: "192.168.2.9",
      hostName: "PC01",
      macAddress: "aa:bb:cc:dd:ee:ff",
    });

    useDnsDhcpStore.getState().addSource(
      dns.filePath,
      "dns.log",
      "DnsDebug",
      [dns],
    );
    useDnsDhcpStore.getState().addSource(
      dhcp.filePath,
      "DhcpSrvLog-Mon.log",
      "Plain",
      [dhcp],
    );

    const { devices, selectedDeviceIp } = useDnsDhcpStore.getState();
    expect(devices).toHaveLength(1);
    expect(devices[0].ip).toBe("192.168.2.9");
    expect(devices[0].hostname).toBe("PC01");
    expect(devices[0].mac).toBe("aa:bb:cc:dd:ee:ff");
    expect(devices[0].isEnriched).toBe(true);
    expect(devices[0].nxdomainCount).toBe(1);
    expect(devices[0].totalQueries).toBe(1);
    expect(selectedDeviceIp).toBe("192.168.2.9");
  });

  it("does not strip IPv6 addresses that contain colons", () => {
    useDnsDhcpStore.getState().addSource("dns.log", "dns.log", "DnsDebug", [
      entry({
        id: 1,
        format: "DnsDebug",
        filePath: "dns.log",
        sourceIp: "fe80::1234",
        queryName: "ipv6.contoso.com",
        queryType: "AAAA",
        responseCode: "NOERROR",
      }),
    ]);

    expect(useDnsDhcpStore.getState().devices[0].ip).toBe("fe80::1234");
  });

  it("filters the device list by hostname, IP, or MAC search", () => {
    useDnsDhcpStore.getState().addSource("dns.log", "dns.log", "DnsDebug", [
      entry({
        id: 1,
        format: "DnsDebug",
        filePath: "dns.log",
        sourceIp: "10.0.0.2",
        queryName: "a.contoso.com",
        responseCode: "NOERROR",
      }),
      entry({
        id: 2,
        format: "DnsDebug",
        filePath: "dns.log",
        sourceIp: "10.0.0.3",
        queryName: "b.contoso.com",
        responseCode: "SERVFAIL",
      }),
    ]);
    useDnsDhcpStore.getState().addSource("dhcp.log", "dhcp.log", "Plain", [
      entry({
        id: 3,
        filePath: "dhcp.log",
        ipAddress: "10.0.0.2",
        hostName: "LAPTOP-A",
        macAddress: "00:11:22:33:44:55",
      }),
    ]);

    expect(useDnsDhcpStore.getState().devices).toHaveLength(2);
    useDnsDhcpStore.getState().setSearchQuery("laptop");
    expect(useDnsDhcpStore.getState().searchQuery).toBe("laptop");
  });
});

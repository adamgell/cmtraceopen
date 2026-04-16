import { create } from "zustand";
import type { LogEntry, LogFormat } from "../../types/log";
import type { Device, SourceFile } from "./types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Strip a trailing port from an IP string (e.g. "192.168.2.9:54159" → "192.168.2.9").
 * Only strips when everything after the last colon is purely decimal digits,
 * so IPv6 addresses like "::1" are not mangled. */
/** Strip a trailing port from an IPv4:port string (e.g. "192.168.2.9:54159" -> "192.168.2.9").
 * Only strips when the address contains a dot (IPv4) and the suffix after the last colon
 * is all digits. IPv6 addresses like "::1" or "fe80::1234" are left untouched. */
function stripPort(ip: string): string {
  if (!ip.includes(".")) return ip; // IPv6 or simple hostname — no stripping
  const lastColon = ip.lastIndexOf(":");
  if (lastColon === -1) return ip;
  const after = ip.slice(lastColon + 1);
  if (/^\d+$/.test(after)) {
    return ip.slice(0, lastColon);
  }
  return ip;
}

/** Build a Device[] from a flat array of log entries.
 *
 * DNS entries (format === "DnsDebug" | "DnsAudit") are keyed by stripped sourceIp.
 * DHCP entries are keyed by ipAddress (present regardless of format).
 * The two groups are unioned per IP address, then sorted by totalQueries descending. */
function buildDevices(entries: LogEntry[]): Device[] {
  // Group DNS entries by source IP (stripped of port)
  const dnsByIp = new Map<string, LogEntry[]>();
  // Group DHCP entries by IP address
  const dhcpByIp = new Map<string, LogEntry[]>();

  for (const entry of entries) {
    const isDns = entry.format === "DnsDebug" || entry.format === "DnsAudit";
    if (isDns && entry.sourceIp != null) {
      const ip = stripPort(entry.sourceIp);
      if (!dnsByIp.has(ip)) dnsByIp.set(ip, []);
      dnsByIp.get(ip)!.push(entry);
    }
    if (entry.ipAddress != null) {
      const ip = entry.ipAddress;
      if (!dhcpByIp.has(ip)) dhcpByIp.set(ip, []);
      dhcpByIp.get(ip)!.push(entry);
    }
  }

  // Union of all IPs
  const allIps = new Set<string>([...dnsByIp.keys(), ...dhcpByIp.keys()]);

  const devices: Device[] = [];

  for (const ip of allIps) {
    const dnsEntries = dnsByIp.get(ip) ?? [];
    const dhcpEntries = dhcpByIp.get(ip) ?? [];

    // DNS metrics
    let totalQueries = 0;
    let nxdomainCount = 0;
    let servfailCount = 0;

    for (const e of dnsEntries) {
      totalQueries++;
      const rcode = e.responseCode?.toUpperCase();
      if (rcode === "NXDOMAIN") nxdomainCount++;
      else if (rcode === "SERVFAIL") servfailCount++;
    }

    // DHCP enrichment — pick the latest DHCP entry for hostname/mac
    let hostname: string | null = null;
    let mac: string | null = null;
    if (dhcpEntries.length > 0) {
      const latest = dhcpEntries.reduce((best, e) => {
        const bestTs = best.timestamp ?? -Infinity;
        const eTs = e.timestamp ?? -Infinity;
        return eTs > bestTs ? e : best;
      });
      hostname = latest.hostName ?? null;
      mac = latest.macAddress ?? null;
    }

    // firstSeen / lastSeen across all entries for this IP
    const allForIp = [...dnsEntries, ...dhcpEntries];
    let firstSeen = Infinity;
    let lastSeen = -Infinity;
    for (const e of allForIp) {
      if (e.timestamp != null) {
        if (e.timestamp < firstSeen) firstSeen = e.timestamp;
        if (e.timestamp > lastSeen) lastSeen = e.timestamp;
      }
    }
    // Fallback to 0 if no timestamps found
    if (!isFinite(firstSeen)) firstSeen = 0;
    if (!isFinite(lastSeen)) lastSeen = 0;

    // Merge and sort all entries by timestamp for the detail view
    const allForDevice = [...dnsEntries, ...dhcpEntries];
    allForDevice.sort((a, b) => (a.timestamp ?? 0) - (b.timestamp ?? 0));

    devices.push({
      ip,
      hostname,
      mac,
      isEnriched: dhcpEntries.length > 0,
      totalQueries,
      nxdomainCount,
      servfailCount,
      firstSeen,
      lastSeen,
      dnsEntries,
      dhcpEntries,
      allEntries: allForDevice,
    });
  }

  // Sort by totalQueries descending
  devices.sort((a, b) => b.totalQueries - a.totalQueries);

  return devices;
}

// ---------------------------------------------------------------------------
// Store shape
// ---------------------------------------------------------------------------

interface DnsDhcpState {
  sources: SourceFile[];
  allEntries: LogEntry[];
  devices: Device[];
  selectedDeviceIp: string | null;
  searchQuery: string;
  rcodeFilter: string;
  qtypeFilter: string;
  isLoading: boolean;
  loadError: string | null;

  addSource: (path: string, fileName: string, format: LogFormat, entries: LogEntry[]) => void;
  batchAddSources: (batch: Array<{ path: string; fileName: string; format: LogFormat; entries: LogEntry[] }>) => void;
  toggleSource: (path: string) => void;
  removeSource: (path: string) => void;
  selectDevice: (ip: string | null) => void;
  setSearchQuery: (query: string) => void;
  setRcodeFilter: (rcode: string) => void;
  setQtypeFilter: (qtype: string) => void;
  setLoading: (loading: boolean) => void;
  setLoadError: (error: string | null) => void;
  clear: () => void;
}

// ---------------------------------------------------------------------------
// Internal helper used by multiple actions
// ---------------------------------------------------------------------------

/** Re-derives devices from only the enabled sources' entries. */
function rebuildDevices(sources: SourceFile[], allEntries: LogEntry[]): Device[] {
  const enabledPaths = new Set(sources.filter((s) => s.enabled).map((s) => s.path));
  const filtered = allEntries.filter((e) => enabledPaths.has(e.filePath));
  return buildDevices(filtered);
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export const useDnsDhcpStore = create<DnsDhcpState>((set, get) => ({
  sources: [],
  allEntries: [],
  devices: [],
  selectedDeviceIp: null,
  searchQuery: "",
  rcodeFilter: "All",
  qtypeFilter: "All",
  isLoading: false,
  loadError: null,

  addSource: (path, fileName, format, entries) => {
    const state = get();
    // Skip if this path is already loaded
    if (state.sources.some((s) => s.path === path)) return;

    const newSource: SourceFile = {
      path,
      fileName,
      format,
      entryCount: entries.length,
      enabled: true,
    };

    const newSources = [...state.sources, newSource];
    const newAllEntries = [...state.allEntries, ...entries];
    const newDevices = rebuildDevices(newSources, newAllEntries);

    // Auto-select the most active device if nothing is selected yet
    let selectedDeviceIp = state.selectedDeviceIp;
    if (selectedDeviceIp === null && newDevices.length > 0) {
      selectedDeviceIp = newDevices[0].ip;
    }

    set({
      sources: newSources,
      allEntries: newAllEntries,
      devices: newDevices,
      selectedDeviceIp,
    });
  },

  batchAddSources: (batch) => {
    const state = get();
    const existingPaths = new Set(state.sources.map((s) => s.path));

    const newSources = [...state.sources];
    const newEntries = [...state.allEntries];

    for (const item of batch) {
      if (existingPaths.has(item.path)) continue;
      existingPaths.add(item.path);
      newSources.push({
        path: item.path,
        fileName: item.fileName,
        format: item.format,
        entryCount: item.entries.length,
        enabled: true,
      });
      newEntries.push(...item.entries);
    }

    if (newSources.length === state.sources.length) return; // nothing new

    const newDevices = rebuildDevices(newSources, newEntries);
    let selectedDeviceIp = state.selectedDeviceIp;
    if (selectedDeviceIp === null && newDevices.length > 0) {
      selectedDeviceIp = newDevices[0].ip;
    }

    set({
      sources: newSources,
      allEntries: newEntries,
      devices: newDevices,
      selectedDeviceIp,
      isLoading: false,
      loadError: null,
    });
  },

  toggleSource: (path) => {
    const state = get();
    const newSources = state.sources.map((s) =>
      s.path === path ? { ...s, enabled: !s.enabled } : s,
    );
    const newDevices = rebuildDevices(newSources, state.allEntries);
    set({ sources: newSources, devices: newDevices });
  },

  removeSource: (path) => {
    const state = get();
    const newSources = state.sources.filter((s) => s.path !== path);
    const newAllEntries = state.allEntries.filter((e) => e.filePath !== path);
    const newDevices = rebuildDevices(newSources, newAllEntries);

    // Reset selection if the selected device is no longer present
    const stillExists =
      state.selectedDeviceIp !== null &&
      newDevices.some((d) => d.ip === state.selectedDeviceIp);
    const selectedDeviceIp = stillExists ? state.selectedDeviceIp : null;

    set({
      sources: newSources,
      allEntries: newAllEntries,
      devices: newDevices,
      selectedDeviceIp,
    });
  },

  selectDevice: (ip) => set({ selectedDeviceIp: ip }),

  setSearchQuery: (query) => set({ searchQuery: query }),

  setRcodeFilter: (rcode) => set({ rcodeFilter: rcode }),

  setQtypeFilter: (qtype) => set({ qtypeFilter: qtype }),

  setLoading: (loading) => set({ isLoading: loading }),

  setLoadError: (error) => set({ loadError: error }),

  clear: () =>
    set({
      sources: [],
      allEntries: [],
      devices: [],
      selectedDeviceIp: null,
      searchQuery: "",
      rcodeFilter: "All",
      qtypeFilter: "All",
      isLoading: false,
      loadError: null,
    }),
}));

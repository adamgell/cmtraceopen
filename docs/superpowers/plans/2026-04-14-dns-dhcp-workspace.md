# DNS/DHCP Cross-Origin Workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a device-centric workspace that correlates DNS and DHCP log data for troubleshooting DNS failures and tracking device lifecycle.

**Architecture:** Frontend-only workspace using existing `open_log_file()` backend command. Client-side correlation groups DNS entries by `source_ip` and enriches with DHCP `ip_address`/`hostname`/`mac_address`. Two-panel layout: device list (left) + device detail with query table (right). Zustand store manages state. Progressive enrichment — works with any combination of DNS/DHCP sources.

**Tech Stack:** React 19, Zustand, Fluent UI, TanStack Virtual (all already in project). No new backend code or dependencies.

**Spec:** `docs/superpowers/specs/2026-04-14-dns-dhcp-workspace-design.md`

---

### Task 1: Types and Store Foundation

**Files:**
- Create: `src/src-react/workspaces/dns-dhcp/types.ts`
- Create: `src/src-react/workspaces/dns-dhcp/dns-dhcp-store.ts`

- [ ] **Step 1: Create `types.ts` with Device and SourceFile interfaces**

Create `src/src-react/workspaces/dns-dhcp/types.ts`:

```typescript
import type { LogEntry, LogFormat } from "../../types/log";

export interface SourceFile {
  path: string;
  fileName: string;
  format: LogFormat;
  entryCount: number;
  enabled: boolean;
}

export interface Device {
  ip: string;
  hostname: string | null;
  mac: string | null;
  isEnriched: boolean;

  totalQueries: number;
  nxdomainCount: number;
  servfailCount: number;
  firstSeen: number;
  lastSeen: number;

  dhcpEntries: LogEntry[];
  dnsEntries: LogEntry[];
}
```

- [ ] **Step 2: Create `dns-dhcp-store.ts` with Zustand store**

Create `src/src-react/workspaces/dns-dhcp/dns-dhcp-store.ts`:

```typescript
import { create } from "zustand";
import type { LogEntry, LogFormat } from "../../types/log";
import type { Device, SourceFile } from "./types";

function stripPort(ip: string): string {
  // IPv6 with port: [::1]:54159 — not expected here
  // IPv4 with port: 192.168.2.9:54159
  const lastColon = ip.lastIndexOf(":");
  if (lastColon === -1) return ip;
  // Check if everything after last colon is digits (port)
  const afterColon = ip.substring(lastColon + 1);
  if (/^\d+$/.test(afterColon)) {
    return ip.substring(0, lastColon);
  }
  return ip; // IPv6 address without port
}

function buildDevices(entries: LogEntry[]): Device[] {
  const dnsByIp = new Map<string, LogEntry[]>();
  const dhcpByIp = new Map<string, LogEntry[]>();

  for (const entry of entries) {
    const format = entry.format;

    if (format === "DnsDebug" || format === "DnsAudit") {
      const rawIp = entry.sourceIp;
      if (!rawIp) continue;
      const ip = stripPort(rawIp);
      const list = dnsByIp.get(ip);
      if (list) {
        list.push(entry);
      } else {
        dnsByIp.set(ip, [entry]);
      }
    } else if (format === "Ccm" || format === "Simple" || format === "Plain" || format === "Timestamped") {
      // Check if this is actually a DHCP entry by checking ipAddress field
      if (entry.ipAddress) {
        const ip = entry.ipAddress;
        const list = dhcpByIp.get(ip);
        if (list) {
          list.push(entry);
        } else {
          dhcpByIp.set(ip, [entry]);
        }
      }
    }
  }

  const allIps = new Set([...dnsByIp.keys(), ...dhcpByIp.keys()]);
  const devices: Device[] = [];

  for (const ip of allIps) {
    const dnsEntries = dnsByIp.get(ip) ?? [];
    const dhcpEntries = dhcpByIp.get(ip) ?? [];

    let hostname: string | null = null;
    let mac: string | null = null;
    const isEnriched = dhcpEntries.length > 0;

    if (isEnriched) {
      // Take hostname/mac from latest DHCP entry
      for (const e of dhcpEntries) {
        if (e.hostName) hostname = e.hostName;
        if (e.macAddress) mac = e.macAddress;
      }
    }

    const allTimestamps = [...dnsEntries, ...dhcpEntries]
      .map((e) => e.timestamp)
      .filter((t): t is number => t != null);

    const nxdomainCount = dnsEntries.filter(
      (e) => e.responseCode === "NXDOMAIN"
    ).length;
    const servfailCount = dnsEntries.filter(
      (e) => e.responseCode === "SERVFAIL"
    ).length;

    devices.push({
      ip,
      hostname,
      mac,
      isEnriched,
      totalQueries: dnsEntries.length,
      nxdomainCount,
      servfailCount,
      firstSeen: allTimestamps.length > 0 ? Math.min(...allTimestamps) : 0,
      lastSeen: allTimestamps.length > 0 ? Math.max(...allTimestamps) : 0,
      dhcpEntries,
      dnsEntries,
    });
  }

  // Sort by total queries descending (most active first)
  devices.sort((a, b) => b.totalQueries - a.totalQueries);
  return devices;
}

interface DnsDhcpState {
  // Data
  sources: SourceFile[];
  allEntries: LogEntry[];

  // Derived
  devices: Device[];
  selectedDeviceIp: string | null;

  // Filtering
  searchQuery: string;
  rcodeFilter: string;
  qtypeFilter: string;

  // Analysis state
  isLoading: boolean;
  loadError: string | null;

  // Actions
  addSource: (path: string, fileName: string, format: LogFormat, entries: LogEntry[]) => void;
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

function rebuildDevices(state: { sources: SourceFile[]; allEntries: LogEntry[] }): Device[] {
  const enabledPaths = new Set(
    state.sources.filter((s) => s.enabled).map((s) => s.path)
  );
  const activeEntries = state.allEntries.filter((e) =>
    enabledPaths.has(e.filePath)
  );
  return buildDevices(activeEntries);
}

export const useDnsDhcpStore = create<DnsDhcpState>((set) => ({
  sources: [],
  allEntries: [],
  devices: [],
  selectedDeviceIp: null,
  searchQuery: "",
  rcodeFilter: "All",
  qtypeFilter: "All",
  isLoading: false,
  loadError: null,

  addSource: (path, fileName, format, entries) =>
    set((state) => {
      // Skip if already loaded
      if (state.sources.some((s) => s.path === path)) return state;

      const newSources = [
        ...state.sources,
        { path, fileName, format, entryCount: entries.length, enabled: true },
      ];
      const newEntries = [...state.allEntries, ...entries];
      const devices = buildDevices(newEntries);

      return {
        sources: newSources,
        allEntries: newEntries,
        devices,
        // Auto-select most active device if none selected
        selectedDeviceIp:
          state.selectedDeviceIp ?? (devices.length > 0 ? devices[0].ip : null),
        isLoading: false,
        loadError: null,
      };
    }),

  toggleSource: (path) =>
    set((state) => {
      const newSources = state.sources.map((s) =>
        s.path === path ? { ...s, enabled: !s.enabled } : s
      );
      const newState = { ...state, sources: newSources };
      const devices = rebuildDevices(newState);
      return { sources: newSources, devices };
    }),

  removeSource: (path) =>
    set((state) => {
      const newSources = state.sources.filter((s) => s.path !== path);
      const newEntries = state.allEntries.filter((e) => e.filePath !== path);
      const devices = buildDevices(newEntries);
      return {
        sources: newSources,
        allEntries: newEntries,
        devices,
        selectedDeviceIp:
          devices.find((d) => d.ip === state.selectedDeviceIp)
            ? state.selectedDeviceIp
            : devices.length > 0
              ? devices[0].ip
              : null,
      };
    }),

  selectDevice: (ip) => set({ selectedDeviceIp: ip }),
  setSearchQuery: (query) => set({ searchQuery: query }),
  setRcodeFilter: (rcode) => set({ rcodeFilter: rcode }),
  setQtypeFilter: (qtype) => set({ qtypeFilter: qtype }),
  setLoading: (loading) => set({ isLoading: loading }),
  setLoadError: (error) => set({ loadError: error, isLoading: false }),
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
```

- [ ] **Step 3: Verify TypeScript compiles**

```bash
npx tsc --noEmit
```

Expected: zero errors.

- [ ] **Step 4: Commit**

```bash
git add src/src-react/workspaces/dns-dhcp/types.ts src/src-react/workspaces/dns-dhcp/dns-dhcp-store.ts
git commit -m "feat(dns-dhcp): add workspace types and Zustand store with device correlation logic"
```

---

### Task 2: Workspace Registration

**Files:**
- Create: `src/src-react/workspaces/dns-dhcp/index.ts`
- Modify: `src/src-react/workspaces/registry.ts`
- Modify: `src/src-react/types/log.ts`

- [ ] **Step 1: Add `dns-dhcp` to `WorkspaceId` type**

In `src/src-react/types/log.ts`, add `| "dns-dhcp"` to the `WorkspaceId` type:

```typescript
export type WorkspaceId =
  | "log"
  | "intune"
  | "new-intune"
  | "dsregcmd"
  | "macos-diag"
  | "deployment"
  | "event-log"
  | "sysmon"
  | "dns-dhcp";
```

- [ ] **Step 2: Create placeholder workspace component files**

Create `src/src-react/workspaces/dns-dhcp/DnsDhcpWorkspace.tsx`:

```tsx
export function DnsDhcpWorkspace() {
  return <div style={{ padding: 24 }}>DNS / DHCP Workspace — loading...</div>;
}
```

Create `src/src-react/workspaces/dns-dhcp/DnsDhcpSidebar.tsx`:

```tsx
export function DnsDhcpSidebar() {
  return null;
}
```

- [ ] **Step 3: Create workspace definition in `index.ts`**

Create `src/src-react/workspaces/dns-dhcp/index.ts`:

```typescript
import { startTransition, lazy } from "react";
import type { WorkspaceDefinition } from "../types";

const ACCEPTED_FORMATS = new Set(["DnsDebug", "DnsAudit"]);
const ACCEPTED_PARSERS = new Set(["dnsDebug", "dnsAudit", "dhcp"]);

export const dnsDhcpWorkspace: WorkspaceDefinition = {
  id: "dns-dhcp",
  label: "DNS / DHCP",
  platforms: "all",
  component: lazy(() =>
    import("./DnsDhcpWorkspace").then((m) => ({ default: m.DnsDhcpWorkspace }))
  ),
  sidebar: lazy(() =>
    import("./DnsDhcpSidebar").then((m) => ({ default: m.DnsDhcpSidebar }))
  ),
  capabilities: {
    fontSizing: true,
  },
  fileFilters: [
    { name: "DNS/DHCP Logs", extensions: ["log", "evtx"] },
    { name: "All Files", extensions: ["*"] },
  ],
  actionLabels: {
    file: "Open DNS/DHCP File",
    folder: "Open Log Folder",
    placeholder: "Open DNS or DHCP logs...",
  },
  onOpenSource: async (source, trigger) => {
    const [{ useUiStore }, { getLogSourcePath }, { openLogFile }, { useDnsDhcpStore }] =
      await Promise.all([
        import("../../stores/ui-store"),
        import("../../lib/log-source"),
        import("../../lib/commands"),
        import("./dns-dhcp-store"),
      ]);

    useUiStore.getState().ensureWorkspaceVisible("dns-dhcp", trigger);
    const sourcePath = getLogSourcePath(source);
    const fileName = sourcePath.split(/[\\/]/).pop() ?? sourcePath;

    useDnsDhcpStore.getState().setLoading(true);

    try {
      const result = await openLogFile(sourcePath);
      const format = result.formatDetected;
      const parser = result.parserSelection.parser;

      if (!ACCEPTED_FORMATS.has(format) && !ACCEPTED_PARSERS.has(parser)) {
        useDnsDhcpStore.getState().setLoadError(
          `"${fileName}" doesn't appear to be a DNS or DHCP log (detected: ${format}).`
        );
        return;
      }

      startTransition(() => {
        useDnsDhcpStore.getState().addSource(sourcePath, fileName, format, result.entries);
      });
    } catch (error) {
      useDnsDhcpStore.getState().setLoadError(
        error instanceof Error ? error.message : String(error)
      );
    }
  },
  onOpenPath: async (path) => {
    const [{ useUiStore }, { openLogFile }, { useDnsDhcpStore }] =
      await Promise.all([
        import("../../stores/ui-store"),
        import("../../lib/commands"),
        import("./dns-dhcp-store"),
      ]);

    useUiStore.getState().ensureWorkspaceVisible("dns-dhcp", "drop");
    const fileName = path.split(/[\\/]/).pop() ?? path;

    useDnsDhcpStore.getState().setLoading(true);

    try {
      const result = await openLogFile(path);
      startTransition(() => {
        useDnsDhcpStore.getState().addSource(path, fileName, result.formatDetected, result.entries);
      });
    } catch (error) {
      useDnsDhcpStore.getState().setLoadError(
        error instanceof Error ? error.message : String(error)
      );
    }
  },
};
```

- [ ] **Step 4: Register in `registry.ts`**

In `src/src-react/workspaces/registry.ts`, add the import and registration:

```typescript
import { dnsDhcpWorkspace } from "./dns-dhcp";
```

Add to the `ALL_WORKSPACES` array after `sysmonWorkspace`:

```typescript
const ALL_WORKSPACES: WorkspaceDefinition[] = [
  logWorkspace,
  intuneWorkspace,
  newIntuneWorkspace,
  dsregcmdWorkspace,
  macosDiagWorkspace,
  deploymentWorkspace,
  eventLogWorkspace,
  sysmonWorkspace,
  dnsDhcpWorkspace,
];
```

- [ ] **Step 5: Verify TypeScript compiles**

```bash
npx tsc --noEmit
```

Expected: zero errors.

- [ ] **Step 6: Commit**

```bash
git add src/src-react/workspaces/dns-dhcp/index.ts src/src-react/workspaces/dns-dhcp/DnsDhcpWorkspace.tsx src/src-react/workspaces/dns-dhcp/DnsDhcpSidebar.tsx src/src-react/workspaces/registry.ts src/src-react/types/log.ts
git commit -m "feat(dns-dhcp): register workspace with file open handlers and placeholder components"
```

---

### Task 3: Device List Component (Left Panel)

**Files:**
- Create: `src/src-react/workspaces/dns-dhcp/DeviceList.tsx`

- [ ] **Step 1: Create `DeviceList.tsx`**

Create `src/src-react/workspaces/dns-dhcp/DeviceList.tsx`:

```tsx
import { tokens, Input, Badge } from "@fluentui/react-components";
import { Search20Regular } from "@fluentui/react-icons";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import type { Device } from "./types";
import { useUiStore } from "../../stores/ui-store";
import { getLogListMetrics } from "../../lib/log-accessibility";

function DeviceRow({
  device,
  isSelected,
  onClick,
  fontSize,
}: {
  device: Device;
  isSelected: boolean;
  onClick: () => void;
  fontSize: number;
}) {
  const metrics = getLogListMetrics(fontSize);
  const hasErrors = device.nxdomainCount > 0 || device.servfailCount > 0;

  return (
    <div
      onClick={onClick}
      style={{
        padding: "6px 10px",
        cursor: "pointer",
        borderLeft: isSelected
          ? `3px solid ${tokens.colorBrandForeground1}`
          : "3px solid transparent",
        background: isSelected
          ? tokens.colorNeutralBackground1Selected
          : "transparent",
        opacity: device.isEnriched ? 1 : 0.7,
        fontSize: metrics.fontSize,
      }}
      onMouseEnter={(e) => {
        if (!isSelected)
          e.currentTarget.style.background =
            tokens.colorNeutralBackground1Hover;
      }}
      onMouseLeave={(e) => {
        if (!isSelected)
          e.currentTarget.style.background = "transparent";
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div>
          <div
            style={{
              color: device.isEnriched
                ? tokens.colorNeutralForeground1
                : tokens.colorNeutralForeground3,
              fontWeight: isSelected ? 600 : 400,
            }}
          >
            {device.hostname ?? device.ip}
          </div>
          {device.hostname && (
            <div
              style={{
                fontSize: metrics.fontSize - 1,
                color: tokens.colorNeutralForeground3,
              }}
            >
              {device.ip}
              {device.mac ? ` | ${device.mac}` : ""}
            </div>
          )}
        </div>
        <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
          {device.totalQueries > 0 && (
            <Badge
              size="small"
              appearance="filled"
              color="informative"
            >
              {device.totalQueries}
            </Badge>
          )}
          {hasErrors && (
            <Badge
              size="small"
              appearance="filled"
              color="danger"
            >
              {device.nxdomainCount + device.servfailCount}
            </Badge>
          )}
        </div>
      </div>
    </div>
  );
}

export function DeviceList() {
  const devices = useDnsDhcpStore((s) => s.devices);
  const selectedDeviceIp = useDnsDhcpStore((s) => s.selectedDeviceIp);
  const selectDevice = useDnsDhcpStore((s) => s.selectDevice);
  const searchQuery = useDnsDhcpStore((s) => s.searchQuery);
  const setSearchQuery = useDnsDhcpStore((s) => s.setSearchQuery);
  const fontSize = useUiStore((s) => s.logListFontSize);

  const filtered = devices.filter((d) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      d.ip.toLowerCase().includes(q) ||
      (d.hostname?.toLowerCase().includes(q) ?? false) ||
      (d.mac?.toLowerCase().includes(q) ?? false)
    );
  });

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        borderRight: `1px solid ${tokens.colorNeutralStroke1}`,
        width: 300,
        minWidth: 220,
      }}
    >
      <div style={{ padding: "8px 10px" }}>
        <Input
          size="small"
          placeholder="Search devices..."
          value={searchQuery}
          onChange={(_, data) => setSearchQuery(data.value)}
          contentBefore={<Search20Regular />}
          style={{ width: "100%" }}
        />
      </div>
      <div
        style={{
          flex: 1,
          overflowY: "auto",
          borderTop: `1px solid ${tokens.colorNeutralStroke1}`,
        }}
      >
        {filtered.length === 0 && (
          <div
            style={{
              padding: 16,
              color: tokens.colorNeutralForeground3,
              textAlign: "center",
              fontSize: 13,
            }}
          >
            {devices.length === 0
              ? "No devices found. Open DNS or DHCP logs."
              : "No devices match the search."}
          </div>
        )}
        {filtered.map((device) => (
          <DeviceRow
            key={device.ip}
            device={device}
            isSelected={device.ip === selectedDeviceIp}
            onClick={() => selectDevice(device.ip)}
            fontSize={fontSize}
          />
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
npx tsc --noEmit
```

- [ ] **Step 3: Commit**

```bash
git add src/src-react/workspaces/dns-dhcp/DeviceList.tsx
git commit -m "feat(dns-dhcp): add DeviceList component with search and enrichment indicators"
```

---

### Task 4: Device Detail Components (Right Panel)

**Files:**
- Create: `src/src-react/workspaces/dns-dhcp/DeviceSummaryHeader.tsx`
- Create: `src/src-react/workspaces/dns-dhcp/DeviceQueryTable.tsx`
- Create: `src/src-react/workspaces/dns-dhcp/DeviceDetail.tsx`

- [ ] **Step 1: Create `DeviceSummaryHeader.tsx`**

Create `src/src-react/workspaces/dns-dhcp/DeviceSummaryHeader.tsx`:

```tsx
import { tokens, Badge } from "@fluentui/react-components";
import type { Device } from "./types";

function formatTimestamp(ms: number): string {
  if (ms === 0) return "—";
  const d = new Date(ms);
  return d.toLocaleString();
}

export function DeviceSummaryHeader({ device }: { device: Device }) {
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 16,
        padding: "10px 16px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
        background: tokens.colorNeutralBackground2,
        fontSize: 13,
        color: tokens.colorNeutralForeground2,
      }}
    >
      <div>
        <div
          style={{
            fontSize: 15,
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
          }}
        >
          {device.hostname ?? device.ip}
        </div>
        {device.hostname && (
          <div style={{ fontSize: 12, color: tokens.colorNeutralForeground3 }}>
            {device.ip}
            {device.mac ? ` | ${device.mac}` : ""}
          </div>
        )}
      </div>
      <div style={{ display: "flex", gap: 16, alignItems: "center", flexWrap: "wrap" }}>
        <Stat label="Queries" value={device.totalQueries} />
        <Stat
          label="NXDOMAIN"
          value={device.nxdomainCount}
          color={device.nxdomainCount > 0 ? "warning" : undefined}
        />
        <Stat
          label="SERVFAIL"
          value={device.servfailCount}
          color={device.servfailCount > 0 ? "danger" : undefined}
        />
        <div>
          <div style={{ fontSize: 11, color: tokens.colorNeutralForeground3 }}>
            First seen
          </div>
          <div>{formatTimestamp(device.firstSeen)}</div>
        </div>
        <div>
          <div style={{ fontSize: 11, color: tokens.colorNeutralForeground3 }}>
            Last seen
          </div>
          <div>{formatTimestamp(device.lastSeen)}</div>
        </div>
        {device.dhcpEntries.length > 0 && (
          <div>
            <div style={{ fontSize: 11, color: tokens.colorNeutralForeground3 }}>
              DHCP events
            </div>
            <div>{device.dhcpEntries.length}</div>
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color?: "warning" | "danger";
}) {
  return (
    <div>
      <div style={{ fontSize: 11, color: tokens.colorNeutralForeground3 }}>
        {label}
      </div>
      <div>
        {color ? (
          <Badge size="small" appearance="filled" color={color}>
            {value}
          </Badge>
        ) : (
          value.toLocaleString()
        )}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create `DeviceQueryTable.tsx`**

Create `src/src-react/workspaces/dns-dhcp/DeviceQueryTable.tsx`:

```tsx
import { useMemo, useRef } from "react";
import { tokens, Dropdown, Option } from "@fluentui/react-components";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Device } from "./types";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { useUiStore } from "../../stores/ui-store";
import { getLogListMetrics } from "../../lib/log-accessibility";

const COLUMNS = [
  { id: "time", label: "Time", width: 170 },
  { id: "queryName", label: "Query Name", width: 260 },
  { id: "type", label: "Type", width: 60 },
  { id: "rcode", label: "RCODE", width: 100 },
  { id: "dir", label: "Dir", width: 45 },
  { id: "proto", label: "Proto", width: 50 },
  { id: "flags", label: "Flags", width: 80 },
];

const RCODE_OPTIONS = ["All", "NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "FORMERR"];
const QTYPE_OPTIONS = ["All", "A", "AAAA", "SOA", "NS", "PTR", "SRV", "CNAME", "MX", "TXT"];

export function DeviceQueryTable({ device }: { device: Device }) {
  const rcodeFilter = useDnsDhcpStore((s) => s.rcodeFilter);
  const qtypeFilter = useDnsDhcpStore((s) => s.qtypeFilter);
  const setRcodeFilter = useDnsDhcpStore((s) => s.setRcodeFilter);
  const setQtypeFilter = useDnsDhcpStore((s) => s.setQtypeFilter);
  const fontSize = useUiStore((s) => s.logListFontSize);
  const metrics = getLogListMetrics(fontSize);
  const parentRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    return device.dnsEntries.filter((e) => {
      if (rcodeFilter !== "All" && e.responseCode !== rcodeFilter) return false;
      if (qtypeFilter !== "All" && e.queryType !== qtypeFilter) return false;
      return true;
    });
  }, [device.dnsEntries, rcodeFilter, qtypeFilter]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => metrics.rowHeight,
    overscan: 20,
  });

  const gridTemplate = COLUMNS.map((c) => `${c.width}px`).join(" ");

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      {/* Filters */}
      <div
        style={{
          display: "flex",
          gap: 8,
          padding: "6px 16px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
          alignItems: "center",
          fontSize: 12,
        }}
      >
        <span style={{ color: tokens.colorNeutralForeground3 }}>RCODE:</span>
        <Dropdown
          size="small"
          value={rcodeFilter}
          onOptionSelect={(_, data) => setRcodeFilter(data.optionValue ?? "All")}
          style={{ minWidth: 100 }}
        >
          {RCODE_OPTIONS.map((o) => (
            <Option key={o} value={o}>
              {o}
            </Option>
          ))}
        </Dropdown>
        <span style={{ color: tokens.colorNeutralForeground3, marginLeft: 8 }}>Type:</span>
        <Dropdown
          size="small"
          value={qtypeFilter}
          onOptionSelect={(_, data) => setQtypeFilter(data.optionValue ?? "All")}
          style={{ minWidth: 80 }}
        >
          {QTYPE_OPTIONS.map((o) => (
            <Option key={o} value={o}>
              {o}
            </Option>
          ))}
        </Dropdown>
        <span style={{ color: tokens.colorNeutralForeground3, marginLeft: "auto" }}>
          {filtered.length.toLocaleString()} entries
        </span>
      </div>

      {/* Header */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: gridTemplate,
          padding: "4px 16px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
          fontSize: metrics.fontSize - 1,
          color: tokens.colorNeutralForeground3,
          fontWeight: 600,
        }}
      >
        {COLUMNS.map((c) => (
          <div key={c.id}>{c.label}</div>
        ))}
      </div>

      {/* Virtual rows */}
      <div
        ref={parentRef}
        style={{ flex: 1, overflowY: "auto" }}
      >
        <div
          style={{
            height: virtualizer.getTotalSize(),
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((virtualRow) => {
            const entry = filtered[virtualRow.index];
            const isError =
              entry.responseCode === "SERVFAIL" ||
              entry.responseCode === "REFUSED" ||
              entry.responseCode === "FORMERR";
            const isWarning = entry.responseCode === "NXDOMAIN";

            return (
              <div
                key={virtualRow.key}
                style={{
                  display: "grid",
                  gridTemplateColumns: gridTemplate,
                  position: "absolute",
                  top: virtualRow.start,
                  left: 0,
                  width: "100%",
                  height: virtualRow.size,
                  padding: "0 16px",
                  alignItems: "center",
                  fontSize: metrics.fontSize,
                  color: isError
                    ? tokens.colorPaletteRedForeground2
                    : isWarning
                      ? tokens.colorPaletteYellowForeground2
                      : tokens.colorNeutralForeground1,
                  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                }}
              >
                <div>{entry.timestampDisplay ?? "—"}</div>
                <div style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {entry.queryName ?? "—"}
                </div>
                <div>{entry.queryType ?? "—"}</div>
                <div style={{ fontWeight: isError || isWarning ? 600 : 400 }}>
                  {entry.responseCode ?? "—"}
                </div>
                <div>{entry.dnsDirection ?? "—"}</div>
                <div>{entry.dnsProtocol ?? "—"}</div>
                <div>{entry.dnsFlags ?? "—"}</div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Create `DeviceDetail.tsx`**

Create `src/src-react/workspaces/dns-dhcp/DeviceDetail.tsx`:

```tsx
import { tokens } from "@fluentui/react-components";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { DeviceSummaryHeader } from "./DeviceSummaryHeader";
import { DeviceQueryTable } from "./DeviceQueryTable";

export function DeviceDetail() {
  const devices = useDnsDhcpStore((s) => s.devices);
  const selectedDeviceIp = useDnsDhcpStore((s) => s.selectedDeviceIp);

  const device = devices.find((d) => d.ip === selectedDeviceIp) ?? null;

  if (!device) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          flex: 1,
          color: tokens.colorNeutralForeground3,
          fontSize: 14,
        }}
      >
        Select a device to view DNS activity
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <DeviceSummaryHeader device={device} />
      <DeviceQueryTable device={device} />
    </div>
  );
}
```

- [ ] **Step 4: Verify TypeScript compiles**

```bash
npx tsc --noEmit
```

- [ ] **Step 5: Commit**

```bash
git add src/src-react/workspaces/dns-dhcp/DeviceSummaryHeader.tsx src/src-react/workspaces/dns-dhcp/DeviceQueryTable.tsx src/src-react/workspaces/dns-dhcp/DeviceDetail.tsx
git commit -m "feat(dns-dhcp): add DeviceDetail with summary header and virtual-scrolled query table"
```

---

### Task 5: Main Workspace Layout and Sidebar

**Files:**
- Modify: `src/src-react/workspaces/dns-dhcp/DnsDhcpWorkspace.tsx`
- Modify: `src/src-react/workspaces/dns-dhcp/DnsDhcpSidebar.tsx`

- [ ] **Step 1: Implement `DnsDhcpWorkspace.tsx`**

Replace the placeholder with the full implementation:

```tsx
import { tokens, Spinner } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";
import { openLogFile } from "../../lib/commands";
import { startTransition } from "react";

const FILE_FILTERS = [
  { name: "DNS/DHCP Logs", extensions: ["log", "evtx"] },
  { name: "All Files", extensions: ["*"] },
];

export function DnsDhcpWorkspace() {
  const sources = useDnsDhcpStore((s) => s.sources);
  const isLoading = useDnsDhcpStore((s) => s.isLoading);
  const loadError = useDnsDhcpStore((s) => s.loadError);
  const addSource = useDnsDhcpStore((s) => s.addSource);
  const setLoading = useDnsDhcpStore((s) => s.setLoading);
  const setLoadError = useDnsDhcpStore((s) => s.setLoadError);

  const handleOpenFile = async () => {
    try {
      const selected = await open({ multiple: true, filters: FILE_FILTERS });
      if (!selected) return;
      const paths = Array.isArray(selected) ? selected : [selected];

      setLoading(true);
      for (const path of paths) {
        try {
          const result = await openLogFile(path);
          const fileName = path.split(/[\\/]/).pop() ?? path;
          startTransition(() => {
            addSource(path, fileName, result.formatDetected, result.entries);
          });
        } catch (err) {
          console.warn(`[dns-dhcp] skipping file: ${path}`, err);
        }
      }
      setLoading(false);
    } catch (error) {
      setLoadError(error instanceof Error ? error.message : String(error));
    }
  };

  // Empty state
  if (sources.length === 0 && !isLoading) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 16,
          color: tokens.colorNeutralForeground3,
        }}
      >
        <div style={{ fontSize: 20, fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
          DNS / DHCP Workspace
        </div>
        <div style={{ fontSize: 14, maxWidth: 440, textAlign: "center", lineHeight: 1.6 }}>
          Open DNS debug logs, DNS audit EVTX files, or DHCP server logs to correlate
          device activity and troubleshoot DNS resolution failures.
        </div>
        <button
          onClick={handleOpenFile}
          style={{
            padding: "8px 20px",
            fontSize: 14,
            cursor: "pointer",
            background: tokens.colorBrandBackground,
            color: tokens.colorNeutralForegroundOnBrand,
            border: "none",
            borderRadius: 4,
          }}
        >
          Open Files
        </button>
        {loadError && (
          <div style={{ color: tokens.colorPaletteRedForeground2, fontSize: 13 }}>
            {loadError}
          </div>
        )}
      </div>
    );
  }

  // Loading state
  if (isLoading && sources.length === 0) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: 12,
        }}
      >
        <Spinner size="small" />
        <span style={{ color: tokens.colorNeutralForeground2 }}>Loading...</span>
      </div>
    );
  }

  // Main two-panel layout
  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      <DeviceList />
      <DeviceDetail />
    </div>
  );
}
```

- [ ] **Step 2: Implement `DnsDhcpSidebar.tsx`**

Replace the placeholder:

```tsx
import { tokens, Switch } from "@fluentui/react-components";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { SourceSummaryCard } from "../../components/common/sidebar-primitives";
import type { LogFormat } from "../../types/log";

function formatBadge(format: LogFormat): string {
  switch (format) {
    case "DnsDebug":
      return "DNS Debug";
    case "DnsAudit":
      return "DNS Audit";
    default:
      return "DHCP";
  }
}

export function DnsDhcpSidebar() {
  const sources = useDnsDhcpStore((s) => s.sources);
  const devices = useDnsDhcpStore((s) => s.devices);
  const allEntries = useDnsDhcpStore((s) => s.allEntries);
  const toggleSource = useDnsDhcpStore((s) => s.toggleSource);
  const isLoading = useDnsDhcpStore((s) => s.isLoading);
  const loadError = useDnsDhcpStore((s) => s.loadError);

  const enrichedCount = devices.filter((d) => d.isEnriched).length;

  return (
    <>
      <SourceSummaryCard
        badge="dns-dhcp"
        title="DNS / DHCP"
        subtitle={
          sources.length === 0
            ? "Open DNS or DHCP logs to begin."
            : `${sources.length} source${sources.length !== 1 ? "s" : ""} loaded`
        }
        body={
          <div
            style={{
              fontSize: "inherit",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {isLoading && <div>Loading...</div>}
            {loadError && (
              <div style={{ color: tokens.colorPaletteRedForeground2 }}>
                {loadError}
              </div>
            )}
            {sources.length > 0 && (
              <>
                <div>Events: {allEntries.length.toLocaleString()}</div>
                <div>Devices: {devices.length}</div>
                {enrichedCount > 0 && (
                  <div>Enriched (DHCP): {enrichedCount}</div>
                )}
              </>
            )}
          </div>
        }
      />

      {sources.length > 0 && (
        <div style={{ padding: "8px 12px" }}>
          <div
            style={{
              fontSize: 11,
              fontWeight: 600,
              color: tokens.colorNeutralForeground3,
              textTransform: "uppercase",
              marginBottom: 6,
            }}
          >
            Sources
          </div>
          {sources.map((source) => (
            <div
              key={source.path}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "4px 0",
                fontSize: 12,
              }}
            >
              <div style={{ overflow: "hidden" }}>
                <div
                  style={{
                    color: tokens.colorNeutralForeground1,
                    whiteSpace: "nowrap",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                  }}
                >
                  {source.fileName}
                </div>
                <div style={{ color: tokens.colorNeutralForeground3, fontSize: 11 }}>
                  {formatBadge(source.format)} | {source.entryCount.toLocaleString()} entries
                </div>
              </div>
              <Switch
                checked={source.enabled}
                onChange={() => toggleSource(source.path)}
                style={{ marginLeft: 8 }}
              />
            </div>
          ))}
        </div>
      )}
    </>
  );
}
```

- [ ] **Step 3: Verify TypeScript compiles**

```bash
npx tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
git add src/src-react/workspaces/dns-dhcp/DnsDhcpWorkspace.tsx src/src-react/workspaces/dns-dhcp/DnsDhcpSidebar.tsx
git commit -m "feat(dns-dhcp): implement main workspace layout and sidebar with source management"
```

---

### Task 6: Auto-Detect Banner in Log Viewer

**Files:**
- Create: `src/src-react/components/log-view/DnsWorkspaceBanner.tsx`

This task adds the auto-detect prompt that appears when a DNS/DHCP file is opened in the standard log viewer.

- [ ] **Step 1: Create `DnsWorkspaceBanner.tsx`**

Create `src/src-react/components/log-view/DnsWorkspaceBanner.tsx`:

```tsx
import { useState } from "react";
import { tokens, Button } from "@fluentui/react-components";
import { Dismiss16Regular } from "@fluentui/react-icons";
import type { ParserKind } from "../../types/log";

const PARSER_LABELS: Partial<Record<ParserKind, string>> = {
  dnsDebug: "DNS debug log",
  dnsAudit: "DNS audit log",
  dhcp: "DHCP server log",
};

export function DnsWorkspaceBanner({
  parser,
  onOpenInWorkspace,
}: {
  parser: ParserKind;
  onOpenInWorkspace: () => void;
}) {
  const [dismissed, setDismissed] = useState(false);

  const label = PARSER_LABELS[parser];
  if (!label || dismissed) return null;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        padding: "6px 12px",
        background: tokens.colorNeutralBackground4,
        borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
        fontSize: 13,
        color: tokens.colorNeutralForeground2,
      }}
    >
      <span>
        This looks like a {label}. Open in the DNS/DHCP workspace for device
        correlation and query analysis?
      </span>
      <Button
        size="small"
        appearance="primary"
        onClick={onOpenInWorkspace}
      >
        Open in Workspace
      </Button>
      <Button
        size="small"
        appearance="subtle"
        icon={<Dismiss16Regular />}
        onClick={() => setDismissed(true)}
      />
    </div>
  );
}
```

- [ ] **Step 2: Integrate the banner**

Find the main log list view component. The banner should be rendered conditionally above the log list when `parserSelection.parser` is `dnsDebug`, `dnsAudit`, or `dhcp` and the active workspace is `log`. The `onOpenInWorkspace` handler should:

1. Load the current file's entries into the dns-dhcp store
2. Switch the active workspace to `dns-dhcp`

The exact integration point depends on the log view component structure — the implementer should find where the log list renders and add the banner above it.

- [ ] **Step 3: Verify TypeScript compiles**

```bash
npx tsc --noEmit
```

- [ ] **Step 4: Commit**

```bash
git add src/src-react/components/log-view/DnsWorkspaceBanner.tsx
git commit -m "feat(dns-dhcp): add auto-detect banner for DNS/DHCP files in log viewer"
```

---

### Task 7: Visual Testing and Polish

**Files:**
- No new files — this task verifies the workspace works end-to-end

- [ ] **Step 1: Build the app**

```bash
npm run app:build:exe-only
```

- [ ] **Step 2: Test with DNS debug log**

Open the app. Switch to DNS/DHCP workspace. Open `Logs/dns-fixtures-20260411-203254/DNSServer_debug.log`. Verify:
- Device list appears with source IPs
- Clicking a device shows its DNS queries
- Summary header shows correct stats
- NXDOMAIN entries are yellow, SERVFAIL are red
- RCODE and QTYPE dropdown filters work

- [ ] **Step 3: Test with DNS audit EVTX**

Open `Logs/dns-fixtures-20260411-203254/dns-audit.evtx`. Verify it adds to the workspace and merges with existing data.

- [ ] **Step 4: Test source toggling**

In the sidebar, toggle off the DNS debug source. Verify the device list updates. Toggle back on. Verify it restores.

- [ ] **Step 5: Fix any visual issues**

Address any layout, spacing, or color issues found during testing.

- [ ] **Step 6: Run final checks**

```bash
npx tsc --noEmit
```

- [ ] **Step 7: Commit fixes**

```bash
git add -A
git commit -m "fix(dns-dhcp): visual polish and layout fixes from testing"
```

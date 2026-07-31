# DNS/DHCP Cross-Origin Workspace Design

**Date:** 2026-04-14
**Status:** Draft

## Overview

A device-centric workspace that correlates DNS and DHCP log data to support two primary use cases:

1. **Troubleshooting DNS resolution failures** — "Client X got IP .15 via DHCP, then made 47 DNS queries, 3 of which got NXDOMAIN — why?"
2. **Device lifecycle tracking** — "Device DESKTOP-ABC joined at 9 AM, got IP .50, registered its A record, then started resolving internal resources."

The workspace accepts any combination of DNS debug logs, DNS audit EVTX files, and DHCP server logs. It works with whatever data is available — DNS-only shows source IPs as provisional devices, adding DHCP data enriches them with hostname and MAC.

## Architecture

### Layout: Device-Centric Two-Panel Dashboard

- **Left panel:** Device list derived from source IPs (DNS) and enriched with hostname/MAC (DHCP). Click to select.
- **Right panel:** Selected device detail — summary stats header + filterable DNS query table.

### Data Flow

1. User opens files via the workspace "Open" action, drag-drop, or auto-detect prompt from the log viewer
2. Backend parses all files through existing parsers (`dns_debug`, `dns_audit`, `dhcp`) → `Vec<LogEntry>`
3. Frontend receives `ParseResult` entries tagged by format (`DnsDebug`, `DnsAudit`, `Dhcp`)
4. Client-side correlation groups entries by source IP, builds device list
5. DHCP entries enrich the device list (IP → hostname + MAC mapping)
6. Selecting a device filters the query table to that device's DNS activity

### No New Backend Commands

The existing `parse_file()` / `open_log_file()` pipeline already handles all three formats and outputs `LogEntry` with domain-specific fields. Correlation is client-side — the data volumes are small enough (3K-5K entries typical) that JS handles it trivially.

---

## 1. Progressive Enrichment

The workspace builds a unified device model from whatever sources are loaded:

| Sources loaded | Device list shows | Detail panel shows |
|---------------|-------------------|-------------------|
| DNS debug only | Source IPs with query stats (provisional) | DNS queries from that IP |
| DNS audit only | Event IDs with zone/record info | Audit events (record creates/deletes) |
| DHCP only | Devices with hostname/MAC, zero DNS | DHCP lease events |
| DNS + DHCP | IPs enriched with hostname/MAC | DNS queries + DHCP context |
| DNS + DHCP + audit | Full picture | DNS queries + audit events + DHCP context |

Provisional (IP-only) devices are shown with a dimmed visual indicator. When DHCP data is added, matching IPs upgrade to enriched entries.

---

## 2. Device Model

```
Device:
  ip: string                       — source IP (always present)
  hostname: string | null          — from DHCP lease (enrichment)
  mac: string | null               — from DHCP lease (enrichment)
  isEnriched: boolean              — true when DHCP data matched

  totalQueries: number
  nxdomainCount: number
  servfailCount: number
  firstSeen: number                — earliest timestamp (epoch ms)
  lastSeen: number                 — latest timestamp (epoch ms)

  dhcpEntries: LogEntry[]          — DHCP events for this IP
  dnsEntries: LogEntry[]           — DNS events from this IP
```

### Correlation Logic

- Group all DNS entries by `source_ip` (strip port if present: `192.168.2.9:54159` → `192.168.2.9`)
- Group all DHCP entries by `ip_address`
- Match on IP → merge into `Device` with `isEnriched: true`
- Unmatched DNS IPs → provisional device entries (`isEnriched: false`)
- Unmatched DHCP entries → device entries with zero DNS activity

---

## 3. Store Design (`dns-dhcp-store.ts`)

```
DnsDhcpState:
  // Data
  sources: SourceFile[]            — loaded files (path, format, enabled toggle)
  allEntries: LogEntry[]           — all parsed entries from all sources

  // Derived
  devices: Device[]                — grouped by source IP, enriched from DHCP
  selectedDeviceIp: string | null  — currently selected device

  // Filtering
  searchQuery: string              — filter query table by name
  rcodeFilter: string | "All"     — filter by RCODE
  qtypeFilter: string | "All"     — filter by query type

  // Analysis state
  isLoading: boolean
  loadError: string | null
```

Zustand store following the same patterns as `sysmon-store.ts` and `dsregcmd-store.ts`.

---

## 4. Frontend Components

### File Structure

```
src/src-react/workspaces/dns-dhcp/
  index.ts                  — workspace definition + registration
  DnsDhcpWorkspace.tsx      — main two-panel layout
  DnsDhcpSidebar.tsx        — sidebar with source files list + toggles
  dns-dhcp-store.ts         — Zustand store
  types.ts                  — Device, SourceFile interfaces
  DeviceList.tsx            — left panel: scrollable device list
  DeviceDetail.tsx          — right panel: summary header + query table
  DeviceSummaryHeader.tsx   — stats bar (queries, errors, time range)
  DeviceQueryTable.tsx      — filterable DNS query table
```

### DeviceList (Left Panel)

- Scrollable list of `Device` entries, sorted by total queries (most active first)
- Each row: IP, hostname (or "unresolved" indicator), query count, error badge
- Enriched devices show hostname + MAC; provisional IPs show a dimmed icon
- Click to select → updates `selectedDeviceIp` in store
- Search/filter at top to find devices by hostname or IP

### DeviceDetail (Right Panel)

**DeviceSummaryHeader:**
- IP, hostname, MAC (when available)
- Total queries, NXDOMAIN count, SERVFAIL count
- First seen / last seen timestamps
- Lease duration (if DHCP data present)

**DeviceQueryTable:**
- Virtual-scrolled table (TanStack Virtual) showing DNS entries for the selected device
- Columns: Time, Query Name, Type, RCODE, Direction, Protocol, Flags
- Filterable by RCODE and QTYPE dropdowns
- Sortable by column

### DnsDhcpSidebar

- "Sources" section listing loaded files with format badge (DNS Debug, DNS Audit, DHCP) and toggle switch to include/exclude
- "Open File" button to add more sources
- Summary stats: total files, total events, total devices

---

## 5. Workspace Registration

**WorkspaceId:** `dns-dhcp`

**Definition:**

```
id: "dns-dhcp"
label: "DNS / DHCP"
platforms: "all"
capabilities: { fontSizing: true }
fileFilters: [
  { name: "DNS/DHCP Logs", extensions: ["log", "evtx"] },
  { name: "All Files", extensions: ["*"] }
]
actionLabels: {
  file: "Open DNS/DHCP File",
  folder: "Open Log Folder",
  placeholder: "Open DNS or DHCP logs..."
}
```

**onOpenSource handler:**
1. Parse the file via existing `open_log_file()` command
2. Check format — accept `DnsDebug`, `DnsAudit`, `Dhcp`; reject others with toast
3. Add entries to the store, rebuild device list
4. If first file, switch to workspace and select the most active device

**Multi-file drop:** User can drop multiple files at once. Each is parsed and merged into the store progressively.

**Folder open:** When a folder is opened, scan for `.log` and `.evtx` files. Parse each through `open_log_file()`, accept files that return DNS or DHCP formats, silently skip others.

**Registry:** Add to `ALL_WORKSPACES` array in `workspaces/registry.ts`.

---

## 6. Auto-Detect Prompt

When a user opens a DNS or DHCP file in the standard log viewer, show a non-intrusive banner.

**Trigger conditions:**
- `parserSelection.parser` is `dnsDebug`, `dnsAudit`, or `dhcp`
- Active workspace is `log` (not already in `dns-dhcp`)
- User hasn't dismissed the banner for this session

**Banner content:**
> "This looks like a [DNS debug log / DNS audit log / DHCP server log]. Open in the DNS/DHCP workspace for device correlation and query analysis?"
> **[Open in Workspace]** **[Dismiss]**

**Behavior:**
- "Open in Workspace" → switches to `dns-dhcp` workspace, loads the file's entries
- "Dismiss" → hides for the session (not persisted)
- Non-blocking — user can ignore and keep using the log viewer

**Implementation:** A small component in `components/log-view/` that reads `parserSelection` from the log store and conditionally renders. No parser pipeline changes.

---

## 7. File Provenance

Each entry is tagged with its source file path and format. The sidebar shows all loaded files with:
- File name
- Format badge (DNS Debug / DNS Audit / DHCP)
- Entry count
- Toggle switch to include/exclude from the view

Toggling a file off removes its entries from the device list and query table without unloading them — toggling back on restores them instantly.

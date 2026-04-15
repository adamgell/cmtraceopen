import { useState } from "react";
import { Button, Spinner, tokens } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { openLogFile, inspectPathKind, listLogFolder } from "../../lib/commands";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";

/** Well-known Windows Server log paths for auto-discovery. */
const KNOWN_DNS_PATHS = [
  "C:\\WINDOWS\\System32\\dns\\dns.log",
  "C:\\Windows\\System32\\dns\\dns.log",
];
const KNOWN_DHCP_DIRS = [
  "C:\\Windows\\System32\\dhcp",
  "C:\\WINDOWS\\system32\\dhcp",
];

const FILE_DIALOG_FILTERS = [
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
  const [localError, setLocalError] = useState<string | null>(null);

  const handleScanServer = async () => {
    setLocalError(null);
    setLoading(true);
    setLoadError(null);

    const discovered: string[] = [];

    // Check DNS debug log paths
    for (const dnsPath of KNOWN_DNS_PATHS) {
      try {
        const kind = await inspectPathKind(dnsPath);
        if (kind === "file") {
          discovered.push(dnsPath);
          break; // Only need one — they're the same file with different casing
        }
      } catch {
        // Path doesn't exist, continue
      }
    }

    // Scan DHCP log directories
    for (const dhcpDir of KNOWN_DHCP_DIRS) {
      try {
        const kind = await inspectPathKind(dhcpDir);
        if (kind !== "folder") continue;

        const listing = await listLogFolder(dhcpDir);
        for (const entry of listing.entries) {
          if (
            !entry.isDir &&
            entry.name.toLowerCase().startsWith("dhcpsrvlog") &&
            entry.name.toLowerCase().endsWith(".log")
          ) {
            discovered.push(entry.path);
          }
        }
        if (discovered.length > 1) break; // Found DHCP logs, stop checking
      } catch {
        // Directory doesn't exist, continue
      }
    }

    if (discovered.length === 0) {
      setLoading(false);
      setLocalError(
        "No DNS or DHCP logs found at standard Windows Server paths. " +
        "Use Open Files to browse manually."
      );
      return;
    }

    // Parse discovered files
    for (const path of discovered) {
      try {
        const result = await openLogFile(path);
        const fileName = path.split(/[\\/]/).pop() ?? path;
        addSource(path, fileName, result.formatDetected, result.entries);
      } catch (err) {
        console.warn(`[dns-dhcp] failed to parse discovered file: ${path}`, err);
      }
    }

    setLoading(false);
  };

  const handleOpenFiles = async () => {
    setLocalError(null);
    try {
      const selected = await open({
        multiple: true,
        filters: FILE_DIALOG_FILTERS,
      });
      if (!selected) return;

      const paths = Array.isArray(selected) ? selected : [selected];
      setLoading(true);
      setLoadError(null);

      for (const path of paths) {
        try {
          const result = await openLogFile(path);
          const format = result.formatDetected;

          const isDns = format === "DnsDebug" || format === "DnsAudit";
          const hasDhcp = result.entries.some((e) => e.ipAddress != null);

          if (!isDns && !hasDhcp) {
            console.warn(
              `[dns-dhcp] Skipping "${path}" — unsupported format "${format}"`
            );
            continue;
          }

          const fileName = path.split(/[\\/]/).pop() ?? path;
          addSource(path, fileName, format, result.entries);
        } catch (err) {
          console.error("[dns-dhcp] failed to parse file", { path, err });
        }
      }

      setLoading(false);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      setLocalError(msg);
      setLoading(false);
    }
  };

  // Loading state (first load only — no sources yet)
  if (isLoading && sources.length === 0) {
    return (
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          height: "100%",
          gap: "12px",
        }}
      >
        <Spinner size="medium" />
        <span
          style={{
            color: tokens.colorNeutralForeground2,
            fontSize: "13px",
          }}
        >
          Loading DNS/DHCP logs...
        </span>
      </div>
    );
  }

  // Empty state
  if (sources.length === 0) {
    return (
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: "24px",
          padding: "40px",
        }}
      >
        <div
          style={{
            fontSize: "18px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
          }}
        >
          DNS / DHCP Workspace
        </div>
        <div
          style={{
            fontSize: "13px",
            color: tokens.colorNeutralForeground3,
            textAlign: "center",
            maxWidth: "420px",
          }}
        >
          Open DNS debug logs, DNS audit EVTX files, or DHCP server logs to
          analyze queries, detect errors, and correlate device activity.
        </div>

        <div style={{ display: "flex", gap: 12 }}>
          <Button appearance="primary" onClick={() => void handleScanServer()}>
            Scan Server Logs
          </Button>
          <Button appearance="secondary" onClick={() => void handleOpenFiles()}>
            Open Files
          </Button>
        </div>
        <div
          style={{
            fontSize: "12px",
            color: tokens.colorNeutralForeground4,
            textAlign: "center",
            maxWidth: "420px",
          }}
        >
          Scan Server Logs checks standard Windows Server paths for DNS and DHCP logs automatically.
        </div>

        {(localError || loadError) && (
          <div
            style={{
              fontSize: "12px",
              color: tokens.colorPaletteRedForeground1,
              maxWidth: "500px",
              textAlign: "center",
            }}
          >
            {localError || loadError}
          </div>
        )}
      </div>
    );
  }

  // Active state — two-panel layout
  return (
    <div
      style={{
        display: "flex",
        height: "100%",
        overflow: "hidden",
      }}
    >
      <DeviceList />
      <DeviceDetail />
    </div>
  );
}

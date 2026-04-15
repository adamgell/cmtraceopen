import { useState } from "react";
import { Button, Spinner, tokens } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import {
  openLogFile,
  inspectPathKind,
  listLogFolder,
  checkDnsLoggingStatus,
  enableDnsDebugLogging,
  type DnsLoggingStatus,
} from "../../lib/commands";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";

/** Well-known Windows Server log paths for auto-discovery. */
const KNOWN_DNS_PATHS = [
  "C:\\WINDOWS\\System32\\dns\\dns.log",
  "C:\\Windows\\System32\\dns\\dns.log",
];
const KNOWN_DNS_EVTX_PATHS = [
  "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-DNSServer%4Audit.evtx",
  "C:\\Windows\\System32\\winevt\\Logs\\DNS Server.evtx",
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
  const [loggingStatus, setLoggingStatus] = useState<DnsLoggingStatus | null>(null);
  const [enabling, setEnabling] = useState(false);
  const [enableResult, setEnableResult] = useState<string | null>(null);

  const handleScanServer = async () => {
    setLocalError(null);
    setEnableResult(null);
    setLoading(true);
    setLoadError(null);

    // Step 1: Check server logging configuration
    let status: DnsLoggingStatus | null = null;
    try {
      status = await checkDnsLoggingStatus();
      setLoggingStatus(status);
    } catch {
      // Non-Windows or command failed — proceed with file scan
    }

    const discovered: string[] = [];

    // Step 2: Scan for existing log files
    // DNS debug log
    if (status?.logFilePath) {
      // Use the configured path from the server
      try {
        const kind = await inspectPathKind(status.logFilePath);
        if (kind === "file") {
          discovered.push(status.logFilePath);
        }
      } catch {
        // Configured path doesn't exist yet
      }
    }
    // Also check default paths (in case logFilePath is different)
    for (const dnsPath of KNOWN_DNS_PATHS) {
      if (discovered.some((d) => d.toLowerCase() === dnsPath.toLowerCase())) continue;
      try {
        const kind = await inspectPathKind(dnsPath);
        if (kind === "file") {
          discovered.push(dnsPath);
          break;
        }
      } catch {
        // Path doesn't exist
      }
    }

    // DNS audit EVTX
    for (const evtxPath of KNOWN_DNS_EVTX_PATHS) {
      try {
        const kind = await inspectPathKind(evtxPath);
        if (kind === "file") {
          discovered.push(evtxPath);
        }
      } catch {
        // Path doesn't exist
      }
    }

    // DHCP logs
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
        break;
      } catch {
        // Directory doesn't exist
      }
    }

    // Step 3: Parse discovered files
    if (discovered.length > 0) {
      for (const path of discovered) {
        try {
          const result = await openLogFile(path);
          const fileName = path.split(/[\\/]/).pop() ?? path;
          addSource(path, fileName, result.formatDetected, result.entries);
        } catch (err) {
          console.warn(`[dns-dhcp] failed to parse: ${path}`, err);
        }
      }
    }

    // Step 4: Build status message if nothing found or logging is off
    if (discovered.length === 0 && !status?.dnsServerInstalled && !status?.dhcpServerInstalled) {
      setLocalError(
        "No DNS or DHCP Server roles detected on this machine. Use Open Files to load logs from another server."
      );
    } else if (discovered.length === 0) {
      // Server roles exist but no log files found — status will show the details
    }

    setLoading(false);
  };

  const handleEnableDnsLogging = async () => {
    setEnabling(true);
    setEnableResult(null);
    try {
      const result = await enableDnsDebugLogging();
      setEnableResult(result);
      // Refresh status
      const status = await checkDnsLoggingStatus();
      setLoggingStatus(status);
    } catch (err) {
      setEnableResult(
        `Failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
    setEnabling(false);
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
            console.warn(`[dns-dhcp] Skipping "${path}" — unsupported format "${format}"`);
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

  // Loading state
  if (isLoading && sources.length === 0) {
    return (
      <div style={{
        display: "flex", flexDirection: "column", alignItems: "center",
        justifyContent: "center", height: "100%", gap: "12px",
      }}>
        <Spinner size="medium" />
        <span style={{ color: tokens.colorNeutralForeground2, fontSize: "13px" }}>
          Scanning for DNS/DHCP logs...
        </span>
      </div>
    );
  }

  // Empty state
  if (sources.length === 0) {
    return (
      <div style={{
        flex: 1, display: "flex", flexDirection: "column", alignItems: "center",
        justifyContent: "center", gap: "20px", padding: "40px",
      }}>
        <div style={{ fontSize: "18px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
          DNS / DHCP Workspace
        </div>
        <div style={{
          fontSize: "13px", color: tokens.colorNeutralForeground3,
          textAlign: "center", maxWidth: "460px",
        }}>
          Correlate DNS queries with DHCP leases to troubleshoot resolution failures
          and track device activity.
        </div>

        <div style={{ display: "flex", gap: 12 }}>
          <Button appearance="primary" onClick={() => void handleScanServer()}>
            Scan Server Logs
          </Button>
          <Button appearance="secondary" onClick={() => void handleOpenFiles()}>
            Open Files
          </Button>
        </div>

        {/* Server logging status panel */}
        {loggingStatus && (
          <div style={{
            maxWidth: 500, width: "100%", padding: "12px 16px",
            background: tokens.colorNeutralBackground3,
            borderRadius: 6, fontSize: 13, lineHeight: 1.6,
            color: tokens.colorNeutralForeground2,
          }}>
            <div style={{ fontWeight: 600, marginBottom: 8, color: tokens.colorNeutralForeground1 }}>
              Server Status
            </div>

            <StatusRow
              label="DNS Server"
              installed={loggingStatus.dnsServerInstalled}
            />
            {loggingStatus.dnsServerInstalled && (
              <div style={{ marginLeft: 16 }}>
                <StatusRow
                  label="Debug logging"
                  installed={loggingStatus.debugLoggingEnabled}
                  notInstalledLabel="Not enabled"
                />
                {!loggingStatus.debugLoggingEnabled && (
                  <div style={{ marginTop: 4, marginBottom: 4 }}>
                    <Button
                      size="small"
                      appearance="primary"
                      onClick={() => void handleEnableDnsLogging()}
                      disabled={enabling}
                    >
                      {enabling ? "Enabling..." : "Enable DNS Debug Logging"}
                    </Button>
                  </div>
                )}
                {loggingStatus.logFilePath && (
                  <div style={{ fontSize: 12, color: tokens.colorNeutralForeground3 }}>
                    Log path: {loggingStatus.logFilePath}
                  </div>
                )}
              </div>
            )}

            <StatusRow
              label="DHCP Server"
              installed={loggingStatus.dhcpServerInstalled}
            />

            {enableResult && (
              <div style={{
                marginTop: 8, fontSize: 12,
                color: enableResult.startsWith("Failed")
                  ? tokens.colorPaletteRedForeground2
                  : tokens.colorPaletteGreenForeground1,
              }}>
                {enableResult}
              </div>
            )}
          </div>
        )}

        {(localError || loadError) && (
          <div style={{
            fontSize: "12px", color: tokens.colorPaletteRedForeground1,
            maxWidth: "500px", textAlign: "center",
          }}>
            {localError || loadError}
          </div>
        )}
      </div>
    );
  }

  // Active state — two-panel layout
  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      <DeviceList />
      <DeviceDetail />
    </div>
  );
}

function StatusRow({
  label,
  installed,
  notInstalledLabel,
}: {
  label: string;
  installed: boolean;
  notInstalledLabel?: string;
}) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <span style={{
        color: installed
          ? tokens.colorPaletteGreenForeground1
          : tokens.colorNeutralForeground4,
      }}>
        {installed ? "\u2713" : "\u2717"}
      </span>
      <span>{label}</span>
      {!installed && (
        <span style={{ fontSize: 12, color: tokens.colorNeutralForeground4 }}>
          {notInstalledLabel ?? "Not installed"}
        </span>
      )}
    </div>
  );
}

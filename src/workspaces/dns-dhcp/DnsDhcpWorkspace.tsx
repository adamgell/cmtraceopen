import { useState, useEffect, startTransition } from "react";
import { Button, Spinner, ProgressBar, tokens } from "@fluentui/react-components";
import { open, confirm } from "@tauri-apps/plugin-dialog";
import { listen } from "@tauri-apps/api/event";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import {
  openLogFile,
  inspectPathKind,
  listLogFolder,
  checkDnsLoggingStatus,
  enableDnsDebugLogging,
  collectDnsDhcpFromDomain,
  type DnsLoggingStatus,
  type DnsDhcpCollectionProgress,
  type DnsDhcpCollectionResult,
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
  const batchAddSources = useDnsDhcpStore((s) => s.batchAddSources);
  const setLoading = useDnsDhcpStore((s) => s.setLoading);
  const setLoadError = useDnsDhcpStore((s) => s.setLoadError);
  const [localError, setLocalError] = useState<string | null>(null);
  const [loggingStatus, setLoggingStatus] = useState<DnsLoggingStatus | null>(null);
  const [enabling, setEnabling] = useState(false);
  const [enableResult, setEnableResult] = useState<string | null>(null);
  const [collecting, setCollecting] = useState(false);
  const [collectionProgress, setCollectionProgress] = useState<DnsDhcpCollectionProgress | null>(null);
  const [collectionResult, setCollectionResult] = useState<DnsDhcpCollectionResult | null>(null);
  const [collectionRequestId, setCollectionRequestId] = useState<string | null>(null);

  // Listen for collection progress events
  useEffect(() => {
    if (!collectionRequestId) return;
    const unlisten = listen<DnsDhcpCollectionProgress>("dns-dhcp-collection-progress", (event) => {
      if (event.payload.requestId === collectionRequestId) {
        setCollectionProgress(event.payload);
      }
    });
    return () => { void unlisten.then((fn) => fn()); };
  }, [collectionRequestId]);

  const handleLoadCollectionBundle = async (bundlePath: string) => {
    setLoading(true);
    setLocalError(null);

    try {
      const listing = await listLogFolder(bundlePath);
      const batch: Array<{ path: string; fileName: string; format: import("../../types/log").LogFormat; entries: import("../../types/log").LogEntry[] }> = [];

      // Each subdirectory is a server
      for (const serverEntry of listing.entries) {
        if (!serverEntry.isDir) continue;
        const serverName = serverEntry.name;
        const serverListing = await listLogFolder(serverEntry.path);

        for (const file of serverListing.entries) {
          if (file.isDir) {
            // Scan subdirs (e.g. dhcp/)
            const subListing = await listLogFolder(file.path);
            for (const subFile of subListing.entries) {
              if (subFile.isDir) continue;
              if (!subFile.name.toLowerCase().endsWith(".log")) continue;
              try {
                const r = await openLogFile(subFile.path);
                batch.push({ path: subFile.path, fileName: `${serverName}/${file.name}/${subFile.name}`, format: r.formatDetected, entries: r.entries });
              } catch { /* skip */ }
            }
          } else {
            // Direct files (dns-debug.log, *.evtx)
            const lower = file.name.toLowerCase();
            if (lower.endsWith(".log") || lower.endsWith(".evtx")) {
              try {
                const r = await openLogFile(file.path);
                batch.push({ path: file.path, fileName: `${serverName}/${file.name}`, format: r.formatDetected, entries: r.entries });
              } catch { /* skip */ }
            }
          }
        }
      }

      if (batch.length > 0) {
        startTransition(() => {
          batchAddSources(batch);
        });
      } else {
        setLocalError("No parseable DNS or DHCP logs found in the collection folder.");
      }
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : String(err));
    }

    setLoading(false);
  };

  const handleCollectFromDomain = async () => {
    const ok = await confirm(
      "This will discover all domain controllers and collect DNS/DHCP logs from each via admin shares (C$). Continue?",
      { title: "Collect DNS/DHCP Logs from Domain", kind: "info" }
    );
    if (!ok) return;

    setCollecting(true);
    setCollectionProgress(null);
    setCollectionResult(null);
    setLocalError(null);

    const requestId = `dns-dhcp-collect-${Date.now()}`;
    setCollectionRequestId(requestId);

    try {
      const result = await collectDnsDhcpFromDomain(requestId);
      setCollectionResult(result);

      // Parse all collected files, then load into workspace in one batch
      if (result.bundlePath) {
        const batch: Array<{ path: string; fileName: string; format: import("../../types/log").LogFormat; entries: import("../../types/log").LogEntry[] }> = [];

        for (const server of result.servers) {
          if (server.status !== "collected" || server.filesCollected === 0) continue;
          const serverDir = `${result.bundlePath}\\${server.server}`;

          // DNS debug log
          try {
            const dnsPath = `${serverDir}\\dns-debug.log`;
            const r = await openLogFile(dnsPath);
            batch.push({ path: dnsPath, fileName: `${server.server}/dns-debug.log`, format: r.formatDetected, entries: r.entries });
          } catch { /* file may not exist */ }

          // DNS audit EVTX
          for (const evtxName of ["Microsoft-Windows-DNSServer%4Audit.evtx", "DNS Server.evtx"]) {
            try {
              const evtxPath = `${serverDir}\\${evtxName}`;
              const r = await openLogFile(evtxPath);
              batch.push({ path: evtxPath, fileName: `${server.server}/${evtxName}`, format: r.formatDetected, entries: r.entries });
            } catch { /* file may not exist */ }
          }

          // DHCP logs
          try {
            const dhcpDir = `${serverDir}\\dhcp`;
            const listing = await listLogFolder(dhcpDir);
            for (const entry of listing.entries) {
              if (!entry.isDir && entry.name.toLowerCase().endsWith(".log")) {
                try {
                  const r = await openLogFile(entry.path);
                  batch.push({ path: entry.path, fileName: `${server.server}/dhcp/${entry.name}`, format: r.formatDetected, entries: r.entries });
                } catch { /* skip unparseable */ }
              }
            }
          } catch { /* dhcp dir may not exist */ }
        }

        // Single batch update — devices rebuild only once
        if (batch.length > 0) {
          startTransition(() => {
            batchAddSources(batch);
          });
        }
      }
    } catch (err) {
      setLocalError(err instanceof Error ? err.message : String(err));
    }

    setCollecting(false);
    setCollectionRequestId(null);
  };

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
          <Button appearance="primary" onClick={() => void handleScanServer()} disabled={collecting}>
            Scan This Server
          </Button>
          <Button appearance="primary" onClick={() => void handleCollectFromDomain()} disabled={collecting}>
            Collect from Domain
          </Button>
          <Button appearance="secondary" onClick={() => void handleOpenFiles()} disabled={collecting}>
            Open Files
          </Button>
        </div>

        {/* Collection progress */}
        {collecting && collectionProgress && (
          <div style={{
            maxWidth: 500, width: "100%", padding: "12px 16px",
            background: tokens.colorNeutralBackground3,
            borderRadius: 6, fontSize: 13,
          }}>
            <div style={{ marginBottom: 8, color: tokens.colorNeutralForeground1 }}>
              {collectionProgress.message}
            </div>
            <ProgressBar
              value={collectionProgress.completedServers / Math.max(collectionProgress.totalServers, 1)}
              thickness="medium"
            />
            <div style={{ marginTop: 4, fontSize: 12, color: tokens.colorNeutralForeground3 }}>
              {collectionProgress.completedServers} / {collectionProgress.totalServers} servers
            </div>
          </div>
        )}

        {/* Collection result */}
        {collectionResult && !collecting && (
          <div style={{
            maxWidth: 500, width: "100%", padding: "12px 16px",
            background: tokens.colorNeutralBackground3,
            borderRadius: 6, fontSize: 13, lineHeight: 1.6,
            color: tokens.colorNeutralForeground2,
          }}>
            <div style={{ fontWeight: 600, marginBottom: 8, color: tokens.colorNeutralForeground1 }}>
              Collection Complete
            </div>
            <div>Files collected: {collectionResult.totalFiles}</div>
            <div>Size: {(collectionResult.totalBytes / 1024 / 1024).toFixed(1)} MB</div>
            <div>Duration: {(collectionResult.durationMs / 1000).toFixed(1)}s</div>
            {collectionResult.servers.map((s) => (
              <div key={s.server} style={{ marginTop: 4 }}>
                <span style={{
                  color: s.status === "collected" && s.errors.length === 0
                    ? tokens.colorPaletteGreenForeground1
                    : s.status === "unreachable"
                      ? tokens.colorPaletteRedForeground2
                      : tokens.colorPaletteYellowForeground2,
                }}>
                  {s.status === "collected" && s.errors.length === 0 ? "\u2713" : s.status === "unreachable" ? "\u2717" : "\u26A0"}
                </span>
                {" "}{s.server}: {s.filesCollected} files
                {s.errors.length > 0 && (
                  <div style={{ marginLeft: 20, fontSize: 12, color: tokens.colorPaletteRedForeground2 }}>
                    {s.errors.map((err, idx) => (
                      <div key={idx}>{err}</div>
                    ))}
                  </div>
                )}
              </div>
            ))}
            <div style={{ fontSize: 12, marginTop: 8, color: tokens.colorNeutralForeground3 }}>
              {collectionResult.bundlePath}
            </div>
            <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
              <Button
                size="small"
                appearance="primary"
                onClick={() => void handleLoadCollectionBundle(collectionResult.bundlePath)}
              >
                Open Collected Logs
              </Button>
            </div>
          </div>
        )}

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

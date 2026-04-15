import { useState } from "react";
import { Button, Spinner, tokens } from "@fluentui/react-components";
import { open } from "@tauri-apps/plugin-dialog";
import { useDnsDhcpStore } from "./dns-dhcp-store";
import { openLogFile } from "../../lib/commands";
import { DeviceList } from "./DeviceList";
import { DeviceDetail } from "./DeviceDetail";

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

        <Button appearance="primary" onClick={() => void handleOpenFiles()}>
          Open Files
        </Button>

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

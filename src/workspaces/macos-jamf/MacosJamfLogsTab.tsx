import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button, Caption1, Subtitle2 } from "@fluentui/react-components";

import { useJamfStore } from "./jamf-store";
import type { JamfLogScanResult } from "./types";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function MacosJamfLogsTab() {
  const slice = useJamfStore((s) => s.logs);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);

  const reload = async () => {
    begin("logs");
    try {
      const result = await invoke<JamfLogScanResult>("jamf_scan_logs");
      finish("logs", result);
    } catch (e) {
      fail("logs", e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    if (slice.status === "idle") {
      void reload();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (slice.status === "loading") return <div>Scanning JAMF log directories...</div>;
  if (slice.status === "error")
    return (
      <div>
        <div>Failed to scan logs: {slice.error}</div>
        <Button onClick={reload}>Retry</Button>
      </div>
    );
  if (!slice.data) return null;
  const { files, scannedDirectories, totalSizeBytes } = slice.data;

  return (
    <div>
      <Subtitle2>JAMF Logs</Subtitle2>
      <Caption1>
        {files.length} file(s) - {formatBytes(totalSizeBytes)} - {scannedDirectories.length} directories with logs
      </Caption1>
      <Button onClick={reload} style={{ marginLeft: 12 }}>Re-scan</Button>
      <table style={{ width: "100%", marginTop: 12 }}>
        <thead>
          <tr><th align="left">Name</th><th align="left">Path</th><th align="right">Size</th></tr>
        </thead>
        <tbody>
          {files.map((f) => (
            <tr key={f.path}>
              <td>{f.fileName}</td>
              <td>{f.path}</td>
              <td align="right">{formatBytes(f.sizeBytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

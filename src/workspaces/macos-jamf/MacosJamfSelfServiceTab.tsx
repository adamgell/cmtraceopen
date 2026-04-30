import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button, Caption1, Subtitle2 } from "@fluentui/react-components";

import { useJamfStore } from "./jamf-store";
import type { JamfSelfServiceEvent } from "./types";

// Verified-real path on JAMF Pro 11 hosts: ~/Library/Logs/JAMF/selfservice.log
const DEFAULT_SELF_SERVICE_LOG = "~/Library/Logs/JAMF/selfservice.log";

export function MacosJamfSelfServiceTab() {
  const slice = useJamfStore((s) => s.selfService);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);

  const reload = async () => {
    begin("selfService");
    try {
      const events = await invoke<JamfSelfServiceEvent[]>("jamf_parse_self_service_log", {
        path: DEFAULT_SELF_SERVICE_LOG,
      });
      finish("selfService", events);
    } catch (e) {
      fail("selfService", e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    if (slice.status === "idle") void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (slice.status === "loading") return <div>Loading Self Service log...</div>;
  if (slice.status === "error")
    return (
      <div>
        <div>Failed to parse Self Service log: {slice.error}</div>
        <Button onClick={reload}>Retry</Button>
      </div>
    );
  const events = slice.data ?? [];
  return (
    <div>
      <Subtitle2>Self Service usage</Subtitle2>
      <Caption1>{events.length} event(s) - {DEFAULT_SELF_SERVICE_LOG}</Caption1>
      <Button onClick={reload} style={{ marginLeft: 12 }}>Reload</Button>
      <table style={{ width: "100%", marginTop: 12 }}>
        <thead><tr><th align="left">Time</th><th align="left">Action</th><th align="left">Item</th><th align="left">Result</th></tr></thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i}><td>{e.timestamp}</td><td>{e.action}</td><td>{e.itemName ?? "-"}</td><td>{e.result ?? "-"}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

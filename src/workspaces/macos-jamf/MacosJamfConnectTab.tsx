import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Button, Caption1, Subtitle2 } from "@fluentui/react-components";

import { useJamfStore } from "./jamf-store";
import type { JamfConnectEvent } from "./types";

export function MacosJamfConnectTab() {
  const slice = useJamfStore((s) => s.connect);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);
  const markNotInstalled = useJamfStore((s) => s.markNotInstalled);
  const installed = useJamfStore((s) => s.environment.data?.jamfConnectInstalled ?? false);

  const reload = async () => {
    if (!installed) {
      markNotInstalled("connect");
      return;
    }
    begin("connect");
    try {
      const events = await invoke<JamfConnectEvent[]>("jamf_parse_connect_log", { path: null });
      finish("connect", events);
    } catch (e) {
      fail("connect", e instanceof Error ? e.message : String(e));
    }
  };

  // `installed` is false until the environment slice resolves, so a first pass
  // can mark this tab notInstalled before detection has actually run. Without
  // the second clause that state was terminal: the idle guard blocked any
  // retry, the store outlives unmounts, and this branch renders no Reload.
  useEffect(() => {
    if (slice.status === "idle" || (installed && slice.status === "notInstalled")) {
      void reload();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [installed, slice.status]);

  if (slice.status === "notInstalled") {
    return (
      <div>
        <Subtitle2>JAMF Connect not detected</Subtitle2>
        <Caption1>
          Install JAMF Connect to populate this view.
        </Caption1>
        <div style={{ marginTop: 8 }}>
          <Button onClick={reload}>Re-check</Button>
        </div>
      </div>
    );
  }
  if (slice.status === "loading") return <div>Loading JAMF Connect log...</div>;
  if (slice.status === "error")
    return (
      <div>
        <div>Failed to parse JAMF Connect log: {slice.error}</div>
        <Button onClick={reload}>Retry</Button>
      </div>
    );

  const events = slice.data ?? [];
  return (
    <div>
      <Subtitle2>JAMF Connect events</Subtitle2>
      <Caption1>{events.length} event(s)</Caption1>
      <Button onClick={reload} style={{ marginLeft: 12 }}>Reload</Button>
      <table style={{ width: "100%", marginTop: 12 }}>
        <thead><tr><th align="left">Time</th><th align="left">Type</th><th align="left">User</th><th align="left">IdP</th><th align="left">Message</th></tr></thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={i}><td>{e.timestamp}</td><td>{e.eventType}</td><td>{e.user ?? "-"}</td><td>{e.idp ?? "-"}</td><td>{e.message}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

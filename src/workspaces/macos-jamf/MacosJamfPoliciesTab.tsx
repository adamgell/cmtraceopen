import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Button,
  Caption1,
  Subtitle2,
  TabList,
  Tab,
} from "@fluentui/react-components";

import { useJamfStore } from "./jamf-store";
import type { JamfPolicyEvent, JamfPolicyLogResult, JamfPolicyTrigger } from "./types";

type ViewMode = "table" | "timeline";

function describeTrigger(t: JamfPolicyTrigger): string {
  switch (t.type) {
    case "recurringCheckIn": return "Recurring check-in";
    case "event":            return `Event: ${t.value}`;
    case "manual":           return "Manual";
    case "startup":          return "Startup";
    case "login":            return "Login";
    case "logout":           return "Logout";
    case "policyId":         return `Policy ID ${t.value}`;
    case "other":            return t.value;
  }
}

// Backend timestamps are UTC instants; render them in the reader's zone.
function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

// Only policy executions carry an elapsed time — see compute_durations in
// src-tauri/src/jamf/policy_log.rs for what it measures.
function formatDuration(ms: number | null): string {
  if (ms == null) return "-";
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

function describeResult(e: JamfPolicyEvent): string {
  switch (e.result.type) {
    case "success":    return "Success";
    case "failure":    return `Failure - ${e.result.value}`;
    case "inProgress": return "In progress";
    case "unknown":    return "-";
  }
}

export function MacosJamfPoliciesTab() {
  const slice = useJamfStore((s) => s.policies);
  const begin = useJamfStore((s) => s.beginLoad);
  const finish = useJamfStore((s) => s.finishLoad);
  const fail = useJamfStore((s) => s.failLoad);
  const [view, setView] = useState<ViewMode>("table");

  const reload = async () => {
    begin("policies");
    try {
      const result = await invoke<JamfPolicyLogResult>("jamf_parse_policy_log", { path: null });
      finish("policies", result);
    } catch (e) {
      fail("policies", e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    if (slice.status === "idle") void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const events = useMemo<JamfPolicyEvent[]>(() => slice.data?.events ?? [], [slice.data]);

  if (slice.status === "loading") return <div>Parsing jamf.log...</div>;
  if (slice.status === "error")
    return (
      <div>
        <div>Failed to parse jamf.log: {slice.error}</div>
        <Button onClick={reload}>Retry</Button>
      </div>
    );

  return (
    <div>
      <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
        <Subtitle2>Policy events</Subtitle2>
        <Caption1>
          {events.length} event(s) - {slice.data?.unparsedLines ?? 0} unparsed line(s) - {slice.data?.sourcePath}
        </Caption1>
        <Button onClick={reload}>Re-parse</Button>
      </div>
      <TabList selectedValue={view} onTabSelect={(_, d) => setView(d.value as ViewMode)}>
        <Tab value="table">Table</Tab>
        <Tab value="timeline">Timeline</Tab>
      </TabList>
      {view === "table" ? <Table events={events} /> : <TriggerSummary events={events} />}
    </div>
  );
}

function Table({ events }: { events: JamfPolicyEvent[] }) {
  return (
    <table style={{ width: "100%", marginTop: 12, fontVariantNumeric: "tabular-nums" }}>
      <thead>
        <tr>
          <th align="left">Time</th>
          <th align="left">Trigger</th>
          <th align="left">Policy</th>
          <th align="left">Result</th>
          <th align="right">Elapsed</th>
        </tr>
      </thead>
      <tbody>
        {events.map((e, i) => (
          <tr key={`${e.rawLineOffset}-${i}`}>
            <td>{formatTimestamp(e.timestamp)}</td>
            <td>{describeTrigger(e.trigger)}</td>
            <td>{e.policyName ?? e.policyId ?? "-"}</td>
            <td>{describeResult(e)}</td>
            <td align="right">{formatDuration(e.durationMs)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function TriggerSummary({ events }: { events: JamfPolicyEvent[] }) {
  // Per-trigger counts. The full SwimLane timeline view is deferred to a later
  // refinement once the lane mapping is nailed down.
  const counts = new Map<string, number>();
  for (const e of events) {
    const k = describeTrigger(e.trigger);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return (
    <ul style={{ marginTop: 12 }}>
      {[...counts.entries()].map(([k, n]) => (
        <li key={k}>{k}: {n}</li>
      ))}
    </ul>
  );
}

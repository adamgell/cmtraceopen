import type { TimelineBundle, IncidentDetail, FirewallTimelineError } from "../types/timeline";
export function syntheticTimeline(id = "synthetic-timeline"): TimelineBundle {
  return { id, sources: [{ idx: 0, kind: { logFile: { parserKind: "windowsFirewall" } }, path: "/synthetic/firewall.log", displayName: "Synthetic firewall", color: "#123456", entryCount: 2, firewallExcluded: 3 }], timeRangeMs: [0, 1000], totalEntries: 2, incidents: [{ id: 1, tsStartMs: 0, tsEndMs: 1000, signalCount: 2, sourceCount: 1, confidence: 0.5, summary: "Synthetic incident" }], deniedGuids: [], errors: [], tunables: { overlapWindowMs: 5000, minSourceCount: 2, maxIncidentSpanMs: 60000, enabledSignalKinds: ["errorSeverity"] } };
}
export function firewallTimelineError(reason: FirewallTimelineError["reason"] = "sourceChanged"): FirewallTimelineError {
  return { kind: "firewallSource", sourceIdx: 0, path: "/synthetic/firewall.log", reason };
}
export function syntheticIncident(): IncidentDetail { return { incident: syntheticTimeline().incidents[0], signals: [], perSourceSignalCounts: {} }; }

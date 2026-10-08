/** Invented records only; all addresses are documentation ranges. */
import type { FirewallCoverage, LogEntry, ParseResult, TailPayload } from "../types/log";
export function firewallCoverage(overrides: Partial<FirewallCoverage> = {}): FirewallCoverage {
  const metric = () => ({ count: "0", lines: [] as number[] });
  return { padding: metric(), malformed: metric(), oversized: metric(), lossEvents: metric(), lostEvents: metric(), unknownLossCount: metric(), unplacedTimestamps: metric(), ...overrides };
}
export function firewallEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  const declaredFields = ["date", "time", "action", "src-ip", "dst-ip", "pid"];
  const values = ["2042-04-05", "06:07:09", "ALLOW", "192.0.2.11", "203.0.113.21", "8801"];
  return { id: 0, lineNumber: 4, message: "ALLOW TCP 192.0.2.11 → 203.0.113.21", component: null,
    timestamp: null, timestampDisplay: "2042-04-05 06:07:09", severity: "Info", thread: null, threadDisplay: null,
    sourceFile: null, format: "Timestamped", filePath: "/synthetic/firewall.log", timezoneOffset: null,
    firewall: { rawLine: values.join(" "), declaredFields, fields: declaredFields.map((name, i) => ({ name, value: values[i] })),
      schemaOrigin: "header", timeBasis: "local", recordKind: "traffic", truncated: false }, ...overrides };
}
export function firewallSnapshot(filePath = "/synthetic/firewall.log"): ParseResult {
  return { entries: [firewallEntry({ filePath })], formatDetected: "Timestamped",
    parserSelection: { parser: "windowsFirewall", implementation: "windowsFirewall", provenance: "dedicated", parseQuality: "structured", recordFraming: "physicalLine", dateOrder: null },
    totalLines: 4, parseErrors: 0, filePath, fileSize: 256, byteOffset: 256, modifiedUnixMs: null,
    firewallSessionId: `session:${filePath}`, firewallCoverage: firewallCoverage({ unplacedTimestamps: { count: "1", lines: [4] } }),
    firewallDecoding: { kind: "ready", pendingBytes: 0, reason: null } };
}
export function firewallPayload(overrides: Partial<TailPayload> = {}): TailPayload {
  const source = firewallSnapshot();
  return { entries: [], amendments: [], filePath: source.filePath, observedThroughLine: 4, parseErrors: 0, reset: false,
    firewallControl: { sourceSessionId: source.firewallSessionId!, watchEpoch: 1 },
    firewallReplacements: [], firewallCoverage: firewallCoverage(), firewallDecoding: { kind: "ready", pendingBytes: 0, reason: null }, ...overrides };
}

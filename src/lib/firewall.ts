import type { FirewallControlToken, FirewallCoverage, FirewallDecodingStatus, FirewallRecord } from "../types/log";
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const integer = (value: unknown, low: number, high = Number.MAX_SAFE_INTEGER): value is number => Number.isSafeInteger(value) && (value as number) >= low && (value as number) <= high;
const count = (value: unknown): value is string => typeof value === "string" && /^(0|[1-9]\d{0,19})$/.test(value) && BigInt(value) <= 18_446_744_073_709_551_615n;
const metrics = ["padding", "malformed", "oversized", "lossEvents", "lostEvents", "unknownLossCount", "unplacedTimestamps"] as const;
export function emptyFirewallCoverage(): FirewallCoverage {
  return Object.fromEntries(metrics.map(key => [key, { count: "0", lines: [] }])) as unknown as FirewallCoverage;
}
export function firewallParseErrors(coverage: FirewallCoverage): number {
  const total = BigInt(coverage.malformed.count) + BigInt(coverage.oversized.count);
  return Number(total > 4_294_967_295n ? 4_294_967_295n : total);
}
export function isFirewallCoverage(value: unknown): value is FirewallCoverage {
  return isObject(value) && metrics.every(key => {
    const m = value[key];
    return isObject(m) && count(m.count) && Array.isArray(m.lines) && m.lines.length <= 8 &&
      m.lines.every(n => integer(n, 1, 4_294_967_295)) && new Set(m.lines).size === m.lines.length &&
      (m.count !== "0" || m.lines.length === 0);
  });
}
export function isFirewallControl(value: unknown): value is FirewallControlToken {
  return isObject(value) && typeof value.sourceSessionId === "string" && value.sourceSessionId.length > 0 &&
    value.sourceSessionId.length <= 128 && integer(value.watchEpoch, 1);
}
export function isFirewallDecoding(value: unknown): value is FirewallDecodingStatus {
  if (!isObject(value) || !integer(value.pendingBytes, 0, 3)) return false;
  if (value.kind === "ready") return value.pendingBytes === 0 && value.reason === null;
  if (value.kind === "pending") return value.pendingBytes > 0 && value.reason === null;
  return value.kind === "gap" && ["readFailed", "invalidEncoding", "generationUnverifiable"].includes(value.reason as string);
}
export function isFirewallRecord(value: unknown): value is FirewallRecord {
  if (!isObject(value) || typeof value.rawLine !== "string" || new TextEncoder().encode(value.rawLine).length > 65_536 ||
    !["header", "canonical", "unavailable"].includes(value.schemaOrigin as string) ||
    !["local", "utc", "unknown"].includes(value.timeBasis as string) ||
    !["traffic", "eventsLost", "malformed"].includes(value.recordKind as string) || typeof value.truncated !== "boolean" ||
    !Array.isArray(value.declaredFields) || value.declaredFields.length > 32_768 ||
    !value.declaredFields.every(f => typeof f === "string") ||
    !Array.isArray(value.fields) || value.fields.length > value.declaredFields.length) return false;
  const names = value.declaredFields as string[];
  if (names.join(" ").length > 65_536) return false;
  if (value.recordKind === "malformed") return value.fields.length === 0;
  return value.schemaOrigin !== "unavailable" && value.fields.length === names.length && value.fields.every((f, i) =>
    isObject(f) && f.name === names[i] && (f.value === null || typeof f.value === "string"));
}

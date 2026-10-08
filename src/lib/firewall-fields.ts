import type { LogEntry } from "../types/log";

export function firewallField(entry: LogEntry, name: string): string | null {
  return entry.firewall?.fields.find(field => field.name.toLowerCase() === name.toLowerCase())?.value ?? null;
}

export function firewallSearchText(entry: LogEntry): string {
  const record = entry.firewall;
  return record ? [record.rawLine, ...record.declaredFields, ...record.fields.map(field => field.value ?? "")].join(" ") : "";
}

/** Calendar validation without the reader's timezone or JavaScript Date. */
function wallClock(display: string | null): string | null {
  const match = display?.match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/);
  if (!match) return null;
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > days[month - 1] || hour > 23 || minute > 59 || second > 59) return null;
  return match[0]; // Fixed-width validated components compare lexically.
}

export function compareEntryTimes(a: LogEntry, b: LogEntry): number {
  // Ordinary undated rows retain their legacy numeric-zero ordering in every
  // comparison. Only firewall rows without an epoch form the unplaced group.
  const leftTime = a.firewall ? a.timestamp : a.timestamp ?? 0;
  const rightTime = b.firewall ? b.timestamp : b.timestamp ?? 0;
  if (leftTime != null && rightTime != null) return leftTime - rightTime;
  if (leftTime != null) return -1;
  if (rightTime != null) return 1;
  // No absolute ordering is implied between two different sources.
  const sourceOrder = a.filePath.localeCompare(b.filePath);
  if (sourceOrder) return sourceOrder;
  if (a.firewall && b.firewall) {
    const left = wallClock(a.timestampDisplay), right = wallClock(b.timestampDisplay);
    if (left !== null && right !== null) return left.localeCompare(right) || a.lineNumber - b.lineNumber;
    // Unparseable rows form a stable physical-order group after validated rows.
    if (left !== null) return -1;
    if (right !== null) return 1;
  }
  return a.lineNumber - b.lineNumber;
}

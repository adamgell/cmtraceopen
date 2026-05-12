import type { LogEntry, Severity } from "../types/log";

export type SeverityNavigationDirection = "previous" | "next";

export function findAdjacentSeverityEntryId(
  entries: LogEntry[],
  selectedId: number | null,
  severity: Severity,
  direction: SeverityNavigationDirection
): number | null {
  if (entries.length === 0) return null;

  const step = direction === "next" ? 1 : -1;
  const fallbackIndex = direction === "next" ? -1 : entries.length;
  const selectedIndex =
    selectedId === null
      ? fallbackIndex
      : entries.findIndex((entry) => entry.id === selectedId);
  const startIndex = selectedIndex >= 0 ? selectedIndex : fallbackIndex;

  for (let offset = 1; offset <= entries.length; offset++) {
    const index = (startIndex + step * offset + entries.length) % entries.length;
    if (entries[index].severity === severity) {
      return entries[index].id;
    }
  }

  return null;
}

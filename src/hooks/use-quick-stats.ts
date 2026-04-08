import { useMemo } from "react";
import { useLogStore } from "../stores/log-store";
import { useFilterStore } from "../stores/filter-store";

export interface ErrorCodeStat {
  hex: string;
  description: string;
  category: string;
  count: number;
}

export interface QuickStats {
  totalLines: number;
  filteredLineCount: number;
  bySeverity: {
    error: number;
    warning: number;
    info: number;
  };
  errorCodes: ErrorCodeStat[];
  earliestTimestamp: number | null;
  latestTimestamp: number | null;
  hasEntries: boolean;
  isEmpty: boolean;
}

/**
 * Hook to compute aggregated stats from the current log state.
 * Follows the same entries + filteredIds pattern as StatusBar.
 */
export function useQuickStats(): QuickStats {
  const entries = useLogStore((s) => s.entries);
  const totalLines = useLogStore((s) => s.totalLines);
  const filteredIds = useFilterStore((s) => s.filteredIds);

  return useMemo(() => {
    const isEmpty = totalLines === 0;

    if (isEmpty) {
      return {
        totalLines: 0,
        filteredLineCount: 0,
        bySeverity: { error: 0, warning: 0, info: 0 },
        errorCodes: [],
        earliestTimestamp: null,
        latestTimestamp: null,
        hasEntries: false,
        isEmpty: true,
      };
    }

    let errorCount = 0;
    let warningCount = 0;
    let infoCount = 0;
    let visibleCount = 0;

    const codeMap = new Map<string, { count: number; description: string; category: string }>();
    let earliest: number | null = null;
    let latest: number | null = null;

    for (const entry of entries) {
      if (filteredIds && !filteredIds.has(entry.id)) continue;
      visibleCount++;

      switch (entry.severity) {
        case "Error":
          errorCount++;
          break;
        case "Warning":
          warningCount++;
          break;
        case "Info":
          infoCount++;
          break;
      }

      if (entry.timestamp != null) {
        if (earliest === null || entry.timestamp < earliest) {
          earliest = entry.timestamp;
        }
        if (latest === null || entry.timestamp > latest) {
          latest = entry.timestamp;
        }
      }

      // Collect all error code spans (not just from Error severity)
      if (entry.errorCodeSpans && entry.errorCodeSpans.length > 0) {
        for (const span of entry.errorCodeSpans) {
          const hex = span.codeHex.startsWith("0x")
            ? "0x" + span.codeHex.slice(2).toUpperCase()
            : span.codeHex.toUpperCase();
          const existing = codeMap.get(hex);
          if (existing) {
            existing.count++;
          } else {
            codeMap.set(hex, {
              count: 1,
              description: span.description,
              category: span.category,
            });
          }
        }
      }
    }

    // Sort by count descending
    const errorCodes = Array.from(codeMap.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .map(([hex, data]) => ({
        hex,
        description: data.description,
        category: data.category,
        count: data.count,
      }));

    return {
      totalLines,
      filteredLineCount: visibleCount,
      bySeverity: {
        error: errorCount,
        warning: warningCount,
        info: infoCount,
      },
      errorCodes,
      earliestTimestamp: earliest,
      latestTimestamp: latest,
      hasEntries: visibleCount > 0,
      isEmpty,
    };
  }, [entries, totalLines, filteredIds]);
}

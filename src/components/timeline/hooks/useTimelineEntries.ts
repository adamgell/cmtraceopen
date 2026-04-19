import { useEffect, useMemo } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { TimelineEntry } from "../../../types/timeline";

const PAGE_SIZE = 1000;

export function useTimelineEntries(offset: number): TimelineEntry[] {
  const bundle = useTimelineStore((s) => s.bundle);
  const brushRange = useTimelineStore((s) => s.brushRange);
  const laneVisibility = useTimelineStore((s) => s.laneVisibility);
  const soloSourceIdx = useTimelineStore((s) => s.soloSourceIdx);
  const putEntries = useTimelineStore((s) => s.putEntries);
  const cache = useTimelineStore((s) => s.entryCache);

  const sourceFilter = useMemo(() => {
    if (soloSourceIdx != null) return [soloSourceIdx];
    return Object.entries(laneVisibility)
      .filter(([, v]) => v)
      .map(([k]) => Number(k));
  }, [laneVisibility, soloSourceIdx]);

  const rangeKey = brushRange ? `${brushRange[0]}-${brushRange[1]}` : "full";
  const filterKey = [...sourceFilter].sort((a, b) => a - b).join(",");
  const key = `${bundle?.id ?? ""}:${offset}:${PAGE_SIZE}:${rangeKey}:${filterKey}`;
  const cached = cache.get(key);

  useEffect(() => {
    if (!bundle || cached) return;
    let cancelled = false;
    invoke<TimelineEntry[]>("query_timeline_entries_cmd", {
      id: bundle.id,
      rangeMs: brushRange ?? null,
      sourceFilter,
      offset,
      limit: PAGE_SIZE,
    })
      .then((v) => {
        if (!cancelled) putEntries(key, v);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [
    bundle,
    offset,
    brushRange,
    filterKey,
    key,
    putEntries,
    cached,
    sourceFilter,
  ]);

  return cached ?? [];
}

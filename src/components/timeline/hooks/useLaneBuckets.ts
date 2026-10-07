import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { LaneBucket } from "../../../types/timeline";

export function useLaneBuckets(bucketCount: number): LaneBucket[] {
  const bundle = useTimelineStore((s) => s.bundle);
  const generation = useTimelineStore(s => s.timelineGeneration);
  const blocked = useTimelineStore(s => Boolean(s.staleSource) || s.building);
  const brushRange = useTimelineStore((s) => s.brushRange);
  const putBuckets = useTimelineStore((s) => s.putBuckets);
  const cache = useTimelineStore((s) => s.bucketCache);

  const rangeKey = brushRange ? `${brushRange[0]}-${brushRange[1]}` : "full";
  const key = `${bundle?.id ?? ""}:${bucketCount}:${rangeKey}`;
  const cached = cache.get(key);

  useEffect(() => {
    if (!bundle || cached || blocked) return;
    const origin = { bundleId: bundle.id, generation };
    let cancelled = false;
    invoke<LaneBucket[]>("query_lane_buckets_cmd", {
      id: bundle.id,
      bucketCount,
      rangeMs: brushRange ?? null,
    })
      .then((v) => {
        if (!cancelled && useTimelineStore.getState().isCurrent(origin)) putBuckets(key, v);
      })
      .catch(error => { if (!cancelled) useTimelineStore.getState().reportQueryError(error, origin); });
    return () => {
      cancelled = true;
    };
  }, [bundle, generation, blocked, bucketCount, brushRange, key, putBuckets, cached]);

  return cached ?? [];
}

import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { LaneBucket } from "../../../types/timeline";

export function useLaneBuckets(bucketCount: number): LaneBucket[] {
  const bundle = useTimelineStore((s) => s.bundle);
  const brushRange = useTimelineStore((s) => s.brushRange);
  const putBuckets = useTimelineStore((s) => s.putBuckets);
  const cache = useTimelineStore((s) => s.bucketCache);

  const rangeKey = brushRange ? `${brushRange[0]}-${brushRange[1]}` : "full";
  const key = `${bundle?.id ?? ""}:${bucketCount}:${rangeKey}`;
  const cached = cache.get(key);

  useEffect(() => {
    if (!bundle || cached) return;
    let cancelled = false;
    invoke<LaneBucket[]>("query_lane_buckets_cmd", {
      id: bundle.id,
      bucketCount,
      rangeMs: brushRange ?? null,
    })
      .then((v) => {
        if (!cancelled) putBuckets(key, v);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [bundle, bucketCount, brushRange, key, putBuckets, cached]);

  return cached ?? [];
}

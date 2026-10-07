import { useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { IncidentDetail } from "../../../types/timeline";

export function useIncidentDetail(incidentId: number | null): IncidentDetail | null {
  const bundleId = useTimelineStore(s => s.bundle?.id);
  const generation = useTimelineStore(s => s.timelineGeneration);
  const blocked = useTimelineStore(s => Boolean(s.staleSource) || s.building);
  const key = `${bundleId ?? ""}:${incidentId}`;
  const detail = useTimelineStore(s => s.detailCache.get(key));
  useEffect(() => {
    if (!bundleId || incidentId == null || blocked || detail) return;
    const origin = { bundleId, generation };
    let cancelled = false;
    invoke<IncidentDetail>("query_incident_details_cmd", { id: bundleId, incidentId })
      .then(value => { if (!cancelled && useTimelineStore.getState().isCurrent(origin)) useTimelineStore.getState().putDetail(key, value); })
      .catch(error => { if (!cancelled) useTimelineStore.getState().reportQueryError(error, origin); });
    return () => { cancelled = true; };
  }, [bundleId, generation, blocked, incidentId, detail, key]);
  return blocked ? null : (detail ?? null);
}

import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { IncidentDetail } from "../../../types/timeline";

export function useIncidentDetail(
  incidentId: number | null,
): IncidentDetail | null {
  const bundleId = useTimelineStore((s) => s.bundle?.id);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);

  useEffect(() => {
    if (!bundleId || incidentId == null) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    invoke<IncidentDetail>("query_incident_details_cmd", {
      id: bundleId,
      incidentId,
    })
      .then((v) => {
        if (!cancelled) setDetail(v);
      })
      .catch(() => {
        if (!cancelled) setDetail(null);
      });
    return () => {
      cancelled = true;
    };
  }, [bundleId, incidentId]);

  return detail;
}

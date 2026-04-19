import { useCallback, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { TimelineBundle } from "../../../types/timeline";

export async function buildTimelineFromSources(
  sources: { path: string; displayName?: string }[],
): Promise<TimelineBundle> {
  const bundle = await invoke<TimelineBundle>("build_timeline_cmd", { sources });
  useTimelineStore.getState().setBundle(bundle);
  return bundle;
}

export function useTimelineBundle() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const build = useCallback(
    async (sources: { path: string; displayName?: string }[]) => {
      setLoading(true);
      setError(null);
      try {
        return await buildTimelineFromSources(sources);
      } catch (e: unknown) {
        const msg =
          typeof e === "string"
            ? e
            : e && typeof e === "object" && "message" in e
              ? String((e as { message: unknown }).message)
              : JSON.stringify(e);
        setError(msg);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  return { build, loading, error };
}

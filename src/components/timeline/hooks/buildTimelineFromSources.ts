import { buildTimeline } from "../../../lib/commands";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { TimelineBundle } from "../../../types/timeline";

export async function buildTimelineFromSources(
  sources: { path: string; displayName?: string }[],
): Promise<TimelineBundle> {
  const origin = useTimelineStore.getState().beginBuild();
  try {
    const bundle = await buildTimeline(sources);
    if (useTimelineStore.getState().isCurrent(origin)) useTimelineStore.getState().setBundle(bundle);
    return bundle;
  } catch (error) {
    useTimelineStore.getState().reportBuildError(error, origin);
    throw error;
  }
}

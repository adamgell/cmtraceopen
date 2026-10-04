import { buildTimeline } from "../../../lib/commands";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { TimelineBundle } from "../../../types/timeline";

export async function buildTimelineFromSources(
  sources: { path: string; displayName?: string }[],
): Promise<TimelineBundle> {
  const timelineGeneration = useTimelineStore.getState().timelineGeneration;
  const bundle = await buildTimeline(sources);
  if (useTimelineStore.getState().timelineGeneration === timelineGeneration) {
    useTimelineStore.getState().setBundle(bundle);
  }
  return bundle;
}

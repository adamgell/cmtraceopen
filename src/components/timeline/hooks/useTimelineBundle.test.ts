import { beforeEach, describe, expect, it, vi } from "vitest";
import { buildTimeline } from "../../../lib/commands";
import { deferred } from "../../../test-utils/deferred";
import { useTimelineStore } from "../../../stores/timeline-store";
import type { TimelineBundle } from "../../../types/timeline";
import { buildTimelineFromSources } from "./useTimelineBundle";

vi.mock("../../../lib/commands", () => ({
  buildTimeline: vi.fn(),
}));

function timelineBundle(): TimelineBundle {
  return {
    id: "stale-build",
    sources: [],
    timeRangeMs: [0, 0],
    totalEntries: 0,
    incidents: [],
    deniedGuids: [],
    errors: [],
    tunables: {
      overlapWindowMs: 5_000,
      minSourceCount: 2,
      maxIncidentSpanMs: 60_000,
      enabledSignalKinds: ["errorSeverity"],
    },
  };
}

describe("buildTimelineFromSources", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useTimelineStore.getState().reset();
  });

  it("does not restore a build completed after New Timeline Empty", async () => {
    const pendingBuild = deferred<TimelineBundle>();
    vi.mocked(buildTimeline).mockReturnValueOnce(pendingBuild.promise);

    const build = buildTimelineFromSources([{ path: "/tmp/stale.log" }]);
    await vi.waitFor(() => {
      expect(buildTimeline).toHaveBeenCalledWith([{ path: "/tmp/stale.log" }]);
    });

    useTimelineStore.getState().setBundle(null);
    pendingBuild.resolve(timelineBundle());

    await expect(build).resolves.toEqual(timelineBundle());
    expect(useTimelineStore.getState().bundle).toBeNull();
  });
});

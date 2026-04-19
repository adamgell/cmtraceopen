import { describe, it, expect, beforeEach } from "vitest";
import { useTimelineStore } from "./timeline-store";
import type { TimelineBundle } from "../types/timeline";

const bundle: TimelineBundle = {
  id: "t1",
  sources: [
    {
      idx: 0,
      kind: { logFile: { parserKind: "ccm" } },
      path: "/a.log",
      displayName: "a",
      color: "#111",
      entryCount: 10,
    },
    {
      idx: 1,
      kind: { logFile: { parserKind: "ccm" } },
      path: "/b.log",
      displayName: "b",
      color: "#222",
      entryCount: 10,
    },
  ],
  timeRangeMs: [0, 10000],
  totalEntries: 20,
  incidents: [],
  deniedGuids: [],
  errors: [],
  tunables: {
    overlapWindowMs: 5000,
    minSourceCount: 2,
    maxIncidentSpanMs: 60000,
    enabledSignalKinds: ["errorSeverity"],
  },
};

describe("timeline-store", () => {
  beforeEach(() => {
    useTimelineStore.getState().reset();
  });

  it("sets bundle and initializes laneVisibility from sources", () => {
    useTimelineStore.getState().setBundle(bundle);
    const s = useTimelineStore.getState();
    expect(s.bundle?.id).toBe("t1");
    expect(s.laneVisibility).toEqual({ 0: true, 1: true });
  });

  it("solo toggle sets and clears soloSourceIdx", () => {
    useTimelineStore.getState().setBundle(bundle);
    useTimelineStore.getState().setSolo(1);
    expect(useTimelineStore.getState().soloSourceIdx).toBe(1);
    useTimelineStore.getState().setSolo(null);
    expect(useTimelineStore.getState().soloSourceIdx).toBeNull();
  });

  it("toggleMute flips just one lane", () => {
    useTimelineStore.getState().setBundle(bundle);
    useTimelineStore.getState().toggleMute(0);
    expect(useTimelineStore.getState().laneVisibility[0]).toBe(false);
    useTimelineStore.getState().toggleMute(0);
    expect(useTimelineStore.getState().laneVisibility[0]).toBe(true);
  });

  it("brushRange defaults to null, can be set and cleared", () => {
    useTimelineStore.getState().setBundle(bundle);
    expect(useTimelineStore.getState().brushRange).toBeNull();
    useTimelineStore.getState().setBrushRange([1000, 2000]);
    expect(useTimelineStore.getState().brushRange).toEqual([1000, 2000]);
    useTimelineStore.getState().clearBrushRange();
    expect(useTimelineStore.getState().brushRange).toBeNull();
  });

  it("selectIncident sets brushRange with 2s pad when incident found", () => {
    const withIncident: TimelineBundle = {
      ...bundle,
      incidents: [
        {
          id: 1,
          tsStartMs: 5000,
          tsEndMs: 5500,
          signalCount: 3,
          sourceCount: 2,
          confidence: 0.7,
          summary: "x",
        },
      ],
    };
    useTimelineStore.getState().setBundle(withIncident);
    useTimelineStore.getState().selectIncident(1);
    expect(useTimelineStore.getState().selectedIncidentId).toBe(1);
    expect(useTimelineStore.getState().brushRange).toEqual([3000, 7500]);
  });
});

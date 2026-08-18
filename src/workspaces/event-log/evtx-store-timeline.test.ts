import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
import { buildUnifiedTimeline } from "./evtx-store";
import type { EvtxRecord } from "./types";

const record = { id: 7, channel: "Security" } as EvtxRecord;

describe("buildUnifiedTimeline", () => {
  beforeEach(() => {
    vi.mocked(invoke).mockReset();
  });

  it("uses the loaded records and parser entries with the real timeline command", async () => {
    const timeline = { items: [], unplaced: [] };
    vi.mocked(invoke).mockResolvedValue(timeline);

    await expect(buildUnifiedTimeline([record])).resolves.toEqual(timeline);
    expect(invoke).toHaveBeenCalledWith("evtx_build_unified_timeline", {
      entries: [],
      records: [record],
    });
  });
});

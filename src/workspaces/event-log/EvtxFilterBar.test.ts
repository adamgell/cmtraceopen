import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { eventLogTimeWindowSnapshotLabel } from "./EvtxFilterBar";

describe("eventLogTimeWindowSnapshotLabel", () => {
  it("labels a relative live window with the passed snapshot time", () => {
    const nowEpoch = Date.UTC(2026, 7, 30, 17, 42, 13);

    expect(eventLogTimeWindowSnapshotLabel("7d", nowEpoch)).toBe(
      `Last 7 days · as of ${new Date(nowEpoch).toLocaleString()}`,
    );
  });

  it("hides the snapshot time for the all-time window", () => {
    expect(eventLogTimeWindowSnapshotLabel("all", 123)).toBe("All time");
  });
});

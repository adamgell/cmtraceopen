import { beforeEach, describe, expect, it, vi } from "vitest";
import type { EventLogSourceManifest } from "./types";

const expandEventLogSources = vi.hoisted(() => vi.fn());
const parseManifest = vi.hoisted(() => vi.fn());

vi.mock("../../lib/commands", () => ({ expandEventLogSources }));
vi.mock("./evtx-store", () => ({
  useEvtxStore: { getState: () => ({ parseManifest }) },
}));

const { openEventLogSources } = await import("./open-event-log-source");
beforeEach(() => {
  expandEventLogSources.mockReset();
  parseManifest.mockReset();
});

describe("openEventLogSources provenance", () => {
  it("keeps backend archive and VSS kinds when the picker reports a generic file", async () => {
    const manifest: EventLogSourceManifest = {
      entries: [
        { sourceId: "archive", path: "Archive-Application.evtx", kind: "archive" },
        { sourceId: "vss", path: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Application.evtx", kind: "vss" },
      ],
      coverage: [],
    };
    expandEventLogSources.mockResolvedValue(manifest);

    await openEventLogSources([
      { kind: "file", path: "Archive-Application.evtx" },
      { kind: "file", path: "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Application.evtx" },
    ]);

    expect(parseManifest).toHaveBeenCalledWith(manifest);
    expect(parseManifest.mock.calls[0][0].entries.map((entry: { kind: string }) => entry.kind)).toEqual([
      "archive",
      "vss",
    ]);
  });

});

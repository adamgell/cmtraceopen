import { describe, expect, it, vi } from "vitest";

vi.mock("../../stores/ui-store", () => ({
  useUiStore: {
    getState: () => ({ ensureWorkspaceVisible: vi.fn() }),
  },
}));

import { eventLogWorkspace } from "../event-log";
import { timelineWorkspace } from ".";

describe("Timeline source picker", () => {
  it("leaves EVTX selection to the Event Log workspace", () => {
    const timelineLogFilter = timelineWorkspace.fileFilters?.find(
      (filter) => filter.name === "Log Files",
    );
    const eventLogFilter = eventLogWorkspace.fileFilters?.find(
      (filter) => filter.name === "EVTX Files",
    );

    expect(timelineLogFilter?.extensions).toEqual(["log", "cmtlog"]);
    expect(eventLogFilter?.extensions).toContain("evtx");
  });
});

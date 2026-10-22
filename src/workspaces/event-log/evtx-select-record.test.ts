import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { selectRecordAndShowDetails } from "./evtx-select-record";
import { useEvtxStore } from "./evtx-store";

describe("selectRecordAndShowDetails", () => {
  beforeEach(() => {
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
  });

  it("selects the record, switches to Details and shows a hidden rail", () => {
    useEvtxLayoutStore.getState().setPanel("insights", false);

    selectRecordAndShowDetails(7);

    expect(useEvtxStore.getState().selectedRecordId).toBe(7);
    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(true);
  });

  it("brings Details back when the already-selected record is chosen again, never toggling it off", () => {
    selectRecordAndShowDetails(7);
    useEvtxLayoutStore.getState().setRailTab("insights");
    useEvtxLayoutStore.getState().setPanel("insights", false);

    selectRecordAndShowDetails(7);

    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(true);
    expect(useEvtxStore.getState().selectedRecordId).toBe(7);
  });
});

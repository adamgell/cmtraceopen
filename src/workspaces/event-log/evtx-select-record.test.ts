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

  it("brings Details back when the already-selected record is chosen again", () => {
    selectRecordAndShowDetails(7);
    useEvtxLayoutStore.getState().setRailTab("insights");
    useEvtxLayoutStore.getState().setPanel("insights", false);

    selectRecordAndShowDetails(7);

    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(true);
  });

  it("leaves the layout alone when the selection is cleared", () => {
    selectRecordAndShowDetails(7);
    useEvtxLayoutStore.getState().setPanel("insights", false);

    selectRecordAndShowDetails(null);

    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(false);
  });

  it("is not triggered by the store reassigning the selection", () => {
    selectRecordAndShowDetails(7);
    useEvtxLayoutStore.getState().setRailTab("insights");
    useEvtxLayoutStore.getState().setPanel("insights", false);

    useEvtxStore.setState({ selectedRecordId: 8 });

    expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
    expect(useEvtxLayoutStore.getState().panels.insights).toBe(false);
  });
});

import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { EvtxInsightsRail } from "./EvtxInsightsRail";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { selectRecordAndShowDetails } from "./evtx-select-record";
import { useEvtxStore } from "./evtx-store";
import { useMarkerStore } from "../../stores/marker-store";
import type { DiagnosisSummary, EvtxRecord } from "./types";

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: Date.parse("2026-08-18T12:00:00Z"),
  provider: "Example Provider",
  channel: "Application",
  eventId: 1000,
  level: "Error",
  computer: "TEST-PC",
  message: "Example event message",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
};

const SUMMARY: DiagnosisSummary = {
  findings: [
    {
      findingId: "f-1",
      class: "confirmedFailure",
      severity: "error",
      confidence: "high",
      title: "Enrollment failed",
      summary: "The provider reported a failure.",
      evidence: [],
      coverageGaps: [],
      recommendedChecks: [],
    },
  ],
  evidence: [],
  coverageGaps: [],
  correlations: [],
  events: [],
  overview: {
    outcome: "confirmedFailure",
    headline: "Evidence contains confirmed operational failure(s).",
    findingCount: 1,
    actionableFindingCount: 1,
    coverageGapCount: 0,
    evidenceCount: 0,
    correlationCount: 0,
    errorTokenEventCount: 0,
  },
};

const tab = (name: string) => screen.getByRole("tab", { name });

describe("EvtxInsightsRail", () => {
  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue([]);
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
    useEvtxStore.setState({ records: [RECORD] });
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:sample.evtx"]),
    });
  });

  afterEach(cleanup);

  it("renders the Insights and Details tabs only, Insights first and selected", () => {
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);

    const list = screen.getByRole("tablist", { name: "Rail tabs" });
    const tabs = within(list).getAllByRole("tab");
    expect(tabs).toHaveLength(2);
    expect(tab("Insights 1")).toHaveAttribute("aria-selected", "true");
    expect(tab("Details")).toHaveAttribute("aria-selected", "false");
    // The Chains tab is built in Phase 10c.
    expect(screen.queryByRole("tab", { name: /Chains/ })).toBeNull();
  });

  it("counts actionable findings from the authoritative total on the Insights tab", () => {
    render(
      <EvtxInsightsRail
        summary={{ ...SUMMARY, overview: { ...SUMMARY.overview, actionableFindingCount: 712 } }}
        records={[RECORD]}
      />,
    );
    expect(tab("Insights 712")).toBeInTheDocument();
  });

  it("shows no count while the diagnosis is pending", () => {
    render(<EvtxInsightsRail summary={null} records={[]} />);
    expect(tab("Insights")).toBeInTheDocument();
  });

  it("renders the diagnosis under Insights and the record under Details", () => {
    useEvtxStore.setState({ selectedRecordId: RECORD.id });
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);

    expect(screen.getByLabelText("Operational diagnosis")).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Event log details" })).toBeNull();

    fireEvent.click(tab("Event 1000"));

    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(screen.getByRole("region", { name: "Event log details" })).toBeInTheDocument();
    expect(screen.queryByLabelText("Operational diagnosis")).toBeNull();
    expect(screen.getByRole("tabpanel")).toHaveAttribute(
      "aria-labelledby",
      tab("Event 1000").id,
    );
  });

  it('labels the Details tab "Event {id}" while a record is selected', () => {
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
    expect(tab("Details")).toBeInTheDocument();

    act(() => useEvtxStore.setState({ selectedRecordId: RECORD.id }));

    expect(tab("Event 1000")).toBeInTheDocument();
    expect(screen.queryByRole("tab", { name: "Details" })).toBeNull();

    act(() => useEvtxStore.setState({ selectedRecordId: null }));
    expect(tab("Details")).toBeInTheDocument();
  });

  it("follows a record selection made elsewhere: the Details tab opens", () => {
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);

    act(() => selectRecordAndShowDetails(RECORD.id));

    expect(tab("Event 1000")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Example event message")).toBeInTheDocument();
  });

  it("closing the details returns to Insights and clears the selection", () => {
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
    act(() => selectRecordAndShowDetails(RECORD.id));

    fireEvent.click(screen.getByRole("button", { name: "Close details" }));

    expect(useEvtxStore.getState().selectedRecordId).toBeNull();
    expect(tab("Insights 1")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByLabelText("Operational diagnosis")).toBeInTheDocument();
  });

  it("shows Insights when the persisted tab is Chains, which does not exist yet", () => {
    useEvtxLayoutStore.setState({ railTab: "chains" });
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);

    expect(tab("Insights 1")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByLabelText("Operational diagnosis")).toBeInTheDocument();
  });

  it("shows the empty details prompt when Details is opened with no selection", () => {
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
    fireEvent.click(tab("Details"));
    expect(screen.getByText("Select a record to view details.")).toBeInTheDocument();
  });
});

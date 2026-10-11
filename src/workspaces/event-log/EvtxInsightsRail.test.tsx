import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { EvtxInsightsRail } from "./EvtxInsightsRail";
import { evtxRailPanelId, sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
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
    invoke.mockResolvedValue(null);
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

    expect(screen.getByLabelText("Operational diagnosis")).toBeVisible();
    expect(screen.queryByRole("region", { name: "Event log details" })).toBeNull();

    fireEvent.click(tab("Event 1000"));

    expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    expect(screen.getByRole("region", { name: "Event log details" })).toBeInTheDocument();
    // Insights stays mounted but hidden, so its state survives.
    expect(screen.getByLabelText("Operational diagnosis", { selector: "section" })).not.toBeVisible();
    const panel = document.getElementById(evtxRailPanelId("details")) as HTMLElement;
    expect(panel).toHaveAttribute("aria-labelledby", tab("Event 1000").id);
    expect(tab("Event 1000")).toHaveAttribute("aria-controls", panel.id);
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
    expect(screen.getByLabelText("Operational diagnosis")).toBeVisible();
  });

  it("moves focus to the Insights tab when Close removes the focused button", () => {
    render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
    act(() => selectRecordAndShowDetails(RECORD.id));
    const close = screen.getByRole("button", { name: "Close details" });
    close.focus();

    fireEvent.click(close);

    expect(tab("Insights 1")).toHaveFocus();
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

  describe("restart, rebuilds and cost", () => {
    const withGap: DiagnosisSummary = {
      ...SUMMARY,
      coverageGaps: [
        { id: "g", source: "x.log", state: "absent", detail: "Not captured.", evidence: [] },
      ],
      overview: { ...SUMMARY.overview, coverageGapCount: 1 },
    };

    it("opens on Insights after a restart that left the tab on Details with nothing selected", () => {
      useEvtxLayoutStore.setState({ railTab: "details" });
      render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);

      expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
      expect(screen.getByLabelText("Operational diagnosis")).toBeVisible();
    });

    it("keeps Details when it was left on a record that is still selected", () => {
      useEvtxStore.setState({ selectedRecordId: RECORD.id });
      useEvtxLayoutStore.setState({ railTab: "details" });
      render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);

      expect(useEvtxLayoutStore.getState().railTab).toBe("details");
    });

    it("restores the Insights scroll offset after the rail is hidden and shown again", () => {
      render(<EvtxInsightsRail summary={withGap} records={[RECORD]} />);
      const panel = document.getElementById(evtxRailPanelId("insights")) as HTMLElement;
      panel.scrollTop = 180;
      fireEvent.scroll(panel);

      act(() => useEvtxLayoutStore.getState().setPanel("insights", false));
      // A browser drops the offset of a hidden element; jsdom does not, so do it here.
      panel.scrollTop = 0;
      act(() => useEvtxLayoutStore.getState().setPanel("insights", true));

      expect(panel.scrollTop).toBe(180);
    });

    it("states the scope the shown build was made from while a rebuild is pending", () => {
      const { rerender } = render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
      const three = [RECORD, { ...RECORD, id: 2 }, { ...RECORD, id: 3 }];
      rerender(<EvtxInsightsRail summary={null} records={three} pending />);

      const section = screen.getByLabelText("Operational diagnosis");
      expect(section).toHaveTextContent("Scoped to 1 visible event");
      expect(section).not.toHaveTextContent("Scoped to 3");

      rerender(<EvtxInsightsRail summary={{ ...SUMMARY }} records={three} />);
      expect(screen.getByLabelText("Operational diagnosis")).toHaveTextContent(
        "Scoped to 3 visible events",
      );
    });

    it("suppresses the Details callout while a rebuild is pending", () => {
      const evidenceSummary: DiagnosisSummary = {
        ...SUMMARY,
        findings: [
          {
            ...SUMMARY.findings[0],
            evidence: [
              {
                kind: "event",
                value: {
                  source: RECORD.sourceLabel,
                  provider: RECORD.provider,
                  eventId: RECORD.eventId,
                  recordId: RECORD.eventRecordId,
                  channel: RECORD.channel,
                  machine: "[host:0123456789abcdef]",
                },
              },
            ],
          },
        ],
      };
      useEvtxStore.setState({ selectedRecordId: RECORD.id });
      useEvtxLayoutStore.setState({ railTab: "details" });
      const { rerender } = render(<EvtxInsightsRail summary={evidenceSummary} records={[RECORD]} />);
      expect(screen.getByRole("button", { name: /Part of finding/ })).toBeInTheDocument();

      rerender(<EvtxInsightsRail summary={null} records={[RECORD]} pending />);
      expect(screen.queryByRole("button", { name: /Part of finding/ })).toBeNull();
    });

    it("keeps the open disclosures and the scroll position across a row click and back", () => {
      render(<EvtxInsightsRail summary={withGap} records={[RECORD]} />);
      fireEvent.click(screen.getByText(/Coverage gaps/, { selector: "summary" }));
      const panel = document.getElementById(evtxRailPanelId("insights")) as HTMLElement;
      panel.scrollTop = 240;
      fireEvent.scroll(panel);

      act(() => selectRecordAndShowDetails(RECORD.id));
      expect(panel).not.toBeVisible();
      act(() => useEvtxLayoutStore.getState().setRailTab("insights"));

      expect(
        (screen.getByText(/Coverage gaps/, { selector: "summary" }).closest("details") as HTMLDetailsElement).open,
      ).toBe(true);
      expect(panel.scrollTop).toBe(240);
    });

    it("keeps showing the previous diagnosis, marked as updating, while it rebuilds", () => {
      const { rerender } = render(
        <EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />,
      );
      rerender(<EvtxInsightsRail summary={null} records={[RECORD]} pending />);

      expect(screen.getByText("Enrollment failed")).toBeInTheDocument();
      expect(screen.getByRole("status")).toHaveTextContent("Updating diagnosis...");
      // The previous build's count is not shown as the new build's.
      expect(tab("Insights")).toBeInTheDocument();
      expect(screen.queryByRole("tab", { name: "Insights 1" })).toBeNull();
      expect(screen.getByRole("region", { name: "Level mix" })).toBeInTheDocument();
    });

    it("drops the previous diagnosis once the build fails, and says so", () => {
      const { rerender } = render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
      rerender(
        <EvtxInsightsRail
          summary={null}
          records={[RECORD]}
          error="Operational diagnosis could not be built: boom"
        />,
      );

      expect(screen.queryByText("Enrollment failed")).toBeNull();
      expect(screen.getByRole("status")).toHaveTextContent(/^Diagnosis could not be built\.$/);
    });

    it("says there is nothing to diagnose when there is no input and no build running", () => {
      render(<EvtxInsightsRail summary={null} records={[]} />);
      expect(screen.getByRole("status")).toHaveTextContent(
        "There are no events or text logs to diagnose.",
      );
    });

    it("debounces the record-derived cards by 75 ms", () => {
      vi.useFakeTimers();
      try {
        const { rerender } = render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
        const level = () => screen.getByRole("region", { name: "Level mix" });
        expect(level()).toHaveTextContent("Error 1");

        rerender(
          <EvtxInsightsRail
            summary={SUMMARY}
            records={[RECORD, { ...RECORD, id: 2, level: "Warning" }]}
          />,
        );
        expect(level()).not.toHaveTextContent("Warning");
        act(() => void vi.advanceTimersByTime(74));
        expect(level()).not.toHaveTextContent("Warning");
        act(() => void vi.advanceTimersByTime(2));
        expect(level()).toHaveTextContent("Warning 1");
      } finally {
        vi.useRealTimers();
      }
    });

    it("skips the record-derived cards while the rail is hidden", () => {
      useEvtxLayoutStore.getState().setPanel("insights", false);
      render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} />);
      expect(screen.queryByRole("region", { name: "Level mix" })).toBeNull();

      act(() => useEvtxLayoutStore.getState().setPanel("insights", true));
      expect(screen.getByRole("region", { name: "Level mix" })).toBeInTheDocument();
    });
  });
});

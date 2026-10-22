import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
const indexBuilds = vi.hoisted(() => ({ count: 0 }));

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
// The real index builder, counted: how often the rail asks the panel to index the records.
vi.mock("./evtx-insights-data", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./evtx-insights-data")>();
  return {
    ...actual,
    buildEvidenceIndex: (...args: Parameters<typeof actual.buildEvidenceIndex>) => {
      indexBuilds.count += 1;
      return actual.buildEvidenceIndex(...args);
    },
  };
});
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import {
  EvtxInsightsRail,
  quickFilterAfterEventIdClick,
  soleQuickFilterEventId,
} from "./EvtxInsightsRail";
import { DEFAULT_QUICK_FILTER, type EvtxQuickFilter } from "./evtx-filter";
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
      const one = { visibleCount: 1, loadedCount: 1, textLogCount: 0 };
      const { rerender } = render(<EvtxInsightsRail summary={SUMMARY} records={[RECORD]} scope={one} />);
      const three = [RECORD, { ...RECORD, id: 2 }, { ...RECORD, id: 3 }];
      // The newer session's scope arrives while its summary is still being built: the shown build
      // keeps the scope it was made with.
      rerender(
        <EvtxInsightsRail
          summary={null}
          records={three}
          scope={{ visibleCount: 3, loadedCount: 3, textLogCount: 0 }}
          pending
        />,
      );

      const section = screen.getByLabelText("Operational diagnosis");
      expect(section).toHaveTextContent("Scoped to 1 visible event");
      expect(section).not.toHaveTextContent("Scoped to 3");

      rerender(
        <EvtxInsightsRail
          summary={{ ...SUMMARY }}
          records={three}
          scope={{ visibleCount: 3, loadedCount: 3, textLogCount: 0 }}
        />,
      );
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

    it("keeps publishing while records change continuously, so a tail cannot starve the cards", () => {
      vi.useFakeTimers();
      try {
        const make = (count: number) =>
          Array.from({ length: count }, (_, index) => ({ ...RECORD, id: index + 1 }));
        const { rerender } = render(<EvtxInsightsRail summary={SUMMARY} records={make(1)} />);
        const level = () => screen.getByRole("region", { name: "Level mix" });
        expect(level()).toHaveTextContent("Error 1");

        // A new batch every 20 ms for 300 ms: a trailing debounce would never publish.
        for (let step = 1; step <= 15; step += 1) {
          act(() => {
            rerender(<EvtxInsightsRail summary={SUMMARY} records={make(1 + step)} />);
            vi.advanceTimersByTime(20);
          });
        }
        // Several publishes happened during the burst: the cards show a count past the first
        // batch although the records are still changing.
        const during = Number(/Error (\d+)/.exec(level().textContent ?? "")?.[1]);
        expect(during).toBeGreaterThan(1);
        expect(during).toBeLessThan(16);
        act(() => void vi.advanceTimersByTime(80));
        expect(level()).toHaveTextContent("Error 16");
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

/**
 * Phase 6a (#834): the rail wires the panel's two actions to the stores. These use the real stores
 * and the real layout, with only the Tauri bridge mocked.
 */
describe("EvtxInsightsRail filter actions", () => {
  const loaded: EvtxRecord[] = [1, 2, 3, 4].map((n) => ({
    ...RECORD,
    id: n,
    eventRecordId: n,
    eventId: n <= 3 ? 1000 : 2000,
    timestampEpoch: n * 1000,
  }));
  const eventRef = (recordId: number) => ({
    kind: "event" as const,
    value: { source: "sample.evtx", provider: "Example Provider", eventId: 1000, recordId },
  });
  const citing = (title: string, ...recordIds: number[]): DiagnosisSummary => ({
    ...SUMMARY,
    findings: [{ ...SUMMARY.findings[0], title, evidence: recordIds.map(eventRef) }],
  });
  const queries = () => invoke.mock.calls.filter(([name]) => name === "evtx_query_channels");

  beforeEach(() => {
    invoke.mockReset();
    invoke.mockResolvedValue(null);
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
    useEvtxStore.setState({
      records: loaded,
      sourceMode: "live",
      channels: [{ name: "Application", eventCount: 4, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
      selectedChannels: new Set(["Application"]),
    });
    useMarkerStore.setState({ markersByFile: new Map(), loadingFiles: new Set(["event-log:sample.evtx"]) });
  });
  afterEach(cleanup);

  describe("Filter to {n} events", () => {
    it("scopes the view to the events the finding names, keeps its title, and shows the Table", () => {
      useEvtxLayoutStore.getState().setActiveView("grouped");
      render(<EvtxInsightsRail summary={citing("Enrollment failed", 1, 3)} records={loaded} />);

      fireEvent.click(screen.getByRole("button", { name: /Filter to 2 events/ }));

      const scope = useEvtxStore.getState().recordScope;
      expect(scope).toMatchObject({ kind: "finding", title: "Enrollment failed" });
      expect([...(scope?.records ?? [])]).toEqual([loaded[0], loaded[2]]);
      expect(useEvtxLayoutStore.getState().activeView).toBe("table");
      expect(useEvtxLayoutStore.getState().railTab).toBe("insights");
    });

    it("sends no query: a record scope is local to the loaded events", async () => {
      render(<EvtxInsightsRail summary={citing("Enrollment failed", 1)} records={loaded} />);
      fireEvent.click(screen.getByRole("button", { name: /Filter to 1 event/ }));
      await act(async () => {
        await Promise.resolve();
      });
      expect(queries()).toHaveLength(0);
      expect(useEvtxStore.getState().isLoading).toBe(false);
    });

    it("keeps the finding's title in the scope when a rebuilt diagnosis drops the finding", () => {
      const { rerender } = render(
        <EvtxInsightsRail summary={citing("Enrollment failed", 1, 2)} records={loaded} />,
      );
      fireEvent.click(screen.getByRole("button", { name: /Filter to 2 events/ }));
      // The scoped rebuild finds nothing actionable.
      rerender(
        <EvtxInsightsRail
          summary={{ ...SUMMARY, findings: [], overview: { ...SUMMARY.overview, actionableFindingCount: 0 } }}
          records={[loaded[0], loaded[1]]}
        />,
      );
      expect(screen.queryByRole("button", { name: /Filter to/ })).toBeNull();
      expect(useEvtxStore.getState().recordScope?.title).toBe("Enrollment failed");
    });

    it("does not switch views when the store refuses the scope", () => {
      useEvtxLayoutStore.getState().setActiveView("grouped");
      render(<EvtxInsightsRail summary={citing("Enrollment failed", 1)} records={loaded} />);
      act(() => useEvtxStore.setState({ isLoading: true }));
      fireEvent.click(screen.getByRole("button", { name: /Filter to 1 event/ }));
      expect(useEvtxStore.getState().recordScope).toBeNull();
      expect(useEvtxLayoutStore.getState().activeView).toBe("grouped");
    });

    it("keeps what each cited event named, so a later change to the records is counted by event", async () => {
      // A cites one event in System; B cites one that two events in Application both match.
      const a = { ...RECORD, id: 1, eventRecordId: 11, channel: "System", sourceLabel: "System.evtx" };
      const b1 = { ...RECORD, id: 2, eventRecordId: 12, sourceLabel: "x1.evtx" };
      const b2 = { ...RECORD, id: 3, eventRecordId: 12, sourceLabel: "x2.evtx" };
      const both = [a, b1, b2];
      const ref = (recordId: number) => ({
        kind: "event" as const,
        value: { provider: "Example Provider", eventId: 1000, recordId, source: undefined as unknown as string },
      });
      useEvtxStore.setState({
        records: both,
        channels: [
          { name: "Application", eventCount: 2, sourceType: "live" },
          { name: "System", eventCount: 1, sourceType: "live" },
        ],
        loadedChannels: new Set(["Application", "System"]),
        selectedChannels: new Set(["Application", "System"]),
      });
      invoke.mockImplementation(async (name: string, args?: Record<string, unknown>) =>
        name === "evtx_clear_channel" ? { channel: args?.channel, result: { status: "cleared" } } : null,
      );
      const summary: DiagnosisSummary = {
        ...SUMMARY,
        findings: [{ ...SUMMARY.findings[0], evidence: [ref(11), ref(12)] }],
      };
      render(<EvtxInsightsRail summary={summary} records={both} />);

      fireEvent.click(screen.getByRole("button", { name: /Filter to 3 events/ }));
      const scope = useEvtxStore.getState().recordScope;
      expect(scope?.references).toEqual([[a], [b1, b2]]);
      expect(scope?.counts).toMatchObject({ notLoaded: 0, ambiguous: 1 });

      await act(async () => {
        await useEvtxStore.getState().clearChannel("Application", true);
      });
      const after = useEvtxStore.getState().recordScope;
      expect([...(after?.records ?? [])]).toEqual([a]);
      // One cited event is gone, not two records; and it no longer matches several.
      expect(after?.counts).toMatchObject({ notLoaded: 1, ambiguous: 0 });
    });

    it("replaces a scope that was already set", () => {
      render(<EvtxInsightsRail summary={citing("Enrollment failed", 2)} records={loaded} />);
      act(() => {
        useEvtxStore.getState().setRecordScope({
          kind: "finding",
          title: "Older",
          records: new Set([loaded[3]]),
          counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
        });
      });
      fireEvent.click(screen.getByRole("button", { name: /Filter to 1 event/ }));
      expect(useEvtxStore.getState().recordScope?.title).toBe("Enrollment failed");
      expect([...(useEvtxStore.getState().recordScope?.records ?? [])]).toEqual([loaded[1]]);
    });
  });

  describe("cost", () => {
    beforeEach(() => {
      indexBuilds.count = 0;
    });

    it("indexes the records once for a diagnosis that cites events, not once per rail render", () => {
      render(<EvtxInsightsRail summary={citing("Enrollment failed", 1, 2)} records={loaded} />);
      expect(indexBuilds.count).toBe(1);

      // The rail re-renders on a selection, a quick filter and a scope; none of them is new evidence.
      act(() => useEvtxStore.setState({ selectedRecordId: 2 }));
      act(() => useEvtxStore.setState({ selectedRecordId: 3 }));
      act(() => {
        useEvtxStore.getState().setQuickFilter({ ...DEFAULT_QUICK_FILTER, query: "x" });
      });
      fireEvent.click(screen.getByRole("button", { name: /Filter to 2 events/ }));
      expect(indexBuilds.count).toBe(1);
    });

    it("indexes again when the records change, after the rail's 75 ms throttle", async () => {
      const summary = citing("Enrollment failed", 1);
      const { rerender } = render(<EvtxInsightsRail summary={summary} records={loaded} />);
      rerender(<EvtxInsightsRail summary={summary} records={[...loaded]} />);
      await waitFor(() => expect(indexBuilds.count).toBe(2));
    });

    it("builds no index for a diagnosis whose findings cite no event", () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded} />);
      act(() => useEvtxStore.setState({ selectedRecordId: 2 }));
      expect(indexBuilds.count).toBe(0);
    });
  });

  describe("Top event IDs", () => {
    const row = (name: string) => screen.getByRole("button", { name });
    const quick = () => useEvtxStore.getState().quickFilter;

    it("applies the ID as an Event IDs quick filter that shows matches, without a query", async () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded} />);
      fireEvent.click(row("Event ID 1000, 3 events"));

      expect(quick()).toMatchObject({ mode: "eventIds", action: "show", query: "1000" });
      expect(useEvtxStore.getState().quickFilterDraft).toBeNull();
      await act(async () => {
        await Promise.resolve();
      });
      expect(queries()).toHaveLength(0);
      expect(useEvtxStore.getState().isLoading).toBe(false);
    });

    it("presses the row of the ID it applied, and clears the filter on a second click", () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded} />);
      fireEvent.click(row("Event ID 1000, 3 events"));
      expect(row("Event ID 1000, 3 events")).toHaveAttribute("aria-pressed", "true");
      expect(row("Event ID 2000, 1 event")).toHaveAttribute("aria-pressed", "false");

      fireEvent.click(row("Event ID 1000, 3 events"));
      expect(quick().query).toBe("");
      expect(quick().mode).toBe("eventIds");
      expect(row("Event ID 1000, 3 events")).toHaveAttribute("aria-pressed", "false");
    });

    it("replaces the quick filter that was there, keeping its scope, case and highlight settings", () => {
      act(() => {
        useEvtxStore.getState().setQuickFilter({
          ...DEFAULT_QUICK_FILTER,
          mode: "allWords",
          action: "hide",
          query: "noise words",
          scope: "visibleColumns",
          caseSensitive: true,
          highlight: false,
        });
      });
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded} />);
      fireEvent.click(row("Event ID 2000, 1 event"));
      expect(quick()).toEqual({
        mode: "eventIds",
        action: "show",
        query: "2000",
        scope: "visibleColumns",
        caseSensitive: true,
        highlight: false,
      });
    });

    it("discards a quick filter that was typed but not applied, and shows the ID instead", () => {
      act(() => {
        useEvtxStore.getState().setQuickFilter({ ...DEFAULT_QUICK_FILTER, mode: "fieldQuery", query: "level:erro" });
      });
      expect(useEvtxStore.getState().quickFilterDraft?.query).toBe("level:erro");
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded} />);
      fireEvent.click(row("Event ID 1000, 3 events"));
      expect(useEvtxStore.getState().quickFilterDraft).toBeNull();
      expect(quick()).toMatchObject({ mode: "eventIds", query: "1000" });
    });
  });

  describe("text logs", () => {
    const panelText = () => screen.getByLabelText("Operational diagnosis");
    /** What the workspace gives for a session: the counts read when it was published. */
    const scopeOf = (visibleCount: number, loadedCount: number, textLogCount: number) => ({
      visibleCount,
      loadedCount,
      textLogCount,
    });

    it("says they are not scoped when the visible events are fewer than the loaded ones", () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded.slice(0, 2)} scope={scopeOf(2, 4, 2)} />);
      expect(panelText()).toHaveTextContent("Scoped to 2 visible events");
      expect(panelText()).toHaveTextContent("Text logs are not scoped.");
    });

    it("says nothing when every loaded event is visible, text logs or not", () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded} scope={scopeOf(4, 4, 2)} />);
      expect(panelText()).toHaveTextContent("Scoped to 4 visible events");
      expect(panelText()).not.toHaveTextContent("Text logs are not scoped.");
    });

    it("counts a narrowing by a time range or a record scope as well as by a filter", () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={[loaded[1]]} scope={scopeOf(1, 4, 1)} />);
      expect(panelText()).toHaveTextContent("Text logs are not scoped.");
    });

    it("states no scope at all when it is given none, rather than counting the records it was handed", () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded.slice(0, 2)} />);
      expect(panelText()).not.toHaveTextContent("Scoped to");
      expect(panelText()).not.toHaveTextContent("Text logs are not scoped.");
    });

    it("states, with the build it came from, what the session held and how many events were loaded", () => {
      const { rerender } = render(
        <EvtxInsightsRail summary={SUMMARY} records={loaded.slice(0, 2)} scope={scopeOf(2, 4, 2)} />,
      );
      expect(panelText()).toHaveTextContent("Text logs are not scoped.");
      // The counts belong to the build, as the scope count does: another scope with the same summary
      // does not rewrite what that build was given.
      act(() => useEvtxStore.setState({ records: loaded.slice(0, 2) }));
      rerender(<EvtxInsightsRail summary={SUMMARY} records={loaded.slice(0, 2)} scope={scopeOf(2, 2, 0)} />);
      expect(panelText()).toHaveTextContent("Scoped to 2 visible events");
      expect(panelText()).toHaveTextContent("Text logs are not scoped.");
      // A new build is made with what is true now: two events loaded, two visible, so nothing narrowed.
      rerender(<EvtxInsightsRail summary={{ ...SUMMARY }} records={loaded.slice(0, 2)} scope={scopeOf(2, 2, 2)} />);
      expect(panelText()).not.toHaveTextContent("Text logs are not scoped.");
    });

    it("reads the loaded count from the session's scope, not from the records loaded now (V1)", () => {
      // Four events are loaded in the store, but the session was published with two loaded: it is
      // not narrowed, whatever the store holds by the time the summary is drawn.
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded.slice(0, 2)} scope={scopeOf(2, 2, 3)} />);
      expect(useEvtxStore.getState().records.length).toBe(4);
      expect(panelText()).toHaveTextContent("Scoped to 2 visible events");
      expect(panelText()).not.toHaveTextContent("Text logs are not scoped.");
    });

    it("reads the text-log count from the session's scope, not from a prop of its own", () => {
      render(<EvtxInsightsRail summary={SUMMARY} records={loaded.slice(0, 2)} scope={scopeOf(2, 4, 0)} />);
      expect(panelText()).toHaveTextContent("Scoped to 2 visible events");
      expect(panelText()).not.toHaveTextContent("Text logs are not scoped.");
    });
  });
});

describe("soleQuickFilterEventId and quickFilterAfterEventIdClick", () => {
  const filter = (overrides: Partial<EvtxQuickFilter>): EvtxQuickFilter => ({
    ...DEFAULT_QUICK_FILTER,
    ...overrides,
  });

  it("names the one ID an Event IDs show filter has, and no other", () => {
    expect(soleQuickFilterEventId(filter({ mode: "eventIds", query: "4624" }))).toBe(4624);
    expect(soleQuickFilterEventId(filter({ mode: "eventIds", query: " 4624 " }))).toBe(4624);
    for (const query of ["4624,4625", "4620-4630", "4624 x", "", "abc"]) {
      expect(soleQuickFilterEventId(filter({ mode: "eventIds", query })), query).toBeNull();
    }
    expect(soleQuickFilterEventId(filter({ mode: "eventIds", query: "4624", action: "hide" }))).toBeNull();
    expect(soleQuickFilterEventId(filter({ mode: "oneString", query: "4624" }))).toBeNull();
  });

  it("replaces the filter with the ID, keeping the settings, and clears only the query on a repeat", () => {
    const shown = filter({ mode: "multipleWords", action: "hide", query: "noise", caseSensitive: true });
    expect(quickFilterAfterEventIdClick(shown, shown, 7036)).toEqual({
      ...shown,
      mode: "eventIds",
      action: "show",
      query: "7036",
    });
    const applied = filter({ mode: "eventIds", query: "7036", caseSensitive: true });
    expect(quickFilterAfterEventIdClick(applied, applied, 7036)).toEqual({ ...applied, query: "" });
    expect(quickFilterAfterEventIdClick(applied, applied, 7040)).toMatchObject({ query: "7040" });
  });

  it("takes the settings from the filter being edited when it differs from the applied one", () => {
    const applied = filter({ mode: "eventIds", query: "1", highlight: true });
    const shown = filter({ mode: "fieldQuery", query: "level:erro", highlight: false });
    expect(quickFilterAfterEventIdClick(applied, shown, 2)).toMatchObject({ query: "2", highlight: false });
  });
});

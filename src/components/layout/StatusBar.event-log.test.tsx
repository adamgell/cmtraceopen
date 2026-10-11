/**
 * Event Logs content of the global status bar (spec 8.14): source mode, channels, text logs,
 * counts, view and updated time, plus the Correlation view variant.
 *
 * The real stores are used, so a renamed field fails to compile instead of drifting from a hand
 * mock. Only the Tauri event bridge is mocked: the workspace stores register listeners at module
 * scope.
 */
import { act, cleanup, render, screen, within } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => undefined),
}));

import fixtureDocument from "../../workspaces/event-log/__fixtures__/correlation-edges.json";
import { buildCorrelationChains } from "../../workspaces/event-log/evtx-correlation-chains";
import {
  sanitizeLayout,
  useEvtxLayoutStore,
  type EvtxViewId,
} from "../../workspaces/event-log/evtx-layout-store";
import { useEvtxStore } from "../../workspaces/event-log/evtx-store";
import {
  summarizeEvtxCorrelationStatus,
  summarizeVisibleRecords,
  useEvtxCorrelationStatusStore,
  useEvtxVisibleSummaryStore,
} from "../../workspaces/event-log/evtx-status-summary";
import type {
  EvtxChannelInfo,
  EvtxLevel,
  EvtxRecord,
} from "../../workspaces/event-log/types";
import {
  assertUnifiedTimelineShape,
  type TimelineCorrelationEdge,
} from "../../workspaces/event-log/unified-timeline";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import {
  StatusBar,
  buildEvtxCorrelationSegments,
  buildEvtxCountsSegments,
  countTextLogFiles,
  evtxStatusText,
} from "./StatusBar";

let nextRecordId = 0;

/** A placeholder machine and provider; no real host names appear in fixtures. */
function record(level: EvtxLevel, channel = "Application"): EvtxRecord {
  nextRecordId += 1;
  return {
    id: nextRecordId,
    eventRecordId: nextRecordId,
    timestamp: "2026-10-10T12:00:00.000Z",
    timestampEpoch: Date.UTC(2026, 9, 10, 12, 0, nextRecordId),
    provider: "Contoso-Provider",
    channel,
    eventId: 1000 + nextRecordId,
    level,
    computer: "CONTOSO-PC01",
    message: `event ${nextRecordId}`,
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
  };
}

function channelInfo(name: string): EvtxChannelInfo {
  return {
    name,
    eventCount: 1,
    sourceType: { file: { path: `C:\\Evidence\\${name}.evtx` } },
  };
}

function logEntry(id: number, filePath: string) {
  return {
    id,
    lineNumber: id,
    message: `line ${id}`,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity: "Info" as const,
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Timestamped" as const,
    filePath,
    timezoneOffset: null,
  };
}

function resetStores() {
  localStorage.clear();
  useUiStore.setState(useUiStore.getInitialState(), true);
  useUiStore.setState({ activeView: "event-log", activeWorkspace: "event-log" });
  useEvtxStore.getState().reset();
  useEvtxLayoutStore.setState(sanitizeLayout(undefined));
  useLogStore.getState().clear();
  useEvtxCorrelationStatusStore.setState({ status: null });
  useEvtxVisibleSummaryStore.setState({ summary: null });
}

/**
 * What EventLogWorkspace publishes for the source on screen: `visible` is the grid's rows, and
 * `loaded` defaults to the same (nothing filtered out).
 */
function publishRows(visible: EvtxRecord[], loaded = visible.length) {
  act(() =>
    useEvtxVisibleSummaryStore
      .getState()
      .publish(
        summarizeVisibleRecords(visible, loaded, useEvtxStore.getState().loadGeneration),
      ),
  );
}

function setLayoutView(view: EvtxViewId) {
  act(() => useEvtxLayoutStore.getState().setActiveView(view));
}

const left = () => screen.getByTestId("status-bar-left");
const right = () => screen.getByTestId("status-bar-right");

describe("StatusBar Event Logs content", () => {
  beforeEach(resetStores);

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
  });

  describe("before and during a load", () => {
    it("keeps the view badge from the registry and shows no counts when nothing is loaded", () => {
      render(<StatusBar />);

      expect(screen.getByText("Event Log (Preview)")).toBeInTheDocument();
      expect(left()).toHaveTextContent(/^Ready$/);
      expect(right()).toHaveTextContent(/^$/);
      // Zeros here would read as a result of querying nothing.
      expect(left()).not.toHaveTextContent(/events|errors|warnings/);
    });

    it("keeps the querying text and progress tone while a query is running", () => {
      useEvtxStore.setState({ isLoading: true, sourceMode: "live" });
      render(<StatusBar />);

      expect(left()).toHaveTextContent(/^Loading\.\.\.$/);
      expect(right()).toHaveTextContent(/^Querying event logs\.\.\.$/);
      expect(screen.getByRole("img", { name: "In progress" })).toBeInTheDocument();
    });

    it("keeps the running count of streamed events while a query is running", () => {
      useEvtxStore.setState({
        isLoading: true,
        sourceMode: "live",
        records: [record("Error"), record("Warning")],
      });
      render(<StatusBar />);

      expect(right()).toHaveTextContent(/^2 events loaded\.\.\.$/);
      expect(left()).not.toHaveTextContent(/errors|warnings/);
    });
  });

  describe("left segment", () => {
    it("reads Live, channels, text logs, events, errors and warnings for a live source", () => {
      const records = [
        record("Error"),
        record("Error"),
        record("Warning"),
        record("Information"),
      ];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["Application", "System"]),
        records,
      });
      publishRows(records);
      useLogStore.setState({
        entries: [
          logEntry(1, "C:\\Logs\\IntuneManagementExtension.log"),
          logEntry(2, "C:\\Logs\\IntuneManagementExtension.log"),
          logEntry(3, "C:\\Logs\\AgentExecutor.log"),
        ],
        sourceOpenMode: "merged",
      });
      render(<StatusBar />);

      expect(left()).toHaveTextContent(
        "Live · 2 channels · 2 text logs · 4 events · 2 errors · 1 warning",
      );
      expect(left()).toHaveAttribute(
        "title",
        "Live · 2 channels · 2 text logs · 4 events · 2 errors · 1 warning",
      );
    });

    it("counts the channels a file source contains, not the live loaded set", () => {
      useEvtxStore.setState({
        sourceMode: "files",
        channels: [channelInfo("Application"), channelInfo("System"), channelInfo("Setup")],
        // A file parse never fills loadedChannels, so a "0 channels" here would be wrong.
        loadedChannels: new Set(),
        records: [record("Warning", "System"), record("Information", "Setup")],
      });
      publishRows(useEvtxStore.getState().records);
      render(<StatusBar />);

      expect(left()).toHaveTextContent(
        "Files · 3 channels · 0 text logs · 2 events · 0 errors · 1 warning",
      );
    });

    it("uses singular nouns for a count of one", () => {
      const records = [record("Error")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records,
      });
      publishRows(records);
      useLogStore.setState({
        entries: [logEntry(1, "C:\\Logs\\only.log")],
        sourceOpenMode: "merged",
      });
      render(<StatusBar />);

      expect(left()).toHaveTextContent(
        "Live · 1 channel · 1 text log · 1 event · 1 error · 0 warnings",
      );
    });

    it("counts a Critical event as an error", () => {
      const records = [record("Critical"), record("Error"), record("Verbose")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records,
      });
      publishRows(records);
      render(<StatusBar />);

      expect(left()).toHaveTextContent(/3 events · 2 errors · 0 warnings/);
    });

    it("scopes text logs to the active source the way the workspace does", () => {
      const records = [record("Information")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records,
      });
      publishRows(records);
      useLogStore.setState({
        entries: [
          logEntry(1, "C:\\Logs\\Intune\\a.log"),
          logEntry(2, "C:\\Logs\\Intune\\b.log"),
          logEntry(3, "C:\\Logs\\Other\\c.log"),
        ],
        sourceOpenMode: "single-file",
        activeSource: { kind: "folder", path: "C:\\Logs\\Intune" },
      });
      render(<StatusBar />);

      expect(left()).toHaveTextContent(/2 text logs/);
    });

    it("draws every count in the numeric font with tabular figures", () => {
      const records = [record("Error"), record("Warning")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records,
      });
      publishRows(records);
      render(<StatusBar />);

      const spans = Array.from(left().querySelectorAll("span"));
      expect(spans.map((span) => span.textContent)).toEqual([
        "1",
        "0",
        "2",
        "1",
        "1",
      ]);
      for (const span of spans) {
        expect(span.style.fontFamily).toBe(tokens.fontFamilyNumeric);
        expect(span.style.fontVariantNumeric).toBe("tabular-nums");
      }
    });

    it("shows the grid's rows and says how many events are loaded behind them", () => {
      const loaded = [
        record("Error"),
        record("Error"),
        record("Warning"),
        record("Information"),
        record("Information"),
      ];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: loaded,
      });
      // A filter narrows the grid to the two Error rows: the chip row reads "Showing 2 of 5".
      publishRows(loaded.slice(0, 2), loaded.length);
      render(<StatusBar />);

      expect(left()).toHaveTextContent(/2 events · 2 errors · 0 warnings$/);
      expect(left()).toHaveAttribute(
        "title",
        "Live · 1 channel · 0 text logs · 2 events · 2 errors · 0 warnings (5 loaded)",
      );
    });

    it("adds no loaded note when the grid shows every loaded event", () => {
      const loaded = [record("Error"), record("Warning")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: loaded,
      });
      publishRows(loaded);
      render(<StatusBar />);

      expect(left().getAttribute("title")).not.toMatch(/loaded/);
    });

    it("reads the published rows and does not recount the loaded records", () => {
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: [record("Error"), record("Error"), record("Error")],
      });
      publishRows([record("Warning")], 3);
      render(<StatusBar />);

      expect(left()).toHaveTextContent(/1 event · 0 errors · 1 warning/);
    });

    it("follows the workspace as it republishes", () => {
      const first = [record("Error")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: first,
      });
      publishRows(first);
      render(<StatusBar />);
      expect(left()).toHaveTextContent(/1 event · 1 error · 0 warnings/);

      const more = [...first, record("Warning"), record("Warning")];
      act(() => useEvtxStore.setState({ records: more }));
      publishRows(more);
      expect(left()).toHaveTextContent(/3 events · 1 error · 2 warnings/);
    });

    it("leaves the event counts out, not at zero, until a summary is published", () => {
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: [record("Error")],
      });
      render(<StatusBar />);

      expect(left()).toHaveTextContent(/^Live · 1 channel · 0 text logs$/);
      expect(left()).not.toHaveTextContent(/event|error|warning/);
    });

    it("never shows a summary published for another source", () => {
      const records = [record("Error")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records,
      });
      publishRows(records);
      render(<StatusBar />);
      expect(left()).toHaveTextContent(/1 event · 1 error/);

      // A new load, refresh, source change or reset bumps the generation. Until the workspace
      // publishes for the new one, the old counts must not stand in for it.
      act(() =>
        useEvtxStore.setState((state) => ({ loadGeneration: state.loadGeneration + 1 })),
      );
      expect(left()).toHaveTextContent(/^Live · 1 channel · 0 text logs$/);

      publishRows(records);
      expect(left()).toHaveTextContent(/1 event · 1 error/);
    });

    it("adds nothing for coverage gaps: the coverage banner discloses them (spec 2.2)", () => {
      const records = [record("Information")];
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["Application"]),
        records,
        coverageGaps: ["Security: access denied"],
        tailCoverageGaps: ["System: live tail batch 3 was not received"],
      });
      publishRows(records);
      render(<StatusBar />);

      expect(left().textContent).toBe(
        "Live · 1 channel · 0 text logs · 1 event · 0 errors · 0 warnings",
      );
    });
  });

  describe("right segment", () => {
    it("names the active layout view", () => {
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: [record("Error")],
      });
      render(<StatusBar />);
      expect(right()).toHaveTextContent(/^Table view/);

      for (const [view, label] of [
        ["grouped", "Grouped"],
        ["timeline", "Timeline"],
        ["charts", "Charts"],
        ["correlation", "Correlation"],
      ] as const) {
        setLayoutView(view);
        expect(right()).toHaveTextContent(new RegExp(`^${label} view`));
      }
    });

    it("stamps Updated when a load completes, in the grid's clock with its zone label", () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2026-10-10T14:32:05Z"));
      render(<StatusBar />);
      expect(right()).toHaveTextContent(/^$/);

      act(() => {
        useEvtxStore.setState({
          sourceMode: "live",
          timeZoneMode: "utc",
          loadedChannels: new Set(["System"]),
          records: [record("Error")],
        });
      });

      expect(right()).toHaveTextContent("Table view · Updated 14:32:05 UTC");
      // The time is a number the operator compares against, so it is set in the numeric font.
      const time = within(right()).getByText("14:32:05");
      expect(time.style.fontFamily).toBe(tokens.fontFamilyNumeric);
    });

    it("moves Updated forward on a live tail append", () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2026-10-10T14:32:05Z"));
      render(<StatusBar />);
      act(() => {
        useEvtxStore.setState({
          sourceMode: "live",
          timeZoneMode: "utc",
          loadedChannels: new Set(["System"]),
          records: [record("Error")],
        });
      });
      expect(right()).toHaveTextContent(/Updated 14:32:05 UTC/);

      vi.setSystemTime(new Date("2026-10-10T14:33:41Z"));
      act(() =>
        useEvtxStore.setState((state) => ({
          records: [...state.records, record("Warning")],
        })),
      );

      expect(right()).toHaveTextContent(/Updated 14:33:41 UTC/);
    });

    it("does not move Updated for a change that leaves the records alone", () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2026-10-10T14:32:05Z"));
      render(<StatusBar />);
      act(() => {
        useEvtxStore.setState({
          sourceMode: "live",
          timeZoneMode: "utc",
          loadedChannels: new Set(["System"]),
          records: [record("Error")],
        });
      });

      vi.setSystemTime(new Date("2026-10-10T15:00:00Z"));
      setLayoutView("charts");

      expect(right()).toHaveTextContent("Charts view · Updated 14:32:05 UTC");
    });

    it("leaves Updated out for records that were already loaded when the bar mounted", () => {
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: [record("Error")],
      });
      render(<StatusBar />);

      // That time was never observed, so it is not invented.
      expect(right()).toHaveTextContent(/^Table view$/);
    });

    it("stamps Updated when a load finishes without a final change to the records", () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date("2026-10-10T08:00:00Z"));
      useEvtxStore.setState({
        isLoading: true,
        sourceMode: "live",
        timeZoneMode: "utc",
        loadedChannels: new Set(["System"]),
        records: [record("Error")],
      });
      render(<StatusBar />);
      expect(right()).toHaveTextContent(/^1 events loaded\.\.\.$/);

      vi.setSystemTime(new Date("2026-10-10T08:00:09Z"));
      act(() => useEvtxStore.setState({ isLoading: false }));

      expect(right()).toHaveTextContent("Table view · Updated 08:00:09 UTC");
    });
  });

  describe("Correlation view variant", () => {
    /**
     * `pairAndGroupDisjoint` is real parser output: one exact pair beside a three-member ambiguous
     * group. The candidate pair and the coverage-blocked pair are built by hand on fresh ids.
     */
    function chainModel(extra: TimelineCorrelationEdge[] = []) {
      const scenarios = fixtureDocument.scenarios as unknown as Record<
        string,
        { edges: unknown[]; coverageGaps: [] }
      >;
      const scenario = scenarios.pairAndGroupDisjoint;
      const decoded = assertUnifiedTimelineShape({
        items: [],
        unplaced: [],
        edges: scenario.edges,
        coverageGaps: scenario.coverageGaps,
      });
      const timelineEdges = [...decoded.edges, ...extra];
      return buildCorrelationChains({
        items: [],
        timelineEdges,
        totalTimelineEdges: timelineEdges.length,
        findings: [],
      });
    }

    function pair(
      id: string,
      strength: TimelineCorrelationEdge["strength"],
      coverage: TimelineCorrelationEdge["coverage"] = { state: "covered" },
    ): TimelineCorrelationEdge {
      return {
        id,
        fromId: `${id}-a`,
        toId: `${id}-b`,
        key: { kind: "activityId", value: `key-${id}` },
        strength,
        confidence: "high",
        candidateIds: [],
        evidence: [{ originId: `${id}-a`, field: "activityId", value: `key-${id}` }],
        coverage,
      };
    }

    function publishCorrelation(
      counts = { exact: 1, candidate: 0, ambiguous: 0, unplaced: 0 },
    ) {
      act(() =>
        useEvtxCorrelationStatusStore.getState().publish({
          generation: useEvtxStore.getState().loadGeneration,
          ...counts,
        }),
      );
    }

    function loadLive() {
      useEvtxStore.setState({
        sourceMode: "live",
        loadedChannels: new Set(["System"]),
        records: [record("Error")],
      });
    }

    it("reads chains, exact, candidate, ambiguous and not placed, with no nearby count", () => {
      loadLive();
      setLayoutView("correlation");
      // An exact pair that carries a coverage gap becomes a coverage-blocked row, which is
      // neither a chain nor an ambiguous item, so it must not move any of the counts below.
      const model = chainModel([
        pair("candidate", "candidate"),
        pair("blocked", "exact", {
          state: "gap",
          gap: { source: "Live", reason: "channel not collected" },
        }),
      ]);
      expect(model.counts).toEqual({
        exact: 1,
        candidate: 1,
        ambiguous: 1,
        coverageBlocked: 1,
      });

      const generation = useEvtxStore.getState().loadGeneration;
      const status = summarizeEvtxCorrelationStatus(model, 4, generation);
      expect(status).toEqual({
        generation,
        exact: 1,
        candidate: 1,
        ambiguous: 1,
        unplaced: 4,
      });
      act(() => useEvtxCorrelationStatusStore.getState().publish(status));
      render(<StatusBar />);

      expect(left()).toHaveTextContent(
        "Correlation · 2 chains · 1 exact, 1 candidate, 1 ambiguous · 4 not placed",
      );
      expect(left()).not.toHaveTextContent(/nearby|not linked|time only|blocked/i);
      expect(right()).toHaveTextContent(/^Correlation view/);
    });

    it("counts only exact and candidate rows as chains", () => {
      expect(
        evtxStatusText(
          buildEvtxCorrelationSegments({
            generation: 0,
            exact: 3,
            candidate: 2,
            ambiguous: 7,
            unplaced: 0,
          }),
        ),
      ).toBe(
        "Correlation · 5 chains · 3 exact, 2 candidate, 7 ambiguous · 0 not placed",
      );
      expect(
        evtxStatusText(
          buildEvtxCorrelationSegments({
            generation: 0,
            exact: 1,
            candidate: 0,
            ambiguous: 0,
            unplaced: 1,
          }),
        ),
      ).toMatch(/^Correlation · 1 chain · /);
    });

    it("shows the standard segment in the Correlation view until counts are published", () => {
      loadLive();
      setLayoutView("correlation");
      render(<StatusBar />);

      expect(left()).toHaveTextContent(/^Live · 1 channel · /);
      expect(left()).not.toHaveTextContent(/chains/);
    });

    it("returns to the standard segment when the published counts are cleared", () => {
      loadLive();
      setLayoutView("correlation");
      publishCorrelation();
      render(<StatusBar />);
      expect(left()).toHaveTextContent(/^Correlation · 1 chain/);

      act(() => useEvtxCorrelationStatusStore.getState().publish(null));
      expect(left()).toHaveTextContent(/^Live · 1 channel · /);
    });

    it("keeps the standard segment in every other view even when counts are published", () => {
      loadLive();
      publishCorrelation();
      render(<StatusBar />);

      for (const view of ["table", "grouped", "timeline", "charts"] as const) {
        setLayoutView(view);
        expect(left()).toHaveTextContent(/^Live · 1 channel · /);
      }
    });

    it("never shows counts published for another source", () => {
      loadLive();
      setLayoutView("correlation");
      publishCorrelation();
      render(<StatusBar />);
      expect(left()).toHaveTextContent(/^Correlation · 1 chain/);

      act(() =>
        useEvtxStore.setState((state) => ({ loadGeneration: state.loadGeneration + 1 })),
      );
      expect(left()).toHaveTextContent(/^Live · 1 channel · /);
      expect(left()).not.toHaveTextContent(/chain/);
    });
  });
});

describe("Event Logs status helpers", () => {
  it("counts distinct log files, not lines", () => {
    expect(
      countTextLogFiles([
        { filePath: "a.log" },
        { filePath: "a.log" },
        { filePath: "b.log" },
      ]),
    ).toBe(2);
    expect(countTextLogFiles([])).toBe(0);
  });

  it("builds the left text from the spec format", () => {
    expect(
      evtxStatusText(
        buildEvtxCountsSegments({
          sourceMode: "files",
          channels: 12,
          textLogs: 3,
          rows: { visible: 12345, errors: 10, warnings: 2 },
        }),
      ),
    ).toBe(
      `Files · 12 channels · 3 text logs · ${(12345).toLocaleString()} events · 10 errors · 2 warnings`,
    );
  });

  it("leaves the event counts out when no rows are published", () => {
    expect(
      evtxStatusText(
        buildEvtxCountsSegments({
          sourceMode: "live",
          channels: 2,
          textLogs: 0,
          rows: null,
        }),
      ),
    ).toBe("Live · 2 channels · 0 text logs");
  });
});

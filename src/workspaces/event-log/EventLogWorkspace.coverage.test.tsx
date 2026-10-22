/**
 * The workspace's coverage wiring, with the real banner, rail and diagnosis panel (the other
 * workspace suites replace the banner module). Only the analysis build and the heavy leaf views are
 * stood in for.
 */
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());
const build = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));
vi.mock("../../lib/commands", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../lib/commands")>()),
  closeEventLogAnalysisSession: vi.fn().mockResolvedValue(undefined),
  queryEventLogAnalysisTimeline: vi.fn(),
}));
vi.mock("./event-analysis-session", () => ({
  buildEventLogAnalysisSession: build,
  EventLogAnalysisCancelled: class EventLogAnalysisCancelled extends Error {},
}));
vi.mock("./SourcePicker", () => ({ SourcePicker: () => <div data-testid="source-picker" /> }));
vi.mock("./ChannelPicker", () => ({ ChannelPicker: () => null }));
vi.mock("./EvtxFilterBar", () => ({ EvtxFilterBar: () => null }));
vi.mock("./EvtxTimeline", () => ({ EvtxTimeline: () => <div data-testid="records-table" /> }));
vi.mock("./EvtxDetailPane", () => ({ EvtxDetailPane: () => null }));
vi.mock("./UnifiedTimelineView", () => ({ UnifiedTimelineView: () => null }));

import { EventLogWorkspace } from "./EventLogWorkspace";
import { formatCoverageGap } from "./evtx-coverage";
import { sanitizeLayout, useEvtxLayoutStore } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import { useLogStore } from "../../stores/log-store";
import type { DiagnosisSummary, EvtxCoverageGap, EvtxRecord } from "./types";

const RECORD: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: Date.parse("2026-08-18T12:00:00Z"),
  provider: "Example Provider",
  channel: "Application",
  eventId: 42,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event message",
  eventData: [],
  rawXml: "<Event />",
  sourceLabel: "sample.evtx",
};

const SYSTEM_LIMIT: EvtxCoverageGap = {
  source: "System",
  kind: "limitReached",
  reason: "reader stopped at 10000 events; the source may contain more",
};
const APPLICATION_RECORD: EvtxCoverageGap = {
  source: "Application",
  kind: "record",
  reason: "record 7 could not be rendered",
};
const SETUP_MISSING: EvtxCoverageGap = {
  source: "Setup",
  kind: "missing",
  reason: "channel not found",
};

/** The store as a load leaves it: structured gaps plus their legacy "source: reason" lines. */
function storeGaps(gaps: readonly EvtxCoverageGap[]) {
  return { coverageDetails: [...gaps], coverageGaps: gaps.map(formatCoverageGap) };
}

/**
 * What the engine answers for a build: the input gaps reported in its coverage, each row echoing
 * the ordinal of the input it reports.
 */
function summaryFor(input: readonly EvtxCoverageGap[]): DiagnosisSummary {
  return {
    findings: [],
    evidence: [],
    coverageGaps: input.map((gap, index) => ({
      id: `coverage-${index}`,
      source: gap.source,
      state: "unknown",
      detail: gap.reason,
      evidence: [],
      inputIndices: [index],
    })),
    correlations: [],
    events: [],
    overview: {
      outcome: "insufficientEvidence",
      headline: "Evidence is incomplete.",
      findingCount: 0,
      actionableFindingCount: 0,
      coverageGapCount: input.length,
      evidenceCount: 0,
      correlationCount: 0,
      errorTokenEventCount: 0,
    },
  };
}

interface BuildInput {
  coverageGaps: EvtxCoverageGap[];
}

/** Answers every build from its own input, like the engine. */
function answerBuildsFromInput(): void {
  let revision = 0;
  build.mockImplementation(async ({ coverageGaps }: BuildInput) => {
    revision += 1;
    return {
      status: { sessionId: `session-${revision}`, revision },
      initialPage: null,
      diagnosis: summaryFor(coverageGaps),
    };
  });
}

function bannerLines(): string[] {
  const banner = document.querySelector("[data-coverage-banner]");
  return banner
    ? Array.from(banner.querySelectorAll("li"))
        .filter((item) => !item.closest("[data-archive-provenance]"))
        .map((item) => item.textContent ?? "")
    : [];
}

function showLoadedWorkspace(gaps: readonly EvtxCoverageGap[]): void {
  useEvtxStore.setState({
    sourceMode: "live",
    records: [RECORD],
    channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
    selectedChannels: new Set(["Application"]),
    loadedChannels: new Set(["Application"]),
    isLoading: false,
    ...storeGaps(gaps),
  });
}

describe("EventLogWorkspace coverage wiring", () => {
  beforeEach(() => {
    invoke.mockReset();
    // Not Windows: the coverage note stays out of these cases; the disclosure claims are tested.
    invoke.mockImplementation((command: string) =>
      Promise.resolve(
        command === "get_app_elevation_state"
          ? { platformSupported: false, isElevated: false }
          : null,
      ),
    );
    build.mockReset();
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
    useLogStore.setState({ entries: [] });
  });

  afterEach(cleanup);

  it("hands the gaps to the rail once the summary built from them lands", async () => {
    let resolve!: () => void;
    const gate = new Promise<void>((done) => {
      resolve = done;
    });
    build.mockImplementation(async ({ coverageGaps }: BuildInput) => {
      await gate;
      return {
        status: { sessionId: "session-1", revision: 1 },
        initialPage: null,
        diagnosis: summaryFor(coverageGaps),
      };
    });
    showLoadedWorkspace([SYSTEM_LIMIT, APPLICATION_RECORD]);
    render(<EventLogWorkspace />);

    // No summary yet: the rail shows no disclosure, so the banner lists both.
    await waitFor(() => expect(build).toHaveBeenCalledTimes(1));
    expect(bannerLines()).toEqual([
      formatCoverageGap(SYSTEM_LIMIT),
      formatCoverageGap(APPLICATION_RECORD),
    ]);

    await act(async () => resolve());
    await waitFor(() => expect(screen.getByText("Coverage gaps (2)")).toBeInTheDocument());
    expect(document.querySelector("[data-coverage-banner]")).toBeNull();
  });

  it("hands a gap to the rail when the engine rewrote its row's text", async () => {
    const profile: EvtxCoverageGap = {
      source: "C:\\Users\\alice\\Downloads\\System.evtx",
      kind: "chunk",
      reason: "chunk 3 is missing or zero-filled",
      chunkId: 3,
    };
    // The engine's display projection replaces the profile segment of the row's source.
    build.mockImplementation(async ({ coverageGaps }: BuildInput) => {
      const diagnosis = summaryFor(coverageGaps);
      diagnosis.coverageGaps = diagnosis.coverageGaps.map((row) => ({
        ...row,
        source: row.source.replace("\\alice\\", "\\[user]\\"),
      }));
      return { status: { sessionId: "session-1", revision: 1 }, initialPage: null, diagnosis };
    });
    showLoadedWorkspace([profile, SYSTEM_LIMIT]);
    render(<EventLogWorkspace />);

    await waitFor(() => expect(screen.getByText("Coverage gaps (2)")).toBeInTheDocument());
    expect(document.querySelector("[data-coverage-banner]")).toBeNull();
  });

  it("keeps every gap in the banner when the diagnosis fails", async () => {
    build.mockRejectedValue(new Error("engine unavailable"));
    showLoadedWorkspace([SYSTEM_LIMIT, APPLICATION_RECORD]);
    render(<EventLogWorkspace />);

    await waitFor(() =>
      expect(
        screen.getByText("Operational diagnosis could not be built: engine unavailable"),
      ).toBeInTheDocument(),
    );
    expect(bannerLines()).toEqual([
      formatCoverageGap(SYSTEM_LIMIT),
      formatCoverageGap(APPLICATION_RECORD),
    ]);
  });

  it("drops the claim when a rebuild after a summary fails", async () => {
    answerBuildsFromInput();
    showLoadedWorkspace([SYSTEM_LIMIT]);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(screen.getByText("Coverage gaps (1)")).toBeInTheDocument());
    expect(bannerLines()).toEqual([]);

    build.mockRejectedValue(new Error("engine unavailable"));
    act(() => useEvtxStore.setState(storeGaps([SYSTEM_LIMIT, SETUP_MISSING])));
    await waitFor(() =>
      expect(
        screen.getByText("Operational diagnosis could not be built: engine unavailable"),
      ).toBeInTheDocument(),
    );
    expect(bannerLines()).toEqual([
      formatCoverageGap(SYSTEM_LIMIT),
      formatCoverageGap(SETUP_MISSING),
    ]);
  });

  it("lists only a gap that arrived after the shown summary while the rebuild runs", async () => {
    answerBuildsFromInput();
    showLoadedWorkspace([SYSTEM_LIMIT, APPLICATION_RECORD]);
    render(<EventLogWorkspace />);
    await waitFor(() => expect(screen.getByText("Coverage gaps (2)")).toBeInTheDocument());
    expect(document.querySelector("[data-coverage-banner]")).toBeNull();

    // The rebuild for the new gap never settles here: the rail keeps the previous summary.
    build.mockImplementation(() => new Promise(() => undefined));
    act(() =>
      useEvtxStore.setState(storeGaps([SYSTEM_LIMIT, APPLICATION_RECORD, SETUP_MISSING])),
    );
    await waitFor(() => expect(build).toHaveBeenCalledTimes(2));
    expect(screen.getByText("Coverage gaps (2)")).toBeInTheDocument();
    expect(bannerLines()).toEqual([formatCoverageGap(SETUP_MISSING)]);
  });

  it("keeps one announcer through the picker, the spinner and the loaded workspace", async () => {
    answerBuildsFromInput();
    render(<EventLogWorkspace />);
    expect(screen.getByTestId("source-picker")).toBeInTheDocument();
    const announcer = document.querySelector("[data-coverage-announcer]");
    expect(announcer).not.toBeNull();

    act(() => useEvtxStore.setState({ sourceMode: "live", isLoading: true, records: [] }));
    expect(screen.getByText("Loading event logs...")).toBeInTheDocument();
    expect(document.querySelector("[data-coverage-announcer]")).toBe(announcer);

    act(() => showLoadedWorkspace([SYSTEM_LIMIT]));
    expect(screen.getByTestId("records-table")).toBeInTheDocument();
    expect(document.querySelector("[data-coverage-announcer]")).toBe(announcer);
    await waitFor(() => expect(announcer).toHaveTextContent(formatCoverageGap(SYSTEM_LIMIT)));
  });
});

/**
 * The coverage invariant, as one table: every current load gap is visible on exactly one rendered
 * surface. Each row renders the real Insights rail and the real grid banner together, the way the
 * workspace mounts them, over real store gaps, and counts where each gap is visible by its shared
 * key: the line `source: reason`.
 *
 * The rail is one surface. Its coverage note and its coverage disclosure both belong to it, so a
 * gap shown by both counts once there.
 */
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invoke = vi.hoisted(() => vi.fn());

vi.mock("@tauri-apps/api/core", () => ({ invoke }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { EvtxCoverageBanner } from "./EvtxCoverageBanner";
import { EvtxInsightsRail } from "./EvtxInsightsRail";
import { CoverageClaimsProvider } from "./evtx-coverage-claims";
import { coverageInputKeys, formatCoverageGap, mergeDiagnosisCoverageGaps } from "./evtx-coverage";
import { sanitizeLayout, useEvtxLayoutStore, type EvtxRailTabId } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import { resetElevationCoordinatorForTests } from "../../lib/elevation";
import { useMarkerStore } from "../../stores/marker-store";
import type { AppElevationState } from "../../types/elevation";
import type { DiagnosisSummary, EvtxCoverageGap, EvtxRecord } from "./types";

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

/** Store gaps in the backend's shapes (absorb_scan for live channels; see the banner tests). */
const SECURITY_DENIED: EvtxCoverageGap = {
  source: "Security",
  kind: "accessDenied",
  reason: "the Event Log service refused the channel query (Windows error 5: Access is denied)",
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
const LOADED = [SECURITY_DENIED, SYSTEM_LIMIT, APPLICATION_RECORD];

const OFFERABLE: AppElevationState = { platformSupported: true, isElevated: false };
const ELEVATED: AppElevationState = { platformSupported: true, isElevated: true };
const NOT_WINDOWS: AppElevationState = { platformSupported: false, isElevated: false };

/** The store as a load leaves it: structured gaps plus their legacy "source: reason" lines. */
function storeGaps(gaps: readonly EvtxCoverageGap[]) {
  return { coverageDetails: [...gaps], coverageGaps: gaps.map(formatCoverageGap) };
}

/** How a fake engine row shows a gap: its source and detail after the engine's projection. */
interface RowText {
  source: string;
  detail: string;
}

interface EngineOptions {
  /** Rewrites a row's text, as the engine's redacted display projection does. */
  redact?: (text: string) => string;
  /** Gaps whose rows the engine leaves out (truncated); still counted in the overview. */
  omit?: readonly EvtxCoverageGap[];
}

/**
 * A summary built from `input` the way the engine reports supplied gaps: one row per gap, its
 * detail with the chunk it names, its ordinal echoed in `inputIndices`.
 */
function summaryOf(
  input: readonly EvtxCoverageGap[],
  { redact = (text) => text, omit = [] }: EngineOptions = {},
): { summary: DiagnosisSummary; input: readonly string[]; display: Map<string, RowText> } {
  const store = storeGaps(input);
  const diagnosisInput = mergeDiagnosisCoverageGaps(store.coverageDetails, [], store.coverageGaps, []);
  const omitted = new Set(omit.map(formatCoverageGap));
  const display = new Map<string, RowText>();
  const rows = diagnosisInput.flatMap((gap, index) => {
    if (omitted.has(formatCoverageGap(gap))) return [];
    const source = redact(gap.source);
    const detail = redact(
      gap.chunkId === undefined ? gap.reason : `${gap.reason} (chunk ${gap.chunkId})`,
    );
    display.set(formatCoverageGap(gap), { source, detail });
    return [
      {
        id: `coverage-${index}`,
        source,
        state: gap.kind === "accessDenied" ? ("accessDenied" as const) : ("unknown" as const),
        detail,
        evidence: [],
        inputIndices: [index],
      },
    ];
  });
  return {
    summary: {
      findings: [],
      evidence: [],
      coverageGaps: rows,
      correlations: [],
      events: [],
      overview: {
        outcome: "insufficientEvidence",
        headline: "Evidence is incomplete.",
        findingCount: 0,
        actionableFindingCount: 0,
        coverageGapCount: diagnosisInput.length,
        evidenceCount: 0,
        correlationCount: 0,
        errorTokenEventCount: 0,
      },
    },
    input: coverageInputKeys(diagnosisInput, diagnosisInput.length),
    display,
  };
}

interface RailProps {
  summary: DiagnosisSummary | null;
  input: readonly string[] | null;
  pending: boolean;
  error: string | null;
  /** How the shown summary's rows read; the identity when absent. */
  display?: ReadonlyMap<string, RowText>;
}

/** The rail and the banner as the workspace mounts them; the aside is hidden with the rail. */
function Surfaces({ summary, input, pending, error }: RailProps) {
  const insights = useEvtxLayoutStore((s) => s.panels.insights);
  return (
    <CoverageClaimsProvider>
      <EvtxCoverageBanner />
      <aside style={{ display: insights ? "flex" : "none" }}>
        <EvtxInsightsRail
          summary={summary}
          records={[RECORD]}
          pending={pending}
          error={error}
          summaryCoverageInput={input}
        />
      </aside>
    </CoverageClaimsProvider>
  );
}

function isVisible(element: Element): boolean {
  for (let node: Element | null = element; node; node = node.parentElement) {
    if (node instanceof HTMLElement) {
      const style = getComputedStyle(node);
      if (node.hidden || style.display === "none" || style.visibility === "hidden") return false;
    }
    const parent = node.parentElement;
    if (
      parent instanceof HTMLDetailsElement &&
      !parent.open &&
      node.tagName !== "SUMMARY"
    ) {
      return false;
    }
  }
  return true;
}

/** Opens every visible coverage disclosure, so its rows can be seen. */
function expandCoverageDisclosures(): void {
  for (const summary of Array.from(document.querySelectorAll("summary"))) {
    if (/^Coverage gaps \(/.test(summary.textContent ?? "") && isVisible(summary)) {
      const details = summary.closest("details");
      if (details && !details.open) fireEvent.click(summary);
    }
  }
}

/** Where `gap` is visible: listed by the banner, and shown by the rail (note or disclosure). */
function occurrences(
  gap: EvtxCoverageGap,
  display: ReadonlyMap<string, RowText> | undefined,
): { banner: number; rail: number } {
  const line = formatCoverageGap(gap);
  const row = display?.get(line) ?? { source: gap.source, detail: gap.reason };
  const banner = Array.from(document.querySelectorAll("[data-coverage-banner] li")).filter(
    (item) =>
      !item.closest("[data-archive-provenance]") &&
      item.textContent === line &&
      isVisible(item),
  ).length;
  const note =
    gap.kind === "accessDenied" &&
    Array.from(document.querySelectorAll<HTMLElement>("[data-coverage-note]")).some(
      (element) => element.dataset.coverageNote === gap.source && isVisible(element),
    );
  const disclosure = Array.from(document.querySelectorAll("span")).some((span) => {
    const text = span.textContent ?? "";
    return (
      text.startsWith(`Coverage: ${row.source} (`) &&
      text.includes(`): ${row.detail} (`) &&
      isVisible(span)
    );
  });
  return { banner, rail: note || disclosure ? 1 : 0 };
}

interface Row {
  name: string;
  insights: boolean;
  railTab: EvtxRailTabId;
  elevation: AppElevationState | Error;
  gaps: readonly EvtxCoverageGap[];
  /** The rail's props; a second step models a change after the first render. */
  steps: RailProps[];
  /** Gaps the store holds after the steps (a gap reported after the summary). */
  finalGaps?: readonly EvtxCoverageGap[];
}

function shownFor(gaps: readonly EvtxCoverageGap[], options?: EngineOptions): RailProps {
  const built = summaryOf(gaps, options);
  return {
    summary: built.summary,
    input: built.input,
    pending: false,
    error: null,
    display: built.display,
  };
}
const SHOWN = shownFor(LOADED);
const BUILDING: RailProps = { summary: null, input: null, pending: true, error: null };
const FAILED: RailProps = { summary: null, input: null, pending: false, error: "engine unavailable" };

/** A files-mode source under a user profile, with a rejected chunk (parser.rs chunk gaps). */
const PROFILE_CHUNK: EvtxCoverageGap = {
  source: "C:\\Users\\alice\\Downloads\\System.evtx",
  kind: "chunk",
  reason: "chunk 3 is missing or zero-filled",
  chunkId: 3,
};
/** The engine's display projection replaces the profile segment of a path. */
const redactProfile = (text: string) => text.replace("\\Users\\alice\\", "\\Users\\[user]\\");

/** Five local channels refused: the note draws three and counts the other two. */
const MANY_DENIED = ["Security", "Setup", "Sysmon", "LAPS", "AppLocker"].map(
  (source): EvtxCoverageGap => ({ ...SECURITY_DENIED, source }),
);
/** More gaps than the disclosure lists (DETAIL_RENDER_CAP is 100): it counts the last five. */
const MANY_RECORDS = Array.from(
  { length: 105 },
  (_, index): EvtxCoverageGap => ({
    source: `Channel-${String(index).padStart(3, "0")}`,
    kind: "record",
    reason: `record ${index} could not be rendered`,
  }),
);

const ROWS: Row[] = [
  { name: "the rail hidden", insights: false, railTab: "insights", elevation: OFFERABLE, gaps: LOADED, steps: [SHOWN] },
  { name: "Insights before the first summary", insights: true, railTab: "insights", elevation: OFFERABLE, gaps: LOADED, steps: [BUILDING] },
  { name: "Insights with a summary", insights: true, railTab: "insights", elevation: OFFERABLE, gaps: LOADED, steps: [SHOWN] },
  {
    name: "Insights with a summary plus a gap that arrived after it",
    insights: true,
    railTab: "insights",
    elevation: OFFERABLE,
    gaps: LOADED,
    // The workspace clears the diagnosis and rebuilds; the rail keeps showing the last build.
    steps: [SHOWN, BUILDING],
    finalGaps: [...LOADED, SETUP_MISSING],
  },
  { name: "Details", insights: true, railTab: "details", elevation: OFFERABLE, gaps: LOADED, steps: [SHOWN] },
  { name: "a persisted chains tab", insights: true, railTab: "chains", elevation: OFFERABLE, gaps: LOADED, steps: [SHOWN] },
  { name: "a failed diagnosis", insights: true, railTab: "insights", elevation: OFFERABLE, gaps: LOADED, steps: [SHOWN, FAILED] },
  { name: "the note hidden: already elevated", insights: true, railTab: "insights", elevation: ELEVATED, gaps: LOADED, steps: [BUILDING] },
  { name: "the note hidden: not Windows", insights: true, railTab: "insights", elevation: NOT_WINDOWS, gaps: LOADED, steps: [BUILDING] },
  { name: "the note hidden: the probe failed", insights: true, railTab: "insights", elevation: new Error("ipc unavailable"), gaps: LOADED, steps: [BUILDING] },
  // A surface claims only what it names; a count names nothing, so the banner names those gaps.
  {
    name: "more than 3 local denied sources before the first summary",
    insights: true,
    railTab: "insights",
    elevation: OFFERABLE,
    gaps: [...MANY_DENIED, SYSTEM_LIMIT],
    steps: [BUILDING],
  },
  {
    name: "more than 100 disclosure rows",
    insights: true,
    railTab: "insights",
    elevation: OFFERABLE,
    gaps: MANY_RECORDS,
    steps: [shownFor(MANY_RECORDS)],
  },
  {
    name: "a redacted profile path in the engine's rows",
    insights: true,
    railTab: "insights",
    elevation: OFFERABLE,
    gaps: [PROFILE_CHUNK, ...LOADED],
    steps: [shownFor([PROFILE_CHUNK, ...LOADED], { redact: redactProfile })],
  },
  {
    // The second summary lists Setup's new row and leaves out Application's.
    name: "a second summary that lists different rows",
    insights: true,
    railTab: "insights",
    elevation: OFFERABLE,
    gaps: [SYSTEM_LIMIT, APPLICATION_RECORD],
    steps: [
      shownFor([SYSTEM_LIMIT, APPLICATION_RECORD]),
      shownFor([SYSTEM_LIMIT, APPLICATION_RECORD, SETUP_MISSING], { omit: [APPLICATION_RECORD] }),
    ],
    finalGaps: [SYSTEM_LIMIT, APPLICATION_RECORD, SETUP_MISSING],
  },
];

async function settle(): Promise<void> {
  await act(async () => {
    await Promise.resolve();
  });
}

describe("every current load gap is visible on exactly one rendered surface", () => {
  beforeEach(() => {
    invoke.mockReset();
    resetElevationCoordinatorForTests();
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    localStorage.clear();
    useEvtxLayoutStore.setState(sanitizeLayout(undefined));
    useEvtxStore.getState().reset();
    useMarkerStore.setState({
      markersByFile: new Map(),
      loadingFiles: new Set(["event-log:sample.evtx"]),
    });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it.each(ROWS.map((row) => [row.name, row] as const))("%s", async (_name, row) => {
    invoke.mockImplementation((command: string) => {
      if (command !== "get_app_elevation_state") return Promise.resolve(null);
      return row.elevation instanceof Error
        ? Promise.reject(row.elevation)
        : Promise.resolve(row.elevation);
    });
    useEvtxLayoutStore.setState({
      panels: { channels: true, insights: row.insights, dock: false },
      railTab: row.railTab,
    });
    useEvtxStore.setState({
      records: [RECORD],
      // Details stays open only with a record selected (the rail falls back to Insights otherwise).
      selectedRecordId: row.railTab === "details" ? RECORD.id : null,
      ...storeGaps(row.gaps),
    });

    const [first, ...rest] = row.steps;
    const { rerender } = render(<Surfaces {...first} />);
    await settle();
    for (const step of rest) {
      if (row.finalGaps) act(() => useEvtxStore.setState(storeGaps(row.finalGaps!)));
      rerender(<Surfaces {...step} />);
      await settle();
    }
    expandCoverageDisclosures();

    const current = row.finalGaps ?? row.gaps;
    const shown = row.steps[row.steps.length - 1];
    const placements = Object.fromEntries(
      current.map((gap) => {
        const { banner, rail } = occurrences(gap, shown.display);
        return [formatCoverageGap(gap), banner + rail];
      }),
    );
    expect(placements).toEqual(
      Object.fromEntries(current.map((gap) => [formatCoverageGap(gap), 1])),
    );
  });
});

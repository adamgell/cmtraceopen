import { tokens } from "@fluentui/react-components";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes, getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import { DETAIL_RENDER_CAP, OUTCOME_LABELS, EventDiagnosisPanel } from "./EventDiagnosisPanel";
import type {
  DiagnosisCorrelationEdge,
  DiagnosisCoverageGap,
  DiagnosisFinding,
  DiagnosisSummary,
  EvtxRecord,
} from "./types";
import neutralSummaries from "../../../crates/cmtraceopen-parser/tests/fixtures/diagnosis/neutral-summaries.json";

function fixtureLiteral<T extends string>(value: string, expected: T): T {
  expect(value).toBe(expected);
  return expected;
}

function neutralSummary(outcome: keyof typeof neutralSummaries): DiagnosisSummary {
  const fixture = neutralSummaries[outcome];
  const coverageGap = (
    gap: (typeof neutralSummaries.insufficientEvidence.coverageGaps)[number],
  ): DiagnosisCoverageGap => ({
    ...gap,
    state: fixtureLiteral(gap.state, "skipped"),
  });
  return {
    ...fixture,
    coverageGaps: fixture.coverageGaps.map(coverageGap),
    findings: fixture.findings.map((finding) => ({
      ...finding,
      class: fixtureLiteral(finding.class, "coverageGap"),
      confidence: fixtureLiteral(finding.confidence, "unknown"),
      severity: fixtureLiteral(finding.severity, "info"),
      coverageGaps: finding.coverageGaps.map(coverageGap),
    })),
    overview: {
      ...fixture.overview,
      outcome: fixtureLiteral(fixture.overview.outcome, outcome),
    },
  };
}

const coverageGap: DiagnosisCoverageGap = {
  id: "ime-gap",
  source: "IntuneManagementExtension.log",
  state: "absent",
  detail: "The log was not captured.",
  evidence: [
    {
      kind: "textLog",
      value: {
        source: "IntuneManagementExtension.log",
        filePath: "C:\\IntuneManagementExtension.log",
        lineNumber: 42,
        entryId: 42,
      },
    },
  ],
};

const finding = {
  findingId: "event-1",
  class: "confirmedFailure" as const,
  severity: "error" as const,
  confidence: "high" as const,
  title: "MDM enrollment failed",
  summary: "The provider reported access denied.",
  evidence: [
    {
      kind: "event" as const,
      value: {
        source: "event.evtx",
        provider: "Provider",
        eventId: 75,
        recordId: 12,
      },
    },
  ],
  coverageGaps: [],
  recommendedChecks: ["Inspect the provider record."],
};

const summary: DiagnosisSummary = {
  findings: [
    finding,
    {
      findingId: "ime-gap-finding",
      class: "coverageGap",
      severity: "info",
      confidence: "unknown",
      title: "IME coverage gap",
      summary: "The log was not captured.",
      evidence: [],
      coverageGaps: [coverageGap],
      recommendedChecks: [],
    },
  ],
  evidence: [
    {
      kind: "event",
      value: {
        source: "summary.evtx",
        provider: "Summary",
        eventId: 99,
        recordId: 99,
      },
    },
  ],
  coverageGaps: [coverageGap],
  correlations: [
    {
      left: "event-1",
      right: "text-1",
      basis: "candidateIdentifier",
      status: "candidate",
      candidateIds: ["text-1"],
      evidence: [
        { originId: "event-1", field: "activityId", value: "activity-1" },
      ],
    },
  ],
  events: [
    {
      family: "mdmEnrollment",
      evidence: [
        {
          kind: "event",
          value: {
            source: "event.evtx",
            provider: "Provider",
            eventId: 75,
            recordId: 12,
          },
        },
      ],
      findings: [finding],
      errorTokens: [
        {
          raw: "0x80070005",
          decimal: -2147024891,
          hex: "0x80070005",
          malformed: false,
          found: true,
          description: "Access is denied",
          category: "authorization",
        },
        {
          raw: "0xDEADBEEF",
          decimal: null,
          hex: null,
          malformed: false,
          found: false,
          description: null,
          category: null,
        },
      ],
    },
    {
      family: "other",
      evidence: [
        {
          kind: "event",
          value: {
            source: "ordinary.evtx",
            provider: "Other",
            eventId: 1,
            recordId: 22,
          },
        },
      ],
      findings: [],
      errorTokens: [],
    },
  ],
  overview: {
    outcome: "confirmedFailure",
    headline: "Evidence contains confirmed operational failure(s).",
    findingCount: 2,
    actionableFindingCount: 1,
    coverageGapCount: 1,
    evidenceCount: 1,
    correlationCount: 1,
    errorTokenEventCount: 1,
  },
};

function disclosure(label: RegExp | string): HTMLDetailsElement {
  const summaryElement = screen.getByText(label, { selector: "summary" });
  const details = summaryElement.closest("details");
  expect(details).not.toBeNull();
  return details as HTMLDetailsElement;
}

function expand(label: RegExp | string): HTMLDetailsElement {
  const details = disclosure(label);
  expect(details).not.toHaveAttribute("open");
  fireEvent.click(screen.getByText(label, { selector: "summary" }));
  expect(details).toHaveProperty("open", true);
  return details;
}

function record(id: number, eventId: number, level: EvtxRecord["level"]): EvtxRecord {
  return {
    id,
    eventRecordId: id,
    timestamp: "2026-08-18T12:00:00Z",
    timestampEpoch: id,
    provider: "Example Provider",
    channel: "Application",
    eventId,
    level,
    computer: "TEST-PC",
    message: "Example",
    eventData: [],
    rawXml: "<Event />",
    sourceLabel: "sample.evtx",
  };
}

function actionable(
  findingId: string,
  severity: DiagnosisFinding["severity"],
  confidence: DiagnosisFinding["confidence"],
): DiagnosisFinding {
  return { ...finding, findingId, title: `Finding ${findingId}`, severity, confidence };
}

describe("EventDiagnosisPanel", () => {
  beforeEach(cleanup);
  afterEach(cleanup);

  it("renders a named section with the overview and starts with every disclosure collapsed", () => {
    render(<EventDiagnosisPanel summary={summary} />);

    expect(screen.getByLabelText("Operational diagnosis")).toBeTruthy();
    expect(disclosure(/Coverage gaps/)).not.toHaveAttribute("open");
    expect(disclosure("Show diagnosis details")).not.toHaveAttribute("open");
    expect(screen.getByTestId("overview-counts")).toHaveTextContent(
      "1 actionable finding, 1 source coverage gap",
    );
    expect(screen.getByRole("region", { name: "Correlations" })).toHaveTextContent(
      "1 correlation",
    );
    expect(screen.getByText("Issues detected")).toBeTruthy();
    expect(screen.getByText("Evidence contains confirmed operational failure(s).")).toBeTruthy();
  });

  it("renders no diagnosis claim while the summary is pending", () => {
    render(<EventDiagnosisPanel summary={null} />);

    expect(screen.queryByLabelText("Operational diagnosis")).toBeNull();
    expect(screen.queryByText("No actionable findings.")).toBeNull();
  });

  // The parser's neutral_summaries_match_the_rendered_contract test verifies
  // these serialized summaries against the real producer. Keep its headline:
  // replacing it with neutral mock text hid a clean-result claim beside the gap
  // badge even after the two badge labels became distinct.
  it.each([
    ["noFindings", "No issues found"],
    ["insufficientEvidence", "Insufficient evidence"],
  ] as const)(
    "labels the %s outcome with its own wording",
    (outcome, label) => {
      render(<EventDiagnosisPanel summary={neutralSummary(outcome)} />);

      expect(screen.getByText(label)).toBeTruthy();
      // The raw enum name is still not shown to a reader.
      expect(screen.queryByText(outcome)).toBeNull();
      // The defect: a coverage gap rendered as the clean result's wording. A
      // panel that cannot conclude must not read as a panel that concluded.
      if (outcome === "insufficientEvidence") {
        expect(screen.queryByText(/no issues/i)).toBeNull();
      }
    },
  );

  describe("finding cards", () => {
    it("shows one card per actionable finding and none for coverage-gap findings", () => {
      render(<EventDiagnosisPanel summary={summary} />);

      expect(screen.getAllByRole("article")).toHaveLength(1);
      expect(screen.getByText("MDM enrollment failed")).toBeTruthy();
      expect(screen.queryByText("IME coverage gap")).toBeNull();
      expect(screen.getByText("error")).toHaveStyle({ textTransform: "uppercase" });
      expect(screen.getByText("Confirmed failure \u00b7 high confidence")).toBeTruthy();
      expect(screen.getByText("The provider reported access denied.")).toBeTruthy();
    });

    it("sorts by severity, then confidence, most significant first", () => {
      const sorted: DiagnosisSummary = {
        ...summary,
        findings: [
          actionable("a", "warning", "high"),
          actionable("b", "critical", "low"),
          actionable("c", "error", "medium"),
          actionable("d", "error", "high"),
          actionable("e", "info", "high"),
          actionable("f", "critical", "high"),
        ],
        overview: { ...summary.overview, actionableFindingCount: 6 },
      };
      render(<EventDiagnosisPanel summary={sorted} />);

      expect(
        screen.getAllByRole("article").map((card) => card.getAttribute("data-finding-id")),
      ).toEqual(["f", "b", "d", "c", "a", "e"]);
    });

    it("renders the evidence references, with a count of the rest", () => {
      const evidence = Array.from({ length: 5 }, (_, index) => ({
        kind: "event" as const,
        value: {
          source: "event.evtx",
          provider: "Provider",
          eventId: 76,
          recordId: 88456 + index,
          channel: "DeviceManagement/Admin",
        },
      }));
      render(
        <EventDiagnosisPanel
          summary={{
            ...summary,
            findings: [{ ...finding, evidence }],
          }}
        />,
      );

      expect(screen.getByText("76 \u00b7 DeviceManagement/Admin \u00b7 record 88456")).toBeTruthy();
      expect(screen.getByText("76 \u00b7 DeviceManagement/Admin \u00b7 record 88458")).toBeTruthy();
      expect(screen.queryByText(/record 88459/)).toBeNull();
      expect(screen.getByText("+2 more")).toBeTruthy();
    });

    it("shows the first recommended check and expands the rest on request", () => {
      render(
        <EventDiagnosisPanel
          summary={{
            ...summary,
            findings: [{ ...finding, recommendedChecks: ["Check one.", "Check two.", "Check three."] }],
          }}
        />,
      );

      expect(screen.getByText("Next: Check one.")).toBeTruthy();
      expect(screen.queryByText("Next: Check two.")).toBeNull();
      fireEvent.click(screen.getByRole("button", { name: "+2 more checks" }));
      expect(screen.getByText("Next: Check two.")).toBeTruthy();
      expect(screen.getByText("Next: Check three.")).toBeTruthy();
    });

    it("writes no finding text of its own", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      const card = screen.getByRole("article");
      // Everything in the card is a field of the finding or its evidence.
      expect(card).toHaveTextContent(finding.title);
      expect(card).toHaveTextContent(finding.summary);
      expect(card).toHaveTextContent("Next: Inspect the provider record.");
    });
  });

  describe("empty state", () => {
    it("shows the overview headline and 'No actionable findings.'", () => {
      render(<EventDiagnosisPanel summary={neutralSummary("noFindings")} />);

      expect(
        screen.getByText(neutralSummaries.noFindings.overview.headline),
      ).toBeTruthy();
      expect(screen.getByText("No actionable findings.")).toBeTruthy();
      expect(screen.queryByRole("article")).toBeNull();
    });

    it("keys the empty state on the authoritative count, not the preview", () => {
      render(
        <EventDiagnosisPanel
          summary={{
            ...summary,
            findings: [],
            overview: { ...summary.overview, actionableFindingCount: 3 },
          }}
        />,
      );

      expect(screen.queryByText("No actionable findings.")).toBeNull();
      expect(screen.getByText("3 actionable findings omitted.")).toBeTruthy();
    });
  });

  describe("coverage disclosure", () => {
    it("is collapsed, counts the authoritative total and groups identical gaps", () => {
      const groupedSummary: DiagnosisSummary = {
        ...summary,
        coverageGaps: [coverageGap, { ...coverageGap, id: "ime-gap-repeat" }],
        overview: { ...summary.overview, coverageGapCount: 2 },
      };
      render(<EventDiagnosisPanel summary={groupedSummary} />);

      expect(disclosure("Coverage gaps (2)")).not.toHaveAttribute("open");
      expand("Coverage gaps (2)");
      expect(
        screen.getByText(
          "Coverage: IntuneManagementExtension.log (absent): The log was not captured. (2 occurrences)",
        ),
      ).toBeTruthy();
    });

    it("exposes the expanded rows as a named keyboard-focusable region", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      expand(/Coverage gaps/);

      const viewport = screen.getByRole("region", { name: "Coverage gaps (1)" });
      expect(viewport).toHaveAttribute("tabindex", "0");
      expect(viewport).toHaveStyle({ overflowY: "auto" });
      viewport.focus();
      expect(viewport).toHaveFocus();
    });

    it("caps the rows at DETAIL_RENDER_CAP and states how many were omitted", () => {
      const cappedSummary: DiagnosisSummary = {
        ...summary,
        coverageGaps: Array.from({ length: 101 }, (_, index) => ({
          ...coverageGap,
          id: `gap-${index}`,
          source: `source-${index}`,
        })),
        overview: { ...summary.overview, coverageGapCount: 101 },
      };
      render(<EventDiagnosisPanel summary={cappedSummary} />);
      expand(/Coverage gaps/);

      expect(DETAIL_RENDER_CAP).toBe(100);
      expect(screen.getAllByText(/^Coverage:/)).toHaveLength(100);
      expect(screen.getByText("1 coverage gap omitted.")).toBeTruthy();
    });

    it("is absent when there are no coverage gaps", () => {
      render(<EventDiagnosisPanel summary={neutralSummary("noFindings")} />);
      expect(screen.queryByText(/Coverage gaps/)).toBeNull();
    });
  });

  describe("diagnosis details disclosure", () => {
    it("does not render source-wide evidence or repeat findings in event details", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      expand("Show diagnosis details");

      expect(screen.queryByText(/summary\.evtx/)).toBeNull();
      expect(screen.getAllByText("MDM enrollment failed")).toHaveLength(1);
      expect(screen.getByText(/^Errors:/)).toHaveTextContent(
        "Errors: 0x80070005 \u2014 Access is denied, 0xDEADBEEF (unresolved)",
      );
    });

    it("does not treat evidence-only events as event details", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      expand("Show diagnosis details");

      expect(screen.queryByText("other")).toBeNull();
      expect(screen.queryByText(/ordinary\.evtx/)).toBeNull();
    });

    it("keeps the per-edge correlation rows reachable", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      expand("Show diagnosis details");

      expect(screen.getByText(/Correlation: candidate \(candidateIdentifier\) event-1/)).toBeTruthy();
      expect(screen.getByText(/event-1 activityId=activity-1/)).toBeTruthy();
    });
  });

  it("uses authoritative totals when the backend returns bounded previews", () => {
    const boundedSummary: DiagnosisSummary = {
      ...summary,
      overview: {
        ...summary.overview,
        findingCount: 812,
        actionableFindingCount: 712,
        coverageGapCount: 4_228,
        evidenceCount: 8_217,
        correlationCount: 849,
        errorTokenEventCount: 207,
      },
    };
    render(<EventDiagnosisPanel summary={boundedSummary} />);

    expect(screen.getByTestId("overview-counts")).toHaveTextContent(
      "712 actionable findings, 4,228 source coverage gaps",
    );
    expect(screen.getByText("711 actionable findings omitted.")).toBeTruthy();
    expect(screen.getByText("Coverage gaps (4,228)")).toBeTruthy();

    expand("Coverage gaps (4,228)");
    expect(screen.getByText("4,227 coverage gaps omitted.")).toBeTruthy();
    expand("Show diagnosis details");
    expect(screen.getByText("848 correlations omitted.")).toBeTruthy();
    expect(
      screen.getByText("206 error-token event details omitted."),
    ).toBeTruthy();
  });

  describe("level mix and top event IDs", () => {
    const records = [
      record(1, 100, "Error"),
      record(2, 100, "Error"),
      record(3, 100, "Warning"),
      record(4, 200, "Information"),
      record(5, 300, "Critical"),
    ];

    it("counts the visible records by level and states the scope", () => {
      render(<EventDiagnosisPanel summary={summary} records={records} />);

      const mix = screen.getByRole("region", { name: "Level mix" });
      const legend = within(mix).getAllByRole("listitem").map((item) => item.textContent);
      expect(legend).toEqual(["Critical 1", "Error 2", "Warning 1", "Information 1"]);
      expect(screen.getByLabelText("Operational diagnosis")).toHaveTextContent(
        "Scoped to 5 visible events",
      );
    });

    it("lists the top event IDs by count, as information only without a handler", () => {
      render(<EventDiagnosisPanel summary={summary} records={records} />);

      const top = screen.getByRole("region", { name: "Top event IDs" });
      const rows = within(top).getAllByRole("listitem");
      expect(rows.map((row) => row.getAttribute("data-event-id"))).toEqual(["100", "200", "300"]);
      expect(rows[0]).toHaveTextContent("1003");
      // Phase 6a (#834) makes a row a button when the caller supplies `onFilterToEventId`; without
      // one it stays information, with no button and no "click to filter" caption.
      expect(within(top).queryAllByRole("button")).toHaveLength(0);
      expect(top).not.toHaveTextContent("click to filter");
    });

    it("draws the bars in exactly the single-series color, not a level color", () => {
      render(<EventDiagnosisPanel summary={summary} records={records} />);
      const visuals = buildEvtxVisualTokens(getThemeById(useUiStore.getState().themeId));
      const resolved = (color: string) => {
        const probe = document.createElement("span");
        probe.style.backgroundColor = color;
        return probe.style.backgroundColor;
      };
      const top = screen.getByRole("region", { name: "Top event IDs" });
      const bars = Array.from(top.querySelectorAll<HTMLElement>("span[style*='height: 10px']"));
      expect(bars).toHaveLength(3);
      for (const bar of bars) {
        expect(bar.style.backgroundColor).toBe(resolved(visuals.singleSeries));
        expect(bar.style.backgroundColor).not.toBe(resolved(visuals.levels.Error.barColor));
        expect(bar.style.backgroundColor).not.toBe(resolved(visuals.levels.Warning.barColor));
      }
    });

    it("renders each ID and count as text and hides only the bar", () => {
      render(<EventDiagnosisPanel summary={summary} records={records} />);
      const top = screen.getByRole("region", { name: "Top event IDs" });
      const row = within(top).getAllByRole("listitem")[0];
      expect(row).not.toHaveAttribute("aria-label");
      const [id, bar, count] = Array.from(row.children);
      expect(id).toHaveTextContent("100");
      expect(count).toHaveTextContent("3");
      expect(id).not.toHaveAttribute("aria-hidden");
      expect(count).not.toHaveAttribute("aria-hidden");
      expect(bar).toHaveAttribute("aria-hidden", "true");
    });

    it("keeps only the seven most frequent IDs", () => {
      const many = Array.from({ length: 10 }, (_, index) => record(index, 1000 + index, "Information"));
      render(<EventDiagnosisPanel summary={summary} records={many} />);

      expect(
        within(screen.getByRole("region", { name: "Top event IDs" })).getAllByRole("listitem"),
      ).toHaveLength(7);
    });

    it("leaves both cards out without records", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      expect(screen.queryByRole("region", { name: "Level mix" })).toBeNull();
      expect(screen.queryByRole("region", { name: "Top event IDs" })).toBeNull();
    });
  });

  describe("correlation summary", () => {
    it("reports the authoritative total with a per-status breakdown of the preview", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      const card = screen.getByRole("region", { name: "Correlations" });
      expect(card).toHaveTextContent("1 correlation");
      expect(card).toHaveTextContent("0 exact \u00b7 1 candidate \u00b7 0 ambiguous");
    });

    it("says when the breakdown covers only a preview and states no correlation total", () => {
      render(
        <EventDiagnosisPanel
          summary={{ ...summary, overview: { ...summary.overview, correlationCount: 849 } }}
        />,
      );
      const card = screen.getByRole("region", { name: "Correlations" });
      expect(card).toHaveTextContent("Showing the first 1 of 849 relations");
      expect(card).not.toHaveTextContent(/849 correlations/);
    });

    it("never counts a coverage-blocked relation as a correlation", () => {
      const edge = (status: DiagnosisCorrelationEdge["status"], id: string) => ({
        ...summary.correlations[0],
        status,
        left: id,
      });
      render(
        <EventDiagnosisPanel
          summary={{
            ...summary,
            correlations: [edge("exact", "a"), edge("coverageBlocked", "b"), edge("coverageBlocked", "c")],
            overview: { ...summary.overview, correlationCount: 3 },
          }}
        />,
      );
      const card = screen.getByRole("region", { name: "Correlations" });
      expect(card).toHaveTextContent(/^Correlations1 correlation1 exact/);
      expect(card).toHaveTextContent("2 coverage blocked");
      expect(card).not.toHaveTextContent("3 correlations");
    });
  });

  describe("finding class, evidence labels and expansion", () => {
    const labelFor = (
      findingClass: DiagnosisFinding["class"],
      label: string,
    ) => {
      cleanup();
      render(
        <EventDiagnosisPanel
          summary={{ ...summary, findings: [{ ...finding, class: findingClass }] }}
        />,
      );
      expect(screen.getByText(`${label} \u00b7 high confidence`)).toBeTruthy();
    };

    it("shows the engine's class on every card, so contradictory evidence is not a plain failure", () => {
      labelFor("confirmedFailure", "Confirmed failure");
      labelFor("likelyContributor", "Likely contributor");
      labelFor("contradictoryEvidence", "Contradictory evidence");
      labelFor("recovered", "Recovered");
    });

    const eventEvidence = (overrides: Record<string, unknown>) => ({
      kind: "event" as const,
      value: {
        source: "a.evtx",
        provider: "Provider",
        eventId: 76,
        recordId: 0,
        channel: "DeviceManagement/Admin",
        machine: "PC-1",
        ...overrides,
      },
    });

    it("follows the engine's identity order and never prints record 0", () => {
      render(
        <EventDiagnosisPanel
          summary={{
            ...summary,
            findings: [
              {
                ...finding,
                evidence: [
                  eventEvidence({ recordIdText: "88456", recordId: 5 }),
                  eventEvidence({ recordIdText: "0", fallbackIdentity: "abcdef0123456789" }),
                  eventEvidence({ recordId: 0 }),
                ],
              },
            ],
          }}
        />,
      );
      const card = screen.getByRole("article");
      expect(card).toHaveTextContent("76 \u00b7 DeviceManagement/Admin \u00b7 record 88456");
      expect(card).toHaveTextContent("76 \u00b7 DeviceManagement/Admin \u00b7 ref abcdef01");
      expect(card).toHaveTextContent("76 \u00b7 DeviceManagement/Admin \u00b7 no record ID");
      expect(card).not.toHaveTextContent("record 0");
    });

    it("adds the source and machine when the evidence spans more than one", () => {
      const spanning = {
        ...summary,
        findings: [
          {
            ...finding,
            evidence: [
              eventEvidence({ recordId: 1 }),
              eventEvidence({ recordId: 2, source: "b.evtx", machine: "PC-2" }),
            ],
          },
        ],
      };
      render(<EventDiagnosisPanel summary={spanning} />);
      const card = screen.getByRole("article");
      expect(card).toHaveTextContent("record 1 \u00b7 a.evtx \u00b7 PC-1");
      expect(card).toHaveTextContent("record 2 \u00b7 b.evtx \u00b7 PC-2");
    });

    it("leaves the origin out when every reference shares it", () => {
      render(
        <EventDiagnosisPanel
          summary={{ ...summary, findings: [{ ...finding, evidence: [eventEvidence({ recordId: 1 })] }] }}
        />,
      );
      expect(screen.getByRole("article")).not.toHaveTextContent("a.evtx");
    });

    it("expands the evidence beyond three references in place, bounded with an omitted count", () => {
      const evidence = Array.from({ length: 105 }, (_, index) =>
        eventEvidence({ recordId: index + 1 }),
      );
      render(<EventDiagnosisPanel summary={{ ...summary, findings: [{ ...finding, evidence }] }} />);
      expect(screen.queryByText(/record 4$/)).toBeNull();

      fireEvent.click(screen.getByRole("button", { name: "+102 more" }));
      expect(screen.getByText(/record 4$/)).toBeTruthy();
      expect(screen.getByText(/record 100$/)).toBeTruthy();
      expect(screen.queryByText(/record 101$/)).toBeNull();
      expect(screen.getByText("5 evidence references omitted.")).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "Show fewer" }));
      expect(screen.queryByText(/record 4$/)).toBeNull();
    });
  });

  describe("rebuilding, failure and no input", () => {
    const records = [record(1, 100, "Error"), record(2, 200, "Warning")];

    it("keeps the record cards while a first diagnosis is being built", () => {
      render(<EventDiagnosisPanel summary={null} records={records} updating />);
      expect(screen.getByRole("status")).toHaveTextContent("Updating diagnosis...");
      expect(screen.getByRole("region", { name: "Level mix" })).toBeTruthy();
      expect(screen.getByRole("region", { name: "Top event IDs" })).toBeTruthy();
      expect(screen.queryByText("No actionable findings.")).toBeNull();
    });

    it("says a build failed without repeating the workspace banner's prefixed message", () => {
      render(
        <EventDiagnosisPanel
          summary={null}
          records={records}
          error="Operational diagnosis could not be built: engine unavailable"
        />,
      );
      const status = screen.getByRole("status");
      expect(status).toHaveTextContent(/^Diagnosis could not be built\.$/);
      expect(status).not.toHaveTextContent("Operational");
      expect(status).not.toHaveTextContent("engine unavailable");
      expect(screen.queryByText(/not available yet/)).toBeNull();
    });

    it("says there is nothing to diagnose when there is no input", () => {
      render(<EventDiagnosisPanel summary={null} />);
      expect(screen.getByRole("status")).toHaveTextContent(
        "There are no events or text logs to diagnose.",
      );
    });

    it("keeps open disclosures and card expansions across a rebuild, marked as updating", () => {
      const many = {
        ...summary,
        findings: [{ ...finding, recommendedChecks: ["One.", "Two."] }],
      };
      const { rerender } = render(<EventDiagnosisPanel summary={many} records={records} />);
      expand(/Coverage gaps/);
      expand("Show diagnosis details");
      fireEvent.click(screen.getByRole("button", { name: "+1 more check" }));

      rerender(<EventDiagnosisPanel summary={many} records={records} updating />);
      // The overview from the previous build is dimmed and busy, like the cards.
      expect(screen.getByTestId("overview-counts").parentElement).toHaveAttribute("aria-busy", "true");
      expect(screen.getByTestId("overview-counts").parentElement).toHaveStyle({ opacity: "0.6" });

      expect(disclosure(/Coverage gaps/)).toHaveProperty("open", true);
      expect(disclosure("Show diagnosis details")).toHaveProperty("open", true);
      expect(screen.getByText("Next: Two.")).toBeTruthy();
      expect(screen.getByRole("status")).toHaveTextContent("Updating diagnosis...");
      expect(screen.getByRole("article")).toHaveAttribute("aria-busy", "true");

      rerender(<EventDiagnosisPanel summary={many} records={records} />);
      expect(screen.queryByRole("status")).toBeNull();
      expect(disclosure(/Coverage gaps/)).toHaveProperty("open", true);
    });
  });

  describe("counts from the previous build while a rebuild is pending", () => {
    const busy = (element: Element | null) => {
      expect(element).not.toBeNull();
      expect(element).toHaveAttribute("aria-busy", "true");
      expect(element).toHaveStyle({ opacity: "0.6" });
    };
    const bounded: DiagnosisSummary = {
      ...summary,
      overview: {
        ...summary.overview,
        actionableFindingCount: 3,
        coverageGapCount: 4,
        correlationCount: 5,
        errorTokenEventCount: 3,
      },
    };

    it("dims every one of them and clears the marks when the build lands", () => {
      const { rerender } = render(<EventDiagnosisPanel summary={bounded} updating />);
      busy(screen.getByText(/Coverage gaps/, { selector: "summary" }).closest("details"));
      busy(screen.getByRole("region", { name: "Correlations" }));
      busy(screen.getByText("2 actionable findings omitted."));
      busy(screen.getByText(/Show diagnosis details/, { selector: "summary" }).closest("details"));

      rerender(<EventDiagnosisPanel summary={bounded} />);
      for (const element of [
        screen.getByText(/Coverage gaps/, { selector: "summary" }).closest("details"),
        screen.getByRole("region", { name: "Correlations" }),
        screen.getByText("2 actionable findings omitted."),
      ]) {
        expect(element).not.toHaveAttribute("aria-busy");
        expect(element).toHaveStyle({ opacity: "1" });
      }
    });

    // Opacity multiplies down the tree, so the number that matters is the effective one.
    const effectiveOpacity = (element: Element | null) => {
      let opacity = 1;
      for (let node = element; node; node = node.parentElement) {
        const own = (node as HTMLElement).style?.opacity;
        if (own) opacity *= Number(own);
      }
      return opacity;
    };

    it("dims each omitted-row count once: 0.6 effective, inside a disclosure or not", () => {
      render(<EventDiagnosisPanel summary={bounded} updating />);
      expand(/Coverage gaps/);
      expand("Show diagnosis details");
      for (const text of [
        "2 actionable findings omitted.",
        "3 coverage gaps omitted.",
        "4 correlations omitted.",
        "2 error-token event details omitted.",
      ]) {
        expect(effectiveOpacity(screen.getByText(text)), text).toBeCloseTo(0.6, 5);
      }
      // The rows inside a stale disclosure carry no dimming of their own.
      expect(screen.getByText("3 coverage gaps omitted.").style.opacity).toBe("");
      expect(screen.getByText("2 actionable findings omitted.").style.opacity).toBe("0.6");
    });

    it("dims 'No actionable findings.'", () => {
      render(<EventDiagnosisPanel summary={neutralSummary("noFindings")} updating />);
      busy(screen.getByText("No actionable findings."));
    });
  });

  describe("scope line", () => {
    it("states the scope the shown summary was built from, not the new record count", () => {
      const three = [record(1, 1, "Error"), record(2, 1, "Error"), record(3, 1, "Error")];
      render(
        <EventDiagnosisPanel summary={summary} records={three} scopeCount={2} updating />,
      );
      const section = screen.getByLabelText("Operational diagnosis");
      expect(section).toHaveTextContent("Scoped to 2 visible events");
      expect(section).not.toHaveTextContent("Scoped to 3");
    });
  });

  describe("rendered text", () => {
    it("is exactly the engine's strings plus the known UI labels", () => {
      render(<EventDiagnosisPanel summary={summary} />);
      let text = screen.getByRole("article").textContent ?? "";
      const known = [
        "error",
        "Confirmed failure",
        "high confidence",
        finding.title,
        finding.summary,
        "76",
        "Next: Inspect the provider record.",
      ];
      // The evidence reference is built from the finding's own fields.
      const evidence = finding.evidence[0].value as { eventId: number; provider: string; recordId: number };
      known.push(`${evidence.eventId} \u00b7 ${evidence.provider} \u00b7 record ${evidence.recordId}`);
      for (const part of known.sort((a, b) => b.length - a.length)) text = text.replace(part, "");
      expect(text.replace(/[\s\u00b7]/g, "")).toBe("");
    });
  });
});

describe("OUTCOME_LABELS", () => {
  it("gives every diagnosis outcome its own wording", () => {
    // A gap and a clean result must not read the same. insufficientEvidence
    // means the analysis could not conclude; noFindings means it concluded
    // nothing was wrong.
    const labels = Object.values(OUTCOME_LABELS);
    expect(new Set(labels).size).toBe(labels.length);
  });

  it("does not report insufficient evidence as a clean result", () => {
    expect(OUTCOME_LABELS.insufficientEvidence).not.toBe(
      OUTCOME_LABELS.noFindings,
    );
  });
});

/**
 * Phase 6a (#834): the two actions that narrow the view. The panel reads no store; the caller gives
 * it handlers, and the panel gives them what the evidence resolves to.
 */
describe("Filter to {n} events", () => {
  const eventRef = (recordId: number, overrides: Record<string, unknown> = {}) => ({
    kind: "event" as const,
    value: { source: "sample.evtx", provider: "Example Provider", eventId: 100, recordId, ...overrides },
  });
  const citing = (id: string, ...evidence: DiagnosisFinding["evidence"]): DiagnosisFinding => ({
    ...finding,
    findingId: id,
    title: `Finding ${id}`,
    evidence,
  });
  const summaryOf = (...findings: DiagnosisFinding[]): DiagnosisSummary => ({
    ...summary,
    findings,
    coverageGaps: [],
    overview: { ...summary.overview, findingCount: findings.length, actionableFindingCount: findings.length },
  });
  // Records 1..5 are event 100 from sample.evtx; their EventRecordID is 100 + id.
  const loaded = [1, 2, 3, 4, 5].map((n) => ({ ...record(n, 100, "Error"), eventRecordId: n }));

  it("offers the link on a finding whose event evidence names loaded events, with their count", () => {
    const onFilter = vi.fn();
    render(
      <EventDiagnosisPanel
        summary={summaryOf(citing("a", eventRef(1), eventRef(3)))}
        records={loaded}
        onFilterToFinding={onFilter}
      />,
    );
    const link = screen.getByRole("button", { name: /Filter to 2 events/ });
    fireEvent.click(link);
    expect(onFilter).toHaveBeenCalledTimes(1);
    const [finding, scope] = onFilter.mock.calls[0];
    expect(finding.findingId).toBe("a");
    expect(scope.records).toEqual([loaded[0], loaded[2]]);
    expect(scope.counts).toEqual({ notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false });
  });

  it("says one event in the singular", () => {
    render(
      <EventDiagnosisPanel
        summary={summaryOf(citing("a", eventRef(2)))}
        records={loaded}
        onFilterToFinding={vi.fn()}
      />,
    );
    expect(screen.getByRole("button", { name: /Filter to 1 event$/ })).toBeInTheDocument();
  });

  it("has no link without a handler", () => {
    render(<EventDiagnosisPanel summary={summaryOf(citing("a", eventRef(2)))} records={loaded} />);
    expect(screen.queryByRole("button", { name: /Filter to/ })).toBeNull();
  });

  it("has no link, and no claim, for a finding that cites no event", () => {
    const textOnly = citing("a", {
      kind: "textLog",
      value: { source: "s", filePath: "f.log", lineNumber: 3, entryId: 3 },
    });
    render(
      <EventDiagnosisPanel summary={summaryOf(textOnly)} records={loaded} onFilterToFinding={vi.fn()} />,
    );
    const card = screen.getByRole("article", { name: "Finding a" });
    expect(within(card).queryByRole("button", { name: /Filter to/ })).toBeNull();
    expect(card).not.toHaveTextContent(/cited|bounded/);
  });

  it("claims nothing about bounded evidence for a finding that cites no event, even when the response was bounded", () => {
    const textOnly = citing("text", {
      kind: "textLog",
      value: { source: "s", filePath: "f.log", lineNumber: 3, entryId: 3 },
    });
    // Another finding cites an event, so the panel does index the records and could resolve both.
    const bounded: DiagnosisSummary = {
      ...summaryOf(citing("events", eventRef(1)), textOnly),
      coverageGaps: [{ ...coverageGap, source: "diagnosis-response-projection", state: "capped" }],
    };
    render(<EventDiagnosisPanel summary={bounded} records={loaded} onFilterToFinding={vi.fn()} />);
    expect(screen.getByRole("article", { name: "Finding events" })).toHaveTextContent("bounded");
    expect(screen.getByRole("article", { name: "Finding text" })).not.toHaveTextContent(/bounded|cited/);
  });

  it("offers no link when nothing the finding cites is loaded, and says why", () => {
    const onFilter = vi.fn();
    render(
      <EventDiagnosisPanel
        summary={summaryOf(citing("a", eventRef(999), eventRef(0, { fallbackIdentity: "abcdef0123456789" })))}
        records={loaded}
        onFilterToFinding={onFilter}
      />,
    );
    const card = screen.getByRole("article", { name: "Finding a" });
    expect(within(card).queryByRole("button", { name: /Filter to/ })).toBeNull();
    expect(card).toHaveTextContent("1 cited event is not loaded.");
    expect(card).toHaveTextContent("1 cited event cannot be matched to a loaded event: no usable record identity.");
  });

  it("names each class that fell short on its own line beside the link", () => {
    const twins = [
      { ...record(6, 100, "Error"), eventRecordId: 6, sourceLabel: "a.evtx" },
      { ...record(7, 100, "Error"), eventRecordId: 6, sourceLabel: "b.evtx" },
    ];
    render(
      <EventDiagnosisPanel
        summary={summaryOf(
          citing(
            "a",
            eventRef(1),
            eventRef(999),
            eventRef(6, { source: undefined }),
            eventRef(0, { fallbackIdentity: "abcdef0123456789" }),
          ),
        )}
        records={[...loaded, ...twins]}
        onFilterToFinding={vi.fn()}
      />,
    );
    const card = screen.getByRole("article", { name: "Finding a" });
    expect(within(card).getByRole("button", { name: /Filter to 3 events/ })).toBeInTheDocument();
    for (const line of [
      "1 cited event is not loaded.",
      "1 cited event cannot be matched to a loaded event: no usable record identity.",
      "1 cited reference matches more than one loaded event. Every match is included.",
      "The diagnosis response is bounded, so this finding may cite more events than were sent.",
    ]) {
      expect(card).toHaveTextContent(line);
    }
  });

  it("says the response is bounded when the engine's projection gap is in the summary", () => {
    const bounded: DiagnosisSummary = {
      ...summaryOf(citing("a", eventRef(1))),
      coverageGaps: [{ ...coverageGap, source: "diagnosis-response-projection", state: "capped" }],
    };
    render(<EventDiagnosisPanel summary={bounded} records={loaded} onFilterToFinding={vi.fn()} />);
    expect(screen.getByRole("article", { name: "Finding a" })).toHaveTextContent(
      "The diagnosis response is bounded",
    );
  });

  it("disables the link while the card is from a previous build", () => {
    const onFilter = vi.fn();
    render(
      <EventDiagnosisPanel
        summary={summaryOf(citing("a", eventRef(1)))}
        records={loaded}
        updating
        onFilterToFinding={onFilter}
      />,
    );
    const link = screen.getByRole("button", { name: /Filter to 1 event/ });
    expect(link).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(link);
    expect(onFilter).not.toHaveBeenCalled();
  });
});

describe("Top event IDs as filters", () => {
  const records = [
    record(1, 100, "Error"),
    record(2, 100, "Error"),
    record(3, 100, "Warning"),
    record(4, 200, "Information"),
  ];
  const top = () => screen.getByRole("region", { name: "Top event IDs" });

  it("makes each row a named button and captions the card", () => {
    render(<EventDiagnosisPanel summary={summary} records={records} onFilterToEventId={vi.fn()} />);
    expect(top()).toHaveTextContent("click to filter");
    const buttons = within(top()).getAllByRole("button");
    expect(buttons.map((b) => b.getAttribute("aria-label"))).toEqual([
      "Event ID 100, 3 events",
      "Event ID 200, 1 event",
    ]);
    expect(buttons.every((b) => b.getAttribute("type") === "button")).toBe(true);
    // The row still reads as an ID, a hidden bar and a count.
    const [id, bar, count] = Array.from(buttons[0].children);
    expect(id).toHaveTextContent("100");
    expect(count).toHaveTextContent("3");
    expect(bar).toHaveAttribute("aria-hidden", "true");
  });

  it("calls back with the row's event ID", () => {
    const onFilter = vi.fn();
    render(<EventDiagnosisPanel summary={summary} records={records} onFilterToEventId={onFilter} />);
    fireEvent.click(screen.getByRole("button", { name: "Event ID 200, 1 event" }));
    expect(onFilter).toHaveBeenCalledExactlyOnceWith(200);
  });

  it("presses only the row of the one ID the quick filter shows", () => {
    const { rerender } = render(
      <EventDiagnosisPanel summary={summary} records={records} onFilterToEventId={vi.fn()} activeEventId={200} />,
    );
    const pressed = () =>
      within(top()).getAllByRole("button").map((b) => b.getAttribute("aria-pressed"));
    expect(pressed()).toEqual(["false", "true"]);
    rerender(<EventDiagnosisPanel summary={summary} records={records} onFilterToEventId={vi.fn()} />);
    expect(pressed()).toEqual(["false", "false"]);
  });

  it("draws the pressed row in the selection colors", () => {
    render(
      <EventDiagnosisPanel summary={summary} records={records} onFilterToEventId={vi.fn()} activeEventId={100} />,
    );
    const visuals = buildEvtxVisualTokens(getThemeById(useUiStore.getState().themeId));
    const pressed = within(top()).getByRole("button", { pressed: true });
    expect(pressed.style.backgroundColor).toBe(visuals.selection.background);
    expect(pressed.style.getPropertyValue("--evtx-top-id-color")).toBe(visuals.selection.foreground);
    expect(pressed.style.getPropertyValue("--evtx-top-count-color")).toBe(visuals.selection.foreground);
  });
});

describe("the scope line and text logs", () => {
  const records = [record(1, 100, "Error")];
  const panel = () => screen.getByLabelText("Operational diagnosis");

  it("adds a muted line that text logs are not scoped when the events are narrowed and the session holds some", () => {
    render(<EventDiagnosisPanel summary={summary} records={records} textLogCount={3} loadedCount={5} />);
    expect(panel()).toHaveTextContent("Scoped to 1 visible event");
    expect(panel()).toHaveTextContent("Text logs are not scoped.");
  });

  it("leaves the line out when nothing is narrowed: every loaded event is visible", () => {
    render(<EventDiagnosisPanel summary={summary} records={records} textLogCount={3} loadedCount={1} />);
    expect(panel()).toHaveTextContent("Scoped to 1 visible event");
    expect(panel()).not.toHaveTextContent("Text logs are not scoped.");
  });

  it("follows the counts the shown build was made with, not the records now in view", () => {
    render(
      <EventDiagnosisPanel summary={summary} records={records} scopeCount={2} textLogCount={3} loadedCount={2} />,
    );
    expect(panel()).not.toHaveTextContent("Text logs are not scoped.");
  });

  it("leaves the line out without text logs, and keeps the scope line's own text unchanged", () => {
    render(<EventDiagnosisPanel summary={summary} records={records} textLogCount={0} loadedCount={5} />);
    expect(panel()).toHaveTextContent("Scoped to 1 visible event");
    expect(panel()).not.toHaveTextContent("Text logs are not scoped.");
  });

  it("leaves the line out when the loaded count is not known", () => {
    render(<EventDiagnosisPanel summary={summary} records={records} textLogCount={3} />);
    expect(panel()).not.toHaveTextContent("Text logs are not scoped.");
  });

  it("leaves the line out where there is no scope line", () => {
    render(<EventDiagnosisPanel summary={summary} textLogCount={3} loadedCount={5} />);
    expect(panel()).not.toHaveTextContent("Scoped to");
    expect(panel()).not.toHaveTextContent("Text logs are not scoped.");
  });
});

/** Contrast in all seven themes for what Phase 6a adds to the rail (spec 10). */
describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))(
  "Top event IDs and the Filter link in the %s theme",
  (id, theme) => {
    const r = (token: string) => resolveToken(token, theme);
    const atLeast = (label: string, a: string, b: string, minimum: number) => {
      expect(contrastRatio(r(a), r(b)), `${id}: ${label}`).toBeGreaterThanOrEqual(minimum);
    };

    function declaredVars(element: Element, pseudo: "" | ":hover" | ":active", property: string): string[] {
      const selectors = Array.from(element.classList).map((name) => `.${name}${pseudo}`);
      const values: string[] = [];
      for (const sheet of Array.from(document.styleSheets)) {
        for (const rule of Array.from(sheet.cssRules)) {
          if (rule instanceof CSSStyleRule && selectors.includes(rule.selectorText)) {
            const value = rule.style.getPropertyValue(property);
            if (value) values.push(value);
          }
        }
      }
      return values;
    }

    it("reads the ID and the count at 4.5:1 at rest, hovered and pressed", () => {
      useUiStore.setState({ themeId: theme.id });
      render(<EventDiagnosisPanel summary={summary} records={[record(1, 100, "Error")]} onFilterToEventId={vi.fn()} />);
      const row = within(screen.getByRole("region", { name: "Top event IDs" })).getByRole("button");
      expect(declaredVars(row, "", "--evtx-top-id-color")).toEqual([tokens.colorNeutralForeground1]);
      expect(declaredVars(row, "", "--evtx-top-count-color")).toEqual([tokens.colorNeutralForeground2]);
      expect(declaredVars(row, ":hover", "--evtx-top-id-color")).toEqual([tokens.colorNeutralForeground1Hover]);
      expect(declaredVars(row, ":hover", "--evtx-top-count-color")).toEqual([tokens.colorNeutralForeground2Hover]);
      expect(declaredVars(row, ":hover", "background-color")).toEqual([tokens.colorSubtleBackgroundHover]);
      expect(declaredVars(row, ":active", "--evtx-top-id-color")).toEqual([tokens.colorNeutralForeground1Pressed]);
      expect(declaredVars(row, ":active", "--evtx-top-count-color")).toEqual([tokens.colorNeutralForeground2Pressed]);
      expect(declaredVars(row, ":active", "background-color")).toEqual([tokens.colorSubtleBackgroundPressed]);

      atLeast("ID at rest", tokens.colorNeutralForeground1, tokens.colorNeutralBackground1, 4.5);
      atLeast("count at rest", tokens.colorNeutralForeground2, tokens.colorNeutralBackground1, 4.5);
      atLeast("ID hovered", tokens.colorNeutralForeground1Hover, tokens.colorSubtleBackgroundHover, 4.5);
      atLeast("count hovered", tokens.colorNeutralForeground2Hover, tokens.colorSubtleBackgroundHover, 4.5);
      atLeast("ID pressed", tokens.colorNeutralForeground1Pressed, tokens.colorSubtleBackgroundPressed, 4.5);
      atLeast("count pressed", tokens.colorNeutralForeground2Pressed, tokens.colorSubtleBackgroundPressed, 4.5);
    });

    it("reads the pressed row's ID and count in the selection foreground at 4.5:1 on its fill", () => {
      const selection = buildEvtxVisualTokens(theme).selection;
      atLeast("pressed row", selection.foreground, selection.background, 4.5);
    });

    it("reads the Filter link at rest, hovered and pressed at 4.5:1 on the card", () => {
      useUiStore.setState({ themeId: theme.id });
      render(
        <EventDiagnosisPanel
          summary={{ ...summary, findings: [finding] }}
          records={[{ ...record(1, 75, "Error"), eventRecordId: 12, provider: "Provider", sourceLabel: "event.evtx" }]}
          onFilterToFinding={vi.fn()}
        />,
      );
      const link = screen.getByRole("button", { name: /Filter to 1 event/ });
      expect(link.className).toContain("fui-Link");
      atLeast("link rest", tokens.colorBrandForegroundLink, tokens.colorNeutralBackground1, 4.5);
      atLeast("link hover", tokens.colorBrandForegroundLinkHover, tokens.colorNeutralBackground1, 4.5);
      atLeast("link pressed", tokens.colorBrandForegroundLinkPressed, tokens.colorNeutralBackground1, 4.5);
    });
  },
);

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DETAIL_RENDER_CAP, OUTCOME_LABELS, EventDiagnosisPanel } from "./EventDiagnosisPanel";
import type {
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
    expect(
      screen.getByText(/1 actionable finding, 1 source coverage gap/),
    ).toBeTruthy();
    expect(screen.queryByText("1 correlation")).toBeTruthy();
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
      expect(screen.getByText("high confidence")).toBeTruthy();
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

    expect(
      screen.getByText(/712 actionable findings, 4228 source coverage gaps/),
    ).toBeTruthy();
    expect(screen.getByText("711 actionable findings omitted.")).toBeTruthy();
    expect(screen.getByText("Coverage gaps (4228)")).toBeTruthy();

    expand("Coverage gaps (4228)");
    expect(screen.getByText("4227 coverage gaps omitted.")).toBeTruthy();
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
      expect(screen.getByText("Scoped to 5 visible events")).toBeTruthy();
    });

    it("lists the top event IDs by count with no click action yet", () => {
      render(<EventDiagnosisPanel summary={summary} records={records} />);

      const top = screen.getByRole("region", { name: "Top event IDs" });
      const rows = within(top).getAllByRole("listitem");
      expect(rows.map((row) => row.getAttribute("data-event-id"))).toEqual(["100", "200", "300"]);
      expect(rows[0]).toHaveTextContent("1003");
      // Phase 5 owns the event-ID chip; until then a row is information only.
      expect(within(top).queryAllByRole("button")).toHaveLength(0);
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

    it("says when the breakdown covers only a preview of the total", () => {
      render(
        <EventDiagnosisPanel
          summary={{ ...summary, overview: { ...summary.overview, correlationCount: 849 } }}
        />,
      );
      const card = screen.getByRole("region", { name: "Correlations" });
      expect(card).toHaveTextContent("849 correlations");
      expect(card).toHaveTextContent("(first 1 of 849)");
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

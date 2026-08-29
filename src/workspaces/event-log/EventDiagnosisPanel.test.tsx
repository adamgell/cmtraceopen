import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EventDiagnosisPanel } from "./EventDiagnosisPanel";
import type { DiagnosisCoverageGap, DiagnosisSummary } from "./types";

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
    coverageGapCount: 1,
    evidenceCount: 1,
    correlationCount: 1,
  },
};

function expandDiagnosis(): HTMLDetailsElement {
  const details = document.querySelector("details");
  expect(details).not.toBeNull();
  fireEvent.click(screen.getByText("Show diagnosis details"));
  expect(details).toHaveProperty("open", true);
  return details as HTMLDetailsElement;
}

describe("EventDiagnosisPanel", () => {
  it("starts collapsed with an actionable-finding and source-coverage overview", () => {
    render(<EventDiagnosisPanel summary={summary} />);

    const details = document.querySelector("details");
    expect(details).not.toBeNull();
    expect(details).not.toHaveAttribute("open");
    const detailViewport = details?.querySelector("div");
    expect(detailViewport).toHaveStyle({ overflowY: "auto" });
    expect(detailViewport?.style.maxHeight).not.toBe("");
    expect(screen.getByText("1 actionable finding")).toBeTruthy();
    expect(screen.getByText("1 source coverage gap")).toBeTruthy();
    expect(
      screen.getByText(/1 actionable finding, 1 source coverage gap/),
    ).toBeTruthy();
  });

  it("exposes expanded details as a named keyboard-focusable region", () => {
    render(<EventDiagnosisPanel summary={summary} />);

    const details = document.querySelector("details");
    expect(details).not.toHaveAttribute("open");
    expandDiagnosis();

    const detailViewport = screen.getByRole("region", {
      name: "Show diagnosis details",
    });
    expect(detailViewport).toHaveAttribute("tabindex", "0");
    detailViewport.focus();
    expect(detailViewport).toHaveFocus();
  });

  it("does not render source-wide evidence or repeat findings in event details", () => {
    render(<EventDiagnosisPanel summary={summary} />);
    expandDiagnosis();

    expect(screen.queryByText(/summary\.evtx/)).toBeNull();
    expect(screen.getAllByText("MDM enrollment failed")).toHaveLength(1);
    expect(screen.getByText(/^Errors:/)).toHaveTextContent(
      "Errors: 0x80070005 — Access is denied, 0xDEADBEEF (unresolved)",
    );
  });

  it("does not treat evidence-only events as event details", () => {
    render(<EventDiagnosisPanel summary={summary} />);
    expandDiagnosis();

    expect(screen.queryByText("other")).toBeNull();
    expect(screen.queryByText(/ordinary\.evtx/)).toBeNull();
  });

  it("groups identical coverage gaps and states their occurrence count", () => {
    const groupedSummary: DiagnosisSummary = {
      ...summary,
      coverageGaps: [coverageGap, { ...coverageGap, id: "ime-gap-repeat" }],
    };
    render(<EventDiagnosisPanel summary={groupedSummary} />);
    expandDiagnosis();

    expect(
      screen.getByText(
        "Coverage: IntuneManagementExtension.log (absent): The log was not captured. (2 occurrences)",
      ),
    ).toBeTruthy();
  });

  it("reports omitted rows when an expanded detailed section reaches its cap", () => {
    const cappedSummary: DiagnosisSummary = {
      ...summary,
      coverageGaps: Array.from({ length: 101 }, (_, index) => ({
        ...coverageGap,
        id: `gap-${index}`,
        source: `source-${index}`,
      })),
    };
    render(<EventDiagnosisPanel summary={cappedSummary} />);
    expandDiagnosis();

    expect(screen.getAllByText(/^Coverage:/)).toHaveLength(100);
    expect(screen.getByText("1 coverage gap omitted.")).toBeTruthy();
  });
});

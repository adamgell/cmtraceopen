import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EventDiagnosisPanel } from "./EventDiagnosisPanel";
import type { DiagnosisSummary } from "./types";

const summary: DiagnosisSummary = {
  findings: [
    {
      findingId: "event-1",
      class: "confirmedFailure",
      severity: "error",
      confidence: "high",
      title: "MDM enrollment failed",
      summary: "The provider reported access denied.",
      evidence: [
        {
          kind: "event",
          value: { source: "event.evtx", provider: "Provider", eventId: 75, recordId: 12 },
        },
      ],
      coverageGaps: [],
      recommendedChecks: ["Inspect the provider record."],
    },
    {
      findingId: "ime-gap-finding",
      class: "coverageGap",
      severity: "info",
      confidence: "unknown",
      title: "IME coverage gap",
      summary: "The log was not captured.",
      evidence: [],
      coverageGaps: [
        {
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
        },
      ],
      recommendedChecks: [],
    },
  ],
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
  coverageGaps: [
    {
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
    },
  ],
  correlations: [
    {
      left: "event-1",
      right: "text-1",
      basis: "candidateIdentifier",
      status: "candidate",
      candidateIds: ["text-1"],
      evidence: [{ originId: "event-1", field: "activityId", value: "activity-1" }],
    },
  ],
  events: [
    {
      family: "mdmEnrollment",
      evidence: [
        {
          kind: "event",
          value: { source: "event.evtx", provider: "Provider", eventId: 75, recordId: 12 },
        },
      ],
      findings: [],
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

describe("EventDiagnosisPanel", () => {
  it("renders finding class, severity, coverage, and lossless error token", () => {
    render(<EventDiagnosisPanel summary={summary} />);
    expect(screen.getAllByText("confirmedFailure")).toHaveLength(2);
    expect(screen.getByText("MDM enrollment failed")).toBeTruthy();
    expect(screen.getByText("error")).toBeTruthy();
    expect(screen.getByText(/Access is denied/)).toBeTruthy();
    expect(screen.getByText(/IntuneManagementExtension\.log \(absent\)/)).toBeTruthy();
    expect(screen.getByText(/0x80070005/)).toBeTruthy();
    expect(screen.queryByText("IME coverage gap")).toBeNull();
  });

  it("renders overview, correlations, and unresolved error tokens", () => {
    render(<EventDiagnosisPanel summary={summary} />);
    expect(screen.getByText(/Evidence contains confirmed operational failure/)).toBeTruthy();
    expect(screen.getByText(/Correlation: candidate/)).toBeTruthy();
    expect(screen.getByText(/0xDEADBEEF \(unresolved\)/)).toBeTruthy();
  });

  it("does not repeat a normalized hexadecimal token that already matches its raw value", () => {
    render(<EventDiagnosisPanel summary={summary} />);

    const errors = screen.getByText(/^Errors:/);
    expect(errors).toHaveTextContent(
      "Errors: 0x80070005 — Access is denied, 0xDEADBEEF (unresolved)",
    );
    expect(errors).not.toHaveTextContent("0x80070005 (0x80070005)");
  });

  it("renders structured evidence and coverage details", () => {
    render(<EventDiagnosisPanel summary={summary} />);
    expect(screen.getAllByText(/provider=Provider/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Coverage: IntuneManagementExtension\.log \(absent\): The log was not captured\./)).toBeTruthy();
    expect(screen.getByText(/Coverage evidence: textLog: source=IntuneManagementExtension\.log, filePath=.*lineNumber=42/)).toBeTruthy();
    expect(screen.getByText(/Correlation evidence: event-1 activityId=activity-1/)).toBeTruthy();
    expect(screen.getAllByText(/Event evidence: event:/).length).toBeGreaterThan(0);
  });
});

import { describe, expect, it } from "vitest";
import {
  getMdmVisibilityLabel,
  selectTopFindings,
  toneForMdmVisibility,
  toneForPrtState,
} from "./dsregcmd-formatters";
import type { DsregcmdAnalysisResult, DsregcmdSeverity } from "./types";

type MdmDerived = Pick<
  DsregcmdAnalysisResult["derived"],
  "mdmEnrolled" | "missingMdm" | "missingComplianceUrl"
>;

const mdmDerived = (overrides: Partial<MdmDerived>) =>
  ({
    mdmEnrolled: null,
    missingMdm: false,
    missingComplianceUrl: false,
    ...overrides,
  }) as DsregcmdAnalysisResult["derived"];

/// The sidebar and the facts panel must tell the same story for every
/// `mdmEnrolled` value. `false` is not "Unknown": it means the analysis
/// affirmatively found no enrollment, which deserves a warning tone.
describe("MDM visibility", () => {
  it("reports Present and good when enrolled with both URLs", () => {
    const derived = mdmDerived({ mdmEnrolled: true });
    expect(getMdmVisibilityLabel(derived)).toBe("Present");
    expect(toneForMdmVisibility(derived)).toBe("good");
  });

  it("reports Partial and neutral when enrolled but a URL is missing", () => {
    const missingMdm = mdmDerived({ mdmEnrolled: true, missingMdm: true });
    const missingCompliance = mdmDerived({
      mdmEnrolled: true,
      missingComplianceUrl: true,
    });
    expect(getMdmVisibilityLabel(missingMdm)).toBe("Partial");
    expect(toneForMdmVisibility(missingMdm)).toBe("neutral");
    expect(getMdmVisibilityLabel(missingCompliance)).toBe("Partial");
    expect(toneForMdmVisibility(missingCompliance)).toBe("neutral");
  });

  it("reports Not enrolled and warn when enrollment is affirmatively absent", () => {
    const derived = mdmDerived({ mdmEnrolled: false });
    expect(getMdmVisibilityLabel(derived)).toBe("Not enrolled");
    expect(toneForMdmVisibility(derived)).toBe("warn");
  });

  it("keeps Unknown and neutral when enrollment could not be determined", () => {
    const derived = mdmDerived({ mdmEnrolled: null });
    expect(getMdmVisibilityLabel(derived)).toBe("Unknown");
    expect(toneForMdmVisibility(derived)).toBe("neutral");
  });
});

/// The Top Findings list claims "Highest-priority diagnostics first". The
/// analysis returns its diagnostics grouped by rule family, so the claim only
/// holds if the list is ordered on the way to the screen.
describe("selectTopFindings", () => {
  const diagnostic = (id: string, severity: DsregcmdSeverity) => ({
    id,
    severity,
  });

  it("orders mixed severities Error, then Warning, then Info", () => {
    const source = [
      diagnostic("info-1", "Info"),
      diagnostic("warning-1", "Warning"),
      diagnostic("error-1", "Error"),
    ];

    expect(selectTopFindings(source, 8).map((item) => item.severity)).toEqual([
      "Error",
      "Warning",
      "Info",
    ]);
  });

  it("keeps the original order within one severity", () => {
    const source = [
      diagnostic("error-a", "Error"),
      diagnostic("warning-a", "Warning"),
      diagnostic("error-b", "Error"),
      diagnostic("warning-b", "Warning"),
    ];

    expect(selectTopFindings(source, 8).map((item) => item.id)).toEqual([
      "error-a",
      "error-b",
      "warning-a",
      "warning-b",
    ]);
  });

  it("finds an Error that sits beyond the unsorted limit", () => {
    // Three Warnings and then the only Error. Limiting before sorting would show
    // three Warnings and hide the Error entirely.
    const source = [
      diagnostic("warning-a", "Warning"),
      diagnostic("warning-b", "Warning"),
      diagnostic("warning-c", "Warning"),
      diagnostic("error-a", "Error"),
    ];

    expect(selectTopFindings(source, 2).map((item) => item.id)).toEqual([
      "error-a",
      "warning-a",
    ]);
  });

  it("leaves the source diagnostics untouched", () => {
    const source = [
      diagnostic("info-1", "Info"),
      diagnostic("error-1", "Error"),
    ];
    const before = source.map((item) => item.id);

    selectTopFindings(source, 8);

    expect(source.map((item) => item.id)).toEqual(before);
    expect(source[0].severity).toBe("Info");
  });

  it("is safe on an empty list", () => {
    expect(selectTopFindings([], 8)).toEqual([]);
  });
});

describe("toneForPrtState", () => {
  it("is neutral when PRT presence is unknown", () => {
    expect(toneForPrtState(null, null)).toBe("neutral");
  });

  it("is bad when no PRT is present", () => {
    expect(toneForPrtState(false, null)).toBe("bad");
  });

  it("is warn when the PRT is stale", () => {
    expect(toneForPrtState(true, true)).toBe("warn");
  });

  it("is good when the PRT is present and fresh", () => {
    expect(toneForPrtState(true, false)).toBe("good");
  });

  it("is neutral when freshness is unknown instead of claiming health", () => {
    expect(toneForPrtState(true, null)).toBe("neutral");
    expect(toneForPrtState(true, undefined)).toBe("neutral");
  });
});

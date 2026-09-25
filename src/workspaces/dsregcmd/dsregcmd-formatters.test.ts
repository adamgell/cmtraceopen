import { describe, expect, it } from "vitest";
import {
  qualifyByCaptureConfidence,
  selectTopFindings,
  toneForPrtState,
} from "./dsregcmd-formatters";
import type { DsregcmdSeverity } from "./types";

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

/// The qualifier prefixes a conclusion drawn from a low-confidence capture. It
/// used to lower-case the detail's first character, which mangled product and
/// acronym names ("MDM" -> "mDM", "PRT present" -> "pRT present").
describe("qualifyByCaptureConfidence", () => {
  it("leaves high-confidence copy untouched", () => {
    expect(qualifyByCaptureConfidence("high", "PRT present is Yes.")).toBe(
      "PRT present is Yes.",
    );
  });

  it("prefixes a caveat without re-casing the detail", () => {
    expect(qualifyByCaptureConfidence("low", "MDM visibility is Unknown.")).toBe(
      "Based on this capture, MDM visibility is Unknown.",
    );
    expect(qualifyByCaptureConfidence("medium", "NGC is Yes.")).toBe(
      "Based on this capture, NGC is Yes.",
    );
  });
});

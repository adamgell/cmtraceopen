import { useMemo } from "react";
import { useDsregcmdStore } from "./dsregcmd-store";
import {
  computeDisplayedPrtAgeHours,
  getDisplayConfidenceAssessment,
  getDisplayPhaseAssessment,
  getFactGroups,
  type FactGroup,
} from "./dsregcmd-formatters";

/**
 * Display assessments and fact groups derived from the current result, shared
 * by the workspace and the left navigation so the navigation's counts are
 * computed from the same rows the page renders.
 */
export function useDsregcmdDerived() {
  const result = useDsregcmdStore((s) => s.result);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);

  return useMemo(() => {
    const diagnostics = result?.diagnostics ?? [];
    const errorCount = diagnostics.filter((item) => item.severity === "Error").length;
    const warningCount = diagnostics.filter((item) => item.severity === "Warning").length;
    const displayedPrtAgeHours = computeDisplayedPrtAgeHours(result, sourceContext);
    const displayPhase = result
      ? getDisplayPhaseAssessment(result, errorCount, warningCount)
      : null;
    const displayConfidence = result
      ? getDisplayConfidenceAssessment(result, sourceContext)
      : null;
    const factGroups: FactGroup[] =
      result && displayPhase && displayConfidence
        ? getFactGroups(
            result,
            displayedPrtAgeHours,
            displayPhase,
            displayConfidence,
            sourceContext,
          )
        : [];

    return {
      errorCount,
      warningCount,
      displayedPrtAgeHours,
      displayPhase,
      displayConfidence,
      factGroups,
    };
  }, [result, sourceContext]);
}

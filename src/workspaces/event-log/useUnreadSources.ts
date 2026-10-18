/**
 * Whether any source's records were not (all) loaded, read from the store's coverage state. The one
 * producer of the dock's `unreadSources` input (`DockModelInput`), and of the Details context's
 * (#843): they ask the same question of the same state. The rule is `hasUnreadSources`'s.
 */
import { useMemo } from "react";
import type { EventLogSourceCoverage } from "./types";
import { unreadSourcesFrom } from "./evtx-coverage";
import { useEvtxStore } from "./evtx-store";

const NO_COVERAGE: readonly EventLogSourceCoverage[] = [];

export function useUnreadSources(): boolean {
  const coverageDetails = useEvtxStore((s) => s.coverageDetails);
  const manifestCoverage = useEvtxStore((s) => s.sourceManifest?.coverage) ?? NO_COVERAGE;
  const coverageGaps = useEvtxStore((s) => s.coverageGaps);
  const tailCoverageGaps = useEvtxStore((s) => s.tailCoverageGaps);
  return useMemo(
    () => unreadSourcesFrom({ coverageDetails, manifestCoverage, coverageGaps, tailCoverageGaps }),
    [coverageDetails, manifestCoverage, coverageGaps, tailCoverageGaps],
  );
}

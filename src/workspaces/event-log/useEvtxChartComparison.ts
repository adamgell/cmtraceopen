/**
 * Wires the Charts view's previous-period comparison (spec 8.16) to the stores.
 *
 * The view is prop-driven and reads no store. This hook reads the comparison's published state and
 * the criteria it was made under, decides whether Compare can be offered, and supplies the three
 * actions. It adds no rule of its own: the availability is the comparison's (`resolveFilesPrior`,
 * `computePriorWindow`), the criteria are the store's (`comparisonVisibility`), and the current
 * period is counted by `countCurrentPeriod`, lazily, so nothing is counted unless a complete
 * comparison is on show and the Charts view is the active one.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ComparisonAvailability, ComparisonPresentationInput } from "./evtx-chart-comparison";
import {
  cancelComparison,
  computePriorWindow,
  countCurrentPeriod,
  getComparisonState,
  resolveFilesPrior,
  useComparisonStore,
} from "./evtx-comparison";
import { comparePreviousPeriod, comparisonVisibility, useEvtxStore } from "./evtx-store";
import type { EvtxChartsComparisonProps } from "./EvtxChartsView";

/**
 * The comparison for the Charts view, or null while Charts is not showing.
 *
 * `nowEpoch` is the instant the grid and the tiles are measured from. It is the anchor a files
 * comparison is made at, the instant a files refusal is judged at, and the snapshot the comparison
 * is checked against for staleness, so all three agree with what the tiles show.
 */
export function useEvtxChartComparison(
  active: boolean,
  nowEpoch: number,
): EvtxChartsComparisonProps | null {
  const state = useComparisonStore((s) => s.state);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const records = useEvtxStore((s) => s.records);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const columnConfig = useEvtxStore((s) => s.columnConfig);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);

  // The store cancels a comparison whenever what it measured changes, and the cancel is silent
  // (the state just goes idle). When that happens without the operator asking, say so once.
  const [cleared, setCleared] = useState(false);
  const quiet = useRef(false);
  useEffect(
    () =>
      useComparisonStore.subscribe((next, previous) => {
        if (next.state.phase !== "idle") setCleared(false);
        else if (previous.state.phase !== "idle" && !quiet.current) setCleared(true);
      }),
    [],
  );

  const onCompare = useCallback(() => {
    if (getComparisonState().phase === "running") return;
    void comparePreviousPeriod(nowEpoch);
  }, [nowEpoch]);

  // The operator's own Clear is not an announcement: the notice is for a comparison the store ended.
  const onClear = useCallback(() => {
    quiet.current = true;
    try {
      cancelComparison();
    } finally {
      quiet.current = false;
    }
  }, []);

  const onRecompare = useCallback(() => {
    quiet.current = true;
    const run = async () => {
      if (useEvtxStore.getState().sourceMode === "live") {
        // A live comparison keeps the anchor of the load it was made from, so comparing again alone
        // would describe the same period. The channels are read again first (which cancels the old
        // comparison, so nothing of it is on show while they load), then compared from the clock.
        await useEvtxStore.getState().refreshLoadedChannels();
        await comparePreviousPeriod(Date.now());
      } else {
        await comparePreviousPeriod(nowEpoch);
      }
    };
    void run()
      .catch((error: unknown) => {
        console.warn("[evtx] Refresh and compare again failed:", error);
      })
      .finally(() => {
        quiet.current = false;
      });
  }, [nowEpoch]);

  const availability = useMemo<ComparisonAvailability>(() => {
    if (!active) return { available: true };
    const prior =
      sourceMode === "files"
        ? resolveFilesPrior(records, selectedChannels, timeWindow, nowEpoch)
        : computePriorWindow(timeWindow, nowEpoch);
    return prior.status === "available"
      ? { available: true }
      : { available: false, detail: prior.detail };
  }, [active, sourceMode, records, selectedChannels, timeWindow, nowEpoch]);

  const input = useMemo<ComparisonPresentationInput | null>(() => {
    if (!active) return null;
    const visibility = comparisonVisibility({
      selectedChannels,
      filterLevels,
      filterEventIds,
      filterSearch,
      quickFilter,
      columnConfig,
      timeZoneMode,
    });
    return {
      state,
      availability,
      timeZoneMode,
      snapshotEpoch: nowEpoch,
      // Called by the presentation only for a complete comparison that is still current.
      countCurrent: () => {
        if (state.phase !== "settled" || state.outcome.status === "unavailable") {
          throw new Error("There is no completed comparison to count the current period for.");
        }
        const tally = countCurrentPeriod(records, state.outcome.result, visibility);
        return {
          errors: tally.counts.levels.Error,
          distinctIds: tally.counts.distinctEvents,
          tailExcluded: tally.tailExcluded,
          unplacedRecords: tally.unplacedRecords,
        };
      },
      cleared,
    };
  }, [
    active,
    state,
    availability,
    nowEpoch,
    cleared,
    records,
    selectedChannels,
    filterLevels,
    filterEventIds,
    filterSearch,
    quickFilter,
    columnConfig,
    timeZoneMode,
  ]);

  return useMemo(
    () => (input ? { input, onCompare, onRecompare, onClear } : null),
    [input, onCompare, onRecompare, onClear],
  );
}

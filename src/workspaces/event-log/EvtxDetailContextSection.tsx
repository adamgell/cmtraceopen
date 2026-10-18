/**
 * The Details "Context ±5 min" section as the pane mounts it (spec 8.13 Details item 7, #843): the
 * list of `EvtxDetailContext` fed from the workspace's own sources, and nothing else. It has no state,
 * no effect and no rule of its own:
 * - the session is the workspace's (`useEvtxAnalysisSession`), mapped to available, building or none
 *   by `analysisSessionState` from the correlation stage, the same mapping the dock uses;
 * - the unread sources are the store's (`useUnreadSources`), the dock's own producer;
 * - the window is the shared reader's (`useEvtxCorrelationWindow`) at a fixed ±5 min around the
 *   record's instant (`dockCenterMs`), and only while the section is `active`: the Insights panel is
 *   shown AND the rail is on its Details tab. (The pane mounts it only on the Details sub-tab, so the
 *   third condition is the mount itself: the XML sub-tab has no section and so no query.)
 * - the counts are the workspace's counts-only model, paired with the window by session key inside
 *   the model.
 *
 * Loaded lazily by the pane, so the model, the copy and the window reader stay out of the entry chunk
 * until the Details tab shows a record. Nothing here is announced.
 */
import { useEvtxCorrelationData } from "./useEvtxCorrelation";
import { analysisSessionState, useEvtxAnalysisSession } from "./evtx-analysis-session";
import { dockCenterMs } from "./evtx-correlation-dock-model";
import type { CorrelationWindowDeps } from "./evtx-correlation-window";
import { DETAIL_CONTEXT_HALF_WIDTH_MS } from "./evtx-detail-context-model";
import { EvtxDetailContext } from "./EvtxDetailContext";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import type { EvtxTimeZoneMode } from "./evtx-time";
import type { EvtxRecord } from "./types";
import { useEvtxCorrelationWindow } from "./useEvtxCorrelationWindow";
import { useUnreadSources } from "./useUnreadSources";

export interface EvtxDetailContextSectionProps {
  /** The record the Details tab shows. */
  record: EvtxRecord;
  timeZoneMode: EvtxTimeZoneMode;
  /** The reader's IO and waits, for a test: the app uses the defaults. */
  windowDeps?: Partial<CorrelationWindowDeps>;
  selectionSettleMs?: number;
  sessionSettleMs?: number;
}

export default function EvtxDetailContextSection({
  record,
  timeZoneMode,
  windowDeps,
  selectionSettleMs,
  sessionSettleMs,
}: EvtxDetailContextSectionProps) {
  const insightsShown = useEvtxLayoutStore((s) => s.panels.insights);
  const railOnDetails = useEvtxLayoutStore((s) => s.railTab === "details");
  const correlation = useEvtxCorrelationData();
  const status = useEvtxAnalysisSession();
  const unreadSources = useUnreadSources();

  const { window } = useEvtxCorrelationWindow({
    status,
    centerMs: dockCenterMs(record),
    halfWidthMs: DETAIL_CONTEXT_HALF_WIDTH_MS,
    active: insightsShown && railOnDetails,
    selectionSettleMs,
    sessionSettleMs,
    deps: windowDeps,
  });

  return (
    <EvtxDetailContext
      record={record}
      window={window}
      counts={correlation.counts}
      unreadSources={unreadSources}
      session={analysisSessionState(status, correlation.stage)}
      timeZoneMode={timeZoneMode}
    />
  );
}

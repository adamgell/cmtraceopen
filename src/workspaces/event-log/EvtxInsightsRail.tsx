/**
 * The right-hand rail of the Event Logs workbench (spec sections 5.2 and 8.13).
 *
 * Tabs: Insights, and Details, which reads "Event {id}" while a record is selected. The Chains tab
 * id already exists in the layout store (Phase 10c builds it); `RAIL_TABS` is the one list to add
 * it to, and a persisted `chains` selection shows Insights until then.
 *
 * The Insights panel stays mounted (hidden) while Details is active, so a row click does not reset
 * its disclosures or its scroll position, and a finding card can be focused from the Details
 * callout. The Details body mounts on demand and scrolls itself under its fixed header.
 */
import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Tab, TabList, tokens } from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { EventDiagnosisPanel, actionableFindings, sortFindings } from "./EventDiagnosisPanel";
import { parseEventIdSelectors, type EvtxQuickFilter } from "./evtx-filter";
import type { FindingScope } from "./evtx-insights-data";
import { EvtxDetailPane } from "./EvtxDetailPane";
import {
  evtxRailPanelId,
  evtxRailTabId,
  useEvtxLayoutStore,
  type EvtxRailTabId,
} from "./evtx-layout-store";
import { findRecordById, formatCount } from "./evtx-insights-data";
import { useRailTextColors } from "./evtx-rail-text";
import { useEvtxStore } from "./evtx-store";
import type { DiagnosisFinding, DiagnosisSummary, EvtxRecord } from "./types";

interface EvtxInsightsRailProps {
  summary: DiagnosisSummary | null;
  /** The visible records the summary was built from. */
  records: readonly EvtxRecord[];
  /** A diagnosis build is under way; `summary` is null meanwhile. */
  pending?: boolean;
  /** Why the last diagnosis build failed. */
  error?: string | null;
  /** How many text-log entries the diagnosis session was given (the event criteria never narrow them). */
  textLogCount?: number;
}

/** Tabs the rail can show today, in order. Phase 10c adds "chains" between the two. */
const RAIL_TABS: readonly EvtxRailTabId[] = ["insights", "details"];

/** Record summaries publish at most once per this long (spec section 11, the 75 ms precedent). */
export const INSIGHTS_DEBOUNCE_MS = 75;

/**
 * The one event ID a quick filter is showing, or null: the applied filter is in Event IDs mode, shows
 * what matches, and names exactly one ID (a range or a list names more, and an invalid one none).
 */
export function soleQuickFilterEventId(filter: EvtxQuickFilter): number | null {
  if (filter.mode !== "eventIds" || filter.action !== "show") return null;
  const { selectors, invalid } = parseEventIdSelectors(filter.query);
  if (invalid || selectors.length !== 1) return null;
  const [only] = selectors;
  return only.kind === "single" && only.id !== undefined ? only.id : null;
}

/**
 * The quick filter after a click on a Top event IDs row. It REPLACES the quick filter slot: mode,
 * query and action become "this ID, show" while the operator's scope, case and highlight settings
 * stay, and the filter that was there is gone (its chip changes to this one). A click on the row
 * that is the only ID shown clears the query instead, as removing the chip does.
 */
export function quickFilterAfterEventIdClick(
  applied: EvtxQuickFilter,
  shown: EvtxQuickFilter,
  eventId: number,
): EvtxQuickFilter {
  if (soleQuickFilterEventId(applied) === eventId) return { ...applied, query: "" };
  return { ...shown, mode: "eventIds", action: "show", query: String(eventId) };
}

const NO_RECORDS: readonly EvtxRecord[] = [];
const NO_FINDINGS: readonly DiagnosisFinding[] = [];

/**
 * `value`, published at most once per `delayMs`: the first change starts a timer that publishes the
 * latest value when it fires, and further changes do not restart it (the analysis pump's precedent).
 * A pure trailing debounce would starve the cards while a tail never goes quiet for the delay. The
 * first value is immediate.
 */
export function useThrottledValue<T>(value: T, delayMs: number): T {
  const [published, setPublished] = useState(value);
  const latestRef = useRef(value);
  const timerRef = useRef<number | null>(null);
  latestRef.current = value;
  useEffect(() => {
    if (Object.is(published, value) || timerRef.current !== null) return;
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      setPublished(latestRef.current);
    }, delayMs);
  }, [value, published, delayMs]);
  useEffect(
    () => () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      timerRef.current = null;
    },
    [],
  );
  return published;
}

function Count({ value, size, color }: { value: number; size: number; color: string }) {
  return (
    <span
      style={{
        marginLeft: "2px",
        fontSize: `${size}px`,
        fontWeight: 400,
        fontFamily: tokens.fontFamilyNumeric,
        color,
      }}
    >
      {formatCount(value)}
    </span>
  );
}

export function EvtxInsightsRail({
  summary,
  records,
  pending = false,
  error = null,
  textLogCount = 0,
}: EvtxInsightsRailProps) {
  const railTab = useEvtxLayoutStore((s) => s.railTab);
  const setRailTab = useEvtxLayoutStore((s) => s.setRailTab);
  const railVisible = useEvtxLayoutStore((s) => s.panels.insights);
  const storeRecords = useEvtxStore((s) => s.records);
  const selectedRecordId = useEvtxStore((s) => s.selectedRecordId);
  const selectedEventId = useMemo(
    () => findRecordById(storeRecords, selectedRecordId)?.eventId ?? null,
    [storeRecords, selectedRecordId],
  );
  const activeEventId = useEvtxStore((s) => soleQuickFilterEventId(s.quickFilter));
  const railText = useRailTextColors();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const countSize = useMemo(
    () => Math.max(10, getLogListMetrics(logListFontSize).fontSize - 1),
    [logListFontSize],
  );

  // After a restart the tab can be Details with nothing selected (the selection is not saved).
  // Open on Insights then, so the diagnosis is the first thing seen. Once the rail is running a
  // user may still open an empty Details tab.
  const startedRef = useRef(false);
  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;
    if (railTab === "details" && useEvtxStore.getState().selectedRecordId === null) {
      setRailTab("insights");
    }
  }, [railTab, setRailTab]);

  const activeTab: EvtxRailTabId = RAIL_TABS.includes(railTab) ? railTab : "insights";

  // The diagnosis is cleared while it rebuilds. Keep showing the previous build, marked as
  // updating, so the reader's place survives a live-tail batch; drop it on failure or no input.
  // The visible-event count is stored WITH the summary, so the scope line states the scope the
  // shown numbers were built from, never the new count beside old numbers.
  const lastBuildRef = useRef<{
    summary: DiagnosisSummary;
    scopeCount: number;
    textLogCount: number;
  } | null>(null);
  if (summary && lastBuildRef.current?.summary !== summary) {
    lastBuildRef.current = { summary, scopeCount: records.length, textLogCount };
  }
  if (error || (!summary && !pending)) lastBuildRef.current = null;
  const shown = summary || (pending && !error) ? lastBuildRef.current : null;
  const shownSummary = shown?.summary ?? null;

  // Record-derived cards are skipped while the rail cannot be seen. Everything derived from the
  // records (cards, Details order, Same ID series) follows the debounced set (spec section 11).
  const insightsActive = railVisible && activeTab === "insights";
  const debouncedRecords = useThrottledValue(records, INSIGHTS_DEBOUNCE_MS);
  const cardRecords = insightsActive ? debouncedRecords : NO_RECORDS;

  // A finding from the previous build is not evidence for the records now shown, so the Details
  // callout waits for the new build.
  const findings = useMemo(
    () =>
      shownSummary && !pending
        ? sortFindings(actionableFindings(shownSummary.findings))
        : NO_FINDINGS,
    [shownSummary, pending],
  );

  // "Filter to {n} events": the scope is the loaded events the finding names, its title is kept as
  // written (a rebuilt diagnosis may drop the finding), and Table is shown only if it was applied.
  const filterToFinding = (finding: DiagnosisFinding, scope: FindingScope) => {
    const applied = useEvtxStore.getState().setRecordScope({
      kind: "finding",
      title: finding.title,
      records: new Set(scope.records),
      counts: scope.counts,
    });
    if (applied) useEvtxLayoutStore.getState().setActiveView("table");
  };
  // A Top event IDs row replaces the quick filter with that ID, an on-load criterion: no re-query.
  const filterToEventId = (eventId: number) => {
    const state = useEvtxStore.getState();
    state.setQuickFilter(
      quickFilterAfterEventIdClick(state.quickFilter, state.quickFilterDraft ?? state.quickFilter, eventId),
    );
  };

  const insightsScrollRef = useRef<HTMLDivElement>(null);
  const savedScrollRef = useRef(0);
  // Hiding the panel (another tab, or the rail toggle) drops its scroll offset in a browser, so the
  // saved offset is put back when it is shown again.
  useLayoutEffect(() => {
    const element = insightsScrollRef.current;
    if (insightsActive && element) element.scrollTop = savedScrollRef.current;
  }, [insightsActive]);

  // No count while a rebuild is pending: the old count would read as the new build's.
  const actionableCount = pending ? null : (shownSummary?.overview.actionableFindingCount ?? null);
  const labels: Record<EvtxRailTabId, ReactNode> = {
    insights: (
      <>
        Insights
        {actionableCount !== null && (
          // The space keeps the accessible name "Insights 3" rather than "Insights3".
          <>
            {" "}
            <Count value={actionableCount} size={countSize} color={railText.secondary} />
          </>
        )}
      </>
    ),
    chains: "Chains",
    details: selectedEventId !== null ? `Event ${selectedEventId}` : "Details",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
      <TabList
        size="small"
        aria-label="Rail tabs"
        selectedValue={activeTab}
        onTabSelect={(_, data) => setRailTab(data.value as EvtxRailTabId)}
        style={{
          paddingLeft: "6px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          flexShrink: 0,
        }}
      >
        {RAIL_TABS.map((tab) => (
          <Tab
            key={tab}
            id={evtxRailTabId(tab)}
            value={tab}
            aria-controls={evtxRailPanelId(tab)}
            style={activeTab === tab ? { color: railText.primary } : undefined}
          >
            {labels[tab]}
          </Tab>
        ))}
      </TabList>
      <div
        ref={insightsScrollRef}
        role="tabpanel"
        id={evtxRailPanelId("insights")}
        aria-labelledby={evtxRailTabId("insights")}
        hidden={activeTab !== "insights"}
        onScroll={(event) => {
          if (activeTab === "insights") savedScrollRef.current = event.currentTarget.scrollTop;
        }}
        style={{
          flex: 1,
          minHeight: 0,
          overflowX: "hidden",
          overflowY: "auto",
          padding: "12px",
          display: activeTab === "insights" ? "block" : "none",
        }}
      >
        <EventDiagnosisPanel
          summary={shownSummary}
          records={cardRecords.length > 0 ? cardRecords : undefined}
          updating={pending}
          error={error}
          scopeCount={shown?.scopeCount ?? null}
          textLogCount={shown?.textLogCount ?? 0}
          onFilterToFinding={filterToFinding}
          onFilterToEventId={filterToEventId}
          activeEventId={activeEventId}
        />
      </div>
      {activeTab === "details" && (
        <div
          role="tabpanel"
          id={evtxRailPanelId("details")}
          aria-labelledby={evtxRailTabId("details")}
          style={{ flex: 1, minHeight: 0, overflow: "hidden" }}
        >
          <EvtxDetailPane visibleRecords={debouncedRecords} findings={findings} />
        </div>
      )}
    </div>
  );
}

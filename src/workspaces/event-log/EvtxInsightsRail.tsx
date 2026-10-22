/**
 * The right-hand rail of the Event Logs workbench (spec sections 5.2 and 8.13).
 *
 * Tabs: Insights, Chains and Details, the layout store's `EVTX_RAIL_TAB_IDS` in its order. Details
 * reads "Event {id}" while a record is selected, and Chains reads "Chains {n}" when the number is
 * known, current and complete for edges (`chainsTabCount`), else "Chains".
 *
 * The Insights panel stays mounted (hidden) while another tab is active, so a row click does not
 * reset its disclosures or its scroll position, and a finding card can be focused from the Details
 * callout. The Details and Chains bodies mount on demand. Details scrolls itself under its fixed
 * header; the Chains body is loaded lazily and scrolls in its panel, and is not mounted at all while
 * the rail is hidden (the same rule that decides whether the workspace reads the entries it lists).
 */
import {
  Suspense,
  lazy,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
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
  EVTX_RAIL_TAB_IDS,
  chainsTabShown,
  evtxRailPanelId,
  evtxRailTabId,
  useEvtxLayoutStore,
  type EvtxRailTabId,
} from "./evtx-layout-store";
import { chainsTabCount } from "./evtx-correlation-chains";
import { useEvtxCorrelationData } from "./useEvtxCorrelation";
import { findRecordById, formatCount } from "./evtx-insights-data";
import { useRailTextColors } from "./evtx-rail-text";
import { useEvtxStore } from "./evtx-store";
import { DERIVATION_THROTTLE_MS, useThrottledValue } from "./evtx-throttle";
import type { DiagnosisFinding, DiagnosisSummary, EvtxRecord } from "./types";
import type { ScopeDisclosureInput } from "./evtx-correlation-copy";

interface EvtxInsightsRailProps {
  summary: DiagnosisSummary | null;
  /** The visible records the summary was built from. */
  records: readonly EvtxRecord[];
  /** A diagnosis build is under way; `summary` is null meanwhile. */
  pending?: boolean;
  /** Why the last diagnosis build failed. */
  error?: string | null;
  /**
   * What the session `summary` came from was built from: the visible, loaded and text-log counts,
   * read once when the session was published. The workspace gives the Correlation view the same
   * object, so the two surfaces state one scope for one session. Null when there is none.
   */
  scope?: ScopeDisclosureInput | null;
}

// The Chains body is loaded when the tab is first shown: the model, the copy and the cards stay out of
// the entry chunk until then. Nothing is announced meanwhile (no fallback, no live region).
const EvtxRailChains = lazy(() => import("./EvtxRailChains"));

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

/**
 * The Chains tab's label. It reads the shared correlation data itself, so a scan's progress, which
 * replaces that data many times, re-renders this label and not the rail around it. The number is the
 * NEWEST counts' (never the model on show, which can be an earlier session's), and is left out when it
 * is not known, not current or not complete for edges.
 */
function ChainsTabLabel({ size, color }: { size: number; color: string }) {
  const { counts } = useEvtxCorrelationData();
  const count = chainsTabCount(counts);
  return (
    <>
      Chains
      {count !== null && (
        // The space keeps the accessible name "Chains 3" rather than "Chains3".
        <>
          {" "}
          <Count value={count} size={size} color={color} />
        </>
      )}
    </>
  );
}

export function EvtxInsightsRail({
  summary,
  records,
  pending = false,
  error = null,
  scope = null,
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

  const activeTab: EvtxRailTabId = railTab;
  const chainsShown = useEvtxLayoutStore(chainsTabShown);

  // The diagnosis is cleared while it rebuilds. Keep showing the previous build, marked as
  // updating, so the reader's place survives a live-tail batch; drop it on failure or no input.
  // The session's scope is stored WITH the summary, so the scope line states the scope the shown
  // numbers were built from, never the new count beside old numbers. It is the workspace's scope
  // for that session, not the store's records now: the loaded count is read once, at the publish.
  const lastBuildRef = useRef<{
    summary: DiagnosisSummary;
    scopeCount: number | null;
    textLogCount: number;
    loadedCount: number | undefined;
  } | null>(null);
  if (summary && lastBuildRef.current?.summary !== summary) {
    lastBuildRef.current = {
      summary,
      scopeCount: scope?.visibleCount ?? null,
      textLogCount: scope?.textLogCount ?? 0,
      loadedCount: scope?.loadedCount,
    };
  }
  if (error || (!summary && !pending)) lastBuildRef.current = null;
  const shown = summary || (pending && !error) ? lastBuildRef.current : null;
  const shownSummary = shown?.summary ?? null;

  // Record-derived cards are skipped while the rail cannot be seen. Everything derived from the
  // records (cards, Details order, Same ID series) follows the debounced set (spec section 11).
  const insightsActive = railVisible && activeTab === "insights";
  const debouncedRecords = useThrottledValue(records, DERIVATION_THROTTLE_MS);
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
  //
  // Both handlers read the stores when called, so they close over nothing and are made once: a new
  // function on every render would defeat the panel's `memo` and rebuild its evidence index each time.
  const filterToFinding = useCallback((finding: DiagnosisFinding, scope: FindingScope) => {
    const applied = useEvtxStore.getState().setRecordScope({
      kind: "finding",
      title: finding.title,
      records: new Set(scope.records),
      references: scope.references,
      counts: scope.counts,
    });
    if (applied) useEvtxLayoutStore.getState().setActiveView("table");
  }, []);
  // A Top event IDs row replaces the quick filter with that ID, an on-load criterion: no re-query.
  const filterToEventId = useCallback((eventId: number) => {
    const state = useEvtxStore.getState();
    state.setQuickFilter(
      quickFilterAfterEventIdClick(state.quickFilter, state.quickFilterDraft ?? state.quickFilter, eventId),
    );
  }, []);

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
    chains: <ChainsTabLabel size={countSize} color={railText.secondary} />,
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
        {EVTX_RAIL_TAB_IDS.map((tab) => (
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
          loadedCount={shown?.loadedCount}
          onFilterToFinding={filterToFinding}
          onFilterToEventId={filterToEventId}
          activeEventId={activeEventId}
        />
      </div>
      {chainsShown && (
        <div
          role="tabpanel"
          id={evtxRailPanelId("chains")}
          aria-labelledby={evtxRailTabId("chains")}
          style={{
            flex: 1,
            minHeight: 0,
            overflowX: "hidden",
            overflowY: "auto",
            padding: "12px",
          }}
        >
          <Suspense fallback={null}>
            <EvtxRailChains />
          </Suspense>
        </div>
      )}
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

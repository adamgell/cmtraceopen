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
import { EvtxDetailPane } from "./EvtxDetailPane";
import {
  evtxRailPanelId,
  evtxRailTabId,
  useEvtxLayoutStore,
  type EvtxRailTabId,
} from "./evtx-layout-store";
import { findRecordById, formatCount } from "./evtx-insights-data";
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
}

/** Tabs the rail can show today, in order. Phase 10c adds "chains" between the two. */
const RAIL_TABS: readonly EvtxRailTabId[] = ["insights", "details"];

/** Record summaries follow the diagnosis debounce (spec section 11). */
export const INSIGHTS_DEBOUNCE_MS = 75;

const NO_RECORDS: readonly EvtxRecord[] = [];
const NO_FINDINGS: readonly DiagnosisFinding[] = [];

/** The latest `value`, delayed by `delayMs` after it last changed. The first value is immediate. */
function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    if (Object.is(debounced, value)) return;
    const timer = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, debounced, delayMs]);
  return debounced;
}

function Count({ value, size }: { value: number; size: number }) {
  return (
    <span
      style={{
        marginLeft: "2px",
        fontSize: `${size}px`,
        fontWeight: 400,
        fontFamily: tokens.fontFamilyNumeric,
        color: tokens.colorNeutralForeground3,
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
  const lastSummaryRef = useRef<DiagnosisSummary | null>(null);
  if (summary) lastSummaryRef.current = summary;
  if (error || (!summary && !pending)) lastSummaryRef.current = null;
  const shownSummary = summary ?? (pending && !error ? lastSummaryRef.current : null);

  // Record-derived cards are skipped while the rail cannot be seen and debounced during a tail.
  const insightsActive = railVisible && activeTab === "insights";
  const debouncedRecords = useDebouncedValue(records, INSIGHTS_DEBOUNCE_MS);
  const cardRecords = insightsActive ? debouncedRecords : NO_RECORDS;

  const findings = useMemo(
    () => (shownSummary ? sortFindings(actionableFindings(shownSummary.findings)) : NO_FINDINGS),
    [shownSummary],
  );

  const insightsScrollRef = useRef<HTMLDivElement>(null);
  const savedScrollRef = useRef(0);
  useLayoutEffect(() => {
    const element = insightsScrollRef.current;
    if (activeTab === "insights" && element) element.scrollTop = savedScrollRef.current;
  }, [activeTab]);

  const actionableCount = shownSummary?.overview.actionableFindingCount ?? null;
  const labels: Record<EvtxRailTabId, ReactNode> = {
    insights: (
      <>
        Insights
        {actionableCount !== null && (
          // The space keeps the accessible name "Insights 3" rather than "Insights3".
          <>
            {" "}
            <Count value={actionableCount} size={countSize} />
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
          <Tab key={tab} id={evtxRailTabId(tab)} value={tab} aria-controls={evtxRailPanelId(tab)}>
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
        />
      </div>
      {activeTab === "details" && (
        <div
          role="tabpanel"
          id={evtxRailPanelId("details")}
          aria-labelledby={evtxRailTabId("details")}
          style={{ flex: 1, minHeight: 0, overflow: "hidden" }}
        >
          <EvtxDetailPane visibleRecords={records} findings={findings} />
        </div>
      )}
    </div>
  );
}

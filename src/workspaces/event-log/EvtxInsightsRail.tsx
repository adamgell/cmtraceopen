/**
 * The right-hand rail of the Event Logs workbench (spec sections 5.2 and 8.13).
 *
 * Tabs: Insights, and Details, which reads "Event {id}" while a record is selected. The Chains tab
 * id already exists in the layout store (Phase 10c builds it); `RAIL_TABS` is the one list to add
 * it to, and a persisted `chains` selection shows Insights until then.
 *
 * Only the active tab renders. The Insights body scrolls inside the panel; the Details body
 * (`EvtxDetailPane`) scrolls itself under its fixed header.
 */
import { useMemo, type ReactNode } from "react";
import { Tab, TabList, tokens } from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { EventDiagnosisPanel } from "./EventDiagnosisPanel";
import { EvtxDetailPane } from "./EvtxDetailPane";
import { useEvtxLayoutStore, type EvtxRailTabId } from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import type { DiagnosisSummary, EvtxRecord } from "./types";

interface EvtxInsightsRailProps {
  summary: DiagnosisSummary | null;
  /** The visible records the summary was built from. */
  records: readonly EvtxRecord[];
}

/** Tabs the rail can show today, in order. Phase 10c adds "chains" between the two. */
const RAIL_TABS: readonly EvtxRailTabId[] = ["insights", "details"];

export const EVTX_RAIL_PANEL_ID = "evtx-rail-panel";
export const evtxRailTabId = (tab: EvtxRailTabId) => `evtx-rail-tab-${tab}`;

function Count({ value, size }: { value: number; size: number }) {
  return (
    <span
      style={{
        marginLeft: "2px",
        fontSize: `${size}px`,
        fontWeight: 400,
        color: tokens.colorNeutralForeground3,
      }}
    >
      {value}
    </span>
  );
}

export function EvtxInsightsRail({ summary, records }: EvtxInsightsRailProps) {
  const railTab = useEvtxLayoutStore((s) => s.railTab);
  const setRailTab = useEvtxLayoutStore((s) => s.setRailTab);
  const selectedEventId = useEvtxStore((s) =>
    s.selectedRecordId === null
      ? null
      : (s.records.find((record) => record.id === s.selectedRecordId)?.eventId ?? null),
  );
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const countSize = useMemo(
    () => Math.max(10, getLogListMetrics(logListFontSize).fontSize - 1),
    [logListFontSize],
  );

  const activeTab: EvtxRailTabId = RAIL_TABS.includes(railTab) ? railTab : "insights";
  const actionableCount = summary?.overview.actionableFindingCount ?? null;

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
          <Tab key={tab} id={evtxRailTabId(tab)} value={tab} aria-controls={EVTX_RAIL_PANEL_ID}>
            {labels[tab]}
          </Tab>
        ))}
      </TabList>
      <div
        role="tabpanel"
        id={EVTX_RAIL_PANEL_ID}
        aria-labelledby={evtxRailTabId(activeTab)}
        style={{
          flex: 1,
          minHeight: 0,
          overflowX: "hidden",
          overflowY: activeTab === "details" ? "hidden" : "auto",
          padding: activeTab === "details" ? 0 : "12px",
        }}
      >
        {activeTab === "details" ? (
          <EvtxDetailPane />
        ) : (
          <EventDiagnosisPanel summary={summary} records={records} />
        )}
      </div>
    </div>
  );
}

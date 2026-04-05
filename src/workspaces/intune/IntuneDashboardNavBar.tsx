import { useMemo } from "react";
import { tokens } from "@fluentui/react-components";
import { useIntuneStore } from "./intune-store";
import type {
  DownloadStat,
  IntuneEvent,
  IntuneEventType,
  IntuneStatus,
  IntuneSummary,
  IntuneTimeWindowPreset,
} from "./types";
import type { IntuneSortField, IntuneTimelineViewMode } from "./intune-store";
import { selectStyle, getFileName } from "./intune-dashboard-utils";

type TabId = "timeline" | "downloads" | "summary";

const TAB_LABELS: Record<TabId, string> = {
  timeline: "Timeline",
  downloads: "Downloads",
  summary: "Summary",
};

export function IntuneDashboardNavBar({
  filteredEventsByTime,
  filteredDownloadsByTime,
  filteredSummary,
  timeWindowLabel,
  isWindowFiltered,
}: {
  filteredEventsByTime: IntuneEvent[];
  filteredDownloadsByTime: DownloadStat[];
  filteredSummary: IntuneSummary;
  timeWindowLabel: string;
  isWindowFiltered: boolean;
}) {
  const summary = useIntuneStore((s) => s.summary);
  const isAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const timeWindow = useIntuneStore((s) => s.timeWindow);
  const activeTab = useIntuneStore((s) => s.activeTab);
  const setActiveTab = useIntuneStore((s) => s.setActiveTab);
  const timelineScope = useIntuneStore((s) => s.timelineScope);
  const clearTimelineFileScope = useIntuneStore((s) => s.clearTimelineFileScope);
  const setTimeWindow = useIntuneStore((s) => s.setTimeWindow);
  const filterEventType = useIntuneStore((s) => s.filterEventType);
  const filterStatus = useIntuneStore((s) => s.filterStatus);
  const setFilterEventType = useIntuneStore((s) => s.setFilterEventType);
  const setFilterStatus = useIntuneStore((s) => s.setFilterStatus);
  const timelineViewMode = useIntuneStore((s) => s.timelineViewMode);
  const setTimelineViewMode = useIntuneStore((s) => s.setTimelineViewMode);
  const sortField = useIntuneStore((s) => s.sortField);
  const sortDirection = useIntuneStore((s) => s.sortDirection);
  const setSortField = useIntuneStore((s) => s.setSortField);
  const toggleSortDirection = useIntuneStore((s) => s.toggleSortDirection);

  const availableTabs = useMemo(
    () => ({
      timeline: filteredEventsByTime.length > 0,
      downloads: filteredDownloadsByTime.length > 0,
      summary: summary != null,
    }),
    [filteredDownloadsByTime.length, filteredEventsByTime.length, summary]
  );

  const filteredEventCount = useMemo(() => {
    return filteredEventsByTime.filter((event) => {
      if (filterEventType !== "All" && event.eventType !== filterEventType) {
        return false;
      }
      if (filterStatus !== "All" && event.status !== filterStatus) {
        return false;
      }
      return true;
    }).length;
  }, [filteredEventsByTime, filterEventType, filterStatus]);

  const hasActiveFilters = filterEventType !== "All" || filterStatus !== "All";
  const timelineScopeFileName = timelineScope.filePath ? getFileName(timelineScope.filePath) : null;

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        padding: "0 12px",
        backgroundColor: tokens.colorNeutralBackground2,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        minHeight: "40px",
        flexShrink: 0,
      }}
    >
      <div style={{ display: "flex", gap: "2px", alignItems: "center", height: "100%" }}>
        {(Object.keys(TAB_LABELS) as TabId[]).map((tabId) => (
          <CanvasTabButton
            key={tabId}
            label={TAB_LABELS[tabId]}
            active={activeTab === tabId}
            disabled={isAnalyzing || !availableTabs[tabId]}
            count={tabId === "timeline" ? filteredEventsByTime.length : tabId === "downloads" ? filteredDownloadsByTime.length : summary ? 1 : 0}
            onClick={() => setActiveTab(tabId)}
          />
        ))}
      </div>

      {summary && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            marginLeft: "12px",
            flex: 1,
            overflow: "hidden",
          }}
        >
          <div style={{ width: "1px", height: "20px", backgroundColor: tokens.colorNeutralStroke2, marginRight: "12px" }} />
          <div
            style={{
              display: "flex",
              gap: "10px",
              flexWrap: "nowrap",
              overflowX: "auto",
              scrollbarWidth: "none",
              alignItems: "center",
            }}
          >
            <StrongBadge label="Total" value={filteredSummary.totalEvents} />
            <StrongBadge label="Success" value={filteredSummary.succeeded} color={tokens.colorPaletteGreenForeground1} />
            <StrongBadge label="Fail" value={filteredSummary.failed} color={tokens.colorPaletteRedForeground1} />
            <StrongBadge label="Prog" value={filteredSummary.inProgress} color={tokens.colorBrandForeground1} />
            <StrongBadge label="Win32" value={filteredSummary.win32Apps} />
            <StrongBadge label="WinGet" value={filteredSummary.wingetApps} />
            {filteredSummary.logTimeSpan && (
              <>
                <div style={{ width: "1px", height: "12px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 4px" }} />
                <span style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, fontWeight: 500 }}>
                  {filteredSummary.logTimeSpan}
                </span>
              </>
            )}
            {isWindowFiltered && (
              <>
                <div style={{ width: "1px", height: "12px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 4px" }} />
                <span style={{ fontSize: "11px", color: tokens.colorPaletteBlueForeground2, fontWeight: 700 }}>
                  {timeWindowLabel}
                </span>
              </>
            )}
          </div>
        </div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginLeft: "auto", paddingLeft: "12px" }}>
        <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground3, fontWeight: 600, textTransform: "uppercase" }}>Window:</span>
        <select
          value={timeWindow}
          onChange={(e) => setTimeWindow(e.target.value as IntuneTimeWindowPreset)}
          style={selectStyle}
          disabled={isAnalyzing}
        >
          <option value="all">All Activity</option>
          <option value="last-hour">Last Hour</option>
          <option value="last-6-hours">Last 6 Hours</option>
          <option value="last-day">Last Day</option>
          <option value="last-7-days">Last 7 Days</option>
        </select>
      </div>

      {activeTab === "timeline" && filteredEventsByTime.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginLeft: "auto", paddingLeft: "12px" }}>
          <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground3, fontWeight: 600, textTransform: "uppercase" }}>Filters:</span>
          <select
            value={filterEventType}
            onChange={(e) => setFilterEventType(e.target.value as IntuneEventType | "All")}
            style={selectStyle}
            disabled={isAnalyzing}
          >
            <option value="All">All Types</option>
            <option value="Win32App">Win32</option>
            <option value="WinGetApp">WinGet</option>
            <option value="PowerShellScript">Script</option>
            <option value="Remediation">Remediation</option>
            <option value="Esp">ESP</option>
            <option value="SyncSession">Sync</option>
            <option value="PolicyEvaluation">Policy</option>
            <option value="ContentDownload">Download</option>
            <option value="Other">Other</option>
          </select>
          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value as IntuneStatus | "All")}
            style={selectStyle}
            disabled={isAnalyzing}
          >
            <option value="All">All Statuses</option>
            <option value="Success">Success</option>
            <option value="Failed">Failed</option>
            <option value="InProgress">In Progress</option>
            <option value="Pending">Pending</option>
            <option value="Timeout">Timeout</option>
            <option value="Unknown">Unknown</option>
          </select>
          <button
            type="button"
            onClick={() => {
              setFilterEventType("All");
              setFilterStatus("All");
            }}
            disabled={!hasActiveFilters || isAnalyzing}
            style={{
              marginLeft: "2px",
              fontSize: "10px",
              padding: "2px 6px",
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              borderRadius: "3px",
              backgroundColor: hasActiveFilters ? tokens.colorNeutralCardBackground : tokens.colorNeutralBackground3,
              color: hasActiveFilters ? tokens.colorNeutralForeground1 : tokens.colorNeutralForeground4,
              cursor: hasActiveFilters && !isAnalyzing ? "pointer" : "not-allowed",
            }}
          >
            Reset
          </button>
          <span style={{ fontSize: "11px", color: tokens.colorNeutralForeground3, fontWeight: 500, marginLeft: "4px" }}>
            {filteredEventCount}/{filteredEventsByTime.length}
          </span>
          <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px" }} />
          <ViewModeToggle
            mode={timelineViewMode}
            onChange={setTimelineViewMode}
            disabled={isAnalyzing}
          />
          {timelineViewMode === "list" && (
            <>
          <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px" }} />
          <span style={{ fontSize: "10px", color: tokens.colorNeutralForeground3, fontWeight: 600, textTransform: "uppercase" }}>Sort:</span>
          <select
            value={sortField}
            onChange={(e) => setSortField(e.target.value as IntuneSortField)}
            style={selectStyle}
            disabled={isAnalyzing}
          >
            <option value="time">Time</option>
            <option value="name">Name</option>
            <option value="type">Type</option>
            <option value="status">Status</option>
            <option value="duration">Duration</option>
          </select>
          <button
            type="button"
            onClick={toggleSortDirection}
            disabled={isAnalyzing}
            title={sortDirection === "asc" ? "Ascending" : "Descending"}
            style={{
              fontSize: "12px",
              padding: "2px 6px",
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              borderRadius: "3px",
              backgroundColor: tokens.colorNeutralCardBackground,
              color: tokens.colorNeutralForeground1,
              cursor: isAnalyzing ? "not-allowed" : "pointer",
              lineHeight: 1,
            }}
          >
            {sortDirection === "asc" ? "▲" : "▼"}
          </button>
            </>
          )}
          {timelineScope.filePath && (
            <>
              <div style={{ width: "1px", height: "16px", backgroundColor: tokens.colorNeutralStroke2, margin: "0 2px" }} />
              <span
                title={timelineScope.filePath}
                style={{
                  maxWidth: "220px",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                  fontSize: "11px",
                  color: tokens.colorPaletteMarigoldForeground2,
                  backgroundColor: tokens.colorPaletteYellowBackground1,
                  border: `1px solid ${tokens.colorPaletteYellowBorder2}`,
                  borderRadius: "999px",
                  padding: "3px 8px",
                  fontWeight: 600,
                }}
              >
                Timeline scoped to {timelineScopeFileName}
              </span>
              <button
                type="button"
                onClick={() => clearTimelineFileScope()}
                disabled={isAnalyzing}
                style={{
                  fontSize: "10px",
                  padding: "2px 6px",
                  border: `1px solid ${tokens.colorNeutralStroke2}`,
                  borderRadius: "3px",
                  backgroundColor: tokens.colorNeutralCardBackground,
                  color: tokens.colorNeutralForeground1,
                  cursor: isAnalyzing ? "not-allowed" : "pointer",
                }}
              >
                Clear Scope
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function CanvasTabButton({
  label,
  active,
  disabled,
  count,
  onClick,
}: {
  label: string;
  active: boolean;
  disabled: boolean;
  count: number;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      style={{
        fontSize: "11px",
        padding: "6px 12px",
        border: "none",
        borderBottom: active ? `2px solid ${tokens.colorBrandForeground1}` : "2px solid transparent",
        backgroundColor: "transparent",
        color: disabled ? tokens.colorNeutralForeground4 : active ? tokens.colorPaletteBlueForeground2 : tokens.colorNeutralForeground3,
        fontWeight: active ? 600 : 500,
        cursor: disabled ? "not-allowed" : "pointer",
        height: "100%",
        display: "flex",
        alignItems: "center",
        gap: "6px",
        transition: "all 0.1s ease",
      }}
    >
      <span>{label}</span>
      <span style={{
        fontSize: "9px",
        backgroundColor: active ? tokens.colorPaletteBlueBackground2 : tokens.colorNeutralBackground3,
        color: active ? tokens.colorPaletteBlueForeground2 : tokens.colorNeutralForeground3,
        padding: "2px 6px",
        borderRadius: "99px",
        fontWeight: 700,
      }}>
        {count}
      </span>
    </button>
  );
}

function StrongBadge({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "baseline", gap: "4px" }}>
      <span style={{ color: tokens.colorNeutralForeground3, fontSize: "10px", fontWeight: 600, textTransform: "uppercase" }}>{label}</span>
      <span style={{ color: color || tokens.colorNeutralForeground1, fontSize: "12px", fontWeight: 700 }}>{value}</span>
    </div>
  );
}

function ViewModeToggle({
  mode,
  onChange,
  disabled,
}: {
  mode: IntuneTimelineViewMode;
  onChange: (mode: IntuneTimelineViewMode) => void;
  disabled: boolean;
}) {
  const buttonStyle = (active: boolean): React.CSSProperties => ({
    fontSize: "10px",
    padding: "2px 8px",
    border: `1px solid ${active ? tokens.colorBrandStroke1 : tokens.colorNeutralStroke2}`,
    backgroundColor: active ? tokens.colorBrandBackground2 : tokens.colorNeutralCardBackground,
    color: active ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground3,
    fontWeight: active ? 700 : 500,
    cursor: disabled ? "not-allowed" : "pointer",
    lineHeight: "18px",
  });

  return (
    <div style={{ display: "flex", alignItems: "center" }}>
      <button
        type="button"
        onClick={() => onChange("list")}
        disabled={disabled}
        style={{ ...buttonStyle(mode === "list"), borderRadius: "3px 0 0 3px", borderRight: "none" }}
      >
        List
      </button>
      <button
        type="button"
        onClick={() => onChange("activity")}
        disabled={disabled}
        style={{ ...buttonStyle(mode === "activity"), borderRadius: "0 3px 3px 0" }}
      >
        Activity
      </button>
    </div>
  );
}

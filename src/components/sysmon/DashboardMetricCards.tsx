import { tokens } from "@fluentui/react-components";
import type { SysmonSummary } from "../../types/sysmon";

interface DashboardMetricCardsProps {
  summary: SysmonSummary;
}

export function DashboardMetricCards({ summary }: DashboardMetricCardsProps) {
  const timeRange =
    summary.earliestTimestamp && summary.latestTimestamp
      ? `${fmtTs(summary.earliestTimestamp)} – ${fmtTs(summary.latestTimestamp)}`
      : summary.earliestTimestamp
        ? fmtTs(summary.earliestTimestamp)
        : "—";

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
        gap: "12px",
        marginBottom: "16px",
      }}
    >
      <MetricCard label="Total Events" value={summary.totalEvents.toLocaleString()} />
      <MetricCard label="Unique Processes" value={summary.uniqueProcesses.toLocaleString()} />
      <MetricCard label="Unique Computers" value={summary.uniqueComputers.toLocaleString()} />
      <MetricCard label="Time Range" value={timeRange} smallValue />
      {summary.parseErrors > 0 && (
        <MetricCard
          label="Parse Errors"
          value={summary.parseErrors.toLocaleString()}
          valueColor={tokens.colorPaletteRedForeground1}
        />
      )}
    </div>
  );
}

function fmtTs(ts: string): string {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return ts;
  }
}

function MetricCard({
  label,
  value,
  valueColor,
  smallValue,
}: {
  label: string;
  value: string;
  valueColor?: string;
  smallValue?: boolean;
}) {
  return (
    <div
      style={{
        padding: "12px 16px",
        backgroundColor: tokens.colorNeutralBackground3,
        borderRadius: "6px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div
        style={{
          fontSize: "11px",
          color: tokens.colorNeutralForeground3,
          marginBottom: "4px",
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: smallValue ? "13px" : "20px",
          fontWeight: 600,
          color: valueColor ?? tokens.colorNeutralForeground1,
          lineHeight: 1.2,
          wordBreak: "break-all",
        }}
      >
        {value}
      </div>
    </div>
  );
}

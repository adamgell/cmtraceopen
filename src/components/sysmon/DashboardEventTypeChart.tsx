import { tokens } from "@fluentui/react-components";
import { DonutChart } from "@fluentui/react-charts";
import type { SysmonSummary } from "../../types/sysmon";

interface DashboardEventTypeChartProps {
  summary: SysmonSummary;
}

// A palette of distinct colors for event types
const COLOR_PALETTE = [
  "#0078d4",
  "#107c10",
  "#ff8c00",
  "#d13438",
  "#881798",
  "#00b7c3",
  "#498205",
  "#c239b3",
  "#ff4343",
  "#0099bc",
  "#7a7574",
  "#4f6bed",
  "#038387",
  "#da3b01",
  "#8e562e",
];

export function DashboardEventTypeChart({ summary }: DashboardEventTypeChartProps) {
  const chartData = summary.eventTypeCounts.map((etc, i) => ({
    legend: etc.displayName,
    data: etc.count,
    color: COLOR_PALETTE[i % COLOR_PALETTE.length],
  }));

  return (
    <div
      style={{
        padding: "16px",
        backgroundColor: tokens.colorNeutralBackground1,
        borderRadius: "6px",
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <h4 style={{ margin: "0 0 12px 0", fontSize: "13px", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
        Event Type Distribution
      </h4>
      {chartData.length === 0 ? (
        <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
          No event type data available.
        </div>
      ) : (
        <DonutChart
          data={{ chartData }}
          innerRadius={55}
          valueInsideDonut={summary.totalEvents.toLocaleString()}
          hideLabels={false}
          height={280}
        />
      )}
    </div>
  );
}

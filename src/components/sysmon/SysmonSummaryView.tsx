import { tokens } from "@fluentui/react-components";
import { useSysmonStore } from "../../stores/sysmon-store";

export function SysmonSummaryView() {
  const summary = useSysmonStore((s) => s.summary);

  if (!summary) {
    return (
      <div style={{ padding: "24px", color: tokens.colorNeutralForeground3 }}>
        No summary available.
      </div>
    );
  }

  return (
    <div style={{ padding: "16px 24px", overflow: "auto", height: "100%" }}>
      <h3 style={{ margin: "0 0 16px 0", fontSize: "16px", fontWeight: 600 }}>
        Sysmon Analysis Summary
      </h3>

      {/* Key metrics */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))",
          gap: "12px",
          marginBottom: "24px",
        }}
      >
        <MetricCard label="Total Events" value={summary.totalEvents.toLocaleString()} />
        <MetricCard label="Unique Processes" value={summary.uniqueProcesses.toLocaleString()} />
        <MetricCard label="Unique Computers" value={summary.uniqueComputers.toLocaleString()} />
        <MetricCard label="Source Files" value={summary.sourceFiles.length.toString()} />
        {summary.parseErrors > 0 && (
          <MetricCard
            label="Parse Errors"
            value={summary.parseErrors.toLocaleString()}
            color={tokens.colorPaletteRedForeground1}
          />
        )}
      </div>

      {/* Time range */}
      {(summary.earliestTimestamp || summary.latestTimestamp) && (
        <div style={{ marginBottom: "24px" }}>
          <h4 style={{ margin: "0 0 8px 0", fontSize: "13px", fontWeight: 600 }}>Time Range</h4>
          <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground2 }}>
            {summary.earliestTimestamp && <div>Earliest: {summary.earliestTimestamp}</div>}
            {summary.latestTimestamp && <div>Latest: {summary.latestTimestamp}</div>}
          </div>
        </div>
      )}

      {/* Event type breakdown */}
      <div style={{ marginBottom: "24px" }}>
        <h4 style={{ margin: "0 0 8px 0", fontSize: "13px", fontWeight: 600 }}>
          Event Type Breakdown
        </h4>
        <table
          style={{
            width: "100%",
            maxWidth: "600px",
            borderCollapse: "collapse",
            fontSize: "12px",
          }}
        >
          <thead>
            <tr>
              <th style={thStyle}>Event ID</th>
              <th style={thStyle}>Type</th>
              <th style={{ ...thStyle, textAlign: "right" }}>Count</th>
              <th style={{ ...thStyle, textAlign: "right" }}>%</th>
            </tr>
          </thead>
          <tbody>
            {summary.eventTypeCounts.map((tc) => (
              <tr key={tc.eventId}>
                <td style={tdStyle}>{tc.eventId}</td>
                <td style={tdStyle}>{tc.displayName}</td>
                <td style={{ ...tdStyle, textAlign: "right" }}>{tc.count.toLocaleString()}</td>
                <td style={{ ...tdStyle, textAlign: "right" }}>
                  {summary.totalEvents > 0
                    ? ((tc.count / summary.totalEvents) * 100).toFixed(1)
                    : "0"}
                  %
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Source files */}
      {summary.sourceFiles.length > 0 && (
        <div>
          <h4 style={{ margin: "0 0 8px 0", fontSize: "13px", fontWeight: 600 }}>Source Files</h4>
          <ul style={{ margin: 0, paddingLeft: "20px", fontSize: "12px" }}>
            {summary.sourceFiles.map((f) => (
              <li key={f} style={{ marginBottom: "2px", color: tokens.colorNeutralForeground2 }}>
                {f}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function MetricCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color?: string;
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
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: "20px",
          fontWeight: 600,
          color: color || tokens.colorNeutralForeground1,
        }}
      >
        {value}
      </div>
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "6px 12px",
  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
  fontWeight: 600,
};

const tdStyle: React.CSSProperties = {
  padding: "4px 12px",
  borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
};

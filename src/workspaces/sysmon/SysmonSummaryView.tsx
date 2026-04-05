import { tokens } from "@fluentui/react-components";
import { useSysmonStore } from "./sysmon-store";

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

import { tokens, Badge } from "@fluentui/react-components";
import type { SecuritySummary } from "./types";

interface DashboardSecurityAlertsProps {
  securityEvents: SecuritySummary;
}

export function DashboardSecurityAlerts({ securityEvents }: DashboardSecurityAlertsProps) {
  const total = securityEvents.totalWarnings + securityEvents.totalErrors;

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
        Security Alerts
      </h4>

      {total === 0 ? (
        <div
          style={{
            fontSize: "12px",
            color: tokens.colorNeutralForeground3,
            padding: "8px 0",
          }}
        >
          No warning or error events detected.
        </div>
      ) : (
        <>
          {/* Summary badges */}
          <div style={{ display: "flex", gap: "12px", marginBottom: "16px", flexWrap: "wrap" }}>
            {securityEvents.totalErrors > 0 && (
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <Badge color="danger" size="medium">
                  {securityEvents.totalErrors.toLocaleString()}
                </Badge>
                <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground2 }}>
                  Error{securityEvents.totalErrors !== 1 ? "s" : ""}
                </span>
              </div>
            )}
            {securityEvents.totalWarnings > 0 && (
              <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <Badge color="warning" size="medium">
                  {securityEvents.totalWarnings.toLocaleString()}
                </Badge>
                <span style={{ fontSize: "12px", color: tokens.colorNeutralForeground2 }}>
                  Warning{securityEvents.totalWarnings !== 1 ? "s" : ""}
                </span>
              </div>
            )}
          </div>

          {/* Events by type table */}
          {securityEvents.eventsByType.length > 0 && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
              <thead>
                <tr>
                  <th style={thStyle}>Event Type</th>
                  <th style={{ ...thStyle, textAlign: "right" }}>Count</th>
                </tr>
              </thead>
              <tbody>
                {securityEvents.eventsByType.map((item) => (
                  <tr key={item.name}>
                    <td style={tdStyle}>{item.name}</td>
                    <td style={{ ...tdStyle, textAlign: "right" }}>{item.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}

const thStyle: React.CSSProperties = {
  textAlign: "left",
  padding: "4px 8px",
  borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
  fontWeight: 600,
  color: tokens.colorNeutralForeground2,
};

const tdStyle: React.CSSProperties = {
  padding: "4px 8px",
  borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
  color: tokens.colorNeutralForeground1,
};

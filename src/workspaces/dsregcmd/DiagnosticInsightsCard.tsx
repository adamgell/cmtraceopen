import { Badge, tokens } from "@fluentui/react-components";
import type { DsregcmdDiagnosticInsight } from "./types";
import { getSeverityColor } from "./dsregcmd-formatters";

export function IssueCard({ issue }: { issue: DsregcmdDiagnosticInsight }) {
  const colors = getSeverityColor(issue.severity);

  return (
    <article
      style={{
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        padding: "12px",
        borderRadius: "10px",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          flexWrap: "wrap",
        }}
      >
        <Badge
          appearance="outline"
          style={{
            fontSize: "10px",
            fontWeight: 700,
            border: `1px solid ${colors.border}`,
            color: colors.text,
            backgroundColor: tokens.colorNeutralCardBackground,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
          }}
        >
          {issue.severity}
        </Badge>
        <span
          style={{
            fontSize: "11px",
            color: tokens.colorNeutralForeground3,
            textTransform: "uppercase",
          }}
        >
          {issue.category}
        </span>
      </div>
      <div
        style={{
          marginTop: "8px",
          fontSize: "15px",
          fontWeight: 700,
          color: tokens.colorNeutralForeground1,
        }}
      >
        {issue.title}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "13px",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.5,
        }}
      >
        {issue.summary}
      </div>

      {issue.suggestedFixes.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            Suggested fixes
          </div>
          <ul
            style={{
              marginTop: "6px",
              paddingLeft: "18px",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {issue.suggestedFixes.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {issue.nextChecks.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            Next checks
          </div>
          <ul
            style={{
              marginTop: "6px",
              paddingLeft: "18px",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {issue.nextChecks.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}

      {issue.evidence.length > 0 && (
        <div style={{ marginTop: "10px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
            Evidence
          </div>
          <ul
            style={{
              marginTop: "6px",
              paddingLeft: "18px",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.5,
            }}
          >
            {issue.evidence.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </article>
  );
}

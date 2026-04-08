import { Badge, tokens } from "@fluentui/react-components";
import type { DiagnosticFinding, DiagnosticSeverity } from "./types";

function severityColors(severity: DiagnosticSeverity) {
  switch (severity) {
    case "error":
      return {
        background: tokens.colorPaletteRedBackground1,
        border: tokens.colorPaletteRedBorder2,
        badgeText: tokens.colorPaletteRedForeground1,
        badgeBorder: tokens.colorPaletteRedBorder2,
      };
    case "warning":
      return {
        background: tokens.colorPaletteYellowBackground1,
        border: tokens.colorPaletteYellowBorder2,
        badgeText: tokens.colorPaletteMarigoldForeground2,
        badgeBorder: tokens.colorPaletteYellowBorder2,
      };
    case "info":
    default:
      return {
        background: tokens.colorPaletteBlueBackground2,
        border: tokens.colorPaletteBlueBorderActive,
        badgeText: tokens.colorPaletteBlueForeground2,
        badgeBorder: tokens.colorPaletteBlueBorderActive,
      };
  }
}

function FindingCard({ finding }: { finding: DiagnosticFinding }) {
  const colors = severityColors(finding.severity);

  return (
    <article
      style={{
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        padding: "12px",
        borderRadius: "8px",
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
            border: `1px solid ${colors.badgeBorder}`,
            color: colors.badgeText,
            backgroundColor: tokens.colorNeutralCardBackground,
            textTransform: "uppercase",
            letterSpacing: "0.04em",
          }}
        >
          {finding.severity}
        </Badge>
        <span
          style={{
            fontSize: "10px",
            color: tokens.colorNeutralForeground3,
            fontFamily: "monospace",
          }}
        >
          {finding.ruleId}
        </span>
      </div>

      <div
        style={{
          marginTop: "8px",
          fontSize: "inherit",
          fontWeight: 700,
          color: tokens.colorNeutralForeground1,
          lineHeight: 1.3,
        }}
      >
        {finding.title}
      </div>

      <div
        style={{
          marginTop: "6px",
          fontSize: "13px",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.5,
        }}
      >
        {finding.detail}
      </div>

      {finding.recommendation && (
        <div
          style={{
            marginTop: "8px",
            fontSize: "12px",
            color: tokens.colorNeutralForeground2,
            lineHeight: 1.5,
            borderTop: `1px solid ${colors.border}`,
            paddingTop: "8px",
          }}
        >
          <span style={{ fontWeight: 600 }}>→ </span>
          {finding.recommendation}
        </div>
      )}
    </article>
  );
}

export interface DiagnosticsTabProps {
  findings: DiagnosticFinding[];
}

export function DiagnosticsTab({ findings }: DiagnosticsTabProps) {
  if (findings.length === 0) {
    return (
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          padding: "48px 24px",
          color: tokens.colorNeutralForeground3,
          fontSize: "13px",
          textAlign: "center",
        }}
      >
        No diagnostic findings were produced for this analysis.
      </div>
    );
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
      {findings.map((finding) => (
        <FindingCard key={finding.ruleId} finding={finding} />
      ))}
    </div>
  );
}

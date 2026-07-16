import type { ReactNode } from "react";
import { tokens } from "@fluentui/react-components";
import {
  ErrorCircleRegular,
  InfoRegular,
  LinkRegular,
  ShieldErrorRegular,
  WarningRegular,
} from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import type {
  EspDiagnosticFinding,
  EspFindingConfidence,
  EspFindingSeverity,
} from "./types";

const severityOrder: Record<EspFindingSeverity, number> = {
  blocker: 0,
  error: 1,
  warning: 2,
  info: 3,
};

const confidenceOrder: Record<EspFindingConfidence, number> = {
  high: 0,
  medium: 1,
  low: 2,
};

function label(value: string): string {
  return `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
}

function severityIcon(severity: EspFindingSeverity): ReactNode {
  switch (severity) {
    case "blocker":
      return <ShieldErrorRegular aria-hidden="true" />;
    case "error":
      return <ErrorCircleRegular aria-hidden="true" />;
    case "warning":
      return <WarningRegular aria-hidden="true" />;
    case "info":
      return <InfoRegular aria-hidden="true" />;
  }
}

function severityColor(severity: EspFindingSeverity): string {
  switch (severity) {
    case "blocker":
    case "error":
      return tokens.colorPaletteRedForeground1;
    case "warning":
      return tokens.colorPaletteYellowForeground2;
    case "info":
      return tokens.colorBrandForeground1;
  }
}

interface FindingProps {
  finding: EspDiagnosticFinding;
}

function Finding({ finding }: FindingProps) {
  return (
    <article
      style={{
        display: "grid",
        gridTemplateColumns: "3px minmax(0, 1fr)",
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground1,
      }}
    >
      <div
        aria-hidden="true"
        style={{ backgroundColor: severityColor(finding.severity) }}
      />
      <div style={{ minWidth: 0, padding: "9px 10px 10px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 8,
          }}
        >
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 5,
              color: severityColor(finding.severity),
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.04em",
              textTransform: "uppercase",
            }}
          >
            {severityIcon(finding.severity)}
            <span>
              {label(finding.severity)} · {label(finding.confidence)} confidence
            </span>
          </div>
          <code
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 9,
            }}
          >
            {finding.findingId}
          </code>
        </div>

        <h3
          style={{
            margin: "5px 0 0",
            fontFamily: LOG_UI_FONT_FAMILY,
            fontSize: 12,
            fontWeight: 650,
            lineHeight: "16px",
          }}
        >
          {finding.title}
        </h3>
        <p
          style={{
            margin: "3px 0 0",
            color: tokens.colorNeutralForeground2,
            fontSize: 10,
            lineHeight: "14px",
          }}
        >
          {finding.summary}
        </p>

        {finding.recommendedChecks.length > 0 ? (
          <div style={{ marginTop: 6 }}>
            <div
              style={{
                color: tokens.colorNeutralForeground3,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: "0.07em",
                textTransform: "uppercase",
              }}
            >
              Recommended read-only checks
            </div>
            <ol
              aria-label={`Recommended checks for ${finding.title}`}
              style={{
                margin: "3px 0 0",
                paddingLeft: 20,
                color: tokens.colorNeutralForeground2,
                fontSize: 10,
                lineHeight: "14px",
              }}
            >
              {finding.recommendedChecks.map((check, index) => (
                <li key={`${finding.findingId}:check:${index}`}>{check}</li>
              ))}
            </ol>
          </div>
        ) : null}

        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            gap: "3px 8px",
            marginTop: 6,
          }}
        >
          {finding.evidence.map((reference) => (
            <a
              key={reference.evidenceId}
              href={`#evidence-${reference.evidenceId}`}
              aria-label={`Open evidence ${reference.evidenceId}`}
              title={`${reference.sourceArtifactId} · ${reference.evidenceId}`}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 3,
                color: tokens.colorBrandForegroundLink,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 9,
                fontWeight: 650,
                textDecoration: "none",
              }}
            >
              <LinkRegular aria-hidden="true" /> {reference.sourceArtifactId}
            </a>
          ))}
          {finding.coverageGapIds.map((coverageGapId) => (
            <a
              key={coverageGapId}
              href={`#coverage-${coverageGapId}`}
              style={{
                color: tokens.colorPaletteYellowForeground2,
                fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                fontSize: 9,
                fontWeight: 650,
                textDecoration: "none",
              }}
            >
              Coverage gap · {coverageGapId}
            </a>
          ))}
        </div>
      </div>
    </article>
  );
}

interface ActionCenterProps {
  findings: EspDiagnosticFinding[];
}

export function ActionCenter({ findings }: ActionCenterProps) {
  const orderedFindings = [...findings].sort(
    (left, right) =>
      severityOrder[left.severity] - severityOrder[right.severity] ||
      confidenceOrder[left.confidence] - confidenceOrder[right.confidence] ||
      left.findingId.localeCompare(right.findingId),
  );
  const blockerCount = findings.filter(
    (finding) => finding.severity === "blocker" || finding.severity === "error",
  ).length;

  return (
    <section
      role="region"
      aria-labelledby="esp-action-center-heading"
      style={{
        minWidth: 0,
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        backgroundColor: tokens.colorNeutralBackground1,
        boxShadow: tokens.shadow2,
      }}
    >
      <div
        style={{
          minHeight: 36,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 8,
          padding: "0 10px",
          borderLeft: `3px solid ${
            blockerCount > 0
              ? tokens.colorPaletteRedBorderActive
              : tokens.colorBrandStroke1
          }`,
          backgroundColor: tokens.colorNeutralBackground3,
        }}
      >
        <div>
          <div
            style={{
              color: tokens.colorNeutralForeground3,
              fontFamily: LOG_MONOSPACE_FONT_FAMILY,
              fontSize: 9,
              fontWeight: 700,
              letterSpacing: "0.09em",
              lineHeight: "11px",
              textTransform: "uppercase",
            }}
          >
            Findings · analyst checks only
          </div>
          <h2
            id="esp-action-center-heading"
            style={{
              margin: 0,
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize: 13,
              fontWeight: 650,
              lineHeight: "17px",
            }}
          >
            Action center
          </h2>
        </div>
        <strong style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, fontSize: 10 }}>
          {blockerCount} primary · {findings.length} total
        </strong>
      </div>

      {orderedFindings.length === 0 ? (
        <div
          role="status"
          style={{
            minHeight: 52,
            display: "flex",
            alignItems: "center",
            gap: 7,
            padding: "0 11px",
            color: tokens.colorNeutralForeground2,
            fontSize: 11,
          }}
        >
          <InfoRegular aria-hidden="true" /> No actionable findings in the
          current evidence window.
        </div>
      ) : (
        orderedFindings.map((finding) => (
          <Finding key={finding.findingId} finding={finding} />
        ))
      )}
    </section>
  );
}

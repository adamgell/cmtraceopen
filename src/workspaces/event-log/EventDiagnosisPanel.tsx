import { Badge, Card, Text, tokens } from "@fluentui/react-components";
import type {
  DiagnosisCorrelationEdge,
  DiagnosisErrorToken,
  DiagnosisEvidence,
  DiagnosisFinding,
  DiagnosisOverview,
  DiagnosisSummary,
  EventDiagnosis,
} from "./types";

interface EventDiagnosisPanelProps {
  summary: DiagnosisSummary | null;
}
function evidenceLabel(evidence: DiagnosisEvidence): string {
  const kind = typeof evidence.kind === "string" ? evidence.kind : "source reference";
  const value = evidence.value;
  if (typeof value === "string") return `${kind}: ${value}`;
  if (value && typeof value === "object") {
    const details = Object.entries(value)
      .filter(([, field]) => typeof field === "string" || typeof field === "number")
      .map(([field, fieldValue]) => `${field}=${String(fieldValue)}`)
      .join(", ");
    return `${kind}: ${details || "source reference"}`;
  }
  return kind;
}

function evidenceText(evidence: DiagnosisEvidence[]): string {
  return evidence.map(evidenceLabel).join("; ");
}

function FindingRow({ finding }: { finding: DiagnosisFinding }) {
  return (
    <div
      style={{
        display: "grid",
        gap: tokens.spacingVerticalXXS,
        padding: `${tokens.spacingVerticalXS} ${tokens.spacingHorizontalS}`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div style={{ display: "flex", gap: tokens.spacingHorizontalXS, alignItems: "center" }}>
        <Badge appearance="tint">{finding.class}</Badge>
        <Badge appearance="tint">{finding.severity}</Badge>
        <Badge appearance="tint">{finding.confidence}</Badge>
        <Text weight="semibold">{finding.title}</Text>
      </div>
      <Text size={200}>{finding.summary}</Text>
      {finding.evidence.length > 0 && (
        <Text size={200}>Evidence: {evidenceText(finding.evidence)}</Text>
      )}
      {finding.recommendedChecks.length > 0 && (
        <Text size={200}>Next: {finding.recommendedChecks.join("; ")}</Text>
      )}
      {finding.coverageGaps.map((gap) => (
        <div key={gap.id} style={{ display: "grid", gap: tokens.spacingVerticalXXS }}>
          <Text size={200} style={{ color: tokens.colorPaletteDarkOrangeForeground1 }}>
            Coverage: {gap.source} ({gap.state}): {gap.detail}
          </Text>
          {gap.evidence.length > 0 && (
            <Text size={200}>Coverage evidence: {evidenceText(gap.evidence)}</Text>
          )}
        </div>
      ))}
    </div>
  );
}

function OverviewRow({ overview }: { overview: DiagnosisOverview }) {
  return (
    <div
      style={{
        display: "grid",
        gap: tokens.spacingVerticalXXS,
        padding: `${tokens.spacingVerticalXS} ${tokens.spacingHorizontalS}`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div style={{ display: "flex", gap: tokens.spacingHorizontalXS, alignItems: "center" }}>
        <Badge appearance="tint">{overview.outcome}</Badge>
        <Text weight="semibold">{overview.headline}</Text>
      </div>
      <Text size={200}>
        {overview.findingCount} findings, {overview.coverageGapCount} coverage gaps,{" "}
        {overview.evidenceCount} evidence items, {overview.correlationCount} correlations
      </Text>
    </div>
  );
}
function CorrelationRow({ edge }: { edge: DiagnosisCorrelationEdge }) {
  const target = edge.right ?? (edge.candidateIds.join(", ") || "no direct match");
  return (
    <div style={{ display: "grid", gap: tokens.spacingVerticalXXS }}>
      <Text size={200}>
        Correlation: {edge.status} ({edge.basis}) {edge.left} → {target}
      </Text>
      {edge.evidence.length > 0 && (
        <Text size={200}>
          Correlation evidence:{" "}
          {edge.evidence
            .map((item) => `${item.originId} ${item.field}=${item.value}`)
            .join("; ")}
        </Text>
      )}
    </div>
  );
}

function errorTokenLabel(token: DiagnosisErrorToken): string {
  const details = [
    token.hex && token.hex !== token.raw ? `(${token.hex})` : null,
    token.description ? `— ${token.description}` : null,
  ]
    .filter(Boolean)
    .join(" ");
  if (details) return `${token.raw} ${details}`;
  return `${token.raw} (unresolved)`;
}

function EventRow({ event }: { event: EventDiagnosis }) {
  const errors = event.errorTokens;
  return (
    <div style={{ display: "grid", gap: tokens.spacingVerticalXXS }}>
      <Text weight="semibold">{event.family}</Text>
      {event.evidence.length > 0 && (
        <Text size={200}>Event evidence: {evidenceText(event.evidence)}</Text>
      )}
      {event.findings.map((finding, index) => (
        <FindingRow key={`${finding.findingId}-${index}`} finding={finding} />
      ))}
      {errors.length > 0 && (
        <Text size={200}>Errors: {errors.map(errorTokenLabel).join(", ")}</Text>
      )}
    </div>
  );
}

export function EventDiagnosisPanel({ summary }: EventDiagnosisPanelProps) {
  if (!summary) return null;
  const actionableFindings = summary.findings.filter((finding) => finding.class !== "coverageGap");
  const notableEvents = summary.events.filter(
    (event) => event.errorTokens.length > 0 || event.findings.length > 0 || event.evidence.length > 0
  );
  const displayedEvents = notableEvents.slice(0, 200);
  return (
    <Card
      aria-label="Operational diagnosis"
      style={{
        marginBottom: tokens.spacingVerticalM,
        padding: tokens.spacingHorizontalM,
        display: "grid",
        gap: tokens.spacingVerticalS,
      }}
    >
      <div style={{ display: "flex", gap: tokens.spacingHorizontalS, alignItems: "center" }}>
        <Text size={400} weight="semibold">Operational diagnosis</Text>
        {actionableFindings.length > 0 && (
          <Badge appearance="tint">{actionableFindings.length} findings</Badge>
        )}
        {summary.coverageGaps.length > 0 && (
          <Badge appearance="tint">{summary.coverageGaps.length} coverage gaps</Badge>
        )}
      </div>
      <OverviewRow overview={summary.overview} />
      {summary.evidence.length > 0 && (
        <Text size={200}>Evidence: {evidenceText(summary.evidence)}</Text>
      )}
      {summary.correlations.map((edge, index) => (
        <CorrelationRow key={`${edge.left}-${edge.right ?? "none"}-${index}`} edge={edge} />
      ))}
      {actionableFindings.map((finding) => (
        <FindingRow key={finding.findingId} finding={finding} />
      ))}
      {summary.coverageGaps.map((gap) => (
        <div key={gap.id} style={{ display: "grid", gap: tokens.spacingVerticalXXS }}>
          <Text
            size={200}
            style={{ color: tokens.colorPaletteDarkOrangeForeground1 }}
          >
            Coverage: {gap.source} ({gap.state}): {gap.detail}
          </Text>
          {gap.evidence.length > 0 && (
            <Text size={200}>Coverage evidence: {evidenceText(gap.evidence)}</Text>
          )}
        </div>
      ))}
      {displayedEvents.map((event, index) => (
        <EventRow key={`${event.family}-${index}`} event={event} />
      ))}
      {notableEvents.length > displayedEvents.length && (
        <Text size={200}>
          Showing the first {displayedEvents.length} of {notableEvents.length} event details.
        </Text>
      )}
    </Card>
  );
}

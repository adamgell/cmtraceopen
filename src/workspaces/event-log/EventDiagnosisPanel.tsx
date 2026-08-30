import { useId } from "react";
import { Badge, Card, Text, tokens } from "@fluentui/react-components";
import type {
  DiagnosisCorrelationEdge,
  DiagnosisCoverageGap,
  DiagnosisErrorToken,
  DiagnosisEvidence,
  DiagnosisFinding,
  DiagnosisOverview,
  DiagnosisSummary,
  EventDiagnosis,
} from "./types";

const DETAIL_RENDER_CAP = 100;

interface EventDiagnosisPanelProps {
  summary: DiagnosisSummary | null;
}

interface GroupedCoverageGap {
  gap: DiagnosisCoverageGap;
  occurrences: number;
}

function actionableFindings(findings: DiagnosisFinding[]): DiagnosisFinding[] {
  return findings.filter((finding) => finding.class !== "coverageGap");
}

function groupCoverageGaps(gaps: DiagnosisCoverageGap[]): GroupedCoverageGap[] {
  const grouped = new Map<string, GroupedCoverageGap>();
  for (const gap of gaps) {
    const key = JSON.stringify([gap.source, gap.state, gap.detail]);
    const existing = grouped.get(key);
    if (existing) {
      existing.occurrences += 1;
    } else {
      grouped.set(key, { gap, occurrences: 1 });
    }
  }
  return [...grouped.values()];
}

function capSection<T>(
  items: T[],
  authoritativeCount = items.length,
): { items: T[]; omitted: number } {
  const visibleItems = items.slice(0, DETAIL_RENDER_CAP);
  return {
    items: visibleItems,
    omitted: Math.max(authoritativeCount - visibleItems.length, 0),
  };
}

function capCoverageSection(
  gaps: DiagnosisCoverageGap[],
  authoritativeCount: number,
): { items: GroupedCoverageGap[]; omitted: number } {
  const items = groupCoverageGaps(gaps).slice(0, DETAIL_RENDER_CAP);
  const representedCount = items.reduce(
    (count, item) => count + item.occurrences,
    0,
  );
  return {
    items,
    omitted: Math.max(authoritativeCount - representedCount, 0),
  };
}

function countLabel(
  count: number,
  singular: string,
  plural = `${singular}s`,
): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

function omittedLabel(count: number, singular: string): string {
  return `${countLabel(count, singular)} omitted.`;
}

function evidenceLabel(evidence: DiagnosisEvidence): string {
  const kind =
    typeof evidence.kind === "string" ? evidence.kind : "source reference";
  const value = evidence.value;
  if (typeof value === "string") return `${kind}: ${value}`;
  if (value && typeof value === "object") {
    const details = Object.entries(value)
      .filter(
        ([, field]) => typeof field === "string" || typeof field === "number",
      )
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
      <div
        style={{
          display: "flex",
          gap: tokens.spacingHorizontalXS,
          alignItems: "center",
        }}
      >
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
        <CoverageGapRow key={gap.id} gap={gap} occurrences={1} />
      ))}
    </div>
  );
}

function CoverageGapRow({
  gap,
  occurrences,
}: {
  gap: DiagnosisCoverageGap;
  occurrences: number;
}) {
  return (
    <div style={{ display: "grid", gap: tokens.spacingVerticalXXS }}>
      <Text
        size={200}
        style={{ color: tokens.colorPaletteDarkOrangeForeground1 }}
      >
        Coverage: {gap.source} ({gap.state}): {gap.detail} (
        {countLabel(occurrences, "occurrence")})
      </Text>
      {gap.evidence.length > 0 && (
        <Text size={200}>Coverage evidence: {evidenceText(gap.evidence)}</Text>
      )}
    </div>
  );
}

const OUTCOME_LABELS: Record<DiagnosisOverview["outcome"], string> = {
  confirmedFailure: "Issues detected",
  contradictoryEvidence: "Conflicting evidence",
  symptomsOnly: "Potential issues detected",
  insufficientEvidence: "No issues detected",
  noFindings: "No issues detected",
};

function OverviewRow({ overview }: { overview: DiagnosisOverview }) {
  return (
    <div
      style={{
        display: "grid",
        gap: tokens.spacingVerticalXXS,
        padding: `${tokens.spacingVerticalXS} ${tokens.spacingHorizontalS}`,
      }}
    >
      <div
        style={{
          display: "flex",
          gap: tokens.spacingHorizontalXS,
          alignItems: "center",
        }}
      >
        <Badge appearance="tint">{OUTCOME_LABELS[overview.outcome]}</Badge>
        <Text weight="semibold">{overview.headline}</Text>
      </div>
      <Text size={200}>
        {countLabel(overview.actionableFindingCount, "actionable finding")},{" "}
        {countLabel(overview.coverageGapCount, "source coverage gap")}
      </Text>
    </div>
  );
}

function CorrelationRow({ edge }: { edge: DiagnosisCorrelationEdge }) {
  const target =
    edge.right ?? (edge.candidateIds.join(", ") || "no direct match");
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
    token.found ? null : "(unresolved)",
  ]
    .filter(Boolean)
    .join(" ");
  if (details) return `${token.raw} ${details}`;
  return token.raw;
}

function EventRow({ event }: { event: EventDiagnosis }) {
  return (
    <div style={{ display: "grid", gap: tokens.spacingVerticalXXS }}>
      <Text weight="semibold">{event.family}</Text>
      {event.evidence.length > 0 && (
        <Text size={200}>Event evidence: {evidenceText(event.evidence)}</Text>
      )}
      <Text size={200}>
        Errors: {event.errorTokens.map(errorTokenLabel).join(", ")}
      </Text>
    </div>
  );
}

function OmittedRows({ count, singular }: { count: number; singular: string }) {
  return count > 0 ? (
    <Text size={200}>{omittedLabel(count, singular)}</Text>
  ) : null;
}

export function EventDiagnosisPanel({ summary }: EventDiagnosisPanelProps) {
  const detailsLabelId = useId();
  if (!summary) return null;

  const findings = capSection(
    actionableFindings(summary.findings),
    summary.overview.actionableFindingCount,
  );
  const coverageGaps = capCoverageSection(
    summary.coverageGaps,
    summary.overview.coverageGapCount,
  );
  const correlations = capSection(
    summary.correlations,
    summary.overview.correlationCount,
  );
  const events = capSection(
    summary.events.filter((event) => event.errorTokens.length > 0),
    summary.overview.errorTokenEventCount,
  );

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
      <div
        style={{
          display: "flex",
          gap: tokens.spacingHorizontalS,
          alignItems: "center",
        }}
      >
        <Text size={400} weight="semibold">
          Operational diagnosis
        </Text>
        {summary.overview.actionableFindingCount > 0 && (
          <Badge appearance="tint">
            {countLabel(
              summary.overview.actionableFindingCount,
              "actionable finding",
            )}
          </Badge>
        )}
        {summary.overview.coverageGapCount > 0 && (
          <Badge appearance="tint">
            {countLabel(
              summary.overview.coverageGapCount,
              "source coverage gap",
            )}
          </Badge>
        )}
      </div>
      <OverviewRow overview={summary.overview} />
      <details>
        <summary id={detailsLabelId} style={{ cursor: "pointer" }}>
          Show diagnosis details
        </summary>
        <div
          aria-labelledby={detailsLabelId}
          role="region"
          tabIndex={0}
          style={{
            display: "grid",
            gap: tokens.spacingVerticalS,
            marginTop: tokens.spacingVerticalS,
            maxHeight: "min(420px, 50vh)",
            overflowY: "auto",
          }}
        >
          {findings.items.length > 0 && (
            <Text weight="semibold">Actionable findings</Text>
          )}
          {findings.items.map((finding) => (
            <FindingRow key={finding.findingId} finding={finding} />
          ))}
          <OmittedRows count={findings.omitted} singular="actionable finding" />

          {coverageGaps.items.length > 0 && (
            <Text weight="semibold">Source coverage</Text>
          )}
          {coverageGaps.items.map(({ gap, occurrences }) => (
            <CoverageGapRow
              key={`${gap.source}-${gap.state}-${gap.detail}`}
              gap={gap}
              occurrences={occurrences}
            />
          ))}
          <OmittedRows count={coverageGaps.omitted} singular="coverage gap" />

          {correlations.items.length > 0 && (
            <Text weight="semibold">Correlations</Text>
          )}
          {correlations.items.map((edge, index) => (
            <CorrelationRow
              key={`${edge.left}-${edge.right ?? "none"}-${index}`}
              edge={edge}
            />
          ))}
          <OmittedRows count={correlations.omitted} singular="correlation" />

          {events.items.length > 0 && (
            <Text weight="semibold">Error-token event details</Text>
          )}
          {events.items.map((event, index) => (
            <EventRow key={`${event.family}-${index}`} event={event} />
          ))}
          <OmittedRows
            count={events.omitted}
            singular="error-token event detail"
          />
        </div>
      </details>
    </Card>
  );
}

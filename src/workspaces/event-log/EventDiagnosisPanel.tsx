/**
 * The Insights tab of the Event Logs rail (spec section 8.13).
 *
 * Every piece of finding text shown here comes from the diagnosis summary the engine produced.
 * The panel only arranges it: it never writes a finding, a verdict or a recommendation of its own
 * (soul.md: evidence first). The counts come from `overview`, which is authoritative; the arrays
 * are bounded previews, so a preview is never presented as a total.
 *
 * Not built yet: the "Filter to {n} events" link and the Top event IDs click action need the chip
 * row of Phase 5, the coverage note with its Elevate action is Phase 4b, and the "nearby, not
 * linked" and unplaced lines of the correlation summary belong to the correlation view phases.
 */
import { useId, useMemo, useState, type ReactNode } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useEvtxVisualTokens, type EvtxVisualTokens } from "./evtx-visual-tokens";
import type {
  DiagnosisCorrelationEdge,
  DiagnosisCoverageGap,
  DiagnosisErrorToken,
  DiagnosisEvidence,
  DiagnosisFinding,
  DiagnosisFindingConfidence,
  DiagnosisFindingSeverity,
  DiagnosisOverview,
  DiagnosisSummary,
  EventDiagnosis,
  EvtxLevel,
  EvtxRecord,
} from "./types";

export const DETAIL_RENDER_CAP = 100;
const EVIDENCE_PREVIEW_COUNT = 3;
const TOP_EVENT_ID_COUNT = 7;
/** A rare level keeps a visible sliver of the level-mix bar. */
const MIN_LEVEL_SEGMENT_SHARE = 0.006;

const SEVERITY_RANK: Record<DiagnosisFindingSeverity, number> = {
  critical: 3,
  error: 2,
  warning: 1,
  info: 0,
};
const CONFIDENCE_RANK: Record<DiagnosisFindingConfidence, number> = {
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};
/** Most severe first, the order of the level-mix bar and its legend. */
const LEVEL_ORDER: readonly EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

interface EventDiagnosisPanelProps {
  summary: DiagnosisSummary | null;
  /**
   * The records the summary was built from (the visible set). Feeds the level mix and the top
   * event IDs; without it those two cards are left out.
   */
  records?: readonly EvtxRecord[];
}

interface GroupedCoverageGap {
  gap: DiagnosisCoverageGap;
  occurrences: number;
}

/** Actionable means every class except `coverageGap`, matching `actionableFindingCount`. */
function actionableFindings(findings: DiagnosisFinding[]): DiagnosisFinding[] {
  return findings.filter((finding) => finding.class !== "coverageGap");
}

/** Severity first, then confidence, most significant first. Stable for equal pairs. */
export function sortFindings(findings: DiagnosisFinding[]): DiagnosisFinding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence],
  );
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
  if (evidence.kind === "event") {
    const { eventId, channel, provider, recordId, recordIdText } = evidence.value;
    return `${eventId} · ${channel ?? provider} · record ${recordIdText ?? recordId}`;
  }
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

interface RailSizes {
  /** Base size: the user's log list font size. */
  f: number;
  small: number;
  caption: number;
}

function useRailSizes(): RailSizes {
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  return useMemo(() => {
    const f = getLogListMetrics(logListFontSize).fontSize;
    return { f, small: Math.max(10, f - 2), caption: Math.max(10, f - 3) };
  }, [logListFontSize]);
}

function CoverageGapRow({
  gap,
  occurrences,
  sizes,
}: {
  gap: DiagnosisCoverageGap;
  occurrences: number;
  sizes: RailSizes;
}) {
  return (
    <div style={{ display: "grid", gap: "2px", fontSize: `${sizes.small}px` }}>
      <span style={{ color: tokens.colorNeutralForeground2 }}>
        Coverage: {gap.source} ({gap.state}): {gap.detail} (
        {countLabel(occurrences, "occurrence")})
      </span>
      {gap.evidence.length > 0 && (
        <span style={{ color: tokens.colorNeutralForeground3 }}>
          Coverage evidence: {evidenceText(gap.evidence)}
        </span>
      )}
    </div>
  );
}

function FindingCard({
  finding,
  sizes,
  visuals,
}: {
  finding: DiagnosisFinding;
  sizes: RailSizes;
  visuals: EvtxVisualTokens;
}) {
  const [checksExpanded, setChecksExpanded] = useState(false);
  const level = visuals.findingSeverityVisual(finding.severity);
  const shownEvidence = finding.evidence.slice(0, EVIDENCE_PREVIEW_COUNT);
  const moreEvidence = finding.evidence.length - shownEvidence.length;
  const [firstCheck, ...otherChecks] = finding.recommendedChecks;
  return (
    <article
      aria-label={finding.title}
      data-finding-id={finding.findingId}
      style={{
        display: "grid",
        gap: "6px",
        padding: "10px 12px",
        borderRadius: "6px",
        backgroundColor: tokens.colorNeutralBackground1,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderTop: `3px solid ${level.barColor}`,
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "baseline",
          gap: "8px",
        }}
      >
        <span
          style={{
            fontSize: `${sizes.caption}px`,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: level.textColor,
          }}
        >
          {finding.severity}
        </span>
        <span
          style={{
            fontSize: `${sizes.caption}px`,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            color: tokens.colorNeutralForeground3,
          }}
        >
          {finding.confidence} confidence
        </span>
      </div>
      <div
        style={{
          fontSize: `${sizes.f}px`,
          fontWeight: 600,
          color: tokens.colorNeutralForeground1,
        }}
      >
        {finding.title}
      </div>
      <div
        style={{
          fontSize: `${sizes.small}px`,
          lineHeight: 1.5,
          color: tokens.colorNeutralForeground2,
        }}
      >
        {finding.summary}
      </div>
      {shownEvidence.length > 0 && (
        <div
          style={{
            display: "grid",
            gap: "2px",
            padding: "6px 8px",
            borderRadius: "4px",
            backgroundColor: tokens.colorNeutralBackground3,
            fontFamily: LOG_MONOSPACE_FONT_FAMILY,
            fontSize: `${sizes.small}px`,
            color: tokens.colorNeutralForeground2,
            wordBreak: "break-word",
          }}
        >
          {shownEvidence.map((item, index) => (
            <div key={index}>{evidenceLabel(item)}</div>
          ))}
          {moreEvidence > 0 && (
            <div style={{ color: tokens.colorNeutralForeground3 }}>
              +{moreEvidence} more
            </div>
          )}
        </div>
      )}
      {firstCheck !== undefined && (
        <div
          style={{
            display: "grid",
            gap: "2px",
            fontSize: `${sizes.small}px`,
            color: tokens.colorNeutralForeground2,
          }}
        >
          <div>Next: {firstCheck}</div>
          {checksExpanded &&
            otherChecks.map((check, index) => <div key={index}>Next: {check}</div>)}
          {otherChecks.length > 0 && (
            <button
              type="button"
              aria-expanded={checksExpanded}
              onClick={() => setChecksExpanded((value) => !value)}
              style={{
                justifySelf: "start",
                padding: 0,
                border: "none",
                background: "none",
                cursor: "pointer",
                font: "inherit",
                color: tokens.colorBrandForeground1,
              }}
            >
              {checksExpanded
                ? "Show fewer checks"
                : `+${otherChecks.length} more ${otherChecks.length === 1 ? "check" : "checks"}`}
            </button>
          )}
        </div>
      )}
      {finding.coverageGaps.map((gap) => (
        <CoverageGapRow key={gap.id} gap={gap} occurrences={1} sizes={sizes} />
      ))}
    </article>
  );
}

// Every outcome needs its own label. `insufficientEvidence` is a coverage gap,
// not a clean result: reporting it as "No issues detected" presents an incomplete
// conclusion as health, which the evidence contract forbids.
export const OUTCOME_LABELS: Record<DiagnosisOverview["outcome"], string> = {
  confirmedFailure: "Issues detected",
  contradictoryEvidence: "Conflicting evidence",
  symptomsOnly: "Potential issues detected",
  insufficientEvidence: "Insufficient evidence",
  noFindings: "No issues found",
};

function OverviewBlock({
  overview,
  scopeCount,
  sizes,
}: {
  overview: DiagnosisOverview;
  scopeCount: number | null;
  sizes: RailSizes;
}) {
  return (
    <div style={{ display: "grid", gap: "4px" }}>
      <div
        style={{
          fontSize: `${sizes.caption}px`,
          fontWeight: 700,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: tokens.colorNeutralForeground3,
        }}
      >
        {OUTCOME_LABELS[overview.outcome]}
      </div>
      <div
        style={{
          fontSize: `${sizes.f}px`,
          fontWeight: 600,
          color: tokens.colorNeutralForeground1,
        }}
      >
        {overview.headline}
      </div>
      <div
        style={{ fontSize: `${sizes.small}px`, color: tokens.colorNeutralForeground3 }}
      >
        {countLabel(overview.actionableFindingCount, "actionable finding")},{" "}
        {countLabel(overview.coverageGapCount, "source coverage gap")}
      </div>
      {scopeCount !== null && (
        <div
          style={{ fontSize: `${sizes.caption}px`, color: tokens.colorNeutralForeground3 }}
        >
          Scoped to {scopeCount} visible {scopeCount === 1 ? "event" : "events"}
        </div>
      )}
    </div>
  );
}

function RailCard({
  title,
  caption,
  sizes,
  children,
}: {
  title: string;
  caption?: string;
  sizes: RailSizes;
  children: ReactNode;
}) {
  return (
    <section
      aria-label={title}
      style={{
        display: "grid",
        gap: "8px",
        padding: "10px 12px",
        borderRadius: "6px",
        backgroundColor: tokens.colorNeutralBackground1,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", gap: "8px" }}>
        <span
          style={{
            fontSize: `${sizes.caption}px`,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: tokens.colorNeutralForeground3,
          }}
        >
          {title}
        </span>
        {caption && (
          <span
            style={{ fontSize: `${sizes.caption}px`, color: tokens.colorNeutralForeground3 }}
          >
            {caption}
          </span>
        )}
      </div>
      {children}
    </section>
  );
}

interface LevelMixEntry {
  level: EvtxLevel;
  count: number;
}

interface TopEventId {
  eventId: number;
  count: number;
  /** The level most of this ID's records carry; ties go to the more severe level. */
  level: EvtxLevel;
}

/** One pass over the records for both the level mix and the top event IDs. */
export function summarizeRecords(records: readonly EvtxRecord[]): {
  levelMix: LevelMixEntry[];
  topEventIds: TopEventId[];
} {
  const levelCounts = new Map<EvtxLevel, number>();
  const perId = new Map<number, Map<EvtxLevel, number>>();
  for (const record of records) {
    levelCounts.set(record.level, (levelCounts.get(record.level) ?? 0) + 1);
    let byLevel = perId.get(record.eventId);
    if (!byLevel) {
      byLevel = new Map();
      perId.set(record.eventId, byLevel);
    }
    byLevel.set(record.level, (byLevel.get(record.level) ?? 0) + 1);
  }
  const levelMix = LEVEL_ORDER.flatMap((level) => {
    const count = levelCounts.get(level) ?? 0;
    return count > 0 ? [{ level, count }] : [];
  });
  const topEventIds = [...perId.entries()]
    .map(([eventId, byLevel]) => {
      let count = 0;
      let level: EvtxLevel = "Information";
      let best = -1;
      for (const candidate of LEVEL_ORDER) {
        const n = byLevel.get(candidate) ?? 0;
        count += n;
        if (n > best && n > 0) {
          best = n;
          level = candidate;
        }
      }
      return { eventId, count, level };
    })
    .sort((a, b) => b.count - a.count || a.eventId - b.eventId)
    .slice(0, TOP_EVENT_ID_COUNT);
  return { levelMix, topEventIds };
}

function LevelMixCard({
  levelMix,
  total,
  sizes,
  visuals,
}: {
  levelMix: LevelMixEntry[];
  total: number;
  sizes: RailSizes;
  visuals: EvtxVisualTokens;
}) {
  return (
    <RailCard title="Level mix" sizes={sizes}>
      <div
        role="img"
        aria-label={levelMix.map((entry) => `${entry.level} ${entry.count}`).join(", ")}
        style={{ display: "flex", gap: "2px", height: "12px" }}
      >
        {levelMix.map((entry) => (
          <div
            key={entry.level}
            data-level-segment={entry.level}
            style={{
              flex: Math.max(entry.count / total, MIN_LEVEL_SEGMENT_SHARE),
              borderRadius: "3px",
              backgroundColor: visuals.levels[entry.level].barColor,
            }}
          />
        ))}
      </div>
      <ul
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: "4px 12px",
          margin: 0,
          padding: 0,
          listStyle: "none",
          fontSize: `${sizes.caption}px`,
          color: tokens.colorNeutralForeground2,
        }}
      >
        {levelMix.map((entry) => (
          <li key={entry.level}>
            {entry.level} {entry.count}
          </li>
        ))}
      </ul>
    </RailCard>
  );
}

function TopEventIdsCard({
  topEventIds,
  sizes,
  visuals,
}: {
  topEventIds: TopEventId[];
  sizes: RailSizes;
  visuals: EvtxVisualTokens;
}) {
  const max = topEventIds[0]?.count ?? 1;
  return (
    <RailCard title="Top event IDs" sizes={sizes}>
      <ul style={{ display: "grid", gap: "4px", margin: 0, padding: 0, listStyle: "none" }}>
        {topEventIds.map((entry) => (
          <li
            key={entry.eventId}
            data-event-id={entry.eventId}
            style={{
              display: "grid",
              gridTemplateColumns: "40px 1fr 30px",
              alignItems: "center",
              gap: "8px",
              fontSize: `${sizes.small}px`,
            }}
          >
            <span
              style={{
                fontFamily: tokens.fontFamilyNumeric,
                fontWeight: 700,
                color: tokens.colorNeutralForeground1,
              }}
            >
              {entry.eventId}
            </span>
            <span
              aria-hidden="true"
              style={{
                height: "10px",
                width: `${Math.max((entry.count / max) * 100, 2)}%`,
                borderRadius: "2px",
                backgroundColor: visuals.levels[entry.level].barColor,
              }}
            />
            <span
              style={{
                fontFamily: tokens.fontFamilyNumeric,
                textAlign: "right",
                color: tokens.colorNeutralForeground2,
              }}
            >
              {entry.count}
            </span>
          </li>
        ))}
      </ul>
    </RailCard>
  );
}

function CorrelationSummaryCard({
  summary,
  sizes,
}: {
  summary: DiagnosisSummary;
  sizes: RailSizes;
}) {
  const total = summary.overview.correlationCount;
  const preview = summary.correlations;
  const previewComplete = preview.length >= total;
  const byStatus = (status: DiagnosisCorrelationEdge["status"]) =>
    preview.filter((edge) => edge.status === status).length;
  return (
    <RailCard title="Correlations" sizes={sizes}>
      <div style={{ fontSize: `${sizes.small}px`, color: tokens.colorNeutralForeground2 }}>
        {countLabel(total, "correlation")}
      </div>
      {preview.length > 0 && (
        <div style={{ fontSize: `${sizes.small}px`, color: tokens.colorNeutralForeground2 }}>
          {byStatus("exact")} exact {"·"} {byStatus("candidate")} candidate {"·"}{" "}
          {byStatus("ambiguous")} ambiguous
          {!previewComplete && (
            <span style={{ color: tokens.colorNeutralForeground3 }}>
              {` (first ${preview.length} of ${total})`}
            </span>
          )}
        </div>
      )}
    </RailCard>
  );
}

function CorrelationRow({
  edge,
  sizes,
}: {
  edge: DiagnosisCorrelationEdge;
  sizes: RailSizes;
}) {
  const target =
    edge.right ?? (edge.candidateIds.join(", ") || "no direct match");
  return (
    <div style={{ display: "grid", gap: "2px", fontSize: `${sizes.small}px` }}>
      <span>
        Correlation: {edge.status} ({edge.basis}) {edge.left} {"→"} {target}
      </span>
      {edge.evidence.length > 0 && (
        <span style={{ color: tokens.colorNeutralForeground3 }}>
          Correlation evidence:{" "}
          {edge.evidence
            .map((item) => `${item.originId} ${item.field}=${item.value}`)
            .join("; ")}
        </span>
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

function EventRow({ event, sizes }: { event: EventDiagnosis; sizes: RailSizes }) {
  return (
    <div style={{ display: "grid", gap: "2px", fontSize: `${sizes.small}px` }}>
      <span style={{ fontWeight: 600 }}>{event.family}</span>
      {event.evidence.length > 0 && (
        <span>Event evidence: {evidenceText(event.evidence)}</span>
      )}
      <span>Errors: {event.errorTokens.map(errorTokenLabel).join(", ")}</span>
    </div>
  );
}

function OmittedRows({
  count,
  singular,
  sizes,
}: {
  count: number;
  singular: string;
  sizes: RailSizes;
}) {
  return count > 0 ? (
    <span style={{ fontSize: `${sizes.small}px`, color: tokens.colorNeutralForeground3 }}>
      {omittedLabel(count, singular)}
    </span>
  ) : null;
}

/** A collapsed-by-default native disclosure whose body is a bounded, focusable scroll region. */
function Disclosure({
  label,
  sizes,
  children,
}: {
  label: string;
  sizes: RailSizes;
  children: ReactNode;
}) {
  const labelId = useId();
  return (
    <details
      style={{
        padding: "8px 12px",
        borderRadius: "6px",
        backgroundColor: tokens.colorNeutralBackground1,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <summary
        id={labelId}
        style={{ cursor: "pointer", fontSize: `${sizes.small}px`, fontWeight: 600 }}
      >
        {label}
      </summary>
      <div
        aria-labelledby={labelId}
        role="region"
        tabIndex={0}
        style={{
          display: "grid",
          gap: "8px",
          marginTop: "8px",
          maxHeight: "min(420px, 50vh)",
          overflowY: "auto",
        }}
      >
        {children}
      </div>
    </details>
  );
}

export function EventDiagnosisPanel({ summary, records }: EventDiagnosisPanelProps) {
  const sizes = useRailSizes();
  const visuals = useEvtxVisualTokens();
  const recordSummary = useMemo(
    () => (records && records.length > 0 ? summarizeRecords(records) : null),
    [records],
  );
  if (!summary) {
    return (
      <div
        role="status"
        style={{ fontSize: `${sizes.small}px`, color: tokens.colorNeutralForeground3 }}
      >
        No diagnosis is available yet.
      </div>
    );
  }

  const findings = capSection(
    sortFindings(actionableFindings(summary.findings)),
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
  const hasDetails = correlations.items.length > 0 || events.items.length > 0;

  return (
    <section
      aria-label="Operational diagnosis"
      style={{ display: "grid", gap: "12px", fontSize: `${sizes.f}px` }}
    >
      <OverviewBlock
        overview={summary.overview}
        scopeCount={records ? records.length : null}
        sizes={sizes}
      />

      {summary.overview.actionableFindingCount === 0 ? (
        <div style={{ fontSize: `${sizes.small}px`, color: tokens.colorNeutralForeground2 }}>
          No actionable findings.
        </div>
      ) : (
        <>
          {findings.items.map((finding) => (
            <FindingCard
              key={finding.findingId}
              finding={finding}
              sizes={sizes}
              visuals={visuals}
            />
          ))}
          <OmittedRows
            count={findings.omitted}
            singular="actionable finding"
            sizes={sizes}
          />
        </>
      )}

      {summary.overview.coverageGapCount > 0 && (
        <Disclosure
          label={`Coverage gaps (${summary.overview.coverageGapCount})`}
          sizes={sizes}
        >
          {coverageGaps.items.map(({ gap, occurrences }) => (
            <CoverageGapRow
              key={`${gap.source}-${gap.state}-${gap.detail}`}
              gap={gap}
              occurrences={occurrences}
              sizes={sizes}
            />
          ))}
          <OmittedRows count={coverageGaps.omitted} singular="coverage gap" sizes={sizes} />
        </Disclosure>
      )}

      {recordSummary && recordSummary.levelMix.length > 0 && records && (
        <LevelMixCard
          levelMix={recordSummary.levelMix}
          total={records.length}
          sizes={sizes}
          visuals={visuals}
        />
      )}
      {recordSummary && recordSummary.topEventIds.length > 0 && (
        <TopEventIdsCard
          topEventIds={recordSummary.topEventIds}
          sizes={sizes}
          visuals={visuals}
        />
      )}

      {(summary.overview.correlationCount > 0 || summary.correlations.length > 0) && (
        <CorrelationSummaryCard summary={summary} sizes={sizes} />
      )}

      {(hasDetails || correlations.omitted > 0 || events.omitted > 0) && (
        <Disclosure label="Show diagnosis details" sizes={sizes}>
          {correlations.items.map((edge, index) => (
            <CorrelationRow
              key={`${edge.left}-${edge.right ?? "none"}-${index}`}
              edge={edge}
              sizes={sizes}
            />
          ))}
          <OmittedRows count={correlations.omitted} singular="correlation" sizes={sizes} />
          {events.items.map((event, index) => (
            <EventRow key={`${event.family}-${index}`} event={event} sizes={sizes} />
          ))}
          <OmittedRows
            count={events.omitted}
            singular="error-token event detail"
            sizes={sizes}
          />
        </Disclosure>
      )}
    </section>
  );
}

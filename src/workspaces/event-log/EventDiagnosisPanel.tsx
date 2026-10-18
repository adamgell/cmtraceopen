/**
 * The Insights tab of the Event Logs rail (spec section 8.13).
 *
 * Every piece of finding text shown here comes from the diagnosis summary the engine produced.
 * The panel only arranges it: it never writes a finding, a verdict or a recommendation of its own
 * (soul.md: evidence first). The counts come from `overview`, which is authoritative; the arrays
 * are bounded previews, so a preview is never presented as a total.
 *
 * The two actions that narrow the view are handlers the caller supplies, so the panel itself reads
 * no store: "Filter to {n} events" on a finding (`onFilterToFinding`, which receives the loaded
 * records the finding's event evidence names and what could not be resolved), and the Top event IDs
 * click (`onFilterToEventId`). Without a handler there is no link and no button.
 *
 * The Correlations card reads the workspace's shared edges-only correlation model
 * (`useEvtxCorrelationData().counts`), never `summary.correlations`: it needs no timeline scan, and
 * an unknown count reads "unknown", not 0. Its links open the Correlation view, and the Not placed
 * list within it ("Review unplaced lines"). The unplaced line reads `counts.unplacedList`, the newest
 * session's, from the first reply: its count is that reply's own, so a partial list says the count
 * and not the preview's length. No other part of the panel shows a correlation row or count either
 * (#838 ruling 1): the diagnosis details list error-token events only, and
 * evtx-diagnosis-correlation-source.test.ts keeps it so.
 *
 * Not drawn here, with the reason:
 * - "{n} nearby, not linked" (spec 8.13 item 6): nothing produces nearby entries in this version
 *   (decision A on issue 838), so there is nothing to count, and the card never says "0 nearby": that
 *   would claim an absence nobody looked for. The Chains tab keeps the typed seam and draws the group
 *   when something feeds it.
 * - The coverage note with its Elevate action: Phase 4b.
 */
import { memo, useMemo, useState, type CSSProperties } from "react";
import {
  createFocusOutlineStyle,
  Link,
  makeStyles,
  tokens,
} from "@fluentui/react-components";
import { ArrowRight12Regular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useEvtxVisualTokens, type EvtxVisualTokens } from "./evtx-visual-tokens";
import { Disclosure, RailCard, useRailSizes, type RailSizes } from "./EvtxRailParts";
import { useRailTextColors } from "./evtx-rail-text";
import { correlationChainCount } from "./evtx-correlation-chains";
import { edgeInputNotice } from "./evtx-correlation-copy";
import { openChainInCorrelationView, openUnplacedInCorrelationView } from "./evtx-correlation-actions";
import { describeUnplaced, unplacedCardLine } from "./evtx-unplaced";
import { useEvtxCorrelationData } from "./useEvtxCorrelation";
import {
  buildEvidenceIndex,
  describeScopeCounts,
  eventEvidenceLabel,
  evidenceSpansSources,
  formatCount,
  scopeForFinding,
  summarizeRecords,
  summaryIsBounded,
  type EvidenceIndex,
  type FindingScope,
  type LevelMixEntry,
  type TopEventId,
} from "./evtx-insights-data";
import type {
  DiagnosisCoverageGap,
  DiagnosisErrorToken,
  DiagnosisEvidence,
  DiagnosisFinding,
  DiagnosisFindingClass,
  DiagnosisFindingConfidence,
  DiagnosisFindingSeverity,
  DiagnosisOverview,
  DiagnosisSummary,
  EventDiagnosis,
  EvtxRecord,
} from "./types";

export const DETAIL_RENDER_CAP = 100;
const EVIDENCE_PREVIEW_COUNT = 3;
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
/** Labels for the finding class, mapped from the engine's enum; never invented text. */
const CLASS_LABELS: Record<DiagnosisFindingClass, string> = {
  confirmedFailure: "Confirmed failure",
  likelyContributor: "Likely contributor",
  symptom: "Symptom",
  recovered: "Recovered",
  contradictoryEvidence: "Contradictory evidence",
  coverageGap: "Coverage gap",
  unknown: "Unknown",
};

interface EventDiagnosisPanelProps {
  summary: DiagnosisSummary | null;
  /**
   * The records the summary was built from (the visible set). Feeds the level mix and the top
   * event IDs; without it those two cards are left out.
   */
  records?: readonly EvtxRecord[];
  /** The diagnosis is being rebuilt; `summary` is then the previous build, shown as such. */
  updating?: boolean;
  /** Why the last build failed, when it did. */
  error?: string | null;
  /**
   * How many visible events the shown summary was built from. While a rebuild is pending this is
   * the previous build's count, so the scope line never pairs a new count with old numbers.
   * Defaults to `records.length`.
   */
  scopeCount?: number | null;
  /**
   * How many text-log entries the diagnosis session was given. Text logs are never narrowed by the
   * event criteria, so once the events ARE narrowed (see `loadedCount`) the scope line says so.
   */
  textLogCount?: number;
  /**
   * How many events were loaded when the shown summary was built. The scope line says text logs are
   * not scoped only when the visible events are fewer than these: with no narrowing there is
   * nothing the text logs were left out of. Absent, the line is not shown.
   */
  loadedCount?: number;
  /**
   * Narrows the view to the loaded events a finding's event evidence names. Called with the finding
   * and what was resolved; absent, a finding card has no "Filter to" link.
   */
  onFilterToFinding?: (finding: DiagnosisFinding, scope: FindingScope) => void;
  /** Narrows the view to one event ID. Absent, the Top event IDs rows are information only. */
  onFilterToEventId?: (eventId: number) => void;
  /** The one event ID the quick filter shows now, for the pressed state of its row. */
  activeEventId?: number | null;
}

interface GroupedCoverageGap {
  gap: DiagnosisCoverageGap;
  occurrences: number;
}

/** Actionable means every class except `coverageGap`, matching `actionableFindingCount`. */
export function actionableFindings(findings: DiagnosisFinding[]): DiagnosisFinding[] {
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
  return `${formatCount(count)} ${count === 1 ? singular : plural}`;
}

function omittedLabel(count: number, singular: string): string {
  return `${countLabel(count, singular)} omitted.`;
}

function evidenceLabel(evidence: DiagnosisEvidence, includeOrigin = false): string {
  if (evidence.kind === "event") return eventEvidenceLabel(evidence.value, includeOrigin);
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
  return evidence.map((item) => evidenceLabel(item)).join("; ");
}

function Count({ value }: { value: number }) {
  return <span style={{ fontFamily: tokens.fontFamilyNumeric }}>{formatCount(value)}</span>;
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
  const { cardSecondary } = useRailTextColors();
  return (
    <div style={{ display: "grid", gap: "2px", fontSize: `${sizes.small}px` }}>
      <span style={{ color: tokens.colorNeutralForeground2 }}>
        Coverage: {gap.source} ({gap.state}): {gap.detail} (
        {countLabel(occurrences, "occurrence")})
      </span>
      {gap.evidence.length > 0 && (
        <span style={{ color: cardSecondary }}>
          Coverage evidence: {evidenceText(gap.evidence)}
        </span>
      )}
    </div>
  );
}

const linkButtonStyle = {
  justifySelf: "start",
  padding: 0,
  border: "none",
  background: "none",
  cursor: "pointer",
  font: "inherit",
  color: tokens.colorBrandForeground1,
} as const;

function FindingCard({
  finding,
  includeOrigin,
  stale,
  sizes,
  visuals,
  scope,
  onFilter,
}: {
  finding: DiagnosisFinding;
  includeOrigin: boolean;
  stale: boolean;
  sizes: RailSizes;
  visuals: EvtxVisualTokens;
  /** What the finding's event evidence resolves to; null when the panel has no way to filter. */
  scope: FindingScope | null;
  onFilter?: (finding: DiagnosisFinding, scope: FindingScope) => void;
}) {
  const [checksExpanded, setChecksExpanded] = useState(false);
  const { cardSecondary } = useRailTextColors();
  const [evidenceExpanded, setEvidenceExpanded] = useState(false);
  const level = visuals.findingSeverityVisual(finding.severity);
  const shownEvidence = evidenceExpanded
    ? finding.evidence.slice(0, DETAIL_RENDER_CAP)
    : finding.evidence.slice(0, EVIDENCE_PREVIEW_COUNT);
  const hiddenEvidence = finding.evidence.length - shownEvidence.length;
  const [firstCheck, ...otherChecks] = finding.recommendedChecks;
  return (
    <article
      aria-label={finding.title}
      aria-busy={stale || undefined}
      data-finding-id={finding.findingId}
      tabIndex={-1}
      style={{
        display: "grid",
        gap: "6px",
        padding: "10px 12px",
        borderRadius: "6px",
        backgroundColor: tokens.colorNeutralBackground1,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        borderTop: `3px solid ${level.barColor}`,
        opacity: stale ? 0.6 : 1,
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
            color: cardSecondary,
            textAlign: "right",
          }}
        >
          {CLASS_LABELS[finding.class]} {"·"} {finding.confidence} confidence
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
            <div key={index}>{evidenceLabel(item, includeOrigin)}</div>
          ))}
          {evidenceExpanded && hiddenEvidence > 0 && (
            <div style={{ color: cardSecondary }}>
              {omittedLabel(hiddenEvidence, "evidence reference")}
            </div>
          )}
          {finding.evidence.length > EVIDENCE_PREVIEW_COUNT && (
            <button
              type="button"
              aria-expanded={evidenceExpanded}
              onClick={() => setEvidenceExpanded((value) => !value)}
              style={linkButtonStyle}
            >
              {evidenceExpanded
                ? "Show fewer"
                : `+${formatCount(finding.evidence.length - EVIDENCE_PREVIEW_COUNT)} more`}
            </button>
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
              style={linkButtonStyle}
            >
              {checksExpanded
                ? "Show fewer checks"
                : `+${otherChecks.length} more ${otherChecks.length === 1 ? "check" : "checks"}`}
            </button>
          )}
        </div>
      )}
      {scope !== null && onFilter && (
        <ScopeLink finding={finding} scope={scope} stale={stale} sizes={sizes} onFilter={onFilter} />
      )}
      {finding.coverageGaps.map((gap) => (
        <CoverageGapRow key={gap.id} gap={gap} occurrences={1} sizes={sizes} />
      ))}
    </article>
  );
}

/**
 * "Filter to {n} events" (spec 8.13): the link, and a muted line for each way the filter falls short
 * of what the finding cites. The link is only offered when at least one cited event is loaded, and
 * it waits while the card is from a previous build. A finding that cites no event gets nothing.
 */
function ScopeLink({
  finding,
  scope,
  stale,
  sizes,
  onFilter,
}: {
  finding: DiagnosisFinding;
  scope: FindingScope;
  stale: boolean;
  sizes: RailSizes;
  onFilter: (finding: DiagnosisFinding, scope: FindingScope) => void;
}) {
  const { cardSecondary } = useRailTextColors();
  if (!finding.evidence.some((evidence) => evidence.kind === "event")) return null;
  const count = scope.records.length;
  const gaps = describeScopeCounts(scope.counts, "finding");
  return (
    <div style={{ display: "grid", gap: "2px", fontSize: `${sizes.small}px` }}>
      {count > 0 && (
        <Link
          as="button"
          type="button"
          disabled={stale}
          onClick={() => onFilter(finding, scope)}
          style={{ justifySelf: "start", fontSize: `${sizes.small}px`, fontWeight: 600 }}
        >
          Filter to {formatCount(count)} {count === 1 ? "event" : "events"}{" "}
          <ArrowRight12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />
        </Link>
      )}
      {gaps.map((sentence) => (
        <div key={sentence} style={{ color: cardSecondary }}>
          {sentence}
        </div>
      ))}
    </div>
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
  textLogCount,
  loadedCount,
  updating,
  sizes,
}: {
  overview: DiagnosisOverview;
  scopeCount: number | null;
  textLogCount: number;
  loadedCount: number | undefined;
  updating: boolean;
  sizes: RailSizes;
}) {
  const railText = useRailTextColors();
  return (
    <div style={{ display: "grid", gap: "4px" }}>
      {updating && (
        <div
          role="status"
          style={{ fontSize: `${sizes.caption}px`, color: railText.secondary }}
        >
          Updating diagnosis...
        </div>
      )}
      {/* Everything below is the previous build while one is pending, so it is dimmed and marked
          busy like the finding cards, and its scope line states the scope it was built from. */}
      <div
        aria-busy={updating || undefined}
        style={{ display: "grid", gap: "4px", opacity: updating ? 0.6 : 1 }}
      >
        <div
          style={{
            fontSize: `${sizes.caption}px`,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: railText.secondary,
          }}
        >
          {OUTCOME_LABELS[overview.outcome]}
        </div>
        <div style={{ fontSize: `${sizes.f}px`, fontWeight: 600, color: railText.primary }}>
          {overview.headline}
        </div>
        <div
          data-testid="overview-counts"
          style={{ fontSize: `${sizes.small}px`, color: railText.secondary }}
        >
          <Count value={overview.actionableFindingCount} />{" "}
          {overview.actionableFindingCount === 1 ? "actionable finding" : "actionable findings"},{" "}
          <Count value={overview.coverageGapCount} />{" "}
          {overview.coverageGapCount === 1 ? "source coverage gap" : "source coverage gaps"}
        </div>
        {scopeCount !== null && (
          <div style={{ fontSize: `${sizes.caption}px`, color: railText.secondary }}>
            Scoped to <Count value={scopeCount} /> visible {scopeCount === 1 ? "event" : "events"}
          </div>
        )}
        {scopeCount !== null &&
          textLogCount > 0 &&
          loadedCount !== undefined &&
          scopeCount < loadedCount && (
          // The event criteria (levels, search, a time range, a record scope) never narrow the text
          // logs the session was given, so a narrowed diagnosis mixes a scoped set of events with
          // all of them. With nothing narrowed there is nothing they were left out of.
          <div style={{ fontSize: `${sizes.caption}px`, color: railText.secondary }}>
            Text logs are not scoped.
          </div>
        )}
      </div>
    </div>
  );
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
            {entry.level} <Count value={entry.count} />
          </li>
        ))}
      </ul>
    </RailCard>
  );
}

const useTopEventIdStyles = makeStyles({
  // A row that filters. The ID and the count take their colors from two variables, so the hover and
  // pressed states can change them (a class cannot reach the inline-colored children otherwise): the
  // Hover and Pressed foreground tokens are the ones that read on the subtle hover and pressed
  // surfaces in every theme, where Foreground1 on the hover surface measures 4.11:1 in solarized-dark
  // and 1.46:1 in high contrast.
  row: {
    "--evtx-top-id-color": tokens.colorNeutralForeground1,
    "--evtx-top-count-color": tokens.colorNeutralForeground2,
    display: "grid",
    gridTemplateColumns: "40px 1fr 30px",
    alignItems: "center",
    columnGap: "8px",
    width: "100%",
    boxSizing: "border-box",
    padding: "2px 4px",
    border: "none",
    borderRadius: "4px",
    backgroundColor: "transparent",
    font: "inherit",
    textAlign: "left",
    cursor: "pointer",
    ":hover": {
      backgroundColor: tokens.colorSubtleBackgroundHover,
      "--evtx-top-id-color": tokens.colorNeutralForeground1Hover,
      "--evtx-top-count-color": tokens.colorNeutralForeground2Hover,
    },
    ":active": {
      backgroundColor: tokens.colorSubtleBackgroundPressed,
      "--evtx-top-id-color": tokens.colorNeutralForeground1Pressed,
      "--evtx-top-count-color": tokens.colorNeutralForeground2Pressed,
    },
    ...createFocusOutlineStyle({ style: { outlineRadius: "4px" } }),
  },
});

function TopEventIdsCard({
  topEventIds,
  sizes,
  visuals,
  onFilter,
  activeEventId,
}: {
  topEventIds: TopEventId[];
  sizes: RailSizes;
  visuals: EvtxVisualTokens;
  onFilter?: (eventId: number) => void;
  activeEventId: number | null;
}) {
  const styles = useTopEventIdStyles();
  const max = topEventIds[0]?.count ?? 1;
  const rowContent = (entry: TopEventId, interactive: boolean) => (
    <>
      <span
        style={{
          fontFamily: tokens.fontFamilyNumeric,
          fontWeight: 700,
          color: interactive ? "var(--evtx-top-id-color)" : tokens.colorNeutralForeground1,
        }}
      >
        {entry.eventId}
      </span>
      {/* Single-series bars (spec 6.3): only the bar is hidden; the ID and the count are text. */}
      <span
        aria-hidden="true"
        style={{
          height: "10px",
          width: `${Math.max((entry.count / max) * 100, 2)}%`,
          borderRadius: "2px",
          backgroundColor: visuals.singleSeries,
        }}
      />
      <span
        style={{
          fontFamily: tokens.fontFamilyNumeric,
          textAlign: "right",
          color: interactive ? "var(--evtx-top-count-color)" : tokens.colorNeutralForeground2,
        }}
      >
        {formatCount(entry.count)}
      </span>
    </>
  );
  return (
    <RailCard title="Top event IDs" sizes={sizes} caption={onFilter ? "click to filter" : undefined}>
      <ul style={{ display: "grid", gap: "4px", margin: 0, padding: 0, listStyle: "none" }}>
        {topEventIds.map((entry) => {
          const pressed = onFilter !== undefined && entry.eventId === activeEventId;
          return (
            <li
              key={entry.eventId}
              data-event-id={entry.eventId}
              style={
                onFilter
                  ? { fontSize: `${sizes.small}px` }
                  : {
                      display: "grid",
                      gridTemplateColumns: "40px 1fr 30px",
                      alignItems: "center",
                      gap: "8px",
                      fontSize: `${sizes.small}px`,
                    }
              }
            >
              {onFilter ? (
                <button
                  type="button"
                  className={styles.row}
                  aria-pressed={pressed}
                  aria-label={`Event ID ${entry.eventId}, ${formatCount(entry.count)} ${entry.count === 1 ? "event" : "events"}`}
                  onClick={() => onFilter(entry.eventId)}
                  // The pressed row is the selection (Q-1): its fill, its inset edge, and the
                  // selection foreground for the ID and the count. Inline, so hover cannot undo it.
                  style={
                    pressed
                      ? ({
                          backgroundColor: visuals.selection.background,
                          boxShadow: `inset 3px 0 0 ${visuals.selection.border}`,
                          "--evtx-top-id-color": visuals.selection.foreground,
                          "--evtx-top-count-color": visuals.selection.foreground,
                        } as CSSProperties)
                      : undefined
                  }
                >
                  {rowContent(entry, true)}
                </button>
              ) : (
                rowContent(entry, false)
              )}
            </li>
          );
        })}
      </ul>
    </RailCard>
  );
}

/**
 * The chain counts of the session, from the shared edges-only model. It needs no timeline scan:
 * the counts are right from the edges alone, and titles and spans are the view's. Rules:
 * - while the model is not in, and whenever the number of edges in the session is not known, the
 *   headline is "unknown", never 0;
 * - when edges were not all loaded the counts are of the loaded ones and the shortfall is stated
 *   in the Correlation view's own words;
 * - a coverage blocked row is a coverage state and is counted apart, never as a correlation;
 * - a session known to hold no edge at all has nothing to summarise, so there is no card.
 */
function CorrelationSummaryCard({ sizes, stale }: { sizes: RailSizes; stale: boolean }) {
  const { counts, stage } = useEvtxCorrelationData();
  const { cardSecondary } = useRailTextColors();
  if (counts === null && stage === "unavailable") return null;
  // Counts that are not in yet are an unplaced count that is not known, not a counted zero.
  const unplacedList = counts === null ? { items: [], total: null } : counts.unplacedList;
  const unplacedLine = unplacedCardLine(unplacedList);
  const unplacedView = describeUnplaced(unplacedList);
  const unplacedKnown = counts !== null && unplacedView.total !== null;
  // Something to review: a counted non-zero or an unknown count over a run. Not while loading.
  const unplacedToReview = counts !== null && unplacedView.present;
  const lineStyle = { fontSize: `${sizes.small}px`, color: tokens.colorNeutralForeground2 };
  const mutedStyle = { fontSize: `${sizes.small}px`, color: cardSecondary };
  const known = counts !== null && counts.edges.totalEdges !== null;
  // A session known to hold no edge has nothing to summarise, unless it has unplaced items to review.
  if (counts !== null && counts.edges.totalEdges === 0 && counts.model.edgeInputComplete && !unplacedToReview) {
    return null;
  }
  const rows = counts?.model.counts;
  const correlations = rows === undefined ? 0 : correlationChainCount(rows);
  const shortfall =
    counts === null
      ? null
      : edgeInputNotice({
          edgeInputComplete: counts.model.edgeInputComplete,
          unloadedEdgeCount: counts.model.unloadedEdgeCount,
        });
  return (
    <RailCard title="Correlations" sizes={sizes} stale={stale || counts?.updating === true}>
      <div style={known ? lineStyle : mutedStyle} data-testid="correlation-card-headline">
        {known ? (
          <>
            <Count value={correlations} /> {correlations === 1 ? "chain" : "chains"}
          </>
        ) : (
          "unknown"
        )}
      </div>
      {known && rows !== undefined && correlations > 0 && (
        <div style={lineStyle}>
          <Count value={rows.exact} /> exact {"\u00b7"} <Count value={rows.candidate} /> candidate{" "}
          {"\u00b7"} <Count value={rows.ambiguous} /> ambiguous
        </div>
      )}
      {known && rows !== undefined && rows.coverageBlocked > 0 && (
        <div style={mutedStyle}>
          <Count value={rows.coverageBlocked} /> coverage blocked
        </div>
      )}
      {shortfall !== null && <div style={mutedStyle}>{shortfall}</div>}
      {unplacedLine !== null && (
        <div style={unplacedKnown ? lineStyle : mutedStyle} data-testid="correlation-card-unplaced">
          {unplacedLine}
        </div>
      )}
      {unplacedToReview && (
        <Link
          as="button"
          type="button"
          onClick={() => openUnplacedInCorrelationView()}
          style={{ justifySelf: "start", fontSize: `${sizes.small}px`, fontWeight: 600 }}
        >
          Review unplaced lines <ArrowRight12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />
        </Link>
      )}
      <Link
        as="button"
        type="button"
        onClick={() => openChainInCorrelationView()}
        style={{ justifySelf: "start", fontSize: `${sizes.small}px`, fontWeight: 600 }}
      >
        Open correlation view <ArrowRight12Regular aria-hidden="true" style={{ verticalAlign: "middle" }} />
      </Link>
    </RailCard>
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
  stale = false,
}: {
  count: number;
  singular: string;
  sizes: RailSizes;
  stale?: boolean;
}) {
  const railText = useRailTextColors();
  return count > 0 ? (
    <span
      aria-busy={stale || undefined}
      style={{ fontSize: `${sizes.small}px`, color: railText.secondary, opacity: stale ? 0.6 : undefined }}
    >
      {omittedLabel(count, singular)}
    </span>
  ) : null;
}

export const EventDiagnosisPanel = memo(function EventDiagnosisPanel({
  summary,
  records,
  updating = false,
  error = null,
  scopeCount,
  textLogCount = 0,
  loadedCount,
  onFilterToFinding,
  onFilterToEventId,
  activeEventId = null,
}: EventDiagnosisPanelProps) {
  const sizes = useRailSizes();
  const railText = useRailTextColors();
  const visuals = useEvtxVisualTokens();
  const [coverageOpen, setCoverageOpen] = useState(false);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const recordSummary = useMemo(
    () => (records && records.length > 0 ? summarizeRecords(records) : null),
    [records],
  );

  // Indexed once per set of records, and only when a card can filter and some finding cites an
  // event: resolving a finding is then a lookup per reference and not a pass over every loaded
  // record, and a live tail that changes the records builds nothing while no card has a link.
  const citesEvents = useMemo(
    () =>
      summary !== null &&
      actionableFindings(summary.findings).some((candidate) =>
        candidate.evidence.some((evidence) => evidence.kind === "event"),
      ),
    [summary],
  );
  const evidenceIndex = useMemo<EvidenceIndex | null>(
    () => (onFilterToFinding && records && citesEvents ? buildEvidenceIndex(records) : null),
    [onFilterToFinding, records, citesEvents],
  );
  const engineBounded = useMemo(() => (summary ? summaryIsBounded(summary) : false), [summary]);

  const recordCards = recordSummary && (
    <>
      {recordSummary.levelMix.length > 0 && (
        <LevelMixCard
          levelMix={recordSummary.levelMix}
          total={recordSummary.total}
          sizes={sizes}
          visuals={visuals}
        />
      )}
      {recordSummary.topEventIds.length > 0 && (
        <TopEventIdsCard
          topEventIds={recordSummary.topEventIds}
          sizes={sizes}
          visuals={visuals}
          onFilter={onFilterToEventId}
          activeEventId={activeEventId}
        />
      )}
    </>
  );

  if (!summary) {
    // The workspace's alert banner carries the full error text; repeating it here would stack two
    // prefixes on one message.
    const message = error
      ? "Diagnosis could not be built."
      : updating
        ? "Updating diagnosis..."
        : "There are no events or text logs to diagnose.";
    return (
      <section
        aria-label="Operational diagnosis status"
        style={{ display: "grid", gap: "12px", fontSize: `${sizes.f}px` }}
      >
        <div
          role="status"
          style={{ fontSize: `${sizes.small}px`, color: railText.secondary }}
        >
          {message}
        </div>
        {recordCards}
      </section>
    );
  }

  const actionable = sortFindings(actionableFindings(summary.findings));
  const findings = capSection(actionable, summary.overview.actionableFindingCount);
  const includeOrigin = evidenceSpansSources(findings.items);
  const coverageGaps = capCoverageSection(
    summary.coverageGaps,
    summary.overview.coverageGapCount,
  );
  const events = capSection(
    summary.events.filter((event) => event.errorTokens.length > 0),
    summary.overview.errorTokenEventCount,
  );
  const hasDetails = events.items.length > 0;

  return (
    <section
      aria-label="Operational diagnosis"
      aria-busy={updating || undefined}
      style={{ display: "grid", gap: "12px", fontSize: `${sizes.f}px` }}
    >
      <OverviewBlock
        overview={summary.overview}
        scopeCount={scopeCount !== undefined ? scopeCount : records ? records.length : null}
        textLogCount={textLogCount}
        loadedCount={loadedCount}
        updating={updating}
        sizes={sizes}
      />

      {summary.overview.actionableFindingCount === 0 ? (
        <div
          aria-busy={updating || undefined}
          style={{
            fontSize: `${sizes.small}px`,
            color: tokens.colorNeutralForeground2,
            opacity: updating ? 0.6 : 1,
          }}
        >
          No actionable findings.
        </div>
      ) : (
        <>
          {findings.items.map((finding) => (
            <FindingCard
              key={finding.findingId}
              finding={finding}
              includeOrigin={includeOrigin}
              stale={updating}
              sizes={sizes}
              visuals={visuals}
              scope={
                evidenceIndex ? scopeForFinding(finding, evidenceIndex, engineBounded) : null
              }
              onFilter={onFilterToFinding}
            />
          ))}
          <OmittedRows
            count={findings.omitted}
            singular="actionable finding"
            sizes={sizes}
            stale={updating}
          />
        </>
      )}

      {summary.overview.coverageGapCount > 0 && (
        <Disclosure
          label={`Coverage gaps (${formatCount(summary.overview.coverageGapCount)})`}
          open={coverageOpen}
          onOpenChange={setCoverageOpen}
          sizes={sizes}
          stale={updating}
        >
          {coverageGaps.items.map(({ gap, occurrences }) => (
            <CoverageGapRow
              key={`${gap.source}-${gap.state}-${gap.detail}`}
              gap={gap}
              occurrences={occurrences}
              sizes={sizes}
            />
          ))}
          <OmittedRows
            count={coverageGaps.omitted}
            singular="coverage gap"
            sizes={sizes}
          />
        </Disclosure>
      )}

      {recordCards}

      <CorrelationSummaryCard sizes={sizes} stale={updating} />

      {(hasDetails || events.omitted > 0) && (
        <Disclosure
          label="Show diagnosis details"
          open={detailsOpen}
          onOpenChange={setDetailsOpen}
          sizes={sizes}
          stale={updating}
        >
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
});

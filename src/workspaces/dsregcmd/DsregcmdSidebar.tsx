import { useMemo, type CSSProperties, type MouseEvent } from "react";
import { tokens } from "@fluentui/react-components";
import {
  DSREGCMD_SECTION_IDS,
  dsregcmdSectionDomId,
  useDsregcmdStore,
  type DsregcmdSectionId,
} from "./dsregcmd-store";
import { buildTimelineItems } from "./dsregcmd-formatters";
import { useDsregcmdDerived } from "./use-dsregcmd-derived";
import { getVisibleFactRows } from "./FactGroupRenderer";
import { SourceStatusNotice } from "../../components/common/sidebar-primitives";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getBaseName } from "../../lib/file-paths";
import { getLogListMetrics, LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import type { DsregcmdSourceContext } from "./types";
import type { EventLogAnalysis } from "../../types/event-log";

// ---------------------------------------------------------------------------
// Source card helpers
// ---------------------------------------------------------------------------

/**
 * The kind line under the source name. A capture time appears only for a live
 * capture that recorded one; other kinds never show a time because none was
 * observed.
 */
function getKindLine(sourceContext: DsregcmdSourceContext): string | null {
  const { source, capturedAt } = sourceContext;
  if (!source) {
    return null;
  }

  switch (source.kind) {
    case "capture": {
      const formatted = capturedAt ? formatDisplayDateTime(capturedAt) : null;
      return formatted ? `Live capture · ${formatted}` : "Live capture";
    }
    case "file":
      return `Text file · ${getBaseName(source.path) || source.path}`;
    case "folder":
      return `Evidence folder · ${getBaseName(source.path) || source.path}`;
    case "clipboard":
    case "text":
      return "Pasted text";
  }
}

interface EventLogCount {
  /** Null when the count would claim more than the evidence supports. */
  value: number | null;
  /** True when some live channels failed, so the real total can be higher. */
  isLowerBound: boolean;
}

/**
 * The Event logs count. A live query in which no channel was read has no known
 * total, so it shows none rather than 0. When some channels failed the total is
 * a lower bound.
 */
function getEventLogCount(analysis: EventLogAnalysis): EventLogCount {
  const live = analysis.liveQuery;
  if (!live) {
    return { value: analysis.totalEntryCount, isLowerBound: false };
  }
  if (live.successfulChannelCount === 0) {
    return { value: null, isLowerBound: false };
  }
  return {
    value: analysis.totalEntryCount,
    isLowerBound: live.failedChannelCount > 0,
  };
}

const VISUALLY_HIDDEN: CSSProperties = {
  position: "absolute",
  width: 1,
  height: 1,
  margin: -1,
  padding: 0,
  overflow: "hidden",
  clip: "rect(0 0 0 0)",
  whiteSpace: "nowrap",
  border: 0,
};

const REASON_NO_RESULT_ID = "dsregcmd-nav-reason-no-result";
const REASON_NO_EVENT_LOGS_ID = "dsregcmd-nav-reason-no-event-logs";

function plural(count: number, singular: string, pluralForm: string): string {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

// ---------------------------------------------------------------------------
// DsregcmdSidebar
// ---------------------------------------------------------------------------

const SECTION_LABELS: Record<DsregcmdSectionId, string> = {
  overview: "Overview",
  findings: "Findings",
  facts: "Facts",
  flows: "Flows",
  timeline: "Timeline",
  export: "Export",
};

/** Nav order from the spec: Event logs sits between Timeline and Export. */
const NAV_ORDER: ReadonlyArray<DsregcmdSectionId | "event-logs"> = [
  ...DSREGCMD_SECTION_IDS.filter((id) => id !== "export"),
  "event-logs",
  "export",
];

export function DsregcmdSidebar() {
  const result = useDsregcmdStore((s) => s.result);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);
  const analysisState = useDsregcmdStore((s) => s.analysisState);
  const activeTab = useDsregcmdStore((s) => s.activeTab);
  const activeSection = useDsregcmdStore((s) => s.activeSection);
  const showNotReported = useDsregcmdStore((s) => s.showNotReported);
  const navigateToSection = useDsregcmdStore((s) => s.navigateToSection);
  const setActiveTab = useDsregcmdStore((s) => s.setActiveTab);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const { factGroups } = useDsregcmdDerived();

  const fontSize = getLogListMetrics(logListFontSize).fontSize;
  const smallFont = Math.max(9, fontSize - 2);
  const tinyFont = Math.max(9, fontSize - 3);
  const eyebrowFont = Math.max(10, fontSize - 3);

  const eventLogAnalysis = result?.eventLogAnalysis ?? null;
  const sourceLabel =
    sourceContext.source === null ? "No source loaded" : sourceContext.displayLabel;
  const showingEventLogs = activeTab === "event-logs" && eventLogAnalysis !== null;

  const counts = useMemo(() => {
    const visibleFactRows = factGroups.reduce(
      (total, group) => total + getVisibleFactRows(group, showNotReported).length,
      0,
    );
    return {
      findings: result?.diagnostics.length ?? 0,
      facts: visibleFactRows,
      timeline: result ? buildTimelineItems(result.facts, result).length : 0,
    };
  }, [factGroups, result, showNotReported]);

  const hasResult = result !== null;
  const kindLine = getKindLine(sourceContext);
  const pathRows = [
    { label: "Bundle root", value: sourceContext.bundlePath },
    { label: "Evidence file", value: sourceContext.evidenceFilePath },
  ].filter((row): row is { label: string; value: string } => !!row.value);

  const numeric: CSSProperties = {
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
  };

  const itemStyle = (isActive: boolean, isDisabled: boolean): CSSProperties => ({
    display: "flex",
    alignItems: "baseline",
    justifyContent: "space-between",
    gap: "8px",
    padding: "7px 16px",
    fontSize,
    fontWeight: isActive ? 600 : 400,
    textDecoration: "none",
    cursor: isDisabled ? "default" : "pointer",
    color: isActive
      ? tokens.colorBrandForeground1
      : isDisabled
        ? tokens.colorNeutralForegroundDisabled
        : tokens.colorNeutralForeground1,
    backgroundColor: isActive ? tokens.colorNeutralBackground1Selected : "transparent",
    borderLeft: isActive
      ? `3px solid ${tokens.colorCompoundBrandStroke}`
      : "3px solid transparent",
  });

  const renderCount = (count: number | null, lowerBoundText?: string) =>
    count === null ? null : (
      <span style={{ ...numeric, fontSize: smallFont, color: tokens.colorNeutralForeground3 }}>
        <span aria-hidden={lowerBoundText ? true : undefined}>
          {count}
          {lowerBoundText ? "+" : ""}
        </span>
        {lowerBoundText && <span style={VISUALLY_HIDDEN}>{lowerBoundText}</span>}
      </span>
    );

  const renderDisabled = (key: string, label: string, reasonId: string) => (
    <a
      key={key}
      role="link"
      aria-disabled="true"
      tabIndex={0}
      aria-describedby={reasonId}
      style={itemStyle(false, true)}
      onClick={(event: MouseEvent) => event.preventDefault()}
    >
      <span>{label}</span>
    </a>
  );

  const renderItem = (id: DsregcmdSectionId | "event-logs") => {
    const label = id === "event-logs" ? "Event logs" : SECTION_LABELS[id];
    if (!hasResult) {
      return renderDisabled(id, label, REASON_NO_RESULT_ID);
    }

    if (id === "event-logs") {
      if (!eventLogAnalysis) {
        return renderDisabled(id, label, REASON_NO_EVENT_LOGS_ID);
      }
      const eventLogCount = getEventLogCount(eventLogAnalysis);
      return (
        <a
          key={id}
          href={`#${dsregcmdSectionDomId(id)}`}
          aria-current={showingEventLogs ? "location" : undefined}
          style={itemStyle(showingEventLogs, false)}
          onClick={(event: MouseEvent) => {
            event.preventDefault();
            setActiveTab("event-logs");
          }}
        >
          <span>{label}</span>
          {renderCount(
            eventLogCount.value,
            eventLogCount.isLowerBound
              ? `at least ${eventLogCount.value}; some channels could not be read`
              : undefined,
          )}
        </a>
      );
    }

    const isActive = !showingEventLogs && activeSection === id;
    const count =
      id === "findings"
        ? counts.findings
        : id === "facts"
          ? counts.facts
          : id === "timeline"
            ? counts.timeline
            : null;
    return (
      <a
        key={id}
        href={`#${dsregcmdSectionDomId(id)}`}
        aria-current={isActive ? "location" : undefined}
        style={itemStyle(isActive, false)}
        onClick={(event: MouseEvent) => {
          event.preventDefault();
          navigateToSection(id);
        }}
      >
        <span>{label}</span>
        {renderCount(count)}
      </a>
    );
  };

  return (
    <nav
      aria-label="Source and sections"
      style={{
        display: "flex",
        flexDirection: "column",
        flex: 1,
        minHeight: 0,
        fontSize,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "4px",
          padding: "16px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        }}
      >
        <span
          style={{
            alignSelf: "flex-start",
            padding: "0 6px",
            border: `1px solid ${tokens.colorNeutralStroke1}`,
            borderRadius: tokens.borderRadiusMedium,
            color: tokens.colorNeutralForeground2,
            fontSize: tinyFont,
            fontWeight: 600,
            letterSpacing: "0.05em",
          }}
        >
          DSREGCMD
        </span>
        <div
          title={sourceLabel}
          style={{
            marginTop: "4px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {sourceLabel}
        </div>
        {kindLine && (
          <div style={{ fontSize: smallFont, color: tokens.colorNeutralForeground2 }}>
            {kindLine}
          </div>
        )}
        {/* Counts exist only once the source was read; before that, or after a
            failed load, they would claim an empty source. */}
        {hasResult && (
          <div style={{ ...numeric, fontSize: tinyFont, color: tokens.colorNeutralForeground3 }}>
            {plural(sourceContext.rawLineCount, "line", "lines")} {"\u00B7"}{" "}
            {plural(sourceContext.rawCharCount, "char", "chars")}
          </div>
        )}
        {pathRows.length > 0 && (
          <details style={{ fontSize: tinyFont, color: tokens.colorNeutralForeground3 }}>
            <summary style={{ cursor: "pointer" }}>Show paths</summary>
            {pathRows.map((row) => (
              <div key={row.label} style={{ marginTop: "4px", wordBreak: "break-word" }}>
                <div>{row.label}</div>
                <div style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, color: tokens.colorNeutralForeground2 }}>
                  {row.value}
                </div>
              </div>
            ))}
          </details>
        )}
      </div>

      {(analysisState.phase === "analyzing" || analysisState.phase === "error") && (
        <SourceStatusNotice
          kind={analysisState.phase === "error" ? "error" : "info"}
          message={analysisState.message}
          detail={analysisState.detail ?? undefined}
        />
      )}

      <div style={{ flex: 1, overflow: "auto" }}>
        <div
          style={{
            padding: "14px 16px 6px",
            fontSize: eyebrowFont,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: tokens.colorNeutralForeground3,
          }}
        >
          On this page
        </div>
        {NAV_ORDER.map(renderItem)}
      </div>

      <span id={REASON_NO_RESULT_ID} style={VISUALLY_HIDDEN}>
        Available after a source has been analyzed.
      </span>
      <span id={REASON_NO_EVENT_LOGS_ID} style={VISUALLY_HIDDEN}>
        Unavailable: this source has no event log data.
      </span>
    </nav>
  );
}

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
import { EmptyState, SourceStatusNotice } from "../../components/common/sidebar-primitives";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getBaseName } from "../../lib/file-paths";
import { getLogListMetrics, LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import type { DsregcmdSourceContext } from "./types";

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

  const eventLogAnalysis = result?.eventLogAnalysis ?? null;
  const showingEventLogs = activeTab === "event-logs" && eventLogAnalysis !== null;

  const counts = useMemo(() => {
    const visibleFactRows = factGroups.reduce(
      (total, group) =>
        total +
        (showNotReported
          ? group.rows.length
          : group.rows.filter((row) => row.isNotReported !== true).length),
      0,
    );
    return {
      findings: result?.diagnostics.length ?? 0,
      facts: visibleFactRows,
      timeline: result ? buildTimelineItems(result.facts, result).length : 0,
    };
  }, [factGroups, result, showNotReported]);

  const kindLine = getKindLine(sourceContext);
  const hasSource = sourceContext.source !== null;
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

  const renderCount = (count: number | null) =>
    count === null ? null : (
      <span style={{ ...numeric, fontSize: smallFont, color: tokens.colorNeutralForeground3 }}>
        {count}
      </span>
    );

  const renderItem = (id: DsregcmdSectionId | "event-logs") => {
    if (id === "event-logs") {
      if (!eventLogAnalysis) {
        return (
          <a
            key={id}
            aria-disabled="true"
            title="This source has no event log data."
            style={itemStyle(false, true)}
          >
            <span>Event logs</span>
          </a>
        );
      }
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
          <span>Event logs</span>
          {renderCount(eventLogAnalysis.totalEntryCount)}
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
        <span>{SECTION_LABELS[id]}</span>
        {renderCount(count)}
      </a>
    );
  };

  return (
    <div
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
          title={sourceContext.displayLabel}
          style={{
            marginTop: "4px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {sourceContext.displayLabel}
        </div>
        {kindLine && (
          <div style={{ fontSize: smallFont, color: tokens.colorNeutralForeground2 }}>
            {kindLine}
          </div>
        )}
        {hasSource && (
          <div style={{ ...numeric, fontSize: tinyFont, color: tokens.colorNeutralForeground3 }}>
            {plural(sourceContext.rawLineCount, "line", "lines")} {"·"}{" "}
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

      {result ? (
        <nav aria-label="On this page" style={{ flex: 1, overflow: "auto" }}>
          <div
            style={{
              padding: "14px 16px 6px",
              fontSize: tinyFont,
              fontWeight: 600,
              letterSpacing: "0.05em",
              textTransform: "uppercase",
              color: tokens.colorNeutralForeground3,
            }}
          >
            On this page
          </div>
          {NAV_ORDER.map(renderItem)}
        </nav>
      ) : (
        analysisState.phase === "idle" && (
          <EmptyState
            title="No dsregcmd analysis yet"
            body="Use the toolbar actions to capture live output, paste clipboard text, open a text file, or open an evidence folder."
          />
        )
      )}
    </div>
  );
}

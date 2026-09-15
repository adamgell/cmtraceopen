import { useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { useEvtxStore } from "./evtx-store";
import { useUiStore } from "../../stores/ui-store";
import { LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { formatCoverageGap, summarizeCoverageGaps } from "./evtx-coverage";
const MAX_DISPLAYED_ARCHIVE_MEMBERS = 4_096;
const MAX_DISPLAYED_COVERAGE_GAPS = 100;
/**
 * Shows what is missing from the loaded events.
 *
 * These are not load failures, so this is deliberately not styled as an error: the events that did
 * load are real and usable. They are gaps, and the reason they get their own banner rather than a
 * console line is that a silently incomplete view is worse than an empty one. Events that never
 * loaded look exactly like evidence that the thing being investigated did not happen.
 *
 * It cannot be dismissed permanently, only collapsed. A gap stays true for as long as the data is
 * on screen, and letting it be dismissed would make the view claim completeness it does not have.
 */
export function EvtxCoverageBanner() {
  const legacyGaps = useEvtxStore((s) => s.coverageGaps);
  const structuredGaps = useEvtxStore((s) => s.coverageDetails);
  const tailGaps = useEvtxStore((s) => s.tailCoverageGaps);
  const archiveMembers = useEvtxStore((s) => s.archiveMembers);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const [collapsed, setCollapsed] = useState(false);

  const gaps = useMemo(
    () => [...new Set([...legacyGaps, ...tailGaps, ...structuredGaps.map(formatCoverageGap)])],
    [legacyGaps, tailGaps, structuredGaps]
  );
  const displayedGaps = useMemo(
    () => gaps.slice(0, MAX_DISPLAYED_COVERAGE_GAPS),
    [gaps],
  );
  const omittedGaps = gaps.length - displayedGaps.length;
  const displayedArchiveMembers = useMemo(
    () => archiveMembers.slice(0, MAX_DISPLAYED_ARCHIVE_MEMBERS),
    [archiveMembers]
  );
  const omittedArchiveMembers = archiveMembers.length - displayedArchiveMembers.length;
  const archiveMemberMessages = useMemo(
    () => [
      ...displayedArchiveMembers.map(
        ({ path, kind, outcome, sha256 }) =>
          `${path}: ${kind} ${outcome}${sha256 ? ` (sha256:${sha256})` : ""}`
      ),
      ...(omittedArchiveMembers > 0
        ? [`<archive member metadata: ${omittedArchiveMembers} omitted by display limit>`]
        : []),
    ],
    [displayedArchiveMembers, omittedArchiveMembers]
  );
  const { fontSize, rowLineHeight } = getLogListMetrics(logListFontSize);
  const summary =
    gaps.length > 0
      ? summarizeCoverageGaps(gaps)
      : `${archiveMembers.length} archive member${archiveMembers.length === 1 ? "" : "s"} in this view`;

  // The live region remains mounted so screen readers announce newly loaded gaps and member
  // provenance. An empty region stays unstyled and carries no children.
  const empty = gaps.length === 0 && archiveMemberMessages.length === 0;

  return (
    <div
      role="status"
      aria-live="polite"
      style={
        empty
          ? undefined
          : {
              flexShrink: 0,
              display: "flex",
              flexDirection: "column",
              gap: "4px",
              padding: "6px 12px",
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize,
              lineHeight: `${rowLineHeight}px`,
              color: tokens.colorPaletteDarkOrangeForeground1,
              backgroundColor: tokens.colorPaletteDarkOrangeBackground1,
              borderBottom: `1px solid ${tokens.colorPaletteDarkOrangeBorderActive}`,
            }
      }
    >
      {empty ? null : (
        <>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontWeight: tokens.fontWeightSemibold }}>{summary}</span>
            <Button
              size="small"
              appearance="transparent"
              aria-expanded={!collapsed}
              onClick={() => setCollapsed((value) => !value)}
            >
              {collapsed ? "Show" : "Hide"}
            </Button>
          </div>
          {!collapsed && (
            <>
              <div style={{ maxHeight: "200px", overflowY: "auto" }}>
                <ul style={{ margin: 0, paddingInlineStart: "20px" }}>
                  {displayedGaps.map((gap, index) => (
                    <li key={`${index}:${gap}`} style={{ wordBreak: "break-word" }}>
                      {gap}
                    </li>
                  ))}
                </ul>
                {omittedGaps > 0 && (
                  <div>{`<coverage gaps: ${omittedGaps} omitted by display limit>`}</div>
                )}
                {archiveMemberMessages.length > 0 && (
                  <details>
                    <summary>Archive member provenance ({archiveMembers.length})</summary>
                    <ul style={{ margin: 0, paddingInlineStart: "20px" }}>
                      {archiveMemberMessages.map((member, index) => (
                        <li
                          key={`archive-member-${index}:${member}`}
                          style={{ wordBreak: "break-word" }}
                        >
                          {member}
                        </li>
                      ))}
                    </ul>
                  </details>
                )}
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

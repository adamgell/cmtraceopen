import { useEffect, useMemo, useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { LockClosed16Regular } from "@fluentui/react-icons";
import { useEvtxStore } from "./evtx-store";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { useUiStore } from "../../stores/ui-store";
import { LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { readableOn } from "../../lib/color-contrast";
import { canOfferElevation, readElevationState } from "../../lib/elevation";
import { buildElevationRequest } from "../../lib/elevation-request";
import { getThemeById } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { resolveToken } from "./evtx-visual-tokens";
import { useRailTextColors } from "./evtx-rail-text";
import { formatCoverageGap, summarizeCoverageGaps } from "./evtx-coverage";
import type { EventLogSourceCoverage, EvtxArchiveMember, EvtxCoverageGap } from "./types";

const MAX_DISPLAYED_ARCHIVE_MEMBERS = 4_096;
const MAX_DISPLAYED_COVERAGE_GAPS = 100;
/** Notes shown one per channel in the rail; the rest are counted. */
export const MAX_COVERAGE_NOTES = 3;
const NOTE_TEXT_FLOOR = 4.5;

type EvtxCoverageBannerProps =
  | {
      /** The full gap list, drawn above the grid. */
      variant?: "grid";
      /**
       * The diagnosis could not be built, so the rail has no coverage disclosure: the banner then
       * stays above the grid even while the rail is shown.
       */
      diagnosisFailed?: boolean;
    }
  | {
      /** The Insights tab's coverage note (spec 8.13, item 2). */
      variant: "rail";
    };

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
 *
 * Two variants. `rail` is the coverage note in the Insights tab: one note per channel the backend
 * refused to read, with an Elevate action. `grid` is the full list above the grid. The rail's
 * coverage disclosure carries every gap kind, so the grid banner is drawn only while that
 * disclosure cannot be seen: the rail is hidden, or the diagnosis failed. Nothing else in the
 * workspace discloses a gap, so without this a hidden rail would present a partial load as whole.
 */
export function EvtxCoverageBanner(props: EvtxCoverageBannerProps) {
  return props.variant === "rail" ? (
    <CoverageNotes />
  ) : (
    <GridBanner diagnosisFailed={props.diagnosisFailed ?? false} />
  );
}

/**
 * The channels whose coverage gap is `accessDenied`, in first-reported order, each once.
 *
 * Reads the structured kinds only (the parser's gaps and the source manifest's coverage). Legacy
 * gap strings are left out on purpose: classifying them would mean matching their wording, and a
 * live channel refused with Windows error 5 or 1314 is reported as kind `record` until #931 maps
 * it to `accessDenied`. The name is the gap's source exactly: a live channel name, `machine/channel`
 * for a remote one, or the file path in files mode (an unreadable file has no channel name).
 */
export function accessDeniedChannels(
  coverageDetails: readonly EvtxCoverageGap[],
  manifestCoverage: readonly EventLogSourceCoverage[],
): string[] {
  const channels = new Set<string>();
  for (const gap of coverageDetails) {
    if (gap.kind === "accessDenied") channels.add(gap.source);
  }
  for (const coverage of manifestCoverage) {
    if (coverage.kind === "accessDenied") channels.add(coverage.path);
  }
  return [...channels];
}

export interface CoverageNoteColors {
  background: string;
  /** The sentence and the decorative lock icon. */
  text: string;
  /** The Elevate action. */
  action: string;
}

/**
 * Colors for the note, on its `colorNeutralBackground4` surface (spec 8.13).
 *
 * The designed colors are Foreground2 for the text and `colorBrandForegroundLink` for the action,
 * but on that surface Foreground2 measures 4.36:1 in solarized-dark and the link 4.12:1 in nord and
 * 4.35:1 in dracula, under the 4.5:1 text floor. Where a designed color misses, black or white
 * (whichever contrasts more) stands in, the Ambiguous badge's rule. Each theme's own values decide,
 * so a passing theme keeps the token and no token value changes. The action is also underlined, so
 * it still reads as an action where it falls back to the text's color family.
 */
export function pickCoverageNoteColors(theme: CMTraceTheme): CoverageNoteColors {
  const background = tokens.colorNeutralBackground4;
  const surface = resolveToken(background, theme);
  const keepOrFallback = (designed: string): string => {
    const resolved = resolveToken(designed, theme);
    const picked = readableOn(surface, resolved, NOTE_TEXT_FLOOR);
    return picked === resolved ? designed : picked;
  };
  return {
    background,
    text: keepOrFallback(tokens.colorNeutralForeground2),
    action: keepOrFallback(tokens.colorBrandForegroundLink),
  };
}

function useCoverageNoteColors(): CoverageNoteColors {
  const themeId = useUiStore((s) => s.themeId);
  return useMemo(() => pickCoverageNoteColors(getThemeById(themeId)), [themeId]);
}

/**
 * Whether elevation can be offered: Windows, not already elevated, and not back from an elevated
 * restart (the shared coordinator's rule). False until the probe answers, and when it fails. The
 * probe runs only while there is something to offer it for.
 */
function useElevationOffer(needed: boolean): boolean {
  const [offer, setOffer] = useState(false);
  useEffect(() => {
    if (!needed) return;
    let cancelled = false;
    void readElevationState().then((state) => {
      if (!cancelled) setOffer(canOfferElevation(state));
    });
    return () => {
      cancelled = true;
    };
  }, [needed]);
  return needed && offer;
}

/**
 * Opens the shared confirmation. A coverage recommendation, not a source retry, so only the
 * workspace is restored; the dialog says so. Never replaces a confirmation already on screen.
 */
function openElevationPrompt(): void {
  const ui = useUiStore.getState();
  if (ui.elevationPrompt) return;
  ui.setElevationPrompt({
    request: buildElevationRequest({
      reason: "coverageRecommended",
      workspace: "event-log",
      source: null,
    }),
  });
}

function useArchiveMemberMessages(archiveMembers: readonly EvtxArchiveMember[]): string[] {
  return useMemo(() => {
    const displayed = archiveMembers.slice(0, MAX_DISPLAYED_ARCHIVE_MEMBERS);
    const omitted = archiveMembers.length - displayed.length;
    return [
      ...displayed.map(
        ({ path, kind, outcome, sha256 }) =>
          `${path}: ${kind} ${outcome}${sha256 ? ` (sha256:${sha256})` : ""}`,
      ),
      ...(omitted > 0 ? [`<archive member metadata: ${omitted} omitted by display limit>`] : []),
    ];
  }, [archiveMembers]);
}

function ArchiveMemberList({ messages }: { messages: readonly string[] }) {
  return (
    <ul style={{ margin: 0, paddingInlineStart: "20px" }}>
      {messages.map((member, index) => (
        <li key={`archive-member-${index}:${member}`} style={{ wordBreak: "break-word" }}>
          {member}
        </li>
      ))}
    </ul>
  );
}

/**
 * The rail variant: one note per channel not read, then the archive member provenance.
 *
 * Not a live region (the spec gives it none). The lock icon is decorative; the sentence carries the
 * state, and each action is named for its channel. Hidden where elevation cannot help (already
 * elevated, or not Windows); the gap itself stays listed in the coverage disclosure below.
 */
function CoverageNotes() {
  const structuredGaps = useEvtxStore((s) => s.coverageDetails);
  const sourceManifest = useEvtxStore((s) => s.sourceManifest);
  const archiveMembers = useEvtxStore((s) => s.archiveMembers);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const colors = useCoverageNoteColors();
  const railText = useRailTextColors();
  const channels = useMemo(
    () => accessDeniedChannels(structuredGaps, sourceManifest?.coverage ?? []),
    [structuredGaps, sourceManifest],
  );
  const canElevate = useElevationOffer(channels.length > 0);
  const archiveMemberMessages = useArchiveMemberMessages(archiveMembers);
  const fontSize = Math.max(10, getLogListMetrics(logListFontSize).fontSize - 2);

  const shownChannels = canElevate ? channels.slice(0, MAX_COVERAGE_NOTES) : [];
  const omittedChannels = canElevate ? channels.length - shownChannels.length : 0;
  if (shownChannels.length === 0 && archiveMembers.length === 0) return null;

  return (
    <div style={{ display: "grid", gap: "8px", fontFamily: LOG_UI_FONT_FAMILY, fontSize: `${fontSize}px` }}>
      {shownChannels.length > 0 && (
        <section aria-label="Channels not read" style={{ display: "grid", gap: "6px" }}>
          {shownChannels.map((channel) => (
            <div
              key={channel}
              data-coverage-note={channel}
              style={{
                display: "flex",
                alignItems: "flex-start",
                gap: "8px",
                padding: "8px 10px",
                borderRadius: "6px",
                backgroundColor: colors.background,
                color: colors.text,
                lineHeight: 1.4,
              }}
            >
              <LockClosed16Regular
                aria-hidden="true"
                style={{ flexShrink: 0, marginTop: "1px", color: colors.text }}
              />
              <span style={{ flex: 1, minWidth: 0, wordBreak: "break-word" }}>
                {channel} channel not read. Findings may be incomplete.
              </span>
              <button
                type="button"
                aria-label={`Elevate to read ${channel}`}
                onClick={openElevationPrompt}
                style={{
                  flexShrink: 0,
                  padding: 0,
                  border: "none",
                  background: "none",
                  cursor: "pointer",
                  font: "inherit",
                  fontWeight: 600,
                  color: colors.action,
                  textDecoration: "underline",
                }}
              >
                Elevate
              </button>
            </div>
          ))}
          {omittedChannels > 0 && (
            <div style={{ color: railText.secondary }}>
              +{omittedChannels} more {omittedChannels === 1 ? "channel" : "channels"} not read
            </div>
          )}
        </section>
      )}
      {archiveMembers.length > 0 && (
        <details
          style={{
            padding: "8px 12px",
            borderRadius: "6px",
            backgroundColor: tokens.colorNeutralBackground1,
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            color: tokens.colorNeutralForeground2,
          }}
        >
          <summary
            style={{ cursor: "pointer", fontWeight: 600, color: tokens.colorNeutralForeground1 }}
          >
            Archive member provenance ({archiveMembers.length})
          </summary>
          <div style={{ marginTop: "8px", maxHeight: "200px", overflowY: "auto" }}>
            <ArchiveMemberList messages={archiveMemberMessages} />
          </div>
        </details>
      )}
    </div>
  );
}

function GridBanner({ diagnosisFailed }: { diagnosisFailed: boolean }) {
  const legacyGaps = useEvtxStore((s) => s.coverageGaps);
  const structuredGaps = useEvtxStore((s) => s.coverageDetails);
  const tailGaps = useEvtxStore((s) => s.tailCoverageGaps);
  const archiveMembers = useEvtxStore((s) => s.archiveMembers);
  const railShown = useEvtxLayoutStore((s) => s.panels.insights);
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
  const archiveMemberMessages = useArchiveMemberMessages(archiveMembers);

  // The rail's coverage disclosure lists every gap while the rail is shown and has a diagnosis.
  if (railShown && !diagnosisFailed) return null;

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
                    <ArchiveMemberList messages={archiveMemberMessages} />
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

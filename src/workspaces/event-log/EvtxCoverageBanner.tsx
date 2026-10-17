import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { Button, Tooltip, tokens } from "@fluentui/react-components";
import { LockClosed16Regular } from "@fluentui/react-icons";
import { useEvtxStore, type EvtxSourceMode } from "./evtx-store";
import { useUiStore } from "../../stores/ui-store";
import { LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { readableOn } from "../../lib/color-contrast";
import { canOfferElevation, readElevationState } from "../../lib/elevation";
import { buildElevationRequest } from "../../lib/elevation-request";
import { getThemeById } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { resolveToken } from "./evtx-visual-tokens";
import { useRailTextColors } from "./evtx-rail-text";
import {
  formatCoverageGap,
  legacyCoverageDisclosureKey,
  summarizeCoverageGaps,
} from "./evtx-coverage";
import { useCoverageClaim, useCoverageClaims } from "./evtx-coverage-claims";
import type { EventLogSourceCoverage, EvtxArchiveMember, EvtxCoverageGap } from "./types";

const MAX_DISPLAYED_ARCHIVE_MEMBERS = 4_096;
const NO_ARCHIVE_MEMBERS: readonly EvtxArchiveMember[] = [];
const MAX_DISPLAYED_COVERAGE_GAPS = 100;
/** Notes shown one per source in the rail; the rest are counted. */
export const MAX_COVERAGE_NOTES = 3;
const NOTE_TEXT_FLOOR = 4.5;

const VISUALLY_HIDDEN: CSSProperties = {
  position: "absolute",
  width: "1px",
  height: "1px",
  overflow: "hidden",
  clipPath: "inset(50%)",
  whiteSpace: "nowrap",
};

type EvtxCoverageBannerProps =
  | {
      /** The gap list above the grid: every current gap no other surface shows. */
      variant?: "grid";
    }
  | {
      /** The Insights tab's coverage note (spec 8.13, item 2) and the archive provenance. */
      variant: "rail";
      /** The Insights panel is on screen; the note claims what it draws only then. */
      visible: boolean;
    }
  | {
      /** The workspace's one polite live region for newly reported gaps. */
      variant: "announcer";
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
 * Every current gap is shown on exactly one rendered surface (evtx-coverage-claims.tsx). Three
 * variants, one export (the workspace tests replace this module with a single component):
 * - `grid`: the gaps, and the archive provenance, that no surface claims. Not drawn when every one
 *   is claimed.
 * - `rail`: the Insights tab's coverage note, one note per source the backend refused to read, plus
 *   the archive provenance. It claims what it draws while the Insights panel is on screen.
 * - `announcer`: a visually hidden polite live region, always mounted, that announces newly
 *   reported gaps whichever surface shows them.
 *
 * The channel pane (spec 8.6, Phase 8) will claim exactly the gaps its model attributes: its rows
 * plus its disclosure of gaps it cannot attribute to a channel. Gaps it leaves out, such as
 * inventory-only archive members, stay with the banner.
 */
export function EvtxCoverageBanner(props: EvtxCoverageBannerProps) {
  if (props.variant === "announcer") return <CoverageAnnouncer />;
  if (props.variant === "rail") return <CoverageNotes visible={props.visible} />;
  return <GridBanner />;
}

/** One current gap as the banner lists it: its shared key and the line shown for it. */
interface CoverageEntry {
  key: string;
  text: string;
}

/**
 * Every current gap, once per shared key, in the banner's order: legacy strings, live-tail strings,
 * then structured gaps. The first line seen for a key is the one shown.
 */
function useCoverageEntries(): CoverageEntry[] {
  const legacyGaps = useEvtxStore((s) => s.coverageGaps);
  const structuredGaps = useEvtxStore((s) => s.coverageDetails);
  const tailGaps = useEvtxStore((s) => s.tailCoverageGaps);
  return useMemo(() => {
    const entries = new Map<string, string>();
    const add = (key: string, text: string) => {
      if (!entries.has(key)) entries.set(key, text);
    };
    for (const gap of legacyGaps) add(legacyCoverageDisclosureKey(gap, "legacy"), gap);
    for (const gap of tailGaps) add(legacyCoverageDisclosureKey(gap, "tail"), gap);
    for (const gap of structuredGaps) {
      const line = formatCoverageGap(gap);
      add(line, line);
    }
    return [...entries].map(([key, text]) => ({ key, text }));
  }, [legacyGaps, tailGaps, structuredGaps]);
}

/**
 * The sources whose coverage gap is `accessDenied`, in first-reported order, each once, with the
 * shared keys of every such gap behind it.
 *
 * Reads the structured kinds only (the parser's gaps and the source manifest's coverage). Legacy
 * gap strings are left out on purpose: classifying them would mean matching their wording, and a
 * live channel refused with Windows error 5 or 1314 is reported as kind `record` until #931 maps
 * it to `accessDenied`.
 */
export function accessDeniedSources(
  coverageDetails: readonly EvtxCoverageGap[],
  manifestCoverage: readonly EventLogSourceCoverage[],
): { source: string; manifest: boolean; keys: string[] }[] {
  const sources = new Map<string, { manifest: boolean; keys: Set<string> }>();
  const note = (source: string, key: string, manifest: boolean) => {
    const entry = sources.get(source) ?? { manifest: false, keys: new Set<string>() };
    entry.manifest ||= manifest;
    entry.keys.add(key);
    sources.set(source, entry);
  };
  for (const gap of coverageDetails) {
    if (gap.kind === "accessDenied") note(gap.source, formatCoverageGap(gap), false);
  }
  for (const coverage of manifestCoverage) {
    if (coverage.kind === "accessDenied") {
      note(
        coverage.path,
        formatCoverageGap({ source: coverage.path, kind: coverage.kind, reason: coverage.reason }),
        true,
      );
    }
  }
  return [...sources].map(([source, { manifest, keys }]) => ({
    source,
    manifest,
    keys: [...keys],
  }));
}

/** How a note names its source. Display only: the `accessDenied` kind alone decides a note. */
export type CoverageNoteSubject =
  | { kind: "channel"; source: string; channel: string }
  | { kind: "file"; source: string; fileName: string }
  | { kind: "remote"; source: string; machine: string; channel: string };

/** A drive-letter, UNC or POSIX absolute path. Channel names never take one of these forms. */
function isAbsolutePath(source: string): boolean {
  return /^(?:[A-Za-z]:[\\/]|[\\/]{2}|\/)/.test(source);
}

/** Splits on both separators so a Windows path is handled on any host. */
function baseName(path: string): string {
  const segments = path.split(/[\\/]+/).filter((segment) => segment.length > 0);
  return segments[segments.length - 1] ?? path;
}

/**
 * Names one unread source. A file (a manifest row or an absolute path) has no channel, so it is
 * named by its base name. A live read of a remote machine reports `machine/channel`; elevating
 * this app does not change the credentials used there, so it is kept apart from a local channel.
 */
export function coverageNoteSubject(
  { source, manifest }: { source: string; manifest: boolean },
  { sourceMode, remoteMachine }: { sourceMode: EvtxSourceMode; remoteMachine: string | null },
): CoverageNoteSubject {
  if (manifest || isAbsolutePath(source)) {
    return { kind: "file", source, fileName: baseName(source) };
  }
  if (sourceMode === "live" && remoteMachine) {
    const prefix = `${remoteMachine}/`;
    const channel = source.startsWith(prefix) ? source.slice(prefix.length) : source;
    return { kind: "remote", source, machine: remoteMachine, channel };
  }
  return { kind: "channel", source, channel: source };
}

function noteSentence(subject: CoverageNoteSubject): string {
  switch (subject.kind) {
    case "channel":
      return `${subject.channel} channel not read. Findings may be incomplete.`;
    case "file":
      return `${subject.fileName} not read. Findings may be incomplete.`;
    case "remote":
      return `${subject.channel} channel on ${subject.machine} not read. Findings may be incomplete.`;
  }
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
 * probe runs only while there is a local source to offer it for.
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

function omittedGapsLine(omitted: number): string {
  return `<coverage gaps: ${omitted} omitted by display limit>`;
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
 * Announces gaps as they are reported, once each, as the lines the banner shows for them. Only the
 * newly added lines are in the region (`role="status"` is read as a whole), and an update that adds
 * nothing empties it, so nothing stale is left to be read. A gap that goes away is forgotten, so it
 * is announced again if it is reported again. The region starts empty and fills after mounting, so
 * the first gaps are announced too.
 */
function CoverageAnnouncer() {
  const entries = useCoverageEntries();
  const announcedRef = useRef<ReadonlySet<string>>(new Set());
  const [fresh, setFresh] = useState<readonly string[]>([]);

  useEffect(() => {
    const announced = announcedRef.current;
    const added = entries.filter((entry) => !announced.has(entry.key));
    announcedRef.current = new Set(entries.map((entry) => entry.key));
    setFresh((current) =>
      added.length === 0 && current.length === 0 ? current : added.map((entry) => entry.text),
    );
  }, [entries]);

  const shown = fresh.slice(0, MAX_DISPLAYED_COVERAGE_GAPS);
  const omitted = fresh.length - shown.length;
  return (
    <div role="status" aria-live="polite" data-coverage-announcer="" style={VISUALLY_HIDDEN}>
      {shown.map((line, index) => (
        <div key={`${index}:${line}`}>{line}</div>
      ))}
      {omitted > 0 && <div>{omittedGapsLine(omitted)}</div>}
    </div>
  );
}

/**
 * The rail variant: one note per source not read, then the archive member provenance.
 *
 * Not a live region (the spec gives it none; the announcer speaks for every surface). The lock icon
 * is decorative; the sentence carries the state. A local channel or a file gets an Elevate action
 * named for it, and is hidden where elevation cannot help (already elevated, or not Windows); a
 * remote channel's note has no action, since elevating here does not change the remote
 * credentials. While the Insights panel is on screen it claims the gaps behind the notes it draws
 * (not the "+N more" ones) and the provenance; the gap itself also stays in the coverage disclosure
 * once a summary covers it.
 */
function CoverageNotes({ visible }: { visible: boolean }) {
  const structuredGaps = useEvtxStore((s) => s.coverageDetails);
  const sourceManifest = useEvtxStore((s) => s.sourceManifest);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const archiveMembers = useEvtxStore((s) => s.archiveMembers);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const colors = useCoverageNoteColors();
  const railText = useRailTextColors();
  const sources = useMemo(
    () => accessDeniedSources(structuredGaps, sourceManifest?.coverage ?? []),
    [structuredGaps, sourceManifest],
  );
  const subjects = useMemo(
    () =>
      sources.map((entry) => ({
        subject: coverageNoteSubject(entry, { sourceMode, remoteMachine }),
        keys: entry.keys,
      })),
    [sources, sourceMode, remoteMachine],
  );
  const canElevate = useElevationOffer(
    subjects.some(({ subject }) => subject.kind !== "remote"),
  );
  const archiveMemberMessages = useArchiveMemberMessages(archiveMembers);
  const fontSize = Math.max(10, getLogListMetrics(logListFontSize).fontSize - 2);

  const noted = useMemo(
    () => subjects.filter(({ subject }) => subject.kind === "remote" || canElevate),
    [subjects, canElevate],
  );
  const shown = useMemo(() => noted.slice(0, MAX_COVERAGE_NOTES), [noted]);
  const omitted = noted.length - shown.length;
  const showsProvenance = archiveMembers.length > 0;

  const claim = useMemo(
    () =>
      visible
        ? {
            keys: new Set(shown.flatMap(({ keys }) => keys)),
            archiveProvenance: showsProvenance,
          }
        : null,
    [visible, shown, showsProvenance],
  );
  useCoverageClaim(claim);

  if (shown.length === 0 && !showsProvenance) return null;

  return (
    <div style={{ display: "grid", gap: "8px", fontFamily: LOG_UI_FONT_FAMILY, fontSize: `${fontSize}px` }}>
      {shown.length > 0 && (
        <section aria-label="Channels not read" style={{ display: "grid", gap: "6px" }}>
          {shown.map(({ subject }) => (
            <div
              key={subject.source}
              data-coverage-note={subject.source}
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
                {noteSentence(subject)}
              </span>
              {subject.kind !== "remote" && (
                <ElevateAction subject={subject} color={colors.action} />
              )}
            </div>
          ))}
          {omitted > 0 && (
            <div style={{ color: railText.secondary }}>
              +{omitted} more {omitted === 1 ? "channel" : "channels"} not read
            </div>
          )}
        </section>
      )}
      {showsProvenance && (
        <details
          data-archive-provenance=""
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

/** The note's Elevate action. A file's full path is its tooltip (and its description). */
function ElevateAction({
  subject,
  color,
}: {
  subject: Exclude<CoverageNoteSubject, { kind: "remote" }>;
  color: string;
}) {
  const name = subject.kind === "file" ? subject.fileName : subject.channel;
  const button = (
    <button
      type="button"
      aria-label={`Elevate to read ${name}`}
      onClick={openElevationPrompt}
      style={{
        flexShrink: 0,
        padding: 0,
        border: "none",
        background: "none",
        cursor: "pointer",
        font: "inherit",
        fontWeight: 600,
        color,
        textDecoration: "underline",
      }}
    >
      Elevate
    </button>
  );
  return subject.kind === "file" ? (
    <Tooltip content={subject.source} relationship="description">
      {button}
    </Tooltip>
  ) : (
    button
  );
}

/**
 * The gaps, and the archive provenance, that no surface claims. Its count counts what it lists.
 * Not a live region: the announcer speaks for every surface.
 */
function GridBanner() {
  const entries = useCoverageEntries();
  const claims = useCoverageClaims();
  const archiveMembers = useEvtxStore((s) => s.archiveMembers);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const [collapsed, setCollapsed] = useState(false);

  const gaps = useMemo(
    () => entries.filter((entry) => !claims.keys.has(entry.key)).map((entry) => entry.text),
    [entries, claims],
  );
  const displayedGaps = useMemo(
    () => gaps.slice(0, MAX_DISPLAYED_COVERAGE_GAPS),
    [gaps],
  );
  const omittedGaps = gaps.length - displayedGaps.length;
  const archiveMemberMessages = useArchiveMemberMessages(
    claims.archiveProvenance ? NO_ARCHIVE_MEMBERS : archiveMembers,
  );
  const provenanceCount = claims.archiveProvenance ? 0 : archiveMembers.length;

  if (gaps.length === 0 && archiveMemberMessages.length === 0) return null;

  const { fontSize, rowLineHeight } = getLogListMetrics(logListFontSize);
  const summary =
    gaps.length > 0
      ? summarizeCoverageGaps(gaps)
      : `${provenanceCount} archive member${provenanceCount === 1 ? "" : "s"} in this view`;

  return (
    <div
      data-coverage-banner=""
      style={{
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
      }}
    >
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
        <div style={{ maxHeight: "200px", overflowY: "auto" }}>
          <ul style={{ margin: 0, paddingInlineStart: "20px" }}>
            {displayedGaps.map((gap, index) => (
              <li key={`${index}:${gap}`} style={{ wordBreak: "break-word" }}>
                {gap}
              </li>
            ))}
          </ul>
          {omittedGaps > 0 && <div>{omittedGapsLine(omittedGaps)}</div>}
          {archiveMemberMessages.length > 0 && (
            <details data-archive-provenance="">
              <summary>Archive member provenance ({provenanceCount})</summary>
              <ArchiveMemberList messages={archiveMemberMessages} />
            </details>
          )}
        </div>
      )}
    </div>
  );
}

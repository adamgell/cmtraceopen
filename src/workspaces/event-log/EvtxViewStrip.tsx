/**
 * The view strip (spec 8.15, Q-5): one card per saved set of filters, the built-in "Enrollment
 * triage" first, a dashed "New view" button, and the source line on the right.
 *
 * A card applies its view. Which card is active is DERIVED, never remembered: a view is active
 * while the criteria on screen equal its own (`viewMatchesCriteria`), so editing a filter, a Stop
 * that restores the time window, a source change or a cleared channel turns it off with no code of
 * its own. Layout is not part of that test (filters persist across layout switches, spec 9) and the
 * transient criteria are not on the criteria shape.
 *
 * What a view cannot show is said, not left as an empty grid: an active view whose channels are not
 * loaded (live) or not in the files says how many.
 */
import {
  useCallback,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
} from "react";
import {
  createFocusOutlineStyle,
  makeStyles,
  mergeClasses,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { Add16Regular } from "@fluentui/react-icons";
import { contrastRatio, readableOn } from "../../lib/color-contrast";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getThemeById } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import { applyView } from "./evtx-criteria-actions";
import { EvtxNewViewDialog } from "./EvtxViewDialogs";
import { useFilterChips } from "./EvtxFilterChips";
import { useEvtxLayoutStore } from "./evtx-layout-store";
import { captureCriteria } from "./evtx-saved-filters";
import { eventLogSourceLabel } from "./evtx-source-label";
import { useEvtxStore } from "./evtx-store";
import {
  captureLayout,
  listViews,
  missingViewChannels,
  viewDescription,
  viewMatchesCriteria,
  viewSubtitle,
  type EvtxView,
} from "./evtx-views";
import { useEvtxViewStore, type EvtxViewFailure } from "./evtx-views-store";
import { resolveToken, useEvtxVisualTokens } from "./evtx-visual-tokens";

const NEW_VIEW_ID = "__new-view__";

const MIN_TEXT_CONTRAST = 4.5;

/**
 * The secondary text color (spec 8.15 names fg3 for the subtitle, the eyebrow and the source line):
 * the theme's third-level foreground where it reaches 4.5:1 on the strip, and otherwise the next
 * stronger neutral that does. fg3 measures 3.37:1 in solarized-dark and 3.03:1 in dracula, and token
 * values are never changed here, so the rendering steps up instead.
 */
export function evtxStripMutedTextColor(theme: CMTraceTheme): string {
  const surface = resolveToken(tokens.colorNeutralBackground1, theme);
  for (const token of [tokens.colorNeutralForeground3, tokens.colorNeutralForeground2]) {
    const color = resolveToken(token, theme);
    if (contrastRatio(color, surface) >= MIN_TEXT_CONTRAST) return color;
  }
  return readableOn(surface, resolveToken(tokens.colorNeutralForeground1, theme), MIN_TEXT_CONTRAST);
}

const useStyles = makeStyles({
  card: {
    display: "inline-flex",
    alignItems: "center",
    columnGap: "6px",
    boxSizing: "border-box",
    // Spec 8.15: radius 6, padding 4px 10px, a 1 px border.
    ...shorthands.padding("4px", "10px"),
    ...shorthands.borderRadius(tokens.borderRadiusLarge),
    ...shorthands.border("1px", "solid", "transparent"),
    fontFamily: "inherit",
    fontSize: "inherit",
    lineHeight: "inherit",
    whiteSpace: "nowrap",
    cursor: "pointer",
    ...createFocusOutlineStyle({ style: { outlineRadius: tokens.borderRadiusLarge } }),
  },
  // The inactive look is classes; the active card is inline, in the selection colors. Hover shows
  // in the border, not the fill: the text colors are guaranteed against the strip surface, and a
  // hover fill is a second surface they would have to clear in every theme (it does not in
  // high contrast, solarized-dark or dracula).
  idle: {
    backgroundColor: "transparent",
    color: tokens.colorNeutralForeground1,
    ...shorthands.borderColor(tokens.colorNeutralStroke1),
    ":hover": { ...shorthands.borderColor(tokens.colorNeutralStroke1Hover) },
  },
  newView: {
    columnGap: "4px",
    backgroundColor: "transparent",
    color: tokens.colorNeutralForeground2,
    ...shorthands.borderStyle("dashed"),
    ...shorthands.borderColor(tokens.colorNeutralStroke1),
    ":hover": { ...shorthands.borderColor(tokens.colorNeutralStroke1Hover) },
  },
  visuallyHidden: {
    position: "absolute",
    width: "1px",
    height: "1px",
    overflow: "hidden",
    clipPath: "inset(50%)",
    whiteSpace: "nowrap",
  },
});

export function EvtxViewStrip() {
  const styles = useStyles();
  const { selection } = useEvtxVisualTokens();
  const themeId = useUiStore((s) => s.themeId);
  const mutedText = useMemo(() => evtxStripMutedTextColor(getThemeById(themeId)), [themeId]);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  // Spec 8.15: f - 2 for the cards, on one line (about 24 px a card, 30 px with the strip's padding);
  // the eyebrow is the 7.1 treatment, max(10, f - 3).
  const fontPx = Math.max(10, metrics.fontSize - 2);
  const fontSize = `${fontPx}px`;
  const lineHeight = `${Math.round(fontPx * 1.3)}px`;
  const eyebrowSize = `${Math.max(10, metrics.fontSize - 3)}px`;
  const dialogFontSize = `${Math.max(11, metrics.fontSize - 1)}px`;

  const custom = useEvtxViewStore((s) => s.views);
  const views = useMemo(() => listViews(custom), [custom]);

  // The criteria on screen, as a saved filter would capture them.
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const filterSearchDraft = useEvtxStore((s) => s.filterSearchDraft);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const quickFilterDraft = useEvtxStore((s) => s.quickFilterDraft);
  const groupBy = useEvtxStore((s) => s.groupBy);
  const current = useMemo(
    () =>
      captureCriteria({
        filterLevels,
        filterEventIds,
        timeWindow,
        selectedChannels,
        filterSearch,
        filterSearchDraft,
        quickFilter,
        quickFilterDraft,
        groupBy,
      }),
    [
      filterLevels,
      filterEventIds,
      timeWindow,
      selectedChannels,
      filterSearch,
      filterSearchDraft,
      quickFilter,
      quickFilterDraft,
      groupBy,
    ],
  );
  const activeIds = useMemo(
    () => new Set(views.filter((view) => viewMatchesCriteria(view, current)).map((view) => view.id)),
    [views, current],
  );

  // Which channels the source holds: the loaded ones live, every channel in the files otherwise.
  // The chip row's own answer, so the two cannot disagree (and it holds still through a refetch).
  const { heldChannels } = useFilterChips();
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const records = useEvtxStore((s) => s.records);
  const sourceLabel = useMemo(
    () => eventLogSourceLabel({ sourceMode, remoteMachine, records }),
    [sourceMode, remoteMachine, records],
  );
  const absence = sourceMode === "live" ? "not loaded" : "not in these files";

  // Polite, one node per message, so a repeated message is announced again.
  const [announcement, setAnnouncement] = useState({ id: 0, text: "" });
  const announce = useCallback(
    (text: string) => setAnnouncement((previous) => ({ id: previous.id + 1, text })),
    [],
  );

  const applyAndAnnounce = (view: EvtxView) => {
    const missing = missingViewChannels(view, heldChannels).length;
    applyView(view);
    announce(
      missing > 0
        ? `Applied ${view.name}. ${missing} of its ${missing === 1 ? "channel is" : "channels are"} ${absence}.`
        : `Applied ${view.name}.`,
    );
  };

  // One tab stop for the whole toolbar, and arrows between its items (the layout tablist's pattern).
  const itemIds = useMemo(() => [...views.map((view) => view.id), NEW_VIEW_ID], [views]);
  const [tabStop, setTabStop] = useState<string | null>(null);
  const firstActive = views.find((view) => activeIds.has(view.id))?.id;
  const stop = tabStop !== null && itemIds.includes(tabStop) ? tabStop : (firstActive ?? itemIds[0]);
  const itemRefs = useRef<Record<string, HTMLButtonElement | null>>({});
  const focusItem = (id: string) => itemRefs.current[id]?.focus();
  const onToolbarKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const target = event.target as HTMLElement;
    const id = target.closest<HTMLElement>("[data-evtx-view-item]")?.dataset.evtxViewItem;
    if (id === undefined) return;
    const index = itemIds.indexOf(id);
    let next: number;
    switch (event.key) {
      case "ArrowRight":
        next = (index + 1) % itemIds.length;
        break;
      case "ArrowLeft":
        next = (index - 1 + itemIds.length) % itemIds.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = itemIds.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    focusItem(itemIds[next]);
  };

  const [newOpen, setNewOpen] = useState(false);
  const closeNew = () => {
    setNewOpen(false);
    // Back to the button that opened it, whether the dialog saved or was cancelled.
    setTimeout(() => focusItem(NEW_VIEW_ID), 0);
  };
  const saveNew = (name: string, includeLayout: boolean): EvtxViewFailure | null => {
    const result = useEvtxViewStore
      .getState()
      .create(
        name,
        captureCriteria(useEvtxStore.getState()),
        includeLayout ? captureLayout(useEvtxLayoutStore.getState()) : null,
      );
    if (!result.ok) return result.reason;
    announce(`Saved view ${result.view.name}.`);
    return null;
  };

  const activeStyle: CSSProperties = {
    backgroundColor: selection.background,
    borderColor: selection.border,
    color: selection.foreground,
  };

  return (
    <div
      data-evtx-region="view-strip"
      style={{
        display: "flex",
        alignItems: "center",
        flexWrap: "wrap",
        columnGap: "6px",
        rowGap: "4px",
        padding: "6px 12px 0",
        flexShrink: 0,
        backgroundColor: tokens.colorNeutralBackground1,
        fontSize,
        lineHeight,
      }}
    >
      <span
        aria-hidden
        style={{
          fontSize: eyebrowSize,
          fontWeight: 600,
          letterSpacing: ".08em",
          textTransform: "uppercase",
          color: mutedText,
        }}
      >
        Views
      </span>
      <div
        role="toolbar"
        aria-label="Views"
        onKeyDown={onToolbarKeyDown}
        style={{ display: "flex", flexWrap: "wrap", alignItems: "center", columnGap: "6px", rowGap: "4px" }}
      >
        {views.map((view) => {
          const active = activeIds.has(view.id);
          const missing = active ? missingViewChannels(view, heldChannels).length : 0;
          const subtitle =
            missing > 0
              ? `${viewSubtitle(view)} · ${missing} ${missing === 1 ? "channel" : "channels"} ${absence}`
              : viewSubtitle(view);
          const subtitleId = `evtx-view-subtitle-${view.id}`;
          return (
            <button
              key={view.id}
              ref={(element) => {
                itemRefs.current[view.id] = element;
              }}
              type="button"
              className={mergeClasses(styles.card, !active && styles.idle)}
              style={active ? activeStyle : undefined}
              aria-pressed={active}
              aria-label={view.name}
              aria-describedby={subtitleId}
              title={viewDescription(view)}
              tabIndex={stop === view.id ? 0 : -1}
              data-evtx-view-item={view.id}
              data-evtx-view-card={view.builtIn ? "built-in" : "custom"}
              onFocus={() => setTabStop(view.id)}
              onClick={() => applyAndAnnounce(view)}
            >
              <span style={{ fontWeight: 600 }}>{view.name}</span>
              <span
                id={subtitleId}
                style={{ color: active ? selection.foreground : mutedText }}
              >
                {subtitle}
              </span>
            </button>
          );
        })}
        <button
          ref={(element) => {
            itemRefs.current[NEW_VIEW_ID] = element;
          }}
          type="button"
          className={mergeClasses(styles.card, styles.newView)}
          tabIndex={stop === NEW_VIEW_ID ? 0 : -1}
          data-evtx-view-item={NEW_VIEW_ID}
          onFocus={() => setTabStop(NEW_VIEW_ID)}
          onClick={() => setNewOpen(true)}
        >
          <Add16Regular aria-hidden />
          New view
        </button>
      </div>
      {sourceLabel && (
        <span
          data-evtx-view-source
          style={{ marginLeft: "auto", whiteSpace: "nowrap", color: mutedText }}
        >
          {sourceLabel}
        </span>
      )}
      <span role="status" aria-live="polite" className={styles.visuallyHidden}>
        {announcement.text && <span key={announcement.id}>{announcement.text}</span>}
      </span>
      <EvtxNewViewDialog open={newOpen} fontSize={dialogFontSize} onClose={closeNew} onSave={saveNew} />
    </div>
  );
}

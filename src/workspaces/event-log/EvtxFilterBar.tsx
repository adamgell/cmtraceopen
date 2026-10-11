/**
 * The workbench filter row (spec section 8.3): search, level toggles with counts, the time window
 * and the "More filters" entry point. The active-criteria chips live in `EvtxFilterChips`.
 *
 * Everything the old single bar offered is still reachable. Group by, Columns and Export moved to
 * the view bar in Phase 3. Event IDs, the quick filter, saved filters, sort and the time zone are
 * in the More filters popover (`EvtxMoreFilters`), one open away.
 *
 * Do the level toggles re-query in live mode? Only when they change what the service is asked for
 * (verified in Phase 5, issue #832). In live mode with a loaded channel, a before-load change that
 * alters `serverFilterKey` makes the store refetch every loaded channel: it empties `records` and
 * sets `isLoading`. While Information is selected the level predicate is never sent
 * (`levelsFilteredAtSource`), so toggling any other level is a local filter and nothing reloads;
 * toggling Information, or a level while it is deselected, changes the pushed subset and reloads.
 * File mode never reloads. The row says which toggles reload (tooltip and description). The
 * workspace keeps this row mounted through a refresh, so while it runs the group is `aria-busy`, a
 * spinner shows beside it and the counts read as not available rather than zero.
 */
import { useMemo, type CSSProperties } from "react";
import {
  Badge,
  createCustomFocusIndicatorStyle,
  createFocusOutlineStyle,
  Dropdown,
  Input,
  Option,
  Spinner,
  makeStyles,
  mergeClasses,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import { Search16Regular } from "@fluentui/react-icons";
import {
  countByLevel,
  EVTX_LEVELS,
  levelsAfterToggle,
  levelsFilteredAtSource,
} from "./evtx-filter";
import {
  LEVEL_TOGGLE_BACKGROUNDS,
  LEVEL_TOGGLE_STATES,
  levelToggleStates,
  type LevelToggleState,
  type LevelToggleStateVisual,
} from "./evtx-level-toggle";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";
import { EVTX_SEARCH_INPUT_ID } from "./EvtxFilterChips";
import { EvtxMoreFilters } from "./EvtxMoreFilters";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { serverFilterKey, useEvtxStore } from "./evtx-store";
import type { EvtxLevel, EvtxTimeWindow } from "./types";
import { EVTX_TIME_WINDOW_LABELS } from "./types";

const TIME_WINDOWS: EvtxTimeWindow[] = ["1h", "24h", "7d", "30d", "all"];

/** Spec 8.3 labels. "Info" is the short form of Information only here; the rest read in full. */
const LEVEL_TOGGLE_LABELS: Record<EvtxLevel, string> = {
  Critical: "Critical",
  Error: "Error",
  Warning: "Warning",
  Information: "Info",
  Verbose: "Verbose",
};

/**
 * Shown in place of a count that is not available: the spec's glyph for a value with no source
 * (section 15.1), written as an escape. Never zero: unknown is not "none".
 */
const UNKNOWN_COUNT = "\u2014";
const UNKNOWN_COUNT_TEXT = "Count not available";

const RELOAD_NOTE = "Changing this level reloads the loaded channels from the live log.";

/** Plain class names on the dot and the count, so a toggle's state rules can reach them. */
const DOT_CLASS = "evtx-level-dot";
const COUNT_CLASS = "evtx-level-count";

/**
 * Windows contrast themes. The theme colors above do not apply there: the browser forces every
 * color to a system color, which would leave a pressed toggle with only its heavier weight and
 * drop the dots. Fluent's own checked ToggleButton answers the same way (Highlight and
 * HighlightText), and so does this: a pressed toggle is a Highlight block, every dot keeps its
 * level color inside a CanvasText ring, and a dot on a pressed toggle rings in HighlightText.
 */
const FORCED_COLORS = "@media (forced-colors: active)";
// Fluent's focus ring is a Highlight pseudo-element, and on a Highlight block it would disappear into
// the block (the block is not forced-color-adjusted, so the theme would not rescue it). CanvasText
// is drawn against the page behind the ring and the block.
const FORCED_PRESSED_FOCUS = createCustomFocusIndicatorStyle({
  "::after": { ...shorthands.borderColor("CanvasText") },
});
const FORCED_PRESSED = {
  backgroundColor: "Highlight",
  ...shorthands.borderColor("Highlight"),
  color: "HighlightText",
  forcedColorAdjust: "none",
  [`& .${COUNT_CLASS}`]: { color: "HighlightText" },
  [`& .${DOT_CLASS}`]: { outlineColor: "HighlightText" },
} as const;

const useStyles = makeStyles({
  levelGroup: {
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
  },
  // The colors per state are CSS custom properties set on the group, because Griffel styles are
  // static and the label, count and ring colors are resolved per theme (`evtx-level-toggle.ts`).
  // The surfaces are the same Fluent tokens that module measures. Every state is written out here,
  // so no Fluent hover or checked rule is left to pair a surface with a color nobody measured.
  toggle: {
    position: "relative",
    display: "inline-flex",
    alignItems: "center",
    gap: "5px",
    height: "26px",
    boxSizing: "border-box",
    paddingLeft: "9px",
    paddingRight: "9px",
    paddingTop: "0",
    paddingBottom: "0",
    border: `1px solid ${tokens.colorNeutralStroke1}`,
    borderRadius: tokens.borderRadiusMedium,
    cursor: "pointer",
    fontFamily: "inherit",
    fontWeight: 400,
    whiteSpace: "nowrap",
    backgroundColor: LEVEL_TOGGLE_BACKGROUNDS.rest,
    color: "var(--evtx-level-label-rest)",
    [`& .${COUNT_CLASS}`]: { color: "var(--evtx-level-count-rest)" },
    [`& .${DOT_CLASS}`]: { outlineColor: "transparent" },
    ":hover": {
      backgroundColor: LEVEL_TOGGLE_BACKGROUNDS.hover,
      ...shorthands.borderColor(tokens.colorNeutralStroke1Hover),
      color: "var(--evtx-level-label-hover)",
      [`& .${COUNT_CLASS}`]: { color: "var(--evtx-level-count-hover)" },
      [`& .${DOT_CLASS}`]: { outlineColor: "var(--evtx-level-ring-hover)" },
    },
    // `:active` covers a held mouse button and a held Space bar alike.
    ":active": {
      backgroundColor: LEVEL_TOGGLE_BACKGROUNDS.active,
      ...shorthands.borderColor(tokens.colorNeutralStroke1Pressed),
      color: "var(--evtx-level-label-active)",
      [`& .${COUNT_CLASS}`]: { color: "var(--evtx-level-count-active)" },
      [`& .${DOT_CLASS}`]: { outlineColor: "var(--evtx-level-ring-active)" },
    },
    // Fluent's default focus indicator, a ring drawn around this positioned box.
    ...createFocusOutlineStyle(),
    [FORCED_COLORS]: {
      [`& .${DOT_CLASS}`]: { outlineColor: "CanvasText" },
      ":hover": { [`& .${DOT_CLASS}`]: { outlineColor: "CanvasText" } },
      ":active": { [`& .${DOT_CLASS}`]: { outlineColor: "CanvasText" } },
    },
  },
  // The level is shown. Hover and mouse-down keep the selection surface, so the dot's ring is
  // measured against one surface for all three.
  pressed: {
    fontWeight: 600,
    ...shorthands.borderColor(tokens.colorNeutralStroke1),
    backgroundColor: LEVEL_TOGGLE_BACKGROUNDS.pressed,
    color: "var(--evtx-level-label-pressed)",
    [`& .${COUNT_CLASS}`]: { color: "var(--evtx-level-count-pressed)" },
    [`& .${DOT_CLASS}`]: { outlineColor: "var(--evtx-level-ring-pressed)" },
    ":hover": {
      backgroundColor: LEVEL_TOGGLE_BACKGROUNDS.pressed,
      ...shorthands.borderColor(tokens.colorNeutralStroke1),
      color: "var(--evtx-level-label-pressed)",
      [`& .${COUNT_CLASS}`]: { color: "var(--evtx-level-count-pressed)" },
      [`& .${DOT_CLASS}`]: { outlineColor: "var(--evtx-level-ring-pressed)" },
    },
    ":active": {
      backgroundColor: LEVEL_TOGGLE_BACKGROUNDS.pressed,
      ...shorthands.borderColor(tokens.colorNeutralStroke1),
      color: "var(--evtx-level-label-pressed)",
      [`& .${COUNT_CLASS}`]: { color: "var(--evtx-level-count-pressed)" },
      [`& .${DOT_CLASS}`]: { outlineColor: "var(--evtx-level-ring-pressed)" },
    },
    // Hover and mouse-down repeat the block: the rules above are pseudo-class rules and would
    // otherwise out-rank the base one and paint the theme's selection surface.
    [FORCED_COLORS]: {
      ...FORCED_PRESSED,
      ":hover": FORCED_PRESSED,
      ":active": FORCED_PRESSED,
      ...FORCED_PRESSED_FOCUS,
    },
  },
  dot: {
    width: "8px",
    height: "8px",
    flexShrink: 0,
    borderRadius: "50%",
    outlineStyle: "solid",
    outlineWidth: "1px",
    outlineColor: "transparent",
    // Keeps the level color; the ring is what the forced palette draws.
    [FORCED_COLORS]: { forcedColorAdjust: "none" },
  },
  count: {
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
    fontWeight: 400,
  },
  visuallyHidden: {
    position: "absolute",
    width: "1px",
    height: "1px",
    overflow: "hidden",
    clipPath: "inset(50%)",
    whiteSpace: "nowrap",
  },
  // Fluent's outline Input draws its bottom edge in colorNeutralStrokeAccessible; spec 8.3 asks for a
  // plain 1 px colorNeutralStroke1 border all round, so only the bottom edge is overridden here.
  search: {
    borderBottomColor: tokens.colorNeutralStroke1,
    ":hover": { borderBottomColor: tokens.colorNeutralStroke1Hover },
    // The key must match Fluent's own (no space after the comma) so that this replaces its class.
    ":active,:focus-within": { borderBottomColor: tokens.colorNeutralStroke1Pressed },
  },
  searchSlot: {
    display: "flex",
    flexDirection: "column",
    gap: "2px",
    flexGrow: 1,
    flexShrink: 1,
    flexBasis: "280px",
    minWidth: "200px",
  },
});

export function eventLogTimeWindowSnapshotLabel(
  timeWindow: EvtxTimeWindow,
  nowEpoch: number,
): string {
  const label = EVTX_TIME_WINDOW_LABELS[timeWindow];
  return timeWindow === "all"
    ? label
    : `${label} · as of ${new Date(nowEpoch).toLocaleString()}`;
}

/** The measured state colors as the custom properties the toggle styles read. */
function toggleColorVariables(
  states: Record<LevelToggleState, LevelToggleStateVisual>,
): CSSProperties {
  const variables: Record<string, string> = {};
  for (const state of LEVEL_TOGGLE_STATES) {
    variables[`--evtx-level-label-${state}`] = states[state].label;
    variables[`--evtx-level-count-${state}`] = states[state].count;
    variables[`--evtx-level-ring-${state}`] = states[state].dotRing ?? "transparent";
  }
  return variables as CSSProperties;
}

interface EvtxFilterBarProps {
  nowEpoch: number;
}

export function EvtxFilterBar({ nowEpoch }: EvtxFilterBarProps) {
  const styles = useStyles();
  const records = useEvtxStore((s) => s.records);
  const filterLevels = useEvtxStore((s) => s.filterLevels);
  const toggleFilterLevel = useEvtxStore((s) => s.toggleFilterLevel);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const setFilterSearch = useEvtxStore((s) => s.setFilterSearch);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const setTimeWindow = useEvtxStore((s) => s.setTimeWindow);
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const loadedChannels = useEvtxStore((s) => s.loadedChannels);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);

  // Sized from the operator's list font rather than hardcoded, so raising the list size raises
  // these controls with it (spec 7.1: controls f - 1, level toggles f - 2).
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const controlFontSize = `${Math.max(11, metrics.fontSize - 1)}px`;
  const toggleFontSize = `${Math.max(10, metrics.fontSize - 2)}px`;

  const themeId = useUiStore((s) => s.themeId);
  const theme = useMemo(() => getThemeById(themeId), [themeId]);
  const visual = useMemo(() => buildEvtxVisualTokens(theme), [theme]);
  const toggleStates = useMemo(() => levelToggleStates(theme, visual), [theme, visual]);
  const toggleVariables = useMemo(() => toggleColorVariables(toggleStates), [toggleStates]);

  // The loaded totals, memoized on the records array so typing in the search box does not recount.
  // One pass is cheap (about a millisecond at 100k records), so the 75 ms debounce spec 11 asks of
  // heavier derivations is not needed here.
  const levelCounts = useMemo(() => countByLevel(records), [records]);

  const live = sourceMode === "live";
  // A level the live query leaves out is not loaded, so its count is unknown rather than zero.
  const leftOutAtSource = live && levelsFilteredAtSource(filterLevels);
  const countIsKnown = (level: EvtxLevel) =>
    !isLoading && (!leftOutAtSource || filterLevels.has(level));
  // A toggle reloads the loaded channels only when it changes what the service is asked for. The
  // store makes the same comparison (`serverFilterKey`) before it refetches.
  const currentServerKey = serverFilterKey(timeWindow, filterEventIds, filterLevels);
  const reloadsOnToggle = (level: EvtxLevel) =>
    live &&
    loadedChannels.size > 0 &&
    serverFilterKey(timeWindow, filterEventIds, levelsAfterToggle(filterLevels, level)) !==
      currentServerKey;

  const timeWindowSnapshotLabel = useMemo(
    () => eventLogTimeWindowSnapshotLabel(timeWindow, nowEpoch),
    [nowEpoch, timeWindow],
  );
  // The window is a live-query criterion, so file mode hides the control. A saved filter can still
  // set a window in file mode, and a hidden active criterion would hide events with no way back.
  const showTimeWindow = live || timeWindow !== "all";

  return (
    <div
      data-evtx-region="filter-row"
      style={{
        display: "flex",
        alignItems: "center",
        gap: "8px",
        padding: "6px 12px 4px",
        backgroundColor: tokens.colorNeutralBackground1,
        flexWrap: "wrap",
        flexShrink: 0,
        fontSize: controlFontSize,
      }}
    >
      <div className={styles.searchSlot}>
        <Input
          id={EVTX_SEARCH_INPUT_ID}
          className={styles.search}
          aria-label="Search events"
          contentBefore={<Search16Regular aria-hidden />}
          input={{ style: { fontSize: controlFontSize } }}
          value={filterSearch}
          onChange={(_, data) => setFilterSearch(data.value)}
          placeholder="Search…"
          style={{ minHeight: "28px" }}
        />
        {/*
          Phase 5b (#833) puts the field-query grammar's inline error here, under the input, in
          visual.levels.Warning.textColor, and its example placeholder above. The slot is a column
          already, so the error needs no layout change.
        */}
      </div>

      <div
        role="group"
        aria-label="Level"
        aria-busy={isLoading}
        className={styles.levelGroup}
        style={toggleVariables}
      >
        {EVTX_LEVELS.map((level) => {
          const pressed = filterLevels.has(level);
          const known = countIsKnown(level);
          const descriptionId = `evtx-level-count-${level}`;
          const countText = known
            ? `${levelCounts[level].toLocaleString()} ${levelCounts[level] === 1 ? "event" : "events"} loaded`
            : UNKNOWN_COUNT_TEXT;
          // Why the count is not available, for a sighted operator's tooltip.
          const unknownReason = isLoading
            ? "Events are loading"
            : `The live query leaves out ${level} events while this level is hidden`;
          const reloads = reloadsOnToggle(level);
          return (
            <button
              key={level}
              type="button"
              className={mergeClasses(styles.toggle, pressed && styles.pressed)}
              aria-label={`Toggle ${level} events`}
              aria-pressed={pressed}
              aria-describedby={descriptionId}
              title={reloads ? `Toggle ${level} events. ${RELOAD_NOTE}` : `Toggle ${level} events`}
              onClick={() => toggleFilterLevel(level)}
              style={{ fontSize: toggleFontSize }}
            >
              <span
                aria-hidden
                className={mergeClasses(DOT_CLASS, styles.dot)}
                style={{ backgroundColor: visual.levels[level].dotColor }}
              />
              <span>{LEVEL_TOGGLE_LABELS[level]}</span>
              <span
                aria-hidden
                className={mergeClasses(COUNT_CLASS, styles.count)}
                title={known ? undefined : unknownReason}
              >
                {known ? levelCounts[level].toLocaleString() : UNKNOWN_COUNT}
              </span>
              <span id={descriptionId} className={styles.visuallyHidden}>
                {reloads ? `${countText}. ${RELOAD_NOTE}` : countText}
              </span>
            </button>
          );
        })}
        {isLoading && <Spinner size="extra-tiny" label="Reloading events" labelPosition="after" />}
      </div>

      {showTimeWindow && (
        <Dropdown
          aria-label="Time window"
          // 28 px (spec 8.3): the small dropdown is 24 px and the button, not the root, sets it.
          button={{ style: { fontSize: controlFontSize, minHeight: "28px" } }}
          size="small"
          value={timeWindowSnapshotLabel}
          selectedOptions={[timeWindow]}
          style={{ minWidth: timeWindow === "all" ? "132px" : "260px" }}
          title={
            timeWindow === "all"
              ? "Query the complete available event history."
              : `${timeWindowSnapshotLabel}. This is a coherent frozen snapshot for the grid, timeline, and diagnosis. Refresh the selected channels to advance it.`
          }
          onOptionSelect={(_, data) => {
            const next = data.optionValue as EvtxTimeWindow;
            if (!next || next === timeWindow) return;
            setTimeWindow(next);
          }}
        >
          {TIME_WINDOWS.map((window) => (
            <Option key={window} value={window} style={{ fontSize: controlFontSize }}>
              {EVTX_TIME_WINDOW_LABELS[window]}
            </Option>
          ))}
        </Dropdown>
      )}

      <EvtxMoreFilters controlFontSize={controlFontSize} visual={visual} />

      {/*
        The epic's Preview label (#583) is pinned by a workspace test and the spec's filter row does
        not mention it, so it stays, out of the way at the end of the row.
      */}
      <Badge appearance="ghost" size="small" style={{ flexShrink: 0, marginLeft: "auto" }}>
        Preview
      </Badge>
    </div>
  );
}

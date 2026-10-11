/**
 * The workbench filter row (spec section 8.3): search, level toggles with counts, the time window
 * and the "More filters" entry point. The active-criteria chips live in `EvtxFilterChips`.
 *
 * Everything the old single bar offered is still reachable. Group by, Columns and Export moved to
 * the view bar in Phase 3. Event IDs, the quick filter, saved filters, sort and the time zone are
 * in the More filters popover (`EvtxMoreFilters`), one open away.
 *
 * Do the level toggles re-query in live mode? Yes, verified in Phase 5 (issue #832). In live mode
 * with at least one loaded channel, every toggle calls `refreshBeforeLoad` in `evtx-store.ts`, which
 * runs `refreshLoadedChannels`: it empties `records`, sets `isLoading` and queries every loaded
 * channel again. The level predicate only reaches the service when it is a strict subset without
 * Information (`levelsFilteredAtSource`); the reload happens either way. In file mode a toggle is a
 * local filter and nothing is queried.
 *
 * What the operator sees in the full workspace: the emptied records make `EventLogWorkspace` return
 * its full-screen "Loading event logs..." spinner (`isLoading && records.length === 0`), which
 * unmounts this row, the toggle just pressed and keyboard focus until the first batch streams in
 * (pinned in EventLogWorkspace.test.tsx; a finding for Main, not changed here because the early
 * return also governs the first live load). This row's own loading state shows once batches
 * repopulate `records` while `isLoading` continues: the group is `aria-busy`, a spinner shows beside
 * it, the counts read as unknown rather than zero, and each toggle's description says it reloads.
 */
import { useMemo, type CSSProperties } from "react";
import {
  Badge,
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
import { countByLevel, EVTX_LEVELS, levelsFilteredAtSource } from "./evtx-filter";
import {
  LEVEL_TOGGLE_BACKGROUNDS,
  LEVEL_TOGGLE_STATES,
  levelToggleStates,
  type LevelToggleState,
  type LevelToggleStateVisual,
} from "./evtx-level-toggle";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";
import { EvtxMoreFilters } from "./EvtxMoreFilters";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getThemeById } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { useEvtxStore } from "./evtx-store";
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

/** Shown in place of a count that is not known. Never zero: unknown is not "none". */
const UNKNOWN_COUNT = "?";

const RELOAD_NOTE = "Changing a level reloads the loaded channels from the live log.";

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
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: "1px",
    },
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
          const description = known
            ? `${levelCounts[level].toLocaleString()} ${levelCounts[level] === 1 ? "event" : "events"} loaded`
            : isLoading
              ? "Count unavailable while events load"
              : `Count unavailable: the live query leaves out ${level} events while this level is hidden`;
          return (
            <button
              key={level}
              type="button"
              className={mergeClasses(styles.toggle, pressed && styles.pressed)}
              aria-label={`Toggle ${level} events`}
              aria-pressed={pressed}
              aria-describedby={descriptionId}
              title={live ? `Toggle ${level} events. ${RELOAD_NOTE}` : `Toggle ${level} events`}
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
                title={known ? undefined : description}
              >
                {known ? levelCounts[level].toLocaleString() : UNKNOWN_COUNT}
              </span>
              <span id={descriptionId} className={styles.visuallyHidden}>
                {live ? `${description}. ${RELOAD_NOTE}` : description}
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
          disabled={isLoading}
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

/**
 * The active-criteria chip row (spec section 8.4): one chip per active criterion, "Clear all",
 * and the "Showing {visible} of {loaded}" readout.
 *
 * Which chips exist is a pure function of the filter state (`buildFilterChips`), so a new criterion
 * adds a descriptor and a removal, not a layout. The transient criteria of Phase 6a (#834) are the
 * last two: the time range ("Time: brushed 09:00-09:45", in the selection colors) and the record
 * scope ("Finding: {title}" or "Chain: {title}"). The level toggles, the search box and the time
 * window are on the filter row, so only the search text has a chip; levels and the time window never
 * do. A chip's `title` is its tooltip when that says more than the chip does.
 */
import {
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type FocusEvent,
} from "react";
import {
  createFocusOutlineStyle,
  Link,
  makeStyles,
  mergeClasses,
  tokens,
} from "@fluentui/react-components";
import { Dismiss12Regular } from "@fluentui/react-icons";
import type { EvtxQuickFilter, EvtxRecordScope, EvtxRecordScopeKind, EvtxTimeRange } from "./evtx-filter";
import { describeScopeCounts, formatCount } from "./evtx-insights-data";
import { useEvtxStore } from "./evtx-store";
import { formatTimeRange, timeZoneLabel, type EvtxTimeZoneMode } from "./evtx-time";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";

/** The id of the search box on the filter row, where focus goes when no chip is left to take it. */
export const EVTX_SEARCH_INPUT_ID = "evtx-filter-search";

export type EvtxFilterChipId =
  | "channels"
  | "eventIds"
  | "quickFilter"
  | "search"
  | "timeRange"
  | "recordScope";

/** The word before a record scope's title (spec section 8.4). */
const SCOPE_KIND_LABELS: Record<EvtxRecordScopeKind, string> = {
  finding: "Finding",
  chain: "Chain",
};

export interface EvtxFilterChip {
  id: EvtxFilterChipId;
  /** The criterion in words. It is the chip text, its tooltip and the end of "Remove {label}". */
  label: string;
  /** The tooltip, when it says more than the label (a zone, or what a scope could not resolve). */
  title?: string;
  /** Drawn in the selection colors (Q-1): the active brushed-time chip. */
  selected?: boolean;
  /**
   * Whether "Clear all" removes this chip. The channel selection is not cleared (spec 9): it is
   * where the events come from, set in the channel pane, and a chip is only the reminder.
   */
  clearedByClearAll: boolean;
}

export interface EvtxFilterChipInput {
  filterEventIds: string;
  filterSearch: string;
  quickFilter: EvtxQuickFilter;
  selectedChannels: ReadonlySet<string>;
  /**
   * The channels whose records are loaded: every parsed channel in file mode, the loaded channels
   * in live mode. A channel that is selected but not loaded hides nothing, and a channel the
   * machine cannot read has no records to hide, so neither belongs in "n of m".
   */
  heldChannels: ReadonlySet<string>;
  /** The transient time range, when one is set. */
  timeRange?: EvtxTimeRange | null;
  /** The transient record scope, when one is set. */
  recordScope?: EvtxRecordScope | null;
  /** The zone the range's times are written in. */
  timeZoneMode?: EvtxTimeZoneMode;
  /** How many events the range hides only because they have no usable timestamp. */
  untimedHiddenCount?: number;
}

/** "4624,4625  4634" becomes "4624, 4625, 4634", the way the chip and the removal label read it. */
function readableIdList(raw: string): string {
  return raw.trim().split(/[\s,]+/).filter(Boolean).join(", ");
}

export function buildFilterChips(input: EvtxFilterChipInput): EvtxFilterChip[] {
  const chips: EvtxFilterChip[] = [];

  let shown = 0;
  for (const channel of input.heldChannels) {
    if (input.selectedChannels.has(channel)) shown += 1;
  }
  if (shown < input.heldChannels.size) {
    chips.push({
      id: "channels",
      label: `Channels: ${shown} of ${input.heldChannels.size}`,
      clearedByClearAll: false,
    });
  }

  if (input.filterEventIds.trim()) {
    chips.push({
      id: "eventIds",
      label: `Event IDs: ${readableIdList(input.filterEventIds)}`,
      clearedByClearAll: true,
    });
  }

  const quick = input.quickFilter;
  if (quick.query.trim()) {
    const text = quick.mode === "eventIds" ? readableIdList(quick.query) : quick.query.trim();
    chips.push({
      id: "quickFilter",
      // A hide rule excludes; a show rule narrows. Both are criteria, so both get a chip.
      label: quick.action === "hide" ? `Exclude: ${text}` : `Quick filter: ${text}`,
      clearedByClearAll: true,
    });
  }

  if (input.filterSearch.trim()) {
    chips.push({
      id: "search",
      label: `Search: ${input.filterSearch.trim()}`,
      clearedByClearAll: true,
    });
  }

  if (input.timeRange) {
    const { startMs, endMs } = input.timeRange;
    const mode = input.timeZoneMode ?? "local";
    const label = `Time: brushed ${formatTimeRange(startMs, endMs, mode)}`;
    const untimed = input.untimedHiddenCount ?? 0;
    const lines = [`${label} (${timeZoneLabel(mode, startMs)})`];
    if (untimed > 0) {
      lines.push(
        `${formatCount(untimed)} ${untimed === 1 ? "event without a timestamp is" : "events without a timestamp are"} hidden by this range`,
      );
    }
    chips.push({
      id: "timeRange",
      label,
      title: lines.join("\n"),
      selected: true,
      clearedByClearAll: true,
    });
  }

  const scope = input.recordScope;
  if (scope) {
    const label = `${SCOPE_KIND_LABELS[scope.kind]}: ${scope.title}`;
    const size = scope.records.size;
    chips.push({
      id: "recordScope",
      label,
      title: [
        label,
        `${formatCount(size)} ${size === 1 ? "event" : "events"} in this scope.`,
        ...describeScopeCounts(scope.counts),
      ].join("\n"),
      clearedByClearAll: true,
    });
  }

  return chips;
}

/**
 * The chips for the current filter state, and the channels they were counted against. The filter
 * row reads the same chips for its "More filters" number, so the two cannot disagree.
 */
export function useFilterChips(untimedHiddenCount = 0): {
  chips: EvtxFilterChip[];
  heldChannels: ReadonlySet<string>;
} {
  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const timeRange = useEvtxStore((s) => s.timeRange);
  const recordScope = useEvtxStore((s) => s.recordScope);
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const channels = useEvtxStore((s) => s.channels);
  const loadedChannels = useEvtxStore((s) => s.loadedChannels);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);

  const currentHeld = useMemo(
    () =>
      sourceMode === "live" ? loadedChannels : new Set(channels.map((channel) => channel.name)),
    [sourceMode, loadedChannels, channels],
  );
  // A live refetch empties `loadedChannels` for its whole duration, though the selection has not
  // changed. The rows stay mounted through it, so the channel chip (and the More filters number)
  // would drop out and come back, moving the grid twice and unmounting a focused remove button. So
  // while loading, the channels are the ones from before the load began. The state is adjusted while
  // rendering, which has no effect lag.
  const [settledHeld, setSettledHeld] = useState(currentHeld);
  if (!isLoading && settledHeld !== currentHeld) setSettledHeld(currentHeld);
  const heldChannels = isLoading ? settledHeld : currentHeld;
  const chips = useMemo(
    () =>
      buildFilterChips({
        filterEventIds,
        filterSearch,
        quickFilter,
        selectedChannels,
        heldChannels,
        timeRange,
        recordScope,
        timeZoneMode,
        untimedHiddenCount,
      }),
    [
      filterEventIds,
      filterSearch,
      quickFilter,
      selectedChannels,
      heldChannels,
      timeRange,
      recordScope,
      timeZoneMode,
      untimedHiddenCount,
    ],
  );
  return { chips, heldChannels };
}

const useStyles = makeStyles({
  row: {
    display: "flex",
    alignItems: "center",
    flexWrap: "wrap",
    columnGap: "6px",
    rowGap: "4px",
    paddingTop: "0",
    paddingBottom: "6px",
    paddingLeft: "12px",
    paddingRight: "12px",
    flexShrink: 0,
    backgroundColor: tokens.colorNeutralBackground1,
  },
  list: {
    display: "flex",
    flexWrap: "wrap",
    alignItems: "center",
    columnGap: "6px",
    rowGap: "4px",
    listStyleType: "none",
    margin: 0,
    padding: 0,
  },
  chip: {
    display: "inline-flex",
    alignItems: "center",
    gap: "4px",
    maxWidth: "320px",
    boxSizing: "border-box",
    paddingTop: "2px",
    paddingBottom: "2px",
    paddingLeft: "10px",
    paddingRight: "8px",
    // Radius 8 is the design-system maximum (D21), not the mockup's pill.
    borderRadius: "8px",
    border: `1px solid ${tokens.colorNeutralStroke1}`,
    backgroundColor: tokens.colorNeutralBackground3,
    // Secondary text, not primary: colorNeutralForeground1 on this surface measures 4.11:1 in
    // solarized-dark, and the secondary token clears 4.5:1 in all seven themes.
    color: tokens.colorNeutralForeground2,
  },
  chipText: {
    overflow: "hidden",
    textOverflow: "ellipsis",
    whiteSpace: "nowrap",
  },
  remove: {
    // The focus ring is Fluent's own, drawn as a pseudo-element around this positioned box.
    position: "relative",
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    flexShrink: 0,
    width: "16px",
    height: "16px",
    padding: 0,
    border: "none",
    borderRadius: tokens.borderRadiusSmall,
    backgroundColor: "transparent",
    color: tokens.colorNeutralForeground2,
    cursor: "pointer",
    ":hover": {
      backgroundColor: tokens.colorSubtleBackgroundHover,
      color: tokens.colorNeutralForeground2Hover,
    },
    ":active": {
      backgroundColor: tokens.colorSubtleBackgroundPressed,
      color: tokens.colorNeutralForeground2Pressed,
    },
    ...createFocusOutlineStyle({ style: { outlineRadius: tokens.borderRadiusSmall } }),
  },
  // The remove icon on the selection fill. Foreground2 measures 3.80:1 there in solarized-dark, so
  // the rest color is the token map's selection foreground (the chip text's own color, 6.42:1 or
  // better in every theme), handed over as a CSS variable the chip sets from `selection`: a component
  // reads the map and does not index the palette. Only the rest color: hover and pressed keep the
  // `remove` pairs, whose surfaces are the subtle hover and pressed backgrounds and not the fill.
  removeSelected: {
    color: "var(--evtx-chip-remove-color)",
  },
  readout: {
    marginLeft: "auto",
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
    color: tokens.colorNeutralForeground2,
  },
});

interface EvtxFilterChipsProps {
  /** How many loaded events the filters leave on screen. */
  visibleCount: number;
  /** How many events are loaded. */
  loadedCount: number;
  /** How many events the time range hides only because they have no usable timestamp. */
  untimedHiddenCount?: number;
}

/** A chip's remove button, or the search box. The search chip has its own id, so the box is not a string. */
type FocusTarget = { chip: EvtxFilterChipId } | { searchBox: true };

/** What has focus inside the row: a chip's remove button, or the Clear all link. */
type FocusHold = { chip: EvtxFilterChipId } | { clearAll: true };

export function EvtxFilterChips({
  visibleCount,
  loadedCount,
  untimedHiddenCount = 0,
}: EvtxFilterChipsProps) {
  const styles = useStyles();
  const { selection } = useEvtxVisualTokens();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const fontPx = Math.max(10, metrics.fontSize - 2);
  const fontSize = `${fontPx}px`;
  // Explicit, so a chip is 16 + 2 x 2 padding + 2 x 1 border = 22 px at the default size (the row
  // is then 28 px with its bottom padding, against the spec's ~26). Inherited, the provider's 20 px
  // body line height made a chip 26 px and the row 32 px.
  const lineHeight = `${Math.round(fontPx * 1.45)}px`;

  const setFilterEventIds = useEvtxStore((s) => s.setFilterEventIds);
  const setFilterSearch = useEvtxStore((s) => s.setFilterSearch);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const setQuickFilter = useEvtxStore((s) => s.setQuickFilter);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const setSelectedChannels = useEvtxStore((s) => s.setSelectedChannels);
  const setTimeRange = useEvtxStore((s) => s.setTimeRange);
  const setRecordScope = useEvtxStore((s) => s.setRecordScope);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const { chips, heldChannels } = useFilterChips(untimedHiddenCount);

  // A chip, the Clear all link or the whole row can unmount while focus is inside it, and then the
  // browser puts focus on the body. That happens by a click on a remove button (below), by Escape on
  // the time range, by a load starting or the source changing (which clear the transient criteria),
  // and by a cleared channel pruning the scope: no caller is listed here. What is watched is the focus
  // itself. The row remembers which of its controls last had it; when that control is no longer in
  // the row after a render and focus has fallen out of the document's controls, focus is handed to
  // the next chip's remove button, else the previous one, else the search box (the anchor in the
  // filter row, as a click has always done).
  const rowRef = useRef<HTMLDivElement>(null);
  const pendingFocus = useRef<FocusTarget | null>(null);
  const heldFocus = useRef<FocusHold | null>(null);
  const previousChipIds = useRef<EvtxFilterChipId[]>([]);
  const clearAllShown = chips.some((chip) => chip.clearedByClearAll);
  useLayoutEffect(() => {
    const ids = chips.map((chip) => chip.id);
    const before = previousChipIds.current;
    previousChipIds.current = ids;

    // A click on a remove button or Clear all names where focus goes; some webviews do not focus a
    // button on click, so this does not depend on the button having had it.
    const target = pendingFocus.current;
    if (target !== null) {
      pendingFocus.current = null;
      heldFocus.current = null;
      const chipButton =
        "chip" in target
          ? rowRef.current?.querySelector<HTMLElement>(`[data-evtx-chip="${target.chip}"] button`)
          : null;
      (chipButton ?? document.getElementById(EVTX_SEARCH_INPUT_ID))?.focus();
      return;
    }

    const held = heldFocus.current;
    if (held === null) return;
    const gone = "chip" in held ? !ids.includes(held.chip) : !clearAllShown;
    if (!gone) return;
    heldFocus.current = null;
    const active = document.activeElement;
    if (active !== null && active !== document.body && active.isConnected) return;

    let next: HTMLElement | null = null;
    if ("chip" in held) {
      const removedAt = before.indexOf(held.chip);
      const around =
        removedAt < 0
          ? []
          : [...before.slice(removedAt + 1), ...before.slice(0, removedAt).reverse()];
      const neighbour = around.find((id) => ids.includes(id));
      next =
        neighbour === undefined
          ? null
          : (rowRef.current?.querySelector<HTMLElement>(`[data-evtx-chip="${neighbour}"] button`) ?? null);
    }
    (next ?? document.getElementById(EVTX_SEARCH_INPUT_ID))?.focus();
  });
  const rememberFocus = (event: FocusEvent<HTMLElement>) => {
    const target = event.target as HTMLElement;
    const chip = target.closest<HTMLElement>("[data-evtx-chip]");
    if (chip) heldFocus.current = { chip: chip.dataset.evtxChip as EvtxFilterChipId };
    else heldFocus.current = target.closest("[data-evtx-clear-all]") ? { clearAll: true } : null;
  };
  const releaseFocus = (event: FocusEvent<HTMLElement>) => {
    // Moving between the row's own controls is not leaving it; the next focus event names the new one.
    if (event.relatedTarget instanceof Node && event.currentTarget.contains(event.relatedTarget)) return;
    // A control that is still in the document when it loses focus was left on purpose (the operator
    // went elsewhere). One that is gone was removed while focused, and the layout effect handles it.
    const left = event.target;
    queueMicrotask(() => {
      if (left instanceof Node && left.isConnected) heldFocus.current = null;
    });
  };

  if (chips.length === 0) return null;

  const removeChip = (id: EvtxFilterChipId) => {
    switch (id) {
      case "channels":
        // Selects the held channels again. Selecting every enumerated channel instead would also
        // tick hundreds of channels the machine never loaded, and the chip would not go away.
        setSelectedChannels(new Set([...selectedChannels, ...heldChannels]));
        break;
      case "eventIds":
        setFilterEventIds("");
        break;
      case "quickFilter":
        // Only the query: the mode, scope, action, case and highlight are the operator's settings.
        setQuickFilter({ ...quickFilter, query: "" });
        break;
      case "search":
        setFilterSearch("");
        break;
      case "timeRange":
        setTimeRange(null);
        break;
      case "recordScope":
        setRecordScope(null);
        break;
    }
  };
  const removeOne = (id: EvtxFilterChipId) => {
    const index = chips.findIndex((chip) => chip.id === id);
    const neighbour = chips[index + 1] ?? chips[index - 1];
    pendingFocus.current = neighbour ? { chip: neighbour.id } : { searchBox: true };
    removeChip(id);
  };
  const clearable = chips.filter((chip) => chip.clearedByClearAll);

  return (
    <div
      ref={rowRef}
      data-evtx-region="chip-row"
      className={styles.row}
      style={{ fontSize, lineHeight }}
      onFocus={rememberFocus}
      onBlur={releaseFocus}
    >
      <ul aria-label="Active filters" className={styles.list}>
        {chips.map((chip) => (
          <li
            key={chip.id}
            data-evtx-chip={chip.id}
            className={styles.chip}
            style={
              chip.selected
                ? ({
                    backgroundColor: selection.background,
                    borderColor: selection.border,
                    color: selection.foreground,
                    "--evtx-chip-remove-color": selection.foreground,
                  } as CSSProperties)
                : undefined
            }
          >
            <span className={styles.chipText} title={chip.title ?? chip.label}>
              {chip.label}
            </span>
            <button
              type="button"
              className={chip.selected ? mergeClasses(styles.remove, styles.removeSelected) : styles.remove}
              aria-label={`Remove ${chip.label}`}
              onClick={() => removeOne(chip.id)}
            >
              <Dismiss12Regular aria-hidden />
            </button>
          </li>
        ))}
      </ul>
      {clearable.length > 0 && (
        <Link
          as="button"
          type="button"
          data-evtx-clear-all="true"
          style={{ fontSize, fontWeight: 600 }}
          onClick={() => {
            // Clear all unmounts itself once nothing clearable is left, so focus goes to the search.
            pendingFocus.current = { searchBox: true };
            for (const chip of clearable) removeChip(chip.id);
          }}
        >
          Clear all
        </Link>
      )}
      <span className={styles.readout} data-evtx-filter-count>
        {isLoading
          ? "Loading events..."
          : `Showing ${visibleCount.toLocaleString()} of ${loadedCount.toLocaleString()}`}
      </span>
    </div>
  );
}

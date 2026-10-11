/**
 * The active-criteria chip row (spec section 8.4): one chip per active criterion, "Clear all",
 * and the "Showing {visible} of {loaded}" readout.
 *
 * Which chips exist is a pure function of the filter state (`buildFilterChips`), so the next
 * criteria add a descriptor and a removal, not a layout:
 * - Phase 6a (#834) adds the transient time range ("Time: brushed 09:00-09:45", `tone: "selection"`
 *   draws it with the selection triplet) and the record scope ("Chain: {title}" / "Finding:
 *   {title}"). Each adds an id to `EvtxFilterChipId`, a branch in `buildFilterChips`, and a case
 *   in `removeChip`; `clearedByClearAll` says whether Clear all takes it too.
 * - Level toggles, the search box and the time window are visible on the filter row, so only the
 *   search text has a chip; levels and the time window never do.
 */
import { useMemo } from "react";
import { Link, makeStyles, tokens } from "@fluentui/react-components";
import { Dismiss12Regular } from "@fluentui/react-icons";
import type { EvtxQuickFilter } from "./evtx-filter";
import { useEvtxStore } from "./evtx-store";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";

export type EvtxFilterChipId = "channels" | "eventIds" | "quickFilter" | "search";

export interface EvtxFilterChip {
  id: EvtxFilterChipId;
  /** The criterion in words. It is the chip text, its tooltip and the end of "Remove {label}". */
  label: string;
  /**
   * Whether "Clear all" removes this chip. The channel selection is not cleared (spec 9): it is
   * where the events come from, set in the channel pane, and a chip is only the reminder.
   */
  clearedByClearAll: boolean;
  /** Draws the chip with the selection triplet (spec 6.2). Used by the brushed time range in 6a. */
  tone?: "selection";
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

  return chips;
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
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: "1px",
    },
  },
  readout: {
    marginLeft: "auto",
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
    color: tokens.colorNeutralForeground2,
  },
});

interface EvtxFilterChipViewProps {
  chip: EvtxFilterChip;
  onRemove: () => void;
}

/** One chip: the criterion in words and a button that removes it. */
export function EvtxFilterChipView({ chip, onRemove }: EvtxFilterChipViewProps) {
  const styles = useStyles();
  const visual = useEvtxVisualTokens();
  return (
    <li
      className={styles.chip}
      style={
        chip.tone === "selection"
          ? {
              backgroundColor: visual.selection.background,
              borderColor: visual.selection.border,
              color: visual.selection.foreground,
            }
          : undefined
      }
    >
      <span className={styles.chipText} title={chip.label}>
        {chip.label}
      </span>
      <button
        type="button"
        className={styles.remove}
        aria-label={`Remove ${chip.label}`}
        onClick={onRemove}
      >
        <Dismiss12Regular aria-hidden />
      </button>
    </li>
  );
}

interface EvtxFilterChipsProps {
  /** How many loaded events the filters leave on screen. */
  visibleCount: number;
  /** How many events are loaded. */
  loadedCount: number;
}

export function EvtxFilterChips({ visibleCount, loadedCount }: EvtxFilterChipsProps) {
  const styles = useStyles();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const fontSize = `${Math.max(10, metrics.fontSize - 2)}px`;

  const filterEventIds = useEvtxStore((s) => s.filterEventIds);
  const setFilterEventIds = useEvtxStore((s) => s.setFilterEventIds);
  const filterSearch = useEvtxStore((s) => s.filterSearch);
  const setFilterSearch = useEvtxStore((s) => s.setFilterSearch);
  const quickFilter = useEvtxStore((s) => s.quickFilter);
  const setQuickFilter = useEvtxStore((s) => s.setQuickFilter);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const setSelectedChannels = useEvtxStore((s) => s.setSelectedChannels);
  const channels = useEvtxStore((s) => s.channels);
  const loadedChannels = useEvtxStore((s) => s.loadedChannels);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const isLoading = useEvtxStore((s) => s.isLoading);

  const heldChannels = useMemo(
    () =>
      sourceMode === "live" ? loadedChannels : new Set(channels.map((channel) => channel.name)),
    [sourceMode, loadedChannels, channels],
  );
  const chips = useMemo(
    () =>
      buildFilterChips({
        filterEventIds,
        filterSearch,
        quickFilter,
        selectedChannels,
        heldChannels,
      }),
    [filterEventIds, filterSearch, quickFilter, selectedChannels, heldChannels],
  );

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
    }
  };
  const clearable = chips.filter((chip) => chip.clearedByClearAll);

  return (
    <div data-evtx-region="chip-row" className={styles.row} style={{ fontSize }}>
      <ul aria-label="Active filters" className={styles.list}>
        {chips.map((chip) => (
          <EvtxFilterChipView key={chip.id} chip={chip} onRemove={() => removeChip(chip.id)} />
        ))}
      </ul>
      {clearable.length > 0 && (
        <Link
          as="button"
          type="button"
          style={{ fontSize, fontWeight: 600 }}
          onClick={() => {
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

/**
 * The Correlation view (spec 8.11): the chains the engine's edges form, strongest first, with the
 * selected chain's lane plot, why it is (or is not) a link, and its entries in time order.
 *
 * The view is lazy and not kept alive, and it owns no correlation data. Everything it draws comes
 * from ONE snapshot of the shared data (`useEvtxCorrelationData`): the model, its items, origins,
 * coverage gaps, unplaced evidence and scan are all read from the same object, because they were
 * stored together by the run that built the model. The selected chain lives in a transient store so
 * it survives a switch to another view and can be set from outside ("Open in Correlation view").
 *
 * Evidence first (soul.md): a missing link is a coverage state, never "no link"; an unknown count is
 * never 0; a chain built from fewer events than were loaded says so; an entry with no loaded
 * position is called "not placed" only when the session proves it.
 */
import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Button, makeStyles, tokens } from "@fluentui/react-components";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { Copy16Regular, Filter16Regular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { CorrelationLegend, EvtxCorrelationLanes } from "./EvtxCorrelationLanes";
import { correlationSizes, type CorrelationSizes } from "./evtx-correlation-sizes";
import { EvtxCorrelationOverview } from "./EvtxCorrelationOverview";
import { EvtxUnplacedList } from "./EvtxUnplacedList";
import {
  CHAIN_ENTRIES_BEING_READ_TEXT,
  NO_ANALYSIS_TEXT,
  NO_ENTRY_POSITION_TEXT,
  NO_POSITION_TEXT,
  READING_EDGES_TEXT,
  SAME_TIME_NOTE,
  SEQUENCE_ORDER_NOTE,
  chainActionAvailability,
  chainCopyText,
  chainRowName,
  correlationFailureText,
  correlationNotices,
  keyKindLabel,
  noChainsFoundText,
  plotOmissionNotice,
  scopeDisclosure,
  timelineReadingText,
  unresolvedNotice,
  whyHeading,
  whyStatement,
  UPDATING_CORRELATION_TEXT,
} from "./evtx-correlation-copy";
import { correlationChainCount, type CorrelationChain } from "./evtx-correlation-chains";
import {
  resolveOriginRecords,
} from "./evtx-correlation-origin-index";
import { filterTableToChain, loadedEvidenceIndex } from "./evtx-correlation-actions";
import { resolveMarkerClick } from "./evtx-correlation-dock-model";
import { zoomWindowFor, type ZoomState } from "./evtx-correlation-overview";
import {
  lossStillTrue,
  lossWasSaid,
  newSelectionLoss,
  spokenLoss,
  visibleLoss,
  type LossFacts,
  type Region,
  type SelectionLoss,
} from "./evtx-correlation-selection-loss";
import { useEvtxCorrelationStore } from "./evtx-correlation-store";
import {
  describeUnplaced,
  notPlacedCaption,
  notPlacedLabel,
  type UnplacedView,
} from "./evtx-unplaced";
import {
  CORRELATION_SEQUENCE_INITIAL,
  buildChainPlot,
  chainAccessibleName,
  chainSequence,
  chainTitle,
  defaultLaneWindow,
  entriesText,
  formatDelta,
  isPartialChain,
  keyHeader,
  listedRows,
  memberLinkSummary,
  reconcileSelection,
  sessionSpeaksForAbsenceOverall,
  spanText,
  whyRows,
  type ListedRows,
  type PlotMarker,
  type TimeWindow,
} from "./evtx-correlation-view-model";
import { useEvtxCorrelationData } from "./useEvtxCorrelation";
import { useUnreadSources } from "./useUnreadSources";
import { useRailTextColors } from "./evtx-rail-text";
import { selectRecordAndShowDetails } from "./evtx-select-record";
import { useEvtxStore } from "./evtx-store";
import { formatEventTime, timeZoneLabel } from "./evtx-time";
import { useEvtxVisualTokens, type EvtxVisualTokens } from "./evtx-visual-tokens";
import { EvtxStrengthBadge } from "./EvtxStrengthBadge";
import { useThrottledValue } from "./evtx-throttle";
import type { TimelineItem } from "./unified-timeline";

/** Spec 10: a polite announcement at most once every 5 s. */
export const CORRELATION_ANNOUNCE_MS = 5_000;
const LIST_WIDTH_PX = 250;

/** A reply to something the operator did, or the failure of it (a failure is announced as an alert). */
interface ActionMessage {
  kind: "reply" | "failure";
  text: string;
}
/** Message heads in the Sequence list; the full message is in the copied text. */
const MESSAGE_HEAD_CHARS = 140;
const NO_NEARBY: readonly TimelineItem[] = [];
const NO_LISTED_ROWS: ListedRows = { rows: [], pastCapId: null };

export interface EvtxCorrelationViewProps {
  /**
   * Context entries drawn as "Not linked" markers on the plot (decision A on issue 838). There is no
   * producer yet, so the workspace passes none; the seam exists so that what a marker may say
   * ("Not linked" or "No loaded link") is wired and tested through the view, not only in the plot.
   */
  nearby?: readonly TimelineItem[];
}

const useStyles = makeStyles({
  visuallyHidden: {
    position: "absolute",
    width: "1px",
    height: "1px",
    overflow: "hidden",
    clipPath: "inset(50%)",
    whiteSpace: "nowrap",
  },
  option: {
    cursor: "pointer",
    ":hover": { filter: "brightness(0.97)" },
  },
});

/** Why a click on a log entry's marker selected nothing (an archive text row is selected, so these are the rest). */
const LOG_ENTRY_NO_SELECTION: Record<Extract<ReturnType<typeof resolveMarkerClick>, { kind: "nothing" }>["selectability"], string> = {
  log: "This is a line of a log file with no record in the grid, so no record is selected.",
  notLoaded: "No loaded log record matches this entry, so no record is selected.",
  ambiguous: "More than one loaded log record matches this entry, so none is selected.",
  noIdentity: "This entry has no usable record identity, so no record is selected.",
};

interface Palette {
  sizes: CorrelationSizes;
  visuals: EvtxVisualTokens;
  /** On the list's surface (Background2). */
  listPrimary: string;
  listSecondary: string;
  /** On the detail's surface (Background1). */
  caption: string;
}

function ChainRow({
  chain,
  id,
  selected,
  timeZoneMode,
  palette,
  onSelect,
}: {
  chain: CorrelationChain;
  id: string;
  selected: boolean;
  timeZoneMode: "local" | "utc";
  palette: Palette;
  onSelect: (chainId: string) => void;
}) {
  const styles = useStyles();
  const { sizes, visuals } = palette;
  const primary = selected ? visuals.selection.foreground : palette.listPrimary;
  const secondary = selected ? visuals.selection.foreground : palette.listSecondary;
  const span = spanText(chain.startMs, chain.endMs, timeZoneMode);
  const partial = isPartialChain(chain);
  return (
    <div
      role="option"
      id={id}
      // Named from the title, or from the id when there is none, so two untitled rows (the
      // counts-only stage, or members whose items were not read) are still told apart.
      aria-label={chainRowName(chain)}
      aria-selected={selected}
      data-chain-id={chain.id}
      className={styles.option}
      onClick={() => onSelect(chain.id)}
      style={{
        display: "grid",
        gap: "3px",
        padding: "8px 12px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: selected ? visuals.selection.background : "transparent",
        boxShadow: selected ? `inset 3px 0 0 ${visuals.selection.border}` : undefined,
        color: primary,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
        <EvtxStrengthBadge strength={chain.strength} selected={selected} visuals={palette.visuals} textSize={palette.sizes.label} />
        <span
          style={{
            fontSize: `${sizes.label}px`,
            fontFamily: tokens.fontFamilyNumeric,
            color: secondary,
            whiteSpace: "nowrap",
          }}
        >
          {entriesText(chain.memberCount)}
          {partial ? " (partial)" : ""}
        </span>
      </div>
      <div
        style={{
          fontSize: `${Math.max(10, sizes.f - 1)}px`,
          fontWeight: 600,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
        title={chainTitle(chain)}
      >
        {chainTitle(chain)}
      </div>
      <div
        style={{
          fontSize: `${sizes.label}px`,
          fontFamily: tokens.fontFamilyNumeric,
          fontVariantNumeric: "tabular-nums",
          color: secondary,
        }}
      >
        {span ?? NO_POSITION_TEXT}
      </div>
    </div>
  );
}

/**
 * The last option of the chain list (spec 8.11): "Not placed (u)", with the caption that says its
 * items are listed and never guessed onto the timeline. Selecting it replaces the detail area with
 * the unplaced list. It is an option of the same listbox, so the arrow keys reach it, and it has
 * the selection look a chain row has.
 */
function NotPlacedRow({
  id,
  view,
  selected,
  palette,
  onSelect,
}: {
  id: string;
  view: UnplacedView;
  selected: boolean;
  palette: Palette;
  onSelect: () => void;
}) {
  const styles = useStyles();
  const { sizes, visuals } = palette;
  return (
    <div
      role="option"
      id={id}
      aria-label={`${notPlacedLabel(view)}. ${notPlacedCaption(view)}`}
      aria-selected={selected}
      data-unplaced-option=""
      className={styles.option}
      onClick={onSelect}
      style={{
        display: "grid",
        gap: "3px",
        padding: "8px 12px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: selected ? visuals.selection.background : "transparent",
        boxShadow: selected ? `inset 3px 0 0 ${visuals.selection.border}` : undefined,
        color: selected ? visuals.selection.foreground : palette.listPrimary,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      <div style={{ fontSize: `${Math.max(10, sizes.f - 1)}px`, fontWeight: 600 }}>{notPlacedLabel(view)}</div>
      <div style={{ fontSize: `${sizes.label}px`, color: selected ? visuals.selection.foreground : palette.listSecondary }}>
        {notPlacedCaption(view)}
      </div>
    </div>
  );
}

function CardHeading({ children, palette }: { children: string; palette: Palette }) {
  return (
    <h3
      style={{
        margin: 0,
        fontSize: `${Math.max(10, palette.sizes.f - 1)}px`,
        fontWeight: 600,
        color: tokens.colorNeutralForeground1,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      {children}
    </h3>
  );
}

/**
 * The detail column scrolls, and its rows are `max-content`, not `auto`. The lane plot is a scroll
 * container (a `maxHeight` and `overflowY: auto`), and a scroll container's automatic minimum size
 * is 0: as an `auto` row it is squeezed to a sliver when the column is taller than the window,
 * instead of the column scrolling. Whatever sits above or inside the column can make it taller (a
 * long Sequence, a large log font, a short window, the histogram above the views). A `max-content`
 * row is as tall as the item's own content up to the item's cap, so the plot keeps its height and
 * the column scrolls. When the column fits, `max-content` and `auto` rows measure the same
 * (`alignContent: start` stretches neither), so nothing else moves. A min-height on the plot
 * could not say "its content height, up to the cap" in CSS; this does, for every row at once.
 */
const DETAIL_COLUMN_STYLE = {
  flex: 1,
  minWidth: 0,
  overflowY: "auto",
  padding: "10px 14px",
  display: "grid",
  gridAutoRows: "max-content",
  gap: "10px",
  alignContent: "start",
} as const;

const cardStyle = {
  flex: "1 1 300px",
  minWidth: 0,
  border: `1px solid ${tokens.colorNeutralStroke2}`,
  borderRadius: "6px",
  padding: "10px 12px",
  display: "grid",
  gap: "8px",
  alignContent: "start",
  backgroundColor: tokens.colorNeutralBackground1,
} as const;

function head(text: string): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  return oneLine.length <= MESSAGE_HEAD_CHARS ? oneLine : `${oneLine.slice(0, MESSAGE_HEAD_CHARS - 1)}…`;
}

/** The phrase a marker's accessible name carries about how it is linked. */
function linkPhrase(chain: CorrelationChain, id: string, summary: ReturnType<typeof memberLinkSummary>): string {
  const partners = summary.get(id);
  const kinds = [...new Set(chain.keys.map((key) => keyKindLabel(key.kind)))];
  const by = kinds.length === 0 ? "" : ` by ${kinds.join(", ")}`;
  if (partners !== undefined && partners.exact > 0 && partners.candidate > 0) {
    return `linked${by} (exact and candidate)`;
  }
  if (partners !== undefined && partners.exact > 0) return `linked${by} (exact)`;
  if (partners !== undefined && partners.candidate > 0) return `linked${by} (candidate)`;
  return chain.strength === "ambiguous"
    ? "part of an ambiguous group, no single link established"
    : chain.strength === "coverageBlocked"
      ? "link blocked by a coverage gap"
      : "no connector drawn";
}

export default function EvtxCorrelationView({ nearby = NO_NEARBY }: EvtxCorrelationViewProps = {}) {
  const styles = useStyles();
  const data = useEvtxCorrelationData();
  const uid = useId();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const sizes = useMemo(() => correlationSizes(logListFontSize), [logListFontSize]);
  const visuals = useEvtxVisualTokens();
  const railText = useRailTextColors();
  const timeZoneMode = useEvtxStore((s) => s.timeZoneMode);
  const selectedChainId = useEvtxCorrelationStore((s) => s.selectedChainId);
  const selectChain = useEvtxCorrelationStore((s) => s.selectChain);
  const unplacedOpen = useEvtxCorrelationStore((s) => s.unplacedOpen);
  const showUnplaced = useEvtxCorrelationStore((s) => s.showUnplaced);
  const openedCount = useEvtxCorrelationStore((s) => s.openedCount);
  const listRef = useRef<HTMLDivElement>(null);
  const palette = useMemo<Palette>(
    () => ({
      sizes,
      visuals,
      listPrimary: railText.primary,
      listSecondary: railText.secondary,
      caption: railText.cardSecondary,
    }),
    [sizes, visuals, railText],
  );

  // One snapshot: all of these were stored together with the model.
  const { model, itemsById, origins, gaps, scan, unplaced, edges, hasItems } = data;
  // The rows the list shows: the model's capped rows, and the selected row after them when the cap
  // dropped it (the dock and the rail open a row by id, and it can be one of thousands).
  const listed = useMemo(
    () => (model === null ? NO_LISTED_ROWS : listedRows(model, selectedChainId)),
    [model, selectedChainId],
  );
  const reconciled = useMemo(
    () => reconcileSelection(listed.rows, selectedChainId),
    [listed, selectedChainId],
  );
  const chain = useMemo(
    () => listed.rows.find((row) => row.id === reconciled.selectedId) ?? null,
    [listed, reconciled.selectedId],
  );
  // The "Not placed" pane: its list is the model's own (it was stored with it), null is no run, and
  // an unknown count is a list that is shown as unknown.
  const unplacedView = useMemo(() => describeUnplaced(data.unplacedList), [data.unplacedList]);
  const unplacedPresent = model !== null && unplacedView.present;
  const showPane = unplacedOpen && unplacedPresent;
  // A selection that no longer exists is replaced, not kept: a stale id would reappear if a chain
  // with that id came back. Only once the model is current, so a rebuild does not lose the choice.
  // While the "Not placed" pane is open nothing here may call selectChain, which leaves the pane:
  // "Review unplaced lines" before any chain is selected would close it as soon as it opened. A pane
  // that is open with nothing left to list is left for the chain.
  // What is lost is an EVENT, recorded here once (`loss`), not a flag the renders go on reading: what
  // is said about it is derived from the record and from what exists now (evtx-correlation-selection-loss).
  const [loss, setLoss] = useState<SelectionLoss | null>(null);
  // How many publications the polite region has made, read when a loss is recorded (below).
  const publicationsRef = useRef(0);
  useEffect(() => {
    if (model === null || data.updating || showPane) return;
    if (unplacedOpen) {
      setLoss(newSelectionLoss("unplaced", null, publicationsRef.current));
      selectChain(reconciled.selectedId);
      return;
    }
    if (reconciled.selectedId !== selectedChainId) {
      if (reconciled.lost) setLoss(newSelectionLoss("chain", selectedChainId, publicationsRef.current));
      selectChain(reconciled.selectedId);
    }
  }, [model, data.updating, showPane, unplacedOpen, reconciled.selectedId, reconciled.lost, selectedChainId, selectChain]);
  const lossFacts = useMemo<LossFacts>(
    () => ({
      // The chains the list shows: the model's capped rows, and the selected row when the cap dropped it.
      chainIds: listed.rows.map((row) => row.id),
      showPane,
      unplacedPresent,
      chainShown: chain !== null,
    }),
    [listed, showPane, unplacedPresent, chain],
  );
  // A chain opened from outside (the dock's Open) replaces the selection a loss was about, so the loss
  // is dropped with it. This runs after the reconcile above in the commit that applies the open: an
  // opened id this model does not have is not a chain that was lost, and records no loss.
  const seenOpened = useRef(openedCount);
  useEffect(() => {
    if (seenOpened.current === openedCount) return;
    seenOpened.current = openedCount;
    setLoss(null);
  }, [openedCount]);
  // A record that stops being true (the pane is shown, the items are listed again, the chain is back)
  // is dropped, so it cannot come true again later and be said about something that did not happen.
  // A pick of a chain drops it in `pickChain`; a pick of Not placed shows the pane, which drops it here.
  useEffect(() => {
    setLoss((current) => (current !== null && !lossStillTrue(current, lossFacts) ? null : current));
  }, [lossFacts]);

  // The scope of the session the shown model was built from; it travels with the model, so it is
  // never a newer session's. A scope that is not known is disclosed as such and reads as narrowed:
  // "Not linked" is never said without it.
  const scope = scopeDisclosure(data.scope);
  const scopeNarrowed = scope !== null;
  // A source that was not fully read is events that never reached the session; both it and a rebuild
  // under way withdraw "Not linked" as the narrowed scope does, as the dock and the rail say.
  const unreadSources = useUnreadSources();

  // The zoom band's window is view-local and belongs to its chain: another chain starts from its own
  // default. It reaches the plot as `undefined` for that default (null would mean no window at all)
  // and is never the time-range criterion.
  const [zoom, setZoom] = useState<ZoomState | null>(null);
  const zoomWindow = zoomWindowFor(zoom, chain?.id ?? null);
  const defaultWindow = chain === null ? null : defaultLaneWindow(chain.startMs, chain.endMs);
  const defaultStartMs = defaultWindow?.startMs;
  const defaultEndMs = defaultWindow?.endMs;
  const bandWindow: TimeWindow | null = zoomWindow ?? defaultWindow;
  const zoomChainId = chain?.id ?? null;
  const onBandChange = useCallback(
    (next: TimeWindow | null) => {
      if (zoomChainId === null) return;
      // A window equal to the chain's default IS the default, so it is stored as no override: a drag
      // cancelled with Escape, or a move that lands exactly on it, must not freeze the plot at a
      // concrete window and stop it following the default when a live rebuild changes it.
      const isDefault = next !== null && next.startMs === defaultStartMs && next.endMs === defaultEndMs;
      setZoom(next === null || isDefault ? null : { chainId: zoomChainId, window: next });
    },
    [zoomChainId, defaultStartMs, defaultEndMs],
  );
  const plot = useMemo(
    () =>
      chain !== null && model !== null && hasItems && !showPane
        ? buildChainPlot({
            chain,
            itemsById,
            edgeInputComplete: model.edgeInputComplete,
            scopeNarrowed,
            unreadSources,
            updating: data.updating,
            gaps,
            nearby,
            window: zoomWindow ?? undefined,
          })
        : null,
    [chain, model, hasItems, showPane, itemsById, scopeNarrowed, unreadSources, data.updating, gaps, nearby, zoomWindow],
  );
  const sequence = useMemo(
    () => (chain !== null && hasItems ? chainSequence(chain, itemsById) : null),
    [chain, hasItems, itemsById],
  );
  const why = useMemo(
    () => (chain !== null && hasItems ? whyRows(chain, itemsById, unplaced) : []),
    [chain, hasItems, itemsById, unplaced],
  );
  const linkSummary = useMemo(
    () => (chain === null ? new Map() : memberLinkSummary(chain)),
    [chain],
  );

  const [showAllSequence, setShowAllSequence] = useState(false);
  const [showAllWhy, setShowAllWhy] = useState(false);
  // What the last action said: a reply to something the operator did (a marker that selected
  // nothing, a copy that worked), or a failure of it (a table that was not filtered, a copy that
  // failed). It is shown under the plot and is never kept for another chain.
  const [actionMessage, setActionMessage] = useState<ActionMessage | null>(null);
  const reply = useCallback((text: string) => setActionMessage({ kind: "reply", text }), []);
  const fail = useCallback((text: string) => setActionMessage({ kind: "failure", text }), []);
  useEffect(() => {
    setShowAllSequence(false);
    setShowAllWhy(false);
    setActionMessage(null);
  }, [chain?.id, showPane]);
  // The band belongs to its chain: choosing another starts from that chain's default window, and so
  // does coming back. (A live rebuild keeps the chain's id, so it keeps the band.)
  useEffect(() => {
    setZoom(null);
  }, [chain?.id]);
  const pickChain = useCallback(
    (chainId: string | null) => {
      setLoss(null);
      selectChain(chainId);
    },
    [selectChain],
  );

  const lossSentence = spokenLoss(loss, lossFacts);
  const announcement = useMemo(() => {
    if (model === null) {
      // Without a model the one polite status says where things stand; a failure is an alert.
      if (data.error !== null) return "";
      return data.stage === "unavailable" ? NO_ANALYSIS_TEXT : READING_EDGES_TEXT;
    }
    // The chain count the Insights card and the Chains tab state: a coverage blocked row is a coverage
    // state and is said apart, never counted as a chain.
    const chainCount = correlationChainCount(model.counts);
    const blocked = model.counts.coverageBlocked;
    return [
      `${chainCount.toLocaleString()} ${chainCount === 1 ? "chain" : "chains"}${blocked > 0 ? `, ${blocked.toLocaleString()} coverage blocked` : ""}`,
      model.edgeInputComplete ? null : "Correlation edges are partial",
      lossSentence,
      data.updating ? "Updating" : null,
    ]
      .filter((part): part is string => part !== null)
      .join(". ");
  }, [model, lossSentence, data.updating, data.error, data.stage]);
  const spoken = useThrottledValue(announcement, CORRELATION_ANNOUNCE_MS);
  // The publications of the throttle, counted here because the throttle does not report them (it is
  // shared and stays as it is): the region's text changes exactly when it publishes.
  const [region, setRegion] = useState<Region>({ text: spoken, publications: 0 });
  if (region.text !== spoken) setRegion({ text: spoken, publications: region.publications + 1 });
  // Mirrored after the commit, before the effects that read it, so it is the count of the commit they run in.
  useLayoutEffect(() => {
    publicationsRef.current = region.publications;
  }, [region.publications]);
  // The loss is given to the polite region until the region has said it once; after that a later model
  // or "updating" change composes an announcement without it.
  useEffect(() => {
    if (loss === null || !lossWasSaid(loss, lossSentence, region, announcement)) return;
    setLoss((current) => (current === loss ? { ...current, announced: true } : current));
  }, [loss, lossSentence, region, announcement]);

  const optionId = (index: number) => `${uid}-chain-${index}`;
  // The options of the listbox: the chains, then "Not placed" last when the session has unplaced items.
  const onListKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const chains = listed.rows;
    const count = chains.length + (unplacedPresent ? 1 : 0);
    const current = showPane ? chains.length : chains.findIndex((row) => row.id === reconciled.selectedId);
    const go = (index: number) => {
      if (count === 0) return;
      const at = Math.min(Math.max(index, 0), count - 1);
      event.preventDefault();
      const target = chains[at];
      if (target === undefined) showUnplaced();
      else pickChain(target.id);
      document.getElementById(optionId(at))?.scrollIntoView?.({ block: "nearest" });
    };
    switch (event.key) {
      case "ArrowDown":
        go(current + 1);
        return;
      case "ArrowUp":
        go(current - 1);
        return;
      case "Home":
        go(0);
        return;
      case "End":
        go(count - 1);
        return;
      case "Escape":
        // Spent here: the workspace's own Escape handler would otherwise clear the time range.
        event.preventDefault();
        return;
    }
  };

  const markerName = useCallback(
    (marker: PlotMarker) => {
      if (chain === null) return marker.entry;
      const lane = plot?.lanes.find((candidate) => candidate.key === marker.laneKey);
      const phrase =
        marker.role === "nearby"
          ? (marker.linkLabel ?? "")
          : `${linkPhrase(chain, marker.id, linkSummary)}`;
      return [
        lane?.label ?? "",
        marker.entry,
        marker.level,
        formatEventTime(marker.timestampMs, timeZoneMode),
        head(marker.message),
        marker.placement.pinned === null ? null : (marker.pinLabel ?? null),
        phrase,
      ]
        .filter((part): part is string => part !== null && part !== "")
        .join(", ");
    },
    [chain, plot, linkSummary, timeZoneMode],
  );

  const activateMarker = useCallback(
    (marker: PlotMarker) => {
      const item = itemsById.get(marker.id);
      if (item === undefined) return;
      if (item.origin.kind === "log") {
        // An archive text row is a grid record: the dock's resolver, over the strict log matcher.
        const click = resolveMarkerClick(item.origin, useEvtxStore.getState().records);
        if (click.kind === "select") {
          setActionMessage(null);
          selectRecordAndShowDetails(click.recordId);
        } else {
          reply(LOG_ENTRY_NO_SELECTION[click.selectability]);
        }
        return;
      }
      const resolution = resolveOriginRecords(item.origin, loadedEvidenceIndex());
      if (resolution.kind === "notEvent") return; // a log entry was handled above
      if (resolution.kind === "noUsableIdentity") {
        reply("This entry has no usable record identity, so no record is selected.");
      } else if (resolution.records.length === 1) {
        setActionMessage(null);
        selectRecordAndShowDetails((resolution.records[0] as { id: number }).id);
      } else if (resolution.records.length === 0) {
        reply("No loaded event matches this entry, so no record is selected.");
      } else {
        reply(`${resolution.records.length.toLocaleString()} loaded events match this entry, so none is selected.`);
      }
    },
    [itemsById, reply],
  );

  const filterToChain = () => {
    if (chain === null || model === null || !hasItems) return;
    // The button that was pressed unmounts with this view, so focus goes to the Table tab first.
    const result = filterTableToChain({ chain, origins, edgeInputComplete: model.edgeInputComplete });
    if (!result.applied) {
      fail(result.text);
      return;
    }
    setActionMessage(null);
  };

  const copyChain = async () => {
    if (chain === null || model === null || !hasItems) return;
    const text = chainCopyText({
      chain,
      itemsById,
      timeZoneMode,
      scope,
      edgeInput: { edgeInputComplete: model.edgeInputComplete, unloadedEdgeCount: model.unloadedEdgeCount },
      unplaced,
    });
    try {
      await writeText(text);
      reply("Copied the chain as text.");
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      fail(`Copy failed: ${message}`);
    }
  };

  const rootStyle = {
    flex: 1,
    minHeight: 0,
    display: "flex",
    overflow: "hidden",
    fontFamily: LOG_UI_FONT_FAMILY,
    backgroundColor: tokens.colorNeutralBackground1,
  } as const;
  // The two polite regions of the view (spec 10), mounted in every state so that text placed in
  // them is announced: the throttled announcer, which says everything unsolicited (data loaded,
  // updating, selection lost, edges partial), and one reply to the operator's own action, which
  // expects an answer at once. A failure of an action is an alert, not a status.
  const announcer = (
    <span role="status" aria-live="polite" data-testid="correlation-announcer" className={styles.visuallyHidden}>
      {spoken}
    </span>
  );
  const feedback = (
    <>
      <div
        role="status"
        aria-live="polite"
        data-testid="correlation-action-status"
        style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}
      >
        {actionMessage?.kind === "reply" ? actionMessage.text : ""}
      </div>
      {actionMessage?.kind === "failure" && (
        <div
          role="alert"
          data-testid="correlation-action-alert"
          style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground1 }}
        >
          {actionMessage.text}
        </div>
      )}
    </>
  );
  const plain = (text: string) => (
    <div style={{ padding: "12px", fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}>{text}</div>
  );

  if (model === null) {
    return (
      <div data-testid="correlation-view" style={rootStyle}>
        {announcer}
        {data.error !== null ? (
          <div
            role="alert"
            style={{ padding: "12px", fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground1 }}
          >
            {correlationFailureText(data.error, "built")}
          </div>
        ) : (
          plain(data.stage === "unavailable" ? NO_ANALYSIS_TEXT : READING_EDGES_TEXT)
        )}
        {feedback}
      </div>
    );
  }

  const reading = data.nextScan?.state === "running" || data.stage === "scanning";
  const progress = data.nextScan?.progress ?? scan.progress;
  // "No correlation chains in this session" is a claim about the whole session: the rail's rule, with
  // every origin gap a member, and the edges only one of its inputs.
  const speaksForAbsence = sessionSpeaksForAbsenceOverall({
    edgeInputComplete: model.edgeInputComplete,
    scopeNarrowed,
    unreadSources,
    updating: data.updating,
    gaps,
  });
  const notices = correlationNotices({
    edgeInput: { edgeInputComplete: model.edgeInputComplete, unloadedEdgeCount: model.unloadedEdgeCount },
    edgeError: edges.error,
    gaps,
    scan,
    selectionLoss: visibleLoss(loss, lossFacts),
    scope,
    cap: { shown: model.chains.length, totalCount: model.totalCount, omittedCount: model.omittedCount },
    pastCapShown: listed.pastCapId === null ? null : model.chains.length,
  });
  const selectedIndex = showPane ? listed.rows.length : listed.rows.findIndex((row) => row.id === chain?.id);
  const header = chain === null ? null : keyHeader(chain.keys);
  const visibleSequence = sequence === null ? [] : showAllSequence ? sequence.entries : sequence.entries.slice(0, CORRELATION_SEQUENCE_INITIAL);
  const visibleWhy = showAllWhy ? why : why.slice(0, CORRELATION_SEQUENCE_INITIAL);
  const plotNotice = plot === null ? null : plotOmissionNotice(plot);
  const { canAct, reason: actReason } = chainActionAvailability({
    hasItems,
    updating: data.updating,
    hasChain: chain !== null,
  });

  return (
    <div data-testid="correlation-view" aria-busy={data.updating || reading || undefined} style={rootStyle}>
      {announcer}
      <div
        style={{
          width: `${LIST_WIDTH_PX}px`,
          flexShrink: 0,
          display: "flex",
          flexDirection: "column",
          minHeight: 0,
          backgroundColor: tokens.colorNeutralBackground2,
          borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
        }}
      >
        <div
          style={{
            padding: "10px 12px 6px",
            fontSize: `${sizes.label}px`,
            fontWeight: 600,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: palette.listSecondary,
          }}
        >
          Chains {"·"} strongest first
        </div>
        {model.chains.length === 0 && (
          <div style={{ padding: "8px 12px", fontSize: `${sizes.lane}px`, color: palette.listPrimary }}>
            {noChainsFoundText(speaksForAbsence)}
          </div>
        )}
        {(model.chains.length > 0 || unplacedPresent) && (
          <div
            ref={listRef}
            role="listbox"
            tabIndex={0}
            aria-label={
              unplacedPresent
                ? "Correlation chains, strongest first, and items that are not placed"
                : "Correlation chains, strongest first"
            }
            aria-activedescendant={selectedIndex >= 0 ? optionId(selectedIndex) : undefined}
            onKeyDown={onListKeyDown}
            style={{ overflowY: "auto", flex: model.chains.length > 0 ? 1 : undefined, minHeight: 0 }}
          >
            {listed.rows.map((row, index) => (
              <ChainRow
                key={row.id}
                chain={row}
                id={optionId(index)}
                selected={!showPane && row.id === chain?.id}
                timeZoneMode={timeZoneMode}
                palette={palette}
                onSelect={pickChain}
              />
            ))}
            {unplacedPresent && (
              <NotPlacedRow
                id={optionId(listed.rows.length)}
                view={unplacedView}
                selected={showPane}
                palette={palette}
                onSelect={showUnplaced}
              />
            )}
          </div>
        )}
      </div>

      <div data-testid="correlation-detail" style={DETAIL_COLUMN_STYLE}>
        {(data.updating || reading) && (
          // Not a live region: the scan reports a page at a time, which would queue an announcement
          // per page. The announcer says "Updating" once, throttled.
          <div data-testid="correlation-updating" style={{ fontSize: `${sizes.lane}px`, color: palette.caption }}>
            {data.updating ? `${UPDATING_CORRELATION_TEXT} ` : ""}
            {reading ? timelineReadingText(progress) : ""}
          </div>
        )}
        {notices.length > 0 && (
          <ul
            data-testid="correlation-notices"
            style={{ margin: 0, paddingLeft: "18px", fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}
          >
            {notices.map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        )}
        {(edges.error !== null || scan.state === "incomplete") && (
          <div>
            <Button size="small" appearance="secondary" onClick={data.retry}>
              Retry
            </Button>
          </div>
        )}
        {data.error !== null && (
          <div role="alert" style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground1 }}>
            {correlationFailureText(data.error, "updated")}
          </div>
        )}
        {showPane ? (
          <>
            <EvtxUnplacedList
              list={data.unplacedList}
              updating={data.updating}
              sizes={sizes}
              onReply={reply}
              onFail={fail}
              onEscape={() => listRef.current?.focus()}
            />
            {feedback}
          </>
        ) : chain === null ? null : (
          <>
            <div style={{ display: "grid", gap: "4px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
                <h2
                  style={{
                    margin: 0,
                    fontSize: `${sizes.f + 1}px`,
                    fontWeight: 600,
                    color: tokens.colorNeutralForeground1,
                  }}
                >
                  {chainTitle(chain)}
                </h2>
                <EvtxStrengthBadge strength={chain.strength} visuals={palette.visuals} textSize={palette.sizes.label} />
              </div>
              <div style={{ fontSize: `${sizes.lane}px`, color: palette.caption, display: "flex", gap: "6px", flexWrap: "wrap" }}>
                {header !== null && (
                  <span>
                    key {keyKindLabel(header.kind)}{" "}
                    <span title={header.value} style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY }}>
                      {header.shortValue}
                    </span>
                    {header.more > 0 ? ` and ${header.more.toLocaleString()} more` : ""}
                  </span>
                )}
                {spanText(chain.startMs, chain.endMs, timeZoneMode) !== null && (
                  <span style={{ fontFamily: tokens.fontFamilyNumeric, fontVariantNumeric: "tabular-nums" }}>
                    {header !== null ? "· " : ""}
                    {spanText(chain.startMs, chain.endMs, timeZoneMode)} ({timeZoneLabel(timeZoneMode, chain.startMs ?? undefined)})
                  </span>
                )}
              </div>
              {isPartialChain(chain) && (
                <div data-testid="partial-notice" style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}>
                  {unresolvedNotice(chain, unplaced)}
                </div>
              )}
              {plot !== null && <CorrelationLegend plot={plot} sizes={sizes} />}
            </div>

            {plot !== null ? (
              <>
                <EvtxCorrelationOverview
                  chains={listed.rows}
                  selectedId={chain.id}
                  window={bandWindow}
                  onWindowChange={onBandChange}
                  timeZoneMode={timeZoneMode}
                  sizes={sizes}
                />
                <EvtxCorrelationLanes
                  plot={plot}
                  timeZoneMode={timeZoneMode}
                  sizes={sizes}
                  label={`Lane plot for ${chainAccessibleName(chain)}: ${chain.memberCount.toLocaleString()} entries across ${plot.lanes.length.toLocaleString()} sources. Sequence lists the same entries in order.`}
                  markerName={markerName}
                  onActivate={activateMarker}
                  onEscape={() => listRef.current?.focus()}
                />
                {plotNotice !== null && (
                  <div data-testid="plot-omission" style={{ fontSize: `${sizes.lane}px`, color: palette.caption }}>
                    {plotNotice}
                  </div>
                )}
              </>
            ) : (
              <div style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}>
                {reading
                  ? CHAIN_ENTRIES_BEING_READ_TEXT
                  : "The entries of this chain were not read, so there is no plot or evidence table."}
              </div>
            )}
            {feedback}

            <div style={{ display: "flex", flexWrap: "wrap", gap: "10px" }}>
              <section aria-labelledby={`${uid}-why`} style={cardStyle}>
                <div id={`${uid}-why`}>
                  <CardHeading palette={palette}>{whyHeading(chain.strength)}</CardHeading>
                </div>
                <p style={{ margin: 0, fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}>
                  {whyStatement(chain)}
                </p>
                {hasItems && (
                  <table style={{ borderCollapse: "collapse", width: "100%", fontSize: `${sizes.lane}px` }}>
                    <thead>
                      <tr>
                        {["Entry", "Where the key appears"].map((title) => (
                          <th
                            key={title}
                            scope="col"
                            style={{
                              textAlign: "left",
                              padding: "3px 6px",
                              fontSize: `${sizes.label}px`,
                              fontWeight: 600,
                              color: palette.caption,
                              borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                            }}
                          >
                            {title}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {visibleWhy.map((row) => (
                        <tr key={`${row.originId}|${row.field}|${row.value}`}>
                          <td style={{ padding: "3px 6px", color: tokens.colorNeutralForeground1, fontFamily: tokens.fontFamilyNumeric }}>
                            {row.entry}
                          </td>
                          <td style={{ padding: "3px 6px", color: tokens.colorNeutralForeground1 }}>
                            {row.field} ={" "}
                            <span style={{ fontFamily: LOG_MONOSPACE_FONT_FAMILY, overflowWrap: "anywhere" }}>{row.value}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
                {hasItems && why.length === 0 && (
                  <div style={{ fontSize: `${sizes.lane}px`, color: palette.caption }}>
                    No evidence row was loaded for this row.
                  </div>
                )}
                {why.length > CORRELATION_SEQUENCE_INITIAL && !showAllWhy && (
                  <Button size="small" appearance="subtle" onClick={() => setShowAllWhy(true)}>
                    {`Show all ${why.length.toLocaleString()}`}
                  </Button>
                )}
              </section>

              <section aria-labelledby={`${uid}-sequence`} style={cardStyle}>
                <div id={`${uid}-sequence`}>
                  <CardHeading palette={palette}>Sequence</CardHeading>
                </div>
                <div style={{ fontSize: `${sizes.label}px`, color: palette.caption }}>
                  {SEQUENCE_ORDER_NOTE}
                </div>
                {sequence !== null && sequence.entries.length === 0 && (
                  <div style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}>
                    {NO_ENTRY_POSITION_TEXT}
                  </div>
                )}
                <ol style={{ margin: 0, paddingLeft: "22px", display: "grid", gap: "4px", fontSize: `${sizes.lane}px` }}>
                  {visibleSequence.map((entry) => {
                    const level = visuals.levels[entry.level];
                    const Icon = level.RailIcon;
                    return (
                      <li
                        key={entry.id}
                        data-sequence-entry={entry.id}
                        style={{ color: tokens.colorNeutralForeground1, fontWeight: entry.highestSeverity ? 600 : 400 }}
                      >
                        <span style={{ fontFamily: tokens.fontFamilyNumeric, fontVariantNumeric: "tabular-nums" }}>
                          {entry.index === 0
                            ? formatEventTime(entry.timestampMs, timeZoneMode)
                            : `+${formatDelta(entry.offsetMs)}`}
                        </span>{" "}
                        <span style={{ color: level.textColor }}>
                          <Icon aria-hidden="true" style={{ verticalAlign: "middle", color: level.railIconColor, width: "14px", height: "14px" }} />{" "}
                          {entry.level}
                        </span>{" "}
                        <span style={{ fontFamily: tokens.fontFamilyNumeric }}>{entry.entry}</span>{" "}
                        <span style={{ color: palette.caption }}>[{entry.laneLabel}]</span>{" "}
                        <span style={{ color: tokens.colorNeutralForeground2 }}>{head(entry.message)}</span>
                        {entry.sameTimeAsPrevious && (
                          <span style={{ color: palette.caption }}> {SAME_TIME_NOTE}</span>
                        )}
                      </li>
                    );
                  })}
                </ol>
                {sequence !== null && sequence.entries.length > CORRELATION_SEQUENCE_INITIAL && !showAllSequence && (
                  <Button size="small" appearance="subtle" onClick={() => setShowAllSequence(true)}>
                    {`Show all ${sequence.entries.length.toLocaleString()}`}
                  </Button>
                )}
                {sequence !== null && sequence.itemlessIds.length > 0 && (
                  <div style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}>
                    {unresolvedNotice(chain, unplaced)}
                  </div>
                )}
                <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                  <Button
                    appearance="primary"
                    size="small"
                    icon={<Filter16Regular />}
                    disabledFocusable={!canAct}
                    title={actReason}
                    onClick={canAct ? filterToChain : undefined}
                  >
                    Filter table to chain
                  </Button>
                  <Button
                    appearance="secondary"
                    size="small"
                    icon={<Copy16Regular />}
                    disabledFocusable={!canAct}
                    title={actReason}
                    onClick={canAct ? () => void copyChain() : undefined}
                  >
                    Copy as text
                  </Button>
                </div>
              </section>
            </div>
          </>
        )}
        {!showPane && chain === null && feedback}
      </div>
    </div>
  );
}

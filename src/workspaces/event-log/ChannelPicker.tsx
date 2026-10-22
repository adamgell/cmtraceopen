import { Fragment, memo, useMemo, useRef, useState, useEffect, useCallback } from "react";
import { Button, Input, Link, makeStyles, tokens } from "@fluentui/react-components";
import { ChevronDown12Regular, ChevronRight12Regular } from "@fluentui/react-icons";
import { contrastRatio } from "../../lib/color-contrast";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { getThemeById } from "../../lib/themes";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { cancelActiveLoad, channelCanHoldEvents, useEvtxStore } from "./evtx-store";
import {
  countChannelLeaves,
  sortedChannelChildren,
  type ChannelTreeNode,
} from "./evtx-channel-order";
import {
  APP_SERVICES_GROUP,
  NO_CHANNEL_STATS,
  TEXT_LOGS_GROUP,
  WINDOWS_LOGS_GROUP,
  buildChannelPaneModel,
  defaultExpandedGroups,
  scaleActivityBars,
  summarizeLogSources,
  type ChannelPaneModel,
  type ChannelReadState,
  type ChannelRowModel,
  type TextLogRowModel,
} from "./evtx-channel-stats";
import { useEvtxVisualTokens, type EvtxVisualTokens } from "./evtx-visual-tokens";
import { AddLogSourceControl } from "./AddLogSourceControl";
import { ChannelClearControls, ChannelClearDialog } from "./ChannelClearControls";
import { EvtxResizeHandle } from "./EvtxResizeHandle";
import { effectiveResizeRange, proposeResize, useRowCappedSize } from "./use-row-capped-size";
import { scopeLogEntries } from "./unified-timeline";
import { useChannelClear } from "./use-channel-clear";
import type { EvtxChannelInfo, EvtxTimeWindow } from "./types";

// ── Constants ───────────────────────────────────────────────────────────────

const MIN_SIDEBAR_WIDTH = 200;
const MAX_SIDEBAR_WIDTH = 500;
const DEFAULT_SIDEBAR_WIDTH = 250;
const CHANNEL_PANE_ID = "evtx-channel-pane";

/** Live tail republishes the pane's numbers at most this often (spec 11). */
const TAIL_STATS_INTERVAL_MS = 75;
const SPARKLINE_HEIGHT = 18;
/** Horizontal units per bin in the sparkline's viewBox; the bar is one unit narrower. */
const SPARKLINE_BIN_UNITS = 4;
const MAX_CORRELATING_SOURCES = 50;
/** Reasons a header disclosure lists, in text and in its tooltip, before "and N more". */
const MAX_DISCLOSED_REASONS = 5;

/**
 * Shown where a channel has no count. U+2014, which spec 8.6 writes for an unreadable channel's
 * total; a literal em dash is otherwise kept out of this repo's sources, hence the escape.
 */
const NO_COUNT = "\u2014";

const WINDOW_ACTIVITY_LABELS: Record<EvtxTimeWindow, string> = {
  "1h": "1 h",
  "24h": "24 h",
  "7d": "7 d",
  "30d": "30 d",
  all: "all-time",
};

const STATE_LABELS: Record<ChannelReadState, string> = {
  read: "",
  partial: "partial",
  notLoaded: "not loaded",
  needsElevation: "needs elevation",
  accessDenied: "access denied",
  notRead: "not read",
  disabled: "",
};

/** States that tell the operator something is missing; their label is emphasized. */
const GAP_STATES: ReadonlySet<ChannelReadState> = new Set([
  "partial",
  "needsElevation",
  "accessDenied",
  "notRead",
]);

/** States with no numbers to show: the name is dimmed and the total is a dash. */
const UNAVAILABLE_STATES: ReadonlySet<ChannelReadState> = new Set([
  "needsElevation",
  "accessDenied",
  "notRead",
  "disabled",
]);

const useStyles = makeStyles({
  disclosure: {
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: "-2px",
    },
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

/** The service says the channel is switched off; the channel is listed, not selectable. */
const isSwitchedOff = (channel: EvtxChannelInfo) => !channelCanHoldEvents(channel);

/**
 * The pane's two text colors the spec draws from Foreground1 (names, labels) and Foreground3
 * (the eyebrow, the header count, an unavailable channel's name). Each is the designed color
 * wherever it reaches the 4.5:1 text floor on the pane (Background2) and falls back to
 * Foreground2 only in the themes where it does not: Foreground1 measures 4.11:1 in solarized-dark,
 * and Foreground3 measures 2.92:1 there and 3.36:1 in dracula. The decision reads each theme's own
 * token values, so a theme where the designed color passes is untouched and keeps the dim cue.
 */
interface PaneText {
  primary: string;
  muted: string;
}

function usePaneText(): PaneText {
  const themeId = useUiStore((s) => s.themeId);
  return useMemo(() => {
    const { fluentTheme } = getThemeById(themeId);
    const reads = (foreground: string) =>
      contrastRatio(foreground, fluentTheme.colorNeutralBackground2) >= 4.5;
    return {
      primary: reads(fluentTheme.colorNeutralForeground1)
        ? tokens.colorNeutralForeground1
        : tokens.colorNeutralForeground2,
      muted: reads(fluentTheme.colorNeutralForeground3)
        ? tokens.colorNeutralForeground3
        : tokens.colorNeutralForeground2,
    };
  }, [themeId]);
}

/**
 * Publishes `value` at most once per `intervalMs` while `active`, and passes it straight through
 * otherwise. A throttle rather than a trailing debounce, so a tail that never goes quiet for the
 * interval still updates the pane.
 */
function useThrottledWhile<T>(value: T, intervalMs: number, active: boolean): T {
  const [published, setPublished] = useState(value);
  const [wasActive, setWasActive] = useState(active);
  if (active !== wasActive) {
    // Adjusted during render so the first throttled value is the current one, not whatever was
    // published the last time a tail ran.
    setWasActive(active);
    if (active) setPublished(value);
  }
  const latest = useRef(value);
  latest.current = value;
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (!active) {
      if (timer.current !== null) {
        clearTimeout(timer.current);
        timer.current = null;
      }
      return;
    }
    if (timer.current !== null) return;
    timer.current = setTimeout(() => {
      timer.current = null;
      setPublished(latest.current);
    }, intervalMs);
  }, [value, active, intervalMs]);

  useEffect(
    () => () => {
      if (timer.current !== null) clearTimeout(timer.current);
    },
    [],
  );

  return active ? published : value;
}

// ── Component ───────────────────────────────────────────────────────────────

export function ChannelPicker() {
  const tailMode = useEvtxStore((s) => s.tailMode);
  const startLiveTail = useEvtxStore((s) => s.startLiveTail);
  const stopLiveTail = useEvtxStore((s) => s.stopLiveTail);
  const clearChannel = useEvtxStore((s) => s.clearChannel);
  const channelFilterRef = useRef<HTMLInputElement | null>(null);
  const channels = useEvtxStore((s) => s.channels);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const toggleChannel = useEvtxStore((s) => s.toggleChannel);
  const selectAllChannels = useEvtxStore((s) => s.selectAllChannels);
  const deselectAllChannels = useEvtxStore((s) => s.deselectAllChannels);
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const loadedChannels = useEvtxStore((s) => s.loadedChannels);
  const loadSelectedChannels = useEvtxStore((s) => s.loadSelectedChannels);
  const refreshLoadedChannels = useEvtxStore((s) => s.refreshLoadedChannels);
  const isLoading = useEvtxStore((s) => s.isLoading);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const smallFontSize = Math.max(9, metrics.fontSize - 3);
  const captionFontSize = Math.max(10, metrics.fontSize - 3);
  const groupFontSize = Math.max(10, metrics.fontSize - 2);
  const visual = useEvtxVisualTokens();
  const { primary: primaryText, muted: mutedText } = usePaneText();
  const styles = useStyles();

  const records = useEvtxStore((s) => s.records);
  const timeWindow = useEvtxStore((s) => s.timeWindow);
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const coverageDetails = useEvtxStore((s) => s.coverageDetails);
  const sourceManifest = useEvtxStore((s) => s.sourceManifest);
  const legacyCoverage = useEvtxStore((s) => s.coverageGaps);
  const tailChannels = useEvtxStore((s) => s.tailChannels);
  const tailCoverageGaps = useEvtxStore((s) => s.tailCoverageGaps);
  const archiveMembers = useEvtxStore((s) => s.archiveMembers);

  const logEntries = useLogStore((s) => s.entries);
  const activeLogSource = useLogStore((s) => s.activeSource);
  const logSourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  // A text-log load moves the source before the entries, so the list is not settled while it runs.
  const logStoreLoading = useLogStore((s) => s.isLoading);
  const currentPlatform = useUiStore((s) => s.currentPlatform);

  const [search, setSearch] = useState("");
  // What the operator opened or closed by hand. Everything else follows the data: see below.
  const [toggledGroups, setToggledGroups] = useState<ReadonlyMap<string, boolean>>(
    () => new Map(),
  );
  const [sidebarWidth, setSidebarWidth] = useState(DEFAULT_SIDEBAR_WIDTH);
  // On a narrow window the workspace caps this pane below `sidebarWidth`; the handle reports and
  // steps from the width actually rendered, and its maximum never exceeds the cap.
  const { ref: paneRef, ...paneMeasure } = useRowCappedSize(2, sidebarWidth);
  const resizeRange = effectiveResizeRange(
    sidebarWidth,
    MIN_SIDEBAR_WIDTH,
    MAX_SIDEBAR_WIDTH,
    paneMeasure,
  );

  // Its effects run before the pane's own (the throttle below): keep the call ahead of them.
  const clearWorkflow = useChannelClear({ clearChannel, loadedChannels, channelFilterRef });

  // The numbers follow the records while a live tail is running, but no faster than once per
  // interval, so a busy tail does not recompute the pane on every batch.
  const statsRecords = useThrottledWhile(records, TAIL_STATS_INTERVAL_MS, tailMode !== null);
  // A snapshot taken when the numbers are, like the workspace's own `nowEpoch`.
  const nowMs = useMemo(() => Date.now(), [statsRecords, timeWindow]);
  const model = useMemo(
    () =>
      buildChannelPaneModel({
        channels,
        records: statsRecords,
        loadedChannels,
        sourceMode,
        remoteMachine,
        nowMs,
        timeWindow,
        coverageDetails,
        manifestCoverage: sourceManifest?.coverage ?? [],
        legacyCoverage,
        tailCoverage: tailCoverageGaps,
        archiveMembers,
        isSwitchedOff,
      }),
    [
      channels,
      statsRecords,
      loadedChannels,
      sourceMode,
      remoteMachine,
      nowMs,
      timeWindow,
      coverageDetails,
      sourceManifest,
      legacyCoverage,
      tailCoverageGaps,
      archiveMembers,
    ],
  );

  // Filtering shortens the list but never renumbers it: a channel's color index comes from the
  // model's display order, which does not depend on the filter text or on collapsed groups.
  const filteredChannels = useMemo(() => {
    if (!search.trim()) return null;
    const lower = search.toLowerCase();
    return model.channels.filter((c) => c.name.toLowerCase().includes(lower));
  }, [model.channels, search]);

  const filteredTextLogs = useMemo(() => {
    if (!search.trim()) return null;
    const lower = search.toLowerCase();
    return model.textLogs.filter(
      (row) => row.label.toLowerCase().includes(lower) || row.name.toLowerCase().includes(lower),
    );
  }, [model.textLogs, search]);

  // The text logs the workspace hands to the analysis session, mirrored from its own scoping.
  const correlatingSources = useMemo(
    () =>
      summarizeLogSources(
        scopeLogEntries(logEntries, activeLogSource, logSourceOpenMode, currentPlatform),
      ),
    [logEntries, activeLogSource, logSourceOpenMode, currentPlatform],
  );

  const rowMetrics = useMemo<RowMetrics>(
    () => ({
      fontSize: metrics.fontSize,
      rowHeight: metrics.rowHeight,
      captionFontSize,
      groupFontSize,
    }),
    [metrics.fontSize, metrics.rowHeight, captionFontSize, groupFontSize],
  );
  const windowLabel = WINDOW_ACTIVITY_LABELS[timeWindow];
  // Gaps that name no row cannot be counted in any row, so while any exist the header prints no
  // "k of k read": it says how many channels are listed and how many gaps belong to none of them.
  const unattributedCount = model.unattributed.count;
  const hasUnattributed = unattributedCount > 0;
  const channelsLabel = `${model.totalCount} ${model.totalCount === 1 ? "channel" : "channels"}`;
  const unattributedNote = `${unattributedCount} not attributed to a channel`;
  const shownReasons = model.unattributed.reasons.slice(0, MAX_DISCLOSED_REASONS);
  const moreReasons = unattributedCount - shownReasons.length;
  const reasonList = (format: (reason: string) => string) =>
    `${shownReasons.map(format).join("; ")}${moreReasons > 0 ? ` and ${moreReasons} more` : ""}`;
  // Spoken text never reads out a digest; the tooltip keeps the reasons as the backend wrote them.
  const unattributedSentence = `${unattributedCount} ${
    unattributedCount === 1 ? "gap" : "gaps"
  } could not be attributed to a channel: ${reasonList(speakable)}.`;

  const unloadedSelectedCount =
    sourceMode !== "live"
      ? 0
      : [...selectedChannels].filter((ch) => !loadedChannels.has(ch)).length;

  // A group starts open when a loaded channel in it holds events, so the rows the operator came
  // for are showing, and the rest stay closed. A group the operator toggled keeps their choice
  // however the data changes afterwards.
  const defaultExpanded = useMemo(() => defaultExpandedGroups(model), [model]);
  const defaultExpandedRef = useRef(defaultExpanded);
  defaultExpandedRef.current = defaultExpanded;
  const expanded = useMemo(() => {
    const open = new Set(defaultExpanded);
    for (const [key, isOpen] of toggledGroups) {
      if (isOpen) open.add(key);
      else open.delete(key);
    }
    return open;
  }, [defaultExpanded, toggledGroups]);
  const toggleExpand = useCallback((key: string) => {
    setToggledGroups((prev) => {
      const wasOpen = prev.get(key) ?? defaultExpandedRef.current.has(key);
      return new Map(prev).set(key, !wasOpen);
    });
  }, []);

  const rowEnv = {
    visual,
    primaryText,
    mutedText,
    windowLabel,
    metrics: rowMetrics,
    onToggleChannel: toggleChannel,
    onToggleExpand: toggleExpand,
  };

  return (
    // The pane is exactly `sidebarWidth` wide including its 1 px right border (spec 5.2). The
    // resize strip is overlaid on that border rather than adding a band beside it.
    <div
      id={CHANNEL_PANE_ID}
      ref={paneRef}
      style={{
        display: "flex",
        // Shrinkable only so the 40% cap on the workspace's channel wrapper (the body row's
        // flex child) can take effect. A percentage cap here would resolve against that
        // shrink-to-fit wrapper, i.e. against the pane's own width.
        flexShrink: 1,
        position: "relative",
        boxSizing: "border-box",
        width: `${sidebarWidth}px`,
        minWidth: 0,
        borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          height: "100%",
          width: "100%",
          backgroundColor: tokens.colorNeutralBackground2,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            gap: "8px",
            padding: "10px 12px 6px",
            flexShrink: 0,
          }}
        >
          <span style={eyebrowStyle(captionFontSize, mutedText)}>Channels</span>
          <span
            title={
              hasUnattributed
                ? `${channelsLabel}. ${unattributedNote}: ${reasonList((reason) => reason)}.`
                : `${model.readCount} of ${model.totalCount} channels read`
            }
            style={{
              ...numericStyle(captionFontSize),
              color: mutedText,
              minWidth: 0,
              overflow: "hidden",
              textOverflow: "ellipsis",
              // The disclosure is longer than the pane: wrap it instead of cutting it off.
              whiteSpace: hasUnattributed ? "normal" : "nowrap",
              textAlign: "right",
            }}
          >
            {hasUnattributed
              ? `${channelsLabel} \u00B7 ${unattributedNote}`
              : `${model.readCount} of ${model.totalCount} read \u00B7 ${windowLabel} activity`}
          </span>
          {hasUnattributed && (
            <span className={styles.visuallyHidden}>{unattributedSentence}</span>
          )}
        </div>
        {/* Controls */}
        <div
          style={{
            padding: "0 8px 8px",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            display: "flex",
            flexDirection: "column",
            gap: "4px",
            flexShrink: 0,
          }}
        >
          <Input
            ref={channelFilterRef}
            value={search}
            onChange={(_, data) => setSearch(data.value)}
            placeholder="Filter channels..."
            size="small"
            input={{ style: { fontSize: `${metrics.fontSize}px` } }}
            style={{ width: "100%" }}
          />
          <div style={{ display: "flex", gap: "4px" }}>
            <Button
              size="small"
              appearance="subtle"
              onClick={selectAllChannels}
              style={{ fontSize: `${metrics.fontSize}px` }}
            >
              Select all
            </Button>
            <Button
              size="small"
              appearance="subtle"
              onClick={deselectAllChannels}
              style={{ fontSize: `${metrics.fontSize}px` }}
            >
              Deselect all
            </Button>
          </div>
          {sourceMode === "live" && (
            <div style={{ display: "flex", gap: "4px" }}>
              {isLoading ? (
                <Button
                  size="small"
                  appearance="primary"
                  onClick={() => void cancelActiveLoad()}
                  title="Stop the running channel load and keep what has arrived so far"
                  style={{ flex: 1, fontSize: `${metrics.fontSize}px` }}
                >
                  Stop load
                </Button>
              ) : (
                unloadedSelectedCount > 0 && (
                  <Button
                    size="small"
                    appearance="primary"
                    onClick={loadSelectedChannels}
                    style={{ flex: 1, fontSize: `${metrics.fontSize}px` }}
                  >
                    Load {unloadedSelectedCount}
                  </Button>
                )
              )}
              <Button
                size="small"
                appearance="subtle"
                disabled={isLoading}
                onClick={refreshLoadedChannels}
                title="Reload all loaded channels"
                style={{ fontSize: `${metrics.fontSize}px` }}
              >
                Refresh
              </Button>
            </div>
          )}
          {sourceMode === "live" && loadedChannels.size > 0 && (
            <ChannelClearControls
              workflow={clearWorkflow}
              loadedChannels={loadedChannels}
              isLoading={isLoading}
              fontSize={metrics.fontSize}
              smallFontSize={smallFontSize}
            />
          )}
        </div>
        <ChannelClearDialog workflow={clearWorkflow} />

        {/* Tree */}
        <div
          data-channel-tree=""
          style={{ flex: 1, overflowY: "auto", padding: "2px 0", fontSize: `${metrics.fontSize}px` }}
        >
          {filteredChannels ? (
            // Flat search results
            filteredChannels.map((ch) => (
              <ChannelRow
                key={ch.name}
                channel={ch}
                row={model.rows.get(ch.name)!}
                label={ch.name}
                depth={0}
                selected={selectedChannels.has(ch.name)}
                tailing={tailChannels.has(ch.name)}
                {...rowEnv}
              />
            ))
          ) : (
            <>
              {/* Windows Logs */}
              <GroupRow
                groupKey={WINDOWS_LOGS_GROUP}
                label="Windows Logs"
                expanded={expanded.has(WINDOWS_LOGS_GROUP)}
                onToggle={toggleExpand}
                depth={0}
                count={model.tree.windowsLogs.length}
                metrics={rowMetrics}
              />
              {expanded.has(WINDOWS_LOGS_GROUP) &&
                model.tree.windowsLogs.map((ch) => (
                  <ChannelRow
                    key={ch.name}
                    channel={ch}
                    row={model.rows.get(ch.name)!}
                    label={ch.name}
                    depth={1}
                    selected={selectedChannels.has(ch.name)}
                    tailing={tailChannels.has(ch.name)}
                    {...rowEnv}
                  />
                ))}

              {/* Applications and Services Logs */}
              <GroupRow
                groupKey={APP_SERVICES_GROUP}
                label="Applications and Services Logs"
                expanded={expanded.has(APP_SERVICES_GROUP)}
                onToggle={toggleExpand}
                depth={0}
                count={countChannelLeaves(model.tree.serviceTree)}
                metrics={rowMetrics}
              />
              {expanded.has(APP_SERVICES_GROUP) && (
                <TreeNodeView
                  node={model.tree.serviceTree}
                  depth={1}
                  expanded={expanded}
                  rows={model.rows}
                  selectedChannels={selectedChannels}
                  tailChannels={tailChannels}
                  rowEnv={rowEnv}
                />
              )}

              {/* Text logs the archive reader listed as channels: not event channels */}
              {model.textLogs.length > 0 && (
                <>
                  <GroupRow
                    groupKey={TEXT_LOGS_GROUP}
                    label="Text logs in sources"
                    expanded={expanded.has(TEXT_LOGS_GROUP)}
                    onToggle={toggleExpand}
                    depth={0}
                    count={model.textLogs.length}
                    metrics={rowMetrics}
                  />
                  {expanded.has(TEXT_LOGS_GROUP) &&
                    model.textLogs.map((row, position) => (
                      <TextLogRow
                        key={row.name}
                        row={row}
                        position={position}
                        depth={1}
                        selected={selectedChannels.has(row.name)}
                        {...rowEnv}
                      />
                    ))}
                </>
              )}
            </>
          )}
          {filteredTextLogs?.map((row, position) => (
            <TextLogRow
              key={row.name}
              row={row}
              position={position}
              depth={0}
              selected={selectedChannels.has(row.name)}
              {...rowEnv}
            />
          ))}
          {filteredChannels && filteredChannels.length === 0 && filteredTextLogs?.length === 0 && (
            <div
              style={{
                fontSize: `${smallFontSize}px`,
                color: tokens.colorNeutralForeground2,
                padding: "12px 8px",
                textAlign: "center",
              }}
            >
              No channels match filter
            </div>
          )}
          {/* Always rendered, even with no text log: the Add log source link lives here. */}
          <AlsoCorrelating
            sources={correlatingSources}
            merged={logSourceOpenMode === "merged"}
            logStoreLoading={logStoreLoading}
            metrics={rowMetrics}
            primaryText={primaryText}
            mutedText={mutedText}
          />
        </div>

        {sourceMode === "live" && loadedChannels.size > 0 && (
          <LiveTailFooter
            tailMode={tailMode}
            tailingChannels={tailChannels.size}
            busy={isLoading}
            onStop={() => void stopLiveTail()}
            onResume={() => void startLiveTail()}
            visual={visual}
            primaryText={primaryText}
            metrics={rowMetrics}
          />
        )}
      </div>

      <EvtxResizeHandle
        orientation="vertical"
        edge="end"
        label="Resize channel pane"
        controls={CHANNEL_PANE_ID}
        value={resizeRange.value}
        min={resizeRange.min}
        max={resizeRange.max}
        direction={1}
        onChange={(next) => {
          // Only an interaction that changes the visible width may change the stored one; while
          // the cap binds, a proposal equal to the rendered width must not overwrite the request.
          const proposed = proposeResize(next, resizeRange);
          if (proposed !== null) setSidebarWidth(proposed);
        }}
      />
    </div>
  );
}


// ── Rows ────────────────────────────────────────────────────────────────────

/** Sizes derived from the list font size, so every row follows the user's setting. */
interface RowMetrics {
  fontSize: number;
  rowHeight: number;
  /** Totals, counts and statuses: max(10, f - 3). */
  captionFontSize: number;
  /** Group headers: max(10, f - 2). */
  groupFontSize: number;
}

/** What every row needs besides its own channel; stable between renders so rows can stay memoized. */
interface RowEnv {
  visual: EvtxVisualTokens;
  primaryText: string;
  mutedText: string;
  windowLabel: string;
  metrics: RowMetrics;
  onToggleChannel: (name: string) => void;
  onToggleExpand: (key: string) => void;
}

const eyebrowStyle = (fontSize: number, color: string) =>
  ({
    fontSize: `${fontSize}px`,
    fontWeight: 600,
    letterSpacing: ".08em",
    textTransform: "uppercase",
    color,
  }) as const;

const numericStyle = (fontSize: number) =>
  ({
    fontSize: `${fontSize}px`,
    fontFamily: tokens.fontFamilyNumeric,
    fontVariantNumeric: "tabular-nums",
  }) as const;

function sparklineLabel(row: ChannelRowModel, windowLabel: string): string {
  const { bins, total, unplaced, outsideSpan } = row.stats;
  const prefix = `${windowLabel} activity: `;
  if (total === 0) return `${prefix}no events`;
  const peak = Math.max(...bins);
  const active = bins.filter((count) => count > 0).length;
  const plotted =
    peak === 0
      ? "no event could be placed on the chart"
      : `${active} of ${bins.length} intervals had events, busiest ${peak}`;
  const unplotted = unplaced + outsideSpan;
  return unplotted === 0
    ? `${prefix}${plotted}`
    : `${prefix}${plotted}; ${unplotted} not plotted (${unplaced} without a timestamp, ${outsideSpan} outside the window)`;
}

/**
 * A reason as it is spoken. Backend reasons can end in "(sha256:<64 hex digits>)" (an archive
 * member that failed to parse): the tooltip keeps the digest, the spoken text does not read it out.
 */
function speakable(reason: string): string {
  return reason.replace(/\s*\(sha256:[0-9a-f]{64}\)/gi, "").trim();
}

/**
 * What a screen reader gets for a row, as the checkbox's description: the total (or that there is
 * none), the counts, the state, the activity chart in words, why the channel is not complete, and
 * whether the tail covers it. The visible counts and the sparkline repeat this and are hidden from
 * assistive technology, so each number is read once and the tooltip is never the only carrier.
 */
function rowDescription(
  row: ChannelRowModel,
  windowLabel: string,
  { tailing, switchedOff }: { tailing: boolean; switchedOff: boolean },
): string {
  const { state, stats } = row;
  const parts: string[] = [];
  if (state === "read" || state === "partial") {
    const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;
    parts.push(
      `${plural(stats.total, "event", "events")}, ${plural(stats.errors, "error", "errors")}, ${plural(stats.warnings, "warning", "warnings")}`,
    );
  } else {
    parts.push("No count");
  }
  if (switchedOff) parts.push("Disabled");
  const stateLabel = STATE_LABELS[state];
  if (stateLabel !== "") {
    parts.push(
      state === "partial"
        ? "Partial: some events may be missing"
        : `${stateLabel[0].toUpperCase()}${stateLabel.slice(1)}`,
    );
  }
  parts.push(
    state === "read" || state === "partial"
      ? sparklineLabel(row, windowLabel)
      : `${windowLabel} activity: no data, the channel was not read`,
  );
  if (row.reasons.length > 0) parts.push(`Why: ${row.reasons.map(speakable).join("; ")}`);
  if (tailing) parts.push("Live tail running");
  return `${parts.join(". ")}.`;
}

/**
 * The 24-bin activity sparkline. An empty bin draws a 1 px baseline segment, so a channel that
 * was not read is a flat line and never a row of zero-height bars that could read as "no events".
 * It is hidden from assistive technology: the row's description carries the same numbers in words.
 */
function ActivitySparkline({
  bins,
  color,
  baseline,
}: {
  bins: readonly number[];
  color: string;
  baseline: string;
}) {
  const heights = scaleActivityBars(bins, SPARKLINE_HEIGHT);
  const unit = SPARKLINE_BIN_UNITS;
  const empty = heights
    .map((height, i) =>
      height === 0 ? `M${i * unit} ${SPARKLINE_HEIGHT - 1}h${unit - 1}v1h-${unit - 1}z` : "",
    )
    .join("");
  return (
    <svg
      aria-hidden="true"
      width="100%"
      height={SPARKLINE_HEIGHT}
      viewBox={`0 0 ${bins.length * unit} ${SPARKLINE_HEIGHT}`}
      preserveAspectRatio="none"
      style={{ display: "block" }}
    >
      {empty !== "" && <path data-empty-bins="" d={empty} style={{ fill: baseline }} />}
      {heights.map(
        (height, i) =>
          height > 0 && (
            <rect
              key={i}
              data-bin={i}
              x={i * unit}
              y={SPARKLINE_HEIGHT - height}
              width={unit - 1}
              height={height}
              style={{ fill: color }}
            />
          ),
      )}
    </svg>
  );
}

function DisclosureButton({
  groupKey,
  label,
  expanded,
  onToggle,
  className,
}: {
  groupKey: string;
  label: string;
  expanded: boolean;
  onToggle: (key: string) => void;
  className?: string;
}) {
  return (
    <button
      type="button"
      className={className}
      onClick={() => onToggle(groupKey)}
      aria-label={`${expanded ? "Collapse" : "Expand"} ${label}`}
      aria-expanded={expanded}
      style={{
        width: "14px",
        flexShrink: 0,
        background: "none",
        border: "none",
        cursor: "pointer",
        padding: 0,
        color: tokens.colorNeutralForeground2,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {expanded ? <ChevronDown12Regular /> : <ChevronRight12Regular />}
    </button>
  );
}

const GroupRow = memo(function GroupRow({
  groupKey,
  label,
  expanded,
  onToggle,
  depth,
  count,
  metrics,
}: {
  groupKey: string;
  label: string;
  expanded: boolean;
  onToggle: (key: string) => void;
  depth: number;
  count?: number;
  metrics: RowMetrics;
}) {
  const styles = useStyles();
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "4px",
        padding: `0 12px 0 ${12 + depth * 16}px`,
        height: `${metrics.rowHeight}px`,
        whiteSpace: "nowrap",
      }}
    >
      <DisclosureButton
        groupKey={groupKey}
        label={label}
        expanded={expanded}
        onToggle={onToggle}
        className={styles.disclosure}
      />
      <span
        onClick={() => onToggle(groupKey)}
        style={{
          cursor: "pointer",
          fontSize: `${metrics.groupFontSize}px`,
          fontWeight: 600,
          color: tokens.colorNeutralForeground2,
          overflow: "hidden",
          textOverflow: "ellipsis",
          flex: 1,
        }}
      >
        {label}
      </span>
      {count != null && count > 0 && (
        <span
          style={{
            ...numericStyle(metrics.captionFontSize),
            color: tokens.colorNeutralForeground2,
            flexShrink: 0,
          }}
        >
          {count}
        </span>
      )}
    </div>
  );
});

/**
 * One channel (spec 8.6): swatch, name and total on the first line, the activity sparkline under
 * it, then the error and warning counts and the status. The first line is the `<label>` of the
 * selection checkbox; the other two lines are not part of the control's name.
 *
 * A row shows numbers only for a channel that was read. For every other state the total is a dash
 * and the sparkline is flat, because a channel that could not be read has an unknown number of
 * events, not zero.
 */
const ChannelRow = memo(function ChannelRow({
  channel,
  row,
  label,
  depth,
  selected,
  tailing,
  disclosure,
  visual,
  primaryText,
  mutedText,
  windowLabel,
  metrics,
  onToggleChannel,
  onToggleExpand,
}: RowEnv & {
  channel: EvtxChannelInfo;
  row: ChannelRowModel;
  label: string;
  depth: number;
  selected: boolean;
  tailing: boolean;
  /** Present when the channel is also a folder of further channels. */
  disclosure?: { key: string; label: string; expanded: boolean };
}) {
  const styles = useStyles();
  const { state, stats } = row;
  const showNumbers = state === "read" || state === "partial";
  const switchedOff = !channelCanHoldEvents(channel);
  const selectable = row.selectable && !switchedOff;
  const dimmed = UNAVAILABLE_STATES.has(state) || switchedOff;

  // Selected rows use the selection triplet (spec 6.2); text on them is the selection foreground.
  const secondary = selected ? visual.selection.foreground : tokens.colorNeutralForeground2;
  const nameColor = selected
    ? visual.selection.foreground
    : dimmed
      ? mutedText
      : primaryText;
  const stateLabel = STATE_LABELS[state];
  const stateColor = GAP_STATES.has(state)
    ? selected
      ? visual.selection.foreground
      : primaryText
    : secondary;
  const countColor = (count: number, levelColor: string) =>
    count > 0 ? levelColor : secondary;

  const descriptionId = `${CHANNEL_PANE_ID}-row-${row.index}`;
  const title =
    row.reasons.length > 0 ? `${channel.name}\n${row.reasons.join("\n")}` : channel.name;

  return (
    <div
      data-channel-row={channel.name}
      data-channel-state={state}
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "3px",
        padding: `7px 12px 7px ${12 + depth * 16}px`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
        backgroundColor: selected ? visual.selection.background : undefined,
        boxShadow: selected ? `inset 3px 0 0 ${visual.selection.border}` : undefined,
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "4px",
          fontSize: `${metrics.fontSize}px`,
        }}
      >
        {disclosure ? (
          <DisclosureButton
            groupKey={disclosure.key}
            label={disclosure.label}
            expanded={disclosure.expanded}
            onToggle={onToggleExpand}
            className={styles.disclosure}
          />
        ) : (
          <span style={{ width: "14px", flexShrink: 0 }} />
        )}
        <label
          title={title}
          style={{
            display: "flex",
            alignItems: "center",
            gap: "6px",
            flex: 1,
            minWidth: 0,
            height: `${metrics.rowHeight}px`,
            cursor: selectable ? "pointer" : "default",
            color: nameColor,
            whiteSpace: "nowrap",
          }}
        >
          <input
            type="checkbox"
            checked={selected}
            onChange={() => {
              // A source that was never opened must not enter the selection, which means "include
              // in the view"; the disabled attribute alone is not the only line of defense.
              if (selectable) onToggleChannel(channel.name);
            }}
            disabled={!selectable}
            aria-label={`Select ${channel.name}`}
            aria-describedby={descriptionId}
            style={{ cursor: "inherit", margin: 0, flexShrink: 0 }}
          />
          <span
            aria-hidden="true"
            style={{
              width: "10px",
              height: "10px",
              boxSizing: "border-box",
              flexShrink: 0,
              borderRadius: "2px",
              backgroundColor: visual.channelColor(row.index),
              border: `1px solid ${selected ? visual.markOutline("selected") : "transparent"}`,
            }}
          />
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", flex: 1, minWidth: 0 }}>
            {label}
          </span>
          {switchedOff && (
            // Listed and marked rather than hidden: the channel exists, it is simply not recording,
            // and that is why Select all leaves it out. Nothing in it is missing from the view.
            <span
              style={{
                fontSize: `${metrics.captionFontSize}px`,
                color: secondary,
                flexShrink: 0,
              }}
            >
              disabled
            </span>
          )}
          <span
            style={{
              ...numericStyle(metrics.captionFontSize),
              color: secondary,
              flexShrink: 0,
            }}
          >
            {showNumbers ? (
              stats.total.toLocaleString()
            ) : (
              <>
                <span aria-hidden="true">{NO_COUNT}</span>
                <span className={styles.visuallyHidden}>no count</span>
              </>
            )}
          </span>
        </label>
      </div>
      <div style={{ paddingLeft: "16px" }}>
        <ActivitySparkline
          bins={showNumbers ? stats.bins : NO_CHANNEL_STATS.bins}
          color={selected ? visual.selectedDataColor : visual.channelColor(row.index)}
          baseline={tokens.colorNeutralStroke2}
        />
      </div>
      <div
        aria-hidden="true"
        style={{
          ...numericStyle(metrics.captionFontSize),
          display: "flex",
          flexWrap: "wrap",
          columnGap: "8px",
          paddingLeft: "16px",
          color: secondary,
        }}
      >
        {showNumbers && (
          <>
            <span style={{ color: countColor(stats.errors, visual.levels.Error.textColor) }}>
              {stats.errors} err
            </span>
            <span style={{ color: countColor(stats.warnings, visual.levels.Warning.textColor) }}>
              {stats.warnings} warn
            </span>
          </>
        )}
        {stateLabel !== "" && (
          <span
            style={{
              color: stateColor,
              fontWeight: GAP_STATES.has(state) ? 600 : undefined,
            }}
          >
            {stateLabel}
          </span>
        )}
        {tailing && <span>{"\u00B7 live"}</span>}
      </div>
      {/* Hidden from reading in browse mode; aria-describedby still resolves it. */}
      <span id={descriptionId} aria-hidden="true" className={styles.visuallyHidden}>
        {rowDescription(row, windowLabel, { tailing, switchedOff })}
      </span>
    </div>
  );
});

/**
 * A text log an archive reader listed as a channel (a .log inside a .zip). It is not an event
 * channel, so it has no swatch, no activity chart, no error and warning counts and no event read
 * state: only its name and how many entries it holds. It does keep its coverage. A member cut off
 * at the archive's line limit, or with lines that would not parse, says "partial" with the reason;
 * one nothing was kept from says "not read" with a dash, never a zero. Its checkbox stays, because
 * the selection is what gates whether the records are shown at all.
 */
const TextLogRow = memo(function TextLogRow({
  row,
  position,
  depth,
  selected,
  visual,
  primaryText,
  metrics,
  onToggleChannel,
}: RowEnv & {
  row: TextLogRowModel;
  position: number;
  depth: number;
  selected: boolean;
}) {
  const styles = useStyles();
  const descriptionId = `${CHANNEL_PANE_ID}-text-log-${position}`;
  const unit = row.entries === 1 ? "entry" : "entries";
  // A member nothing was kept from has an unknown number of entries, not none.
  const hasCount = row.state !== "notRead";
  const cue = row.state === "partial" ? "partial" : row.state === "notRead" ? "not read" : "";
  const description = [
    hasCount ? `${row.entries.toLocaleString()} ${unit}` : "No count",
    row.state === "partial"
      ? "Partial: some entries may be missing"
      : row.state === "notRead"
        ? "Not read"
        : "",
    row.reasons.length > 0 ? `Why: ${row.reasons.map(speakable).join("; ")}` : "",
    "A text log from an archive, not an event channel",
  ]
    .filter((part) => part !== "")
    .join(". ");
  return (
    <div
      data-text-log-row={row.name}
      data-text-log-state={row.state}
      style={{
        display: "flex",
        alignItems: "center",
        padding: `0 12px 0 ${12 + depth * 16}px`,
        borderBottom: `1px solid ${tokens.colorNeutralStroke3}`,
        fontSize: `${metrics.fontSize}px`,
        backgroundColor: selected ? visual.selection.background : undefined,
        boxShadow: selected ? `inset 3px 0 0 ${visual.selection.border}` : undefined,
      }}
    >
      <span style={{ width: "14px", flexShrink: 0, marginRight: "4px" }} />
      <label
        title={row.reasons.length > 0 ? `${row.name}\n${row.reasons.join("\n")}` : row.name}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "6px",
          flex: 1,
          minWidth: 0,
          height: `${metrics.rowHeight}px`,
          cursor: "pointer",
          color: selected ? visual.selection.foreground : primaryText,
          whiteSpace: "nowrap",
        }}
      >
        <input
          type="checkbox"
          checked={selected}
          onChange={() => onToggleChannel(row.name)}
          aria-label={`Select ${row.name}`}
          aria-describedby={descriptionId}
          style={{ cursor: "inherit", margin: 0, flexShrink: 0 }}
        />
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", flex: 1, minWidth: 0 }}>
          {row.label}
        </span>
        {cue !== "" && (
          <span
            style={{
              fontSize: `${metrics.captionFontSize}px`,
              fontWeight: 600,
              color: selected ? visual.selection.foreground : primaryText,
              flexShrink: 0,
            }}
          >
            {cue}
          </span>
        )}
        <span
          style={{
            ...numericStyle(metrics.captionFontSize),
            color: selected ? visual.selection.foreground : tokens.colorNeutralForeground2,
            flexShrink: 0,
          }}
        >
          {hasCount ? (
            `${row.entries.toLocaleString()} ${unit}`
          ) : (
            <>
              <span aria-hidden="true">{NO_COUNT}</span>
              <span className={styles.visuallyHidden}>no count</span>
            </>
          )}
        </span>
      </label>
      <span id={descriptionId} aria-hidden="true" className={styles.visuallyHidden}>
        {`${description}.`}
      </span>
    </div>
  );
});

function TreeNodeView({
  node,
  depth,
  expanded,
  rows,
  selectedChannels,
  tailChannels,
  rowEnv,
}: {
  node: ChannelTreeNode<EvtxChannelInfo>;
  depth: number;
  expanded: ReadonlySet<string>;
  rows: ChannelPaneModel["rows"];
  selectedChannels: ReadonlySet<string>;
  tailChannels: ReadonlySet<string>;
  rowEnv: RowEnv;
}) {
  return (
    <>
      {sortedChannelChildren(node).map((child) => {
        const key = child.fullPath || child.name;
        const hasChildren = child.children.size > 0;
        const isExpanded = expanded.has(key);
        const nested = hasChildren && isExpanded && (
          <TreeNodeView
            node={child}
            depth={depth + 1}
            expanded={expanded}
            rows={rows}
            selectedChannels={selectedChannels}
            tailChannels={tailChannels}
            rowEnv={rowEnv}
          />
        );

        if (child.channel) {
          // A leaf, or a channel that is also a folder of further channels.
          const row = rows.get(child.channel.name);
          if (!row) return null;
          return (
            <Fragment key={key}>
              <ChannelRow
                channel={child.channel}
                row={row}
                label={child.name}
                depth={depth}
                selected={selectedChannels.has(child.channel.name)}
                tailing={tailChannels.has(child.channel.name)}
                disclosure={hasChildren ? { key, label: child.name, expanded: isExpanded } : undefined}
                {...rowEnv}
              />
              {nested}
            </Fragment>
          );
        }

        return (
          <div key={key}>
            <GroupRow
              groupKey={key}
              label={child.name}
              expanded={isExpanded}
              onToggle={rowEnv.onToggleExpand}
              depth={depth}
              count={countChannelLeaves(child)}
              metrics={rowEnv.metrics}
            />
            {nested}
          </div>
        );
      })}
    </>
  );
}

// ── Also correlating and the live tail footer ───────────────────────────────

function AlsoCorrelating({
  sources,
  merged,
  logStoreLoading,
  metrics,
  primaryText,
  mutedText,
}: {
  sources: ReturnType<typeof summarizeLogSources>;
  /** The log store is in "merged" mode, the only mode that correlates every open log. */
  merged: boolean;
  /** The log store is loading, so `sources` may not have settled. */
  logStoreLoading: boolean;
  metrics: RowMetrics;
  primaryText: string;
  mutedText: string;
}) {
  const shown = sources.slice(0, MAX_CORRELATING_SOURCES);
  const omitted = sources.length - shown.length;
  return (
    <section aria-label="Also correlating" style={{ padding: "10px 0 6px" }}>
      <div style={{ ...eyebrowStyle(metrics.captionFontSize, mutedText), padding: "0 12px 4px" }}>
        Also correlating
      </div>
      {/* Read from the live mode, so it always says what the session is being given (spec 8.19). */}
      {sources.length > 0 && (
        <div
          style={{
            padding: "0 12px 4px",
            fontSize: `${metrics.captionFontSize}px`,
            color: mutedText,
          }}
        >
          {merged ? "Correlating: all open logs" : "Correlating: active log source only"}
        </div>
      )}
      {shown.map((source) => (
        <div
          key={source.path}
          title={source.path}
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            gap: "8px",
            padding: "3px 12px",
            fontSize: `${metrics.groupFontSize}px`,
            color: primaryText,
          }}
        >
          <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {source.label}
          </span>
          <span
            style={{
              ...numericStyle(metrics.captionFontSize),
              color: tokens.colorNeutralForeground2,
              flexShrink: 0,
              whiteSpace: "nowrap",
            }}
          >
            {`${source.entries.toLocaleString()} ${source.entries === 1 ? "entry" : "entries"}`}
          </span>
        </div>
      ))}
      {omitted > 0 && (
        <div
          style={{
            padding: "3px 12px",
            fontSize: `${metrics.captionFontSize}px`,
            color: tokens.colorNeutralForeground2,
          }}
        >
          {`and ${omitted} more`}
        </div>
      )}
      <AddLogSourceControl
        primaryText={primaryText}
        groupFontSize={metrics.groupFontSize}
        captionFontSize={metrics.captionFontSize}
        correlatedCount={sources.length}
        logStoreLoading={logStoreLoading}
      />
    </section>
  );
}

function LiveTailFooter({
  tailMode,
  tailingChannels,
  busy,
  onStop,
  onResume,
  visual,
  primaryText,
  metrics,
}: {
  tailMode: string | null;
  tailingChannels: number;
  busy: boolean;
  /** Stops the tail: Pause while it runs, Stop when it was asked for and is not running. */
  onStop: () => void;
  onResume: () => void;
  visual: EvtxVisualTokens;
  primaryText: string;
  metrics: RowMetrics;
}) {
  const on = tailMode !== null;
  // `unsupported` is a tail that was asked for and is not running, so it is not called live.
  const running = on && tailingChannels > 0;
  // A tail that is not running has nothing to pause: offering Pause would call stopLiveTail on a
  // tail that never started. It can be stopped (cleared) or, with no tail at all, resumed.
  const action = running ? "Pause" : on ? "Stop" : "Resume";
  const text = running
    ? `Live tail \u00B7 ${tailingChannels} ${tailingChannels === 1 ? "channel" : "channels"}`
    : on
      ? "Live tail \u00B7 not tailing"
      : "Live tail off";
  return (
    <div
      style={{
        padding: "10px 12px",
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
        flexShrink: 0,
        display: "flex",
        flexDirection: "column",
        gap: "2px",
        fontSize: `${metrics.groupFontSize}px`,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <span
          aria-hidden="true"
          style={{
            width: "8px",
            height: "8px",
            boxSizing: "border-box",
            flexShrink: 0,
            borderRadius: "50%",
            backgroundColor: running ? visual.liveSource.foreground : "transparent",
            border: `1px solid ${running ? visual.liveSource.foreground : tokens.colorNeutralForeground2}`,
          }}
        />
        <span style={{ flex: 1, minWidth: 0, color: primaryText }}>{text}</span>
        <Link
          as="button"
          disabled={busy}
          onClick={on ? onStop : onResume}
          aria-label={`${action} live tail`}
          style={{ fontWeight: 600, flexShrink: 0 }}
        >
          {action}
        </Link>
      </div>
      {on && (
        <span
          aria-label={`Live tail mode: ${tailMode}`}
          style={{
            fontSize: `${metrics.captionFontSize}px`,
            color: tokens.colorNeutralForeground2,
            paddingLeft: "16px",
          }}
        >
          {tailMode}
        </span>
      )}
    </div>
  );
}

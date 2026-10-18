/**
 * The workbench view bar (spec section 8.2): layout switcher, panel toggles, and the Group by,
 * Columns and Export controls.
 *
 * Group by, Columns and Export moved here from `EvtxFilterBar` unchanged in behavior, so every
 * capability stays reachable: Group by keeps its nesting, the Columns popover holds the same
 * show/hide chooser plus reset and reorder, and Export keeps its single-flight guard and abort.
 */
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactElement,
} from "react";
import {
  Button,
  Dropdown,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  Option,
  Popover,
  PopoverSurface,
  PopoverTrigger,
  ToggleButton,
  Tooltip,
  makeStyles,
  mergeClasses,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import {
  ArrowDown16Regular,
  ArrowUp16Regular,
  ChartMultiple20Regular,
  Checkmark12Regular,
  Dismiss12Regular,
  Flowchart20Regular,
  GroupList20Regular,
  TableSimple20Regular,
  Timeline20Regular,
  type FluentIcon,
} from "@fluentui/react-icons";
import { save } from "@tauri-apps/plugin-dialog";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import {
  availableColumns,
  discoverMappedProperties,
  type EvtxColumnId,
} from "./evtx-columns";
import { useEvtxActiveTextColor } from "./evtx-active-state";
import { EVTX_EXPORT_FORMATS } from "./evtx-export";
import {
  EVTX_GROUP_LABELS,
  selectVisibleRecords,
  sortRecords,
  type EvtxGroupField,
} from "./evtx-filter";
import {
  EVTX_PANELS_AVAILABLE,
  EVTX_VIEW_IDS,
  EVTX_VIEW_LABELS,
  EVTX_VIEW_PANEL_ID,
  evtxPanelToggleId,
  evtxViewTabId,
  useEvtxLayoutStore,
  type EvtxPanelId,
  type EvtxViewId,
} from "./evtx-layout-store";
import { useEvtxStore } from "./evtx-store";
import { streamEventLogExport } from "./event-export-session";

const VIEW_ICONS: Record<EvtxViewId, FluentIcon> = {
  table: TableSimple20Regular,
  grouped: GroupList20Regular,
  timeline: Timeline20Regular,
  charts: ChartMultiple20Regular,
  correlation: Flowchart20Regular,
};

const PANEL_TOGGLES: ReadonlyArray<{
  id: EvtxPanelId;
  label: string;
  /** Shown (as the toggle's description) while the panel cannot be shown. */
  unavailableReason: string;
}> = [
  { id: "channels", label: "Channels", unavailableReason: "No event log channels loaded" },
  { id: "insights", label: "Insights", unavailableReason: "" },
  { id: "dock", label: "Correlation dock", unavailableReason: "" },
];

const useStyles = makeStyles({
  // The tablist clips to its rounded corners, so the focus ring is drawn INSIDE each tab
  // (negative offset) instead of outside, where it would be cut off.
  layoutTab: {
    backgroundColor: "transparent",
    color: tokens.colorNeutralForeground2,
    fontWeight: 400,
    ":hover": { backgroundColor: tokens.colorNeutralBackground1Hover },
    ":focus-visible": {
      outlineStyle: "solid",
      outlineWidth: "2px",
      outlineColor: tokens.colorStrokeFocus2,
      outlineOffset: "-2px",
    },
  },
  // Active states read their text color from --evtx-active-text, set on the bar from the theme:
  // the brand foreground where it reaches 4.5:1 on the selected surface, black or white where not.
  // Hover and pressed keep the selected surface (so the text contrast guarantee holds) and show
  // the state through the border instead.
  layoutTabActive: {
    backgroundColor: tokens.colorNeutralBackground1Selected,
    color: "var(--evtx-active-text)",
    fontWeight: 600,
    ":hover": {
      backgroundColor: tokens.colorNeutralBackground1Selected,
      color: "var(--evtx-active-text)",
    },
  },
  toggleChecked: {
    backgroundColor: tokens.colorNeutralBackground1Selected,
    color: "var(--evtx-active-text)",
    ":hover": {
      backgroundColor: tokens.colorNeutralBackground1Selected,
      color: "var(--evtx-active-text)",
      ...shorthands.borderColor(tokens.colorNeutralStroke1Hover),
    },
    ":hover:active": {
      backgroundColor: tokens.colorNeutralBackground1Selected,
      color: "var(--evtx-active-text)",
      ...shorthands.borderColor(tokens.colorNeutralStroke1Pressed),
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

const GROUP_FIELDS: EvtxGroupField[] = ["eventId", "provider", "channel", "level", "day"];
const NO_GROUPING = "__none__";
const EXPORT_TITLE = "Export the events currently shown, using the same filters as the list";

interface EvtxViewBarProps {
  /** The workspace clock snapshot, so an export selects the same records the list shows. */
  nowEpoch: number;
}

export function EvtxViewBar({ nowEpoch }: EvtxViewBarProps) {
  const styles = useStyles();
  const activeText = useEvtxActiveTextColor();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const controlFontSize = `${Math.max(11, metrics.fontSize - 1)}px`;
  const labelFontSize = `${Math.max(10, metrics.fontSize - 2)}px`;

  const activeView = useEvtxLayoutStore((s) => s.activeView);
  const setActiveView = useEvtxLayoutStore((s) => s.setActiveView);
  const panels = useEvtxLayoutStore((s) => s.panels);
  const setPanel = useEvtxLayoutStore((s) => s.setPanel);

  const tabRefs = useRef<Partial<Record<EvtxViewId, HTMLButtonElement | null>>>({});
  const onTabKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const index = EVTX_VIEW_IDS.indexOf(activeView);
    let next: number;
    switch (event.key) {
      case "ArrowRight":
        next = (index + 1) % EVTX_VIEW_IDS.length;
        break;
      case "ArrowLeft":
        next = (index - 1 + EVTX_VIEW_IDS.length) % EVTX_VIEW_IDS.length;
        break;
      case "Home":
        next = 0;
        break;
      case "End":
        next = EVTX_VIEW_IDS.length - 1;
        break;
      default:
        return;
    }
    event.preventDefault();
    // Selection follows focus. Switching a view only swaps what the main region renders, so it
    // is cheap enough to do on arrow keys, and it keeps one tab stop meaning "the active view".
    const view = EVTX_VIEW_IDS[next];
    setActiveView(view);
    tabRefs.current[view]?.focus();
  };

  const groupBy = useEvtxStore((s) => s.groupBy);
  const setGroupBy = useEvtxStore((s) => s.setGroupBy);
  const groupSummary = groupBy.length
    ? groupBy.map((field) => EVTX_GROUP_LABELS[field]).join(" > ")
    : "None";

  const records = useEvtxStore((s) => s.records);
  const channelCount = useEvtxStore((s) => s.channels.length);
  const columnConfig = useEvtxStore((s) => s.columnConfig);
  const toggleColumnVisible = useEvtxStore((s) => s.toggleColumnVisible);
  const moveColumnBy = useEvtxStore((s) => s.moveColumnBy);
  const resetColumns = useEvtxStore((s) => s.resetColumns);
  // Map columns are offered only when a loaded map actually produced them, so the chooser does not
  // fill with columns that are empty for the log in front of the operator.
  const choosableColumns = useMemo(
    () => availableColumns(discoverMappedProperties(records)),
    [records],
  );
  const [reorderTarget, setReorderTarget] = useState<EvtxColumnId | null>(null);
  const columnLabel = (id: EvtxColumnId) =>
    choosableColumns.find((column) => column.id === id)?.label ?? id;

  // Visible progress and results. Not a live region: progress changes once per chunk, which
  // would flood a screen reader.
  const [exportState, setExportState] = useState<string | null>(null);
  // What a screen reader hears: the start and the final result only.
  // Each announcement is a new keyed node, so repeating the same message (a second "Nothing to
  // export") is announced again instead of being a no-op text change.
  const [exportAnnouncement, setExportAnnouncement] = useState({ id: 0, text: "" });
  const announce = (text: string) =>
    setExportAnnouncement((previous) => ({ id: previous.id + 1, text }));
  const exportTriggerRef = useRef<HTMLButtonElement | null>(null);
  // A failure is shown in full under the bar and stays until dismissed or the next export.
  const [exportError, setExportError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);
  const exportAbortRef = useRef<AbortController | null>(null);
  // The save dialog is awaited before the export session exists, so the abort controller cannot be
  // the guard: it stays null while the operator is choosing a file, and two selections made before
  // the first dialog resolves would both pass a check against it. This ref is set synchronously
  // before the dialog opens and cleared in `finally`, so it covers the dialog and the session
  // together, and a thrown dialog error cannot leave it set.
  const exportPendingRef = useRef(false);
  useEffect(
    () => () => {
      exportAbortRef.current?.abort();
    },
    [],
  );

  // Exports what is on screen, using the same predicate the list uses, so the file cannot quietly
  // differ from the view.
  const exportVisible = async (format: (typeof EVTX_EXPORT_FORMATS)[number]) => {
    if (exportPendingRef.current) return;
    // A new attempt supersedes an old failure line, including attempts that end early.
    setExportError(null);
    const state = useEvtxStore.getState();
    const visibleColumns = state.columnConfig.order;
    const exportRecords = sortRecords(
      selectVisibleRecords({
        records: state.records,
        selectedChannels: state.selectedChannels,
        filterLevels: state.filterLevels,
        filterEventIds: state.filterEventIds,
        filterSearch: state.filterSearch,
        quickFilter: state.quickFilter,
        timeWindow: state.timeWindow,
        timeRange: state.timeRange,
        scopeRecords: state.recordScope?.records ?? null,
        visibleColumns,
        timeZoneMode: state.timeZoneMode,
        nowEpoch,
      }),
      state.sortField,
      state.sortDirection,
    );
    if (exportRecords.length === 0) {
      setExportState("Nothing to export");
      announce("Nothing to export");
      return;
    }
    // Claimed before the dialog opens: this is the whole point of the ref, since everything after
    // it is asynchronous and a second selection can arrive while the operator is still choosing.
    exportPendingRef.current = true;
    try {
      const destination = await save({
        defaultPath: `events.${format.extension}`,
        filters: [{ name: format.label, extensions: [format.extension] }],
      });
      if (!destination) return;
      const controller = new AbortController();
      exportAbortRef.current = controller;
      setIsExporting(true);
      announce("Export started");
      setExportState(`Exporting 0 of ${exportRecords.length.toLocaleString()} events...`);
      const result = await streamEventLogExport({
        records: exportRecords,
        format: format.value,
        destination,
        sourcePaths: state.sourcePaths,
        signal: controller.signal,
        onProgress: (received, expected) => {
          setExportState(
            `Exporting ${received.toLocaleString()} of ${expected.toLocaleString()} events...`,
          );
        },
      });
      const done = `Exported ${result.records.toLocaleString()} events (${result.bytes.toLocaleString()} bytes)`;
      setExportState(done);
      announce(done);
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        setExportState("Export cancelled");
        announce("Export cancelled");
      } else {
        setExportState(null);
        // The alert carries the message; announcing it too would read it twice.
        announce("");
        setExportError(
          `Export failed: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    } finally {
      exportPendingRef.current = false;
      exportAbortRef.current = null;
      setIsExporting(false);
    }
  };

  const small = { minWidth: "auto", padding: "2px 8px", fontSize: controlFontSize } as const;

  return (
    <>
      <div
        data-evtx-region="view-bar"
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          padding: "6px 12px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          backgroundColor: tokens.colorNeutralBackground1,
          flexWrap: "wrap",
          flexShrink: 0,
          fontSize: controlFontSize,
          ["--evtx-active-text" as string]: activeText,
        }}
      >
        <div
          role="tablist"
          aria-label="Layout"
          style={{
            display: "inline-flex",
            // An inset outline rather than a border, so the group is exactly the 28 px of its
            // buttons and the bar measures 6 + 28 + 6 plus its bottom border (spec 5.1: ~40).
            outline: `1px solid ${tokens.colorNeutralStroke1}`,
            outlineOffset: "-1px",
            borderRadius: "6px",
            overflow: "hidden",
          }}
        >
          {EVTX_VIEW_IDS.map((view, index): ReactElement => {
            const selected = view === activeView;
            const Icon = VIEW_ICONS[view];
            return (
              <button
                key={view}
                ref={(element) => {
                  tabRefs.current[view] = element;
                }}
                id={evtxViewTabId(view)}
                className={mergeClasses(styles.layoutTab, selected && styles.layoutTabActive)}
                type="button"
                role="tab"
                aria-selected={selected}
                aria-controls={EVTX_VIEW_PANEL_ID}
                tabIndex={selected ? 0 : -1}
                onClick={() => setActiveView(view)}
                onKeyDown={onTabKeyDown}
                style={{
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "6px",
                  height: "28px",
                  padding: "0 14px",
                  border: "none",
                  borderLeft:
                    index === 0 ? "none" : `1px solid ${tokens.colorNeutralStroke1}`,
                  cursor: "pointer",
                  fontFamily: "inherit",
                  fontSize: controlFontSize,
                }}
              >
                <Icon fontSize={16} aria-hidden />
                {EVTX_VIEW_LABELS[view]}
              </button>
            );
          })}
        </div>

        <div
          aria-hidden
          style={{
            width: "1px",
            height: "20px",
            backgroundColor: tokens.colorNeutralStroke1,
          }}
        />

        <span style={{ fontSize: labelFontSize, color: tokens.colorNeutralForeground2 }}>
          Panels
        </span>
        {PANEL_TOGGLES.map(({ id, label, unavailableReason }) => {
          const available =
            EVTX_PANELS_AVAILABLE[id] && (id !== "channels" || channelCount > 0);
          // An unavailable panel is never shown as pressed, even from a stale persisted value.
          const checked = available && panels[id];
          const toggle = (
            <ToggleButton
              // So Close on the dock can return focus to the toggle that opened it.
              id={evtxPanelToggleId(id)}
              shape="rounded"
              size="small"
              checked={checked}
              disabledFocusable={!available}
              icon={checked ? <Checkmark12Regular /> : undefined}
              onClick={() => {
                if (available) setPanel(id, !checked);
              }}
              className={checked ? styles.toggleChecked : undefined}
              style={{ ...small, fontWeight: checked ? 600 : 400 }}
            >
              {label}
            </ToggleButton>
          );
          // The tooltip shows on hover and focus and supplies the toggle's accessible description,
          // so the reason is reachable by keyboard and read once.
          return available ? (
            <span key={id} style={{ display: "inline-flex" }}>
              {toggle}
            </span>
          ) : (
            <Tooltip key={id} content={unavailableReason} relationship="description">
              {toggle}
            </Tooltip>
          );
        })}

        {/*
          The spacer doubles as the export status, so a long message is ellipsized into the free
          space instead of widening the cluster and wrapping the bar onto a second row (spec 5.1).
          The full text stays in the title. A failure is shown in full, under the bar.
        */}
        <div
          data-evtx-export-status
          title={exportState ?? undefined}
          style={{
            flex: 1,
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            textAlign: "right",
            fontSize: labelFontSize,
            color: tokens.colorNeutralForeground3,
          }}
        >
          {exportState}
        </div>
        {isExporting && (
          <Button
            size="small"
            appearance="subtle"
            onClick={() => exportAbortRef.current?.abort()}
          >
            Cancel export
          </Button>
        )}

        <span style={{ fontSize: labelFontSize, color: tokens.colorNeutralForeground2 }}>
          Group by
        </span>
        <Dropdown
          button={{ style: { fontSize: controlFontSize } }}
          size="small"
          multiselect
          aria-label="Group by"
          value={groupSummary}
          selectedOptions={groupBy.length ? groupBy : [NO_GROUPING]}
          style={{ minWidth: "128px" }}
          title="Group the list. Selecting several nests them in the order chosen."
          onOptionSelect={(_, data) => {
            const field = data.optionValue;
            if (!field) return;
            if (field === NO_GROUPING) {
              setGroupBy([]);
              return;
            }
            const grouped = field as EvtxGroupField;
            // Appending rather than sorting keeps the nesting order under the operator's control.
            setGroupBy(
              groupBy.includes(grouped)
                ? groupBy.filter((existing) => existing !== grouped)
                : [...groupBy, grouped],
            );
          }}
        >
          <Option value={NO_GROUPING} text="None" style={{ fontSize: controlFontSize }}>
            None
          </Option>
          {GROUP_FIELDS.map((field) => (
            <Option
              key={field}
              value={field}
              text={EVTX_GROUP_LABELS[field]}
              style={{ fontSize: controlFontSize }}
            >
              {EVTX_GROUP_LABELS[field]}
            </Option>
          ))}
        </Dropdown>

        <Popover positioning="below-end" trapFocus>
          <PopoverTrigger disableButtonEnhancement>
            <Button
              size="small"
              appearance="outline"
              title="Choose which columns the list shows."
              style={small}
            >
              {`Columns (${columnConfig.order.length})`}
            </Button>
          </PopoverTrigger>
          <PopoverSurface aria-label="Columns">
            <div
              style={{
                display: "flex",
                flexWrap: "wrap",
                alignItems: "center",
                gap: "8px",
                maxWidth: "420px",
              }}
            >
              {/* inlinePopup keeps the listbox inside the surface, so choosing a column is not an outside click. */}
              <Dropdown
                button={{ style: { fontSize: controlFontSize } }}
                inlinePopup
                size="small"
                multiselect
                placeholder="Columns"
                aria-label="Visible columns"
                value={`${columnConfig.order.length} shown`}
                selectedOptions={columnConfig.order}
                style={{ minWidth: "104px" }}
                onOptionSelect={(_, data) => {
                  const id = data.optionValue as EvtxColumnId | undefined;
                  if (id) toggleColumnVisible(id);
                }}
              >
                {choosableColumns.map((column) => (
                  <Option
                    key={column.id}
                    value={column.id}
                    text={column.label}
                    style={{ fontSize: controlFontSize }}
                  >
                    {column.label}
                  </Option>
                ))}
              </Dropdown>
              {/*
                A button, not an option. In a multiselect listbox every option carries a selection
                indicator, so "Reset to defaults" rendered as though it were a column that could be
                checked, and it is an action rather than a member of the set.
              */}
              <Button
                size="small"
                appearance="outline"
                onClick={resetColumns}
                title="Restore the default columns, order and widths"
                style={small}
              >
                Reset columns
              </Button>
              {/*
                Reordering lives outside the listbox. Buttons nested in a Fluent Option are invalid
                ARIA and never receive focus, because a listbox moves focus between options rather
                than into them, so a keyboard-only operator could show and hide columns but never
                order them.
              */}
              <Dropdown
                button={{ style: { fontSize: controlFontSize } }}
                inlinePopup
                size="small"
                placeholder="Reorder"
                aria-label="Column to reorder"
                value={reorderTarget ? columnLabel(reorderTarget) : ""}
                selectedOptions={reorderTarget ? [reorderTarget] : []}
                style={{ minWidth: "104px" }}
                title="Pick a column, then use the arrows to move it."
                onOptionSelect={(_, data) => {
                  if (data.optionValue) setReorderTarget(data.optionValue as EvtxColumnId);
                }}
              >
                {columnConfig.order.map((id) => (
                  <Option
                    key={id}
                    value={id}
                    text={columnLabel(id)}
                    style={{ fontSize: controlFontSize }}
                  >
                    {columnLabel(id)}
                  </Option>
                ))}
              </Dropdown>
              <Button
                size="small"
                appearance="outline"
                aria-label="Move the selected column earlier"
                title="Move the selected column earlier"
                disabled={!reorderTarget || columnConfig.order.indexOf(reorderTarget) <= 0}
                onClick={() => reorderTarget && moveColumnBy(reorderTarget, -1)}
                style={small}
              >
                <ArrowUp16Regular />
              </Button>
              <Button
                size="small"
                appearance="outline"
                aria-label="Move the selected column later"
                title="Move the selected column later"
                disabled={
                  !reorderTarget ||
                  columnConfig.order.indexOf(reorderTarget) === columnConfig.order.length - 1
                }
                onClick={() => reorderTarget && moveColumnBy(reorderTarget, 1)}
                style={small}
              >
                <ArrowDown16Regular />
              </Button>
            </div>
          </PopoverSurface>
        </Popover>

        <Menu>
          <MenuTrigger disableButtonEnhancement>
            <Button
              ref={exportTriggerRef}
              size="small"
              appearance="outline"
              disabled={isExporting}
              title={EXPORT_TITLE}
              style={small}
            >
              Export
            </Button>
          </MenuTrigger>
          <MenuPopover>
            <MenuList>
              {EVTX_EXPORT_FORMATS.map((format) => (
                <MenuItem key={format.value} onClick={() => void exportVisible(format)}>
                  {format.label}
                </MenuItem>
              ))}
            </MenuList>
          </MenuPopover>
        </Menu>
        <span
          role="status"
          aria-live="polite"
          data-evtx-export-announcement
          className={styles.visuallyHidden}
        >
          {exportAnnouncement.text && (
            <span key={exportAnnouncement.id}>{exportAnnouncement.text}</span>
          )}
        </span>
      </div>
      {exportError && (
        <div
          role="alert"
          data-evtx-export-error
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: "8px",
            padding: "4px 12px",
            color: tokens.colorPaletteRedForeground1,
            fontSize: controlFontSize,
            overflowWrap: "anywhere",
          }}
        >
          <span style={{ flex: 1, minWidth: 0 }}>{exportError}</span>
          <Button
            size="small"
            appearance="subtle"
            icon={<Dismiss12Regular />}
            aria-label="Dismiss export error"
            onClick={() => {
              setExportError(null);
              // The button that had focus is about to unmount; put focus somewhere sensible.
              exportTriggerRef.current?.focus();
            }}
          />
        </div>
      )}
    </>
  );
}

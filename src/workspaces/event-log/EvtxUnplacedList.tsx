/**
 * The "Not placed" pane of the Correlation view (spec 8.11a): the items the engine could not place
 * because they carry no timestamp, listed and never given a position on any timeline.
 *
 * The list is the engine's own unplaced preview (at most 100, no pager) with the count from the same
 * reply. Everything it says about how many, and what it left out, comes from `evtx-unplaced.ts`.
 * It draws no time, no window and no placement, and imports nothing that could (a source guard in
 * the pure module's test keeps the pure layer so).
 *
 * Replies go through the view's two existing action regions (`onReply`, `onFail`): the pane adds no
 * live region of its own, so the view still has exactly two `role="status"` regions.
 *
 * "Open in Log Viewer" is for log lines, and is offered only when the Log Viewer can show that line
 * for what it is. Availability is judged twice from the log store: at render, to enable or disable
 * the button with its reason, and again at CLICK TIME from `useLogStore.getState()`, because the
 * store can change between the two and a target that cannot be consumed would stay armed for a later
 * load. It arms the target and switches to the Log view with no reload.
 */
import { useMemo, type KeyboardEvent } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { Copy16Regular, Open16Regular } from "@fluentui/react-icons";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import type { CorrelationSizes } from "./EvtxCorrelationLanes";
import {
  OPEN_IN_LOG_VIEWER_LABEL,
  WAIT_FOR_UPDATE_REASON,
  describeUnplaced,
  logViewerLines,
  notPlacedCaption,
  openAtLineAvailability,
  unplacedCopyText,
  unplacedHeader,
  unplacedOmittedNotice,
  type UnplacedListInput,
  type UnplacedRow,
} from "./evtx-unplaced";
import { useRailTextColors } from "./evtx-rail-text";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

interface EvtxUnplacedListProps {
  /** The engine's unplaced list and its count, from the model on show. Null is no run: nothing to show. */
  list: UnplacedListInput | null;
  /** The correlation data is being rebuilt, so this list belongs to an earlier session. */
  updating: boolean;
  sizes: CorrelationSizes;
  /** A reply to something the operator did (the view says it in its action region). */
  onReply: (text: string) => void;
  /** The failure of something the operator did (the view says it as an alert). */
  onFail: (text: string) => void;
  /** Escape on the pane: the view moves focus back to its list. */
  onEscape: () => void;
}

const NO_LINES: ReadonlySet<number> = new Set();

export function EvtxUnplacedList({ list, updating, sizes, onReply, onFail, onEscape }: EvtxUnplacedListProps) {
  const visuals = useEvtxVisualTokens();
  const { cardSecondary } = useRailTextColors();
  const view = useMemo(() => describeUnplaced(list), [list]);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  const entries = useLogStore((s) => s.entries);

  // The lines the list names in the open file: the Log Viewer's pass keeps only these, so a large
  // tailed file does not build a set of every line, and the pass is memoized on what it reads.
  const wanted = useMemo(() => {
    if (openFilePath === null) return NO_LINES;
    const lines = new Set<number>();
    for (const row of view.rows) if (row.file === openFilePath && row.line !== null) lines.add(row.line);
    return lines;
  }, [view.rows, openFilePath]);
  const viewer = useMemo(
    () => logViewerLines(openFilePath, sourceOpenMode, entries, wanted),
    [openFilePath, sourceOpenMode, entries, wanted],
  );

  if (!view.present) return null;

  const chipSize = sizes.tick;
  const open = (row: UnplacedRow) => {
    if (row.file === null || row.line === null) return;
    // Judged again from the store as it is NOW, never from the render's copy or a derived list.
    // `updating` is the committed render's: a button drawn for stale data is disabled, and a disabled
    // button does not click.
    const state = useLogStore.getState();
    const now = logViewerLines(state.openFilePath, state.sourceOpenMode, state.entries, new Set([row.line]));
    const result = openAtLineAvailability(now, row.file, row.line, updating);
    if (!result.enabled) {
      onFail(`Not opened: ${result.reason ?? "the Log Viewer cannot show this line."}`);
      return;
    }
    state.setPendingScrollTarget({ filePath: row.file, lineNumber: row.line });
    useUiStore.getState().setActiveView("log");
    // The Log view is always built in (the backend's workspace list starts with it), but the switch
    // refuses a workspace that is not available, and a target armed with no Log view to consume it
    // would scroll a later load. So an armed target is never left behind by a switch that did not happen.
    if (useUiStore.getState().activeView !== "log") {
      state.setPendingScrollTarget(null);
      onFail("Not opened: the Log Viewer is not available here.");
    }
  };

  const copy = async () => {
    try {
      await writeText(unplacedCopyText(view));
      onReply("Copied the unplaced list as text.");
    } catch (error) {
      onFail(`Copy failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    if (event.key !== "Escape") return;
    // Spent here, so the workspace's own Escape handler does not also clear the time range.
    event.preventDefault();
    onEscape();
  };

  const omitted = unplacedOmittedNotice(view);
  const buttonFont = { fontSize: `${sizes.lane}px` };
  return (
    <section
      aria-label="Items without a timestamp"
      data-testid="unplaced-pane"
      onKeyDown={onKeyDown}
      style={{ display: "grid", gap: "8px", alignContent: "start", fontFamily: LOG_UI_FONT_FAMILY }}
    >
      <h2 style={{ margin: 0, fontSize: `${sizes.f}px`, fontWeight: 600, color: tokens.colorNeutralForeground1 }}>
        {unplacedHeader(view)}
      </h2>
      <div style={{ fontSize: `${sizes.label}px`, color: cardSecondary }}>{notPlacedCaption(view)}</div>
      <div>
        <Button
          appearance="secondary"
          size="small"
          icon={<Copy16Regular />}
          style={buttonFont}
          // The list on show belongs to an earlier session while the data is updating, and the copy
          // carries no mark of that, so it waits (as the chain's Copy does).
          disabledFocusable={updating}
          title={updating ? WAIT_FOR_UPDATE_REASON : undefined}
          aria-description={updating ? WAIT_FOR_UPDATE_REASON : undefined}
          onClick={updating ? undefined : () => void copy()}
        >
          Copy as text
        </Button>
      </div>
      <ul
        aria-label="Unplaced entries"
        style={{ listStyle: "none", margin: 0, padding: 0, display: "grid", fontSize: `${sizes.lane}px` }}
      >
        {view.rows.map((row) => {
          const chip =
            row.kind === "event"
              ? { backgroundColor: visuals.selection.background, color: visuals.selection.foreground }
              : // Spec 8.13 puts LOG on bg4; Foreground2 on bg4 measures 4.36:1 in solarized-dark, so
                // it is bg3 (at least 4.86:1 in every theme).
                { backgroundColor: tokens.colorNeutralBackground3, color: tokens.colorNeutralForeground2 };
          const availability =
            row.file === null || row.line === null
              ? null
              : openAtLineAvailability(viewer, row.file, row.line, updating);
          return (
            <li
              key={row.key}
              title={row.detail}
              style={{
                display: "flex",
                alignItems: "center",
                flexWrap: "wrap",
                gap: "4px 10px",
                padding: "6px 4px",
                borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                color: tokens.colorNeutralForeground1,
              }}
            >
              <span
                data-chip={row.chip}
                style={{
                  ...chip,
                  fontFamily: tokens.fontFamilyBase,
                  fontSize: `${chipSize}px`,
                  fontWeight: 700,
                  padding: "1px 6px",
                  borderRadius: "4px",
                }}
              >
                {row.chip}
              </span>
              <span style={{ fontFamily: tokens.fontFamilyNumeric }}>{row.label}</span>
              <span style={{ color: cardSecondary }}>{row.context}</span>
              <span style={{ fontFamily: tokens.fontFamilyNumeric, color: tokens.colorNeutralForeground2 }}>
                {row.position}
              </span>
              {availability !== null && (
                <Button
                  appearance="subtle"
                  size="small"
                  icon={<Open16Regular />}
                  style={buttonFont}
                  aria-label={availability.name}
                  aria-description={availability.reason ?? undefined}
                  title={availability.reason ?? availability.name}
                  disabledFocusable={!availability.enabled}
                  onClick={() => open(row)}
                >
                  {OPEN_IN_LOG_VIEWER_LABEL}
                </Button>
              )}
            </li>
          );
        })}
      </ul>
      {omitted !== null && (
        <div data-testid="unplaced-omitted" style={{ fontSize: `${sizes.lane}px`, color: tokens.colorNeutralForeground2 }}>
          {omitted}
        </div>
      )}
    </section>
  );
}

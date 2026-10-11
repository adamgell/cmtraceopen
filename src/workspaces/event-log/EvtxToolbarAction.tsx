/**
 * The Event Logs workspace toolbar action: a live or files source pill (spec 8.1).
 *
 * It names where the events on screen came from. A live source shows the machine and the tail
 * state; a file source shows how many sources were opened. It is a status, not a control: it has
 * no hover, focus or pressed state, so the colors below are the only ones it ever draws.
 *
 * The live pill is drawn from `liveSource` in the visual token map and from nothing else; the
 * files pill uses the neutral surface tokens the spec names. The label identifies the pill, so
 * the background and the decorative border are never what tells it apart from the toolbar.
 */
import { Fragment, useMemo, type CSSProperties } from "react";
import { tokens } from "@fluentui/react-components";
import { LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useEvtxStore } from "./evtx-store";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";
import type { EvtxLiveMode, EvtxRecord } from "./types";

/** Shown when a live source names no machine and no loaded event says which one it is. */
export const LOCAL_MACHINE_LABEL = "This computer";

/**
 * The machine the loaded events came from, for a live source with no remote target.
 *
 * The most frequent non-empty `computer`; a tie goes to the name that sorts first, so the answer
 * never depends on load order. Null when no event carries one: the caller says "This computer"
 * then, rather than guessing a name.
 */
export function mostFrequentComputer(
  records: readonly Pick<EvtxRecord, "computer">[],
): string | null {
  const counts = new Map<string, number>();
  for (const { computer } of records) {
    if (computer.trim() === "") continue;
    counts.set(computer, (counts.get(computer) ?? 0) + 1);
  }
  let best: string | null = null;
  let bestCount = 0;
  for (const [name, count] of counts) {
    if (count > bestCount || (count === bestCount && best !== null && name < best)) {
      best = name;
      bestCount = count;
    }
  }
  return best;
}

/** `remoteMachine`, otherwise the most frequent `records[].computer`, otherwise "This computer". */
export function resolveMachineName(
  remoteMachine: string | null,
  records: readonly Pick<EvtxRecord, "computer">[],
): string {
  if (remoteMachine !== null && remoteMachine.trim() !== "") return remoteMachine;
  return mostFrequentComputer(records) ?? LOCAL_MACHINE_LABEL;
}

/**
 * What a running tail adds to the pill. A source whose tail has not been started has nothing to
 * add: the pill then reads like the plain "Live · {machine}" form. An unsupported tail is not a
 * qualifier but a different label; see `liveLabel`.
 */
const TAIL_QUALIFIER: Record<Exclude<EvtxLiveMode, "unsupported">, string> = {
  subscription: "tailing",
  polling: "polling",
  mixed: "tailing (mixed)",
};

const TAIL_DESCRIPTION: Record<EvtxLiveMode | "idle", string> = {
  idle: "Live tail is not running.",
  subscription: "Live tail is running on event subscriptions.",
  polling: "Live tail is running by polling.",
  mixed: "Live tail is running on subscriptions for some channels and by polling for others.",
  unsupported: "Live tail is not supported for these channels, so new events are not followed.",
};

/** "Live · {machine}", with the tail state after it; "Live · not tailing" when it is unsupported. */
export function liveLabel(machine: string, tailMode: EvtxLiveMode | null): string {
  if (tailMode === "unsupported") return "Live · not tailing";
  return tailMode === null
    ? `Live · ${machine}`
    : `Live · ${machine} · ${TAIL_QUALIFIER[tailMode]}`;
}

export function liveDescription(machine: string, tailMode: EvtxLiveMode | null): string {
  return `Live event logs from ${machine}. ${TAIL_DESCRIPTION[tailMode ?? "idle"]}`;
}

interface PillRun {
  text: string;
  /** Counts use the numeric font with tabular figures (spec D4). */
  numeric?: boolean;
}

/** "Files · {n} sources". With no source count on record the pill says "Files" and no number. */
function filesRuns(sourceCount: number): PillRun[] {
  if (sourceCount <= 0) return [{ text: "Files" }];
  return [
    { text: "Files · " },
    { text: sourceCount.toLocaleString(), numeric: true },
    { text: sourceCount === 1 ? " source" : " sources" },
  ];
}

export function filesLabel(sourceCount: number): string {
  return filesRuns(sourceCount)
    .map((run) => run.text)
    .join("");
}

function filesDescription(sourceCount: number): string {
  return sourceCount > 0
    ? `Event logs opened from ${sourceCount.toLocaleString()} ${sourceCount === 1 ? "source" : "sources"}.`
    : "Event logs opened from files.";
}

const DOT_SIZE_PX = 7;
const PILL_RADIUS_PX = 8;

export function EvtxToolbarAction() {
  const sourceMode = useEvtxStore((s) => s.sourceMode);
  const tailMode = useEvtxStore((s) => s.tailMode);
  const remoteMachine = useEvtxStore((s) => s.remoteMachine);
  const sourceCount = useEvtxStore((s) => s.sourcePaths.length);
  const records = useEvtxStore((s) => s.records);
  const visual = useEvtxVisualTokens();
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const fontSize = Math.max(10, getLogListMetrics(logListFontSize).fontSize - 2);

  // Only a live source with no remote target reads the records, and then once per records array.
  const machine = useMemo(
    () => (sourceMode === "live" ? resolveMachineName(remoteMachine, records) : null),
    [sourceMode, remoteMachine, records],
  );

  if (sourceMode === null) return null;

  const live = sourceMode === "live";
  const colors = live
    ? visual.liveSource
    : {
        background: tokens.colorNeutralBackground3,
        border: tokens.colorNeutralStroke1,
        foreground: tokens.colorNeutralForeground2,
      };
  const runs: PillRun[] = live
    ? [{ text: liveLabel(machine ?? LOCAL_MACHINE_LABEL, tailMode) }]
    : filesRuns(sourceCount);
  const description = live
    ? liveDescription(machine ?? LOCAL_MACHINE_LABEL, tailMode)
    : filesDescription(sourceCount);

  const pillStyle: CSSProperties = {
    display: "inline-flex",
    alignItems: "center",
    gap: "6px",
    boxSizing: "border-box",
    maxWidth: "360px",
    padding: "3px 10px",
    borderRadius: `${PILL_RADIUS_PX}px`,
    border: `1px solid ${colors.border}`,
    backgroundColor: colors.background,
    color: colors.foreground,
    fontFamily: LOG_UI_FONT_FAMILY,
    fontSize: `${fontSize}px`,
    fontWeight: 600,
    whiteSpace: "nowrap",
    cursor: "default",
    userSelect: "none",
  };

  return (
    <span
      data-testid="evtx-source-pill"
      data-source={sourceMode}
      title={description}
      style={pillStyle}
    >
      <span
        aria-hidden="true"
        data-testid="evtx-source-pill-dot"
        style={{
          flexShrink: 0,
          width: `${DOT_SIZE_PX}px`,
          height: `${DOT_SIZE_PX}px`,
          borderRadius: "50%",
          backgroundColor: colors.foreground,
        }}
      />
      <span
        data-testid="evtx-source-pill-label"
        style={{
          minWidth: 0,
          overflow: "hidden",
          textOverflow: "ellipsis",
        }}
      >
        {runs.map((run, index) =>
          run.numeric ? (
            <span
              key={index}
              style={{
                fontFamily: tokens.fontFamilyNumeric,
                fontVariantNumeric: "tabular-nums",
              }}
            >
              {run.text}
            </span>
          ) : (
            <Fragment key={index}>{run.text}</Fragment>
          ),
        )}
      </span>
    </span>
  );
}

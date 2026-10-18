/**
 * The value of the EVT / LOG chip: the one place that says which entries get which. Pure, so the
 * models (the unplaced rows, the Details context rows) and the views take it without pulling in
 * the component that draws the chip (EvtxKindChip.tsx). The one-chip guard (evtx-one-chip.test.ts)
 * keeps this module and the chip as the only files of the workspace that write the two words.
 */
import type { TimelineOrigin } from "./unified-timeline";

export type KindChip = "EVT" | "LOG";

/** Keyed by every origin kind, so a new kind is a compile error here and not a silent LOG. */
const CHIPS = { event: "EVT", log: "LOG" } as const satisfies Record<TimelineOrigin["kind"], KindChip>;

/** A Windows event is EVT; a text-log line is LOG. */
export function chipForOriginKind(kind: TimelineOrigin["kind"]): KindChip {
  return CHIPS[kind];
}

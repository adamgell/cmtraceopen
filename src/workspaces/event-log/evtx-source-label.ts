/**
 * The machine and mode an Event Logs session is reading, in the words the view strip and the
 * toolbar pill (spec 8.1) both show. One rule here, so the two cannot name different machines.
 *
 * Pure: it reads what the store holds and sends nothing.
 */
import type { EvtxSourceMode } from "./evtx-store";
import type { EvtxRecord } from "./types";

/** What stands in for a machine name when no source names one. */
export const EVTX_LOCAL_MACHINE_NAME = "This computer";

export interface EvtxSourceLabelInput {
  sourceMode: EvtxSourceMode;
  remoteMachine: string | null;
  records: readonly Pick<EvtxRecord, "computer">[];
}

/**
 * The machine the events are from (spec 8.1): the remote machine when there is one, otherwise the
 * `computer` most of the loaded records carry (the first one seen wins a tie), otherwise
 * "This computer". Never a name the data does not carry.
 */
export function eventLogMachineName(input: Pick<EvtxSourceLabelInput, "remoteMachine" | "records">): string {
  const remote = input.remoteMachine?.trim();
  if (remote) return remote;

  const counts = new Map<string, number>();
  for (const { computer } of input.records) {
    const name = computer.trim();
    if (name) counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  let best = EVTX_LOCAL_MACHINE_NAME;
  let bestCount = 0;
  for (const [name, count] of counts) {
    if (count > bestCount) {
      best = name;
      bestCount = count;
    }
  }
  return best;
}

/** "Source: {machine} · {live|files}", or null while no source is open. */
export function eventLogSourceLabel(input: EvtxSourceLabelInput): string | null {
  if (input.sourceMode === null) return null;
  return `Source: ${eventLogMachineName(input)} · ${input.sourceMode}`;
}

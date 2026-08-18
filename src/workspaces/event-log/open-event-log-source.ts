import { expandEventLogSources } from "../../lib/commands";
import { useEvtxStore } from "./evtx-store";

export type EventLogOpenSource =
  | { kind: "file"; path: string }
  | { kind: "folder"; path: string }
  | { kind: "wildcard"; path: string }
  | { kind: "archive"; path: string }
  | { kind: "vss"; path: string };

/** Expand selected sources once and hand the complete manifest to the store. */
export async function openEventLogSources(sources: EventLogOpenSource[]): Promise<void> {
  const manifest = await expandEventLogSources(sources);

  await useEvtxStore.getState().parseManifest(manifest);
}

export async function openEventLogSource(source: EventLogOpenSource): Promise<void> {
  await openEventLogSources([source]);
}

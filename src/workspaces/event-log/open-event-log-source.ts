import { expandEventLogSources } from "../../lib/commands";
import { useEvtxStore } from "./evtx-store";

export type EventLogOpenSource =
  | { kind: "file"; path: string }
  | { kind: "folder"; path: string }
  | { kind: "wildcard"; path: string }
  | { kind: "vss"; path: string };

/** Expand selected sources once and hand the complete manifest to the store. */
export async function openEventLogSources(sources: EventLogOpenSource[]): Promise<void> {
  const manifest = await expandEventLogSources(sources.map((source) => source.path));
  if (manifest.entries.length === 0) {
    const details = manifest.coverage
      .map((gap) => `${gap.path}: ${gap.reason}`)
      .join("; ");
    throw new Error(details || "No .evtx files were found for this source.");
  }

  await useEvtxStore.getState().parseManifest(manifest);
}

export async function openEventLogSource(source: EventLogOpenSource): Promise<void> {
  await openEventLogSources([source]);
}

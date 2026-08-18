import { expandEventLogSources } from "../../lib/commands";
import { useEvtxStore } from "./evtx-store";

export type EventLogOpenSource =
  | { kind: "file"; path: string }
  | { kind: "folder"; path: string }
  | { kind: "wildcard"; path: string }
  | { kind: "vss"; path: string };

/** Expand a selected source once, then hand only the bounded manifest to the parser. */
export async function openEventLogSource(source: EventLogOpenSource): Promise<void> {
  const manifest = await expandEventLogSources([source.path]);
  if (manifest.entries.length === 0) {
    const details = manifest.coverage
      .map((gap) => `${gap.path}: ${gap.reason}`)
      .join("; ");
    throw new Error(details || "No .evtx files were found for this source.");
  }

  await useEvtxStore.getState().parseFiles(manifest.entries.map((entry) => entry.path));
}

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
  const manifest = await expandEventLogSources(sources.map((source) => source.path));
  const explicitKinds = new Map(
    sources
      .filter((source) => source.kind !== "folder" && source.kind !== "wildcard")
      .map((source) => [source.path.replaceAll("/", "\\").toLowerCase(), source.kind] as const)
  );
  manifest.entries = manifest.entries.map((entry) => ({
    ...entry,
    kind: explicitKinds.get(entry.path.replaceAll("/", "\\").toLowerCase()) ?? entry.kind,
  }));

  await useEvtxStore.getState().parseManifest(manifest);
}

export async function openEventLogSource(source: EventLogOpenSource): Promise<void> {
  await openEventLogSources([source]);
}

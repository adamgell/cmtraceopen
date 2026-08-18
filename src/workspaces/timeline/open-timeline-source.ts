import { buildTimelineFromSources } from "../../components/timeline/hooks/useTimelineBundle";
import { listLogFolder } from "../../lib/commands";
import { useTimelineStore } from "../../stores/timeline-store";
import type { LogSource } from "../../types/log";

export async function openTimelineSource(source: LogSource): Promise<void> {
  const existing =
    useTimelineStore.getState().bundle?.sources.map((item) => item.path) ?? [];

  let incoming: string[] = [];
  if (source.kind === "file") {
    incoming = [source.path];
  } else if (source.kind === "folder") {
    const listing = await listLogFolder(source.path);
    incoming = listing.entries.filter((entry) => !entry.isDir).map((entry) => entry.path);
    if (incoming.length === 0) {
      incoming = [source.path];
    }
  } else if (source.pathKind === "file") {
    incoming = [source.defaultPath];
  } else {
    const listing = await listLogFolder(source.defaultPath);
    incoming = listing.entries.filter((entry) => !entry.isDir).map((entry) => entry.path);
    if (incoming.length === 0) {
      incoming = [source.defaultPath];
    }
  }

  const merged = Array.from(new Set([...existing, ...incoming])).map((path) => ({
    path,
  }));
  await buildTimelineFromSources(merged);
}

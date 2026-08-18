import { buildTimelineFromSources } from "../../components/timeline/hooks/useTimelineBundle";
import { listLogFolder } from "../../lib/commands";
import { useTimelineStore } from "../../stores/timeline-store";
import type { FolderEntry, LogSource } from "../../types/log";

function incomingFromListing(folderPath: string, entries: FolderEntry[]): string[] {
  const childPaths = entries.filter((entry) => !entry.isDir).map((entry) => entry.path);
  if (childPaths.length === 0) {
    return [];
  }
  const hasIme = childPaths.some((path) => {
    const lower = path.toLowerCase();
    return (
      lower.endsWith("agentexecutor.log") ||
      lower.endsWith("intunemanagementextension.log")
    );
  });
  return hasIme ? [...childPaths, folderPath] : childPaths;
}

export async function openTimelineSource(source: LogSource): Promise<void> {
  const existing =
    useTimelineStore.getState().bundle?.sources.map((item) => item.path) ?? [];

  let incoming: string[] = [];
  if (source.kind === "file") {
    incoming = [source.path];
  } else if (source.kind === "folder") {
    const listing = await listLogFolder(source.path);
    incoming = incomingFromListing(source.path, listing.entries);
  } else if (source.pathKind === "file") {
    incoming = [source.defaultPath];
  } else {
    const listing = await listLogFolder(source.defaultPath);
    incoming = incomingFromListing(source.defaultPath, listing.entries);
  }

  if (incoming.length === 0 && existing.length === 0) {
    return;
  }

  const merged = Array.from(new Set([...existing, ...incoming])).map((path) => ({
    path,
  }));
  await buildTimelineFromSources(merged);
}

import { buildTimelineFromSources } from "../../components/timeline/hooks/useTimelineBundle";
import { listLogFolder } from "../../lib/commands";
import { useTimelineStore } from "../../stores/timeline-store";
import type { FolderEntry, LogSource } from "../../types/log";

function incomingFromListing(
  folderPath: string,
  entries: FolderEntry[],
): string[] {
  const childPaths = entries
    .filter((entry) => !entry.isDir)
    .map((entry) => entry.path);
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

let timelineOpenQueue: Promise<void> = Promise.resolve();

function enqueueTimelineOpen(operation: () => Promise<void>): Promise<void> {
  const queued = timelineOpenQueue.then(() => {
    useTimelineStore.getState().setLoadError(null);
    return operation();
  });
  timelineOpenQueue = queued.catch((error) => {
    useTimelineStore
      .getState()
      .setLoadError(error instanceof Error ? error.message : String(error));
  });
  return queued;
}

async function appendTimelineSources(incoming: string[]): Promise<void> {
  if (incoming.length === 0) {
    return;
  }

  const existing =
    useTimelineStore.getState().bundle?.sources.map((item) => item.path) ?? [];
  const merged = Array.from(new Set([...existing, ...incoming])).map(
    (path) => ({
      path,
    }),
  );
  await buildTimelineFromSources(merged);
}

async function replaceTimelineSources(incoming: string[]): Promise<void> {
  if (incoming.length === 0) {
    return;
  }

  const sources = Array.from(new Set(incoming)).map((path) => ({ path }));
  await buildTimelineFromSources(sources);
}

async function incomingFromSource(source: LogSource): Promise<string[]> {
  if (source.kind === "file") {
    return [source.path];
  }

  if (source.kind === "folder") {
    const listing = await listLogFolder(source.path);
    return incomingFromListing(source.path, listing.entries);
  }

  if (source.pathKind === "file") {
    return [source.defaultPath];
  }

  const listing = await listLogFolder(source.defaultPath);
  return incomingFromListing(source.defaultPath, listing.entries);
}

export function openTimelineSource(source: LogSource): Promise<void> {
  return enqueueTimelineOpen(async () => {
    await appendTimelineSources(await incomingFromSource(source));
  });
}

export function replaceTimelineSource(source: LogSource): Promise<void> {
  return enqueueTimelineOpen(async () => {
    useTimelineStore.getState().setBundle(null);
    await replaceTimelineSources(await incomingFromSource(source));
  });
}

export function openTimelineFiles(paths: string[]): Promise<void> {
  return enqueueTimelineOpen(() => appendTimelineSources(paths));
}

import { formatTimelineError } from "../../lib/timeline-errors";
import { buildTimelineFromSources } from "../../components/timeline/hooks/buildTimelineFromSources";
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

function enqueueTimelineOpen(operation: (refreshOrigin: () => void, isCurrent: () => boolean) => Promise<void>): Promise<void> {
  const queued = timelineOpenQueue.then(async () => {
    let origin = useTimelineStore.getState().buildOrigin();
    const refreshOrigin = () => { origin = useTimelineStore.getState().buildOrigin(); };
    useTimelineStore.getState().setLoadError(null);
    try { await operation(refreshOrigin, () => useTimelineStore.getState().isBuildCurrent(origin)); }
    catch (error) {
      // Builds have their own guarded error handler. This handles listing errors
      // only while the queue operation still owns the same visible timeline.
      if (useTimelineStore.getState().isBuildCurrent(origin)) useTimelineStore.getState().setLoadError(formatTimelineError(error));
      throw error;
    }
  });
  timelineOpenQueue = queued.catch(() => {});
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
  return enqueueTimelineOpen(async (_refreshOrigin, isCurrent) => {
    const incoming = await incomingFromSource(source);
    if (isCurrent()) await appendTimelineSources(incoming);
  });
}

export function replaceTimelineSource(source: LogSource): Promise<void> {
  return enqueueTimelineOpen(async (refreshOrigin, isCurrent) => {
    if (!useTimelineStore.getState().staleSource) {
      useTimelineStore.getState().setBundle(null);
      refreshOrigin();
    }
    const incoming = await incomingFromSource(source);
    if (isCurrent()) await replaceTimelineSources(incoming);
  });
}

export function openTimelineFiles(paths: string[]): Promise<void> {
  return enqueueTimelineOpen(() => appendTimelineSources(paths));
}

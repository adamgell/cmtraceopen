import { listLogFolder } from "../../lib/commands";
import type { FolderEntry, LogSource } from "../../types/log";
import { useEvtxStore } from "./evtx-store";

function evtxPathsFromFolderEntries(entries: FolderEntry[]): string[] {
  return entries
    .filter((entry) => !entry.isDir && entry.name.toLowerCase().endsWith(".evtx"))
    .map((entry) => entry.path);
}

export async function openEventLogSource(source: LogSource): Promise<void> {
  const parseFiles = useEvtxStore.getState().parseFiles;

  try {
    if (source.kind === "file") {
      await parseFiles([source.path]);
      return;
    }

    if (source.kind === "folder") {
      const listing = await listLogFolder(source.path);
      const evtxPaths = evtxPathsFromFolderEntries(listing.entries);
      if (evtxPaths.length === 0) {
        throw new Error(
          "No .evtx files were found in that folder. Choose a folder that contains Windows Event Log files.",
        );
      }
      await parseFiles(evtxPaths);
      return;
    }

    if (source.pathKind === "file") {
      await parseFiles([source.defaultPath]);
      return;
    }

    const listing = await listLogFolder(source.defaultPath);
    const evtxPaths = evtxPathsFromFolderEntries(listing.entries);
    if (evtxPaths.length === 0) {
      throw new Error("No .evtx files were found for that known source.");
    }
    await parseFiles(evtxPaths);
  } catch (error) {
    useEvtxStore.getState().setLoadError(
      error instanceof Error ? error.message : String(error),
    );
    throw error;
  }
}

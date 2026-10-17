/**
 * "Add log source..." (spec 8.19): opens a text log from the Event Logs channel pane.
 *
 * It runs the same loaders the Log workspace's own Open runs, so the log lands in the global log
 * store and the workspace's analysis session picks it up. It does NOT merge: a single file or a
 * folder becomes the store's active source, exactly as it does from the Log workspace, and the
 * previous log stays a tab there but is no longer correlated (`scopeLogEntries` hands the session
 * the active source only unless the store is in "merged" mode). The pane says which mode is live.
 *
 * Why this has its own dialogs: the ones in `use-app-actions` take their filters and their route
 * from the ACTIVE workspace, so in Event Logs they open EVTX. Here the filters are the Log
 * workspace's, minus registry files, which the loaders hand to the registry viewer and which would
 * leave the store with no entries at all.
 *
 * Every outcome is described from the store as it is AFTER the attempt. A failed single-file or
 * folder load clears the active log (`loadLogSource`'s catch), a failed multi-file parse leaves the
 * previous one alone, and a batch parse skips the files it cannot read without an error, so the
 * message never assumes which of those happened.
 */
import { open } from "@tauri-apps/plugin-dialog";
import { getBaseName } from "../../lib/file-paths";
import {
  classifySourceError,
  loadFilesAsLogSource,
  loadPathAsLogSource,
} from "../../lib/log-source";
import { useFilterStore } from "../../stores/filter-store";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { logWorkspace } from "../log";
import { summarizeLogSources } from "./evtx-channel-stats";
import { scopeLogEntries } from "./unified-timeline";

export type AddLogSourceKind = "file" | "folder";

export type AddLogSourceOutcome =
  /** The dialog was dismissed, or a newer load superseded this one. Nothing is reported. */
  | { status: "cancelled" }
  /** The selection was refused before anything was loaded; the store is untouched. */
  | { status: "rejected"; message: string }
  /** At least one text log is loaded. `notice` names what was not, when anything was not. */
  | { status: "added"; notice: string | null }
  | { status: "failed"; message: string };

/** The Log workspace's Open filters without the registry viewer's. */
const TEXT_LOG_FILE_FILTERS = (logWorkspace.fileFilters ?? [
  { name: "All Files", extensions: ["*"] },
]).filter((filter) => !filter.extensions.some((ext) => ext.toLowerCase() === "reg"));

const MAX_NAMED_FILES = 3;

const isRegistryFile = (path: string) => /\.reg$/i.test(path);

/** The same file under either separator or case, since only identity matters here. */
const pathKey = (path: string) => path.replace(/\\/g, "/").toLowerCase();

function nameFiles(paths: readonly string[]): string {
  const names = paths.slice(0, MAX_NAMED_FILES).map((path) => getBaseName(path) || path);
  const more = paths.length - names.length;
  return more > 0 ? `${names.join(", ")} and ${more} more` : names.join(", ");
}

/** The text logs Event Logs correlates right now, as the workspace scopes them. */
function correlatedLogSources() {
  const log = useLogStore.getState();
  return summarizeLogSources(
    scopeLogEntries(
      log.entries,
      log.activeSource,
      log.sourceOpenMode,
      useUiStore.getState().currentPlatform,
    ),
  );
}

function resultingState(): string {
  const count = correlatedLogSources().length;
  if (count === 0) return "No text log is now correlated.";
  return `${count} text ${count === 1 ? "log is" : "logs are"} now correlated.`;
}

async function pickPaths(kind: AddLogSourceKind): Promise<string[]> {
  if (kind === "folder") {
    const selected = await open({ directory: true, multiple: false });
    return typeof selected === "string" ? [selected] : [];
  }
  const selected = await open({ multiple: true, filters: TEXT_LOG_FILE_FILTERS });
  if (!selected) return [];
  return [...new Set(Array.isArray(selected) ? selected : [selected])];
}

/** What the attempt was asked to read, for the message that names it. */
function describeRequest(kind: AddLogSourceKind, paths: readonly string[]): string {
  if (kind === "folder") return `folder ${getBaseName(paths[0]) || paths[0]}`;
  return paths.length === 1 ? getBaseName(paths[0]) || paths[0] : `${paths.length} files`;
}

function failed(request: string, reason: string): AddLogSourceOutcome {
  return {
    status: "failed",
    message: `Could not add ${request}: ${reason.replace(/[.\s]+$/, "")}. ${resultingState()}`,
  };
}

/**
 * Asks for a file or folder and loads it as the store's active text-log source.
 *
 * Never throws: a failure is an outcome. The caller disables its control while this runs.
 */
export async function addLogSource(kind: AddLogSourceKind): Promise<AddLogSourceOutcome> {
  let paths: string[];
  try {
    paths = await pickPaths(kind);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    return {
      status: "failed",
      message: `Could not open the file dialog: ${reason.replace(/[.\s]+$/, "")}. ${resultingState()}`,
    };
  }
  if (paths.length === 0) return { status: "cancelled" };

  const registryFiles = paths.filter(isRegistryFile);
  if (registryFiles.length > 0) {
    return {
      status: "rejected",
      message: `Not added: ${nameFiles(registryFiles)} ${
        registryFiles.length === 1
          ? "is a registry file, which opens"
          : "are registry files, which open"
      } in the Log workspace. ${resultingState()}`,
    };
  }

  const request = describeRequest(kind, paths);
  // Every other open clears the Log workspace's filter before it loads (use-app-actions).
  useFilterStore.getState().clearFilter();

  let settled: boolean;
  try {
    settled =
      kind === "folder"
        ? (await loadPathAsLogSource(paths[0], { preferFolder: true })) !== null
        : paths.length === 1
          ? (await loadPathAsLogSource(paths[0], { fallbackToFolder: false })) !== null
          : await loadFilesAsLogSource(paths);
  } catch (error) {
    return failed(request, classifySourceError(error).message);
  }
  if (!settled) return { status: "cancelled" };

  // A batch parse skips what it cannot read without an error, so ask the store what it loaded.
  const log = useLogStore.getState();
  const loaded =
    log.sourceOpenMode === "aggregate-folder"
      ? log.aggregateFiles.map((file) => file.filePath)
      : log.selectedSourceFilePath
        ? [log.selectedSourceFilePath]
        : [];
  if (loaded.length === 0) {
    return failed(request, kind === "folder" ? "no readable log file was found" : "no text log could be read");
  }

  const loadedKeys = new Set(loaded.map(pathKey));
  const expected =
    kind === "folder"
      ? log.sourceEntries.filter((entry) => !entry.isDir).map((entry) => entry.path)
      : paths;
  const notRead = expected.filter((path) => !loadedKeys.has(pathKey(path)));
  const listedKeys = new Set(correlatedLogSources().map((source) => pathKey(source.path)));
  const noEntries = loaded.filter((path) => !listedKeys.has(pathKey(path)));

  const parts: string[] = [];
  if (notRead.length > 0) parts.push(`Not read: ${nameFiles(notRead)}.`);
  if (noEntries.length > 0) parts.push(`Read but holds no entries: ${nameFiles(noEntries)}.`);
  return { status: "added", notice: parts.length > 0 ? parts.join(" ") : null };
}

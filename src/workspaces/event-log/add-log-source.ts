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
 * workspace's, and a selection that cannot be a text log is refused before anything loads:
 * registry files, which the loaders hand to the registry viewer and which would leave the store
 * with no entries, and event logs, which Event Logs opens through its own source picker.
 *
 * Outcomes are decided from the store as it is AFTER the attempt, and the messages carry only what
 * happened; the pane appends how many text logs are correlated now, live
 * (`describeCorrelatedState`). A failed single-file or
 * folder load clears the active log (`loadLogSource`'s catch), a failed multi-file parse leaves the
 * previous one alone, and a batch parse skips the files it cannot read without an error, so
 * nothing here assumes which of those happened. An add that leaves none of its files correlated is
 * not "added".
 *
 * The Log workspace's filter is cleared only after an add that took, as every open does. The
 * multi-file loader clears it itself, before it parses, so an add that then fails or takes nothing
 * gives it back. Both loaders stop the earlier tail before they parse, so an add that then fails
 * leaves the earlier log correlated but no longer live; nothing here can undo that.
 */
import { open } from "@tauri-apps/plugin-dialog";
import { getBaseName } from "../../lib/file-paths";
import {
  classifySourceError,
  loadFilesAsLogSource,
  loadPathAsLogSource,
  type LoadLogSourceResult,
} from "../../lib/log-source";
import { useFilterStore } from "../../stores/filter-store";
import { useLogStore } from "../../stores/log-store";
import { useUiStore } from "../../stores/ui-store";
import { logWorkspace } from "../log";
import { summarizeLogSources } from "./evtx-channel-stats";
import { normalizeLogPath, scopeLogEntries } from "./unified-timeline";

export type AddLogSourceKind = "file" | "folder";

/**
 * What an add did. Messages say what happened to the add; none states how many text logs are
 * correlated, because that changes under a report that stays on screen.
 */
export type AddLogSourceOutcome =
  /** The dialog was dismissed, or a newer load superseded this one. Nothing is reported. */
  | { status: "cancelled" }
  /** The selection was refused before anything was loaded; the store is untouched. */
  | { status: "rejected"; message: string }
  /**
   * At least one file the add loaded is correlated now. `notice` names what was not read or not
   * covered, when anything was not.
   */
  | { status: "added"; notice: string | null }
  /** The add loaded, and none of its files is correlated: a log with no entries, a registry export. */
  | { status: "notAdded"; message: string }
  /** The load failed, or read nothing. */
  | { status: "failed"; message: string };

/**
 * The Log workspace's Open filters without the registry viewer's. "All Files" stays, so what cannot
 * be a text log is refused after it is picked, with the reason (`refusalFor`).
 */
const TEXT_LOG_FILE_FILTERS = (logWorkspace.fileFilters ?? [
  { name: "All Files", extensions: ["*"] },
]).filter((filter) => !filter.extensions.some((ext) => ext.toLowerCase() === "reg"));

const MAX_NAMED = 3;
const MAX_REASON_LENGTH = 120;

const isRegistryFile = (path: string) => /\.reg$/i.test(path);

/**
 * The names the event-log backend treats as EVTX (`is_evtx_candidate`, event_log/parser.rs): a
 * name that ends in `.evtx`, contains `.evtx.` (a rotation or backup, such as `.evtx.bak`), or ends
 * in `.evtx~`.
 */
function isEventLogFile(path: string): boolean {
  const name = (getBaseName(path) || path).toLowerCase();
  return name.endsWith(".evtx") || name.includes(".evtx.") || name.endsWith(".evtx~");
}

/** The first few names, then how many more. */
function nameList(names: readonly string[]): string {
  const shown = names.slice(0, MAX_NAMED);
  const more = names.length - shown.length;
  return more > 0 ? `${shown.join(", ")} and ${more} more` : shown.join(", ");
}

function nameFiles(paths: readonly string[]): string {
  return nameList(paths.map((path) => getBaseName(path) || path));
}

const plural = (count: number, one: string, many: string) => (count === 1 ? one : many);

const sentence = (text: string) => text.replace(/[.\s]+$/, "") + ".";

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
  return nameFiles(paths);
}

/** Why a selection cannot be added, or null. The whole selection is refused, not a part of it. */
function refusalFor(paths: readonly string[]): string | null {
  const registry = paths.filter(isRegistryFile);
  const eventLogs = paths.filter(isEventLogFile);
  const reasons: string[] = [];
  if (registry.length > 0) {
    reasons.push(
      `${nameFiles(registry)} ${plural(
        registry.length,
        "is a registry file, which opens",
        "are registry files, which open",
      )} in the Log workspace.`,
    );
  }
  if (eventLogs.length > 0) {
    reasons.push(
      `${nameFiles(eventLogs)} ${plural(
        eventLogs.length,
        "is an event log file",
        "are event log files",
      )}; Event Logs opens EVTX files through its source picker.`,
    );
  }
  return reasons.length > 0 ? `Not added: ${reasons.join(" ")}` : null;
}

/**
 * What a folder add did not cover, from what the loaders know: the listing's own diagnostics and
 * limits, the subfolders a non-bundle folder load never enters, and, for an evidence bundle, the
 * kinds of file its collector skips without counting them anywhere the UI can read.
 */
function folderCoverage(result: LoadLogSourceResult, isBundle: boolean): string[] {
  const parts: string[] = [];
  const childErrors = result.childErrors ?? [];
  if (childErrors.length > 0) {
    const described = childErrors.map((diagnostic) => {
      const reason =
        diagnostic.reason.length > MAX_REASON_LENGTH
          ? `${diagnostic.reason.slice(0, MAX_REASON_LENGTH - 3)}...`
          : diagnostic.reason;
      return `${getBaseName(diagnostic.path) || diagnostic.path} (${reason})`;
    });
    parts.push(
      `${childErrors.length} ${plural(childErrors.length, "entry", "entries")} could not be listed: ${nameList(described)}.`,
    );
  }
  if (isBundle) {
    parts.push("Binary and oversized files in an evidence bundle are not read.");
  } else {
    const subfolders = result.entries.filter((entry) => entry.isDir).map((entry) => entry.name);
    if (subfolders.length > 0) {
      parts.push(
        `${subfolders.length} ${plural(subfolders.length, "subfolder", "subfolders")} not read: ${nameList(subfolders)}.`,
      );
    }
  }
  return parts;
}

function failed(request: string, reason: string, coverage: readonly string[] = []): AddLogSourceOutcome {
  return {
    status: "failed",
    message: [`Could not add ${request}: ${sentence(reason)}`, ...coverage].join(" "),
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
    return { status: "failed", message: `Could not open the file dialog: ${sentence(reason)}` };
  }
  if (paths.length === 0) return { status: "cancelled" };

  const refusal = refusalFor(paths);
  if (refusal !== null) return { status: "rejected", message: refusal };

  const request = describeRequest(kind, paths);

  // loadFilesAsLogSource clears the Log filter before it parses, so an add that then fails, or
  // takes nothing, would have discarded it. Give it back unless something has set another since.
  const priorClauses = useFilterStore.getState().clauses;
  const keepFilter = () => {
    const filter = useFilterStore.getState();
    if (priorClauses.length > 0 && filter.clauses.length === 0) filter.setClauses(priorClauses);
  };

  let folderResult: LoadLogSourceResult | null = null;
  let settled: boolean;
  try {
    if (kind === "folder") {
      folderResult = await loadPathAsLogSource(paths[0], { preferFolder: true });
      settled = folderResult !== null;
    } else if (paths.length === 1) {
      settled = (await loadPathAsLogSource(paths[0], { fallbackToFolder: false })) !== null;
    } else {
      settled = await loadFilesAsLogSource(paths);
    }
  } catch (error) {
    keepFilter();
    return failed(request, classifySourceError(error).message);
  }
  // A newer load took over, and it owns the filter from here.
  if (!settled) return { status: "cancelled" };

  const log = useLogStore.getState();
  const platform = useUiStore.getState().currentPlatform;
  const keyOf = (path: string) => normalizeLogPath(path, platform);

  // A batch parse skips what it cannot read without an error, so ask the store what it loaded.
  const loaded =
    log.sourceOpenMode === "aggregate-folder"
      ? log.aggregateFiles.map((file) => ({
          path: file.filePath,
          registry: file.parserSelection?.parser === "registry",
        }))
      : log.selectedSourceFilePath
        ? [
            {
              path: log.selectedSourceFilePath,
              registry: log.parserSelection?.parser === "registry",
            },
          ]
        : [];

  const coverage =
    kind === "folder" && folderResult !== null
      ? folderCoverage(folderResult, log.bundleMetadata !== null)
      : [];

  if (loaded.length === 0) {
    keepFilter();
    return failed(
      request,
      kind === "folder" ? "no readable log file was found" : "no text log could be read",
      coverage,
    );
  }

  const loadedKeys = new Set(loaded.map((file) => keyOf(file.path)));
  const expected =
    kind === "folder"
      ? log.sourceEntries.filter((entry) => !entry.isDir).map((entry) => entry.path)
      : paths;
  const notRead = expected.filter((path) => !loadedKeys.has(keyOf(path)));

  const listedKeys = new Set(correlatedLogSources().map((source) => keyOf(source.path)));
  const unlisted = loaded.filter((file) => !listedKeys.has(keyOf(file.path)));
  const registryExports = unlisted.filter((file) => file.registry).map((file) => file.path);
  const noEntries = unlisted.filter((file) => !file.registry).map((file) => file.path);

  const parts: string[] = [];
  if (notRead.length > 0) parts.push(`Not read: ${nameFiles(notRead)}.`);
  if (registryExports.length > 0) {
    parts.push(
      `${nameFiles(registryExports)} ${plural(
        registryExports.length,
        "is a registry export",
        "are registry exports",
      )}; registry files are not correlated.`,
    );
  }
  if (noEntries.length > 0) {
    parts.push(`${nameFiles(noEntries)} ${plural(noEntries.length, "holds", "hold")} no entries.`);
  }
  parts.push(...coverage);

  if (unlisted.length === loaded.length) {
    keepFilter();
    return { status: "notAdded", message: `Not added: ${parts.join(" ")}` };
  }

  // The add took: the filter that applied to the previous log no longer describes anything.
  useFilterStore.getState().clearFilter();
  return { status: "added", notice: parts.length > 0 ? parts.join(" ") : null };
}

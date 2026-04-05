import { useCallback, useEffect, useMemo, useState, Suspense } from "react";
import {
  Badge,
  Button,
  tokens,
} from "@fluentui/react-components";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getBaseName } from "../../lib/file-paths";
import { getLogListMetrics, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { loadLogSource, loadSelectedLogFile } from "../../lib/log-source";
import { useFilterStore } from "../../stores/filter-store";
import { getWorkspace } from "../../workspaces/registry";
import {
  getActiveSourceLabel,
  getActiveSourcePath,
  getCachedTabSnapshot,
  getSourceFailureReason,
  useLogStore,
} from "../../stores/log-store";
import type { FolderEntry, LogSource } from "../../types/log";
import { useUiStore, type WorkspaceId } from "../../stores/ui-store";
import { useAppActions } from "./Toolbar";
import {
  EmptyState,
  SectionHeader,
  SidebarActionButton,
  SourceStatusNotice,
  SourceSummaryCard,
} from "../common/sidebar-primitives";

export const FILE_SIDEBAR_RECOMMENDED_WIDTH = 280;

interface FileSidebarProps {
  width?: number | string;
  activeView: WorkspaceId;
  onCollapse?: () => void;
}

function isFolderLikeSource(source: LogSource | null): boolean {
  if (!source) {
    return false;
  }

  return source.kind === "folder" || (source.kind === "known" && source.pathKind === "folder");
}

function formatCount(count: number, singular: string, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

function formatBytes(sizeBytes: number | null): string {
  if (sizeBytes === null) {
    return "Size unknown";
  }

  if (sizeBytes < 1024) {
    return `${sizeBytes} B`;
  }

  const units = ["KB", "MB", "GB", "TB"];
  let value = sizeBytes / 1024;
  let unitIndex = 0;

  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }

  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatModified(unixMs: number | null): string {
  if (!unixMs) {
    return "Modified time unavailable";
  }

  return formatDisplayDateTime(unixMs) ?? "Modified time unavailable";
}

function FileRow({
  entry,
  isSelected,
  isPending,
  disabled,
  onSelect,
}: {
  entry: FolderEntry;
  isSelected: boolean;
  isPending: boolean;
  disabled: boolean;
  onSelect: (path: string) => void;
}) {
  return (
    <button
      type="button"
      onClick={() => onSelect(entry.path)}
      disabled={disabled}
      aria-pressed={isSelected}
      title={entry.path}
      style={{
        width: "100%",
        textAlign: "left",
        padding: "8px 10px",
        border: "none",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        borderLeft: isSelected ? `3px solid ${tokens.colorCompoundBrandStroke}` : "3px solid transparent",
        backgroundColor: isSelected ? tokens.colorNeutralBackground1Selected : isPending ? tokens.colorNeutralBackground1Hover : tokens.colorNeutralBackground1,
        cursor: disabled ? "default" : "pointer",
        opacity: disabled && !isSelected ? 0.7 : 1,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
        <div
          style={{
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontSize: "inherit",
            fontWeight: isSelected ? 600 : 400,
            color: tokens.colorNeutralForeground1,
          }}
        >
          {entry.name}
        </div>
        {isSelected && (
          <Badge appearance="outline" color="brand" size="small" style={{ flexShrink: 0 }}>
            Active
          </Badge>
        )}
        {isPending && !isSelected && (
          <Badge appearance="ghost" color="informative" size="small" style={{ flexShrink: 0 }}>
            Loading...
          </Badge>
        )}
      </div>
      <div
        style={{
          marginTop: "3px",
          fontSize: "inherit",
          color: tokens.colorNeutralForeground3,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {formatBytes(entry.sizeBytes)} • {formatModified(entry.modifiedUnixMs)}
      </div>
    </button>
  );
}

export function LogSidebar() {
  const activeSource = useLogStore((s) => s.activeSource);
  const sourceEntries = useLogStore((s) => s.sourceEntries);
  const bundleMetadata = useLogStore((s) => s.bundleMetadata);
  const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);
  const aggregateFiles = useLogStore((s) => s.aggregateFiles);
  const selectedSourceFilePath = useLogStore((s) => s.selectedSourceFilePath);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const isLoading = useLogStore((s) => s.isLoading);
  const knownSources = useLogStore((s) => s.knownSources);
  const sourceStatus = useLogStore((s) => s.sourceStatus);
  const createMergedTab = useLogStore((s) => s.createMergedTab);
  const clearFilter = useFilterStore((s) => s.clearFilter);

  const [pendingPath, setPendingPath] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lastFailedPath, setLastFailedPath] = useState<string | null>(null);
  const [isRefreshingSource, setIsRefreshingSource] = useState(false);
  const [refreshErrorMessage, setRefreshErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    setPendingPath(null);
    setErrorMessage(null);
    setLastFailedPath(null);
    setIsRefreshingSource(false);
    setRefreshErrorMessage(null);
  }, [activeSource, selectedSourceFilePath, sourceOpenMode]);

  const folderLike = isFolderLikeSource(activeSource);
  const sourcePath = getActiveSourcePath(activeSource);
  const sourceLabel = useMemo(
    () => getActiveSourceLabel(activeSource, knownSources),
    [activeSource, knownSources]
  );
  const folders = useMemo(() => sourceEntries.filter((entry) => entry.isDir), [sourceEntries]);
  const files = useMemo(() => sourceEntries.filter((entry) => !entry.isDir), [sourceEntries]);
  const activeFilePath = selectedSourceFilePath ?? openFilePath;
  const activeFileName = getBaseName(activeFilePath) || "No file selected";
  const sourceFailureReason = getSourceFailureReason(sourceStatus);

  const handleSelectFile = useCallback(
    async (path: string) => {
      if (!activeSource || !folderLike || path === activeFilePath) {
        return;
      }

      setErrorMessage(null);
      setRefreshErrorMessage(null);
      setPendingPath(path);
      clearFilter();

      try {
        await loadSelectedLogFile(path, activeSource);
        setLastFailedPath(null);
      } catch (error) {
        setLastFailedPath(path);
        setErrorMessage(
          error instanceof Error ? error.message : "Failed to open the selected file."
        );
      } finally {
        setPendingPath(null);
      }
    },
    [activeSource, activeFilePath, clearFilter, folderLike]
  );

  const handleRefreshSource = useCallback(async () => {
    if (!activeSource || isLoading || isRefreshingSource || pendingPath) {
      return;
    }

    setErrorMessage(null);
    setRefreshErrorMessage(null);
    setIsRefreshingSource(true);
    clearFilter();

    try {
      await loadLogSource(activeSource, {
        selectedFilePath: activeFilePath,
      });
      setLastFailedPath(null);
    } catch (error) {
      setRefreshErrorMessage(
        error instanceof Error ? error.message : "Failed to reload source."
      );
    } finally {
      setIsRefreshingSource(false);
    }
  }, [activeFilePath, activeSource, clearFilter, isLoading, isRefreshingSource, pendingPath]);

  const canRefreshSource = Boolean(activeSource) && !isLoading && !isRefreshingSource && !pendingPath;
  const canRetryFailedSelection =
    Boolean(lastFailedPath) && folderLike && !isLoading && !isRefreshingSource && !pendingPath;

  return (
    <>
      <SourceSummaryCard
        badge={
          activeSource
            ? bundleMetadata
              ? "Evidence Bundle"
              : folderLike
                ? "Folder Source"
                : "File Source"
            : "No Source"
        }
        title={activeSource ? sourceLabel : "Open a log file or folder"}
        subtitle={sourcePath ?? "Choose a source to start viewing logs."}
        body={
          <div
            style={{
              padding: "8px 10px",
              border: `1px solid ${tokens.colorNeutralStroke2}`,
              borderRadius: "8px",
              backgroundColor: tokens.colorNeutralBackground1,
              fontSize: "inherit",
              color: tokens.colorNeutralForeground2,
              lineHeight: 1.45,
            }}
          >
            <div>{folderLike ? `${formatCount(files.length, "file")} • ${formatCount(folders.length, "folder")}` : "Single file source"}</div>
            {bundleMetadata && (
              <div style={{ marginTop: "4px" }}>
                Bundle: {bundleMetadata.bundleLabel ?? bundleMetadata.bundleId ?? "Detected"}
              </div>
            )}
            {bundleMetadata?.caseReference && (
              <div style={{ marginTop: "4px" }}>Case: {bundleMetadata.caseReference}</div>
            )}
            <div style={{ marginTop: "4px" }}>Selected: {activeFileName}</div>
            <div style={{ marginTop: "4px" }}>{sourceStatus.message}</div>
            {sourceFailureReason && (
              <div style={{ marginTop: "6px", color: tokens.colorPaletteRedForeground2 }}>Failure reason: {sourceFailureReason}</div>
            )}
          </div>
        }
      />

      {sourceStatus.kind !== "idle" && sourceStatus.kind !== "loading" && (
        <SourceStatusNotice
          kind={sourceStatus.kind}
          message={sourceStatus.message}
          detail={sourceStatus.detail}
        />
      )}

      {activeSource && folderLike && (
        <div
          style={{
            padding: "8px 10px",
            borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
            backgroundColor: tokens.colorNeutralBackground2,
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <SidebarActionButton
            label={isRefreshingSource ? "Reloading..." : "Reload source"}
            disabled={!canRefreshSource}
            onClick={handleRefreshSource}
          />
          {canRetryFailedSelection && lastFailedPath && (
            <SidebarActionButton
              label={`Retry ${getBaseName(lastFailedPath)}`}
              disabled={!canRetryFailedSelection}
              onClick={() => {
                void handleSelectFile(lastFailedPath);
              }}
            />
          )}
        </div>
      )}

      {refreshErrorMessage && (
        <div role="alert" style={{ padding: "9px 12px", borderBottom: `1px solid ${tokens.colorPaletteRedBorder2}`, backgroundColor: tokens.colorPaletteRedBackground1, color: tokens.colorPaletteRedForeground2, fontSize: "inherit" }}>
          {refreshErrorMessage}
        </div>
      )}
      {errorMessage && (
        <div role="alert" style={{ padding: "9px 12px", borderBottom: `1px solid ${tokens.colorPaletteRedBorder2}`, backgroundColor: tokens.colorPaletteRedBackground1, color: tokens.colorPaletteRedForeground2, fontSize: "inherit" }}>
          {errorMessage}
        </div>
      )}

      <div style={{ flex: 1, overflow: "auto", backgroundColor: tokens.colorNeutralBackground2 }}>
        {!activeSource && (
          <EmptyState
            title="No file source open"
            body="Open a file for the classic single-log workflow, or open a folder to browse sibling files here."
          />
        )}

        {activeSource && !folderLike && (
          <>
            <SectionHeader title="Current file" caption="Classic single-file workflow" />
            <EmptyState
              title={activeFileName}
              body={sourcePath ?? "Use Open to choose a log file."}
            />
          </>
        )}

        {activeSource && folderLike && sourceEntries.length === 0 && isLoading && (
          <EmptyState title="Loading files" body="Reading the selected folder and preparing the file list." />
        )}

        {activeSource && folderLike && sourceEntries.length === 0 && !isLoading && (
          <EmptyState
            title={sourceStatus.kind === "missing" || sourceStatus.kind === "error" ? "Source path unavailable" : "This folder is empty"}
            body={sourceStatus.detail ?? "No files were found in the selected folder."}
          />
        )}

        {activeSource && folderLike && sourceEntries.length > 0 && (
          <>
            {folders.length > 0 && (
              <>
                <SectionHeader title={`Folders (${folders.length})`} caption="Shown for context." />
                {folders.map((entry) => (
                  <div key={entry.path} style={{ padding: "7px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, fontSize: "inherit", color: tokens.colorNeutralForeground2 }}>
                    {entry.name}
                  </div>
                ))}
              </>
            )}
            <SectionHeader
              title={`Files (${files.length})`}
              caption={
                sourceOpenMode === "aggregate-folder"
                  ? "Folder is loaded as a merged aggregate view. Select a file to replace it with a single-file view."
                  : activeFilePath
                    ? "Select a file to replace the active log view."
                    : "Select a file to begin viewing log entries."
              }
            />
            {files.length >= 2 && (
              <div style={{ padding: "8px 10px 0" }}>
                <button
                  type="button"
                  onClick={() => {
                    const filePaths = files
                      .filter((e) => !e.isDir && getCachedTabSnapshot(e.path))
                      .map((e) => e.path);
                    if (filePaths.length >= 2) createMergedTab(filePaths);
                  }}
                  style={{
                    width: "100%",
                    padding: "6px 8px",
                    marginBottom: "8px",
                    fontSize: "11px",
                    border: `1px solid ${tokens.colorNeutralStroke2}`,
                    borderRadius: "4px",
                    backgroundColor: tokens.colorNeutralBackground1,
                    color: tokens.colorNeutralForeground1,
                    cursor: "pointer",
                    fontWeight: 500,
                  }}
                >
                  Merge into Timeline
                </button>
              </div>
            )}
            {files.length === 0 ? (
              <EmptyState title="No files available" body="This source only returned folders." />
            ) : (
              files.map((entry) => (
                <FileRow
                  key={entry.path}
                  entry={entry}
                  isSelected={entry.path === activeFilePath}
                  isPending={entry.path === pendingPath}
                  disabled={Boolean(pendingPath)}
                  onSelect={handleSelectFile}
                />
              ))
            )}
          </>
        )}
      </div>

      {activeSource && folderLike && !activeFilePath && !isLoading && (
        <div style={{ padding: "8px 10px", borderTop: `1px solid ${tokens.colorNeutralStroke2}`, backgroundColor: tokens.colorNeutralBackground2, fontSize: "inherit", color: tokens.colorNeutralForeground2 }}>
          {sourceOpenMode === "aggregate-folder"
            ? `Merged folder view active across ${aggregateFiles.length} file${aggregateFiles.length === 1 ? "" : "s"}.`
            : sourceStatus.kind === "awaiting-file-selection"
            ? sourceStatus.message
            : "Select a file to populate the main log list."}
        </div>
      )}
    </>
  );
}

function SidebarFooter() {
  const isPaused = useLogStore((s) => s.isPaused);
  const isLoading = useLogStore((s) => s.isLoading);
  const activeSource = useLogStore((s) => s.activeSource);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const { commandState, togglePauseResume, refreshActiveSource } = useAppActions();

  const hasActiveSource = activeSource !== null || openFilePath !== null;

  const statusLabel = isLoading ? "Loading" : isPaused ? "Paused" : "Streaming";
  const statusBg = isLoading
    ? tokens.colorPaletteBlueBackground2
    : isPaused
      ? tokens.colorPaletteYellowBackground1
      : tokens.colorPaletteGreenBackground1;
  const statusFg = isLoading
    ? tokens.colorPaletteBlueForeground2
    : isPaused
      ? tokens.colorPaletteMarigoldForeground2
      : tokens.colorPaletteGreenForeground1;

  return (
    <div
      style={{
        marginTop: "auto",
        padding: "6px 8px",
        borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
        display: "flex",
        gap: "5px",
        alignItems: "center",
        flexShrink: 0,
      }}
    >
      <Button
        size="small"
        appearance="subtle"
        disabled={!commandState.canPauseResume}
        onClick={togglePauseResume}
        style={{ fontSize: "10px", padding: "3px 8px", minWidth: 0 }}
      >
        {isPaused ? "Resume" : "Pause"}
      </Button>
      <Button
        size="small"
        appearance="subtle"
        disabled={!commandState.canRefresh}
        onClick={() => { refreshActiveSource().catch((err) => console.error("[sidebar-footer] refresh failed", err)); }}
        style={{ fontSize: "10px", padding: "3px 8px", minWidth: 0 }}
      >
        Refresh
      </Button>
      {hasActiveSource && (
        <span
          style={{
            marginLeft: "auto",
            fontSize: "9px",
            padding: "2px 6px",
            borderRadius: "10px",
            backgroundColor: statusBg,
            color: statusFg,
            fontWeight: 600,
            flexShrink: 0,
          }}
        >
          {statusLabel}
        </span>
      )}
    </div>
  );
}

export function FileSidebar({ width = FILE_SIDEBAR_RECOMMENDED_WIDTH, activeView, onCollapse }: FileSidebarProps) {
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);

  return (
    <aside
      aria-label="Source files"
      style={{
        width,
        minWidth: typeof width === "number" ? `${width}px` : width,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        backgroundColor: tokens.colorNeutralBackground2,
        borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
        fontSize: `${metrics.fontSize}px`,
        lineHeight: `${metrics.rowLineHeight}px`,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      {/* Collapse button */}
      {onCollapse && (
        <div style={{ display: "flex", justifyContent: "flex-end", padding: "4px 4px 0" }}>
          <button
            onClick={onCollapse}
            title="Collapse sidebar (Ctrl+B)"
            aria-label="Collapse sidebar"
            style={{
              background: "none",
              border: "none",
              cursor: "pointer",
              padding: 4,
              borderRadius: 4,
              color: tokens.colorNeutralForeground3,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
              <path d="M10 3L5 8l5 5V3z" />
            </svg>
          </button>
        </div>
      )}
      {(() => {
        const workspace = getWorkspace(activeView);
        const SidebarComponent = workspace.sidebar;
        return SidebarComponent ? (
          <Suspense fallback={null}>
            <SidebarComponent />
          </Suspense>
        ) : (
          <LogSidebar />
        );
      })()}
      {getWorkspace(activeView).capabilities?.footerBar && <SidebarFooter />}
    </aside>
  );
}

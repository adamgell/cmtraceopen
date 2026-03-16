import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Badge,
  Button,
  Caption1,
  Subtitle2,
} from "@fluentui/react-components";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getLogListMetrics, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { loadLogSource, loadSelectedLogFile } from "../../lib/log-source";
import { useFilterStore } from "../../stores/filter-store";
import { useIntuneStore } from "../../stores/intune-store";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import {
  getActiveSourceLabel,
  getActiveSourcePath,
  getBaseName,
  getSourceFailureReason,
  useLogStore,
} from "../../stores/log-store";
import type { FolderEntry, LogSource } from "../../types/log";
import { isIntuneWorkspace, useUiStore, type WorkspaceId } from "../../stores/ui-store";
import { useAppActions } from "./Toolbar";

export const FILE_SIDEBAR_RECOMMENDED_WIDTH = 280;

interface FileSidebarProps {
  width?: number | string;
  activeView: WorkspaceId;
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

function SectionHeader({ title, caption }: { title: string; caption?: string }) {
  return (
    <div
      style={{
        padding: "10px 12px 8px",
        borderBottom: "1px solid #e2e8f0",
        backgroundColor: "#f8fafc",
      }}
    >
      <Caption1
        style={{
          fontWeight: 600,
          color: "#526071",
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {title}
      </Caption1>
      {caption && (
        <Caption1
          style={{
            display: "block",
            marginTop: "2px",
            color: "#6b7280",
          }}
        >
          {caption}
        </Caption1>
      )}
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div
      style={{
        padding: "18px 14px",
        color: "#6b7280",
        fontSize: "inherit",
        lineHeight: 1.5,
      }}
    >
      <Subtitle2 style={{ color: "#1f2937", marginBottom: "4px" }}>{title}</Subtitle2>
      <div>{body}</div>
    </div>
  );
}

function SidebarActionButton({
  label,
  disabled,
  onClick,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      disabled={disabled}
      onClick={onClick}
      size="small"
      appearance="secondary"
      style={{
        justifyContent: "flex-start",
        minWidth: 0,
        flex: 1,
      }}
    >
      {label}
    </Button>
  );
}

function SourceStatusNotice({
  kind,
  message,
  detail,
}: {
  kind: string;
  message: string;
  detail?: string;
}) {
  const colors =
    kind === "missing" || kind === "error"
      ? { border: "#fecaca", background: "#fef2f2", text: "#991b1b" }
      : kind === "empty" || kind === "awaiting-file-selection"
        ? { border: "#fde68a", background: "#fffbeb", text: "#92400e" }
        : { border: "#bfdbfe", background: "#eff6ff", text: "#1e40af" };

  return (
    <div
      role="status"
      style={{
        padding: "9px 12px",
        borderBottom: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        color: colors.text,
        fontSize: "inherit",
        lineHeight: 1.4,
      }}
    >
      <div style={{ fontWeight: 600 }}>{message}</div>
      {detail && <div style={{ marginTop: "2px", opacity: 0.9 }}>{detail}</div>}
    </div>
  );
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
        borderBottom: "1px solid #edf2f7",
        borderLeft: isSelected ? "3px solid #3b82f6" : "3px solid transparent",
        backgroundColor: isSelected ? "#dbeafe" : isPending ? "#eff6ff" : "#ffffff",
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
            color: "#111827",
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
          color: "#6b7280",
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

function SourceSummaryCard({
  badge,
  title,
  subtitle,
  body,
}: {
  badge: string;
  title: string;
  subtitle: string;
  body: ReactNode;
}) {
  return (
    <div
      style={{
        padding: "12px",
        borderBottom: "1px solid #d8e1ec",
        backgroundColor: "#f7fafc",
      }}
    >
      <Badge
        appearance="outline"
        color="brand"
        style={{
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {badge}
      </Badge>
      <Subtitle2
        title={title}
        style={{
          display: "block",
          marginTop: "8px",
          color: "#111827",
          fontSize: "inherit",
          fontWeight: 600,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {title}
      </Subtitle2>
      <Caption1
        title={subtitle}
        style={{
          display: "block",
          marginTop: "4px",
          color: "#6b7280",
          fontSize: "0.85em",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {subtitle}
      </Caption1>
      <div style={{ marginTop: "10px" }}>{body}</div>
    </div>
  );
}

function LogSidebar() {
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
              border: "1px solid #d8e1ec",
              borderRadius: "8px",
              backgroundColor: "#ffffff",
              fontSize: "inherit",
              color: "#374151",
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
              <div style={{ marginTop: "6px", color: "#991b1b" }}>Failure reason: {sourceFailureReason}</div>
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
            borderBottom: "1px solid #e2e8f0",
            backgroundColor: "#f8fafc",
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
        <div role="alert" style={{ padding: "9px 12px", borderBottom: "1px solid #fecaca", backgroundColor: "#fef2f2", color: "#991b1b", fontSize: "inherit" }}>
          {refreshErrorMessage}
        </div>
      )}
      {errorMessage && (
        <div role="alert" style={{ padding: "9px 12px", borderBottom: "1px solid #fecaca", backgroundColor: "#fef2f2", color: "#991b1b", fontSize: "inherit" }}>
          {errorMessage}
        </div>
      )}

      <div style={{ flex: 1, overflow: "auto" }}>
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
                  <div key={entry.path} style={{ padding: "7px 10px", borderBottom: "1px solid #f1f5f9", fontSize: "inherit", color: "#4b5563" }}>
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
        <div style={{ padding: "8px 10px", borderTop: "1px solid #c0c0c0", backgroundColor: "#fafafa", fontSize: "inherit", color: "#4b5563" }}>
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

function IntuneSidebar() {
  const activeView = useUiStore((s) => s.activeView);
  const intuneAnalysisState = useIntuneStore((s) => s.analysisState);
  const intuneIsAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const intuneSummary = useIntuneStore((s) => s.summary);
  const eventLogAnalysis = useIntuneStore((s) => s.eventLogAnalysis);
  const intuneEvidenceBundle = useIntuneStore((s) => s.evidenceBundle);
  const intuneSourceContext = useIntuneStore((s) => s.sourceContext);
  const intuneTimelineScope = useIntuneStore((s) => s.timelineScope);
  const setIntuneTimelineFileScope = useIntuneStore((s) => s.setTimelineFileScope);

  const intuneIncludedFiles = intuneSourceContext.includedFiles;
  const intuneSelectedFilePath = intuneTimelineScope.filePath;
  const intuneRequestedPath = intuneAnalysisState.requestedPath;
  const hasIntuneResults = intuneSummary != null || intuneIncludedFiles.length > 0;
  const workspaceTitle = activeView === "new-intune" ? "New Intune Workspace" : "Intune diagnostics workspace";
  const workspaceBadge = activeView === "new-intune" ? "New Intune" : intuneEvidenceBundle ? "Intune Bundle" : "Intune";

  return (
    <>
      <SourceSummaryCard
        badge={workspaceBadge}
        title={getBaseName(intuneRequestedPath) || workspaceTitle}
        subtitle={intuneRequestedPath ?? "Select an IME log source to begin analysis."}
        body={
          <div style={{ fontSize: "inherit", color: "#374151", lineHeight: 1.45 }}>
            <div>{intuneAnalysisState.message}</div>
            <div style={{ marginTop: "4px" }}>Included files: {intuneIncludedFiles.length}</div>
            {intuneEvidenceBundle && (
              <div style={{ marginTop: "4px" }}>
                Bundle: {intuneEvidenceBundle.bundleLabel ?? intuneEvidenceBundle.bundleId ?? "Detected"}
              </div>
            )}
            {intuneSummary && <div style={{ marginTop: "4px" }}>Events: {intuneSummary.totalEvents}</div>}
            {eventLogAnalysis && (
              <div style={{ marginTop: "4px" }}>
                Event logs: {eventLogAnalysis.totalEntryCount} entries
                {eventLogAnalysis.sourceKind === "Live" && eventLogAnalysis.liveQuery
                  ? ` across ${eventLogAnalysis.liveQuery.channelsWithResultsCount}/${eventLogAnalysis.liveQuery.attemptedChannelCount} queried channels`
                  : ` across ${eventLogAnalysis.parsedFileCount} channel(s)`}
              </div>
            )}
          </div>
        }
      />

      {(intuneAnalysisState.phase === "analyzing" ||
        intuneAnalysisState.phase === "error" ||
        intuneAnalysisState.phase === "empty") && (
        <SourceStatusNotice
          kind={
            intuneAnalysisState.phase === "error"
              ? "error"
              : intuneAnalysisState.phase === "empty"
                ? "empty"
                : "info"
          }
          message={intuneAnalysisState.message}
          detail={intuneAnalysisState.detail ?? undefined}
        />
      )}

      <div style={{ flex: 1, overflow: "auto" }}>
        {!hasIntuneResults && !intuneIsAnalyzing && intuneAnalysisState.phase !== "error" && (
          <EmptyState
            title="No Intune diagnostics data"
            body="Select an Intune Management Extension (IME) log source to begin analysis."
          />
        )}

        {intuneIsAnalyzing && (
          <EmptyState
            title="Analyzing Intune logs"
            body="Scanning source files for events, downloads, and metrics..."
          />
        )}

        {!hasIntuneResults && intuneAnalysisState.phase === "error" && (
          <EmptyState
            title="Intune diagnostics failed"
            body={intuneAnalysisState.detail ?? "The selected Intune source could not be analyzed."}
          />
        )}

        {intuneSummary && (
          <>
            <SectionHeader title="Diagnostics Summary" caption="Overview of the current Intune diagnostics data" />
            <div style={{
              padding: "10px",
              borderBottom: "1px solid #eef2f7",
              fontSize: "inherit",
              color: "#374151",
              display: "grid",
              gridTemplateColumns: "auto 1fr",
              gap: "4px 10px",
              alignItems: "baseline",
            }}>
              <span style={{ fontWeight: 600, color: "#6b7280" }}>Events</span>
              <span>{intuneSummary.totalEvents.toLocaleString()}</span>
              <span style={{ fontWeight: 600, color: "#6b7280" }}>Downloads</span>
              <span>{intuneSummary.totalDownloads}</span>
              {eventLogAnalysis && (
                <>
                  <span style={{ fontWeight: 600, color: "#6b7280" }}>Event logs</span>
                  <span>{eventLogAnalysis.totalEntryCount.toLocaleString()} entries</span>
                  <span style={{ fontWeight: 600, color: "#6b7280" }}>Severity</span>
                  <span>{eventLogAnalysis.errorEntryCount} errors, {eventLogAnalysis.warningEntryCount} warnings</span>
                </>
              )}
              {eventLogAnalysis?.sourceKind === "Live" && eventLogAnalysis.liveQuery && (
                <>
                  <span style={{ fontWeight: 600, color: "#6b7280" }}>Live query</span>
                  <span>{eventLogAnalysis.liveQuery.successfulChannelCount} ok, {eventLogAnalysis.liveQuery.failedChannelCount} failed</span>
                </>
              )}
              {intuneSummary.logTimeSpan && (
                <>
                  <span style={{ fontWeight: 600, color: "#6b7280" }}>Time span</span>
                  <span>{intuneSummary.logTimeSpan}</span>
                </>
              )}
            </div>
          </>
        )}

        {intuneIncludedFiles.length > 0 && (
          <>
            <SectionHeader
              title={`Included Files (${intuneIncludedFiles.length})`}
              caption={intuneSelectedFilePath
                ? "Timeline is scoped — click the active file to clear scope"
                : "Click a file to scope the timeline to that log only"}
            />
            {intuneIncludedFiles.map((path) => {
              const isSelected = intuneSelectedFilePath === path;
              return (
                <button
                  key={path}
                  type="button"
                  onClick={() => setIntuneTimelineFileScope(isSelected ? null : path)}
                  aria-pressed={isSelected}
                  title={path}
                  style={{
                    width: "100%",
                    textAlign: "left",
                    padding: isSelected ? "10px 10px 10px 9px" : "7px 10px 7px 9px",
                    border: "none",
                    borderLeft: isSelected ? "4px solid #3b82f6" : "4px solid transparent",
                    borderBottom: "1px solid #edf2f7",
                    fontSize: "inherit",
                    color: isSelected ? "#1e3a8a" : "#374151",
                    backgroundColor: isSelected ? "#dbeafe" : "#ffffff",
                    cursor: "pointer",
                    transition: "background-color 100ms ease",
                  }}
                >
                  <div style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                  }}>
                    <div style={{
                      flex: 1,
                      minWidth: 0,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      fontWeight: isSelected ? 700 : 400,
                    }}>
                      {getBaseName(path)}
                    </div>
                    {isSelected && (
                      <Badge appearance="filled" color="brand" size="small" style={{ flexShrink: 0 }}>
                        Scoped
                      </Badge>
                    )}
                  </div>
                  {isSelected && (
                    <div style={{
                      marginTop: "4px",
                      fontSize: "0.85em",
                      color: "#2563eb",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}>
                      {path}
                    </div>
                  )}
                </button>
              );
            })}
          </>
        )}
      </div>
    </>
  );
}

function DsregcmdSidebar() {
  const result = useDsregcmdStore((s) => s.result);
  const sourceContext = useDsregcmdStore((s) => s.sourceContext);
  const analysisState = useDsregcmdStore((s) => s.analysisState);
  const isAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const { openSourceFileDialog, openSourceFolderDialog, pasteDsregcmdSource, captureDsregcmdSource } = useAppActions();

  const diagnostics = result?.diagnostics ?? [];
  const errorCount = diagnostics.filter((item) => item.severity === "Error").length;
  const warningCount = diagnostics.filter((item) => item.severity === "Warning").length;
  const infoCount = diagnostics.filter((item) => item.severity === "Info").length;

  return (
    <>
      <SourceSummaryCard
        badge="dsregcmd"
        title={sourceContext.displayLabel}
        subtitle={sourceContext.resolvedPath ?? sourceContext.requestedPath ?? "Open a dsregcmd source to begin."}
        body={
          <div style={{ fontSize: "inherit", color: "#374151", lineHeight: 1.5 }}>
            <div>{analysisState.message}</div>
            <div style={{ marginTop: "4px" }}>Lines: {sourceContext.rawLineCount}</div>
            <div style={{ marginTop: "4px" }}>Chars: {sourceContext.rawCharCount}</div>
            {result && <div style={{ marginTop: "4px" }}>Join type: {result.derived.joinTypeLabel}</div>}
          </div>
        }
      />

      {(analysisState.phase === "analyzing" || analysisState.phase === "error") && (
        <SourceStatusNotice
          kind={analysisState.phase === "error" ? "error" : "info"}
          message={analysisState.message}
          detail={analysisState.detail ?? undefined}
        />
      )}

      <div style={{ padding: "8px 10px", borderBottom: "1px solid #e5e7eb", backgroundColor: "#f8fafc", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
        <SidebarActionButton label="Capture" disabled={isAnalyzing} onClick={() => void captureDsregcmdSource()} />
        <SidebarActionButton label="Paste" disabled={isAnalyzing} onClick={() => void pasteDsregcmdSource()} />
        <SidebarActionButton label="Open file" disabled={isAnalyzing} onClick={() => void openSourceFileDialog()} />
        <SidebarActionButton label="Open folder" disabled={isAnalyzing} onClick={() => void openSourceFolderDialog()} />
      </div>

      <div style={{ flex: 1, overflow: "auto" }}>
        {!result && !isAnalyzing && analysisState.phase !== "error" && (
          <EmptyState
            title="No dsregcmd analysis yet"
            body="Capture live output with registry evidence, paste clipboard text, open a text file, or select a bundle root, evidence folder, or command-output folder."
          />
        )}

        {result && (
          <>
            <SectionHeader title="Triage Summary" caption="Fast sidebar readout of the current dsregcmd result" />
            <div style={{ padding: "12px 10px", borderBottom: "1px solid #eef2f7", fontSize: "inherit", color: "#374151", lineHeight: 1.5 }}>
              <div><strong>Join type:</strong> {result.derived.joinTypeLabel}</div>
              <div style={{ marginTop: "6px" }}><strong>PRT present:</strong> {result.derived.azureAdPrtPresent === null ? 'Unknown' : result.derived.azureAdPrtPresent ? 'Yes' : 'No'}</div>
              <div style={{ marginTop: "6px" }}><strong>MDM enrolled:</strong> {result.derived.mdmEnrolled === null ? 'Unknown' : result.derived.mdmEnrolled ? 'Yes' : 'No'}</div>
              <div style={{ marginTop: "6px" }}><strong>Issues:</strong> {errorCount} errors • {warningCount} warnings • {infoCount} info</div>
              {sourceContext.evidenceFilePath && (
                <div style={{ marginTop: "6px", wordBreak: "break-word" }}><strong>Evidence file:</strong> {sourceContext.evidenceFilePath}</div>
              )}
              {sourceContext.bundlePath && (
                <div style={{ marginTop: "6px", wordBreak: "break-word" }}><strong>Bundle root:</strong> {sourceContext.bundlePath}</div>
              )}
            </div>

            <SectionHeader title="Top Findings" caption="Highest-priority diagnostics first" />
            {diagnostics.length === 0 ? (
              <EmptyState title="No diagnostics" body="The backend parser did not emit diagnostic findings for this capture." />
            ) : (
              diagnostics.slice(0, 8).map((item) => (
                <div key={item.id} style={{ padding: "8px 10px", borderBottom: "1px solid #eef2f7", backgroundColor: item.severity === 'Error' ? '#fef2f2' : item.severity === 'Warning' ? '#fffbeb' : '#eff6ff' }}>
                  <div style={{ fontSize: "inherit", textTransform: "uppercase", fontWeight: 700, color: item.severity === 'Error' ? '#991b1b' : item.severity === 'Warning' ? '#92400e' : '#1e40af' }}>{item.severity}</div>
                  <div style={{ marginTop: "4px", fontSize: "inherit", fontWeight: 600, color: "#111827" }}>{item.title}</div>
                  <div style={{ marginTop: "3px", fontSize: "inherit", color: "#4b5563", lineHeight: 1.45 }}>{item.summary}</div>
                </div>
              ))
            )}
          </>
        )}
      </div>
    </>
  );
}

export function FileSidebar({ width = FILE_SIDEBAR_RECOMMENDED_WIDTH, activeView }: FileSidebarProps) {
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
        backgroundColor: "#fbfdff",
        borderRight: "1px solid #d8e1ec",
        fontSize: `${metrics.fontSize}px`,
        lineHeight: `${metrics.rowLineHeight}px`,
        fontFamily: LOG_UI_FONT_FAMILY,
      }}
    >
      {activeView === "log" ? <LogSidebar /> : isIntuneWorkspace(activeView) ? <IntuneSidebar /> : <DsregcmdSidebar />}
    </aside>
  );
}

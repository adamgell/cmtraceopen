import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Badge,
  Button,
  Caption1,
  Subtitle2,
  tokens,
} from "@fluentui/react-components";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { getLogListMetrics, LOG_UI_FONT_FAMILY } from "../../lib/log-accessibility";
import { loadLogSource, loadSelectedLogFile } from "../../lib/log-source";
import { useFilterStore } from "../../stores/filter-store";
import { useIntuneStore } from "../../stores/intune-store";
import { useDsregcmdStore } from "../../stores/dsregcmd-store";
import { useSysmonStore } from "../../stores/sysmon-store";
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

function SectionHeader({ title, caption }: { title: string; caption?: string }) {
  return (
    <div
      style={{
        padding: "10px 12px 8px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <Caption1
        style={{
          fontWeight: 600,
          color: tokens.colorNeutralForeground3,
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
            color: tokens.colorNeutralForeground3,
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
        color: tokens.colorNeutralForeground3,
        fontSize: "inherit",
        lineHeight: 1.5,
      }}
    >
      <Subtitle2 style={{ color: tokens.colorNeutralForeground1, marginBottom: "4px" }}>{title}</Subtitle2>
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
      ? { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, text: tokens.colorPaletteRedForeground2 }
      : kind === "empty" || kind === "awaiting-file-selection"
        ? { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, text: tokens.colorPaletteMarigoldForeground2 }
        : { border: tokens.colorPaletteBlueBorderActive, background: tokens.colorPaletteBlueBackground2, text: tokens.colorPaletteBlueForeground2 };

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
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
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
          color: tokens.colorNeutralForeground1,
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
          color: tokens.colorNeutralForeground3,
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
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.45 }}>
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

      <div style={{ flex: 1, overflow: "auto", backgroundColor: tokens.colorNeutralBackground2 }}>
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
              borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
              fontSize: "inherit",
              color: tokens.colorNeutralForeground2,
              display: "grid",
              gridTemplateColumns: "auto 1fr",
              gap: "4px 10px",
              alignItems: "baseline",
            }}>
              <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Events</span>
              <span>{intuneSummary.totalEvents.toLocaleString()}</span>
              <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Downloads</span>
              <span>{intuneSummary.totalDownloads}</span>
              {eventLogAnalysis && (
                <>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Event logs</span>
                  <span>{eventLogAnalysis.totalEntryCount.toLocaleString()} entries</span>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Severity</span>
                  <span>{eventLogAnalysis.errorEntryCount} errors, {eventLogAnalysis.warningEntryCount} warnings</span>
                </>
              )}
              {eventLogAnalysis?.sourceKind === "Live" && eventLogAnalysis.liveQuery && (
                <>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Live query</span>
                  <span>{eventLogAnalysis.liveQuery.successfulChannelCount} ok, {eventLogAnalysis.liveQuery.failedChannelCount} failed</span>
                </>
              )}
              {intuneSummary.logTimeSpan && (
                <>
                  <span style={{ fontWeight: 600, color: tokens.colorNeutralForeground3 }}>Time span</span>
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
                    borderLeft: isSelected ? `4px solid ${tokens.colorCompoundBrandStroke}` : "4px solid transparent",
                    borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    fontSize: "inherit",
                    color: isSelected ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground2,
                    backgroundColor: isSelected ? tokens.colorNeutralBackground1Selected : tokens.colorNeutralBackground1,
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
                      color: tokens.colorBrandForeground1,
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

function SysmonSidebar() {
  const summary = useSysmonStore((s) => s.summary);
  const sourcePath = useSysmonStore((s) => s.sourcePath);
  const isAnalyzing = useSysmonStore((s) => s.isAnalyzing);
  const analysisError = useSysmonStore((s) => s.analysisError);
  const progressMessage = useSysmonStore((s) => s.progressMessage);

  const title = sourcePath ? getBaseName(sourcePath) : "Sysmon";
  const subtitle = sourcePath ?? "Open a folder containing Sysmon EVTX files to begin.";

  return (
    <>
      <SourceSummaryCard
        badge="sysmon"
        title={title}
        subtitle={subtitle}
        body={
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
            {isAnalyzing && <div>{progressMessage ?? "Analyzing..."}</div>}
            {analysisError && <div style={{ color: tokens.colorPaletteRedForeground2 }}>{analysisError}</div>}
            {summary && (
              <>
                <div>Events: {summary.totalEvents.toLocaleString()}</div>
                <div>Processes: {summary.uniqueProcesses.toLocaleString()}</div>
                <div>Files: {summary.sourceFiles.length}</div>
                {summary.parseErrors > 0 && (
                  <div style={{ color: tokens.colorPaletteRedForeground2 }}>
                    Parse errors: {summary.parseErrors}
                  </div>
                )}
              </>
            )}
            {!isAnalyzing && !analysisError && !summary && <div>Ready</div>}
          </div>
        }
      />
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
          <div style={{ fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
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

      <div style={{ padding: "8px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, backgroundColor: tokens.colorNeutralBackground2, display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
        <SidebarActionButton label="Capture" disabled={isAnalyzing} onClick={() => void captureDsregcmdSource().catch((err) => console.error("[dsregcmd-sidebar] capture failed", err))} />
        <SidebarActionButton label="Paste" disabled={isAnalyzing} onClick={() => void pasteDsregcmdSource().catch((err) => console.error("[dsregcmd-sidebar] paste failed", err))} />
        <SidebarActionButton label="Open file" disabled={isAnalyzing} onClick={() => void openSourceFileDialog().catch((err) => console.error("[dsregcmd-sidebar] open file failed", err))} />
        <SidebarActionButton label="Open folder" disabled={isAnalyzing} onClick={() => void openSourceFolderDialog().catch((err) => console.error("[dsregcmd-sidebar] open folder failed", err))} />
      </div>

      <div style={{ flex: 1, overflow: "auto", backgroundColor: tokens.colorNeutralBackground2 }}>
        {!result && !isAnalyzing && analysisState.phase !== "error" && (
          <EmptyState
            title="No dsregcmd analysis yet"
            body="Capture live output with registry evidence, paste clipboard text, open a text file, or select a bundle root, evidence folder, or command-output folder."
          />
        )}

        {result && (
          <>
            <SectionHeader title="Triage Summary" caption="Fast sidebar readout of the current dsregcmd result" />
            <div style={{ padding: "12px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.5 }}>
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
                <div key={item.id} style={{ padding: "8px 10px", borderBottom: `1px solid ${tokens.colorNeutralStroke2}`, backgroundColor: item.severity === 'Error' ? tokens.colorPaletteRedBackground1 : item.severity === 'Warning' ? tokens.colorPaletteYellowBackground1 : tokens.colorPaletteBlueBackground2 }}>
                  <div style={{ fontSize: "inherit", textTransform: "uppercase", fontWeight: 700, color: item.severity === 'Error' ? tokens.colorPaletteRedForeground2 : item.severity === 'Warning' ? tokens.colorPaletteMarigoldForeground2 : tokens.colorPaletteBlueForeground2 }}>{item.severity}</div>
                  <div style={{ marginTop: "4px", fontSize: "inherit", fontWeight: 600, color: tokens.colorNeutralForeground1 }}>{item.title}</div>
                  <div style={{ marginTop: "3px", fontSize: "inherit", color: tokens.colorNeutralForeground2, lineHeight: 1.45 }}>{item.summary}</div>
                </div>
              ))
            )}
          </>
        )}
      </div>
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
      {activeView === "log" || activeView === "deployment" || activeView === "macos-diag"
        ? <LogSidebar />
        : isIntuneWorkspace(activeView)
          ? <IntuneSidebar />
          : activeView === "sysmon"
            ? <SysmonSidebar />
            : <DsregcmdSidebar />}
      {(activeView === "log" || activeView === "deployment") && <SidebarFooter />}
    </aside>
  );
}

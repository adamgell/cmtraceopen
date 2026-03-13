import { useCallback, useEffect, useMemo, useState } from "react";
import { loadLogSource, loadSelectedLogFile } from "../../lib/log-source";
import { useFilterStore } from "../../stores/filter-store";
import { useIntuneStore } from "../../stores/intune-store";
import {
  getActiveSourceLabel,
  getActiveSourcePath,
  getBaseName,
  getSourceFailureReason,
  useLogStore,
} from "../../stores/log-store";
import type { FolderEntry, LogSource } from "../../types/log";

export const FILE_SIDEBAR_RECOMMENDED_WIDTH = 280;

interface FileSidebarProps {
  width?: number | string;
  activeView: "log" | "intune";
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

  try {
    return new Intl.DateTimeFormat(undefined, {
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
    }).format(new Date(unixMs));
  } catch {
    return "Modified time unavailable";
  }
}

function getSourcePresentation(
  source: LogSource | null,
  knownSourceLabel: string | null
): { badge: string; title: string; subtitle: string } {
  if (!source) {
    return {
      badge: "No source",
      title: "Open a log file or folder",
      subtitle: "Choose a source to start viewing logs.",
    };
  }

  if (source.kind === "file") {
    return { badge: "File", title: getBaseName(source.path), subtitle: source.path };
  }

  if (source.kind === "folder") {
    return { badge: "Folder", title: getBaseName(source.path), subtitle: source.path };
  }

  return {
    badge: source.pathKind === "folder" ? "Known folder" : "Known file",
    title: knownSourceLabel ?? source.sourceId,
    subtitle: source.defaultPath,
  };
}

function SectionHeader({ title, caption }: { title: string; caption?: string }) {
  return (
    <div
      style={{
        padding: "8px 10px 6px",
        borderBottom: "1px solid #e5e7eb",
        backgroundColor: "#fafafa",
      }}
    >
      <div
        style={{
          fontSize: "11px",
          fontWeight: 600,
          color: "#4b5563",
          textTransform: "uppercase",
          letterSpacing: "0.04em",
          fontFamily: "'Segoe UI', Tahoma, sans-serif",
        }}
      >
        {title}
      </div>
      {caption && (
        <div
          style={{
            marginTop: "2px",
            fontSize: "11px",
            color: "#6b7280",
            fontFamily: "'Segoe UI', Tahoma, sans-serif",
          }}
        >
          {caption}
        </div>
      )}
    </div>
  );
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div
      style={{
        padding: "16px 12px",
        color: "#6b7280",
        fontSize: "12px",
        lineHeight: 1.5,
        fontFamily: "'Segoe UI', Tahoma, sans-serif",
      }}
    >
      <div style={{ fontWeight: 600, color: "#374151", marginBottom: "4px" }}>{title}</div>
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
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      style={{
        padding: "5px 8px",
        border: "1px solid #d1d5db",
        backgroundColor: disabled ? "#f3f4f6" : "#ffffff",
        color: disabled ? "#9ca3af" : "#1f2937",
        cursor: disabled ? "default" : "pointer",
        fontSize: "11px",
        borderRadius: "2px",
        fontFamily: "'Segoe UI', Tahoma, sans-serif",
      }}
    >
      {label}
    </button>
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
        padding: "8px 10px",
        borderBottom: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        color: colors.text,
        fontSize: "12px",
        lineHeight: 1.4,
        fontFamily: "'Segoe UI', Tahoma, sans-serif",
      }}
    >
      <div style={{ fontWeight: 600 }}>{message}</div>
      {detail && <div style={{ marginTop: "2px", opacity: 0.9 }}>{detail}</div>}
    </div>
  );
}

function ContextRow({ entry }: { entry: FolderEntry }) {
  return (
    <div
      title={entry.path}
      aria-label={`${entry.name}, folder`}
      style={{
        padding: "7px 10px",
        borderBottom: "1px solid #f1f5f9",
        fontFamily: "'Segoe UI', Tahoma, sans-serif",
        backgroundColor: "#fbfbfb",
      }}
    >
      <div
        style={{
          fontSize: "12px",
          color: "#4b5563",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {entry.name}
      </div>
      <div style={{ marginTop: "2px", fontSize: "11px", color: "#9ca3af" }}>Folder</div>
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
        borderBottom: "1px solid #eef2f7",
        borderLeft: isSelected ? "3px solid #3b82f6" : "3px solid transparent",
        backgroundColor: isSelected ? "#dbeafe" : isPending ? "#eff6ff" : "#ffffff",
        cursor: disabled ? "default" : "pointer",
        opacity: disabled && !isSelected ? 0.7 : 1,
        fontFamily: "'Segoe UI', Tahoma, sans-serif",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "8px" }}>
        <div
          style={{
            minWidth: 0,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            fontSize: "12px",
            fontWeight: isSelected ? 600 : 400,
            color: "#111827",
          }}
        >
          {entry.name}
        </div>
        {isSelected && (
          <span
            style={{
              flexShrink: 0,
              fontSize: "10px",
              fontWeight: 700,
              color: "#1d4ed8",
              textTransform: "uppercase",
              letterSpacing: "0.03em",
            }}
          >
            Active
          </span>
        )}
        {isPending && !isSelected && (
          <span style={{ flexShrink: 0, fontSize: "10px", color: "#2563eb" }}>Loading...</span>
        )}
      </div>

      <div
        style={{
          marginTop: "3px",
          fontSize: "11px",
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

export function FileSidebar({ width = FILE_SIDEBAR_RECOMMENDED_WIDTH, activeView }: FileSidebarProps) {
  const activeSource = useLogStore((s) => s.activeSource);
  const sourceEntries = useLogStore((s) => s.sourceEntries);
  const selectedSourceFilePath = useLogStore((s) => s.selectedSourceFilePath);
  const openFilePath = useLogStore((s) => s.openFilePath);
  const isLoading = useLogStore((s) => s.isLoading);
  const knownSources = useLogStore((s) => s.knownSources);
  const sourceStatus = useLogStore((s) => s.sourceStatus);
  const clearFilter = useFilterStore((s) => s.clearFilter);

  const intuneAnalysisState = useIntuneStore((s) => s.analysisState);
  const intuneIsAnalyzing = useIntuneStore((s) => s.isAnalyzing);
  const intuneSummary = useIntuneStore((s) => s.summary);
  const intuneSourceContext = useIntuneStore((s) => s.sourceContext);
  const intuneTimelineScope = useIntuneStore((s) => s.timelineScope);
  const setIntuneTimelineFileScope = useIntuneStore((s) => s.setTimelineFileScope);

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
  }, [activeSource, selectedSourceFilePath]);

  const folderLike = isFolderLikeSource(activeSource);
  const sourcePath = getActiveSourcePath(activeSource);
  const knownSourceLabel = useMemo(() => {
    if (!activeSource || activeSource.kind !== "known") {
      return null;
    }

    return knownSources.find((source) => source.id === activeSource.sourceId)?.label ?? null;
  }, [activeSource, knownSources]);

  const sourcePresentation = useMemo(
    () => getSourcePresentation(activeSource, knownSourceLabel),
    [activeSource, knownSourceLabel]
  );

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

  const showRecoveryActions =
    Boolean(activeSource) &&
    folderLike &&
    (sourceStatus.kind === "missing" ||
      sourceStatus.kind === "error" ||
      sourceStatus.kind === "empty" ||
      sourceStatus.kind === "awaiting-file-selection" ||
      Boolean(lastFailedPath));
  const summary = useMemo(() => {
    if (!activeSource) {
      return "No source selected";
    }

    if (!folderLike) {
      return "Single file source";
    }

    return [formatCount(files.length, "file"), formatCount(folders.length, "folder")].join(" • ");
  }, [activeSource, files.length, folderLike, folders.length]);

  const intuneIncludedFiles = intuneSourceContext.includedFiles;
  const intuneSelectedFilePath = intuneTimelineScope.filePath;
  const intuneRequestedPath = intuneAnalysisState.requestedPath;
  const hasIntuneResults = intuneSummary != null || intuneIncludedFiles.length > 0;

  return (
    <aside
      aria-label="Source files"
      style={{
        width,
        minWidth: typeof width === "number" ? `${width}px` : width,
        display: "flex",
        flexDirection: "column",
        overflow: "hidden",
        backgroundColor: "#ffffff",
        borderRight: "1px solid #c0c0c0",
      }}
    >
      <div
        style={{
          padding: "10px",
          borderBottom: "1px solid #c0c0c0",
          backgroundColor: "#f8f8f8",
          fontFamily: "'Segoe UI', Tahoma, sans-serif",
        }}
      >
        <div
          style={{
            fontSize: "11px",
            fontWeight: 700,
            color: "#4b5563",
            textTransform: "uppercase",
            letterSpacing: "0.05em",
          }}
        >
          {sourcePresentation.badge}
        </div>
        <div
          title={sourcePresentation.title}
          style={{
            marginTop: "3px",
            fontSize: "13px",
            fontWeight: 600,
            color: "#111827",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {sourcePresentation.title}
        </div>
        <div
          title={sourcePresentation.subtitle}
          style={{
            marginTop: "3px",
            fontSize: "11px",
            color: "#6b7280",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {sourcePresentation.subtitle}
        </div>
        <div style={{ marginTop: "8px", fontSize: "11px", color: "#4b5563" }}>
          {isLoading && !activeFilePath ? "Loading source..." : `${summary} • ${sourceStatus.message}`}
        </div>
        <div
          style={{
            marginTop: "8px",
            padding: "7px 8px",
            border: "1px solid #e5e7eb",
            backgroundColor: "#ffffff",
            fontSize: "11px",
            color: "#374151",
            lineHeight: 1.45,
          }}
        >
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "72px 1fr",
              gap: "2px 6px",
              alignItems: "start",
            }}
          >
            <span style={{ color: "#6b7280" }}>Source:</span>
            <span title={sourceLabel} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {sourceLabel}
            </span>
            <span style={{ color: "#6b7280" }}>Selected file:</span>
            <span
              title={activeFilePath ?? undefined}
              style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
            >
              {activeFileName}
            </span>
          </div>
          {sourceFailureReason && (
            <div
              title={sourceFailureReason}
              style={{
                marginTop: "6px",
                paddingTop: "6px",
                borderTop: "1px solid #fee2e2",
                color: "#991b1b",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              Failure reason: {sourceFailureReason}
            </div>
          )}
        </div>
      </div>

      {sourceStatus.kind !== "idle" && sourceStatus.kind !== "loading" && (
        <SourceStatusNotice
          kind={sourceStatus.kind}
          message={sourceStatus.message}
          detail={sourceStatus.detail}
        />
      )}

      {showRecoveryActions && (
        <div
          style={{
            padding: "8px 10px",
            borderBottom: "1px solid #e5e7eb",
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
        <div
          role="alert"
          style={{
            padding: "8px 10px",
            borderBottom: "1px solid #fecaca",
            backgroundColor: "#fef2f2",
            color: "#991b1b",
            fontSize: "12px",
            fontFamily: "'Segoe UI', Tahoma, sans-serif",
          }}
        >
          {refreshErrorMessage}
        </div>
      )}

      {errorMessage && (
        <div
          role="alert"
          style={{
            padding: "8px 10px",
            borderBottom: "1px solid #fecaca",
            backgroundColor: "#fef2f2",
            color: "#991b1b",
            fontSize: "12px",
            fontFamily: "'Segoe UI', Tahoma, sans-serif",
          }}
        >
          {errorMessage}
        </div>
      )}

      <div style={{ flex: 1, overflow: "auto" }}>
        {activeView === "intune" && (
          <>
            <SectionHeader title="Intune Diagnostics" caption={intuneAnalysisState.message} />
            <div
              style={{
                padding: "12px 10px",
                fontFamily: "'Segoe UI', Tahoma, sans-serif",
                borderBottom: "1px solid #eef2f7",
                fontSize: "12px",
                color: "#374151",
              }}
            >
              <div style={{ marginBottom: "6px" }}>
                <span style={{ fontWeight: 600 }}>Requested source:</span>{" "}
                <span title={intuneRequestedPath ?? undefined}>
                  {intuneRequestedPath ?? "No analysis requested"}
                </span>
              </div>
              <div style={{ marginBottom: "6px" }}>
                <span style={{ fontWeight: 600 }}>Analyzed file:</span>{" "}
                <span title={intuneSourceContext.analyzedPath ?? undefined}>
                  {intuneSourceContext.analyzedPath ?? "Pending analysis"}
                </span>
              </div>
              <div>
                <span style={{ fontWeight: 600 }}>Timeline scope:</span>{" "}
                <span title={intuneSelectedFilePath ?? undefined}>
                  {getBaseName(intuneSelectedFilePath) || "All included files"}
                </span>
              </div>
            </div>

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

            {!hasIntuneResults && intuneAnalysisState.phase === "empty" && (
              <EmptyState
                title="No IME logs found"
                body={
                  intuneAnalysisState.detail ??
                  "Choose a folder that contains Intune IME log files such as IntuneManagementExtension.log."
                }
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
                <div
                  style={{
                    padding: "12px 10px",
                    fontFamily: "'Segoe UI', Tahoma, sans-serif",
                    borderBottom: "1px solid #eef2f7",
                    fontSize: "12px",
                    color: "#374151"
                  }}
                >
                  <div style={{ marginBottom: "6px" }}>
                    <span style={{ fontWeight: 600 }}>Total Events:</span> {intuneSummary.totalEvents}
                  </div>
                  <div style={{ marginBottom: "6px" }}>
                    <span style={{ fontWeight: 600 }}>Downloads:</span> {intuneSummary.totalDownloads}
                  </div>
                  {intuneSummary.logTimeSpan && (
                    <div style={{ marginBottom: "6px" }}>
                      <span style={{ fontWeight: 600 }}>Time Span:</span> {intuneSummary.logTimeSpan}
                    </div>
                  )}
                </div>

                {intuneIncludedFiles.length > 0 && (
                  <>
                    <SectionHeader
                      title={`Included IME Log Files (${intuneIncludedFiles.length})`}
                      caption="Click a file to scope the timeline to that log only"
                    />
                    <div>
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
                              padding: "6px 10px",
                              border: "none",
                              borderLeft: isSelected ? "3px solid #3b82f6" : "3px solid transparent",
                              borderBottom: "1px solid #eef2f7",
                              fontFamily: "'Segoe UI', Tahoma, sans-serif",
                              fontSize: "11px",
                              color: isSelected ? "#1d4ed8" : "#4b5563",
                              backgroundColor: isSelected ? "#eff6ff" : "#ffffff",
                              cursor: "pointer",
                            }}
                          >
                            <div
                              style={{
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                                fontWeight: isSelected ? 600 : 400,
                              }}
                            >
                              {getBaseName(path)}
                            </div>
                            <div
                              style={{
                                marginTop: "2px",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap",
                                color: isSelected ? "#2563eb" : "#6b7280",
                              }}
                            >
                              {isSelected ? "Timeline scope active" : path}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  </>
                )}
              </>
            )}
          </>
        )}

        {activeView === "log" && (
          <>
            {!activeSource && (
              <EmptyState
                title="No file source open"
                body="Open a file for the classic single-log workflow, or open a folder to browse files here."
              />
            )}

            {activeSource && !folderLike && (
              <>
                <SectionHeader title="Current file" caption="Classic single-file workflow" />
                <div
                  style={{
                    padding: "12px 10px",
                    fontFamily: "'Segoe UI', Tahoma, sans-serif",
                    borderBottom: "1px solid #eef2f7",
                  }}
                >
                  <div
                    style={{
                      fontSize: "12px",
                      fontWeight: 600,
                      color: "#111827",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={getBaseName(activeFilePath)}
                  >
                    {getBaseName(activeFilePath) || "No file selected"}
                  </div>
                  <div
                    style={{
                      marginTop: "4px",
                      fontSize: "11px",
                      color: "#6b7280",
                      lineHeight: 1.45,
                      wordBreak: "break-word",
                    }}
                    title={sourcePath ?? undefined}
                  >
                    {sourcePath ?? "Use Open to choose a log file."}
                  </div>
                </div>
                <EmptyState
                  title="Sidebar stays compact for single files"
                  body="When a folder source is open, this area becomes a file picker so switching between sibling logs feels immediate."
                />
              </>
            )}

            {activeSource && folderLike && sourceEntries.length === 0 && isLoading && (
              <EmptyState title="Loading files" body="Reading the selected folder and preparing the file list." />
            )}

            {activeSource &&
              folderLike &&
              sourceEntries.length === 0 &&
              !isLoading &&
              sourceStatus.kind !== "missing" &&
              sourceStatus.kind !== "error" && (
                <EmptyState
                  title="This folder is empty"
                  body="No files were found in the selected folder. Choose another folder or reopen with a different source."
                />
              )}

            {activeSource &&
              folderLike &&
              sourceEntries.length === 0 &&
              !isLoading &&
              (sourceStatus.kind === "missing" || sourceStatus.kind === "error") && (
                <EmptyState
                  title="Source path unavailable"
                  body={sourceStatus.detail ?? "The selected source path could not be read."}
                />
              )}

            {activeSource && folderLike && sourceEntries.length > 0 && (
              <>
                {folders.length > 0 && (
                  <div>
                    <SectionHeader
                      title={`Folders (${folders.length})`}
                      caption="Shown for context; nested browsing can be added later."
                    />
                    {folders.map((entry) => (
                      <ContextRow key={entry.path} entry={entry} />
                    ))}
                  </div>
                )}

                <div>
                  <SectionHeader
                    title={`Files (${files.length})`}
                    caption={
                      activeFilePath
                        ? "Select a file to replace the active log view."
                        : "Select a file to begin tailing and viewing log entries."
                    }
                  />
                  {files.length === 0 ? (
                    <EmptyState
                      title="No files available"
                      body="This source only returned folders. Open one of those folders directly when nested navigation is added."
                    />
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
                </div>
              </>
            )}
          </>
        )}
      </div>

      {activeView === "log" && activeSource && folderLike && !activeFilePath && !isLoading && (
        <div
          style={{
            padding: "8px 10px",
            borderTop: "1px solid #c0c0c0",
            backgroundColor: "#fafafa",
            fontSize: "11px",
            color: "#4b5563",
            fontFamily: "'Segoe UI', Tahoma, sans-serif",
          }}
        >
          {sourceStatus.kind === "awaiting-file-selection"
            ? sourceStatus.message
            : "Select a file to populate the main log list."}
        </div>
      )}
    </aside>
  );
}



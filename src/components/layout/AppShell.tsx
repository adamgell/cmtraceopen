import { useCallback, useEffect, useRef, Suspense } from "react";
import { tokens, ProgressBar, Spinner } from "@fluentui/react-components";
import { ChevronRightRegular } from "@fluentui/react-icons";
import { Toolbar } from "./Toolbar";
import { TabStrip } from "./TabStrip";
import { StatusBar } from "./StatusBar";
import { FileSidebar, FILE_SIDEBAR_RECOMMENDED_WIDTH } from "./FileSidebar";
import { LogListView } from "../log-view/LogListView";
import { DiffView } from "../log-view/DiffView";
import { DnsWorkspaceBanner } from "../log-view/DnsWorkspaceBanner";
import { InfoPane } from "../log-view/InfoPane";
import { FindBar } from "./FindBar";
import { FilterDialog } from "../dialogs/FilterDialog";
import { ErrorLookupDialog } from "../dialogs/ErrorLookupDialog";
import { GuidRegistryDialog } from "../dialogs/GuidRegistryDialog";
import { AboutDialog } from "../dialogs/AboutDialog";
import { SettingsDialog } from "../dialogs/SettingsDialog";
import { EvidenceBundleDialog } from "../dialogs/EvidenceBundleDialog";
import { FileAssociationPromptDialog } from "../dialogs/FileAssociationPromptDialog";
import { CollectDiagnosticsDialog } from "../dialogs/CollectDiagnosticsDialog";
import { CollectionCompleteDialog } from "../dialogs/CollectionCompleteDialog";
import { UpdateDialog } from "../dialogs/UpdateDialog";
import { MergeTabsDialog } from "../dialogs/MergeTabsDialog";
import { DiffConfigDialog } from "../dialogs/DiffConfigDialog";
import { getWorkspace } from "../../workspaces/registry";
import { RegistryViewer } from "../registry-view/RegistryViewer";
import type { FilterClause } from "../dialogs/FilterDialog";
import type { LogEntry } from "../../types/log";
import { useUiStore } from "../../stores/ui-store";
import {
  getActiveFilterSessionKey,
  isLargeFileModeActive,
  useLogStore,
} from "../../stores/log-store";
import {
  applyBackendFilter,
  mergeFilteredIds,
  useFilterStore,
} from "../../stores/filter-store";
import { switchToTab } from "../../lib/log-source";
import { useFileWatcher } from "../../hooks/use-file-watcher";
import { useIntuneAnalysisProgress } from "../../workspaces/intune/use-intune-analysis-progress";
import { useSysmonAnalysisProgress } from "../../workspaces/sysmon/use-sysmon-analysis-progress";
import { useKeyboard } from "../../hooks/use-keyboard";
import { useDragDrop } from "../../hooks/use-drag-drop";
import { useFileAssociation } from "../../hooks/use-file-association";
import { useFileAssociationPrompt } from "../../hooks/use-file-association-prompt";
import { useCollectionProgressListener } from "../../hooks/use-collection-progress-listener";
import { useParseProgressListener } from "../../hooks/use-parse-progress-listener";
import { useUpdateChecker } from "../../hooks/use-update-checker";
import { QuickStatsPanel } from "../panels/QuickStatsPanel";

function buildClauseSignature(clauses: FilterClause[]): string {
  return clauses
    .map((clause) => `${clause.field}:${clause.op}:${clause.value}`)
    .join("|");
}

function buildFilterRunSignature(
  entries: LogEntry[],
  clauses: FilterClause[],
  entriesRevision: number,
  filterTarget: string
): string {
  const lastId = entries.length > 0 ? entries[entries.length - 1].id : -1;
  const lastLineNumber = entries.length > 0 ? entries[entries.length - 1].lineNumber : -1;
  const clauseSignature = buildClauseSignature(clauses);

  return `${clauseSignature}:${filterTarget}:${entriesRevision}:${entries.length}:${lastId}:${lastLineNumber}`;
}

interface AppliedFilterSnapshot {
  clauseSignature: string;
  filterTarget: string;
  entryCount: number;
  maxEntryId: number;
}

interface RunFilterOptions {
  trigger: string;
  mode?: "full" | "incremental";
  baseFilteredIds?: ReadonlySet<number> | null;
  fullEntriesSnapshot?: LogEntry[];
}

function getMaxEntryId(entries: LogEntry[]): number {
  let maxEntryId = -1;

  for (const entry of entries) {
    if (entry.id > maxEntryId) {
      maxEntryId = entry.id;
    }
  }

  return maxEntryId;
}

function buildAppliedFilterSnapshot(
  entries: LogEntry[],
  clauses: FilterClause[],
  filterTarget: string
): AppliedFilterSnapshot {
  return {
    clauseSignature: buildClauseSignature(clauses),
    filterTarget,
    entryCount: entries.length,
    maxEntryId: getMaxEntryId(entries),
  };
}

function getIncrementalTailEntries(
  entries: LogEntry[],
  appliedSnapshot: AppliedFilterSnapshot | null,
  clauses: FilterClause[],
  filterTarget: string
): LogEntry[] | null {
  if (!appliedSnapshot || appliedSnapshot.entryCount >= entries.length) {
    return null;
  }

  if (
    appliedSnapshot.clauseSignature !== buildClauseSignature(clauses) ||
    appliedSnapshot.filterTarget !== filterTarget
  ) {
    return null;
  }

  const appendedEntries = entries.filter((entry) => entry.id > appliedSnapshot.maxEntryId);

  if (appendedEntries.length === 0) {
    return null;
  }

  return appliedSnapshot.entryCount + appendedEntries.length === entries.length
    ? appendedEntries
    : null;
}

export function AppShell() {
  const activeView = useUiStore((s) => s.activeView);
  const sidebarCollapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const showInfoPane = useUiStore((s) => s.showInfoPane);
  const infoPaneHeight = useUiStore((s) => s.infoPaneHeight);
  const setInfoPaneHeight = useUiStore((s) => s.setInfoPaneHeight);
  const showFindBar = useUiStore((s) => s.showFindBar);
  const showFilterDialog = useUiStore((s) => s.showFilterDialog);
  const showErrorLookupDialog = useUiStore((s) => s.showErrorLookupDialog);
  const showAboutDialog = useUiStore((s) => s.showAboutDialog);
  const showSettingsDialog = useUiStore(
    (s) => s.showSettingsDialog
  );
  const showEvidenceBundleDialog = useUiStore(
    (s) => s.showEvidenceBundleDialog
  );
  const showFileAssociationPrompt = useUiStore(
    (s) => s.showFileAssociationPrompt
  );
  const setShowFindBar = useUiStore((s) => s.setShowFindBar);
  const setShowFilterDialog = useUiStore((s) => s.setShowFilterDialog);
  const setShowErrorLookupDialog = useUiStore(
    (s) => s.setShowErrorLookupDialog
  );
  const setShowAboutDialog = useUiStore((s) => s.setShowAboutDialog);
  const setShowSettingsDialog = useUiStore(
    (s) => s.setShowSettingsDialog
  );
  const setShowEvidenceBundleDialog = useUiStore(
    (s) => s.setShowEvidenceBundleDialog
  );
  const showGuidRegistryDialog = useUiStore(
    (s) => s.showGuidRegistryDialog
  );
  const setShowGuidRegistryDialog = useUiStore(
    (s) => s.setShowGuidRegistryDialog
  );
  const setShowFileAssociationPrompt = useUiStore(
    (s) => s.setShowFileAssociationPrompt
  );

  const activeTabIndex = useUiStore((s) => s.activeTabIndex);
  const collectionProgress = useUiStore((s) => s.collectionProgress);
  const collectionResult = useUiStore((s) => s.collectionResult);
  const setCollectionResult = useUiStore((s) => s.setCollectionResult);
  const showCollectDiagnosticsDialog = useUiStore((s) => s.showCollectDiagnosticsDialog);
  const setShowCollectDiagnosticsDialog = useUiStore((s) => s.setShowCollectDiagnosticsDialog);
  const showUpdateDialog = useUiStore((s) => s.showUpdateDialog);
  const setShowUpdateDialog = useUiStore((s) => s.setShowUpdateDialog);
  const showMergeTabsDialog = useUiStore((s) => s.showMergeTabsDialog);
  const setShowMergeTabsDialog = useUiStore((s) => s.setShowMergeTabsDialog);
  const createMergedTab = useLogStore((s) => s.createMergedTab);
  const showDiffConfigDialog = useUiStore((s) => s.showDiffConfigDialog);
  const setShowDiffConfigDialog = useUiStore((s) => s.setShowDiffConfigDialog);
  const createDiff = useLogStore((s) => s.createDiff);
  const sourceOpenMode = useLogStore((s) => s.sourceOpenMode);

  useCollectionProgressListener();
  useParseProgressListener();

  const {
    updateInfo,
    isChecking: isUpdateChecking,
    isDownloading: isUpdateDownloading,
    downloadProgress: updateDownloadProgress,
    checkForUpdates,
    downloadAndInstall,
    openReleasePage,
    skipVersion,
    dismiss: dismissUpdate,
  } = useUpdateChecker();

  const entries = useLogStore((s) => s.entries);
  const largeFileMode = useLogStore((s) => s.largeFileMode);
  const activeSource = useLogStore((s) => s.activeSource);
  const filterClauses = useFilterStore((s) => s.clauses);
  const setClauses = useFilterStore((s) => s.setClauses);
  const setFilteredIds = useFilterStore((s) => s.setFilteredIds);
  const setIsFiltering = useFilterStore((s) => s.setIsFiltering);
  const setFilterError = useFilterStore((s) => s.setFilterError);

  const infoPaneResizeRef = useRef<{ startY: number; startHeight: number } | null>(null);
  const backendFilterSessionKey = getActiveFilterSessionKey(activeSource, sourceOpenMode);
  const filterTarget = backendFilterSessionKey ?? `raw:${sourceOpenMode ?? "none"}`;

  useEffect(() => {
    const onMouseMove = (e: MouseEvent) => {
      if (!infoPaneResizeRef.current) return;
      const { startY, startHeight } = infoPaneResizeRef.current;
      const delta = startY - e.clientY;
      const newHeight = Math.max(80, Math.min(startHeight + delta, window.innerHeight * 0.7));
      setInfoPaneHeight(newHeight);
    };
    const onMouseUp = () => {
      if (infoPaneResizeRef.current) {
        infoPaneResizeRef.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
    return () => {
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      if (infoPaneResizeRef.current) {
        infoPaneResizeRef.current = null;
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      }
    };
  }, [setInfoPaneHeight]);

  const filterRequestIdRef = useRef(0);
  const largeFileModeFilterMessage = "Filtering is disabled in large-file mode to keep the app responsive.";
  const inFlightSignatureRef = useRef<string | null>(null);
  const lastAppliedSignatureRef = useRef<string | null>(null);
  const appliedFilterSnapshotRef = useRef<AppliedFilterSnapshot | null>(null);
  const entriesRevisionRef = useRef<{ entries: LogEntry[] | null; revision: number }>({
    entries: null,
    revision: 0,
  });

  const getEntriesRevision = useCallback((entriesSnapshot: LogEntry[]) => {
    if (entriesRevisionRef.current.entries !== entriesSnapshot) {
      entriesRevisionRef.current = {
        entries: entriesSnapshot,
        revision: entriesRevisionRef.current.revision + 1,
      };
    }

    return entriesRevisionRef.current.revision;
  }, []);

  const runFilter = useCallback(
    async (
      clauses: FilterClause[],
      entriesToFilter: LogEntry[],
      options: RunFilterOptions
    ) => {
      const {
        trigger,
        mode = "full",
        baseFilteredIds = null,
        fullEntriesSnapshot = entriesToFilter,
      } = options;

      if (clauses.length === 0) {
        filterRequestIdRef.current += 1;
        inFlightSignatureRef.current = null;
        lastAppliedSignatureRef.current = null;
        appliedFilterSnapshotRef.current = null;
        setFilteredIds(null);
        setIsFiltering(false);
        setFilterError(null);
        return;
      }

      if (isLargeFileModeActive(largeFileMode)) {
        filterRequestIdRef.current += 1;
        inFlightSignatureRef.current = null;
        lastAppliedSignatureRef.current = null;
        appliedFilterSnapshotRef.current = null;
        setFilteredIds(null);
        setIsFiltering(false);
        setFilterError(largeFileModeFilterMessage);
        console.info("[app-shell] skipped filter while large-file mode is active", {
          trigger,
          mode,
          clauseCount: clauses.length,
          entryCount: fullEntriesSnapshot.length,
          filterEntryCount: entriesToFilter.length,
          filterTransport: backendFilterSessionKey ? "session-key" : "raw-entries",
          backendSessionKeyPresent: backendFilterSessionKey !== null,
        });
        return;
      }

      const signature = buildFilterRunSignature(
        fullEntriesSnapshot,
        clauses,
        getEntriesRevision(fullEntriesSnapshot),
        filterTarget
      );

      if (
        signature === inFlightSignatureRef.current ||
        signature === lastAppliedSignatureRef.current
      ) {
        return;
      }

      inFlightSignatureRef.current = signature;
      const requestId = filterRequestIdRef.current + 1;
      filterRequestIdRef.current = requestId;

      setFilterError(null);
      setIsFiltering(true);

      try {
        const ids = await applyBackendFilter(clauses, entriesToFilter, {
          backendSessionKey: backendFilterSessionKey,
          forceRawEntries: mode === "incremental",
        });

        if (filterRequestIdRef.current !== requestId) {
          return;
        }

        const nextFilteredIds =
          mode === "incremental" && baseFilteredIds
            ? mergeFilteredIds(baseFilteredIds, ids)
            : new Set(ids);

        setFilteredIds(nextFilteredIds);
        lastAppliedSignatureRef.current = signature;
        appliedFilterSnapshotRef.current = buildAppliedFilterSnapshot(
          fullEntriesSnapshot,
          clauses,
          filterTarget
        );

        console.info("[app-shell] applied filter snapshot", {
          trigger,
          mode,
          clauseCount: clauses.length,
          entryCount: fullEntriesSnapshot.length,
          filterEntryCount: entriesToFilter.length,
          matchedCount: ids.length,
          mergedMatchedCount: nextFilteredIds.size,
          filterTransport:
            mode === "incremental"
              ? "raw-entries-incremental"
              : backendFilterSessionKey
                ? "session-key"
                : "raw-entries",
          backendSessionKeyPresent: backendFilterSessionKey !== null,
        });
      } catch (err) {
        if (filterRequestIdRef.current !== requestId) {
          return;
        }

        appliedFilterSnapshotRef.current = null;
        const errorMessage =
          err instanceof Error ? err.message : "Unknown filter error";

        setFilterError(errorMessage);
        console.error("[app-shell] failed to apply filter", {
          trigger,
          mode,
          error: err,
          clauseCount: clauses.length,
          entryCount: fullEntriesSnapshot.length,
          filterEntryCount: entriesToFilter.length,
          filterTransport:
            mode === "incremental"
              ? "raw-entries-incremental"
              : backendFilterSessionKey
                ? "session-key"
                : "raw-entries",
          backendSessionKeyPresent: backendFilterSessionKey !== null,
        });

        throw err;
      } finally {
        if (filterRequestIdRef.current === requestId) {
          inFlightSignatureRef.current = null;
          setIsFiltering(false);
        }
      }
    },
    [
      backendFilterSessionKey,
      filterTarget,
      getEntriesRevision,
      largeFileMode,
      largeFileModeFilterMessage,
      setFilterError,
      setFilteredIds,
      setIsFiltering,
    ]
  );

  useEffect(() => {
    if (filterClauses.length === 0) {
      filterRequestIdRef.current += 1;
      inFlightSignatureRef.current = null;
      lastAppliedSignatureRef.current = null;
      appliedFilterSnapshotRef.current = null;
      setFilteredIds(null);
      setFilterError(null);
      setIsFiltering(false);
      return;
    }

    const currentFilterState = useFilterStore.getState();
    const appendedEntries =
      currentFilterState.filterError === null && currentFilterState.filteredIds !== null
        ? getIncrementalTailEntries(
            entries,
            appliedFilterSnapshotRef.current,
            filterClauses,
            filterTarget
          )
        : null;

    if (appendedEntries) {
      runFilter(filterClauses, appendedEntries, {
        trigger: "live-tail-append",
        mode: "incremental",
        baseFilteredIds: currentFilterState.filteredIds,
        fullEntriesSnapshot: entries,
      }).catch((error) => {
        console.warn("[app-shell] live incremental filter refresh failed", { error });
      });
      return;
    }

    runFilter(filterClauses, entries, {
      trigger: "live-tail-update",
      mode: "full",
    }).catch((error) => {
      console.warn("[app-shell] live filter refresh failed", { error });
    });
  }, [entries, filterClauses, filterTarget, runFilter, setFilteredIds, setIsFiltering]);

  useEffect(() => {
    if (!isLargeFileModeActive(largeFileMode) || !showFilterDialog) {
      return;
    }

    setShowFilterDialog(false);
  }, [largeFileMode, setShowFilterDialog, showFilterDialog]);

  useFileWatcher();
  useIntuneAnalysisProgress();
  useSysmonAnalysisProgress();
  useKeyboard();
  useDragDrop();
  // Handle file path passed via OS file association at startup
  useFileAssociation();
  // Prompt standalone Windows users to associate .log files like CMTrace.exe
  useFileAssociationPrompt();

  // When the active tab changes, load the corresponding file using stored source context.
  // This avoids redundant folder re-parsing — switchToTab uses the tab's source context
  // to restore the folder sidebar and load only the selected file.
  useEffect(() => {
    const tabs = useUiStore.getState().openTabs;
    if (activeTabIndex < 0 || activeTabIndex >= tabs.length) return;
    const tab = tabs[activeTabIndex];
    const currentPath = useLogStore.getState().openFilePath;
    if (currentPath === tab.filePath) return;

    useUiStore.getState().ensureLogViewVisible("tab-switch");
    switchToTab(tab.filePath, tab.sourceContext).catch((err) => {
      console.error("[tab-switch] failed to load", tab.filePath, err);
    });
  }, [activeTabIndex]);

  const handleApplyFilter = useCallback(
    async (clauses: FilterClause[]) => {
      setClauses(clauses);
      await runFilter(clauses, entries, {
        trigger: "filter-dialog-apply",
        mode: "full",
      });
    },
    [entries, runFilter, setClauses]
  );

  const folderLoadProgress = useLogStore((s) => s.folderLoadProgress);
  const folderLoadCurrentFile = useLogStore((s) => s.folderLoadCurrentFile);
  const folderLoadTotalFiles = useLogStore((s) => s.folderLoadTotalFiles);
  const folderLoadCompletedFiles = useLogStore((s) => s.folderLoadCompletedFiles);

  const renderWorkspace = () => {
    if (activeView === "log") {
      // Check if active tab is a registry file
      const tabs = useUiStore.getState().openTabs;
      const activeTab = tabs[useUiStore.getState().activeTabIndex];
      if (activeTab?.fileKind === "registry") {
        return (
          <div style={{ flex: 1, overflow: "hidden" }}>
            <RegistryViewer />
          </div>
        );
      }

      return (
        <>
          <DnsWorkspaceBanner />
          <QuickStatsPanel />
          <div
            style={{
              flex: 1,
              overflow: "hidden",
              position: "relative",
            }}
          >
            {sourceOpenMode === "diff" ? <DiffView /> : <LogListView />}

            {/* Folder loading overlay with progress bar */}
            {folderLoadProgress !== null && (
              <div
                style={{
                  position: "absolute",
                  inset: 0,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  justifyContent: "center",
                  background: tokens.colorNeutralBackground1,
                  opacity: 0.95,
                  zIndex: 100,
                  gap: "16px",
                  padding: "32px",
                }}
              >
                <Spinner size="large" />
                <div style={{ width: "100%", maxWidth: "400px" }}>
                  <ProgressBar
                    thickness="large"
                    color="brand"
                    value={folderLoadProgress ?? undefined}
                    max={1}
                  />
                </div>
                <div
                  style={{
                    fontSize: "14px",
                    fontWeight: 600,
                    color: tokens.colorNeutralForeground1,
                  }}
                >
                  Parsing files{folderLoadTotalFiles ? ` — ${folderLoadCompletedFiles ?? 0} of ${folderLoadTotalFiles}` : ""}...
                </div>
                {folderLoadCurrentFile && (
                  <div
                    style={{
                      fontSize: "12px",
                      color: tokens.colorNeutralForeground3,
                    }}
                  >
                    {folderLoadCurrentFile}
                  </div>
                )}
              </div>
            )}
          </div>

          {showInfoPane && (
            <>
              <div
                role="separator"
                aria-orientation="horizontal"
                aria-label="Resize detail pane"
                style={{
                  height: "4px",
                  flexShrink: 0,
                  cursor: "row-resize",
                  backgroundColor: tokens.colorNeutralStroke2,
                }}
                onMouseDown={(e) => {
                  e.preventDefault();
                  infoPaneResizeRef.current = { startY: e.clientY, startHeight: infoPaneHeight };
                  document.body.style.cursor = "row-resize";
                  document.body.style.userSelect = "none";
                }}
              />
              <div
                style={{
                  height: `${infoPaneHeight}px`,
                  flexShrink: 0,
                  overflow: "hidden",
                }}
              >
                <InfoPane />
              </div>
            </>
          )}
        </>
      );
    }

    // All other workspaces: registry lookup with lazy loading
    const workspace = getWorkspace(activeView);
    const WorkspaceComponent = workspace.component;
    return (
      <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
        <Suspense fallback={null}>
          <WorkspaceComponent />
        </Suspense>
      </div>
    );
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        overflow: "hidden",
        backgroundColor: tokens.colorNeutralBackground3,
      }}
    >
      <Toolbar />
      {getWorkspace(activeView).capabilities?.tabStrip && <TabStrip />}
      {showFindBar && getWorkspace(activeView).capabilities?.findBar && (
        <FindBar onClose={() => setShowFindBar(false)} />
      )}

      <div
        style={{
          flex: 1,
          display: "flex",
          overflow: "hidden",
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        {activeView !== "event-log" && (
          sidebarCollapsed ? (
            <div
              style={{
                width: 36,
                minWidth: 36,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
                backgroundColor: tokens.colorNeutralBackground2,
                paddingTop: 8,
              }}
            >
              <button
                onClick={toggleSidebar}
                title="Expand sidebar (Ctrl+B)"
                aria-label="Expand sidebar"
                style={{
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  padding: 6,
                  borderRadius: 4,
                  color: tokens.colorNeutralForeground2,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
              >
                <ChevronRightRegular style={{ fontSize: 16 }} />
              </button>
            </div>
          ) : (
            <FileSidebar
              width={FILE_SIDEBAR_RECOMMENDED_WIDTH}
              activeView={activeView}
              onCollapse={toggleSidebar}
            />
          )
        )}

        <div
          style={{
            flex: 1,
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
            backgroundColor: tokens.colorNeutralBackground1,
          }}
        >
          {renderWorkspace()}
        </div>
      </div>

      <StatusBar />

      {collectionProgress && collectionProgress.completedItems < collectionProgress.totalItems && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            padding: "6px 16px",
            backgroundColor: tokens.colorNeutralBackground3,
            borderTop: `1px solid ${tokens.colorNeutralStroke2}`,
            fontSize: "12px",
            color: tokens.colorNeutralForeground2,
          }}
        >
          <Spinner size="tiny" />
          <span>Collecting diagnostics…</span>
          <div style={{ flex: 1, height: "4px", backgroundColor: tokens.colorNeutralBackground5, borderRadius: "2px", overflow: "hidden" }}>
            <div
              style={{
                width: collectionProgress.totalItems > 0
                  ? `${(collectionProgress.completedItems / collectionProgress.totalItems) * 100}%`
                  : "0%",
                height: "100%",
                backgroundColor: tokens.colorBrandBackground,
                borderRadius: "2px",
                transition: "width 0.3s ease",
              }}
            />
          </div>
          <span style={{ color: tokens.colorNeutralForeground3, whiteSpace: "nowrap" }}>
            {collectionProgress.completedItems} / {collectionProgress.totalItems}
          </span>
        </div>
      )}

      <FilterDialog
        isOpen={showFilterDialog}
        onClose={() => setShowFilterDialog(false)}
        onApply={handleApplyFilter}
        currentClauses={filterClauses}
      />
      <ErrorLookupDialog
        isOpen={showErrorLookupDialog}
        onClose={() => setShowErrorLookupDialog(false)}
      />
      <AboutDialog
        isOpen={showAboutDialog}
        onClose={() => setShowAboutDialog(false)}
      />
      <SettingsDialog
        isOpen={showSettingsDialog}
        onClose={() => setShowSettingsDialog(false)}
      />
      <GuidRegistryDialog
        isOpen={showGuidRegistryDialog}
        onClose={() => setShowGuidRegistryDialog(false)}
      />
      <EvidenceBundleDialog
        isOpen={showEvidenceBundleDialog}
        onClose={() => setShowEvidenceBundleDialog(false)}
      />
      <FileAssociationPromptDialog
        isOpen={showFileAssociationPrompt}
        onClose={() => setShowFileAssociationPrompt(false)}
      />
      <CollectDiagnosticsDialog
        isOpen={showCollectDiagnosticsDialog}
        onClose={() => setShowCollectDiagnosticsDialog(false)}
      />
      <CollectionCompleteDialog
        result={collectionResult}
        onClose={() => setCollectionResult(null)}
      />
      <MergeTabsDialog
        isOpen={showMergeTabsDialog}
        onClose={() => setShowMergeTabsDialog(false)}
        onMerge={(filePaths) => createMergedTab(filePaths)}
      />
      <DiffConfigDialog
        isOpen={showDiffConfigDialog}
        onClose={() => setShowDiffConfigDialog(false)}
        onCompare={(sourceA, sourceB) => createDiff(sourceA, sourceB)}
      />
      <UpdateDialog
        isOpen={showUpdateDialog}
        onClose={() => {
          dismissUpdate();
          setShowUpdateDialog(false);
        }}
        updateInfo={updateInfo}
        isChecking={isUpdateChecking}
        isDownloading={isUpdateDownloading}
        downloadProgress={updateDownloadProgress}
        onCheckForUpdates={checkForUpdates}
        onDownloadAndInstall={downloadAndInstall}
        onOpenReleasePage={openReleasePage}
        onSkipVersion={skipVersion}
      />
    </div>
  );
}

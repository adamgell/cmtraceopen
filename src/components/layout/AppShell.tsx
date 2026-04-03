import { useCallback, useEffect, useRef } from "react";
import { tokens, ProgressBar, Spinner } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { Toolbar } from "./Toolbar";
import { TabStrip } from "./TabStrip";
import { StatusBar } from "./StatusBar";
import { FileSidebar, FILE_SIDEBAR_RECOMMENDED_WIDTH } from "./FileSidebar";
import { LogListView } from "../log-view/LogListView";
import { DiffView } from "../log-view/DiffView";
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
import { IntuneDashboard } from "../intune/IntuneDashboard";
import { NewIntuneWorkspace } from "../intune/NewIntuneWorkspace";
import { DsregcmdWorkspace } from "../dsregcmd/DsregcmdWorkspace";
import { MacosDiagWorkspace } from "../macos-diag/MacosDiagWorkspace";
import { DeploymentWorkspace } from "../deployment/DeploymentWorkspace";
import { EventLogWorkspace } from "../event-log-workspace/EventLogWorkspace";
import { SysmonWorkspace } from "../sysmon/SysmonWorkspace";
import { RegistryViewer } from "../registry-view/RegistryViewer";
import type { FilterClause } from "../dialogs/FilterDialog";
import type { LogEntry } from "../../types/log";
import { useUiStore } from "../../stores/ui-store";
import { useLogStore } from "../../stores/log-store";
import { useFilterStore } from "../../stores/filter-store";
import { switchToTab } from "../../lib/log-source";
import { useFileWatcher } from "../../hooks/use-file-watcher";
import { useIntuneAnalysisProgress } from "../../hooks/use-intune-analysis-progress";
import { useSysmonAnalysisProgress } from "../../hooks/use-sysmon-analysis-progress";
import { useKeyboard } from "../../hooks/use-keyboard";
import { useDragDrop } from "../../hooks/use-drag-drop";
import { useFileAssociation } from "../../hooks/use-file-association";
import { useFileAssociationPrompt } from "../../hooks/use-file-association-prompt";
import { useCollectionProgressListener } from "../../hooks/use-collection-progress-listener";
import { useParseProgressListener } from "../../hooks/use-parse-progress-listener";
import { useUpdateChecker } from "../../hooks/use-update-checker";

function buildFilterRunSignature(entries: LogEntry[], clauses: FilterClause[]): string {
  const lastId = entries.length > 0 ? entries[entries.length - 1].id : -1;
  const lastLineNumber = entries.length > 0 ? entries[entries.length - 1].lineNumber : -1;
  const clauseSignature = clauses
    .map((clause) => `${clause.field}:${clause.op}:${clause.value}`)
    .join("|");

  return `${clauseSignature}:${entries.length}:${lastId}:${lastLineNumber}`;
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
  const filterClauses = useFilterStore((s) => s.clauses);
  const setClauses = useFilterStore((s) => s.setClauses);
  const setFilteredIds = useFilterStore((s) => s.setFilteredIds);
  const setIsFiltering = useFilterStore((s) => s.setIsFiltering);
  const setFilterError = useFilterStore((s) => s.setFilterError);

  const infoPaneResizeRef = useRef<{ startY: number; startHeight: number } | null>(null);

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
  const inFlightSignatureRef = useRef<string | null>(null);
  const lastAppliedSignatureRef = useRef<string | null>(null);

  const runFilter = useCallback(
    async (clauses: FilterClause[], entriesSnapshot: LogEntry[], trigger: string) => {
      if (clauses.length === 0) {
        inFlightSignatureRef.current = null;
        lastAppliedSignatureRef.current = null;
        setFilteredIds(null);
        setIsFiltering(false);
        setFilterError(null);
        return;
      }

      const signature = buildFilterRunSignature(entriesSnapshot, clauses);

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
        const ids = await invoke<number[]>("apply_filter", {
          entries: entriesSnapshot,
          clauses,
        });

        if (filterRequestIdRef.current !== requestId) {
          return;
        }

        setFilteredIds(new Set(ids));
        lastAppliedSignatureRef.current = signature;

        console.info("[app-shell] applied filter snapshot", {
          trigger,
          clauseCount: clauses.length,
          entryCount: entriesSnapshot.length,
          matchedCount: ids.length,
        });
      } catch (err) {
        if (filterRequestIdRef.current !== requestId) {
          return;
        }

        const errorMessage =
          err instanceof Error ? err.message : "Unknown filter error";

        setFilterError(errorMessage);
        console.error("[app-shell] failed to apply filter", {
          trigger,
          error: err,
          clauseCount: clauses.length,
          entryCount: entriesSnapshot.length,
        });

        throw err;
      } finally {
        if (filterRequestIdRef.current === requestId) {
          inFlightSignatureRef.current = null;
          setIsFiltering(false);
        }
      }
    },
    [setFilterError, setFilteredIds, setIsFiltering]
  );

  useEffect(() => {
    if (filterClauses.length === 0) {
      inFlightSignatureRef.current = null;
      lastAppliedSignatureRef.current = null;
      setFilteredIds(null);
      setIsFiltering(false);
      return;
    }

    runFilter(filterClauses, entries, "live-tail-update").catch((error) => {
      console.warn("[app-shell] live filter refresh failed", { error });
    });
  }, [entries, filterClauses, runFilter, setFilteredIds, setIsFiltering]);

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
      await runFilter(clauses, entries, "filter-dialog-apply");
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

    if (activeView === "intune") {
      return (
        <div style={{ flex: 1, overflow: "hidden" }}>
          <IntuneDashboard />
        </div>
      );
    }

    if (activeView === "new-intune") {
      return (
        <div style={{ flex: 1, overflow: "hidden" }}>
          <NewIntuneWorkspace />
        </div>
      );
    }

    if (activeView === "macos-diag") {
      return (
        <div style={{ flex: 1, overflow: "hidden" }}>
          <MacosDiagWorkspace />
        </div>
      );
    }

    if (activeView === "sysmon") {
      return (
        <div style={{ flex: 1, overflow: "hidden" }}>
          <SysmonWorkspace />
        </div>
      );
    }

    if (activeView === "deployment") {
      return (
        <div style={{ flex: 1, overflow: "hidden" }}>
          <DeploymentWorkspace />
        </div>
      );
    }

    if (activeView === "event-log") {
      return (
        <div style={{ flex: 1, overflow: "hidden", display: "flex" }}>
          <EventLogWorkspace />
        </div>
      );
    }

    if (activeView === "dsregcmd") {
      return (
        <div style={{ flex: 1, overflow: "hidden" }}>
          <DsregcmdWorkspace />
        </div>
      );
    }

    return null;
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
      {activeView === "log" && <TabStrip />}
      {showFindBar && activeView === "log" && (
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
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M6 3l5 5-5 5V3z" />
                </svg>
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

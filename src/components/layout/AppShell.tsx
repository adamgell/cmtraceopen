import { useCallback, useEffect, useRef } from "react";
import { tokens } from "@fluentui/react-components";
import { invoke } from "@tauri-apps/api/core";
import { Toolbar } from "./Toolbar";
import { StatusBar } from "./StatusBar";
import { FileSidebar, FILE_SIDEBAR_RECOMMENDED_WIDTH } from "./FileSidebar";
import { LogListView } from "../log-view/LogListView";
import { InfoPane } from "../log-view/InfoPane";
import { FindDialog } from "../dialogs/FindDialog";
import { FilterDialog } from "../dialogs/FilterDialog";
import { ErrorLookupDialog } from "../dialogs/ErrorLookupDialog";
import { AboutDialog } from "../dialogs/AboutDialog";
import { AccessibilityDialog } from "../dialogs/AccessibilityDialog";
import { EvidenceBundleDialog } from "../dialogs/EvidenceBundleDialog";
import { FileAssociationPromptDialog } from "../dialogs/FileAssociationPromptDialog";
import { IntuneDashboard } from "../intune/IntuneDashboard";
import { NewIntuneWorkspace } from "../intune/NewIntuneWorkspace";
import { DsregcmdWorkspace } from "../dsregcmd/DsregcmdWorkspace";
import { MacosDiagWorkspace } from "../macos-diag/MacosDiagWorkspace";
import type { FilterClause } from "../dialogs/FilterDialog";
import type { LogEntry } from "../../types/log";
import { useUiStore } from "../../stores/ui-store";
import { useLogStore } from "../../stores/log-store";
import { useFilterStore } from "../../stores/filter-store";
import { useFileWatcher } from "../../hooks/use-file-watcher";
import { useIntuneAnalysisProgress } from "../../hooks/use-intune-analysis-progress";
import { useKeyboard } from "../../hooks/use-keyboard";
import { useDragDrop } from "../../hooks/use-drag-drop";
import { useFileAssociation } from "../../hooks/use-file-association";
import { useFileAssociationPrompt } from "../../hooks/use-file-association-prompt";

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
  const showInfoPane = useUiStore((s) => s.showInfoPane);
  const infoPaneHeight = useUiStore((s) => s.infoPaneHeight);
  const showFindDialog = useUiStore((s) => s.showFindDialog);
  const showFilterDialog = useUiStore((s) => s.showFilterDialog);
  const showErrorLookupDialog = useUiStore((s) => s.showErrorLookupDialog);
  const showAboutDialog = useUiStore((s) => s.showAboutDialog);
  const showAccessibilityDialog = useUiStore(
    (s) => s.showAccessibilityDialog
  );
  const showEvidenceBundleDialog = useUiStore(
    (s) => s.showEvidenceBundleDialog
  );
  const showFileAssociationPrompt = useUiStore(
    (s) => s.showFileAssociationPrompt
  );
  const setShowFindDialog = useUiStore((s) => s.setShowFindDialog);
  const setShowFilterDialog = useUiStore((s) => s.setShowFilterDialog);
  const setShowErrorLookupDialog = useUiStore(
    (s) => s.setShowErrorLookupDialog
  );
  const setShowAboutDialog = useUiStore((s) => s.setShowAboutDialog);
  const setShowAccessibilityDialog = useUiStore(
    (s) => s.setShowAccessibilityDialog
  );
  const setShowEvidenceBundleDialog = useUiStore(
    (s) => s.setShowEvidenceBundleDialog
  );
  const setShowFileAssociationPrompt = useUiStore(
    (s) => s.setShowFileAssociationPrompt
  );

  const entries = useLogStore((s) => s.entries);
  const filterClauses = useFilterStore((s) => s.clauses);
  const setClauses = useFilterStore((s) => s.setClauses);
  const setFilteredIds = useFilterStore((s) => s.setFilteredIds);
  const setIsFiltering = useFilterStore((s) => s.setIsFiltering);
  const setFilterError = useFilterStore((s) => s.setFilterError);

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
  useKeyboard();
  useDragDrop();
  // Handle file path passed via OS file association at startup
  useFileAssociation();
  // Prompt standalone Windows users to associate .log files like CMTrace.exe
  useFileAssociationPrompt();

  const handleApplyFilter = useCallback(
    async (clauses: FilterClause[]) => {
      setClauses(clauses);
      await runFilter(clauses, entries, "filter-dialog-apply");
    },
    [entries, runFilter, setClauses]
  );

  const renderWorkspace = () => {
    if (activeView === "log") {
      return (
        <>
          <div
            style={{
              flex: 1,
              overflow: "hidden",
            }}
          >
            <LogListView />
          </div>

          {showInfoPane && (
            <div
              style={{
                height: `${infoPaneHeight}px`,
                flexShrink: 0,
                overflow: "hidden",
              }}
            >
              <InfoPane />
            </div>
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

    return (
      <div style={{ flex: 1, overflow: "hidden" }}>
        <DsregcmdWorkspace />
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

      <div
        style={{
          flex: 1,
          display: "flex",
          overflow: "hidden",
          backgroundColor: tokens.colorNeutralBackground2,
        }}
      >
        <FileSidebar width={FILE_SIDEBAR_RECOMMENDED_WIDTH} activeView={activeView} />

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

      <FindDialog
        isOpen={showFindDialog}
        onClose={() => setShowFindDialog(false)}
      />
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
      <AccessibilityDialog
        isOpen={showAccessibilityDialog}
        onClose={() => setShowAccessibilityDialog(false)}
      />
      <EvidenceBundleDialog
        isOpen={showEvidenceBundleDialog}
        onClose={() => setShowEvidenceBundleDialog(false)}
      />
      <FileAssociationPromptDialog
        isOpen={showFileAssociationPrompt}
        onClose={() => setShowFileAssociationPrompt(false)}
      />
    </div>
  );
}

import {
  Suspense,
  useCallback,
  useEffect,
  useMemo,
} from "react";
import {
  Button,
  Divider,
  Dropdown,
  Input,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  Option,
  tokens,
} from "@fluentui/react-components";
import { platform } from "@tauri-apps/plugin-os";
import {
  getAvailableWorkspaces as getAvailableBackendWorkspaces,
  inspectPathKind,
  listLogFolder,
} from "../../lib/commands";
import { useLogStore } from "../../stores/log-store";
import { useFilterStore } from "../../stores/filter-store";
import { isIntuneWorkspace, getAvailableWorkspaces, type WorkspaceId, type PlatformId, useUiStore } from "../../stores/ui-store";
import { getWorkspace } from "../../workspaces/registry";
import type { WorkspaceDefinition } from "../../workspaces/types";
import { ThemePicker } from "./ThemePicker";
import { useAppActions } from "../../hooks/use-app-actions";
import {
  loadFilesAsLogSource,
  refreshKnownLogSources,
} from "../../lib/log-source";
import { matchesAnyPattern } from "../../lib/glob";

export { useAppActions };
export type { AppActionHandlers, AppCommandState } from "../../hooks/use-app-actions";

export function WorkspaceToolbarAction({
  workspace,
}: {
  workspace: WorkspaceDefinition;
}) {
  const ToolbarAction = workspace.toolbarAction;
  if (!ToolbarAction) {
    return null;
  }

  return (
    <Suspense fallback={null}>
      <ToolbarAction />
    </Suspense>
  );
}

export function Toolbar() {
  const highlightText = useLogStore((s) => s.highlightText);
  const setHighlightText = useLogStore((s) => s.setHighlightText);
  const knownSourceToolbarFamilies = useLogStore((s) => s.knownSourceToolbarFamilies);

  const activeView = useUiStore((s) => s.activeView);
  const currentPlatform = useUiStore((s) => s.currentPlatform);
  const activeWorkspace = useUiStore((s) => s.activeWorkspace);
  const openTabs = useUiStore((s) => s.openTabs);
  const setShowMergeTabsDialog = useUiStore((s) => s.setShowMergeTabsDialog);
  const setShowDiffConfigDialog = useUiStore((s) => s.setShowDiffConfigDialog);
  const enabledWorkspaces = useUiStore((s) => s.enabledWorkspaces);
  const availableWorkspaces = useMemo(
    () => getAvailableWorkspaces(currentPlatform, enabledWorkspaces),
    [currentPlatform, enabledWorkspaces]
  );

  const canMergeTabs = activeWorkspace === "log" && openTabs.length >= 2;

  const openAllKnownSourcesInFamily = useCallback(
    async (familyId: string) => {
      const families = useLogStore.getState().knownSourceToolbarFamilies;
      const family = families.find((f) => f.id === familyId);
      if (!family) return;

      const folderSources: Array<{ folderPath: string; patterns: string[] }> = [];
      const directFilePaths = new Set<string>();

      for (const group of family.groups) {
        for (const source of group.sources) {
          if (source.source.kind === "known") {
            if (source.source.pathKind === "folder") {
              folderSources.push({
                folderPath: source.source.defaultPath,
                patterns: source.filePatterns ?? [],
              });
            } else if (source.source.pathKind === "file") {
              directFilePaths.add(source.source.defaultPath);
            }
          }
        }
      }

      if (folderSources.length === 0 && directFilePaths.size === 0) return;

      useUiStore.getState().ensureLogViewVisible("toolbar.open-all-family");
      useFilterStore.getState().clearFilter();

      // Verify direct file paths actually exist on disk before including them
      const verifiedFilePaths = new Set<string>();
      await Promise.all(
        [...directFilePaths].map(async (filePath) => {
          try {
            const kind = await inspectPathKind(filePath);
            if (kind === "file") {
              verifiedFilePaths.add(filePath);
            }
          } catch {
            // Path doesn't exist or isn't accessible — skip silently
          }
        }),
      );

      const allFilePaths = new Set<string>(verifiedFilePaths);
      for (const { folderPath, patterns } of folderSources) {
        try {
          const listing = await listLogFolder(folderPath);
          for (const entry of listing.entries) {
            if (entry.isDir) continue;
            if (patterns.length > 0 && !matchesAnyPattern(entry.name, patterns)) continue;
            allFilePaths.add(entry.path);
          }
        } catch {
          console.warn("[toolbar] skipping unavailable folder", folderPath);
        }
      }

      if (allFilePaths.size === 0) return;

      await loadFilesAsLogSource([...allFilePaths]);
    },
    []
  );

  const {
    commandState,
    openSourceFileDialog,
    openSourceFolderDialog,
    openKnownSourceCatalogAction,
    pasteDsregcmdSource,
    captureDsregcmdSource,
    showFilterDialog,
    showErrorLookupDialog,
    toggleDetailsPane,
    toggleInfoPane,
    switchWorkspace,
  } = useAppActions();

  const clearFilter = useCallback(() => {
    useFilterStore.getState().clearFilter();
  }, []);


  useEffect(() => {
    refreshKnownLogSources().catch((error) => {
      console.warn("[toolbar] failed to refresh known sources", { error });
    });

    let disposed = false;

    void getAvailableBackendWorkspaces()
      .then((workspaces) => {
        if (disposed) {
          return;
        }

        const store = useUiStore.getState();
        store.setEnabledWorkspaces(workspaces);
      })
      .catch((error) => {
        console.warn("[toolbar] failed to load build workspace availability", {
          error,
        });
      });

    try {
      const p = platform();
      const mapped: PlatformId = p === "macos" ? "macos" : p === "windows" ? "windows" : "linux";
      const store = useUiStore.getState();
      store.setCurrentPlatform(mapped);
      const available = getAvailableWorkspaces(mapped, store.enabledWorkspaces);
      if (!available.includes(store.activeWorkspace)) {
        store.setActiveWorkspace("log");
      }
    } catch (error) {
      console.warn("[toolbar] failed to detect platform", { error });
    }

    return () => {
      disposed = true;
    };
  }, []);

  const openLabels = useMemo(() => {
    const ws = getWorkspace(activeView);
    return ws.actionLabels ?? {
      file: "Open file...",
      folder: "Open folder...",
      placeholder: "Open...",
    };
  }, [activeView]);


  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        gap: "10px",
        padding: "10px 12px",
        backgroundColor: tokens.colorNeutralBackground2,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        flexShrink: 0,
      }}
    >
      <Menu>
        <MenuTrigger disableButtonEnhancement>
          <Button
            size="small"
            disabled={!commandState.canOpenSources}
            title={openLabels.placeholder}
          >
            {openLabels.placeholder}
          </Button>
        </MenuTrigger>
        <MenuPopover>
          <MenuList>
            <MenuItem onClick={() => void openSourceFileDialog().catch((err) => console.error("Failed to open file dialog", err))}>
              {openLabels.file}
            </MenuItem>
            <MenuItem onClick={() => void openSourceFolderDialog().catch((err) => console.error("Failed to open folder dialog", err))}>
              {openLabels.folder}
            </MenuItem>
            {activeView === "dsregcmd" && (
              <>
                <MenuItem onClick={() => void pasteDsregcmdSource().catch((err) => console.error("Failed to paste dsregcmd source", err))}>
                  Paste clipboard
                </MenuItem>
                <MenuItem onClick={() => void captureDsregcmdSource().catch((err) => console.error("Failed to capture dsregcmd source", err))}>
                  Capture live output
                </MenuItem>
              </>
            )}
          </MenuList>
        </MenuPopover>
      </Menu>
      <Menu>
        <MenuTrigger disableButtonEnhancement>
          <Button
            size="small"
            disabled={
              !commandState.canOpenKnownSources ||
              knownSourceToolbarFamilies.length === 0
            }
            title="Open a known log source"
          >
            {commandState.canOpenKnownSources
              ? knownSourceToolbarFamilies.length > 0
                ? isIntuneWorkspace(activeView)
                  ? "Open known Intune source..."
                  : "Open known log source..."
                : "No known log sources"
              : "Known sources unavailable"}
          </Button>
        </MenuTrigger>
        <MenuPopover>
          <MenuList>
            {knownSourceToolbarFamilies.map((family) => (
              <Menu key={family.id}>
                <MenuTrigger disableButtonEnhancement>
                  <MenuItem>{family.label}</MenuItem>
                </MenuTrigger>
                <MenuPopover>
                  <MenuList>
                    <MenuItem
                      onClick={() =>
                        void openAllKnownSourcesInFamily(family.id).catch((err) =>
                          console.error("Failed to open all sources in family", err)
                        )
                      }
                      style={{ fontWeight: 500 }}
                    >
                      Open all {family.label}
                    </MenuItem>
                    <Divider />
                    {family.groups.map((group) => (
                      <Menu key={group.id}>
                        <MenuTrigger disableButtonEnhancement>
                          <MenuItem>{group.label}</MenuItem>
                        </MenuTrigger>
                        <MenuPopover>
                          <MenuList>
                            {group.sources.map((source) => (
                              <MenuItem
                                key={source.id}
                                title={source.description}
                                onClick={() =>
                                  void openKnownSourceCatalogAction({
                                    sourceId: source.id,
                                    trigger: "toolbar.known-source-select",
                                  }).catch((err) =>
                                    console.error(
                                      "Failed to open known source catalog action",
                                      err
                                    )
                                  )
                                }
                              >
                                {source.label}
                              </MenuItem>
                            ))}
                          </MenuList>
                        </MenuPopover>
                      </Menu>
                    ))}
                  </MenuList>
                </MenuPopover>
              </Menu>
            ))}
          </MenuList>
        </MenuPopover>
      </Menu>

      <Divider vertical />

      <Input
        value={highlightText}
        onChange={(e) => setHighlightText(e.target.value)}
        placeholder="Highlight..."
        disabled={commandState.activeWorkspace !== "log"}
        size="small"
        style={{
          width: "200px",
          minWidth: "120px",
        }}
      />

      {canMergeTabs && (
        <button
          type="button"
          onClick={() => setShowMergeTabsDialog(true)}
          title="Merge open tabs into a unified timeline"
          style={{
            fontSize: "12px",
            padding: "4px 10px",
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: "4px",
            backgroundColor: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          Merge tabs...
        </button>
      )}
      {canMergeTabs && (
        <button
          type="button"
          onClick={() => setShowDiffConfigDialog(true)}
          title="Compare two open tabs"
          style={{
            fontSize: "12px",
            padding: "4px 10px",
            border: `1px solid ${tokens.colorNeutralStroke2}`,
            borderRadius: "4px",
            backgroundColor: tokens.colorNeutralBackground1,
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          Diff tabs...
        </button>
      )}

      <Divider vertical />

      <Button
        onClick={commandState.activeFilterCount > 0 ? clearFilter : showFilterDialog}
        title={
          commandState.activeFilterCount > 0
            ? `Clear active filter (${commandState.activeFilterCount} clause${commandState.activeFilterCount === 1 ? "" : "s"}) — click to remove`
            : "Filter... (Ctrl+Shift+L)"
        }
        disabled={commandState.activeFilterCount === 0 && !commandState.canFilter}
        aria-pressed={commandState.activeFilterCount > 0}
        size="small"
        appearance={commandState.activeFilterCount > 0 ? "primary" : "secondary"}
      >
        {commandState.activeFilterCount > 0
          ? `Filter (${commandState.activeFilterCount})`
          : "Filter..."}
      </Button>

      <Button
        onClick={showErrorLookupDialog}
        title="Error lookup (Ctrl+E)"
        size="small"
        appearance="secondary"
      >
        Error lookup
      </Button>

      <Divider vertical />

      <Button
        onClick={toggleDetailsPane}
        title="Show / hide details (Ctrl+H)"
        disabled={!commandState.canToggleDetailsPane}
        aria-pressed={commandState.isDetailsVisible}
        size="small"
        appearance={commandState.isDetailsVisible ? "primary" : "secondary"}
      >
        Details
      </Button>
      <Button
        onClick={toggleInfoPane}
        title="Toggle info pane"
        disabled={!commandState.canToggleInfoPane}
        aria-pressed={commandState.isInfoPaneVisible}
        size="small"
        appearance={commandState.isInfoPaneVisible ? "primary" : "secondary"}
      >
        Info
      </Button>

      {enabledWorkspaces !== null && availableWorkspaces.length > 1 && (
        <>
          <Divider vertical />

          <label
            style={{
              fontSize: "11px",
              color: tokens.colorNeutralForeground3,
              whiteSpace: "nowrap",
            }}
          >
            Workspace:
          </label>
          <Dropdown
            value={getWorkspace(activeView).label}
            selectedOptions={[activeView]}
            onOptionSelect={(_e, data) => {
              if (data.optionValue) {
                switchWorkspace(
                  data.optionValue as WorkspaceId,
                  "toolbar.workspace-select",
                );
              }
            }}
            size="small"
            style={{ minWidth: "180px" }}
            aria-label="Workspace"
          >
            {availableWorkspaces.map((wsId) => (
              <Option key={wsId} value={wsId}>{getWorkspace(wsId).label}</Option>
            ))}
          </Dropdown>
        </>
      )}

      <WorkspaceToolbarAction workspace={getWorkspace(activeView)} />

      <div style={{ flex: 1 }} />

      <ThemePicker />
    </div>
  );
}

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const pasteDsregcmdSource = vi.fn(async () => undefined);
const captureDsregcmdSource = vi.fn(async () => undefined);

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    commandState: {
      canOpenSources: true,
      canOpenKnownSources: false,
      canPauseResume: false,
      canFind: false,
      hasFindSession: false,
      canFilter: false,
      canRefresh: false,
      canToggleSidebar: true,
      canToggleDetailsPane: false,
      canToggleInfoPane: false,
      canAdjustTextSize: false,
      canShowEvidenceBundle: false,
      canSaveSession: false,
      canCollectDiagnostics: true,
      isLoading: false,
      isPaused: false,
      hasActiveSource: false,
      isSidebarVisible: true,
      isDetailsVisible: false,
      isInfoPaneVisible: false,
      activeFilterCount: 0,
      isFiltering: false,
      filterError: null,
      activeWorkspace: "dsregcmd",
      openFileLabel: "Open text file...",
      openFolderLabel: "Open evidence folder...",
    },
    openSourceFileDialog: vi.fn(),
    openSourceFolderDialog: vi.fn(),
    openKnownSourceCatalogAction: vi.fn(),
    pasteDsregcmdSource,
    captureDsregcmdSource,
    showFilterDialog: vi.fn(),
    showErrorLookupDialog: vi.fn(),
    toggleDetailsPane: vi.fn(),
    toggleInfoPane: vi.fn(),
    switchWorkspace: vi.fn(),
  }),
}));

vi.mock("../../lib/log-source", () => ({
  loadFilesAsLogSource: vi.fn(),
  refreshKnownLogSources: vi.fn(async () => undefined),
}));

vi.mock("@tauri-apps/plugin-os", () => ({
  platform: () => "windows",
}));

import { Toolbar } from "./Toolbar";
import { useUiStore } from "../../stores/ui-store";
import { useLogStore } from "../../stores/log-store";

describe("Toolbar dsregcmd paste and capture", () => {
  beforeEach(() => {
    pasteDsregcmdSource.mockClear();
    captureDsregcmdSource.mockClear();
    useLogStore.getState().clear();
    useUiStore.setState(useUiStore.getInitialState(), true);
    useUiStore.setState({
      activeWorkspace: "dsregcmd",
      activeView: "dsregcmd",
      currentPlatform: "windows",
      enabledWorkspaces: null,
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("adds Paste clipboard and Capture live output when dsregcmd is active", async () => {
    render(<Toolbar />);
    fireEvent.click(screen.getByRole("button", { name: /Open dsregcmd source/i }));
    fireEvent.click(await screen.findByText("Paste clipboard"));
    expect(pasteDsregcmdSource).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole("button", { name: /Open dsregcmd source/i }));
    fireEvent.click(await screen.findByText("Capture live output"));
    expect(captureDsregcmdSource).toHaveBeenCalledTimes(1);
  });
});

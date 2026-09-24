import { cleanup, fireEvent, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../stores/ui-store";
import { useKeyboard } from "./use-keyboard";

const actions = vi.hoisted(() => ({
  commandState: { canAdjustTextSize: false },
  openSourceFileDialog: vi.fn(),
  showFindBar: vi.fn(),
  findNext: vi.fn(),
  findPrevious: vi.fn(),
  showFilterDialog: vi.fn(),
  showErrorLookupDialog: vi.fn(),
  increaseLogListTextSize: vi.fn(),
  decreaseLogListTextSize: vi.fn(),
  resetLogListTextSize: vi.fn(),
  togglePauseResume: vi.fn(),
  refreshActiveSource: vi.fn(),
  toggleSidebar: vi.fn(),
  toggleDetailsPane: vi.fn(),
  dismissTransientDialogs: vi.fn(),
}));

vi.mock("./use-app-actions", () => ({
  useAppActions: () => actions,
}));

function Harness() {
  useKeyboard();
  return <div data-testid="keyboard-harness">ready</div>;
}

describe("useKeyboard (CHROME-007)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState({
      showFindBar: false,
      showFilterDialog: false,
      showErrorLookupDialog: false,
      showAboutDialog: false,
      showSettingsDialog: false,
      showEvidenceBundleDialog: false,
      showGuidRegistryDialog: false,
      showMergeTabsDialog: false,
      showDiffConfigDialog: false,
      showFileAssociationPrompt: false,
      showCollectDiagnosticsDialog: false,
      showUpdateDialog: false,
      collectionResult: null,
      elevationPrompt: null,
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("opens Find with Ctrl+F and walks matches with F3 / Shift+F3", () => {
    render(<Harness />);

    fireEvent.keyDown(window, { key: "f", ctrlKey: true });
    expect(actions.showFindBar).toHaveBeenCalled();

    fireEvent.keyDown(window, { key: "F3" });
    expect(actions.findNext).toHaveBeenCalledWith("keyboard.f3");

    fireEvent.keyDown(window, { key: "F3", shiftKey: true });
    expect(actions.findPrevious).toHaveBeenCalledWith("keyboard.shift-f3");
  });

  it("does not steal find shortcuts while a modal dialog is open", () => {
    useUiStore.setState({ showErrorLookupDialog: true });
    render(<Harness />);

    fireEvent.keyDown(window, { key: "f", ctrlKey: true });
    fireEvent.keyDown(window, { key: "F3" });
    expect(actions.showFindBar).not.toHaveBeenCalled();
    expect(actions.findNext).not.toHaveBeenCalled();
  });
});

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DsregcmdToolbarAction } from "./DsregcmdToolbarAction";
import { DsregcmdWorkspace } from "./DsregcmdWorkspace";
import { dsregcmdWorkspace } from "./index";
import { useDsregcmdStore } from "./dsregcmd-store";

const actions = vi.hoisted(() => ({
  openSourceFileDialog: vi.fn().mockResolvedValue(undefined),
  openSourceFolderDialog: vi.fn().mockResolvedValue(undefined),
  pasteDsregcmdSource: vi.fn().mockResolvedValue(undefined),
  captureDsregcmdSource: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    ...actions,
    commandState: { canRefresh: false },
    refreshActiveSource: vi.fn(),
  }),
}));

beforeEach(() => {
  vi.clearAllMocks();
  useDsregcmdStore.getState().clear();
});

afterEach(() => {
  cleanup();
  useDsregcmdStore.getState().clear();
});

describe("DsregcmdToolbarAction", () => {
  it("is registered as the dsregcmd workspace toolbar action", () => {
    expect(dsregcmdWorkspace.toolbarAction).toBeDefined();
  });

  it("runs a live capture from the primary 'Capture now' button", () => {
    render(<DsregcmdToolbarAction />);
    fireEvent.click(screen.getByRole("button", { name: "Capture now" }));
    expect(actions.captureDsregcmdSource).toHaveBeenCalledTimes(1);
  });

  it("offers Paste, Open text file... and Open evidence folder... in the split menu", async () => {
    render(<DsregcmdToolbarAction />);
    fireEvent.click(screen.getByRole("button", { name: "More capture options" }));

    fireEvent.click(await screen.findByRole("menuitem", { name: "Paste" }));
    expect(actions.pasteDsregcmdSource).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "More capture options" }));
    fireEvent.click(
      await screen.findByRole("menuitem", { name: "Open text file..." }),
    );
    expect(actions.openSourceFileDialog).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "More capture options" }));
    fireEvent.click(
      await screen.findByRole("menuitem", { name: "Open evidence folder..." }),
    );
    expect(actions.openSourceFolderDialog).toHaveBeenCalledTimes(1);
  });

  it("routes the inline links to the same handlers", () => {
    render(<DsregcmdToolbarAction />);
    fireEvent.click(screen.getByRole("button", { name: "Paste from clipboard" }));
    fireEvent.click(screen.getByRole("button", { name: "Open file" }));
    fireEvent.click(screen.getByRole("button", { name: "Open folder" }));
    expect(actions.pasteDsregcmdSource).toHaveBeenCalledTimes(1);
    expect(actions.openSourceFileDialog).toHaveBeenCalledTimes(1);
    expect(actions.openSourceFolderDialog).toHaveBeenCalledTimes(1);
  });

  it("disables every control while analyzing", () => {
    useDsregcmdStore.setState({ isAnalyzing: true });
    render(<DsregcmdToolbarAction />);
    for (const name of [
      "Capture now",
      "More capture options",
      "Paste from clipboard",
      "Open file",
      "Open folder",
    ]) {
      expect(screen.getByRole("button", { name })).toBeDisabled();
    }
    fireEvent.click(screen.getByRole("button", { name: "Capture now" }));
    expect(actions.captureDsregcmdSource).not.toHaveBeenCalled();
  });
});

describe("DsregcmdWorkspace without its own header", () => {
  it("renders no header row in the empty state", () => {
    render(<DsregcmdWorkspace />);
    expect(screen.queryByText("dsregcmd Workspace")).toBeNull();
    expect(screen.queryByRole("button", { name: "Capture" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Paste" })).toBeNull();
    expect(screen.getByText("No dsregcmd source loaded")).toBeInTheDocument();
  });
});

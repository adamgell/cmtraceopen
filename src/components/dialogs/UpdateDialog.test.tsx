import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { UpdateInfo } from "../../hooks/use-update-checker";
import { UpdateDialog } from "./UpdateDialog";

function renderDialog(
  overrides: {
    isOpen?: boolean;
    onClose?: () => void;
    updateInfo?: UpdateInfo | null;
    isChecking?: boolean;
    isDownloading?: boolean;
    downloadProgress?: number;
    onCheckForUpdates?: () => Promise<UpdateInfo | null>;
    onDownloadAndInstall?: () => void;
    onOpenReleasePage?: () => void;
    onSkipVersion?: (version: string) => void;
  } = {},
) {
  const props = {
    isOpen: true,
    onClose: vi.fn(),
    updateInfo: null as UpdateInfo | null,
    isChecking: false,
    isDownloading: false,
    downloadProgress: 0,
    onCheckForUpdates: vi.fn().mockResolvedValue(null),
    onDownloadAndInstall: vi.fn(),
    onOpenReleasePage: vi.fn(),
    onSkipVersion: vi.fn(),
    ...overrides,
  };
  const rendered = render(<UpdateDialog {...props} />);
  return { props, ...rendered };
}

const availableUpdate = (overrides: Partial<UpdateInfo> = {}): UpdateInfo => ({
  available: true,
  currentVersion: "1.3.1",
  newVersion: "1.3.2",
  updateChannel: "stable",
  canAutoUpdate: true,
  releaseNotes: "Bug fixes",
  ...overrides,
});

describe("UpdateDialog", () => {
  it("exposes a dialog landmark when open", () => {
    renderDialog({ isChecking: true });
    const dialog = screen.getByRole("dialog", { name: "Check for Updates" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("traps focus and restores the opener when closed", () => {
    const opener = document.createElement("button");
    document.body.appendChild(opener);
    opener.focus();

    const { rerender } = renderDialog({ isChecking: true });
    const dialog = screen.getByRole("dialog", { name: "Check for Updates" });
    const cancel = screen.getByRole("button", { name: "Cancel" });

    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(document.activeElement).toBe(cancel);

    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(cancel);
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(cancel);

    opener.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(cancel);

    rerender(
      <UpdateDialog
        isOpen={false}
        onClose={vi.fn()}
        updateInfo={null}
        isChecking={false}
        isDownloading={false}
        downloadProgress={0}
        onCheckForUpdates={vi.fn().mockResolvedValue(null)}
        onDownloadAndInstall={vi.fn()}
        onOpenReleasePage={vi.fn()}
        onSkipVersion={vi.fn()}
      />,
    );
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });

  it("shows Cancel while checking", () => {
    const { props } = renderDialog({ isChecking: true });

    expect(screen.getByText("Check for Updates")).toBeVisible();
    expect(screen.getByText("Checking for updates...")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(props.onClose).toHaveBeenCalledOnce();
  });

  it("shows Skip, Later, and Download & install when an auto-update is available", () => {
    const { props } = renderDialog({ updateInfo: availableUpdate() });

    expect(screen.getByText("Update Available")).toBeVisible();
    expect(screen.getByText(/Main channel/)).toBeVisible();
    expect(screen.getByText("Bug fixes")).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Skip this version" }));
    expect(props.onSkipVersion).toHaveBeenCalledWith("1.3.2");

    fireEvent.click(screen.getByRole("button", { name: "Later" }));
    expect(props.onClose).toHaveBeenCalledOnce();

    fireEvent.click(screen.getByRole("button", { name: "Download & install" }));
    expect(props.onDownloadAndInstall).toHaveBeenCalledOnce();
  });

  it("offers GitHub download when auto-update is unavailable", () => {
    const { props } = renderDialog({
      updateInfo: availableUpdate({ canAutoUpdate: false }),
    });

    fireEvent.click(screen.getByRole("button", { name: "Download from GitHub..." }));
    expect(props.onOpenReleasePage).toHaveBeenCalledOnce();
    expect(
      screen.queryByRole("button", { name: "Download & install" }),
    ).not.toBeInTheDocument();
  });

  it("shows download percent and ignores Escape while downloading", () => {
    const { props } = renderDialog({
      isDownloading: true,
      downloadProgress: 0.42,
    });

    expect(screen.getByText("Downloading Update")).toBeVisible();
    expect(screen.getByText("42%")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument();

    fireEvent.keyDown(window, { key: "Escape" });
    expect(props.onClose).not.toHaveBeenCalled();
  });

  it("shows OK when the app is up to date", () => {
    const { props } = renderDialog({
      updateInfo: {
        available: false,
        currentVersion: "1.3.1",
        updateChannel: "stable",
        canAutoUpdate: true,
      },
    });

    expect(
      screen.getByText("You're running the latest version (v1.3.1)."),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "OK" }));
    expect(props.onClose).toHaveBeenCalledOnce();
  });

  it("shows OK when the check fails", () => {
    const { props } = renderDialog({
      updateInfo: {
        available: false,
        currentVersion: "1.3.1",
        updateChannel: "stable",
        canAutoUpdate: true,
        error: "network down",
      },
    });

    expect(
      screen.getByText("Unable to check for updates: network down"),
    ).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "OK" }));
    expect(props.onClose).toHaveBeenCalledOnce();
  });

  it("does not render when closed", () => {
    renderDialog({ isOpen: false, isChecking: true });
    expect(screen.queryByText("Check for Updates")).not.toBeInTheDocument();
  });
});

import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FileAssociationsTab } from "./FileAssociationsTab";
import { FileAssociationPromptDialog } from "../FileAssociationPromptDialog";
import { useUiStore } from "../../../stores/ui-store";
import {
  getFileAssociationPromptStatus,
  openWindowsDefaultApps,
  registerLogFileHandler,
} from "../../../lib/commands";

vi.mock("../../../lib/commands", () => ({
  getSafeErrorMessage: (error: unknown, fallback = "Unknown error") =>
    error instanceof Error ? error.message : fallback,
  getFileAssociationPromptStatus: vi.fn(),
  openWindowsDefaultApps: vi.fn(),
  registerLogFileHandler: vi.fn(),
  setFileAssociationPromptSuppressed: vi.fn(),
}));

describe("FileAssociationsTab", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState(useUiStore.getInitialState(), true);
    vi.mocked(getFileAssociationPromptStatus).mockResolvedValue({
      supported: true,
      shouldPrompt: false,
      isRegistered: false,
    });
    vi.mocked(registerLogFileHandler).mockResolvedValue(undefined);
    vi.mocked(openWindowsDefaultApps).mockResolvedValue(undefined);
  });

  afterEach(() => {
    cleanup();
  });

  it("shows a static note off Windows", () => {
    useUiStore.setState({ currentPlatform: "macos" });
    render(<FileAssociationsTab />);
    expect(
      screen.getByText(/File associations are only available on Windows/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: "Register CMTrace Open as an available handler",
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Open Windows Default Apps" }),
    ).not.toBeInTheDocument();
  });

  it("registers only an available handler and routes default choice to Windows", async () => {
    useUiStore.setState({ currentPlatform: "windows" });
    render(<FileAssociationsTab />);
    expect(
      await screen.findByRole("button", {
        name: "Register CMTrace Open as an available handler",
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Open Windows Default Apps" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Windows keeps your current defaults until you choose CMTrace Open/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/default handler/i)).not.toBeInTheDocument();
  });

  it("registers the handler and lets the user open the Windows-owned picker", async () => {
    useUiStore.setState({ currentPlatform: "windows" });
    render(<FileAssociationsTab />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Register CMTrace Open as an available handler",
      }),
    );

    await waitFor(() => {
      expect(registerLogFileHandler).toHaveBeenCalledTimes(1);
    });
    expect(
      screen.getByText(/CMTrace Open is now available to choose in Windows Default Apps/),
    ).toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Open Windows Default Apps" }),
    );

    await waitFor(() => {
      expect(openWindowsDefaultApps).toHaveBeenCalledTimes(1);
    });
  });
});

describe("FileAssociationPromptDialog", () => {
  afterEach(() => {
    cleanup();
  });

  it("exposes a dialog landmark when open", () => {
    render(<FileAssociationPromptDialog isOpen onClose={() => {}} />);
    const dialog = screen.getByRole("dialog", {
      name: "Make CMTrace Open available for log files?",
    });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("explains registration without claiming to replace the Windows default", () => {
    render(<FileAssociationPromptDialog isOpen onClose={vi.fn()} />);
    expect(
      screen.getByText(/Make CMTrace Open available for log files/),
    ).toBeInTheDocument();
    expect(screen.getByText(/\.cmtlog/)).toBeInTheDocument();
    expect(
      screen.getByText(/Windows keeps your current defaults until you choose CMTrace Open/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Register and open Default Apps" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Don't Ask Again" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask Later" })).toBeInTheDocument();
  });
});

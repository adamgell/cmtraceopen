import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getFileAssociationPromptStatus,
  openWindowsDefaultApps,
  registerLogFileHandler,
  setFileAssociationPromptSuppressed,
} from "../../lib/commands";
import { FileAssociationPromptDialog } from "./FileAssociationPromptDialog";

vi.mock("../../lib/commands", () => ({
  getSafeErrorMessage: (error: unknown, fallback = "Unknown error") =>
    error instanceof Error ? error.message : fallback,
  getFileAssociationPromptStatus: vi.fn(),
  openWindowsDefaultApps: vi.fn(),
  registerLogFileHandler: vi.fn(),
  setFileAssociationPromptSuppressed: vi.fn(),
}));

describe("FileAssociationPromptDialog", () => {
  let opener: HTMLButtonElement;

  beforeEach(() => {
    vi.clearAllMocks();
    opener = document.createElement("button");
    document.body.appendChild(opener);
    opener.focus();
  });

  afterEach(() => {
    opener.remove();
  });
  it("traps focus and restores the opener when closed", () => {
    vi.mocked(registerLogFileHandler).mockResolvedValue(undefined);
    vi.mocked(openWindowsDefaultApps).mockResolvedValue(undefined);
    vi.mocked(setFileAssociationPromptSuppressed).mockResolvedValue(undefined);
    const rendered = render(
      <FileAssociationPromptDialog isOpen onClose={() => {}} />,
    );
    const dialog = screen.getByRole("dialog");
    const buttons = within(dialog).getAllByRole("button");
    const first = buttons[0];
    const last = buttons[buttons.length - 1];
    expect(document.activeElement).toBe(first);

    last.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(first);
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);

    opener.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(first);

    opener.focus();
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);
    rendered.rerender(
      <FileAssociationPromptDialog isOpen={false} onClose={() => {}} />,
    );
    expect(document.activeElement).toBe(opener);
  });

  it("keeps focus on the dialog surface while submission disables its controls", () => {
    vi.mocked(registerLogFileHandler).mockReturnValue(
      new Promise<void>(() => {}),
    );
    const rendered = render(
      <FileAssociationPromptDialog isOpen onClose={() => {}} />,
    );
    const dialog = screen.getByRole("dialog");
    const associate = within(dialog).getByRole("button", {
      name: "Register and open Default Apps",
    });

    associate.focus();
    fireEvent.click(associate);

    expect(associate).toBeDisabled();
    expect(document.activeElement).toBe(dialog);
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(dialog);

    rendered.rerender(
      <FileAssociationPromptDialog isOpen={false} onClose={() => {}} />,
    );
    expect(document.activeElement).toBe(opener);
  });

  it("registers before opening the Windows-owned default picker", async () => {
    vi.mocked(registerLogFileHandler).mockResolvedValue(undefined);
    vi.mocked(getFileAssociationPromptStatus).mockResolvedValue({
      supported: true,
      shouldPrompt: false,
      isRegistered: true,
    });
    vi.mocked(openWindowsDefaultApps).mockResolvedValue(undefined);
    const onClose = vi.fn();
    render(<FileAssociationPromptDialog isOpen onClose={onClose} />);

    fireEvent.click(
      screen.getByRole("button", { name: "Register and open Default Apps" }),
    );

    await vi.waitFor(() => {
      expect(openWindowsDefaultApps).toHaveBeenCalledTimes(1);
    });
    expect(registerLogFileHandler).toHaveBeenCalledTimes(1);
    expect(getFileAssociationPromptStatus).toHaveBeenCalledTimes(1);
    expect(
      vi.mocked(registerLogFileHandler).mock.invocationCallOrder[0],
    ).toBeLessThan(
      vi.mocked(getFileAssociationPromptStatus).mock.invocationCallOrder[0],
    );
    expect(
      vi.mocked(getFileAssociationPromptStatus).mock.invocationCallOrder[0],
    ).toBeLessThan(vi.mocked(openWindowsDefaultApps).mock.invocationCallOrder[0]);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("retains the prompt when post-registration readback is false", async () => {
    vi.mocked(registerLogFileHandler).mockResolvedValue(undefined);
    vi.mocked(getFileAssociationPromptStatus).mockResolvedValue({
      supported: true,
      shouldPrompt: true,
      isRegistered: false,
    });
    const onClose = vi.fn();
    render(<FileAssociationPromptDialog isOpen onClose={onClose} />);

    fireEvent.click(
      screen.getByRole("button", { name: "Register and open Default Apps" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /registration could not be confirmed/i,
    );
    expect(openWindowsDefaultApps).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it("retains the prompt when post-registration readback fails", async () => {
    vi.mocked(registerLogFileHandler).mockResolvedValue(undefined);
    vi.mocked(getFileAssociationPromptStatus).mockRejectedValue(
      new Error("registry read denied"),
    );
    const onClose = vi.fn();
    render(<FileAssociationPromptDialog isOpen onClose={onClose} />);

    fireEvent.click(
      screen.getByRole("button", { name: "Register and open Default Apps" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /could not be confirmed.*registry read denied/i,
    );
    expect(openWindowsDefaultApps).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });
});

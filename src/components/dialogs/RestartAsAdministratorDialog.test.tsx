import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RestartAsAdministratorDialog } from "./RestartAsAdministratorDialog";
import { useUiStore } from "../../stores/ui-store";
import { requestElevatedRestart } from "../../lib/elevation";
import type { ElevationRequest } from "../../types/elevation";

vi.mock("../../lib/elevation", async () => {
  const actual = await vi.importActual<typeof import("../../lib/elevation")>(
    "../../lib/elevation",
  );
  return { ...actual, requestElevatedRestart: vi.fn() };
});

const requestElevatedRestartMock = vi.mocked(requestElevatedRestart);

const FILE_REQUEST: ElevationRequest = {
  reason: "accessDenied",
  workspace: "log",
  target: { kind: "file", path: "C:\\Windows\\Logs\\CBS.log" },
};

function openPrompt(request: ElevationRequest = FILE_REQUEST) {
  useUiStore.getState().setElevationPrompt({ request });
}

describe("RestartAsAdministratorDialog", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.getState().setElevationPrompt(null);
    requestElevatedRestartMock.mockResolvedValue({ status: "launched" });
  });

  it("renders nothing until a prompt is requested", () => {
    render(<RestartAsAdministratorDialog />);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("describes the restore target without leaking the full path", () => {
    openPrompt();
    render(<RestartAsAdministratorDialog />);

    expect(screen.getByRole("dialog")).toBeVisible();
    expect(screen.getByText(/CBS\.log/)).toBeVisible();
    expect(screen.queryByText(/C:\\Windows\\Logs/)).toBeNull();
  });

  it("makes no backend call when the user cancels", async () => {
    openPrompt();
    render(<RestartAsAdministratorDialog />);

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    expect(requestElevatedRestartMock).not.toHaveBeenCalled();
    expect(useUiStore.getState().elevationPrompt).toBeNull();
  });

  it("requests elevation once even when the button is double-clicked", async () => {
    openPrompt();
    render(<RestartAsAdministratorDialog />);

    const confirm = screen.getByRole("button", {
      name: "Restart as administrator",
    });
    fireEvent.click(confirm);
    fireEvent.click(confirm);

    await waitFor(() => {
      expect(requestElevatedRestartMock).toHaveBeenCalledTimes(1);
    });
    expect(requestElevatedRestartMock).toHaveBeenCalledWith(FILE_REQUEST);
  });

  it("keeps the dialog pending after a successful launch", async () => {
    openPrompt();
    render(<RestartAsAdministratorDialog />);

    fireEvent.click(
      screen.getByRole("button", { name: "Restart as administrator" }),
    );

    // The process is exiting; the prompt must not flash closed first.
    await waitFor(() => {
      expect(screen.getByRole("button", { name: "Requesting…" })).toBeVisible();
    });
    expect(useUiStore.getState().elevationPrompt).not.toBeNull();
  });

  it("closes without an error when the user cancels the UAC prompt", async () => {
    requestElevatedRestartMock.mockResolvedValue({ status: "cancelled" });
    openPrompt();
    render(<RestartAsAdministratorDialog />);

    fireEvent.click(
      screen.getByRole("button", { name: "Restart as administrator" }),
    );

    await waitFor(() => {
      expect(useUiStore.getState().elevationPrompt).toBeNull();
    });
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("moves focus into the modal and restores it to the opener on close", async () => {
    const opener = document.createElement("button");
    opener.textContent = "behind the modal";
    document.body.appendChild(opener);
    opener.focus();
    expect(document.activeElement).toBe(opener);

    openPrompt();
    const { rerender } = render(<RestartAsAdministratorDialog />);

    // aria-modal is a promise to assistive tech, not an implementation: without
    // this the keyboard user stays parked on the content behind the overlay.
    const dialog = screen.getByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    rerender(<RestartAsAdministratorDialog />);

    await waitFor(() => expect(document.activeElement).toBe(opener));
    opener.remove();
  });

  it("cycles Tab inside the modal instead of leaking to the page behind", () => {
    const outside = document.createElement("button");
    outside.textContent = "behind the modal";
    document.body.appendChild(outside);

    openPrompt();
    render(<RestartAsAdministratorDialog />);

    const cancel = screen.getByRole("button", { name: "Cancel" });
    const confirm = screen.getByRole("button", {
      name: "Restart as administrator",
    });

    // Forward past the last control wraps to the first, never to `outside`.
    confirm.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(cancel);

    // And backwards past the first wraps to the last.
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(confirm);

    // Focus parked outside the modal is pulled back in.
    outside.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(cancel);

    outside.remove();
  });

  it("shows a recoverable failure and keeps the dialog usable", async () => {
    requestElevatedRestartMock.mockResolvedValue({
      status: "failed",
      message: "Administrator restart could not be started.",
    });
    openPrompt();
    render(<RestartAsAdministratorDialog />);

    fireEvent.click(
      screen.getByRole("button", { name: "Restart as administrator" }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Administrator restart could not be started.",
    );
    // Still open, so the user can retry or cancel rather than losing the app.
    expect(useUiStore.getState().elevationPrompt).not.toBeNull();
    expect(
      screen.getByRole("button", { name: "Restart as administrator" }),
    ).toBeEnabled();
  });
});

import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import {
  associateLogFilesWithApp,
  setFileAssociationPromptSuppressed,
} from "../../lib/commands";
import { FileAssociationPromptDialog } from "./FileAssociationPromptDialog";

vi.mock("../../lib/commands", () => ({
  associateLogFilesWithApp: vi.fn(),
  setFileAssociationPromptSuppressed: vi.fn(),
}));

describe("FileAssociationPromptDialog", () => {
  it("traps focus and restores the opener when closed", () => {
    vi.mocked(associateLogFilesWithApp).mockResolvedValue(undefined);
    vi.mocked(setFileAssociationPromptSuppressed).mockResolvedValue(undefined);

    const opener = document.createElement("button");
    document.body.appendChild(opener);
    opener.focus();

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

    rendered.rerender(
      <FileAssociationPromptDialog isOpen={false} onClose={() => {}} />,
    );
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });
});

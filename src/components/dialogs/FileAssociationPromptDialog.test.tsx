import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
  let opener: HTMLButtonElement;

  beforeEach(() => {
    opener = document.createElement("button");
    document.body.appendChild(opener);
    opener.focus();
  });

  afterEach(() => {
    opener.remove();
  });
  it("traps focus and restores the opener when closed", () => {
    vi.mocked(associateLogFilesWithApp).mockResolvedValue(undefined);
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
    vi.mocked(associateLogFilesWithApp).mockReturnValue(
      new Promise<void>(() => {}),
    );


    const rendered = render(
      <FileAssociationPromptDialog isOpen onClose={() => {}} />,
    );
    const dialog = screen.getByRole("dialog");
    const associate = within(dialog).getByRole("button", { name: "Associate" });

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
});

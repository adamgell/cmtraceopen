import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FilterDialog } from "./FilterDialog";

describe("FilterDialog", () => {
  it("exposes a dialog landmark when open", () => {
    render(
      <FilterDialog
        isOpen
        onClose={() => {}}
        onApply={async () => undefined}
        currentClauses={[]}
      />,
    );

    const dialog = screen.getByRole("dialog", { name: "Filter" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("traps focus and restores the opener when closed", () => {
    const opener = document.createElement("button");
    document.body.appendChild(opener);
    opener.focus();

    const rendered = render(
      <FilterDialog
        isOpen
        onClose={() => {}}
        onApply={async () => undefined}
        currentClauses={[]}
      />,
    );
    const dialog = screen.getByRole("dialog", { name: "Filter" });
    const input = dialog.querySelector("input");
    const tabWrapTarget = dialog.querySelector("select");
    const close = screen.getByRole("button", { name: "Cancel" });

    expect(input).not.toBeNull();
    expect(tabWrapTarget).not.toBeNull();
    expect(document.activeElement).toBe(input);

    close.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(tabWrapTarget);
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(close);

    opener.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(tabWrapTarget);

    rendered.rerender(
      <FilterDialog
        isOpen={false}
        onClose={() => {}}
        onApply={async () => undefined}
        currentClauses={[]}
      />,
    );
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });
});

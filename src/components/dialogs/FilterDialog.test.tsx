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

  it("traps focus and restores focus to the opener", () => {
    const opener = document.createElement("button");
    document.body.append(opener);
    opener.focus();

    const view = render(
      <FilterDialog
        isOpen
        onClose={() => {}}
        onApply={async () => undefined}
        currentClauses={[]}
      />,
    );
    const dialog = screen.getByRole("dialog", { name: "Filter" });
    const focusable = Array.from(
      dialog.querySelectorAll<HTMLElement>("button, input, select"),
    );
    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    expect(dialog.contains(document.activeElement)).toBe(true);
    last?.focus();
    fireEvent.keyDown(window, { key: "Tab" });
    expect(document.activeElement).toBe(first);

    first?.focus();
    fireEvent.keyDown(window, { key: "Tab", shiftKey: true });
    expect(document.activeElement).toBe(last);

    view.unmount();
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });
});

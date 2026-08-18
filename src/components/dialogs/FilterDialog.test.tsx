import { render, screen } from "@testing-library/react";
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
});

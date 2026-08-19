import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { useUiStore } from "../../../stores/ui-store";
import { BehaviorTab } from "./BehaviorTab";

describe("BehaviorTab", () => {
  beforeEach(() => {
    useUiStore.setState({
      defaultShowInfoPane: true,
      confirmTabClose: false,
    });
  });

  it("shows the info-pane and tab-close checkboxes", () => {
    render(<BehaviorTab />);

    const infoPane = screen.getByRole("checkbox", {
      name: /show info pane by default/i,
    });
    const confirmClose = screen.getByRole("checkbox", {
      name: /confirm before closing tabs/i,
    });

    expect(infoPane).toBeChecked();
    expect(confirmClose).not.toBeChecked();
  });

  it("writes checkbox changes to the store", () => {
    render(<BehaviorTab />);

    fireEvent.click(
      screen.getByRole("checkbox", { name: /show info pane by default/i }),
    );
    fireEvent.click(
      screen.getByRole("checkbox", { name: /confirm before closing tabs/i }),
    );

    expect(useUiStore.getState().defaultShowInfoPane).toBe(false);
    expect(useUiStore.getState().confirmTabClose).toBe(true);
  });
});

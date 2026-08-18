import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";
import { useUiStore } from "../../../stores/ui-store";
import { ColumnsTab } from "./ColumnsTab";

describe("ColumnsTab", () => {
  beforeEach(() => {
    useUiStore.setState({
      columnOrder: null,
      columnWidths: {},
    });
  });

  it("reports default column order and widths", () => {
    render(<ColumnsTab />);

    expect(
      screen.getByText("Using default column order and widths."),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Reset to Defaults" }),
    ).not.toBeInTheDocument();
  });

  it("reports custom order and widths and Reset to Defaults clears them", () => {
    useUiStore.setState({
      columnOrder: ["dateTime", "message", "component"],
      columnWidths: { message: 420, component: 160 },
    });

    render(<ColumnsTab />);

    expect(screen.getByText("Custom column order is active.")).toBeVisible();
    expect(
      screen.getByText("Custom column widths are active (2 columns)."),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Reset to Defaults" }));

    expect(useUiStore.getState().columnOrder).toBeNull();
    expect(useUiStore.getState().columnWidths).toEqual({});
    expect(
      screen.getByText("Using default column order and widths."),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Reset to Defaults" }),
    ).not.toBeInTheDocument();
  });
});

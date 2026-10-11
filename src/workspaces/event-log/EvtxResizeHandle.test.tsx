import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EvtxResizeHandle } from "./EvtxResizeHandle";

function renderHandle(
  overrides: Partial<React.ComponentProps<typeof EvtxResizeHandle>> = {},
) {
  const onChange = vi.fn();
  render(
    <div style={{ position: "relative" }}>
      <EvtxResizeHandle
        orientation="vertical"
        edge="start"
        label="Resize test region"
        controls="region-id"
        value={340}
        min={280}
        max={480}
        direction={-1}
        onChange={onChange}
        {...overrides}
      />
    </div>,
  );
  return { onChange, handle: screen.getByRole("separator", { name: "Resize test region" }) };
}

describe("EvtxResizeHandle", () => {
  afterEach(() => {
    cleanup();
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  });

  it("names the region it sizes and reports its range", () => {
    const { handle } = renderHandle();
    expect(handle).toHaveAttribute("aria-controls", "region-id");
    expect(handle).toHaveAttribute("aria-orientation", "vertical");
    expect(handle).toHaveAttribute("aria-valuenow", "340");
    expect(handle).toHaveAttribute("aria-valuemin", "280");
    expect(handle).toHaveAttribute("aria-valuemax", "480");
    expect(handle.tabIndex).toBe(0);
  });

  it("drags toward the region to grow it when direction is -1, and releases the cursor", () => {
    const { onChange, handle } = renderHandle({ direction: -1 });
    fireEvent.mouseDown(handle, { clientX: 500 });
    expect(document.body.style.cursor).toBe("col-resize");
    fireEvent.mouseMove(window, { clientX: 460 });
    expect(onChange).toHaveBeenLastCalledWith(380);
    fireEvent.mouseMove(window, { clientX: 520 });
    expect(onChange).toHaveBeenLastCalledWith(320);
    fireEvent.mouseUp(window);
    expect(document.body.style.cursor).toBe("");
    onChange.mockClear();
    fireEvent.mouseMove(window, { clientX: 100 });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("drags away from the region to grow it when direction is +1", () => {
    const { onChange, handle } = renderHandle({ direction: 1, value: 250, min: 200, max: 500 });
    fireEvent.mouseDown(handle, { clientX: 250 });
    fireEvent.mouseMove(window, { clientX: 300 });
    expect(onChange).toHaveBeenLastCalledWith(300);
    fireEvent.mouseUp(window);
  });

  it("drags on the Y axis for a horizontal separator", () => {
    const { onChange, handle } = renderHandle({
      orientation: "horizontal",
      direction: -1,
      value: 210,
      min: 160,
      max: 450,
    });
    fireEvent.mouseDown(handle, { clientY: 600 });
    expect(document.body.style.cursor).toBe("row-resize");
    fireEvent.mouseMove(window, { clientY: 560 });
    expect(onChange).toHaveBeenLastCalledWith(250);
    fireEvent.mouseUp(window);
  });

  it("makes arrow keys follow direction -1 like the drag does", () => {
    const { onChange, handle } = renderHandle({ direction: -1 });
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    expect(onChange).toHaveBeenLastCalledWith(356);
    fireEvent.keyDown(handle, { key: "ArrowRight" });
    expect(onChange).toHaveBeenLastCalledWith(324);
  });

  it("makes arrow keys follow direction +1 like the drag does", () => {
    const { onChange, handle } = renderHandle({ direction: 1 });
    fireEvent.keyDown(handle, { key: "ArrowRight" });
    expect(onChange).toHaveBeenLastCalledWith(356);
    fireEvent.keyDown(handle, { key: "ArrowLeft" });
    expect(onChange).toHaveBeenLastCalledWith(324);
  });

  it("uses Up and Down on a horizontal separator and Home and End for the bounds", () => {
    const { onChange, handle } = renderHandle({ orientation: "horizontal", direction: -1 });
    fireEvent.keyDown(handle, { key: "ArrowUp" });
    expect(onChange).toHaveBeenLastCalledWith(356);
    fireEvent.keyDown(handle, { key: "ArrowDown" });
    expect(onChange).toHaveBeenLastCalledWith(324);
    fireEvent.keyDown(handle, { key: "Home" });
    expect(onChange).toHaveBeenLastCalledWith(280);
    fireEvent.keyDown(handle, { key: "End" });
    expect(onChange).toHaveBeenLastCalledWith(480);
  });

  it("sits on the requested edge of its positioned wrapper", () => {
    const { handle } = renderHandle({ edge: "end" });
    expect(handle.style.right).toBe("-3px");
    cleanup();
    const { handle: start } = renderHandle({ edge: "start" });
    expect(start.style.left).toBe("-3px");
  });
});

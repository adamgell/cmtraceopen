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
    fireEvent.pointerDown(handle, { clientX: 500, button: 0, isPrimary: true, pointerId: 1 });
    expect(document.body.style.cursor).toBe("col-resize");
    fireEvent.pointerMove(handle, { clientX: 460, buttons: 1, pointerId: 1 });
    expect(onChange).toHaveBeenLastCalledWith(380);
    fireEvent.pointerMove(handle, { clientX: 520, buttons: 1, pointerId: 1 });
    expect(onChange).toHaveBeenLastCalledWith(320);
    fireEvent.pointerUp(handle, { pointerId: 1 });
    expect(document.body.style.cursor).toBe("");
    onChange.mockClear();
    fireEvent.pointerMove(handle, { clientX: 100, buttons: 1, pointerId: 1 });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("drags away from the region to grow it when direction is +1", () => {
    const { onChange, handle } = renderHandle({ direction: 1, value: 250, min: 200, max: 500 });
    fireEvent.pointerDown(handle, { clientX: 250, button: 0, isPrimary: true, pointerId: 1 });
    fireEvent.pointerMove(handle, { clientX: 300, buttons: 1, pointerId: 1 });
    expect(onChange).toHaveBeenLastCalledWith(300);
    fireEvent.pointerUp(handle, { pointerId: 1 });
  });

  it("drags on the Y axis for a horizontal separator", () => {
    const { onChange, handle } = renderHandle({
      orientation: "horizontal",
      direction: -1,
      value: 210,
      min: 160,
      max: 450,
    });
    fireEvent.pointerDown(handle, { clientY: 600, button: 0, isPrimary: true, pointerId: 1 });
    expect(document.body.style.cursor).toBe("row-resize");
    fireEvent.pointerMove(handle, { clientY: 560, buttons: 1, pointerId: 1 });
    expect(onChange).toHaveBeenLastCalledWith(250);
    fireEvent.pointerUp(handle, { pointerId: 1 });
  });

  it("captures the pointer on a primary press only, and disables touch panning", () => {
    const capture = vi.fn();
    const original = HTMLElement.prototype.setPointerCapture;
    HTMLElement.prototype.setPointerCapture = capture;
    try {
      const { handle } = renderHandle();
      expect(handle.style.touchAction).toBe("none");
      fireEvent.pointerDown(handle, { button: 2, isPrimary: true, pointerId: 7 });
      expect(capture).not.toHaveBeenCalled();
      fireEvent.pointerDown(handle, { button: 0, isPrimary: true, pointerId: 7 });
      expect(capture).toHaveBeenCalledWith(7);
    } finally {
      HTMLElement.prototype.setPointerCapture = original;
    }
  });

  it("does not arm a drag from a right-click or a non-primary pointer", () => {
    const { onChange, handle } = renderHandle();
    fireEvent.pointerDown(handle, { clientX: 500, button: 2, isPrimary: true, pointerId: 1 });
    expect(document.body.style.cursor).toBe("");
    fireEvent.pointerMove(handle, { clientX: 400, buttons: 2, pointerId: 1 });
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.pointerDown(handle, { clientX: 500, button: 0, isPrimary: false, pointerId: 2 });
    fireEvent.pointerMove(handle, { clientX: 400, buttons: 1, pointerId: 2 });
    expect(onChange).not.toHaveBeenCalled();
  });

  it("ends a drag on window blur, on lost capture, and when no button is down", () => {
    const { onChange, handle } = renderHandle();
    const start = () =>
      fireEvent.pointerDown(handle, { clientX: 500, button: 0, isPrimary: true, pointerId: 1 });

    start();
    fireEvent.blur(window);
    expect(document.body.style.cursor).toBe("");
    fireEvent.pointerMove(handle, { clientX: 400, buttons: 1, pointerId: 1 });
    expect(onChange).not.toHaveBeenCalled();

    start();
    fireEvent.lostPointerCapture(handle, { pointerId: 1 });
    fireEvent.pointerMove(handle, { clientX: 400, buttons: 1, pointerId: 1 });
    expect(onChange).not.toHaveBeenCalled();

    start();
    fireEvent.pointerMove(handle, { clientX: 400, buttons: 0, pointerId: 1 });
    expect(onChange).not.toHaveBeenCalled();
    expect(document.body.style.cursor).toBe("");
  });

  it("keeps a real outline on focus so it survives forced-colors mode", () => {
    const { handle } = renderHandle();
    const classes = handle.className.split(/\s+/).filter(Boolean);
    const css = Array.from(document.styleSheets)
      .flatMap((sheet) => Array.from(sheet.cssRules))
      .filter(
        (rule): rule is CSSStyleRule =>
          rule instanceof CSSStyleRule &&
          rule.selectorText.includes(":focus-visible") &&
          classes.some((name) => rule.selectorText.includes(`.${name}`)),
      )
      .map((rule) => rule.cssText)
      .join(" ");
    expect(css).toMatch(/outline-style:\s*solid/);
    expect(css).toMatch(/outline-width:\s*2px/);
    expect(css).toMatch(/outline-offset:\s*-2px/);
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

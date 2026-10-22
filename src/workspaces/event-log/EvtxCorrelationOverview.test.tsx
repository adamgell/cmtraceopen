/**
 * The overview strip draws what the pure layer decided and moves the band by the pointer and the
 * keyboard. The geometry is stubbed (jsdom has no layout): the box is 720 px wide at x = 100.
 */
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { useUiStore } from "../../stores/ui-store";
import { EvtxCorrelationOverview } from "./EvtxCorrelationOverview";
import { correlationSizes } from "./evtx-correlation-sizes";
import type { CorrelationChain, CorrelationChainStrength } from "./evtx-correlation-chains";
import {
  OVERVIEW_BAR_HEIGHT_PX,
  OVERVIEW_BOX_HEIGHT_PX,
  bandValueText,
  overviewDomain,
} from "./evtx-correlation-overview";
import { CORRELATION_MIN_WINDOW_MS, defaultLaneWindow, type TimeWindow } from "./evtx-correlation-view-model";
import { useEvtxStore } from "./evtx-store";
import overviewSource from "./EvtxCorrelationOverview.tsx?raw";

const S = 1_000;
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);
const LEFT = 100;
const WIDTH = 720;

function chain(
  id: string,
  strength: CorrelationChainStrength,
  startS: number | null,
  endS: number | null,
): CorrelationChain {
  return {
    id,
    strength,
    memberIds: [],
    unresolvedMemberIds: [],
    memberCount: 2,
    edges: [],
    keys: [],
    evidence: [],
    coverageGaps: [],
    startMs: startS === null ? null : T0 + startS * S,
    endMs: endS === null ? null : T0 + endS * S,
    title: null,
  };
}

/** A: 0 to 100 s (exact). B: 40 to 60 s (candidate). C: 400 to 500 s (ambiguous). D: no position. */
const chains = [
  chain("A", "exact", 0, 100),
  chain("B", "candidate", 40, 60),
  chain("C", "ambiguous", 400, 500),
  chain("D", "coverageBlocked", null, null),
];
const domain = overviewDomain(chains)!;
const win = (startS: number, endS: number): TimeWindow => ({ startMs: T0 + startS * S, endMs: T0 + endS * S });
/** Pixels across the stubbed box for a time. */
const xOf = (ms: number) => LEFT + ((ms - domain.startMs) / (domain.endMs - domain.startMs)) * WIDTH;
const msOf = (x: number) => domain.startMs + ((x - LEFT) / WIDTH) * (domain.endMs - domain.startMs);

type EvtxCorrelationOverviewProps = ComponentProps<typeof EvtxCorrelationOverview>;

let onWindowChange: ReturnType<typeof vi.fn>;

function mount(extra: Partial<EvtxCorrelationOverviewProps> = {}, sizes = correlationSizes(13)) {
  const props: EvtxCorrelationOverviewProps = {
    chains,
    selectedId: "A",
    window: defaultLaneWindow(chains[0]!.startMs, chains[0]!.endMs),
    onWindowChange: onWindowChange as unknown as EvtxCorrelationOverviewProps["onWindowChange"],
    timeZoneMode: "utc",
    sizes,
    ...extra,
  };
  const view = render(<EvtxCorrelationOverview {...props} />);
  const box = screen.getByTestId("overview-box");
  box.getBoundingClientRect = () =>
    ({ left: LEFT, top: 0, right: LEFT + WIDTH, bottom: 48, width: WIDTH, height: 48, x: LEFT, y: 0, toJSON: () => ({}) }) as DOMRect;
  return {
    ...view,
    box,
    rerenderWith: (next: Partial<EvtxCorrelationOverviewProps>) =>
      view.rerender(<EvtxCorrelationOverview {...props} {...next} />),
  };
}

const down = (target: Element, clientX: number, init: Record<string, unknown> = {}) =>
  fireEvent.pointerDown(target, { clientX, button: 0, buttons: 1, isPrimary: true, pointerId: 1, ...init });
const move = (target: Element, clientX: number, buttons = 1) =>
  fireEvent.pointerMove(target, { clientX, buttons, pointerId: 1 });
const up = (target: Element, clientX: number) => fireEvent.pointerUp(target, { clientX, pointerId: 1 });
const key = (target: Element, name: string, init: Record<string, unknown> = {}) =>
  fireEvent.keyDown(target, { key: name, ...init });
const layer = (name: string) => [...document.querySelectorAll<HTMLElement>(`[data-evtx-layer="${name}"]`)];
const lastWindow = () => onWindowChange.mock.calls[onWindowChange.mock.calls.length - 1]?.[0] as TimeWindow | null;

beforeEach(() => {
  // The year rule compares a label's year with the real clock, so the clock is pinned to the
  // fixture's year for every test that reads clock text. Only Date is faked: timers stay real.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-16T12:00:00Z"));
  onWindowChange = vi.fn();
  useUiStore.setState({ themeId: "light", logListFontSize: 13 });
  useEvtxStore.setState({ timeRange: null });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("what it draws", () => {
  it("is a 48 px box of bars with the caption above it and the ticks below, and records the total", () => {
    mount();
    const box = screen.getByTestId("overview-box");
    expect(box.style.height).toBe("48px");
    expect(OVERVIEW_BOX_HEIGHT_PX).toBe(48);
    const caption = screen.getByTestId("overview-caption");
    const axis = screen.getByTestId("overview-axis");
    // f = 13: caption row at least 10 + 4 = 14 px (it wraps, so that is a minimum), 4 px gap, the 48 px
    // box, 2 px gap, tick row 9 + 6 = 15 px. The total is therefore at least 83 px.
    expect(caption.style.minHeight).toBe("14px");
    expect(caption.style.marginBottom).toBe("4px");
    expect(axis.style.height).toBe("15px");
    expect(axis.style.marginTop).toBe("2px");
    expect(14 + 4 + OVERVIEW_BOX_HEIGHT_PX + 2 + 15).toBe(83);
    // The caption is above the box and the ticks below it, in the document.
    expect(caption.compareDocumentPosition(box) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(box.compareDocumentPosition(axis) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("scales the caption row and the ticks with the log list font size (f = 20: 21 + 4 + 48 + 2 + 22 = 97)", () => {
    mount({}, correlationSizes(20));
    expect(screen.getByTestId("overview-caption").style.minHeight).toBe("21px");
    expect(screen.getByTestId("overview-axis").style.height).toBe("22px");
    expect(21 + 4 + 48 + 2 + 22).toBe(97);
  });

  it("names the strip, its hint and what it spans, and says the extent is the chains shown", () => {
    mount();
    const caption = screen.getByTestId("overview-caption");
    expect(caption).toHaveTextContent("Overview");
    expect(caption).toHaveTextContent("drag the band to zoom");
    expect(caption).toHaveTextContent("Spans the chains shown, not the whole session.");
  });

  it("lets the caption wrap instead of clipping the note that the extent is only the chains shown", () => {
    // jsdom has no layout, so this reads the styles that would clip: a fixed height, a hidden overflow
    // or a no-wrap row cut the note off at a large font size with the side panes open.
    mount({}, correlationSizes(20));
    const caption = screen.getByTestId("overview-caption");
    expect(caption.style.flexWrap).toBe("wrap");
    expect(caption.style.height).toBe("");
    expect(caption.style.overflow).not.toBe("hidden");
    expect(caption.style.whiteSpace).not.toBe("nowrap");
    const note = within(caption).getByText("Spans the chains shown, not the whole session.");
    expect(note.style.whiteSpace).not.toBe("nowrap");
    expect(note.style.overflow).not.toBe("hidden");
    // The separator dot rides with the hint, so a wrapped line never starts with it.
    expect(within(caption).getByText("drag the band to zoom ·").style.whiteSpace).toBe("nowrap");
  });

  it("sizes the caption from the font setting: max(10, f - 3), and the ticks max(9, f - 4)", () => {
    mount();
    expect(screen.getByTestId("overview-caption").style.fontSize).toBe("10px");
    expect((screen.getByTestId("overview-axis").firstElementChild as HTMLElement).style.fontSize).toBe("9px");
    cleanup();
    mount({}, correlationSizes(20));
    expect(screen.getByTestId("overview-caption").style.fontSize).toBe("17px");
    expect((screen.getByTestId("overview-axis").firstElementChild as HTMLElement).style.fontSize).toBe("16px");
  });

  it("draws one bar per chain with a position, in its strength's row, 6 px high", () => {
    mount();
    const bars = [...document.querySelectorAll<HTMLElement>("[data-bar]")];
    expect(bars.map((bar) => bar.dataset.bar).sort()).toEqual(["A", "B", "C"]);
    const top = Object.fromEntries(bars.map((bar) => [bar.dataset.strength, bar.style.top]));
    expect(top).toEqual({ exact: "7px", candidate: "16px", ambiguous: "25px" });
    for (const bar of bars) expect(bar.style.height).toBe(`${OVERVIEW_BAR_HEIGHT_PX}px`);
    expect(OVERVIEW_BAR_HEIGHT_PX).toBe(6);
    // The last row ends at 7 + 3 * 9 + 6 = 40, inside the 48 px box.
    expect(7 + 3 * 9 + 6).toBeLessThan(OVERVIEW_BOX_HEIGHT_PX);
  });

  it("gives a bar a minimum drawn width, so a single instant or a short chain can still be seen", () => {
    mount({ chains: [chain("A", "exact", 0, 100), chain("Z", "exact", 90, 90)] });
    for (const bar of document.querySelectorAll<HTMLElement>("[data-bar]")) expect(bar.style.minWidth).toBe("3px");
  });

  it("draws the selected chain solid and the others at 40% in their fill, each with a full-opacity outline (R1)", () => {
    mount();
    const fill = (id: string) => document.querySelector(`[data-bar="${id}"] [data-bar-fill]`) as HTMLElement;
    const bar = (id: string) => document.querySelector(`[data-bar="${id}"]`) as HTMLElement;
    expect(fill("A").style.opacity).toBe("1");
    expect(fill("B").style.opacity).toBe("0.4");
    expect(fill("C").style.opacity).toBe("0.4");
    for (const id of ["A", "B", "C"]) {
      // The element itself is never faded: its outline is the boundary that keeps 3:1.
      expect(bar(id).style.opacity).toBe("");
      expect(bar(id).style.border).toContain("1px solid");
    }
    expect(bar("A").dataset.selected).toBe("true");
    expect(bar("B").dataset.selected).toBe("false");
  });

  it("draws the selected chain's bar last, on top where bars overlap", () => {
    mount({ selectedId: "B" });
    const order = [...document.querySelectorAll<HTMLElement>("[data-bar]")].map((bar) => bar.dataset.bar);
    expect(order[order.length - 1]).toBe("B");
  });

  it("paints the wash, then the bars, then the handles, in the document, with no z-index", () => {
    mount();
    expect([...document.querySelectorAll("[data-evtx-layer]")].map((node) => (node as HTMLElement).dataset.evtxLayer)).toEqual([
      "wash",
      "bars",
      "edge",
      "edge",
    ]);
    for (const node of document.querySelectorAll<HTMLElement>("[data-evtx-layer], [data-part]")) {
      expect(node.style.zIndex).toBe("");
    }
  });

  it("draws the band over the window, never narrower than 12 px, and the handles at its two edges", () => {
    const window = win(-25, 125);
    mount({ window });
    const wash = layer("wash")[0]!;
    expect(parseFloat(wash.style.left)).toBeCloseTo(((window.startMs - domain.startMs) / (domain.endMs - domain.startMs)) * 100);
    expect(wash.style.minWidth).toBe("12px");
    const handles = [...document.querySelectorAll<HTMLElement>("[data-part='start'],[data-part='end']")];
    expect(handles.map((handle) => handle.dataset.part)).toEqual(["start", "end"]);
    expect(layer("edge").map((edge) => edge.style.borderLeft)).toEqual([
      "2px solid var(--colorNeutralStrokeAccessible)",
      "2px solid var(--colorNeutralStrokeAccessible)",
    ]);
  });

  it("draws the wash at the opacity solved from the token map: 0.6, and 0.5 in high contrast", () => {
    mount();
    expect(layer("wash")[0]!.style.opacity).toBe("0.6");
    expect(layer("wash")[0]!.style.backgroundColor).toBe("var(--colorNeutralBackground1Selected)");
    cleanup();
    useUiStore.setState({ themeId: "high-contrast" });
    mount();
    expect(layer("wash")[0]!.style.opacity).toBe("0.5");
  });

  it("labels five ticks across the strip in the chosen zone, keeping the day when the strip crosses midnight", () => {
    mount();
    const ticks = [...screen.getByTestId("overview-axis").children].map((node) => node.textContent);
    expect(ticks).toHaveLength(5);
    expect(new Set(ticks).size).toBe(5);
    cleanup();
    const late = Date.UTC(2026, 9, 6, 23, 50, 0);
    const across = [
      { ...chain("L", "exact", null, null), startMs: late, endMs: late + 20 * 60_000 },
    ];
    mount({ chains: across, selectedId: "L", window: defaultLaneWindow(across[0]!.startMs, across[0]!.endMs) });
    const labels = [...screen.getByTestId("overview-axis").children].map((node) => node.textContent ?? "");
    expect(labels.some((text) => text.startsWith("Oct 7"))).toBe(true);
    expect(labels.every((text) => /^Oct \d/.test(text))).toBe(true);
  });

  it("counts the chains it cannot draw without saying why", () => {
    mount();
    expect(screen.getByTestId("overview-undrawn")).toHaveTextContent(
      "1 chain has no loaded timeline position and is not drawn here.",
    );
    cleanup();
    mount({ chains: chains.slice(0, 3) });
    expect(screen.queryByTestId("overview-undrawn")).toBeNull();
  });

  it("says so, in a frame, when no chain has a position, and offers no slider", () => {
    mount({ chains: [chain("D", "exact", null, null)], selectedId: "D", window: null });
    expect(screen.getByTestId("overview-box")).toHaveTextContent(
      "No chain has a loaded timeline position, so there is nothing to show here.",
    );
    expect(screen.queryByRole("slider")).toBeNull();
    expect(screen.getByTestId("overview-box").style.height).toBe("48px");
    expect(screen.getByTestId("overview-box").textContent).not.toMatch(/no timestamp|not placed/i);
  });

  it("draws the bars with no band, and says why, when the selected chain has no position", () => {
    mount({ selectedId: "D", window: null });
    expect(screen.queryByRole("slider")).toBeNull();
    expect(layer("wash")).toHaveLength(0);
    expect(layer("edge")).toHaveLength(0);
    expect(screen.getByRole("img")).toHaveAccessibleName(
      "Spans of 3 chains. The selected chain has no loaded timeline position, so there is no zoom window.",
    );
  });
});

describe("the slider", () => {
  it("is one named slider whose value text is the band's two ends and width", () => {
    const window = win(0, 300);
    mount({ window });
    const slider = screen.getByRole("slider", { name: "Zoom window of the lane plot" });
    expect(slider).toHaveAttribute("aria-valuetext", bandValueText(window, "utc"));
    expect(slider.getAttribute("aria-valuetext")).toBe("10:20:00 to 10:25:00, 5 min wide");
    expect(slider).toHaveAttribute("aria-valuemin", String(domain.startMs));
    expect(slider).toHaveAttribute("aria-valuemax", String(domain.endMs));
    expect(slider).toHaveAttribute("aria-valuenow", String(window.startMs));
    expect(slider).toHaveAttribute("aria-orientation", "horizontal");
    expect(slider).toHaveAttribute("aria-keyshortcuts", "ArrowLeft ArrowRight Shift+ArrowLeft Shift+ArrowRight Home");
  });

  it("is one tab stop, and the handles and bars are not", () => {
    mount();
    const slider = screen.getByRole("slider");
    expect(slider).toHaveAttribute("tabindex", "0");
    const focusable = document.querySelectorAll("[tabindex], button, a[href], input");
    expect([...focusable]).toEqual([slider]);
    for (const part of document.querySelectorAll("[data-part='start'],[data-part='end']")) {
      expect(part.closest("[aria-hidden='true']")).not.toBeNull();
    }
    expect(document.querySelector("[data-evtx-layer='bars']")).toHaveAttribute("aria-hidden", "true");
  });

  it("follows the window it is given", () => {
    const { rerenderWith } = mount({ window: win(0, 300) });
    rerenderWith({ window: win(10, 20) });
    expect(screen.getByRole("slider")).toHaveAttribute("aria-valuetext", "10:20:10 to 10:20:20, 10 s wide");
  });
});

describe("dragging with the pointer", () => {
  const window = win(100, 300);

  it("pans the band by how far the pointer has moved, from the press, live", () => {
    const { box } = mount({ window });
    const grab = xOf(window.startMs) + 20;
    down(box, grab);
    move(box, grab + 40);
    const first = lastWindow()!;
    const delta = msOf(grab + 40) - msOf(grab);
    expect(first.startMs).toBeCloseTo(window.startMs + delta, 0);
    expect(first.endMs - first.startMs).toBe(window.endMs - window.startMs);
    move(box, grab + 80);
    expect(lastWindow()!.startMs).toBeCloseTo(window.startMs + (msOf(grab + 80) - msOf(grab)), 0);
    up(box, grab + 80);
    const calls = onWindowChange.mock.calls.length;
    move(box, grab + 200, 0);
    expect(onWindowChange.mock.calls.length).toBe(calls);
  });

  it("resizes only the pressed edge when a handle is dragged", () => {
    const { box } = mount({ window });
    const startHandle = document.querySelector("[data-part='start']")!;
    const x = xOf(window.startMs);
    down(startHandle, x);
    move(box, x + 30);
    const resized = lastWindow()!;
    expect(resized.endMs).toBe(window.endMs);
    expect(resized.startMs).toBeGreaterThan(window.startMs);
    up(box, x + 30);
    cleanup();
    onWindowChange.mockClear();
    const second = mount({ window });
    const endHandle = document.querySelector("[data-part='end']")!;
    const xe = xOf(window.endMs);
    down(endHandle, xe);
    move(second.box, xe + 25);
    expect(lastWindow()!.startMs).toBe(window.startMs);
    expect(lastWindow()!.endMs).toBeGreaterThan(window.endMs);
  });

  it("does not let a drag leave the strip or make the band narrower than 10 s", () => {
    const { box } = mount({ window });
    const startHandle = document.querySelector("[data-part='start']")!;
    down(startHandle, xOf(window.startMs));
    move(box, xOf(window.endMs) + 300);
    const squeezed = lastWindow()!;
    expect(squeezed.endMs - squeezed.startMs).toBe(CORRELATION_MIN_WINDOW_MS);
    expect(squeezed.endMs).toBe(window.endMs);
  });

  it("does nothing for a press outside the band (no click to recenter), and takes no right-button press", () => {
    const { box } = mount({ window });
    down(box, LEFT + 2);
    move(box, LEFT + 200);
    expect(onWindowChange).not.toHaveBeenCalled();
    down(box, xOf(window.startMs) + 20, { button: 2, buttons: 2 });
    move(box, xOf(window.startMs) + 90);
    expect(onWindowChange).not.toHaveBeenCalled();
  });

  it("stops following a pointer that is no longer pressed", () => {
    const { box } = mount({ window });
    down(box, xOf(window.startMs) + 20);
    move(box, xOf(window.startMs) + 60, 0);
    expect(onWindowChange).not.toHaveBeenCalled();
    move(box, xOf(window.startMs) + 90);
    expect(onWindowChange).not.toHaveBeenCalled();
  });

  it("ends the gesture on cancel and on lost capture", () => {
    const { box } = mount({ window });
    down(box, xOf(window.startMs) + 20);
    fireEvent.pointerCancel(box, { pointerId: 1 });
    move(box, xOf(window.startMs) + 90);
    expect(onWindowChange).not.toHaveBeenCalled();
    down(box, xOf(window.startMs) + 20);
    fireEvent.lostPointerCapture(box, { pointerId: 1 });
    move(box, xOf(window.startMs) + 90);
    expect(onWindowChange).not.toHaveBeenCalled();
  });

  it("goes back to where the band was pressed on Escape, and spends the key", () => {
    const { box } = mount({ window });
    down(box, xOf(window.startMs) + 20);
    move(box, xOf(window.startMs) + 120);
    const notPrevented = key(box, "Escape");
    expect(notPrevented).toBe(false);
    expect(lastWindow()).toEqual(window);
    const calls = onWindowChange.mock.calls.length;
    move(box, xOf(window.startMs) + 200);
    expect(onWindowChange.mock.calls.length).toBe(calls);
  });

  it("ends the drag, and makes the window legal, when the domain changes under it (a live rebuild)", () => {
    const { box, rerenderWith } = mount({ window });
    down(box, xOf(window.startMs) + 20);
    move(box, xOf(window.startMs) + 40);
    onWindowChange.mockClear();
    // A rebuild: the chains now span a much narrower stretch that no longer holds the band.
    const narrower = [chain("A", "exact", 0, 40)];
    rerenderWith({ chains: narrower, window });
    const newDomain = overviewDomain(narrower)!;
    const fitted = lastWindow()!;
    expect(fitted.startMs).toBeGreaterThanOrEqual(newDomain.startMs);
    expect(fitted.endMs).toBeLessThanOrEqual(newDomain.endMs);
    onWindowChange.mockClear();
    // The pointer is still down, but the gesture it belonged to is over.
    move(box, xOf(window.startMs) + 200);
    expect(onWindowChange).not.toHaveBeenCalled();
  });

  it("leaves a window that still fits alone when the domain changes", () => {
    const { rerenderWith } = mount({ window: win(0, 100) });
    rerenderWith({ chains: [...chains, chain("E", "exact", 450, 520)] });
    expect(onWindowChange).not.toHaveBeenCalled();
  });
});

describe("the keyboard (R7)", () => {
  const window = win(100, 200);

  it("moves the band by a tenth of its width with Left and Right, and spends the key", () => {
    const { box } = mount({ window });
    expect(key(box, "ArrowRight")).toBe(false);
    expect(lastWindow()).toEqual(win(110, 210));
    key(box, "ArrowLeft");
    expect(lastWindow()).toEqual(win(90, 190));
  });

  it("resizes symmetrically with Shift+Left and Shift+Right", () => {
    const { box } = mount({ window });
    key(box, "ArrowRight", { shiftKey: true });
    expect(lastWindow()).toEqual(win(90, 210));
    key(box, "ArrowLeft", { shiftKey: true });
    expect(lastWindow()).toEqual(win(110, 190));
  });

  it("goes back to the chain's own window with Home, by asking for null", () => {
    const { box } = mount({ window });
    expect(key(box, "Home")).toBe(false);
    expect(onWindowChange).toHaveBeenCalledWith(null);
  });

  it("spends Escape even when there is nothing to cancel, and calls nothing", () => {
    const { box } = mount({ window });
    expect(key(box, "Escape")).toBe(false);
    expect(onWindowChange).not.toHaveBeenCalled();
  });

  it("leaves every other key, and any key with a modifier, alone", () => {
    const { box } = mount({ window });
    for (const name of ["End", "PageUp", "ArrowUp", "ArrowDown", "Enter", "Tab", "a"]) {
      expect(key(box, name), name).toBe(true);
    }
    for (const init of [{ ctrlKey: true }, { metaKey: true }, { altKey: true }]) {
      expect(key(box, "ArrowRight", init), JSON.stringify(init)).toBe(true);
    }
    expect(onWindowChange).not.toHaveBeenCalled();
  });

  it("ignores arrow keys while a drag is in progress", () => {
    const { box } = mount({ window });
    down(box, xOf(window.startMs) + 20);
    key(box, "ArrowRight");
    expect(onWindowChange).not.toHaveBeenCalled();
  });
});

describe("it is the lane window and nothing else (6a)", () => {
  it("never writes the time-range criterion, by pointer or keyboard", () => {
    const original = useEvtxStore.getState().setTimeRange;
    const spy = vi.fn(original);
    useEvtxStore.setState({ setTimeRange: spy as typeof original });
    try {
      const window = win(100, 200);
      const { box } = mount({ window });
      down(box, xOf(window.startMs) + 20);
      move(box, xOf(window.startMs) + 90);
      up(box, xOf(window.startMs) + 90);
      for (const name of ["ArrowLeft", "ArrowRight", "Home", "Escape"]) key(box, name);
      key(box, "ArrowRight", { shiftKey: true });
      expect(spy).not.toHaveBeenCalled();
      expect(useEvtxStore.getState().timeRange).toBeNull();
    } finally {
      useEvtxStore.setState({ setTimeRange: original });
    }
  });

  it("keeps a brushed range when Escape is pressed on the band, because the key is spent before the window's handler", () => {
    const range = { startMs: T0, endMs: T0 + 60 * S };
    useEvtxStore.setState({ timeRange: range });
    // The workspace's own rule: Escape clears the range unless something already used the key.
    const clearOnEscape = (event: KeyboardEvent) => {
      if (event.key !== "Escape" || event.defaultPrevented) return;
      useEvtxStore.getState().setTimeRange(null);
    };
    window.addEventListener("keydown", clearOnEscape);
    try {
      const { box } = mount({ window: win(100, 200) });
      box.focus();
      key(box, "Escape");
      expect(useEvtxStore.getState().timeRange).toEqual(range);
      // And the same key from somewhere that does not spend it does clear it: the listener is live.
      fireEvent.keyDown(document.body, { key: "Escape" });
      expect(useEvtxStore.getState().timeRange).toBeNull();
    } finally {
      window.removeEventListener("keydown", clearOnEscape);
      useEvtxStore.setState({ timeRange: null });
    }
  });
});

describe("what it is not", () => {
  it("has no live region, no transition and no color literal", () => {
    mount();
    expect(document.querySelectorAll("[role='status'],[role='alert'],[aria-live]")).toHaveLength(0);
    for (const node of document.querySelectorAll<HTMLElement>("[style]")) {
      expect(node.style.transition, node.outerHTML.slice(0, 80)).toBe("");
    }
    const code = overviewSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    expect(code).not.toMatch(/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/);
    expect(code).not.toMatch(/transition/);
  });

  it("takes every font size from the font setting and has no px font of its own", () => {
    const code = overviewSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    for (const match of code.matchAll(/fontSize:\s*([^,}\n]+)/g)) {
      expect(match[1], match[0]).toMatch(/sizes\.(label|tick|lane|f)/);
    }
    expect(code).not.toMatch(/fontSize:\s*"?\d/);
  });
});

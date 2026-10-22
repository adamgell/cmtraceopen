/**
 * The overview strip's rules: its scale, its bars, where the zoom band may go and how a gesture or
 * a key moves it, and how opaque the wash behind the bars may be. Pure; the component test draws it.
 */
import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import { STRENGTH_ORDER, type CorrelationChainStrength } from "./evtx-correlation-chains";
import { CORRELATION_MIN_WINDOW_MS, defaultLaneWindow, type TimeWindow } from "./evtx-correlation-view-model";
import { BRUSH_FILL_OPACITIES, BRUSH_MIN_CONTRAST, compositeOver } from "./evtx-histogram-brush";
import { tokenPalette } from "./evtx-correlation-test-fixtures";
import {
  OVERVIEW_BAR_HEIGHT_PX,
  OVERVIEW_BOX_HEIGHT_PX,
  OVERVIEW_CAPTION,
  OVERVIEW_EXTENT_NOTE,
  OVERVIEW_HINT,
  OVERVIEW_UNSELECTED_FILL_OPACITY,
  bandFractions,
  bandValueText,
  clampWindow,
  dragBand,
  fractionToMs,
  overviewBandOpacity,
  overviewBars,
  overviewDomain,
  reduceBandKey,
  undrawnNote,
  zoomWindowFor,
} from "./evtx-correlation-overview";
import overviewSource from "./evtx-correlation-overview.ts?raw";
import { resolveToken } from "./evtx-visual-tokens";

const S = 1_000;
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);
const chain = (
  id: string,
  strength: CorrelationChainStrength,
  startS: number | null,
  endS: number | null,
) => ({
  id,
  strength,
  startMs: startS === null ? null : T0 + startS * S,
  endMs: endS === null ? null : T0 + endS * S,
});
const win = (startS: number, endS: number) => ({ startMs: T0 + startS * S, endMs: T0 + endS * S });

/** Panning, resizing and the key step are private to the module: they are tested through the gesture and the key. */
const panWindow = (window: TimeWindow, domain: TimeWindow, deltaMs: number) =>
  dragBand({ part: "body", origin: window, grabMs: 0 }, deltaMs, domain);
const resizeEdge = (window: TimeWindow, domain: TimeWindow, edge: "start" | "end", toMs: number) =>
  dragBand(
    { part: edge, origin: window, grabMs: 0 },
    toMs - (edge === "start" ? window.startMs : window.endMs),
    domain,
  );
const WIDE = { startMs: T0 - 10_000 * S, endMs: T0 + 10_000 * S };
const bandStepMs = (window: TimeWindow) =>
  (reduceBandKey(window, WIDE, "ArrowRight", false) as { kind: "set"; window: TimeWindow }).window.startMs -
  window.startMs;

describe("the scale (R5)", () => {
  it("is the union of every chain's default lane window, not of the spans", () => {
    // A: 0 to 100 s, padded 25% of the span on each side: -25 to 125. B: 40 to 60 s: width max(30, 10)
    // centred on 50: 35 to 65, inside A's.
    const domain = overviewDomain([chain("A", "exact", 0, 100), chain("B", "candidate", 40, 60)]);
    expect(domain).toEqual(win(-25, 125));
  });

  it("holds each chain's default window, so the default band fits whatever the others are", () => {
    const chains = [chain("A", "exact", 0, 100), chain("far", "exact", 400, 400), chain("C", "ambiguous", 90, 130)];
    const domain = overviewDomain(chains)!;
    for (const c of chains) {
      const own = defaultLaneWindow(c.startMs, c.endMs)!;
      expect(own.startMs).toBeGreaterThanOrEqual(domain.startMs);
      expect(own.endMs).toBeLessThanOrEqual(domain.endMs);
    }
    // A single instant still has the lane plot's minimum 10 s window around it.
    expect(domain.endMs).toBe(T0 + 405 * S);
  });

  it("is null when no chain has a position, and ignores a chain that has none", () => {
    expect(overviewDomain([])).toBeNull();
    expect(overviewDomain([chain("A", "exact", null, null)])).toBeNull();
    expect(overviewDomain([chain("A", "exact", null, null), chain("B", "exact", 0, 20)])).toEqual(
      defaultLaneWindow(T0, T0 + 20 * S),
    );
  });
});

describe("the bars", () => {
  const chains = [
    chain("A", "exact", 0, 100),
    chain("B", "candidate", 40, 60),
    chain("C", "coverageBlocked", 10, 10),
    chain("D", "ambiguous", null, null),
  ];
  const domain = overviewDomain(chains)!;

  it("puts a chain in its strength's row, across the domain, and counts the one with no position", () => {
    const { bars, undrawn } = overviewBars(chains, null, domain);
    const byId = Object.fromEntries(bars.map((bar) => [bar.chainId, bar]));
    expect(STRENGTH_ORDER).toEqual(["exact", "candidate", "ambiguous", "coverageBlocked"]);
    expect(byId.A).toMatchObject({ row: 0, strength: "exact" });
    expect(byId.B).toMatchObject({ row: 1, strength: "candidate" });
    expect(byId.C).toMatchObject({ row: 3, strength: "coverageBlocked" });
    // The domain is -25 s to 125 s: 150 s wide.
    expect(byId.A.left).toBeCloseTo(25 / 150);
    expect(byId.A.width).toBeCloseTo(100 / 150);
    expect(byId.B.left).toBeCloseTo(65 / 150);
    expect(byId.B.width).toBeCloseTo(20 / 150);
    expect(undrawn).toBe(1);
    expect(bars.find((bar) => bar.chainId === "D")).toBeUndefined();
  });

  it("draws a single instant as a bar of width 0, which the view gives a minimum, rather than dropping it", () => {
    const bar = overviewBars(chains, null, domain).bars.find((entry) => entry.chainId === "C")!;
    expect(bar.width).toBe(0);
  });

  it("marks the selected chain and draws it last, so it is on top where bars overlap", () => {
    const { bars } = overviewBars(chains, "A", domain);
    expect(bars.map((bar) => bar.selected)).toEqual([false, false, true]);
    expect(bars[bars.length - 1].chainId).toBe("A");
    // The others keep their order.
    expect(bars.slice(0, 2).map((bar) => bar.chainId)).toEqual(["B", "C"]);
  });

  it("selects nothing when the selection is not among the chains", () => {
    expect(overviewBars(chains, "missing", domain).bars.some((bar) => bar.selected)).toBe(false);
  });

  it("draws nothing, and counts every chain, when there is no domain", () => {
    expect(overviewBars(chains, null, null)).toEqual({ bars: [], undrawn: 4 });
  });

  it("says how many chains are not drawn without saying why", () => {
    expect(undrawnNote(0)).toBeNull();
    expect(undrawnNote(1)).toBe("1 chain has no loaded timeline position and is not drawn here.");
    expect(undrawnNote(3)).toBe("3 chains have no loaded timeline position and are not drawn here.");
    expect(`${undrawnNote(2)}`).not.toMatch(/no timestamp|not placed/i);
  });
});

describe("the band's geometry", () => {
  const domain = win(0, 1_000);

  it("reads its edges as fractions of the domain, clamped to the strip", () => {
    expect(bandFractions(win(100, 300), domain)).toEqual({ left: 0.1, right: 0.3 });
    expect(bandFractions(win(-50, 2_000), domain)).toEqual({ left: 0, right: 1 });
  });

  it("maps a fraction back to time, clamped", () => {
    expect(fractionToMs(0.25, domain)).toBe(T0 + 250 * S);
    expect(fractionToMs(-1, domain)).toBe(T0);
    expect(fractionToMs(2, domain)).toBe(T0 + 1_000 * S);
  });

  it("clamps a window into the domain with its width kept, to no less than the minimum or more than the domain", () => {
    expect(clampWindow(win(-100, 100), domain)).toEqual(win(0, 200));
    expect(clampWindow(win(900, 1_100), domain)).toEqual(win(800, 1_000));
    expect(clampWindow(win(100, 103), domain)).toEqual(win(100, 110));
    expect(clampWindow(win(-500, 5_000), domain)).toEqual(domain);
  });

  it("pans with its width kept and stops at both ends of the domain", () => {
    expect(panWindow(win(100, 200), domain, 50 * S)).toEqual(win(150, 250));
    expect(panWindow(win(100, 200), domain, 5_000 * S)).toEqual(win(900, 1_000));
    expect(panWindow(win(100, 200), domain, -5_000 * S)).toEqual(win(0, 100));
  });

  it("moves one edge at a time, inside the domain and never closer to the other than 10 s", () => {
    expect(resizeEdge(win(100, 200), domain, "start", T0 + 150 * S)).toEqual(win(150, 200));
    expect(resizeEdge(win(100, 200), domain, "end", T0 + 400 * S)).toEqual(win(100, 400));
    expect(resizeEdge(win(100, 200), domain, "start", T0 + 195 * S)).toEqual(win(190, 200));
    expect(resizeEdge(win(100, 200), domain, "end", T0 + 101 * S)).toEqual(win(100, 110));
    expect(resizeEdge(win(100, 200), domain, "start", T0 - 99 * S)).toEqual(win(0, 200));
    expect(resizeEdge(win(100, 200), domain, "end", T0 + 9_999 * S)).toEqual(win(100, 1_000));
  });

  it("makes the whole window legal, not only the edge that moved, when the domain changed under it", () => {
    // A gesture began with a window inside the old domain; a live rebuild moved the domain.
    const moved = win(500, 600);
    const next = resizeEdge(win(100, 700), moved, "start", T0 + 550 * S);
    expect(next.startMs).toBeGreaterThanOrEqual(moved.startMs);
    expect(next.endMs).toBeLessThanOrEqual(moved.endMs);
    expect(next.endMs - next.startMs).toBeGreaterThanOrEqual(CORRELATION_MIN_WINDOW_MS);
    const farOff = resizeEdge(win(900, 1_000), win(0, 300), "end", T0 + 950 * S);
    expect(farOff.startMs).toBeGreaterThanOrEqual(T0);
    expect(farOff.endMs).toBeLessThanOrEqual(T0 + 300 * S);
  });

  it("leaves the other edge where it is", () => {
    expect(resizeEdge(win(100, 200), domain, "start", T0 + 120 * S).endMs).toBe(T0 + 200 * S);
    expect(resizeEdge(win(100, 200), domain, "end", T0 + 220 * S).startMs).toBe(T0 + 100 * S);
  });
});

describe("a pointer gesture is measured from the press", () => {
  const domain = win(0, 1_000);
  const origin = win(100, 200);

  it("pans by how far the pointer has moved, whatever it did on the way", () => {
    const drag = { part: "body" as const, origin, grabMs: T0 + 150 * S };
    expect(dragBand(drag, T0 + 250 * S, domain)).toEqual(win(200, 300));
    expect(dragBand(drag, T0 + 150 * S, domain)).toEqual(origin);
    expect(dragBand(drag, T0 + 9_000 * S, domain)).toEqual(win(900, 1_000));
  });

  it("stays inside a domain that changed mid-gesture, whatever the origin and the pointer say", () => {
    const changed = win(0, 300);
    for (const part of ["body", "start", "end"] as const) {
      const drag = { part, origin: win(800, 900), grabMs: T0 + 850 * S };
      for (const pointer of [100, 850, 5_000]) {
        const next = dragBand(drag, T0 + pointer * S, changed);
        expect(next.startMs, `${part} ${pointer}`).toBeGreaterThanOrEqual(changed.startMs);
        expect(next.endMs, `${part} ${pointer}`).toBeLessThanOrEqual(changed.endMs);
        expect(next.endMs - next.startMs, `${part} ${pointer}`).toBeGreaterThanOrEqual(CORRELATION_MIN_WINDOW_MS);
      }
    }
  });

  it("resizes the pressed edge by that distance, without jumping to the pointer", () => {
    const start = { part: "start" as const, origin, grabMs: T0 + 102 * S };
    expect(dragBand(start, T0 + 132 * S, domain)).toEqual(win(130, 200));
    const end = { part: "end" as const, origin, grabMs: T0 + 198 * S };
    expect(dragBand(end, T0 + 148 * S, domain)).toEqual(win(100, 150));
  });
});

describe("the keyboard (R7)", () => {
  const domain = win(0, 1_000);

  it("steps by a tenth of the band's width, at least a second", () => {
    expect(bandStepMs(win(100, 200))).toBe(10 * S);
    expect(bandStepMs(win(100, 110))).toBe(1 * S);
    // Below the minimum width, which clampWindow forbids: the step floor still holds.
    expect(bandStepMs(win(100, 105))).toBe(1 * S);
  });

  it("moves the band with Left and Right, and stops at the domain", () => {
    expect(reduceBandKey(win(100, 200), domain, "ArrowRight", false)).toEqual({ kind: "set", window: win(110, 210) });
    expect(reduceBandKey(win(100, 200), domain, "ArrowLeft", false)).toEqual({ kind: "set", window: win(90, 190) });
    expect(reduceBandKey(win(0, 100), domain, "ArrowLeft", false)).toEqual({ kind: "set", window: win(0, 100) });
    expect(reduceBandKey(win(900, 1_000), domain, "ArrowRight", false)).toEqual({ kind: "set", window: win(900, 1_000) });
  });

  it("widens symmetrically with Shift+Right and narrows with Shift+Left", () => {
    expect(reduceBandKey(win(100, 200), domain, "ArrowRight", true)).toEqual({ kind: "set", window: win(90, 210) });
    expect(reduceBandKey(win(100, 200), domain, "ArrowLeft", true)).toEqual({ kind: "set", window: win(110, 190) });
  });

  it("clamps a widening at the domain and a narrowing at 10 s about the centre", () => {
    expect(reduceBandKey(win(0, 1_000), domain, "ArrowRight", true)).toEqual({ kind: "set", window: win(0, 1_000) });
    expect(reduceBandKey(win(5, 105), domain, "ArrowRight", true)).toEqual({ kind: "set", window: win(0, 115) });
    const narrow = reduceBandKey(win(100, 112), domain, "ArrowLeft", true);
    expect(narrow).toEqual({ kind: "set", window: win(101, 111) });
    const floor = reduceBandKey(win(100, 110), domain, "ArrowLeft", true);
    expect(floor).toEqual({ kind: "set", window: win(100, 110) });
    expect(CORRELATION_MIN_WINDOW_MS).toBe(10_000);
  });

  it("resets on Home, with or without Shift, and leaves every other key alone", () => {
    expect(reduceBandKey(win(100, 200), domain, "Home", false)).toEqual({ kind: "reset" });
    expect(reduceBandKey(win(100, 200), domain, "Home", true)).toEqual({ kind: "reset" });
    for (const key of ["End", "PageUp", "ArrowUp", "ArrowDown", "Enter", " ", "a"]) {
      expect(reduceBandKey(win(100, 200), domain, key, false), key).toEqual({ kind: "ignore" });
    }
  });
});

describe("the window the operator set belongs to its chain", () => {
  const state = { chainId: "A", window: win(10, 20) };

  it("is the chain's own, and nothing for another chain, for none, or before any is set", () => {
    expect(zoomWindowFor(state, "A")).toEqual(win(10, 20));
    expect(zoomWindowFor(state, "B")).toBeNull();
    expect(zoomWindowFor(state, null)).toBeNull();
    expect(zoomWindowFor(null, "A")).toBeNull();
  });
});

describe("the value text", () => {
  it("names the ends and the width, with seconds", () => {
    expect(bandValueText(win(0, 300), "utc", T0)).toBe("10:20:00 to 10:25:00, 5 min wide");
    expect(bandValueText(win(0, 10), "utc", T0)).toBe("10:20:00 to 10:20:10, 10 s wide");
    expect(bandValueText(win(5, 5 + 3_660), "utc", T0)).toBe("10:20:05 to 11:21:05, 1 h 1 min wide");
    expect(bandValueText(win(0, 90), "utc", T0)).toBe("10:20:00 to 10:21:30, 1 min 30 s wide");
  });

  it("names the day when the window crosses midnight", () => {
    const start = Date.UTC(2026, 9, 6, 23, 59, 0);
    expect(bandValueText({ startMs: start, endMs: start + 120 * S }, "utc", T0)).toBe(
      "Oct 6 23:59:00 to Oct 7 00:01:00, 2 min wide",
    );
  });
});

describe("the fixed measures (R1, R8, spec 8.11)", () => {
  it("is a 48 px box of 6 px bars, the selected chain solid and the others 40% in their fill", () => {
    expect(OVERVIEW_BOX_HEIGHT_PX).toBe(48);
    expect(OVERVIEW_BAR_HEIGHT_PX).toBe(6);
    // Four rows of bars with a 3 px gap between them fit the box with room for its padding.
    expect(STRENGTH_ORDER.length * OVERVIEW_BAR_HEIGHT_PX + (STRENGTH_ORDER.length - 1) * 3).toBeLessThan(
      OVERVIEW_BOX_HEIGHT_PX,
    );
    expect(OVERVIEW_UNSELECTED_FILL_OPACITY).toBe(0.4);
  });

  it("says what the strip is for and what it spans", () => {
    expect(OVERVIEW_CAPTION).toBe("Overview");
    expect(OVERVIEW_HINT).toBe("drag the band to zoom");
    expect(OVERVIEW_EXTENT_NOTE).toBe("Spans the chains shown, not the whole session.");
  });
});

describe("the wash behind the bars (Adam's criterion on #840)", () => {
  const themes = getAllThemes();
  const resolved = (id: string) => {
    const theme = themes.find((candidate) => candidate.id === id)!;
    const palette = tokenPalette(theme);
    return { theme, palette, opacity: overviewBandOpacity(theme) };
  };

  it("is the spec's 60% in six themes and 50% in high contrast, solved from the token map", () => {
    expect(Object.fromEntries(themes.map((theme) => [theme.id, overviewBandOpacity(theme)]))).toEqual({
      light: 0.6,
      dark: 0.6,
      "high-contrast": 0.5,
      "classic-cmtrace": 0.6,
      "solarized-dark": 0.6,
      nord: 0.6,
      dracula: 0.6,
    });
    expect(BRUSH_FILL_OPACITIES[0]).toBe(0.6);
  });

  it.each(themes.map((theme) => [theme.id] as const))(
    "keeps every strength bar at 3:1 on the wash in %s",
    (id) => {
      const { palette, opacity } = resolved(id);
      const wash = compositeOver(palette.surface, palette.fill, opacity);
      expect(palette.bars).toHaveLength(4);
      for (const [index, bar] of palette.bars.entries()) {
        expect(contrastRatio(bar, wash), `${id} ${STRENGTH_ORDER[index]}`).toBeGreaterThanOrEqual(
          BRUSH_MIN_CONTRAST,
        );
      }
    },
  );

  it.each(themes.map((theme) => [theme.id] as const))(
    "keeps the handles and the focus ring at 3:1 on the wash and on the surface in %s",
    (id) => {
      const { palette, opacity } = resolved(id);
      const wash = compositeOver(palette.surface, palette.fill, opacity);
      for (const color of [palette.border, palette.focus]) {
        expect(contrastRatio(color, wash), id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
      expect(contrastRatio(palette.border, palette.surface), id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
    },
  );

  it("is why high contrast takes 50%: its Exact bar is 2.72:1 on a 60% wash, the number Adam measured", () => {
    const { palette } = resolved("high-contrast");
    const exact = palette.bars[0];
    expect(contrastRatio(exact, compositeOver(palette.surface, palette.fill, 0.6))).toBeCloseTo(2.72, 2);
    expect(contrastRatio(exact, compositeOver(palette.surface, palette.fill, 0.5))).toBeCloseTo(3.67, 2);
  });

  it("uses the handles' stroke token, not Foreground3, which is 2.34:1 on the dracula wash", () => {
    const dracula = resolved("dracula");
    const wash = compositeOver(dracula.palette.surface, dracula.palette.fill, dracula.opacity);
    const foreground3 = resolveToken(tokens.colorNeutralForeground3, dracula.theme);
    expect(contrastRatio(foreground3, wash)).toBeLessThan(BRUSH_MIN_CONTRAST);
    expect(dracula.palette.border).toBe(resolveToken(tokens.colorNeutralStrokeAccessible, dracula.theme));
  });

  it("takes the bars from the token map's strengthBars role", () => {
    const { theme, palette } = resolved("light");
    expect(palette.bars).toEqual(["#0078d4", "#424242", "#78350F", "#616161"]);
    expect(theme.id).toBe("light");
  });
});

describe("one strength order and one strength type", () => {
  const code = overviewSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");

  it("takes its rows and its palette from the chain model's STRENGTH_ORDER and declares no list of its own", () => {
    expect(code).toMatch(/STRENGTH_ORDER\.indexOf\(chain\.strength\)/);
    expect(code).toMatch(/STRENGTH_ORDER\.map\(/);
    expect(code).not.toMatch(/OVERVIEW_STRENGTH_ROWS|"candidate",\s*"ambiguous"/);
  });

  it("types a bar's strength with the chain model's type, not one of its own", () => {
    expect(code).toMatch(/type CorrelationChainStrength/);
    expect(code).not.toMatch(/EvtxChainStrength/);
  });
});

describe("the strip reads chains and nothing else", () => {
  it("imports no unplaced code and mentions no unplaced item", () => {
    const code = overviewSource.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
    expect(code).not.toMatch(/evtx-unplaced|UnplacedItem|unplacedList/);
  });
});

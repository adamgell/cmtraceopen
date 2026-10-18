/**
 * Adam's criterion on #840: the chain strength bars under the zoom band keep at least 3:1, in all
 * seven themes, measured on what the component DRAWS (the DOM order and the opacities it wrote),
 * not on a copy of its rules. Modelled on the histogram's brush test.
 */
import { tokens } from "@fluentui/react-components";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import type { ThemeId } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import { EvtxCorrelationOverview } from "./EvtxCorrelationOverview";
import { correlationSizes } from "./EvtxCorrelationLanes";
import type { CorrelationChain, CorrelationChainStrength } from "./evtx-correlation-chains";
import { overviewPaletteFor } from "./evtx-correlation-overview";
import { defaultLaneWindow } from "./evtx-correlation-view-model";
import { BRUSH_MIN_CONTRAST, compositeOver } from "./evtx-histogram-brush";
import { resolveToken } from "./evtx-visual-tokens";

const S = 1_000;
const T0 = Date.UTC(2026, 9, 6, 10, 20, 0);

function chain(id: string, strength: CorrelationChainStrength, startS: number, endS: number): CorrelationChain {
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
    startMs: T0 + startS * S,
    endMs: T0 + endS * S,
    title: null,
  };
}

/** One chain of every strength, the exact one selected, so every bar is in the strip. */
const chains = [
  chain("A", "exact", 0, 100),
  chain("B", "candidate", 40, 60),
  chain("C", "ambiguous", 200, 260),
  chain("D", "coverageBlocked", 300, 330),
];
const STRENGTHS: CorrelationChainStrength[] = ["exact", "candidate", "ambiguous", "coverageBlocked"];

const themes = getAllThemes();
const themeOf = (id: string) => themes.find((candidate) => candidate.id === id)!;

/** `rgb(r, g, b)` or `#rrggbb` as `#rrggbb`. */
function toHex(color: string): string {
  const rgb = /^rgb\(\s*(\d+),\s*(\d+),\s*(\d+)\s*\)$/.exec(color);
  if (!rgb) return color;
  return `#${[rgb[1], rgb[2], rgb[3]].map((part) => Number(part).toString(16).padStart(2, "0")).join("")}`;
}

/** The resolved colour of a `var(--token)` the component wrote, or the plain colour. */
const resolved = (value: string, themeId: string) => toHex(resolveToken(value, themeOf(themeId)));

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderIn(themeId: string, fontSize = 13) {
  useUiStore.setState({ themeId: themeId as ThemeId, logListFontSize: fontSize });
  const window = defaultLaneWindow(chains[0]!.startMs, chains[0]!.endMs)!;
  return render(
    <EvtxCorrelationOverview
      chains={chains}
      selectedId="A"
      window={window}
      onWindowChange={() => undefined}
      timeZoneMode="utc"
      sizes={correlationSizes(fontSize)}
    />,
  );
}

interface Paint {
  /** The layers in document order. */
  order: string[];
  opacity: number;
  /** The strip's surface and the wash composited over it, as the component paints them. */
  surface: string;
  wash: string;
  /** Contrast of each strength's bar against what is behind it, for a sequence of layers. */
  bars: Record<string, number>;
  /** Every bar's outline against the surface and against the wash. */
  outlines: { onSurface: number; onWash: number }[];
}

/**
 * Paints the rendered layers in the order they appear in the document onto two sample points, one
 * on empty strip and one inside a bar. A layer later in the document paints over the ones before
 * it, so a wash placed after the bars would wash the bars as well.
 */
function paintModel(
  container: HTMLElement,
  themeId: string,
  order?: string[],
  opacityOverride?: number,
): Paint {
  const surface = resolved(tokens.colorNeutralBackground1, themeId);
  const layers = [...container.querySelectorAll<HTMLElement>("[data-evtx-layer]")];
  const documentOrder = layers.map((node) => node.dataset.evtxLayer!);
  const sequence = order ?? documentOrder;
  const washLayer = layers.find((node) => node.dataset.evtxLayer === "wash")!;
  const opacity = opacityOverride ?? Number(washLayer.style.opacity);
  const fill = resolved(washLayer.style.backgroundColor, themeId);
  const wash = compositeOver(surface, fill, opacity);
  const bars: Record<string, number> = {};
  const outlines: Paint["outlines"] = [];
  for (const bar of container.querySelectorAll<HTMLElement>("[data-bar]")) {
    const fillNode = bar.querySelector<HTMLElement>("[data-bar-fill]")!;
    const color = resolved(fillNode.style.backgroundColor, themeId);
    const outline = resolved(/var\([^)]*\)|rgb\([^)]*\)|#[0-9a-f]{6}/i.exec(bar.style.border)![0], themeId);
    let empty = surface;
    let inBar = surface;
    for (const name of sequence) {
      if (name === "wash") {
        empty = compositeOver(empty, fill, opacity);
        inBar = compositeOver(inBar, fill, opacity);
      } else if (name === "bars") {
        // The selected bar is solid; the rest are painted in their outline, which is full opacity.
        inBar = color;
      }
    }
    bars[bar.dataset.strength!] = contrastRatio(inBar, empty);
    outlines.push({ onSurface: contrastRatio(outline, surface), onWash: contrastRatio(outline, wash) });
  }
  return { order: documentOrder, opacity, surface, wash, bars, outlines };
}

describe("the strength bars under the zoom band keep 3:1 (issue #840, Adam's criterion)", () => {
  it("draws the wash first, then the bars, then the handles", () => {
    const { container } = renderIn("light");
    expect(paintModel(container, "light").order).toEqual(["wash", "bars", "edge", "edge"]);
  });

  it.each(themes.map((theme) => [theme.id] as const))(
    "keeps all four strength bars at 3:1 against the composited wash in %s",
    (themeId) => {
      const { container } = renderIn(themeId);
      const model = paintModel(container, themeId);
      expect(Object.keys(model.bars).sort()).toEqual([...STRENGTHS].sort());
      for (const strength of STRENGTHS) {
        expect(model.bars[strength], `${themeId} ${strength}`).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    },
  );

  it.each(themes.map((theme) => [theme.id] as const))(
    "draws the wash at the opacity solved from the token map in %s",
    (themeId) => {
      const { container } = renderIn(themeId);
      const palette = overviewPaletteFor(themeOf(themeId));
      const model = paintModel(container, themeId);
      expect(model.surface.toLowerCase()).toBe(palette.surface.toLowerCase());
      expect(model.opacity).toBe(themeId === "high-contrast" ? 0.5 : 0.6);
    },
  );

  it("takes 60% where the spec's holds and 50% in high contrast, where its Exact bar is 2.72:1 at 60%", () => {
    const opacities = Object.fromEntries(
      themes.map((theme) => {
        cleanup();
        const { container } = renderIn(theme.id);
        return [theme.id, paintModel(container, theme.id).opacity];
      }),
    );
    expect(opacities).toEqual({
      light: 0.6,
      dark: 0.6,
      "high-contrast": 0.5,
      "classic-cmtrace": 0.6,
      "solarized-dark": 0.6,
      nord: 0.6,
      dracula: 0.6,
    });
    const palette = overviewPaletteFor(themeOf("high-contrast"));
    expect(contrastRatio(palette.bars[0]!, compositeOver(palette.surface, palette.fill, 0.6))).toBeCloseTo(2.72, 2);
  });

  it("would fail in every theme at the spec's 60% if the wash were painted over the bars", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderIn(theme.id);
      const swapped = paintModel(container, theme.id, ["bars", "wash", "edge", "edge"], 0.6);
      const worst = Math.min(...STRENGTHS.map((strength) => swapped.bars[strength]!));
      expect(worst, theme.id).toBeLessThan(BRUSH_MIN_CONTRAST);
    }
  });

  it("would still fail at the solved opacity in the six themes that keep 60%, so the order is not decoration", () => {
    for (const theme of themes.filter((candidate) => candidate.id !== "high-contrast")) {
      cleanup();
      const { container } = renderIn(theme.id);
      const swapped = paintModel(container, theme.id, ["bars", "wash", "edge", "edge"]);
      const worst = Math.min(...STRENGTHS.map((strength) => swapped.bars[strength]!));
      expect(worst, theme.id).toBeLessThan(BRUSH_MIN_CONTRAST);
    }
  });

  it("keeps every bar's full-opacity outline at 3:1 on the strip and on the wash in every theme (R1)", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderIn(theme.id);
      const { outlines } = paintModel(container, theme.id);
      expect(outlines).toHaveLength(4);
      for (const outline of outlines) {
        expect(outline.onSurface, theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
        expect(outline.onWash, theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    }
  });

  it("is why the unselected bars are faded in their fill only: faded as a whole they miss 3:1 in light", () => {
    cleanup();
    const { container } = renderIn("light");
    const palette = overviewPaletteFor(themeOf("light"));
    const wash = paintModel(container, "light").wash;
    const exactFaded = compositeOver(wash, palette.bars[0]!, 0.4);
    expect(contrastRatio(exactFaded, wash)).toBeLessThan(BRUSH_MIN_CONTRAST);
  });

  it("keeps the handles, which are the band's edges, at 3:1 on the strip and on the wash in every theme", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderIn(theme.id);
      const model = paintModel(container, theme.id);
      const edges = [...container.querySelectorAll<HTMLElement>("[data-evtx-layer='edge']")];
      expect(edges).toHaveLength(2);
      for (const edge of edges) {
        const color = resolved(/var\([^)]*\)/.exec(edge.style.borderLeft)![0], theme.id);
        expect(contrastRatio(color, model.surface), theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
        expect(contrastRatio(color, model.wash), theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      }
    }
  });

  it("keeps the focus ring at 3:1 on the strip and on the wash in every theme", () => {
    for (const theme of themes) {
      cleanup();
      const { container } = renderIn(theme.id);
      const model = paintModel(container, theme.id);
      const focus = toHex(resolveToken(tokens.colorStrokeFocus2, theme));
      expect(contrastRatio(focus, model.surface), theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
      expect(contrastRatio(focus, model.wash), theme.id).toBeGreaterThanOrEqual(BRUSH_MIN_CONTRAST);
    }
  });
});

describe("the text reads at 4.5:1 on the strip's surface in every theme", () => {
  it.each(themes.map((theme) => [theme.id] as const))("in %s: the caption and the ticks", (themeId) => {
    const { container } = renderIn(themeId);
    const surface = resolved(tokens.colorNeutralBackground1, themeId);
    const caption = screen.getByTestId("overview-caption");
    expect(contrastRatio(resolved(caption.style.color, themeId), surface), `${themeId} caption`).toBeGreaterThanOrEqual(4.5);
    const tick = screen.getByTestId("overview-axis").firstElementChild as HTMLElement;
    expect(contrastRatio(resolved(tick.style.color, themeId), surface), `${themeId} tick`).toBeGreaterThanOrEqual(4.5);
    // The ticks are outside the box, so they are never read over the wash.
    expect(screen.getByTestId("overview-box").contains(tick)).toBe(false);
    expect(container.querySelectorAll("[data-evtx-layer]").length).toBe(4);
  });
});

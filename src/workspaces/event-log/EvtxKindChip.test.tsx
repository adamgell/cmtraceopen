/**
 * The EVT and LOG chip (#843): one component, so one pair of colors, measured in every theme. EVT is
 * the selection triplet's fill and text; LOG is bg3 with fg2 (spec 8.13 names bg4, which fg2 misses
 * 4.5:1 on in solarized-dark, and which is the defect of the older inline chip).
 */
import { tokens } from "@fluentui/react-components";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { contrastRatio } from "../../lib/color-contrast";
import {
  LOG_MONOSPACE_FONT_FAMILY,
  MAX_LOG_LIST_FONT_SIZE,
  MIN_LOG_LIST_FONT_SIZE,
} from "../../lib/log-accessibility";
import { getAllThemes, type ThemeId } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { EvtxKindChip } from "./EvtxKindChip";
import { resolveToken } from "./evtx-visual-tokens";

const { themeId: INITIAL_THEME_ID, logListFontSize: INITIAL_FONT_SIZE } = useUiStore.getState();

afterEach(() => {
  cleanup();
  useUiStore.setState({ themeId: INITIAL_THEME_ID, logListFontSize: INITIAL_FONT_SIZE });
});

const themes = getAllThemes();

/** The chip's own source, to see that it takes no size. */
const chipSource = Object.entries(
  import.meta.glob("./EvtxKindChip.tsx", { query: "?raw", import: "default", eager: true }) as Record<string, string>,
)[0]![1];

/** Every component source of the workspace, to see which of them draws a chip. */
const componentSources = import.meta.glob("./*.tsx", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

/** The colors a chip was drawn with, resolved to hex in `themeId`. */
function drawn(chip: "EVT" | "LOG", themeId: string) {
  useUiStore.setState({ themeId: themeId as ThemeId });
  const view = render(<EvtxKindChip chip={chip} />);
  const element = view.container.querySelector("[data-chip]") as HTMLElement;
  const theme = themes.find((candidate) => candidate.id === themeId)!;
  const result = {
    background: resolveToken(element.style.backgroundColor, theme),
    text: resolveToken(element.style.color, theme),
    element,
  };
  view.unmount();
  return result;
}

describe("EvtxKindChip", () => {
  it("shows EVT for a Windows event and LOG for a text-log line, and names what each is", () => {
    render(
      <>
        <EvtxKindChip chip="EVT" />
        <EvtxKindChip chip="LOG" />
      </>,
    );
    expect(screen.getByRole("img", { name: "Windows event" })).toHaveTextContent("EVT");
    expect(screen.getByRole("img", { name: "Text log line" })).toHaveTextContent("LOG");
    // The spoken name is its own attribute, not left to the tooltip.
    expect(screen.getByRole("img", { name: "Windows event" })).toHaveAttribute("aria-label", "Windows event");
    expect(screen.getByRole("img", { name: "Windows event" })).toHaveAttribute("title", "Windows event");
    expect(screen.getByRole("img", { name: "Text log line" })).toHaveAttribute("data-chip", "LOG");
  });

  it("draws EVT in the selection triplet and LOG on bg3 with fg2", () => {
    const evt = drawn("EVT", "light").element;
    expect(evt.style.backgroundColor).toBe(tokens.colorPaletteBlueBackground2);
    expect(evt.style.color).toBe(tokens.colorPaletteBlueForeground2);
    const log = drawn("LOG", "light").element;
    expect(log.style.backgroundColor).toBe(tokens.colorNeutralBackground3);
    expect(log.style.color).toBe(tokens.colorNeutralForeground2);
  });

  it("is drawn in the mono face, bold, with the spec's padding", () => {
    const view = render(<EvtxKindChip chip="LOG" />);
    const element = view.container.querySelector("[data-chip]") as HTMLElement;
    expect(element.style.fontFamily).toBe(LOG_MONOSPACE_FONT_FAMILY);
    expect(element.style.fontWeight).toBe("700");
    expect(element.style.padding).toBe("1px 6px");
    expect(element.style.borderRadius).toBe("4px");
    expect(element.style.whiteSpace).toBe("nowrap");
  });

  describe("owns its size: max(10, f - 4) of the log list font size", () => {
    const sizeAt = (chip: "EVT" | "LOG", fontSize: number) => {
      useUiStore.setState({ logListFontSize: fontSize });
      const view = render(<EvtxKindChip chip={chip} />);
      const size = (view.container.querySelector("[data-chip]") as HTMLElement).style.fontSize;
      view.unmount();
      return size;
    };

    it.each(["EVT", "LOG"] as const)("%s follows the store at every font size, and never goes under 10 px", (chip) => {
      const sizes: string[] = [];
      for (let f = MIN_LOG_LIST_FONT_SIZE; f <= MAX_LOG_LIST_FONT_SIZE; f += 1) {
        sizes.push(sizeAt(chip, f));
        expect(sizes[sizes.length - 1], `at ${f}`).toBe(`${Math.max(10, f - 4)}px`);
      }
      // The 10 px floor is real at the small end: f - 4 alone is 7 px at 11, and the tick's own floor 9 px.
      expect(sizes[0]).toBe("10px");
      expect(sizes[sizes.length - 1]).toBe("16px");
    });

    it("follows the store while it is mounted", () => {
      useUiStore.setState({ logListFontSize: MIN_LOG_LIST_FONT_SIZE });
      const view = render(<EvtxKindChip chip="EVT" />);
      const chip = () => view.container.querySelector("[data-chip]") as HTMLElement;
      expect(chip().style.fontSize).toBe("10px");
      act(() => useUiStore.setState({ logListFontSize: MAX_LOG_LIST_FONT_SIZE }));
      expect(chip().style.fontSize).toBe("16px");
    });

    it("takes no size from a caller: a size passed anyway is ignored", () => {
      useUiStore.setState({ logListFontSize: 14 });
      const extra = { fontSize: 30, style: { fontSize: "30px" } } as Record<string, unknown>;
      const view = render(<EvtxKindChip {...extra} chip="LOG" />);
      expect((view.container.querySelector("[data-chip]") as HTMLElement).style.fontSize).toBe("10px");
    });

    it("has no size prop to pass: its props are the kind alone", () => {
      const body = /interface EvtxKindChipProps \{([^}]*)\}/.exec(chipSource)?.[1] ?? "";
      expect(body.match(/^\s*\w+\??:/gm)?.map((line) => line.trim())).toEqual(["chip:"]);
    });
  });

  it("is the only component of the workspace that draws a kind chip", () => {
    const drawing = Object.entries(componentSources)
      .filter(([path, source]) => !path.endsWith(".test.tsx") && /data-chip=/.test(source))
      .map(([path]) => path);
    expect(drawing).toEqual(["./EvtxKindChip.tsx"]);
  });

  describe("contrast, in every theme", () => {
    it("measures seven themes", () => {
      expect(themes).toHaveLength(7);
    });

    it.each(["EVT", "LOG"] as const)("reaches 4.5:1 for the %s chip's text on its fill", (chip) => {
      const figures: string[] = [];
      for (const theme of themes) {
        const { background, text } = drawn(chip, theme.id);
        const ratio = contrastRatio(text, background);
        figures.push(`${theme.id} ${ratio.toFixed(2)}`);
        expect(ratio, `${chip} in ${theme.id}`).toBeGreaterThanOrEqual(4.5);
      }
      console.info(`${chip} chip text contrast: ${figures.join(", ")}`);
    });

    it("shows why LOG is bg3: the older inline chip's bg4 pair misses 4.5:1 in solarized-dark", () => {
      const theme = themes.find((candidate) => candidate.id === "solarized-dark")!;
      const bg4 = contrastRatio(
        resolveToken(tokens.colorNeutralForeground2, theme),
        resolveToken(tokens.colorNeutralBackground4, theme),
      );
      expect(bg4).toBeLessThan(4.5);
      const bg3 = contrastRatio(
        resolveToken(tokens.colorNeutralForeground2, theme),
        resolveToken(tokens.colorNeutralBackground3, theme),
      );
      expect(bg3).toBeGreaterThanOrEqual(4.5);
    });
  });
});

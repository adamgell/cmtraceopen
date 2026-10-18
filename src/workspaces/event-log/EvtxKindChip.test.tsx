/**
 * The EVT and LOG chip (#843): one component, so one pair of colors, measured in every theme. EVT is
 * the selection triplet's fill and text; LOG is bg3 with fg2 (spec 8.13 names bg4, which fg2 misses
 * 4.5:1 on in solarized-dark, and which is the defect of the older inline chip).
 */
import { tokens } from "@fluentui/react-components";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { contrastRatio } from "../../lib/color-contrast";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { getAllThemes, type ThemeId } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import { EvtxKindChip } from "./EvtxKindChip";
import { resolveToken } from "./evtx-visual-tokens";

afterEach(() => {
  cleanup();
});

const themes = getAllThemes();

/** Every component source of the workspace, to see which of them draws a chip. */
const componentSources = import.meta.glob("./*.tsx", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

/** The colors a chip was drawn with, resolved to hex in `themeId`. */
function drawn(chip: "EVT" | "LOG", themeId: string) {
  useUiStore.setState({ themeId: themeId as ThemeId });
  const view = render(<EvtxKindChip chip={chip} fontSize={11} />);
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
        <EvtxKindChip chip="EVT" fontSize={11} />
        <EvtxKindChip chip="LOG" fontSize={11} />
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

  it("takes its size from the caller, in the mono face, bold, with the spec's padding", () => {
    const view = render(<EvtxKindChip chip="LOG" fontSize={13} />);
    const element = view.container.querySelector("[data-chip]") as HTMLElement;
    expect(element.style.fontSize).toBe("13px");
    expect(element.style.fontFamily).toBe(LOG_MONOSPACE_FONT_FAMILY);
    expect(element.style.fontWeight).toBe("700");
    expect(element.style.padding).toBe("1px 6px");
    expect(element.style.borderRadius).toBe("4px");
    expect(element.style.whiteSpace).toBe("nowrap");
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

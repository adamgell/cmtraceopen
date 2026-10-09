import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { contrastRatio, readableOn } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes";
import type { DiagnosisCorrelationStatus, EvtxLevel } from "./types";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";
import moduleSource from "./evtx-visual-tokens.ts?raw";

const LEVELS: EvtxLevel[] = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

const STRENGTHS: DiagnosisCorrelationStatus[] = [
  "exact",
  "candidate",
  "ambiguous",
  "coverageBlocked",
  "notCausal",
];

const themes = getAllThemes().map((theme) => [theme.id, theme] as const);

/** Resolves a `var(--name)` reference through the theme, else returns the value. */
function resolve(value: string, theme: CMTraceTheme): string {
  const match = /^var\(\s*--([\w-]+)\s*(?:,[^)]*)?\)$/.exec(value.trim());
  if (!match) return value;
  const resolved = (theme.fluentTheme as unknown as Record<string, string>)[
    match[1]
  ];
  if (typeof resolved !== "string") {
    throw new Error(`Theme ${theme.id} has no token ${match[1]}`);
  }
  return resolved;
}

function toRgb(color: string): [number, number, number] {
  const hex = color.trim().replace(/^#/, "");
  if (!/^([0-9a-f]{3}|[0-9a-f]{6})$/i.test(hex)) {
    throw new Error(`Not a #rgb or #rrggbb color: ${color}`);
  }
  const full =
    hex.length === 3
      ? hex
          .split("")
          .map((c) => c + c)
          .join("")
      : hex;
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ];
}

function distance(a: string, b: string): number {
  const [ar, ag, ab] = toRgb(a);
  const [br, bg, bb] = toRgb(b);
  return Math.hypot(ar - br, ag - bg, ab - bb);
}

function hueSaturation(color: string): { hue: number; saturation: number } {
  const [r, g, b] = toRgb(color).map((v) => v / 255);
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const delta = max - min;
  const lightness = (max + min) / 2;
  if (delta === 0) return { hue: 0, saturation: 0 };
  const saturation = delta / (1 - Math.abs(2 * lightness - 1));
  let hue: number;
  if (max === r) hue = ((g - b) / delta + 6) % 6;
  else if (max === g) hue = (b - r) / delta + 2;
  else hue = (r - g) / delta + 4;
  return { hue: hue * 60, saturation };
}

function hslLightness(color: string): number {
  const [r, g, b] = toRgb(color).map((v) => v / 255);
  return (Math.max(r, g, b) + Math.min(r, g, b)) / 2;
}

const inRedBand = (hue: number) => hue >= 330 || hue <= 20;

describe("evtx visual tokens", () => {
  it("cycles channel colors every six channels", () => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0].severityPalette);

    expect(visual.channelColor(6)).toBe(visual.channelColor(0));
    expect(visual.channelColor(13)).toBe(visual.channelColor(1));
  });

  it.each(themes)("maps every level in the %s theme", (_id, theme) => {
    const visual = buildEvtxVisualTokens(theme.severityPalette);

    for (const level of LEVELS) {
      const entry = visual.levels[level];
      expect(entry.label).toBe(level);
      for (const color of [
        entry.barColor,
        entry.dotColor,
        entry.iconColor,
        entry.rowBackground,
        entry.rowText,
      ]) {
        expect(color).toEqual(expect.any(String));
        expect(color.length).toBeGreaterThan(0);
      }
      expect(entry.GridIcon).toBeDefined();
      expect(entry.RailIcon).toBeDefined();
    }
  });

  it("tints Critical and Error rows red and Warning rows amber, others plain", () => {
    const palette = getAllThemes()[0].severityPalette;
    const { levels } = buildEvtxVisualTokens(palette);

    expect(levels.Critical.rowBackground).toBe(palette.error.background);
    expect(levels.Error.rowBackground).toBe(palette.error.background);
    expect(levels.Warning.rowBackground).toBe(palette.warning.background);
    expect(levels.Information.rowBackground).toBe(
      tokens.colorNeutralBackground1,
    );
    expect(levels.Verbose.rowBackground).toBe(tokens.colorNeutralBackground1);
  });

  it("gives every level a distinct grid icon and rail icon", () => {
    const { levels } = buildEvtxVisualTokens(getAllThemes()[0].severityPalette);
    expect(new Set(LEVELS.map((l) => levels[l].GridIcon)).size).toBe(
      LEVELS.length,
    );
    expect(new Set(LEVELS.map((l) => levels[l].RailIcon)).size).toBe(
      LEVELS.length,
    );
  });

  describe.each(themes)("resolved colors in the %s theme", (id, theme) => {
    const visual = buildEvtxVisualTokens(theme.severityPalette);
    const surface = resolve(tokens.colorNeutralBackground1, theme);
    const selectionBorder = resolve(tokens.colorPaletteBlueBorderActive, theme);
    const mark = (level: EvtxLevel) => resolve(visual.levels[level].barColor, theme);
    const channel = (i: number) => resolve(visual.channelColor(i), theme);

    it("keeps every level bar and dot at 3:1 against the surface", () => {
      for (const level of LEVELS) {
        for (const [part, value] of [
          ["bar", visual.levels[level].barColor],
          ["dot", visual.levels[level].dotColor],
        ] as const) {
          const color = resolve(value, theme);
          const ratio = contrastRatio(color, surface);
          expect(
            ratio,
            `${id}: ${level} ${part} ${color} on surface ${surface} = ${ratio.toFixed(2)}`,
          ).toBeGreaterThanOrEqual(3);
        }
      }
    });

    it("keeps every level icon at 3:1 against its own row background", () => {
      for (const level of LEVELS) {
        const icon = resolve(visual.levels[level].iconColor, theme);
        const row = resolve(visual.levels[level].rowBackground, theme);
        const ratio = contrastRatio(icon, row);
        expect(
          ratio,
          `${id}: ${level} icon ${icon} on row ${row} = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(3);
      }
    });

    it("keeps critical, error, warning and information marks apart", () => {
      const names: EvtxLevel[] = ["Critical", "Error", "Warning", "Information"];
      for (let i = 0; i < names.length; i++) {
        for (let j = i + 1; j < names.length; j++) {
          const d = distance(mark(names[i]), mark(names[j]));
          expect(
            d,
            `${id}: ${names[i]} ${mark(names[i])} vs ${names[j]} ${mark(names[j])} = ${d.toFixed(1)}`,
          ).toBeGreaterThanOrEqual(80);
        }
      }
    });

    it("keeps the critical mark apart from the selection border", () => {
      const d = distance(mark("Critical"), selectionBorder);
      expect(
        d,
        `${id}: Critical ${mark("Critical")} vs selection ${selectionBorder} = ${d.toFixed(1)}`,
      ).toBeGreaterThanOrEqual(80);
    });

    it("keeps channel colors readable and apart from levels and selection", () => {
      for (let i = 0; i < 6; i++) {
        const color = channel(i);
        const ratio = contrastRatio(color, surface);
        expect(
          ratio,
          `${id}: channel ${i} ${color} on surface ${surface} = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(3);
        const others: [string, string][] = [
          ["Critical", mark("Critical")],
          ["Error", mark("Error")],
          ["Warning", mark("Warning")],
          ["selection", selectionBorder],
        ];
        for (const [name, other] of others) {
          const d = distance(color, other);
          expect(
            d,
            `${id}: channel ${i} ${color} vs ${name} ${other} = ${d.toFixed(1)}`,
          ).toBeGreaterThanOrEqual(80);
        }
        for (let j = i + 1; j < 6; j++) {
          const d = distance(color, channel(j));
          expect(
            d,
            `${id}: channel ${i} ${color} vs channel ${j} ${channel(j)} = ${d.toFixed(1)}`,
          ).toBeGreaterThanOrEqual(60);
        }
      }
    });

    it("keeps critical and error in the red family", () => {
      if (id === "hotdog-stand") return; // red surface, exempt
      for (const level of ["Critical", "Error"] as const) {
        const color = mark(level);
        const { hue, saturation } = hueSaturation(color);
        expect(
          inRedBand(hue) && saturation >= 0.35,
          `${id}: ${level} ${color} hue ${hue.toFixed(0)} saturation ${saturation.toFixed(2)} outside red band [330,20] or below 0.35`,
        ).toBe(true);
      }
    });

    it("keeps every channel in the cool hue band", () => {
      for (let i = 0; i < 6; i++) {
        const color = channel(i);
        const { hue, saturation } = hueSaturation(color);
        expect(
          hue >= 165 && hue <= 290 && saturation >= 0.3,
          `${id}: channel ${i} ${color} hue ${hue.toFixed(0)} saturation ${saturation.toFixed(2)} outside [165,290] or below 0.30`,
        ).toBe(true);
      }
    });

    it("keeps the classic-cmtrace error bar a visible red", () => {
      if (id !== "classic-cmtrace") return;
      const color = mark("Error");
      const { hue, saturation } = hueSaturation(color);
      const lightness = hslLightness(color);
      expect(
        inRedBand(hue) && saturation >= 0.35 && lightness >= 0.25,
        `${id}: Error bar ${color} hue ${hue.toFixed(0)} saturation ${saturation.toFixed(2)} lightness ${lightness.toFixed(2)} is not a visible red`,
      ).toBe(true);
    });

    it("keeps coverage states apart from success and failure", () => {
      const palette = theme.severityPalette;
      // Foreground and border must differ from every outcome color. A
      // background may equal the surface but not an outcome tint that differs
      // from the surface (error/success/warning backgrounds). In high-contrast
      // and hotdog-stand the error tint is the surface itself, so none exists.
      const outcomes = [
        palette.error.text,
        palette.success.text,
        palette.status.error.foreground,
        palette.status.success.foreground,
        palette.error.background,
        palette.success.background,
        visual.levels.Critical.barColor,
        visual.levels.Error.barColor,
      ].map((value) => resolve(value, theme).toLowerCase());
      const tints = [
        palette.error.background,
        palette.success.background,
        palette.warning.background,
      ]
        .map((value) => resolve(value, theme).toLowerCase())
        .filter((tint) => tint !== surface.toLowerCase());

      const collisions: string[] = [];
      for (const strength of ["coverageBlocked", "notCausal"] as const) {
        const badge = visual.strengths[strength];
        for (const [part, value] of [
          ["foreground", badge.foreground],
          ["border", badge.border],
        ] as const) {
          const color = resolve(value, theme).toLowerCase();
          if (outcomes.includes(color)) {
            collisions.push(`${strength} ${part} ${color}`);
          }
        }
        const background = resolve(badge.background, theme).toLowerCase();
        if (tints.includes(background)) {
          collisions.push(`${strength} background ${background}`);
        }
      }
      expect(
        collisions,
        `${id}: neutral badge colors collide with outcome colors [${outcomes.join(", ")}] or tints [${tints.join(", ")}]`,
      ).toEqual([]);

      const border = resolve(visual.strengths.coverageBlocked.border, theme);
      const ratio = contrastRatio(border, surface);
      expect(
        ratio,
        `${id}: coverageBlocked border ${border} on surface ${surface} = ${ratio.toFixed(2)}`,
      ).toBeGreaterThanOrEqual(3);
      expect(visual.strengths.coverageBlocked.borderStyle).not.toBe(
        visual.strengths.candidate.borderStyle,
      );
      expect(visual.strengths.coverageBlocked.Icon).toBeDefined();
    });

    it("keeps selection text at 4.5:1 on the selection background", () => {
      const fg = resolve(visual.selection.foreground, theme);
      const bg = resolve(visual.selection.background, theme);
      const ratio = contrastRatio(fg, bg);
      expect(
        ratio,
        `${id}: selection foreground ${fg} on ${bg} = ${ratio.toFixed(2)}`,
      ).toBeGreaterThanOrEqual(4.5);
    });
  });

  it.each(themes)("maps every strength in the %s theme", (_id, theme) => {
    const { strengths } = buildEvtxVisualTokens(theme.severityPalette);

    expect(STRENGTHS.map((strength) => strengths[strength].label)).toEqual([
      "Exact",
      "Candidate",
      "Ambiguous",
      "Coverage blocked",
      "Not linked",
    ]);
    for (const strength of STRENGTHS) {
      const badge = strengths[strength];
      for (const color of [badge.background, badge.foreground, badge.border]) {
        expect(color).toEqual(expect.any(String));
        expect(color.length).toBeGreaterThan(0);
      }
    }
  });

  it("uses the blue palette triplet for selection and the Exact badge (Q-1)", () => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0].severityPalette);

    expect(visual.selection).toEqual({
      background: tokens.colorPaletteBlueBackground2,
      border: tokens.colorPaletteBlueBorderActive,
      foreground: tokens.colorPaletteBlueForeground2,
    });
    expect(visual.strengths.exact).toMatchObject({
      background: tokens.colorPaletteBlueBackground2,
      foreground: tokens.colorPaletteBlueForeground2,
      border: tokens.colorPaletteBlueBorderActive,
    });
  });

  it("builds six heat-map steps from merge color 0 (Q-3 interim)", () => {
    const palette = getAllThemes()[0].severityPalette;
    const { heatSteps } = buildEvtxVisualTokens(palette);

    expect(heatSteps).toEqual(
      [15, 30, 45, 60, 75, 90].map(
        (percent) =>
          `color-mix(in srgb, ${palette.mergeColors[0]} ${percent}%, ${tokens.colorNeutralBackground1})`,
      ),
    );
  });

  it("contains no color literals", () => {
    expect(moduleSource).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(moduleSource).not.toMatch(/\brgba?\(/i);
    expect(moduleSource).not.toMatch(/\bhsla?\(/i);
  });
});

describe("readableOn", () => {
  it("keeps a preferred color that reaches the minimum", () => {
    expect(readableOn("#ffffff", "#dc2626")).toBe("#dc2626");
  });

  it("falls back to black on a light background", () => {
    expect(readableOn("#ffff00", "#ffffaa")).toBe("#000000");
  });

  it("falls back to white on a dark background", () => {
    expect(readableOn("#111111", "#222222")).toBe("#ffffff");
  });

  it("honors a custom minimum", () => {
    expect(readableOn("#ffffff", "#767676", 7)).toBe("#000000");
  });

  it("throws on a non-hex color", () => {
    expect(() => contrastRatio("red", "#fff")).toThrow(
      "Expected a #rgb or #rrggbb color, got red",
    );
  });
});

import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import {
  contrastRatio,
  parseHex,
  readableOn,
} from "../../lib/color-contrast";
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

/**
 * Themes excluded from the "neutral badges are unlike outcome colors" test
 * only. Every neutral token in hotdog-stand is yellow on a red surface, and
 * its error and warning colors are those same yellows and reds, so no neutral
 * can be perceptually unlike an outcome color there.
 */
const NEUTRAL_OUTCOME_EXEMPT_THEMES: readonly string[] = ["hotdog-stand"];

/** hotdog-stand sits on a red surface, so the red-family rule cannot apply. */
const RED_FAMILY_EXEMPT_THEMES: readonly string[] = ["hotdog-stand"];

const themes = getAllThemes().map((theme) => [theme.id, theme] as const);
const redFamilyThemes = themes.filter(
  ([id]) => !RED_FAMILY_EXEMPT_THEMES.includes(id),
);
const outcomeCheckedThemes = themes.filter(
  ([id]) => !NEUTRAL_OUTCOME_EXEMPT_THEMES.includes(id),
);
const classicTheme = themes.filter(([id]) => id === "classic-cmtrace");

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

type Lab = [number, number, number];

function hexToLab(color: string): Lab {
  const [r, g, b] = parseHex(color).map((channel) => {
    const c = channel / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  // sRGB to XYZ, D65.
  const x = 0.4124564 * r + 0.3575761 * g + 0.1804375 * b;
  const y = 0.2126729 * r + 0.7151522 * g + 0.072175 * b;
  const z = 0.0193339 * r + 0.119192 * g + 0.9503041 * b;
  const f = (t: number) =>
    t > 216 / 24389 ? Math.cbrt(t) : (24389 / 27 * t + 16) / 116;
  const fx = f(x / 0.95047);
  const fy = f(y);
  const fz = f(z / 1.08883);
  return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
}

/** CIEDE2000 between two Lab colors (Sharma, Wu, Dalal 2005). */
function deltaE00Lab(lab1: Lab, lab2: Lab): number {
  const rad = (deg: number) => (deg * Math.PI) / 180;
  const deg = (r: number) => (r * 180) / Math.PI;
  const [l1, a1, b1] = lab1;
  const [l2, a2, b2] = lab2;
  const c1 = Math.hypot(a1, b1);
  const c2 = Math.hypot(a2, b2);
  const cBar = (c1 + c2) / 2;
  const g = 0.5 * (1 - Math.sqrt(cBar ** 7 / (cBar ** 7 + 25 ** 7)));
  const a1p = (1 + g) * a1;
  const a2p = (1 + g) * a2;
  const c1p = Math.hypot(a1p, b1);
  const c2p = Math.hypot(a2p, b2);
  const hp = (b: number, a: number) =>
    b === 0 && a === 0 ? 0 : (deg(Math.atan2(b, a)) + 360) % 360;
  const h1p = hp(b1, a1p);
  const h2p = hp(b2, a2p);
  const dLp = l2 - l1;
  const dCp = c2p - c1p;
  let dhp = 0;
  if (c1p * c2p !== 0) {
    dhp = h2p - h1p;
    if (dhp > 180) dhp -= 360;
    else if (dhp < -180) dhp += 360;
  }
  const dHp = 2 * Math.sqrt(c1p * c2p) * Math.sin(rad(dhp / 2));
  const lBarP = (l1 + l2) / 2;
  const cBarP = (c1p + c2p) / 2;
  let hBarP = h1p + h2p;
  if (c1p * c2p !== 0) {
    if (Math.abs(h1p - h2p) > 180) {
      hBarP += h1p + h2p < 360 ? 360 : -360;
    }
    hBarP /= 2;
  }
  const t =
    1 -
    0.17 * Math.cos(rad(hBarP - 30)) +
    0.24 * Math.cos(rad(2 * hBarP)) +
    0.32 * Math.cos(rad(3 * hBarP + 6)) -
    0.2 * Math.cos(rad(4 * hBarP - 63));
  const dTheta = 30 * Math.exp(-(((hBarP - 275) / 25) ** 2));
  const rC = 2 * Math.sqrt(cBarP ** 7 / (cBarP ** 7 + 25 ** 7));
  const sL =
    1 + (0.015 * (lBarP - 50) ** 2) / Math.sqrt(20 + (lBarP - 50) ** 2);
  const sC = 1 + 0.045 * cBarP;
  const sH = 1 + 0.015 * cBarP * t;
  const rT = -Math.sin(rad(2 * dTheta)) * rC;
  return Math.sqrt(
    (dLp / sL) ** 2 +
      (dCp / sC) ** 2 +
      (dHp / sH) ** 2 +
      rT * (dCp / sC) * (dHp / sH),
  );
}

/** Perceptual distance between two `#rgb` or `#rrggbb` colors. */
function deltaE00(a: string, b: string): number {
  return deltaE00Lab(hexToLab(a), hexToLab(b));
}

function hueSaturation(color: string): { hue: number; saturation: number } {
  const [r, g, b] = parseHex(color).map((v) => v / 255);
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
  const [r, g, b] = parseHex(color).map((v) => v / 255);
  return (Math.max(r, g, b) + Math.min(r, g, b)) / 2;
}

const inRedBand = (hue: number) => hue >= 330 || hue <= 20;

describe("deltaE00", () => {
  it("matches the Sharma 2005 reference pair", () => {
    expect(deltaE00Lab([50, 2.6772, -79.7751], [50, 0, -82.7485])).toBeCloseTo(
      2.0425,
      3,
    );
  });

  it("is zero for identical colors", () => {
    expect(deltaE00("#336699", "#336699")).toBeCloseTo(0, 6);
  });
});

describe("contrastRatio", () => {
  it("gives 21 for black on white", () => {
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
  });

  it("throws on a non-hex color", () => {
    expect(() => contrastRatio("red", "#fff")).toThrow(
      "Expected a #rgb or #rrggbb color, got red",
    );
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
});

describe("evtx visual tokens", () => {
  it("cycles channel colors every six channels", () => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0].severityPalette);

    expect(visual.channelColor(6)).toBe(visual.channelColor(0));
    expect(visual.channelColor(13)).toBe(visual.channelColor(1));
  });

  it.each(["light", "high-contrast"])(
    "maps every level to concrete tokens in the %s theme",
    (id) => {
      const theme = getAllThemes().find((t) => t.id === id)!;
      const palette = theme.severityPalette;
      const { levels } = buildEvtxVisualTokens(palette);
      const selectedIcon = tokens.colorPaletteBlueForeground2;
      const marks: Record<EvtxLevel, string> = {
        Critical: palette.eventLog.critical,
        Error: palette.eventLog.error,
        Warning: palette.eventLog.warning,
        Information: palette.eventLog.information,
        Verbose: palette.eventLog.verbose,
      };
      const rows: Record<EvtxLevel, { background: string; text: string }> = {
        Critical: {
          background: palette.error.background,
          text: palette.error.text,
        },
        Error: {
          background: palette.error.background,
          text: palette.error.text,
        },
        Warning: {
          background: palette.warning.background,
          text: palette.warning.text,
        },
        Information: {
          background: tokens.colorNeutralBackground1,
          text: tokens.colorNeutralForeground1,
        },
        Verbose: {
          background: tokens.colorNeutralBackground1,
          text: tokens.colorNeutralForeground1,
        },
      };

      for (const level of LEVELS) {
        const entry = levels[level];
        expect(entry.label).toBe(level);
        expect(entry.barColor).toBe(marks[level]);
        expect(entry.dotColor).toBe(marks[level]);
        expect(entry.railIconColor).toBe(marks[level]);
        expect(entry.rowBackground).toBe(rows[level].background);
        expect(entry.rowText).toBe(rows[level].text);
        expect(entry.selectedIconColor).toBe(selectedIcon);
        expect(entry.GridIcon).toBeDefined();
        expect(entry.RailIcon).toBeDefined();
      }
    },
  );

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
    const rail = resolve(tokens.colorNeutralBackground2, theme);
    const selectionBorder = resolve(tokens.colorPaletteBlueBorderActive, theme);
    const brandBackground = resolve(tokens.colorBrandBackground, theme);
    const brandLink = resolve(tokens.colorBrandForegroundLink, theme);
    const mark = (level: EvtxLevel) =>
      resolve(visual.levels[level].barColor, theme);
    const channel = (i: number) => resolve(visual.channelColor(i), theme);
    const channelFloor = id === "high-contrast" ? 4.5 : 3;

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

    it("keeps every rail icon at 3:1 against the rail background", () => {
      for (const level of LEVELS) {
        const icon = resolve(visual.levels[level].railIconColor, theme);
        const ratio = contrastRatio(icon, rail);
        expect(
          ratio,
          `${id}: ${level} rail icon ${icon} on rail ${rail} = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(3);
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

    it("keeps selected-row icons at 4.5:1 on the selection background", () => {
      const bg = resolve(visual.selection.background, theme);
      for (const level of LEVELS) {
        const icon = resolve(visual.levels[level].selectedIconColor, theme);
        const ratio = contrastRatio(icon, bg);
        expect(
          ratio,
          `${id}: ${level} selected icon ${icon} on selection ${bg} = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    });

    it("keeps level marks perceptually apart", () => {
      for (let i = 0; i < LEVELS.length; i++) {
        for (let j = i + 1; j < LEVELS.length; j++) {
          const a = LEVELS[i];
          const b = LEVELS[j];
          // Information and Verbose may look alike; both are neutrals.
          if (a === "Information" && b === "Verbose") continue;
          const d = deltaE00(mark(a), mark(b));
          expect(
            d,
            `${id}: ${a} ${mark(a)} vs ${b} ${mark(b)} dE00 = ${d.toFixed(1)}`,
          ).toBeGreaterThanOrEqual(20);
        }
      }
    });

    it("keeps the critical mark apart from the selection border", () => {
      const d = deltaE00(mark("Critical"), selectionBorder);
      expect(
        d,
        `${id}: Critical ${mark("Critical")} vs selection ${selectionBorder} dE00 = ${d.toFixed(1)}`,
      ).toBeGreaterThanOrEqual(20);
    });

    it("keeps channel colors readable on the surface", () => {
      for (let i = 0; i < 6; i++) {
        const color = channel(i);
        const ratio = contrastRatio(color, surface);
        expect(
          ratio,
          `${id}: channel ${i} ${color} on surface ${surface} = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(channelFloor);
      }
    });

    it("keeps channels apart from each other", () => {
      for (let i = 0; i < 6; i++) {
        for (let j = i + 1; j < 6; j++) {
          const d = deltaE00(channel(i), channel(j));
          expect(
            d,
            `${id}: channel ${i} ${channel(i)} vs channel ${j} ${channel(j)} dE00 = ${d.toFixed(1)}`,
          ).toBeGreaterThanOrEqual(15);
        }
      }
    });

    it("keeps channels apart from level marks, brand and selection", () => {
      const others: [string, string][] = [
        ...LEVELS.map((level) => [level, mark(level)] as [string, string]),
        ["brand background", brandBackground],
        ["brand link", brandLink],
        ["selection border", selectionBorder],
      ];
      for (let i = 0; i < 6; i++) {
        for (const [name, other] of others) {
          const d = deltaE00(channel(i), other);
          expect(
            d,
            `${id}: channel ${i} ${channel(i)} vs ${name} ${other} dE00 = ${d.toFixed(1)}`,
          ).toBeGreaterThanOrEqual(15);
        }
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

    it("keeps badge label text at 4.5:1 on its badge background", () => {
      for (const strength of ["coverageBlocked", "notCausal"] as const) {
        const badge = visual.strengths[strength];
        const fg = resolve(badge.foreground, theme);
        const bg = resolve(badge.background, theme);
        const ratio = contrastRatio(fg, bg);
        expect(
          ratio,
          `${id}: ${strength} label ${fg} on ${bg} = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    });

    it("gives coverageBlocked a visible border unlike Candidate's", () => {
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

  describe.each(redFamilyThemes)("red family in the %s theme", (id, theme) => {
    const visual = buildEvtxVisualTokens(theme.severityPalette);

    it.each(["Critical", "Error"] as const)("keeps %s red", (level) => {
      const color = resolve(visual.levels[level].barColor, theme);
      const { hue, saturation } = hueSaturation(color);
      expect(
        inRedBand(hue) && saturation >= 0.35,
        `${id}: ${level} ${color} hue ${hue.toFixed(0)} saturation ${saturation.toFixed(2)} outside red band [330,20] or below 0.35`,
      ).toBe(true);
    });
  });

  describe.each(redFamilyThemes)("severity vividness in the %s theme", (id, theme) => {
    const visual = buildEvtxVisualTokens(theme.severityPalette);

    it.each(["Critical", "Error"] as const)(
      "keeps the %s mark vivid (Lab chroma >= 40)",
      (level) => {
        const color = resolve(visual.levels[level].barColor, theme);
        const [, a, b] = hexToLab(color);
        const chroma = Math.hypot(a, b);
        expect(
          chroma,
          `${id}: ${level} ${color} chroma C* = ${chroma.toFixed(1)}`,
        ).toBeGreaterThanOrEqual(40);
      },
    );
  });

  describe.each(classicTheme)("%s error bar", (id, theme) => {
    it("is a visible red, not near-black", () => {
      const visual = buildEvtxVisualTokens(theme.severityPalette);
      const color = resolve(visual.levels.Error.barColor, theme);
      const { hue, saturation } = hueSaturation(color);
      const lightness = hslLightness(color);
      expect(
        inRedBand(hue) && saturation >= 0.35 && lightness >= 0.25,
        `${id}: Error bar ${color} hue ${hue.toFixed(0)} saturation ${saturation.toFixed(2)} lightness ${lightness.toFixed(2)} is not a visible red`,
      ).toBe(true);
    });
  });

  describe.each(outcomeCheckedThemes)(
    "neutral badges in the %s theme",
    (id, theme) => {
      const visual = buildEvtxVisualTokens(theme.severityPalette);
      const palette = theme.severityPalette;
      const surface = resolve(tokens.colorNeutralBackground1, theme);

      it("are perceptually unlike outcome colors (dE00 >= 10)", () => {
        const outcomes = [
          palette.error.text,
          palette.success.text,
          palette.status.error.foreground,
          palette.status.success.foreground,
          palette.error.background,
          palette.success.background,
          visual.levels.Critical.barColor,
          visual.levels.Error.barColor,
        ].map((value) => resolve(value, theme));
        // A background may equal the surface but not an outcome tint that
        // differs from it by dE00 >= 10 (error, success and warning backgrounds);
        // a tint closer to the surface than that is not a distinct tint.
        const tints = [
          palette.error.background,
          palette.success.background,
          palette.warning.background,
        ]
          .map((value) => resolve(value, theme))
          .filter((tint) => deltaE00(tint, surface) >= 10);

        const problems: string[] = [];
        for (const strength of ["coverageBlocked", "notCausal"] as const) {
          const badge = visual.strengths[strength];
          for (const [part, value] of [
            ["foreground", badge.foreground],
            ["border", badge.border],
          ] as const) {
            const color = resolve(value, theme);
            for (const outcome of outcomes) {
              const d = deltaE00(color, outcome);
              if (d < 10) {
                problems.push(
                  `${strength} ${part} ${color} vs ${outcome} dE00 ${d.toFixed(1)}`,
                );
              }
            }
          }
          const background = resolve(badge.background, theme);
          for (const tint of tints) {
            const d = deltaE00(background, tint);
            if (d < 10) {
              problems.push(
                `${strength} background ${background} vs tint ${tint} dE00 ${d.toFixed(1)}`,
              );
            }
          }
        }
        expect(problems, `${id}: ${problems.join("; ")}`).toEqual([]);
      });
    },
  );

  it.each(themes)("maps every strength in the %s theme", (_id, theme) => {
    const { strengths } = buildEvtxVisualTokens(theme.severityPalette);

    expect(STRENGTHS.map((strength) => strengths[strength].label)).toEqual([
      "Exact",
      "Candidate",
      "Ambiguous",
      "Coverage blocked",
      "Not linked",
    ]);
  });

  it.each(["light", "high-contrast"])(
    "maps strengths to concrete tokens in the %s theme",
    (id) => {
      const palette = getAllThemes().find((t) => t.id === id)!.severityPalette;
      const { strengths } = buildEvtxVisualTokens(palette);

      expect(strengths.exact).toMatchObject({
        background: tokens.colorPaletteBlueBackground2,
        foreground: tokens.colorPaletteBlueForeground2,
        border: tokens.colorPaletteBlueBorderActive,
        borderStyle: "solid",
      });
      expect(strengths.candidate).toMatchObject({
        background: tokens.colorNeutralBackground3,
        foreground: tokens.colorNeutralForeground2,
        border: tokens.colorNeutralForeground2,
        borderStyle: "dashed",
      });
      expect(strengths.ambiguous).toMatchObject({
        background: palette.warning.background,
        foreground: palette.warning.text,
        border: tokens.colorPaletteMarigoldBorder2,
        borderStyle: "solid",
      });
      expect(strengths.coverageBlocked).toMatchObject({
        background: tokens.colorNeutralBackground3,
        foreground: tokens.colorNeutralForeground2,
        border: tokens.colorNeutralStrokeAccessible,
        borderStyle: "solid",
      });
      expect(strengths.notCausal).toMatchObject({
        background: tokens.colorNeutralBackground3,
        foreground: tokens.colorNeutralForeground2,
        border: tokens.colorNeutralForeground3,
        borderStyle: "dotted",
      });
    },
  );

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

  it("contains no color literals outside comments", () => {
    const code = moduleSource
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/.*$/gm, "$1");
    expect(code).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(code).not.toMatch(
      /\b(rgba?|hsla?|oklch|oklab|lab|lch|hwb|color)\(/i,
    );
    expect(code).not.toMatch(
      /["'`](black|white|red|green|blue|yellow|orange|purple|gray|grey)["'`]/i,
    );
  });
});

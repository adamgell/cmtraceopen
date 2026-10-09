import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { contrastRatio, parseHex, readableOn } from "../../lib/color-contrast";
import { getAllThemes } from "../../lib/themes";
import type { DiagnosisCorrelationStatus, EvtxLevel } from "./types";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
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
 * removed in #878. hotdog-stand is exempt from the red-family rule (red
 * surface), the neutral-badge outcome rule (every neutral is yellow on red)
 * and every placement rule; its values are unchanged.
 */
const HOTDOG_REMOVED_IN_878: readonly string[] = ["hotdog-stand"];

const themes = getAllThemes().map((theme) => [theme.id, theme] as const);
const redFamilyThemes = themes.filter(
  ([id]) => !HOTDOG_REMOVED_IN_878.includes(id),
);
const outcomeCheckedThemes = themes.filter(
  ([id]) => !HOTDOG_REMOVED_IN_878.includes(id),
);
const surfaceThemes = themes.filter(
  ([id]) => !HOTDOG_REMOVED_IN_878.includes(id),
);
const classicTheme = themes.filter(([id]) => id === "classic-cmtrace");

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
    t > 216 / 24389 ? Math.cbrt(t) : ((24389 / 27) * t + 16) / 116;
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

type SurfaceKey =
  "surface" | "rail" | "group" | "pressed" | "selected" | "ownRow";

const SURFACE_TOKEN_LABEL: Record<SurfaceKey, string> = {
  surface: "colorNeutralBackground1",
  rail: "colorNeutralBackground2",
  group: "colorNeutralBackground3",
  // 6.2 note: the active-toggle TEXT (colorBrandForeground1 on
  // colorNeutralBackground1Selected) also fails in high-contrast at 1.46:1.
  // Toggle text is drawn by Fluent components, not by this module, so it is
  // not tested here; Phase 3, which builds the toggles, must handle it.
  // markOutline("pressed") is resolved per theme and is tested below.
  pressed: "colorNeutralBackground1Selected",
  selected: "selection background (colorPaletteBlueBackground2)",
  ownRow: "the level's own row background",
};

interface Placement {
  surface: SurfaceKey;
  /** Spec section that places the role on this surface. */
  section: string;
  /** Levels intentionally de-emphasized here, with the spec's reason. */
  exempt?: { names: readonly string[]; reason: string };
}

interface RoleEntry {
  role: string;
  minimum: number;
  colors: (
    visual: ReturnType<typeof buildEvtxVisualTokens>,
  ) => Record<string, string>;
  placements: readonly Placement[];
}

/**
 * Placement inventory, from a full read of spec sections 5, 6 (including 6.2
 * states) and 8.1 to 8.19 plus the v2 scenario notes (15.1). Every place a
 * color from this module is drawn is listed with its surface and section.
 * The spec names no hover state for these surfaces; the only pressed or
 * selected states are 6.2's `colorNeutralBackground1Selected` (pressed
 * toggles) and the selection triplet. Small marks on those two and on row
 * tints are covered by markOutline, tested separately below.
 */
const PLACEMENT_INVENTORY: readonly RoleEntry[] = [
  {
    role: "level bar",
    minimum: 3,
    colors: (v) =>
      Object.fromEntries(LEVELS.map((l) => [l, v.levels[l].barColor])),
    placements: [
      { surface: "surface", section: "8.5 histogram bars and legend swatches" },
      { surface: "surface", section: "8.8 collapsed group trend sparkline" },
      {
        surface: "surface",
        section: "8.10 errors and warnings per hour columns",
      },
      { surface: "surface", section: "8.13 finding card top border" },
      { surface: "rail", section: "8.13 level mix and top event IDs bars" },
      { surface: "group", section: "8.8 expanded group row trend sparkline" },
    ],
  },
  {
    role: "level dot",
    minimum: 3,
    colors: (v) =>
      Object.fromEntries(LEVELS.map((l) => [l, v.levels[l].dotColor])),
    placements: [
      { surface: "surface", section: "8.3 level toggle dots" },
      { surface: "surface", section: "8.13 chain card steps (card bg1)" },
      {
        surface: "surface",
        section: "8.11 correlation lane markers (lane plot)",
      },
      {
        surface: "surface",
        section: "8.12 dock lane markers (dock inner panel bg1)",
      },
    ],
  },
  {
    role: "swimlane dot",
    minimum: 3,
    colors: (v) =>
      Object.fromEntries(LEVELS.map((l) => [l, v.levels[l].dotColor])),
    placements: [
      {
        surface: "surface",
        section: "8.9 provider swimlane dots",
        // 8.9: "Info dots at 55% opacity". The spec de-emphasizes them on
        // purpose; Information is also tested at full strength on the surface
        // by every other placement above.
        exempt: {
          names: ["Information"],
          reason: "8.9 draws Information dots at 55% opacity by design",
        },
      },
    ],
  },
  {
    role: "level rail icon",
    minimum: 3,
    colors: (v) =>
      Object.fromEntries(LEVELS.map((l) => [l, v.levels[l].railIconColor])),
    placements: [
      { surface: "rail", section: "8.13 Details tab header icon (16px)" },
      { surface: "surface", section: "8.8 group row level icon (20px)" },
      { surface: "group", section: "8.8 expanded group row level icon" },
    ],
  },
  {
    role: "grid icon on own row tint",
    minimum: 3,
    colors: (v) =>
      Object.fromEntries(LEVELS.map((l) => [l, v.levels[l].iconColor])),
    placements: [{ surface: "ownRow", section: "8.7 Level cell icon, D13" }],
  },
  {
    role: "selected-row icon",
    minimum: 4.5,
    colors: (v) =>
      Object.fromEntries(LEVELS.map((l) => [l, v.levels[l].selectedIconColor])),
    placements: [
      { surface: "selected", section: "8.7 selected grid row, 6.2 selection" },
    ],
  },
  {
    role: "level text",
    minimum: 4.5,
    colors: (v) =>
      Object.fromEntries(LEVELS.map((l) => [l, v.levels[l].textColor])),
    placements: [
      {
        surface: "surface",
        section: "8.13 finding card eyebrow; 8.3 grammar error",
      },
      {
        surface: "rail",
        section: "8.13 Details level word; 8.6 err and warn counts",
      },
      {
        surface: "selected",
        section: "8.6 err and warn counts on a selected row",
      },
    ],
  },
  {
    role: "selection text",
    minimum: 4.5,
    colors: (v) => ({ selectionForeground: v.selection.foreground }),
    placements: [{ surface: "selected", section: "6.2 selected row text" }],
  },
  {
    role: "selected data color",
    minimum: 3,
    colors: (v) => ({ selectedDataColor: v.selectedDataColor }),
    placements: [
      { surface: "selected", section: "8.6 selected channel row sparkline" },
    ],
  },
  {
    role: "channel",
    minimum: 3,
    colors: (v) =>
      Object.fromEntries(
        [0, 1, 2, 3, 4, 5].map((i) => [`ch${i}`, v.channelColor(i)]),
      ),
    placements: [
      { surface: "surface", section: "8.7 Channel cell swatch on plain rows" },
      {
        surface: "surface",
        section: "8.10 events by channel bars",
      },
      { surface: "rail", section: "8.6 channel pane swatch and sparkline" },
    ],
  },
  {
    role: "single series",
    minimum: 3,
    colors: (v) => ({ singleSeries: v.singleSeries }),
    placements: [
      {
        surface: "surface",
        section: "8.10 top event IDs and crashes per day bars",
      },
    ],
  },
  {
    role: "scenario bar",
    minimum: 3,
    colors: (v) => ({
      succeededBar: v.scenario.succeeded.bar,
      running: v.scenario.running,
      retrying: v.scenario.retrying,
      sleep: v.scenario.sleep,
    }),
    placements: [
      { surface: "surface", section: "15.1 boot sessions and attempt bars" },
    ],
  },
  {
    role: "finding callout border",
    minimum: 3,
    colors: (v) => ({ border: v.findingCallout.border }),
    placements: [
      { surface: "rail", section: "8.13 Details tab finding callout (item 8)" },
    ],
  },
];

/**
 * Commented exemptions: places a color is drawn that this matrix does not
 * hold to the contrast floor, each with the spec section and reason.
 */
const INVENTORY_EXEMPTIONS: readonly {
  what: string;
  section: string;
  reason: string;
}[] = [
  {
    what: "Information dots in swimlanes",
    section: "8.9",
    reason: "the spec draws them at 55% opacity on purpose",
  },
  {
    what: "heat-map steps (15 to 90% mixes of mergeColors[0])",
    section: "8.10, D11",
    reason: "a sequential ramp of data fills; the faint steps are intentional",
  },
  {
    what: "row text, level words and finding callout text on error or warning tints",
    section: "6.3, 8.13",
    reason:
      "the palette.error.text on palette.error.background pairing is owned by PR #877",
  },
  {
    what: "selection inset border and Exact badge border on the selection background (light, classic-cmtrace: 2.87:1)",
    section: "6.2, Q-1, 8.11, 8.13",
    reason:
      "accepted by Adam 2026-10-08 (Q-1); the border is also the row's 3px inset",
  },
  {
    what: "severity eyebrow text in finding cards",
    section: "8.13",
    reason: "text, not a mark; it uses rowText, owned by PR #877",
  },
];

const BADGE_PLACEMENTS: readonly Placement[] = [
  {
    surface: "surface",
    section: "8.11 detail header and 8.13 chain cards (bg1)",
  },
  {
    surface: "rail",
    section: "8.11 chain list, 8.12 dock summary, 8.13 compact rows (bg2)",
  },
  {
    surface: "selected",
    section: "8.11 selected chain row and 8.13 selected chain card",
    // The Exact badge is the selection triplet itself (6.2, Q-1): its border
    // is the selection inset color, which is 2.87:1 on the selection
    // background in the light-family themes. The Q-1 triplet is fixed, the
    // badge fill equals the row fill, and the row is also marked by the 3px
    // inset, so this one pair is an explicit exemption.
    exempt: {
      names: ["exact"],
      reason: "6.2 and Q-1 fix the selection triplet; Exact is that triplet",
    },
  },
];

const SHARMA_PAIRS: [Lab, Lab, number][] = [
  [[50, 2.6772, -79.7751], [50, 0, -82.7485], 2.0425],
  [[50, 3.1571, -77.2803], [50, 0, -82.7485], 2.8615],
  [[50, 2.8361, -74.02], [50, 0, -82.7485], 3.4412],
  [[50, -1.3802, -84.2814], [50, 0, -82.7485], 1.0],
  [[50, -1.1848, -84.8006], [50, 0, -82.7485], 1.0],
  [[50, -0.9009, -85.5211], [50, 0, -82.7485], 1.0],
  [[50, 0, 0], [50, -1, 2], 2.3669],
  [[50, -1, 2], [50, 0, 0], 2.3669],
  [[50, 2.49, -0.001], [50, -2.49, 0.0009], 7.1792],
  [[50, 2.49, -0.001], [50, -2.49, 0.001], 7.1792],
  [[50, 2.49, -0.001], [50, -2.49, 0.0011], 7.2195],
  [[50, 2.49, -0.001], [50, -2.49, 0.0012], 7.2195],
  [[50, -0.001, 2.49], [50, 0.0009, -2.49], 4.8045],
  [[50, -0.001, 2.49], [50, 0.001, -2.49], 4.8045],
  [[50, -0.001, 2.49], [50, 0.0011, -2.49], 4.7461],
  [[50, 2.5, 0], [50, 0, -2.5], 4.3065],
  [[50, 2.5, 0], [73, 25, -18], 27.1492],
  [[50, 2.5, 0], [61, -5, 29], 22.8977],
  [[50, 2.5, 0], [56, -27, -3], 31.903],
  [[50, 2.5, 0], [58, 24, 15], 19.4535],
  [[50, 2.5, 0], [50, 3.1736, 0.5854], 1.0],
  [[50, 2.5, 0], [50, 3.2972, 0], 1.0],
  [[50, 2.5, 0], [50, 1.8634, 0.5757], 1.0],
  [[50, 2.5, 0], [50, 3.2592, 0.335], 1.0],
  [[60.2574, -34.0099, 36.2677], [60.4626, -34.1751, 39.4387], 1.2644],
  [[63.0109, -31.0961, -5.8663], [62.8187, -29.7946, -4.0864], 1.263],
  [[61.2901, 3.7196, -5.3901], [61.4292, 2.248, -4.962], 1.8731],
  [[35.0831, -44.1164, 3.7933], [35.0232, -40.0716, 1.5901], 1.8645],
  [[22.7233, 20.0904, -46.694], [23.0331, 14.973, -42.5619], 2.0373],
  [[36.4612, 47.858, 18.3852], [36.2715, 50.5065, 21.2231], 1.4146],
  [[90.8027, -2.0831, 1.441], [91.1528, -1.6435, 0.0447], 1.4441],
  [[90.9257, -0.5406, -0.9208], [88.6381, -0.8985, -0.7239], 1.5381],
  [[6.7747, -0.2908, -2.4247], [5.8714, -0.0985, -2.2286], 0.6377],
  [[2.0776, 0.0795, -1.135], [0.9033, -0.0636, -0.5514], 0.9082],
];

describe("deltaE00", () => {
  it.each(SHARMA_PAIRS)(
    "matches Sharma 2005 reference pair %j vs %j",
    (lab1, lab2, expected) => {
      expect(deltaE00Lab(lab1, lab2)).toBeCloseTo(expected, 3);
    },
  );

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

describe("resolveToken", () => {
  it("throws on an unknown Fluent token", () => {
    expect(() =>
      resolveToken("var(--colorDoesNotExist)", getAllThemes()[0]),
    ).toThrow("Unknown Fluent token");
  });

  it("returns non-token values unchanged", () => {
    expect(resolveToken("#123456", getAllThemes()[0])).toBe("#123456");
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
    const visual = buildEvtxVisualTokens(getAllThemes()[0]);

    expect(visual.channelColor(6)).toBe(visual.channelColor(0));
    expect(visual.channelColor(13)).toBe(visual.channelColor(1));
  });

  it("wraps negative channel indices", () => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0]);

    expect(visual.channelColor(-1)).toBe(visual.channelColor(5));
    expect(visual.channelColor(-7)).toBe(visual.channelColor(5));
  });

  it.each(["light", "high-contrast"])(
    "maps every level to concrete tokens in the %s theme",
    (id) => {
      const theme = getAllThemes().find((t) => t.id === id)!;
      const palette = theme.severityPalette;
      const { levels } = buildEvtxVisualTokens(theme);
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
    const { levels } = buildEvtxVisualTokens(getAllThemes()[0]);

    expect(levels.Critical.rowBackground).toBe(palette.error.background);
    expect(levels.Error.rowBackground).toBe(palette.error.background);
    expect(levels.Warning.rowBackground).toBe(palette.warning.background);
    expect(levels.Information.rowBackground).toBe(
      tokens.colorNeutralBackground1,
    );
    expect(levels.Verbose.rowBackground).toBe(tokens.colorNeutralBackground1);
  });

  it("gives every level a distinct grid icon and rail icon", () => {
    const { levels } = buildEvtxVisualTokens(getAllThemes()[0]);
    expect(new Set(LEVELS.map((l) => levels[l].GridIcon)).size).toBe(
      LEVELS.length,
    );
    expect(new Set(LEVELS.map((l) => levels[l].RailIcon)).size).toBe(
      LEVELS.length,
    );
  });

  describe.each(themes)("resolved colors in the %s theme", (id, theme) => {
    const visual = buildEvtxVisualTokens(theme);
    const selectionBorder = resolveToken(
      tokens.colorPaletteBlueBorderActive,
      theme,
    );
    const brandBackground = resolveToken(tokens.colorBrandBackground, theme);
    const brandLink = resolveToken(tokens.colorBrandForegroundLink, theme);
    const mark = (level: EvtxLevel) =>
      resolveToken(visual.levels[level].barColor, theme);
    const channel = (i: number) => resolveToken(visual.channelColor(i), theme);

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

    it("gives coverageBlocked a distinct border style and an icon", () => {
      expect(visual.strengths.coverageBlocked.borderStyle).not.toBe(
        visual.strengths.candidate.borderStyle,
      );
      expect(visual.strengths.coverageBlocked.Icon).toBeDefined();
    });
  });

  describe.each(redFamilyThemes)("red family in the %s theme", (id, theme) => {
    const visual = buildEvtxVisualTokens(theme);

    it.each(["Critical", "Error"] as const)("keeps %s red", (level) => {
      const color = resolveToken(visual.levels[level].barColor, theme);
      const { hue, saturation } = hueSaturation(color);
      expect(
        inRedBand(hue) && saturation >= 0.35,
        `${id}: ${level} ${color} hue ${hue.toFixed(0)} saturation ${saturation.toFixed(2)} outside red band [330,20] or below 0.35`,
      ).toBe(true);
    });
  });

  describe.each(redFamilyThemes)(
    "severity vividness in the %s theme",
    (id, theme) => {
      const visual = buildEvtxVisualTokens(theme);

      it.each(["Critical", "Error"] as const)(
        "keeps the %s mark vivid (Lab chroma >= 40)",
        (level) => {
          const color = resolveToken(visual.levels[level].barColor, theme);
          const [, a, b] = hexToLab(color);
          const chroma = Math.hypot(a, b);
          expect(
            chroma,
            `${id}: ${level} ${color} chroma C* = ${chroma.toFixed(1)}`,
          ).toBeGreaterThanOrEqual(40);
        },
      );
    },
  );

  describe.each(surfaceThemes)(
    "placement inventory in the %s theme",
    (id, theme) => {
      const visual = buildEvtxVisualTokens(theme);

      const surfaceFor = (key: SurfaceKey, name: string): string => {
        switch (key) {
          case "surface":
            return resolveToken(tokens.colorNeutralBackground1, theme);
          case "rail":
            return resolveToken(tokens.colorNeutralBackground2, theme);
          case "group":
            return resolveToken(tokens.colorNeutralBackground3, theme);
          case "pressed":
            return resolveToken(tokens.colorNeutralBackground1Selected, theme);
          case "selected":
            return resolveToken(visual.selection.background, theme);
          case "ownRow":
            return resolveToken(
              visual.levels[name as EvtxLevel].rowBackground,
              theme,
            );
        }
      };

      it("cites a spec section for every placement", () => {
        for (const entry of PLACEMENT_INVENTORY) {
          for (const placement of entry.placements) {
            expect(
              placement.section,
              `${id}: ${entry.role} on ${placement.surface}`,
            ).toMatch(/^\d+(\.\d+)?[ a-z0-9,.()-]/i);
          }
        }
        for (const exemption of INVENTORY_EXEMPTIONS) {
          expect(exemption.section).toMatch(/\d/);
          expect(exemption.reason.length).toBeGreaterThan(0);
        }
      });

      it.each(PLACEMENT_INVENTORY.map((entry) => [entry.role, entry] as const))(
        "keeps every %s color readable on each placement surface",
        (role, entry) => {
          const failures: string[] = [];
          for (const [name, value] of Object.entries(entry.colors(visual))) {
            const color = resolveToken(value, theme);
            for (const placement of entry.placements) {
              if (placement.exempt?.names.includes(name)) continue;
              const surface = surfaceFor(placement.surface, name);
              const floor =
                role === "channel" && id === "high-contrast"
                  ? 4.5
                  : entry.minimum;
              const ratio = contrastRatio(color, surface);
              if (ratio < floor) {
                failures.push(
                  `${id}: ${role} ${name} ${color} on ${SURFACE_TOKEN_LABEL[placement.surface]} ${surface} (${placement.section}) = ${ratio.toFixed(2)} (< ${floor})`,
                );
              }
            }
          }
          expect(failures, failures.join("; ")).toEqual([]);
        },
      );

      it("gives every mark context an outline at 3:1 on its background", () => {
        const failures: string[] = [];
        const contexts: [
          EvtxLevel | "selected" | "pressed",
          SurfaceKey,
          string,
        ][] = [
          ...LEVELS.map(
            (l) =>
              [l, "ownRow" as SurfaceKey, "8.7 row tint"] as [
                EvtxLevel,
                SurfaceKey,
                string,
              ],
          ),
          ["selected", "selected", "8.6, 8.7, 8.11, 8.13 selected rows"],
          ["pressed", "pressed", "8.3 and 6.2 pressed level toggles"],
        ];
        for (const [context, key, section] of contexts) {
          const outline = resolveToken(visual.markOutline(context), theme);
          const background = surfaceFor(key, context);
          const ratio = contrastRatio(outline, background);
          if (ratio < 3) {
            failures.push(
              `${id}: markOutline(${context}) ${outline} on ${SURFACE_TOKEN_LABEL[key]} ${background} (${section}) = ${ratio.toFixed(2)}`,
            );
          }
        }
        expect(failures, failures.join("; ")).toEqual([]);
      });

      it("keeps channels apart from the single-series color and all selection colors", () => {
        const single = resolveToken(visual.singleSeries, theme);
        const selection = [
          ["selection background", visual.selection.background],
          ["selection border", visual.selection.border],
          ["selection foreground", visual.selection.foreground],
        ] as const;
        const failures: string[] = [];
        for (let i = 0; i < 6; i++) {
          const color = resolveToken(visual.channelColor(i), theme);
          const others: [string, string][] = [
            ["single series", single],
            ...selection.map(
              ([name, value]) =>
                [name, resolveToken(value, theme)] as [string, string],
            ),
          ];
          for (const [name, other] of others) {
            const d = deltaE00(color, other);
            if (d < 15) {
              failures.push(
                `${id}: channel ${i} ${color} vs ${name} ${other} dE00 = ${d.toFixed(1)}`,
              );
            }
          }
        }
        expect(failures, failures.join("; ")).toEqual([]);
      });

      it("keeps every channel at Lab chroma >= 25 in the cool band [175, 290]", () => {
        const failures: string[] = [];
        for (let i = 0; i < 6; i++) {
          const color = resolveToken(visual.channelColor(i), theme);
          const [, a, b] = hexToLab(color);
          const chroma = Math.hypot(a, b);
          const { hue } = hueSaturation(color);
          if (chroma < 25 || hue < 175 || hue > 290) {
            failures.push(
              `${id}: channel ${i} ${color} hue ${hue.toFixed(0)} chroma ${chroma.toFixed(1)}`,
            );
          }
        }
        expect(failures, failures.join("; ")).toEqual([]);
      });

      it("keeps every badge border at 3:1 and label at 4.5:1 wherever badges sit", () => {
        const failures: string[] = [];
        for (const strength of STRENGTHS) {
          const badge = visual.strengths[strength];
          const border = resolveToken(badge.border, theme);
          for (const placement of BADGE_PLACEMENTS) {
            if (placement.exempt?.names.includes(strength)) continue;
            const surface = surfaceFor(placement.surface, strength);
            const ratio = contrastRatio(border, surface);
            if (ratio < 3) {
              failures.push(
                `${id}: ${strength} border ${border} on ${SURFACE_TOKEN_LABEL[placement.surface]} ${surface} (${placement.section}) = ${ratio.toFixed(2)}`,
              );
            }
          }
          const label = resolveToken(badge.foreground, theme);
          const background = resolveToken(badge.background, theme);
          const labelRatio = contrastRatio(label, background);
          if (labelRatio < 4.5) {
            failures.push(
              `${id}: ${strength} label ${label} on badge ${background} = ${labelRatio.toFixed(2)}`,
            );
          }
        }
        expect(failures, failures.join("; ")).toEqual([]);
      });

      it("keeps scenario colors at dE00 >= 20 from every level mark", () => {
        const failures: string[] = [];
        const scenario = {
          succeededBar: visual.scenario.succeeded.bar,
          running: visual.scenario.running,
          retrying: visual.scenario.retrying,
          sleep: visual.scenario.sleep,
        };
        for (const [name, value] of Object.entries(scenario)) {
          const color = resolveToken(value, theme);
          for (const level of LEVELS) {
            const mark = resolveToken(visual.levels[level].barColor, theme);
            const d = deltaE00(color, mark);
            if (d < 20) {
              failures.push(
                `${id}: scenario ${name} ${color} vs ${level} ${mark} dE00 = ${d.toFixed(1)}`,
              );
            }
          }
        }
        expect(failures, failures.join("; ")).toEqual([]);
      });

      it("keeps scenario states and the selection border apart (dE00 >= 20)", () => {
        const failures: string[] = [];
        // running and retrying share one token by spec design (6.3).
        const states: [string, string][] = [
          ["running", visual.scenario.running],
          ["sleep", visual.scenario.sleep],
          ["succeeded bar", visual.scenario.succeeded.bar],
          ["not started stroke", visual.scenario.notStarted.stroke],
        ].map(([n, v]) => [n, resolveToken(v, theme)] as [string, string]);
        const selectionBorder = resolveToken(visual.selection.border, theme);
        for (let i = 0; i < states.length; i++) {
          const d = deltaE00(states[i][1], selectionBorder);
          if (d < 20) {
            failures.push(
              `${id}: ${states[i][0]} ${states[i][1]} vs selection border ${selectionBorder} dE00 = ${d.toFixed(1)}`,
            );
          }
          for (let j = i + 1; j < states.length; j++) {
            const e = deltaE00(states[i][1], states[j][1]);
            if (e < 20) {
              failures.push(
                `${id}: ${states[i][0]} ${states[i][1]} vs ${states[j][0]} ${states[j][1]} dE00 = ${e.toFixed(1)}`,
              );
            }
          }
        }
        expect(failures, failures.join("; ")).toEqual([]);
      });

      it("keeps the not-started stroke at 3:1 on its background", () => {
        const stroke = resolveToken(visual.scenario.notStarted.stroke, theme);
        const background = resolveToken(
          visual.scenario.notStarted.background,
          theme,
        );
        const ratio = contrastRatio(stroke, background);
        expect(
          ratio,
          `${id}: not-started stroke ${stroke} on ${background} (15.1 hatch) = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(3);
      });

      it("keeps the succeeded label at 4.5:1 on its background", () => {
        const fg = resolveToken(visual.scenario.succeeded.foreground, theme);
        const bg = resolveToken(visual.scenario.succeeded.background, theme);
        const ratio = contrastRatio(fg, bg);
        expect(
          ratio,
          `${id}: succeeded foreground ${fg} on ${bg} (8.1 live pill, 15.1 end-state) = ${ratio.toFixed(2)}`,
        ).toBeGreaterThanOrEqual(4.5);
      });
    },
  );

  describe.each(classicTheme)("%s error bar", (id, theme) => {
    it("is a visible red, not near-black", () => {
      const visual = buildEvtxVisualTokens(theme);
      const color = resolveToken(visual.levels.Error.barColor, theme);
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
      const visual = buildEvtxVisualTokens(theme);
      const palette = theme.severityPalette;
      const surface = resolveToken(tokens.colorNeutralBackground1, theme);

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
        ].map((value) => resolveToken(value, theme));
        // A background may equal the surface but not an outcome tint that
        // differs from it by dE00 >= 10 (error, success and warning backgrounds);
        // a tint closer to the surface than that is not a distinct tint.
        const tints = [
          palette.error.background,
          palette.success.background,
          palette.warning.background,
        ]
          .map((value) => resolveToken(value, theme))
          .filter((tint) => deltaE00(tint, surface) >= 10);

        const problems: string[] = [];
        for (const strength of ["coverageBlocked", "notCausal"] as const) {
          const badge = visual.strengths[strength];
          for (const [part, value] of [
            ["foreground", badge.foreground],
            ["border", badge.border],
          ] as const) {
            const color = resolveToken(value, theme);
            for (const outcome of outcomes) {
              const d = deltaE00(color, outcome);
              if (d < 10) {
                problems.push(
                  `${strength} ${part} ${color} vs ${outcome} dE00 ${d.toFixed(1)}`,
                );
              }
            }
          }
          const background = resolveToken(badge.background, theme);
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
    const { strengths } = buildEvtxVisualTokens(theme);

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
      const theme = getAllThemes().find((t) => t.id === id)!;
      const palette = theme.severityPalette;
      const { strengths } = buildEvtxVisualTokens(theme);

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
        border: palette.warning.text,
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
        border: tokens.colorNeutralStrokeAccessible,
        borderStyle: "dotted",
      });
    },
  );

  it("uses the blue palette triplet for selection and the Exact badge (Q-1)", () => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0]);

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
    const { heatSteps } = buildEvtxVisualTokens(getAllThemes()[0]);

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

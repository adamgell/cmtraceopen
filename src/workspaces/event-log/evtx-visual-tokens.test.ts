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

/**
 * Critical and Error share the red family: every cross pair between them
 * (mark or text) uses this one floor. "Critical stays red-family",
 * 2026-10-08; red-pair floor, 2026-10-09 (owner decisions).
 */
const RED_FAMILY_PAIR_DE00 = 15;
const RED_FAMILY_LEVELS: readonly EvtxLevel[] = ["Critical", "Error"];
const isRedFamilyPair = (a?: EvtxLevel, b?: EvtxLevel) =>
  a !== undefined &&
  b !== undefined &&
  a !== b &&
  RED_FAMILY_LEVELS.includes(a) &&
  RED_FAMILY_LEVELS.includes(b);

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

/** CIELAB hue angle (h_ab, degrees 0 to 360) and chroma C* of a color. */
function labHueChroma(color: string): { hue: number; chroma: number } {
  const [, a, b] = hexToLab(color);
  return {
    hue: ((Math.atan2(b, a) * 180) / Math.PI + 360) % 360,
    chroma: Math.hypot(a, b),
  };
}

/** Inclusive [from, to] ranges of Lab hue; a band may not wrap past 360. */
type HueBands = readonly (readonly [number, number])[];
const inHueBands = (hue: number, bands: HueBands) =>
  bands.some(([from, to]) => hue >= from && hue <= to);

/**
 * Crimson to red. The red anchor #dc2626 measures h 35.03, so the upper edge
 * is 37; the accepted orange-red #ff6640 (h 41.9), orange (h 52) and amber
 * (h 73) are out.
 */
const CRITICAL_HUE_BANDS: HueBands = [
  [335, 360],
  [0, 37],
];
/** Red to red-orange; pure red is h 40 and the accepted dark red-orange h 46. */
const ERROR_HUE_BANDS: HueBands = [
  [345, 360],
  [0, 50],
];
/** Amber (h 70 to 73) to pure yellow (h 103). */
const WARNING_HUE_BANDS: HueBands = [[55, 105]];
/**
 * True red for Error text on a light surface: pure red is h 40, so the upper
 * edge is 40. The red-orange accepted for dark themes (h 46) and the brown
 * #8c2800 are out; they read as orange or brown on white.
 */
const LIGHT_ERROR_TEXT_HUE_BANDS: HueBands = [
  [345, 360],
  [0, 40],
];
const LIGHT_FAMILY_THEME_IDS: readonly string[] = ["light", "classic-cmtrace"];

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
 * states) and 8.1 to 8.19. The v2 scenario states are deferred to the v2
 * phases. Every place a color from this module is drawn is listed with its
 * surface and section.
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
    // 8.3 grammar error uses levels.Warning.textColor.
    role: "severity level text",
    minimum: 4.5,
    colors: (v) =>
      Object.fromEntries(
        (["Critical", "Error", "Warning"] as const).map((l) => [
          l,
          v.levels[l].textColor,
        ]),
      ),
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
    role: "neutral level text",
    minimum: 4.5,
    colors: (v) =>
      Object.fromEntries(
        (["Information", "Verbose"] as const).map((l) => [
          l,
          v.levels[l].textColor,
        ]),
      ),
    placements: [
      { surface: "surface", section: "8.13 finding card eyebrow" },
      { surface: "rail", section: "8.13 Details level word" },
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

type Family =
  | "level mark"
  | "level text"
  | "channel"
  | "single series"
  | "selection"
  | "brand";
const FAMILIES: readonly Family[] = [
  "level mark",
  "level text",
  "channel",
  "single series",
  "selection",
  "brand",
];

interface FamilyColor {
  family: Family;
  name: string;
  level?: EvtxLevel;
  color: string;
}

/** Every color family the module exposes, resolved for one theme. */
function familyColors(
  visual: ReturnType<typeof buildEvtxVisualTokens>,
  theme: ReturnType<typeof getAllThemes>[number],
): FamilyColor[] {
  const r = (value: string) => resolveToken(value, theme);
  return [
    ...LEVELS.map((level) => ({
      family: "level mark" as const,
      name: `${level} mark`,
      level,
      color: r(visual.levels[level].barColor),
    })),
    ...LEVELS.map((level) => ({
      family: "level text" as const,
      name: `${level} text`,
      level,
      color: r(visual.levels[level].textColor),
    })),
    ...[0, 1, 2, 3, 4, 5].map((i) => ({
      family: "channel" as const,
      name: `channel ${i}`,
      color: r(visual.channelColor(i)),
    })),
    {
      family: "single series",
      name: "single series",
      color: r(visual.singleSeries),
    },
    {
      family: "selection",
      name: "selection background",
      color: r(visual.selection.background),
    },
    {
      family: "selection",
      name: "selection border",
      color: r(visual.selection.border),
    },
    {
      family: "selection",
      name: "selection foreground",
      color: r(visual.selection.foreground),
    },
    {
      family: "brand",
      name: "brand background",
      color: r(tokens.colorBrandBackground),
    },
    {
      family: "brand",
      name: "brand link",
      color: r(tokens.colorBrandForegroundLink),
    },
  ];
}

/**
 * Per-family-pair floors: 20 where either family is a level mark, 15 otherwise. Same-family pairs have their own tests.
 */
const FAMILY_PAIR_FLOORS: Record<string, number> = {};
for (const a of FAMILIES) {
  for (const b of FAMILIES) {
    if (a >= b) continue;
    const strict = [a, b].some((f) => f === "level mark");
    FAMILY_PAIR_FLOORS[`${a}|${b}`] = strict ? 20 : 15;
  }
}
const familyFloor = (a: Family, b: Family) =>
  FAMILY_PAIR_FLOORS[a < b ? `${a}|${b}` : `${b}|${a}`];

const THEME_OWNED_FAMILIES: readonly Family[] = [
  "selection",
  "brand",
  "single series",
];
const NEUTRAL_LEVELS: readonly EvtxLevel[] = ["Information", "Verbose"];
/** Intended overlaps between different families, each with its reason. */
const FAMILY_EXCEPTIONS: readonly {
  reason: string;
  applies: (a: FamilyColor, b: FamilyColor) => boolean;
}[] = [
  {
    reason: "a level's text color is a legible version of its own mark",
    applies: (a, b) =>
      a.level !== undefined && a.level === b.level && a.family !== b.family,
  },
  {
    reason:
      "Information and Verbose are neutrals and may look alike (marks and texts)",
    applies: (a, b) =>
      a.level !== undefined &&
      b.level !== undefined &&
      NEUTRAL_LEVELS.includes(a.level) &&
      NEUTRAL_LEVELS.includes(b.level),
  },
  {
    reason:
      "selection, brand and single-series colors are theme tokens and mergeColors[0]; this module cannot retune them",
    applies: (a, b) =>
      THEME_OWNED_FAMILIES.includes(a.family) &&
      THEME_OWNED_FAMILIES.includes(b.family),
  },
];

describe("evtx visual tokens", () => {
  it("cites a spec section for every placement and exemption", () => {
    for (const entry of [...PLACEMENT_INVENTORY]) {
      for (const placement of entry.placements) {
        expect(
          placement.section,
          `${entry.role} on ${placement.surface}`,
        ).toMatch(/^\d+(\.\d+)?[ a-z0-9,.()-]/i);
      }
    }
    for (const placement of BADGE_PLACEMENTS) {
      expect(placement.section).toMatch(/^\d+(\.\d+)?/);
    }
    for (const exemption of INVENTORY_EXEMPTIONS) {
      expect(exemption.section).toMatch(/\d/);
      expect(exemption.reason.length).toBeGreaterThan(0);
    }
  });

  it("cycles channel colors every six channels", () => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0]);

    expect(visual.channelColor(6)).toBe(visual.channelColor(0));
    expect(visual.channelColor(13)).toBe(visual.channelColor(1));
  });

  describe.each(surfaceThemes)(
    "FAMILY_SEPARATION in the %s theme",
    (id, theme) => {
      it("keeps every pair of colors from different families apart", () => {
        const visual = buildEvtxVisualTokens(theme);
        const colors = familyColors(visual, theme);
        const failures: string[] = [];
        for (let i = 0; i < colors.length; i++) {
          for (let j = i + 1; j < colors.length; j++) {
            const a = colors[i];
            const b = colors[j];
            if (a.family === b.family) continue;
            if (FAMILY_EXCEPTIONS.some((e) => e.applies(a, b))) continue;
            const floor = isRedFamilyPair(a.level, b.level)
              ? RED_FAMILY_PAIR_DE00
              : familyFloor(a.family, b.family);
            const d = deltaE00(a.color, b.color);
            if (d < floor) {
              failures.push(
                `${id}: ${a.name} ${a.color} vs ${b.name} ${b.color} dE00 = ${d.toFixed(1)} (< ${floor})`,
              );
            }
          }
        }
        expect(failures, failures.join("; ")).toEqual([]);
      });

      it("keeps Critical text and Error text at least the red-family floor apart", () => {
        const visual = buildEvtxVisualTokens(theme);
        const a = resolveToken(visual.levels.Critical.textColor, theme);
        const b = resolveToken(visual.levels.Error.textColor, theme);
        const d = deltaE00(a, b);
        expect(
          d,
          `${id}: Critical text ${a} vs Error text ${b} dE00 = ${d.toFixed(1)}`,
        ).toBeGreaterThanOrEqual(RED_FAMILY_PAIR_DE00);
      });
    },
  );

  it.each([
    ["info", "Information"],
    ["warning", "Warning"],
    ["error", "Error"],
    ["critical", "Critical"],
  ] as const)("maps finding severity %s to the %s level", (severity, level) => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0]);
    expect(visual.findingSeverityVisual(severity)).toBe(visual.levels[level]);
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
          ).toBeGreaterThanOrEqual(
            isRedFamilyPair(a, b) ? RED_FAMILY_PAIR_DE00 : 20,
          );
        }
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

  describe("semantic hue anchors", () => {
    // Measured CIELAB hue (h_ab, degrees) and chroma C* of the reference
    // colors the bands below are built around (D65, same conversion as the
    // tests): red #dc2626 h 35.0 C 81.7; pure red #FF0000 h 40.0 C 104.6;
    // crimson #881337 h 12.4 C 49.9; rose #ff4d80 h 9.2 C 70.9;
    // red-orange #ff5a1f h 46.2 C 87.3; orange #ff9966 h 51.9 C 54.4;
    // amber #f59e0b h 72.7 C 78.8; dark amber #a16207 h 69.9 C 57.1;
    // yellow #FFFF00 h 102.9 C 96.9; green #16a34a h 146.4 C 65.4.
    // Orange (h 52) is outside the Critical band on purpose; amber at h 73 is
    // the nearest Warning anchor.
    const anchor = (color: string) => labHueChroma(color);

    it.each([
      ["red #dc2626", "#dc2626", CRITICAL_HUE_BANDS],
      ["crimson #881337", "#881337", CRITICAL_HUE_BANDS],
      ["rose #ff4d80", "#ff4d80", CRITICAL_HUE_BANDS],
      ["red #dc2626", "#dc2626", ERROR_HUE_BANDS],
      ["pure red #FF0000", "#FF0000", ERROR_HUE_BANDS],
      ["red-orange #ff5a1f", "#ff5a1f", ERROR_HUE_BANDS],
      ["amber #f59e0b", "#f59e0b", WARNING_HUE_BANDS],
      ["yellow #FFFF00", "#FFFF00", WARNING_HUE_BANDS],
    ])("puts the %s anchor inside its band", (name, color, bands) => {
      const { hue } = anchor(color);
      expect(inHueBands(hue, bands), `${name} hue ${hue.toFixed(1)}`).toBe(
        true,
      );
    });

    it.each([
      ["orange #ff9966", "#ff9966", CRITICAL_HUE_BANDS],
      ["amber #f59e0b", "#f59e0b", CRITICAL_HUE_BANDS],
      ["green #16a34a", "#16a34a", WARNING_HUE_BANDS],
    ])("keeps the %s anchor outside a band it does not belong to", (name, color, bands) => {
      const { hue } = anchor(color);
      expect(inHueBands(hue, bands), `${name} hue ${hue.toFixed(1)}`).toBe(
        false,
      );
    });
  });

  describe.each(surfaceThemes)(
    "semantic hue and chroma in the %s theme",
    (id, theme) => {
      const visual = buildEvtxVisualTokens(theme);
      const resolved = (value: string) => resolveToken(value, theme);
      const describeColor = (role: string, color: string) => {
        const { hue, chroma } = labHueChroma(color);
        return `${id}: ${role} ${color} Lab hue ${hue.toFixed(1)} C* ${chroma.toFixed(1)}`;
      };

      const levelColors = (level: EvtxLevel) =>
        [
          [`${level} mark`, resolved(visual.levels[level].barColor)],
          [`${level} text`, resolved(visual.levels[level].textColor)],
        ] as const;

      it.each([
        ["Critical", CRITICAL_HUE_BANDS, "[335, 360) or [0, 37]", 45],
        ["Error", ERROR_HUE_BANDS, "[345, 360) or [0, 50]", 45],
        ["Warning", WARNING_HUE_BANDS, "[55, 105]", 45],
      ] as const)(
        "keeps %s mark and text in its hue band and vivid",
        (level, bands, bandLabel, minChroma) => {
          const failures: string[] = [];
          for (const [role, color] of levelColors(level)) {
            const { hue, chroma } = labHueChroma(color);
            if (!inHueBands(hue, bands) || chroma < minChroma) {
              failures.push(
                `${describeColor(role, color)} (need hue ${bandLabel} and C* >= ${minChroma})`,
              );
            }
          }
          expect(failures, failures.join("; ")).toEqual([]);
        },
      );

      if (LIGHT_FAMILY_THEME_IDS.includes(id)) {
        it("keeps Error text true red, not orange or brown (h <= 40)", () => {
          const color = resolved(visual.levels.Error.textColor);
          const { hue } = labHueChroma(color);
          expect(
            inHueBands(hue, LIGHT_ERROR_TEXT_HUE_BANDS),
            `${describeColor("Error text", color)} (need hue [345, 360) or [0, 40])`,
          ).toBe(true);
        });
      }

      it.each(["Critical", "Error"] as const)(
        "keeps the %s mark from going pastel",
        (level) => {
          // A light mark needs real chroma to read as red: the pale rose
          // #ff8c9f (L* 71.2, C* 46.4) clears C* >= 45 yet reads as pink.
          // Text is exempt: 4.5:1 on the selection background forces text to
          // L* >= 70, where a red-pink tops out near C* 48, so text answers
          // to the C* >= 45 floor above.
          const color = resolved(visual.levels[level].barColor);
          const [lightness] = hexToLab(color);
          const { chroma } = labHueChroma(color);
          expect(
            lightness < 65 || chroma >= 60,
            `${describeColor(`${level} mark`, color)} L* ${lightness.toFixed(1)} (pastel: L* >= 65 needs C* >= 60)`,
          ).toBe(true);
        },
      );

      it.each(["Information", "Verbose"] as const)(
        "keeps %s mark and text neutral gray (C* <= 12)",
        (level) => {
          const failures: string[] = [];
          for (const [role, color] of levelColors(level)) {
            const { chroma } = labHueChroma(color);
            if (chroma > 12) {
              failures.push(`${describeColor(role, color)} (need C* <= 12)`);
            }
          }
          expect(failures, failures.join("; ")).toEqual([]);
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

  it("uses the blue palette triplet for selection (Q-1)", () => {
    const visual = buildEvtxVisualTokens(getAllThemes()[0]);

    expect(visual.selection).toEqual({
      background: tokens.colorPaletteBlueBackground2,
      border: tokens.colorPaletteBlueBorderActive,
      foreground: tokens.colorPaletteBlueForeground2,
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

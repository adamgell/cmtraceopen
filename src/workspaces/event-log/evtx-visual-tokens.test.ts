import { tokens } from "@fluentui/react-components";
import { describe, expect, it } from "vitest";
import { getAllThemes } from "../../lib/themes";
import type { DiagnosisCorrelationStatus, EvtxLevel } from "./types";
import {
  CHANNEL_MERGE_COLOR_INDICES,
  buildEvtxVisualTokens,
} from "./evtx-visual-tokens";
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

describe("evtx visual tokens", () => {
  it("assigns channel colors from merge indices 0, 4, 5, 3, 6, 7 and cycles", () => {
    const palette = getAllThemes()[0].severityPalette;
    const visual = buildEvtxVisualTokens(palette);
    const expected = [0, 4, 5, 3, 6, 7].map((i) => palette.mergeColors[i]);

    expect(Array.from({ length: 6 }, (_, i) => visual.channelColor(i))).toEqual(
      expected,
    );
    expect(visual.channelColor(6)).toBe(expected[0]);
    expect(visual.channelColor(13)).toBe(expected[1]);
  });

  it("never gives a channel the red (1) or green (2) merge color", () => {
    expect(CHANNEL_MERGE_COLOR_INDICES).not.toContain(1);
    expect(CHANNEL_MERGE_COLOR_INDICES).not.toContain(2);
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

  it("gives every level a distinct icon so severity is not color alone", () => {
    const { levels } = buildEvtxVisualTokens(getAllThemes()[0].severityPalette);
    const gridIcons = new Set(LEVELS.map((level) => levels[level].GridIcon));
    expect(gridIcons.size).toBe(LEVELS.length);
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

  it("keeps coverage states visually apart from success and failure", () => {
    const palette = getAllThemes()[0].severityPalette;
    const { strengths } = buildEvtxVisualTokens(palette);
    const outcomeColors = [
      palette.error.background,
      palette.error.text,
      palette.success.background,
      palette.success.text,
      palette.status.error.foreground,
      palette.status.success.foreground,
      tokens.colorPaletteRedBackground3,
      tokens.colorPaletteGreenBackground3,
    ];

    for (const strength of ["coverageBlocked", "notCausal"] as const) {
      const badge = strengths[strength];
      expect(outcomeColors).not.toContain(badge.background);
      expect(outcomeColors).not.toContain(badge.foreground);
      expect(outcomeColors).not.toContain(badge.border);
      expect(badge.borderStyle).not.toBe("solid");
    }
    expect(strengths.coverageBlocked.Icon).toBeDefined();
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

  it("contains no hex color literals", () => {
    expect(moduleSource).not.toMatch(/#[0-9a-f]{3,8}\b/i);
  });
});

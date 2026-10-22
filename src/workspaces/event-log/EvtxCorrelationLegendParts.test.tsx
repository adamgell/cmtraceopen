/**
 * The parts of a legend that the lane plot's key and the rail's Chains tab draw alike (#841): the
 * connector styles, the swatch of an exact or candidate line, the marker swatch, and the entry that
 * holds a swatch and a word. One definition, so a line weight or a dash cannot differ between the two.
 */
import { tokens } from "@fluentui/react-components";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { getAllThemes } from "../../lib/themes";
import { useUiStore } from "../../stores/ui-store";
import {
  CONNECTOR_STYLES,
  ConnectorSwatch,
  LegendItem,
  MarkerSwatch,
} from "./EvtxCorrelationLegendParts";
import lanesSource from "./EvtxCorrelationLanes.tsx?raw";
import partsSource from "./EvtxCorrelationLegendParts.tsx?raw";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";

const { themeId: INITIAL_THEME } = useUiStore.getState();
beforeEach(() => useUiStore.setState({ themeId: "light" }));
afterEach(() => {
  cleanup();
  useUiStore.setState({ themeId: INITIAL_THEME });
});

describe("CONNECTOR_STYLES (spec 8.11)", () => {
  it("is 2.5 px solid for exact and 1.5 px dashed 5 4 for candidate", () => {
    expect(CONNECTOR_STYLES.exact).toEqual({ width: 2.5, dash: undefined });
    expect(CONNECTOR_STYLES.candidate).toEqual({ width: 1.5, dash: "5 4" });
  });
});

describe("ConnectorSwatch", () => {
  it("draws the strength's own weight and dash, in a line that does not scale", () => {
    render(
      <>
        <ConnectorSwatch strength="exact" />
        <ConnectorSwatch strength="candidate" />
      </>,
    );
    const [exact, candidate] = Array.from(document.querySelectorAll("line"));
    expect(exact!.getAttribute("stroke-width")).toBe("2.5");
    expect(exact!.getAttribute("stroke-dasharray")).toBeNull();
    expect(candidate!.getAttribute("stroke-width")).toBe("1.5");
    expect(candidate!.getAttribute("stroke-dasharray")).toBe("5 4");
    expect(exact!.style.vectorEffect).toBe("non-scaling-stroke");
  });

  it("is hidden from assistive technology: the word beside it names the strength", () => {
    render(<ConnectorSwatch strength="exact" />);
    expect(document.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it.each(getAllThemes().map((theme) => [theme.id] as const))("is drawn in the strength's border color in %s", (themeId) => {
    useUiStore.setState({ themeId });
    const theme = getAllThemes().find((candidate) => candidate.id === themeId)!;
    const visuals = buildEvtxVisualTokens(theme);
    render(
      <>
        <ConnectorSwatch strength="exact" />
        <ConnectorSwatch strength="candidate" />
      </>,
    );
    const [exact, candidate] = Array.from(document.querySelectorAll("line"));
    expect(resolveToken(exact!.style.stroke, theme)).toBe(resolveToken(visuals.strengths.exact.border, theme));
    expect(resolveToken(candidate!.style.stroke, theme)).toBe(resolveToken(visuals.strengths.candidate.border, theme));
  });
});

describe("MarkerSwatch", () => {
  it("draws a filled shape in the foreground color, for an entry that is drawn", () => {
    render(<MarkerSwatch radius="3px" outlined={false} />);
    const swatch = document.querySelector("span[aria-hidden='true']") as HTMLElement;
    expect(swatch.style.borderRadius).toBe("3px");
    expect(swatch.style.backgroundColor).toBe(tokens.colorNeutralForeground2);
    expect(swatch.style.border).toContain("solid");
  });

  it("draws the outlined one as a 1 px dotted outline in the not-causal border, with no fill (spec 6.3)", () => {
    render(<MarkerSwatch radius="50%" outlined />);
    const swatch = document.querySelector("span[aria-hidden='true']") as HTMLElement;
    const visuals = buildEvtxVisualTokens(getAllThemes().find((theme) => theme.id === "light")!);
    expect(swatch.style.border).toContain("1px dotted");
    expect(swatch.style.border).toContain(visuals.strengths.notCausal.border);
    expect(swatch.style.backgroundColor).toBe("transparent");
  });
});

describe("LegendItem", () => {
  it("puts the swatch and the word side by side, at the size and color it is given", () => {
    render(
      <LegendItem label="Exact match" color={tokens.colorNeutralForeground2} size={11}>
        <MarkerSwatch radius="50%" outlined={false} />
      </LegendItem>,
    );
    const word = screen.getByText("Exact match");
    expect(word.style.fontSize).toBe("11px");
    expect(word.style.color).toBe(tokens.colorNeutralForeground2);
    expect(word.querySelector("span[aria-hidden='true']")).not.toBeNull();
  });
});

describe("one definition", () => {
  it("is imported by the lane plot, which no longer defines the styles or the swatches itself", () => {
    expect(lanesSource).toMatch(/from "\.\/EvtxCorrelationLegendParts"/);
    expect(lanesSource).not.toMatch(/const CONNECTOR_STYLES\b/);
    expect(lanesSource).not.toMatch(/function LegendItem\b/);
    expect(lanesSource).not.toMatch(/<svg aria-hidden="true" width="28"/);
  });

  it("has no color literal", () => {
    expect(partsSource).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(partsSource).not.toMatch(/\brgba?\(/);
    expect(partsSource).not.toMatch(/\bhsla?\(/);
  });
});

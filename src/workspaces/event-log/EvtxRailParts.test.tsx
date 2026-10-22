/**
 * The card, the disclosure and the text sizes of the Insights rail (spec 8.13), shared by the
 * Insights tab and the Chains tab (#841): one card style, one disclosure, one set of sizes. The
 * Insights tab's own tests (EventDiagnosisPanel.test.tsx) keep driving them through the panel.
 */
import { cleanup, fireEvent, render, renderHook, screen } from "@testing-library/react";
import { useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { tokens } from "@fluentui/react-components";
import { MAX_LOG_LIST_FONT_SIZE, MIN_LOG_LIST_FONT_SIZE } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import panelSource from "./EventDiagnosisPanel.tsx?raw";
import { Disclosure, RailCard, useRailSizes } from "./EvtxRailParts";
import partsSource from "./EvtxRailParts.tsx?raw";

const { logListFontSize: INITIAL_FONT_SIZE } = useUiStore.getState();
afterEach(() => {
  cleanup();
  useUiStore.setState({ logListFontSize: INITIAL_FONT_SIZE });
});

const SIZES = { f: 13, small: 11, caption: 10 };

describe("useRailSizes", () => {
  it.each([
    [MIN_LOG_LIST_FONT_SIZE, { f: 11, small: 10, caption: 10 }],
    [13, { f: 13, small: 11, caption: 10 }],
    [14, { f: 14, small: 12, caption: 11 }],
    [MAX_LOG_LIST_FONT_SIZE, { f: 20, small: 18, caption: 17 }],
  ])("is f, f - 2 and f - 3 with a floor of 10, at a log list font of %s", (fontSize, expected) => {
    useUiStore.setState({ logListFontSize: fontSize });
    expect(renderHook(() => useRailSizes()).result.current).toEqual(expected);
  });
});

describe("RailCard", () => {
  it("is a labelled section on the card surface, with the title as an uppercase eyebrow", () => {
    render(
      <RailCard title="Level mix" sizes={SIZES}>
        <span>body</span>
      </RailCard>,
    );
    const card = screen.getByRole("region", { name: "Level mix" });
    expect(card.style.backgroundColor).toBe(tokens.colorNeutralBackground1);
    expect(card.style.padding).toBe("10px 12px");
    expect(card.style.borderRadius).toBe("6px");
    expect(card).toHaveTextContent("body");
    const eyebrow = screen.getByText("Level mix");
    expect(eyebrow.style.textTransform).toBe("uppercase");
    expect(eyebrow.style.fontSize).toBe("10px");
    expect(card).not.toHaveAttribute("aria-busy");
    expect(card.style.opacity).toBe("1");
  });

  it("dims a card whose numbers are from the previous build and marks it busy", () => {
    render(
      <RailCard title="Correlations" sizes={SIZES} stale>
        <span>body</span>
      </RailCard>,
    );
    const card = screen.getByRole("region", { name: "Correlations" });
    expect(card).toHaveAttribute("aria-busy", "true");
    expect(card.style.opacity).toBe("0.6");
  });

  it("says its caption at the right of the title, when it has one", () => {
    render(
      <RailCard title="Top event IDs" sizes={SIZES} caption="click to filter">
        <span>body</span>
      </RailCard>,
    );
    expect(screen.getByText("click to filter")).toBeInTheDocument();
  });
});

describe("Disclosure", () => {
  function Host({ stale = false }: { stale?: boolean }) {
    const [open, setOpen] = useState(false);
    return (
      <Disclosure label="Coverage gaps (3)" open={open} onOpenChange={setOpen} sizes={SIZES} stale={stale}>
        <span>the rows</span>
      </Disclosure>
    );
  }

  it("is closed until its summary is activated, then open, and the caller owns the state", () => {
    render(<Host />);
    const details = document.querySelector("details") as HTMLDetailsElement;
    expect(details.open).toBe(false);
    fireEvent.click(screen.getByText("Coverage gaps (3)"));
    expect(details.open).toBe(true);
    fireEvent.click(screen.getByText("Coverage gaps (3)"));
    expect(details.open).toBe(false);
  });

  it("holds its rows in a focusable region named by the summary, bounded in height", () => {
    render(<Host />);
    fireEvent.click(screen.getByText("Coverage gaps (3)"));
    const region = screen.getByRole("region", { name: "Coverage gaps (3)" });
    expect(region).toHaveAttribute("tabindex", "0");
    expect(region).toHaveTextContent("the rows");
    expect(region.style.maxHeight).toBe("min(420px, 50vh)");
    expect(region.style.overflowY).toBe("auto");
  });

  it("dims and marks busy a disclosure whose rows are from the previous build", () => {
    render(<Host stale />);
    const details = document.querySelector("details") as HTMLDetailsElement;
    expect(details).toHaveAttribute("aria-busy", "true");
    expect(details.style.opacity).toBe("0.6");
  });
});

describe("one definition", () => {
  it("is imported by the Insights panel, which no longer defines the card, the disclosure or the sizes", () => {
    expect(panelSource).toMatch(/from "\.\/EvtxRailParts"/);
    expect(panelSource).not.toMatch(/function RailCard\b/);
    expect(panelSource).not.toMatch(/function Disclosure\b/);
    expect(panelSource).not.toMatch(/function useRailSizes\b/);
    expect(panelSource).not.toMatch(/interface RailSizes\b/);
  });

  it("has no color literal", () => {
    expect(partsSource).not.toMatch(/#[0-9a-fA-F]{3,8}\b/);
    expect(partsSource).not.toMatch(/\brgba?\(/);
  });
});

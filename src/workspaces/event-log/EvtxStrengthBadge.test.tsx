/**
 * The strength badge is one component for the Correlation view and the dock: its word, its icon and
 * its tokens, per strength and per theme. The contrast of the tokens themselves is measured in
 * evtx-visual-tokens.test.ts; this pins that the component paints exactly them.
 */
import { cleanup, render } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { afterEach, describe, expect, it } from "vitest";
import { getAllThemes } from "../../lib/themes";
import { STRENGTH_LABELS } from "./evtx-correlation-copy";
import { STRENGTH_ORDER } from "./evtx-correlation-chains";
import { EvtxStrengthBadge } from "./EvtxStrengthBadge";
import { buildEvtxVisualTokens } from "./evtx-visual-tokens";

afterEach(cleanup);

/** A color as the DOM reads it back (jsdom turns a hex into rgb()), so the expectation and the style agree. */
function asStyled(property: "backgroundColor" | "color" | "border", value: string): string {
  const probe = document.createElement("span");
  probe.style[property] = value;
  return probe.style[property];
}

describe.each(getAllThemes().map((theme) => [theme.id, theme] as const))("the strength badge in the %s theme", (_id, theme) => {
  const visuals = buildEvtxVisualTokens(theme);

  it.each(STRENGTH_ORDER.map((strength) => [strength] as const))("paints %s with its word and its own tokens", (strength) => {
    const { container } = render(<EvtxStrengthBadge strength={strength} visuals={visuals} textSize={10} />);
    const badge = container.querySelector<HTMLElement>(`[data-strength-badge="${strength}"]`)!;
    expect(badge).toHaveTextContent(STRENGTH_LABELS[strength]);
    expect(badge.style.backgroundColor).toBe(asStyled("backgroundColor", visuals.strengths[strength].background));
    expect(badge.style.color).toBe(asStyled("color", visuals.strengths[strength].foreground));
    expect(badge.style.border).toBe(
      asStyled("border", `1px ${visuals.strengths[strength].borderStyle} ${visuals.strengths[strength].border}`),
    );
    expect(badge.style.fontSize).toBe("10px");
    expect(Boolean(badge.querySelector("svg"))).toBe(visuals.strengths[strength].Icon !== undefined);
  });

  it("draws a selected Exact badge on the surface color, and no other strength differently", () => {
    const exact = render(<EvtxStrengthBadge strength="exact" selected visuals={visuals} textSize={10} />);
    expect(exact.container.querySelector<HTMLElement>("[data-strength-badge]")!.style.backgroundColor).toBe(
      tokens.colorNeutralBackground1,
    );
    cleanup();
    const candidate = render(<EvtxStrengthBadge strength="candidate" selected visuals={visuals} textSize={10} />);
    expect(candidate.container.querySelector<HTMLElement>("[data-strength-badge]")!.style.backgroundColor).toBe(
      asStyled("backgroundColor", visuals.strengths.candidate.background),
    );
  });
});

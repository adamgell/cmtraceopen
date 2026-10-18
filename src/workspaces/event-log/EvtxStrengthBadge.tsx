/**
 * A chain row's strength badge (spec 8.11, 8.12, 8.13): its icon, its word, its fill, its border and
 * its text, all from the visual tokens. The Correlation view's list and detail header and the
 * dock's summary draw the same badge, so the strength reads the same wherever it appears.
 */
import { tokens } from "@fluentui/react-components";
import { STRENGTH_LABELS } from "./evtx-correlation-copy";
import type { CorrelationChainStrength } from "./evtx-correlation-chains";
import type { EvtxVisualTokens } from "./evtx-visual-tokens";

export function EvtxStrengthBadge({
  strength,
  selected = false,
  visuals,
  textSize,
}: {
  strength: CorrelationChainStrength;
  /** On a selected list row, where the Exact badge's own fill IS the selection fill. */
  selected?: boolean;
  visuals: EvtxVisualTokens;
  /** The badge text's size: max(10, f - 3). */
  textSize: number;
}) {
  const badge = visuals.strengths[strength];
  // On a selected row the Exact badge's own fill IS the selection fill (1.00:1), so it is drawn on
  // the surface color with its border and its text; the other badges already differ from it.
  const background = selected && strength === "exact" ? tokens.colorNeutralBackground1 : badge.background;
  const Icon = badge.Icon;
  return (
    <span
      data-strength-badge={strength}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "3px",
        padding: "1px 6px",
        borderRadius: "8px",
        fontSize: `${textSize}px`,
        fontWeight: 700,
        lineHeight: 1.3,
        backgroundColor: background,
        color: badge.foreground,
        border: `1px ${badge.borderStyle} ${badge.border}`,
        whiteSpace: "nowrap",
      }}
    >
      {Icon !== undefined && <Icon aria-hidden="true" style={{ width: "12px", height: "12px" }} />}
      {STRENGTH_LABELS[strength]}
    </span>
  );
}

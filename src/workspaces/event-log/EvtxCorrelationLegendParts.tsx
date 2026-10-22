/**
 * The parts of a legend that the lane plot's key (`CorrelationLegend`, spec 8.11) and the rail's
 * Chains tab (spec 8.13) draw alike: how a connector of each strength is styled, the swatch of that
 * line, the swatch of a marker, and the entry that holds a swatch and a word. They live apart from
 * the lane plot so a surface that only needs a legend does not pull the plot in, and so the weight
 * and dash of a line cannot differ between the two keys.
 *
 * Colors are the visual tokens' and the caller's; nothing here is a literal.
 */
import type { ReactNode } from "react";
import { tokens } from "@fluentui/react-components";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

/** Spec 8.11: an exact connector is 2.5 px solid, a candidate one 1.5 px dashed `5 4`. */
export const CONNECTOR_STYLES = {
  exact: { width: 2.5, dash: undefined },
  candidate: { width: 1.5, dash: "5 4" },
} as const;

/** A 28 px sample of the line a connector of `strength` is drawn with. */
export function ConnectorSwatch({ strength }: { strength: "exact" | "candidate" }) {
  const visuals = useEvtxVisualTokens();
  return (
    <svg aria-hidden="true" width="28" height="6" style={{ flexShrink: 0 }}>
      <line
        x1="0"
        x2="28"
        y1="3"
        y2="3"
        strokeWidth={CONNECTOR_STYLES[strength].width}
        strokeDasharray={CONNECTOR_STYLES[strength].dash}
        style={{ stroke: visuals.strengths[strength].border, vectorEffect: "non-scaling-stroke" }}
      />
    </svg>
  );
}

/**
 * A 10 px sample of a marker: a filled shape for an entry that is drawn, or the 1 px dotted outline
 * with no fill that an entry that is not linked is drawn with (spec 6.3). `radius` is the shape: 50%
 * for an event, 3px for a log line.
 */
export function MarkerSwatch({ radius, outlined }: { radius: string; outlined: boolean }) {
  const visuals = useEvtxVisualTokens();
  return (
    <span
      aria-hidden="true"
      style={{
        width: "10px",
        height: "10px",
        boxSizing: "border-box",
        borderRadius: radius,
        border: outlined
          ? `1px ${visuals.strengths.notCausal.borderStyle} ${visuals.strengths.notCausal.border}`
          : `1px solid ${tokens.colorNeutralForeground2}`,
        backgroundColor: outlined ? "transparent" : tokens.colorNeutralForeground2,
        flexShrink: 0,
      }}
    />
  );
}

/** One entry of a legend: a swatch and the word for it, in the color and size the surface chose. */
export function LegendItem({
  children,
  label,
  color,
  size,
}: {
  children: ReactNode;
  label: string;
  color: string;
  size: number;
}) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: "6px", fontSize: `${size}px`, color }}>
      {children}
      {label}
    </span>
  );
}

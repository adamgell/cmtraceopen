/**
 * The card, the disclosure and the text sizes of the Insights rail (spec 8.13). The Insights tab and
 * the Chains tab draw their cards the same way, so the card style, the disclosure that keeps its open
 * state in the caller, and the sizes (f, f - 2 and f - 3 with a floor of 10, from the log list font
 * size) are written once here and not twice.
 *
 * Colors are tokens and the rail's text colors; nothing here is a literal.
 */
import { useId, useMemo, type ReactNode } from "react";
import { tokens } from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useRailTextColors } from "./evtx-rail-text";

export interface RailSizes {
  /** Base size: the user's log list font size. */
  f: number;
  small: number;
  caption: number;
}

export function useRailSizes(): RailSizes {
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  return useMemo(() => {
    const f = getLogListMetrics(logListFontSize).fontSize;
    return { f, small: Math.max(10, f - 2), caption: Math.max(10, f - 3) };
  }, [logListFontSize]);
}

export function RailCard({
  title,
  sizes,
  stale = false,
  caption,
  children,
}: {
  title: string;
  sizes: RailSizes;
  /** Its numbers are from the previous build: dimmed and marked busy. */
  stale?: boolean;
  /** Said at the right of the title, in the muted card color (spec 8.13: "click to filter"). */
  caption?: string;
  children: ReactNode;
}) {
  const { cardSecondary } = useRailTextColors();
  return (
    <section
      aria-label={title}
      aria-busy={stale || undefined}
      style={{
        opacity: stale ? 0.6 : 1,
        display: "grid",
        gap: "8px",
        padding: "10px 12px",
        borderRadius: "6px",
        backgroundColor: tokens.colorNeutralBackground1,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: "8px" }}>
        <span
          style={{
            fontSize: `${sizes.caption}px`,
            fontWeight: 700,
            letterSpacing: "0.08em",
            textTransform: "uppercase",
            color: cardSecondary,
          }}
        >
          {title}
        </span>
        {caption !== undefined && (
          <span style={{ fontSize: `${sizes.caption}px`, fontWeight: 400, color: cardSecondary }}>
            {caption}
          </span>
        )}
      </div>
      {children}
    </section>
  );
}

/**
 * A disclosure whose open state lives in the caller, so it survives the diagnosis being rebuilt.
 * The body is a bounded, focusable scroll region.
 */
export function Disclosure({
  label,
  open,
  onOpenChange,
  sizes,
  stale = false,
  children,
}: {
  label: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  sizes: RailSizes;
  /** The label's count and the rows are from the previous build. The rows inherit the dimming. */
  stale?: boolean;
  children: ReactNode;
}) {
  const labelId = useId();
  return (
    <details
      open={open}
      aria-busy={stale || undefined}
      style={{
        opacity: stale ? 0.6 : 1,
        padding: "8px 12px",
        borderRadius: "6px",
        backgroundColor: tokens.colorNeutralBackground1,
        border: `1px solid ${tokens.colorNeutralStroke2}`,
      }}
    >
      <summary
        id={labelId}
        onClick={(event) => {
          event.preventDefault();
          onOpenChange(!open);
        }}
        // The label's own color, on the card surface the disclosure draws (Background1), where
        // Foreground1 reaches 4.5:1 in all seven themes: a text with no color of its own cannot be measured.
        style={{ cursor: "pointer", fontSize: `${sizes.small}px`, fontWeight: 600, color: tokens.colorNeutralForeground1 }}
      >
        {label}
      </summary>
      <div
        aria-labelledby={labelId}
        role="region"
        tabIndex={0}
        style={{
          display: "grid",
          gap: "8px",
          marginTop: "8px",
          maxHeight: "min(420px, 50vh)",
          overflowY: "auto",
        }}
      >
        {children}
      </div>
    </details>
  );
}

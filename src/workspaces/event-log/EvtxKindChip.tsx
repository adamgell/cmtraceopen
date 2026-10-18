/**
 * The EVT / LOG chip that says whether a timeline entry is a Windows event or a text-log line (spec
 * 8.13, the Chains tab steps and the Details context rows). One component, so there is one pair of
 * colors to measure.
 *
 * EVT is the selection triplet's fill with its text (colorPaletteBlue Background2 / Foreground2).
 * LOG is colorNeutralBackground3 with Foreground2: the spec names bg4, but Foreground2 on bg4 is
 * 4.36:1 in solarized-dark, under the 4.5:1 text floor, and on bg3 it is at least 4.86:1 in every
 * theme. The kind is also said in words (`role="img"` with a name and a tooltip), since the three
 * letters are not a word.
 */
import { tokens } from "@fluentui/react-components";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { correlationSizes } from "./evtx-correlation-sizes";
import { useEvtxVisualTokens } from "./evtx-visual-tokens";

interface EvtxKindChipProps {
  chip: "EVT" | "LOG";
}

const NAMES = { EVT: "Windows event", LOG: "Text log line" } as const;

/**
 * The chip owns its size: the spec's mono f - 4, with the 10 px floor it puts on text. A caller
 * cannot pass one, so no surface can draw the chip a different size from the others.
 */
export function EvtxKindChip({ chip }: EvtxKindChipProps) {
  const visuals = useEvtxVisualTokens();
  const fontSize = Math.max(10, correlationSizes(useUiStore((s) => s.logListFontSize)).tick);
  const colors =
    chip === "EVT"
      ? { backgroundColor: visuals.selection.background, color: visuals.selection.foreground }
      : { backgroundColor: tokens.colorNeutralBackground3, color: tokens.colorNeutralForeground2 };
  return (
    <span
      role="img"
      aria-label={NAMES[chip]}
      title={NAMES[chip]}
      data-chip={chip}
      style={{
        ...colors,
        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
        fontSize: `${fontSize}px`,
        fontWeight: 700,
        lineHeight: 1.2,
        padding: "1px 6px",
        borderRadius: "4px",
        whiteSpace: "nowrap",
        flexShrink: 0,
      }}
    >
      {chip}
    </span>
  );
}

import { useState } from "react";
import { Button, tokens } from "@fluentui/react-components";
import { useEvtxStore } from "./evtx-store";
import { useUiStore } from "../../stores/ui-store";
import { LOG_UI_FONT_FAMILY, getLogListMetrics } from "../../lib/log-accessibility";
import { summarizeCoverageGaps } from "./evtx-coverage";

/**
 * Shows what is missing from the loaded events.
 *
 * These are not load failures, so this is deliberately not styled as an error: the events that did
 * load are real and usable. They are gaps, and the reason they get their own banner rather than a
 * console line is that a silently incomplete view is worse than an empty one. Events that never
 * loaded look exactly like evidence that the thing being investigated did not happen.
 *
 * It cannot be dismissed permanently, only collapsed. A gap stays true for as long as the data is
 * on screen, and letting it be dismissed would make the view claim completeness it does not have.
 */
export function EvtxCoverageBanner() {
  const gaps = useEvtxStore((s) => s.coverageGaps);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const [collapsed, setCollapsed] = useState(false);

  const { fontSize, rowLineHeight } = getLogListMetrics(logListFontSize);
  const summary = summarizeCoverageGaps(gaps);

  // The live region is always rendered, and the banner content appears inside it. A screen reader
  // announces changes within a region it was already tracking, so a region that arrives already
  // populated is read as ordinary page content and the first gaps go unannounced. It must also
  // stay in the accessibility tree while empty, which display:none would prevent, so an empty
  // region is simply an unstyled element with no children.
  const empty = gaps.length === 0;

  return (
    <div
      role="status"
      aria-live="polite"
      style={
        empty
          ? undefined
          : {
              flexShrink: 0,
              display: "flex",
              flexDirection: "column",
              gap: "4px",
              padding: "6px 12px",
              fontFamily: LOG_UI_FONT_FAMILY,
              fontSize,
              lineHeight: `${rowLineHeight}px`,
              color: tokens.colorPaletteDarkOrangeForeground1,
              backgroundColor: tokens.colorPaletteDarkOrangeBackground1,
              borderBottom: `1px solid ${tokens.colorPaletteDarkOrangeBorderActive}`,
            }
      }
    >
      {empty ? null : (
        <>
      <div
        style={{ display: "flex", alignItems: "center", gap: "8px" }}
      >
        <span style={{ fontWeight: tokens.fontWeightSemibold }}>{summary}</span>
        <Button
          size="small"
          appearance="transparent"
          aria-expanded={!collapsed}
          onClick={() => setCollapsed((value) => !value)}
        >
          {collapsed ? "Show" : "Hide"}
        </Button>
      </div>
      {!collapsed && (
        <ul style={{ margin: 0, paddingInlineStart: "20px" }}>
          {gaps.map((gap) => (
            <li key={gap} style={{ wordBreak: "break-word" }}>
              {gap}
            </li>
          ))}
        </ul>
      )}
        </>
      )}
    </div>
  );
}

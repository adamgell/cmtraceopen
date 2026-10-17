/**
 * The "Add log source..." link that ends the channel pane's "Also correlating" section (spec 8.19),
 * and the report of how the last add went.
 *
 * The link opens a two-item menu, a file or a folder, because the text-log open flow takes either.
 * `addLogSource` does the work; this only runs it once at a time and says what it reported. A
 * failure is a `role="alert"` that names the file and the state it left, since a failed load can
 * clear the log that was being correlated and Event Logs does not show the log store's own status.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, Menu, MenuItem, MenuList, MenuPopover, MenuTrigger } from "@fluentui/react-components";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { addLogSource, type AddLogSourceKind } from "./add-log-source";

/** U+2026, the glyph the spec writes in all three labels. */
const ELLIPSIS = "…";

interface Report {
  /** A failure interrupts; a notice about files that were skipped does not. */
  role: "alert" | "status";
  message: string;
}

export function AddLogSourceControl({ primaryText }: { primaryText: string }) {
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const metrics = useMemo(() => getLogListMetrics(logListFontSize), [logListFontSize]);
  const groupFontSize = Math.max(10, metrics.fontSize - 2);
  const captionFontSize = Math.max(10, metrics.fontSize - 3);

  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const linkRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef(false);

  // The native dialog and the menu item that started the add are both gone when it finishes, so
  // focus would otherwise fall to the page. Put it back on the link, whatever the outcome.
  useEffect(() => {
    if (!busy && returnFocus.current) {
      returnFocus.current = false;
      linkRef.current?.focus();
    }
  }, [busy]);

  const run = useCallback(
    async (kind: AddLogSourceKind) => {
      if (busy) return;
      setBusy(true);
      setReport(null);
      returnFocus.current = true;
      try {
        const outcome = await addLogSource(kind);
        if (outcome.status === "failed" || outcome.status === "rejected") {
          setReport({ role: "alert", message: outcome.message });
        } else if (outcome.status === "added" && outcome.notice !== null) {
          setReport({ role: "status", message: outcome.notice });
        }
      } finally {
        setBusy(false);
      }
    },
    [busy],
  );

  const itemStyle = { fontSize: `${groupFontSize}px` };
  return (
    <div style={{ padding: "4px 12px 0" }}>
      <Menu>
        <MenuTrigger disableButtonEnhancement>
          <Link
            ref={linkRef}
            as="button"
            // Focusable while it works, so keyboard focus is not dropped when the add starts.
            disabledFocusable={busy}
            style={{ fontSize: `${groupFontSize}px`, fontWeight: 600 }}
          >
            {`Add log source${ELLIPSIS}`}
          </Link>
        </MenuTrigger>
        <MenuPopover>
          <MenuList>
            <MenuItem style={itemStyle} onClick={() => void run("file")}>
              {`Add log file${ELLIPSIS}`}
            </MenuItem>
            <MenuItem style={itemStyle} onClick={() => void run("folder")}>
              {`Add log folder${ELLIPSIS}`}
            </MenuItem>
          </MenuList>
        </MenuPopover>
      </Menu>
      {report !== null && (
        <div
          role={report.role}
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "flex-start",
            gap: "2px",
            paddingTop: "6px",
            fontSize: `${captionFontSize}px`,
            color: primaryText,
            overflowWrap: "anywhere",
          }}
        >
          <span>{report.message}</span>
          <Link
            as="button"
            onClick={() => {
              setReport(null);
              linkRef.current?.focus();
            }}
            style={{ fontSize: `${captionFontSize}px` }}
          >
            Dismiss
          </Link>
        </div>
      )}
    </div>
  );
}

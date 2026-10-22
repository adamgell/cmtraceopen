/**
 * The "Add log source..." link that ends the channel pane's "Also correlating" section (spec 8.19),
 * and the report of how the last add went.
 *
 * The link opens a two-item menu, a file or a folder, because the text-log open flow takes either.
 * `addLogSource` does the work; this only runs it once at a time and says what it reported.
 *
 * The report is two live regions, `role="status"` for a notice about files that were not covered and
 * `role="alert"` for an add that did not take. Both are mounted from the start and empty, and the
 * text arrives in a later render: an element inserted already holding its text is announced
 * unreliably by some screen readers, and Dismiss stays outside them so it is not read as part of the
 * message. A report says what happened to the add; how many text logs are correlated is appended from
 * the pane's own count, so it stays true if the correlated set changes under a report that is still
 * on screen.
 *
 * That sentence is its own node in a region that is not atomic, so a real change of the count
 * announces the changed sentence and not the whole report again. While the log store loads the count
 * is held at its last settled value: a folder load moves the active source before it parses, and the
 * values in between are not facts anyone should hear.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, Menu, MenuItem, MenuList, MenuPopover, MenuTrigger } from "@fluentui/react-components";
import { addLogSource, type AddLogSourceKind } from "./add-log-source";
import { describeCorrelatedState } from "./evtx-channel-stats";

/** U+2026, the glyph the spec writes in all three labels. */
const ELLIPSIS = "…";

interface Report {
  /** A notice about what was not covered does not interrupt; an add that did not take does. */
  kind: "notice" | "failure";
  message: string;
}

export function AddLogSourceControl({
  primaryText,
  groupFontSize,
  captionFontSize,
  correlatedCount,
  logStoreLoading,
}: {
  primaryText: string;
  /** The pane's group-header size (f - 2): the link and the menu items. */
  groupFontSize: number;
  /** The pane's caption size (f - 3): the report and Dismiss. */
  captionFontSize: number;
  /** How many text logs the pane lists as correlated right now. */
  correlatedCount: number;
  /** The log store is loading, so `correlatedCount` may be a value no load has settled on. */
  logStoreLoading: boolean;
}) {
  // The count shown is the last one the log store settled on. Adjusted during render, as the pane's
  // throttle is, so the first value shown after a load is the settled one and not a stale one.
  const [settledCount, setSettledCount] = useState(correlatedCount);
  if (!logStoreLoading && settledCount !== correlatedCount) setSettledCount(correlatedCount);
  const shownCount = logStoreLoading ? settledCount : correlatedCount;

  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const linkRef = useRef<HTMLButtonElement>(null);
  const returnFocus = useRef(false);

  // The native dialog and the menu item that started the add are both gone when it finishes, so
  // focus would otherwise fall to the page. Put it back on the link, whatever the outcome, unless
  // the user has moved it somewhere since: a folder add can take seconds, and finishing must not
  // pull focus out of the table they went to.
  useEffect(() => {
    if (!busy && returnFocus.current) {
      returnFocus.current = false;
      const active = document.activeElement;
      if (active === null || active === document.body) linkRef.current?.focus();
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
        if (
          outcome.status === "failed" ||
          outcome.status === "rejected" ||
          outcome.status === "notAdded"
        ) {
          setReport({ kind: "failure", message: outcome.message });
        } else if (outcome.status === "added" && outcome.notice !== null) {
          setReport({ kind: "notice", message: outcome.notice });
        }
      } finally {
        setBusy(false);
      }
    },
    [busy],
  );

  const regionStyle = (shown: boolean) => ({
    marginTop: shown ? "6px" : 0,
    fontSize: `${captionFontSize}px`,
    color: primaryText,
    overflowWrap: "anywhere" as const,
  });
  // The message and the sentence are separate nodes: the sentence changes without the message.
  const reportText = (kind: Report["kind"]) =>
    report?.kind === kind ? (
      <>
        <span>{report.message}</span> <span>{describeCorrelatedState(shownCount)}</span>
      </>
    ) : null;

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
      <div role="status" aria-atomic="false" style={regionStyle(report?.kind === "notice")}>
        {reportText("notice")}
      </div>
      <div role="alert" aria-atomic="false" style={regionStyle(report?.kind === "failure")}>
        {reportText("failure")}
      </div>
      {report !== null && (
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
      )}
    </div>
  );
}

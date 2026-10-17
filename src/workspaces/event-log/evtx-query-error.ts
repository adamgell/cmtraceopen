/**
 * How the search box and the More filters field query say that a query was not applied.
 *
 * A query that does not parse is not applied (spec 8.3): the view keeps the last one that did. Most
 * terms pass through such a state while they are typed (`level:`, an open quote, a trailing OR), so
 * the message waits until the text has stopped changing, and it goes away at once when the text
 * parses again.
 */
import { useEffect, useMemo, useState } from "react";
import { fieldQueryError } from "./evtx-filter";
import type { EvtxQueryError } from "./evtx-query-grammar";

/** How long text must stay unparseable after the last keystroke before the message shows. */
export const QUERY_ERROR_SETTLE_MS = 400;

/** The message for a query the view is not applying. */
export function notAppliedMessage(error: EvtxQueryError): string {
  return `Not applied: ${error.message}`;
}

/**
 * The error to show for `text` as a field query, or null.
 *
 * Null as soon as the text parses (or `enabled` is false). Otherwise the text's error, once
 * QUERY_ERROR_SETTLE_MS has passed without the text changing. Until then the error already shown,
 * if any, stays: correcting one problem into another does not make the line blink away and back.
 */
export function useSettledQueryError(text: string, enabled = true): EvtxQueryError | null {
  const error = useMemo(() => (enabled ? fieldQueryError(text) : null), [enabled, text]);
  const [settled, setSettled] = useState<EvtxQueryError | null>(null);
  useEffect(() => {
    if (!error) {
      setSettled(null);
      return undefined;
    }
    // A new error object per change of text, so every keystroke restarts the wait.
    const timer = window.setTimeout(() => setSettled(error), QUERY_ERROR_SETTLE_MS);
    return () => window.clearTimeout(timer);
  }, [error]);
  return error ? settled : null;
}

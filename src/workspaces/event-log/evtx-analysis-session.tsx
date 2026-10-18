/**
 * The published event-log analysis session, for a surface that asks the engine about it: its id and
 * its revision. The workspace holds the session (it builds it, publishes it and closes the one it
 * supersedes) and provides it here, so a surface anywhere under the workspace reads the same session
 * the same way: the correlation dock now, the Details pane in the rail for the context list (#843).
 * Outside a provider it reads as no session.
 *
 * Only the identity is provided. A consumer that pairs what it read with another reader's data (the
 * dock pairs a window with the counts-only chain model) compares session keys (`sessionKeyOf`), never
 * ids alone: the revision moves with every append.
 */
import { createContext, useContext, type ReactNode } from "react";
import type { EventLogAnalysisSessionStatus } from "../../lib/commands";
import type { CorrelationStage } from "./useEvtxCorrelation";

export type EvtxAnalysisSession = Pick<EventLogAnalysisSessionStatus, "sessionId" | "revision">;

const EvtxAnalysisSessionContext = createContext<EvtxAnalysisSession | null>(null);

export function EvtxAnalysisSessionProvider({
  value,
  children,
}: {
  /** The published session, or null while there is none. */
  value: EvtxAnalysisSession | null;
  children: ReactNode;
}) {
  return <EvtxAnalysisSessionContext.Provider value={value}>{children}</EvtxAnalysisSessionContext.Provider>;
}

/** The published session, or null while there is none. */
export function useEvtxAnalysisSession(): EvtxAnalysisSession | null {
  return useContext(EvtxAnalysisSessionContext);
}

/**
 * What a surface that reads the session can say about it. "No session" is two states, and only the
 * correlation stage tells them apart, because the workspace holds the status at null for the whole
 * of every (re)build: one is on the way (`building`: the events are loaded and the analysis is being
 * built or rebuilt, and a window read earlier is kept and shown as an earlier session's), and one is
 * not coming (`none`: there is nothing to wait for, and nothing read earlier is shown).
 */
export type EvtxAnalysisSessionState = "available" | "building" | "none";

/**
 * The state of the analysis session, from the status the provider holds and the correlation stage.
 * The one place this rule is written: the dock and the Details context list both call it.
 */
export function analysisSessionState(
  status: EvtxAnalysisSession | null,
  stage: CorrelationStage,
): EvtxAnalysisSessionState {
  if (status !== null) return "available";
  return stage === "pending" ? "building" : "none";
}

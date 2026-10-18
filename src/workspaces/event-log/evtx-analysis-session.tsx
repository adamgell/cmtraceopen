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

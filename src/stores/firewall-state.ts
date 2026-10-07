import type { FirewallControlToken, FirewallCoverage, FirewallDecodingStatus, LogEntry, ParseResult, TailPayload } from "../types/log";
import { emptyFirewallCoverage, firewallParseErrors } from "../lib/firewall";
export interface FirewallSourceState {
  sessionId: string;
  watchEpoch: number;
  active: boolean;
  coverage: FirewallCoverage;
  decoding: FirewallDecodingStatus;
  parseErrors: number;
  /** Native source IDs remain independent from aggregate display IDs. */
  sourceIds: Record<number, number>;
}
export function sourceFromSnapshot(snapshot: ParseResult, previous?: FirewallSourceState): FirewallSourceState | undefined {
  if (!snapshot.firewallSessionId) return undefined;
  if (previous?.sessionId === snapshot.firewallSessionId) return previous;
  const coverage = snapshot.firewallCoverage ?? emptyFirewallCoverage();
  return { sessionId: snapshot.firewallSessionId, watchEpoch: 0, active: false,
    coverage, decoding: snapshot.firewallDecoding ?? { kind: "ready", pendingBytes: 0, reason: null },
    parseErrors: firewallParseErrors(coverage), sourceIds: Object.fromEntries(snapshot.entries.map(row => [row.lineNumber, row.id])) };
}
export function sameFirewallControl(source: FirewallSourceState | undefined, token: FirewallControlToken | undefined): boolean {
  return !!source && !!token && source.sessionId === token.sourceSessionId && source.watchEpoch === token.watchEpoch;
}
export function reconcileFirewallRows(rows: LogEntry[], source: FirewallSourceState, payload: TailPayload, aggregate: boolean): { entries: LogEntry[]; source: FirewallSourceState } | null {
  if (!source.active || !sameFirewallControl(source, payload.firewallControl) || !payload.firewallCoverage || !payload.firewallDecoding || !payload.firewallReplacements) return null;
  const ids = payload.reset ? {} : { ...source.sourceIds };
  const entries = payload.reset ? rows.filter(row => row.filePath !== payload.filePath) : [...rows];
  const usedIds = new Set(Object.values(ids));
  const rowIndexes = new Map<number, number>();
  entries.forEach((row, index) => { if (row.filePath === payload.filePath) rowIndexes.set(row.lineNumber, index); });
  let nextDisplayId = aggregate ? rows.reduce((max, row) => Math.max(max, row.id), -1) + 1 : 0;
  for (const row of payload.entries) {
    if (row.filePath !== payload.filePath || !row.firewall) return null;
    if (rowIndexes.has(row.lineNumber)) {
      if (ids[row.lineNumber] !== row.id) return null;
      continue; // Repeated publication does not append the same source row twice.
    }
    if (usedIds.has(row.id)) return null;
    ids[row.lineNumber] = row.id;
    usedIds.add(row.id);
    rowIndexes.set(row.lineNumber, entries.length);
    entries.push(aggregate ? { ...row, id: nextDisplayId++ } : row);
  }
  for (const replacement of payload.firewallReplacements) {
    if (ids[replacement.expectedLineNumber] !== replacement.expectedId) return null;
    const index = rowIndexes.get(replacement.expectedLineNumber);
    if (index === undefined || replacement.entry.id !== replacement.expectedId || replacement.entry.lineNumber !== replacement.expectedLineNumber || replacement.entry.filePath !== payload.filePath) return null;
    entries[index] = { ...replacement.entry, id: entries[index].id };
  }
  return { entries, source: { ...source, sourceIds: ids, coverage: payload.firewallCoverage,
    decoding: payload.firewallDecoding, parseErrors: firewallParseErrors(payload.firewallCoverage) } };
}

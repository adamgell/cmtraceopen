import type { EspDiagnosticsSnapshot } from "./types";

const WORKLOAD_GUID_RE =
  /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/;

// A decorated workload identifier token: an optional prefix/suffix around a GUID,
// e.g. `Win32App_<guid>_1`. Global so it can rewrite every id in a finding string.
const DECORATED_IDENTIFIER_RE =
  /[0-9A-Za-z_]*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[0-9A-Za-z_]*/g;

/**
 * Graph friendly-name lookup keyed by BOTH the raw Graph id and its normalized
 * GUID. A Graph app/policy/script id is the bare GUID, while a classic workload's
 * raw identifier is decorated (`Win32App_<guid>_1`), so keying by the embedded GUID
 * lets either form resolve.
 */
export function buildEspGraphNameMap(
  snapshot: EspDiagnosticsSnapshot,
): Map<string, string> {
  const names = new Map<string, string>();
  const add = (id: string, displayName: string | null | undefined) => {
    if (!displayName) return;
    names.set(id.toLowerCase(), displayName);
    const guid = WORKLOAD_GUID_RE.exec(id)?.[0].toLowerCase();
    if (guid) names.set(guid, displayName);
  };
  for (const app of snapshot.graph?.apps.data ?? []) add(app.appId, app.displayName);
  for (const policy of snapshot.graph?.policies.data ?? [])
    add(policy.policyId, policy.displayName);
  for (const script of snapshot.graph?.scripts.data ?? [])
    add(script.scriptId, script.displayName);
  // Fall back to reduced workload display names (local/IME-derived) for objects
  // Graph did not return, keyed by the GUID embedded in the decorated raw
  // identifier so a bare `Win32App_<guid>_1` token still resolves. Graph names
  // added above are authoritative and are never overwritten here.
  for (const workload of snapshot.workloads) {
    if (!workload.displayName) continue;
    const guid = WORKLOAD_GUID_RE.exec(workload.rawIdentifier)?.[0]?.toLowerCase();
    if (guid && !names.has(guid)) names.set(guid, workload.displayName);
  }
  return names;
}

/** Resolve a single workload/raw identifier to its Graph friendly name, if known. */
export function lookupEspGraphName(
  names: Map<string, string>,
  rawIdentifier: string,
): string | undefined {
  const direct = names.get(rawIdentifier.toLowerCase());
  if (direct) return direct;
  const guid = WORKLOAD_GUID_RE.exec(rawIdentifier)?.[0].toLowerCase();
  return guid ? names.get(guid) : undefined;
}

/**
 * Replace every GUID-bearing identifier token in free text (e.g. a finding summary)
 * with its Graph friendly name, leaving unknown ids untouched. Used so the Action
 * Center reads "Company Portal" instead of "Win32App_<guid>_1".
 */
export function resolveEspIdentifiers(
  text: string,
  names: Map<string, string>,
): string {
  if (names.size === 0) return text;
  return text.replace(DECORATED_IDENTIFIER_RE, (token) => {
    const guid = WORKLOAD_GUID_RE.exec(token)?.[0].toLowerCase();
    const name = names.get(token.toLowerCase()) ?? (guid ? names.get(guid) : undefined);
    return name ?? token;
  });
}

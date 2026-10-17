/**
 * Which coverage surface shows which load gap.
 *
 * The invariant: every current load gap is disclosed on at least one rendered surface, and the
 * grid banner never repeats a gap that a rendered surface names. A surface (the Insights rail today;
 * the channel pane once Phase 8 adds its claim) claims the gaps it names, while it is on screen,
 * keyed by the shared key in evtx-coverage.ts (`formatCoverageGap`, `legacyCoverageDisclosureKey`).
 * The grid banner lists only what no surface claims, so no gap goes unshown and the banner repeats
 * none. Two surfaces may name the same gap (the rail note and the channel pane both name a refused
 * channel); claims are a union.
 *
 * Claims are registered in a layout effect, and the banner subscribes in a layout effect too, so it
 * re-renders before the browser paints and never shows a frame of gaps a surface is about to claim,
 * including on first mount. (`useSyncExternalStore` subscribes in a passive effect, after paint, so
 * a claim registered in the same commit would reach the banner one frame late.)
 * The registry lives in the workspace's provider, so claims reset with the workspace; without a
 * provider every hook is a no-op and nothing is claimed.
 */
import {
  createContext,
  useContext,
  useLayoutEffect,
  useState,
  type ReactNode,
} from "react";

export interface CoverageClaim {
  /** Keys of the gaps the surface shows. */
  keys: ReadonlySet<string>;
  /** The surface shows the archive member provenance. */
  archiveProvenance: boolean;
}

export type CoverageClaims = CoverageClaim;

const NO_CLAIMS: CoverageClaims = { keys: new Set(), archiveProvenance: false };

interface ClaimsRegistry {
  set(owner: symbol, claim: CoverageClaim | null): void;
  subscribe(listener: () => void): () => void;
  snapshot(): CoverageClaims;
}

function isEmpty(claim: CoverageClaim | null): boolean {
  return claim === null || (claim.keys.size === 0 && !claim.archiveProvenance);
}

function sameClaim(a: CoverageClaim, b: CoverageClaim): boolean {
  if (a.archiveProvenance !== b.archiveProvenance || a.keys.size !== b.keys.size) return false;
  for (const key of a.keys) if (!b.keys.has(key)) return false;
  return true;
}

function createRegistry(): ClaimsRegistry {
  const claims = new Map<symbol, CoverageClaim>();
  const listeners = new Set<() => void>();
  let snapshot = NO_CLAIMS;
  return {
    set(owner, claim) {
      const previous = claims.get(owner);
      if (isEmpty(claim)) {
        if (previous === undefined) return;
        claims.delete(owner);
      } else {
        // Callers build a new claim every render; only a change of content is news.
        if (previous !== undefined && sameClaim(previous, claim!)) return;
        claims.set(owner, claim!);
      }
      const keys = new Set<string>();
      let archiveProvenance = false;
      for (const held of claims.values()) {
        for (const key of held.keys) keys.add(key);
        archiveProvenance ||= held.archiveProvenance;
      }
      snapshot = { keys, archiveProvenance };
      for (const listener of listeners) listener();
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    },
    snapshot: () => snapshot,
  };
}

const ClaimsContext = createContext<ClaimsRegistry | null>(null);

/** Holds the claims of one workspace instance. */
export function CoverageClaimsProvider({ children }: { children: ReactNode }) {
  const [registry] = useState(createRegistry);
  return <ClaimsContext.Provider value={registry}>{children}</ClaimsContext.Provider>;
}

/**
 * Registers what the calling surface shows. Pass null (or an empty claim) while it shows nothing,
 * for instance while it is hidden; the claim is also released when the surface unmounts.
 */
export function useCoverageClaim(claim: CoverageClaim | null): void {
  const registry = useContext(ClaimsContext);
  const [owner] = useState(() => Symbol("coverage-claim"));
  useLayoutEffect(() => {
    registry?.set(owner, claim);
  }, [registry, owner, claim]);
  useLayoutEffect(
    () => () => {
      registry?.set(owner, null);
    },
    [registry, owner],
  );
}

/**
 * Everything claimed by every surface, as one union. Subscribes, then reads, in a layout effect: a
 * claim registered earlier in the same commit is read at once, and a later one notifies; either
 * way the update re-renders before paint. The snapshot changes identity only when its content does.
 */
export function useCoverageClaims(): CoverageClaims {
  const registry = useContext(ClaimsContext);
  const [claims, setClaims] = useState<CoverageClaims>(() => registry?.snapshot() ?? NO_CLAIMS);
  useLayoutEffect(() => {
    if (registry === null) {
      setClaims(NO_CLAIMS);
      return undefined;
    }
    const read = () => setClaims(registry.snapshot());
    const unsubscribe = registry.subscribe(read);
    read();
    return unsubscribe;
  }, [registry]);
  return claims;
}

import { formatTimelineError, isFirewallTimelineError } from "../lib/timeline-errors";
import { create } from "zustand";
import type {
  TimelineBundle,
  Incident,
  LaneBucket,
  TimelineEntry,
  IncidentDetail, FirewallTimelineError, TimelineRequestOrigin,
} from "../types/timeline";

interface TimelineState {
  bundle: TimelineBundle | null;
  timelineGeneration: number;
  loadError: string | null;
  queryError: string | null;
  staleSource: FirewallTimelineError | null;
  building: boolean;
  detailCache: Map<string, IncidentDetail>;
  requestOrigin(): TimelineRequestOrigin;
  isCurrent(origin: TimelineRequestOrigin): boolean;
  beginBuild(): TimelineRequestOrigin;
  reportQueryError(error: unknown, origin: TimelineRequestOrigin): void;
  reportBuildError(error: unknown, origin: TimelineRequestOrigin): void;
  putDetail(key: string, value: IncidentDetail): void;
  selectedIncidentId: number | null;
  brushRange: [number, number] | null;
  laneVisibility: Record<number, boolean>;
  soloSourceIdx: number | null;

  bucketCache: Map<string, LaneBucket[]>;
  entryCache: Map<string, TimelineEntry[]>;

  setBundle(b: TimelineBundle | null): void;
  setLoadError(error: string | null): void;
  reset(): void;
  setBrushRange(r: [number, number]): void;
  clearBrushRange(): void;
  selectIncident(id: number | null): void;
  toggleMute(sourceIdx: number): void;
  setSolo(sourceIdx: number | null): void;
  replaceIncidents(incidents: Incident[]): void;

  putBuckets(key: string, v: LaneBucket[]): void;
  putEntries(key: string, v: TimelineEntry[]): void;
  invalidateCaches(): void;
}

const MAX_BUCKET_CACHE = 32;
const MAX_ENTRY_CACHE = 128;

export const useTimelineStore = create<TimelineState>((set, get) => ({
  bundle: null,
  timelineGeneration: 0,
  loadError: null,
  queryError: null, staleSource: null, building: false, detailCache: new Map(),
  selectedIncidentId: null,
  brushRange: null,
  laneVisibility: {},
  soloSourceIdx: null,
  bucketCache: new Map(),
  entryCache: new Map(),

  setBundle(b) {
    const laneVisibility: Record<number, boolean> = {};
    b?.sources.forEach((s) => {
      laneVisibility[s.idx] = true;
    });
    set((state) => ({
      bundle: b,
      loadError: null,
      queryError: null, staleSource: null, building: false, detailCache: new Map(),
      timelineGeneration: state.timelineGeneration + 1,
      selectedIncidentId: null,
      brushRange: null,
      laneVisibility,
      soloSourceIdx: null,
      bucketCache: new Map(),
      entryCache: new Map(),
    }));
  },
  requestOrigin() { const state = get(); return { bundleId: state.bundle?.id ?? null, generation: state.timelineGeneration }; },
  isCurrent(origin) { const state = get(); return (state.bundle?.id ?? null) === origin.bundleId && state.timelineGeneration === origin.generation; },
  beginBuild() {
    set(state => ({ timelineGeneration: state.timelineGeneration + 1, building: true, entryCache: new Map(), detailCache: new Map() }));
    return get().requestOrigin();
  },
  reportQueryError(error, origin) {
    if (!get().isCurrent(origin)) return;
    if (isFirewallTimelineError(error) && error.reason === "sourceChanged") {
      set(state => ({ queryError: formatTimelineError(error), staleSource: error, timelineGeneration: state.timelineGeneration + 1, entryCache: new Map(), detailCache: new Map(), building: false }));
    } else set({ queryError: formatTimelineError(error) });
  },
  reportBuildError(error, origin) {
    if (!get().isCurrent(origin)) return;
    set({ loadError: formatTimelineError(error), building: false });
    if (isFirewallTimelineError(error) && error.reason === "sourceChanged" && get().bundle?.sources.some(source => source.path === error.path)) get().reportQueryError(error, origin);
  },
  putDetail(key, value) {
    const cache = new Map(get().detailCache);
    if (cache.size >= 32) { const first = cache.keys().next().value; if (first !== undefined) cache.delete(first); }
    cache.set(key, value); set({ detailCache: cache });
  },
  setLoadError(error) {
    set({ loadError: error });
  },

  reset() {
    get().setBundle(null);
  },

  setBrushRange(r) {
    set({ brushRange: r });
    get().invalidateCaches();
  },

  clearBrushRange() {
    set({ brushRange: null });
    get().invalidateCaches();
  },

  selectIncident(id) {
    const b = get().bundle;
    const inc =
      id == null ? null : (b?.incidents.find((i) => i.id === id) ?? null);
    if (inc) {
      const pad = 2000;
      set({
        selectedIncidentId: id,
        brushRange: [inc.tsStartMs - pad, inc.tsEndMs + pad],
      });
      get().invalidateCaches();
    } else {
      set({ selectedIncidentId: id });
    }
  },

  toggleMute(sourceIdx) {
    set((s) => ({
      laneVisibility: {
        ...s.laneVisibility,
        [sourceIdx]: !s.laneVisibility[sourceIdx],
      },
    }));
    get().invalidateCaches();
  },

  setSolo(sourceIdx) {
    set({ soloSourceIdx: sourceIdx });
    get().invalidateCaches();
  },

  replaceIncidents(incidents) {
    set((s) => (s.bundle ? { bundle: { ...s.bundle, incidents } } : s));
  },

  putBuckets(key, v) {
    const m = new Map(get().bucketCache);
    if (m.size >= MAX_BUCKET_CACHE) {
      const first = m.keys().next().value;
      if (first !== undefined) m.delete(first);
    }
    m.set(key, v);
    set({ bucketCache: m });
  },

  putEntries(key, v) {
    const m = new Map(get().entryCache);
    if (m.size >= MAX_ENTRY_CACHE) {
      const first = m.keys().next().value;
      if (first !== undefined) m.delete(first);
    }
    m.set(key, v);
    set({ entryCache: m });
  },

  invalidateCaches() {
    set(state => ({ timelineGeneration: state.timelineGeneration + 1, building: false, bucketCache: new Map(), entryCache: new Map(), detailCache: new Map() }));
  },
}));

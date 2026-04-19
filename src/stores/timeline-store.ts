import { create } from "zustand";
import type {
  TimelineBundle,
  Incident,
  LaneBucket,
  TimelineEntry,
} from "../types/timeline";

interface TimelineState {
  bundle: TimelineBundle | null;
  selectedIncidentId: number | null;
  brushRange: [number, number] | null;
  laneVisibility: Record<number, boolean>;
  soloSourceIdx: number | null;

  bucketCache: Map<string, LaneBucket[]>;
  entryCache: Map<string, TimelineEntry[]>;

  setBundle(b: TimelineBundle | null): void;
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
    set({
      bundle: b,
      selectedIncidentId: null,
      brushRange: null,
      laneVisibility,
      soloSourceIdx: null,
      bucketCache: new Map(),
      entryCache: new Map(),
    });
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
    set({ bucketCache: new Map(), entryCache: new Map() });
  },
}));

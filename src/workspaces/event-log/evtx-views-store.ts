/**
 * The persisted library of custom views.
 *
 * Its own store under its own key, not part of the saved-filter store: that one is pinned at persist
 * version 2 and holds `{ savedFilters }`, and no older build reads this key, so nothing here has to
 * be tolerated by one. Only custom views are stored. The built-ins are constants in `evtx-views.ts`,
 * so they cannot be edited, deleted, reordered or left stale by an update, and no stored or imported
 * entry can be one.
 *
 * Persistence mirrors `evtx-layout-store.ts`: zustand `persist` over localStorage, version 1, and
 * deliberately no `migrate` (AGENTS.md: no migrations). Zustand discards an envelope of another
 * version and `merge` runs on every rehydration, so everything read back from storage is
 * sanitized whatever its version, and a hand-edited envelope reaches the strip only as views this
 * build can read exactly.
 */
import { create } from "zustand";
import { persist } from "zustand/middleware";

import type { EvtxFilterCriteria } from "./evtx-saved-filters";
import {
  cleanViewName,
  MAX_CUSTOM_VIEWS,
  MAX_VIEW_NAME_LENGTH,
  mergeViews,
  sanitizeStoredViews,
  sanitizeViewBody,
  SAVED_VIEW_SCHEMA,
  uniqueViewName,
  viewNameTaken,
  type EvtxStoredView,
  type EvtxViewBody,
  type EvtxViewLayout,
  type EvtxViewMerge,
} from "./evtx-views";

export const EVTX_VIEWS_STORAGE_KEY = "cmtraceopen-evtx-views";

/** Why a view was not made or changed, for the dialog to say. */
export type EvtxViewFailure =
  /** Empty, too long, or carrying characters a typed name does not. */
  | "invalid-name"
  /** Another view, or a built-in, has this name (ignoring case). */
  | "name-taken"
  | "library-full"
  /** The view would not be read back as written, for example a list of Event IDs that does not parse. */
  | "unreadable"
  | "not-found";

export type EvtxViewResult =
  | { ok: true; view: EvtxStoredView }
  | { ok: false; reason: EvtxViewFailure };

interface EvtxViewState {
  views: EvtxStoredView[];
  /** Makes a view. The criteria are read as written: pass `captureCriteria`, which holds no transient one. */
  create: (name: string, criteria: EvtxFilterCriteria, layout: EvtxViewLayout | null) => EvtxViewResult;
  rename: (id: string, name: string) => EvtxViewResult;
  /**
   * Replaces a view's criteria with `criteria`. The layout is replaced only when the view already has
   * one: whether a view holds a layout is the operator's choice when it was made, and stays.
   */
  update: (id: string, criteria: EvtxFilterCriteria, layout: EvtxViewLayout) => EvtxViewResult;
  /** A copy of `source` (a built-in or a custom view) under a name made unique. */
  duplicate: (source: EvtxViewBody) => EvtxViewResult;
  remove: (id: string) => void;
  importViews: (imported: readonly EvtxViewBody[]) => EvtxViewMerge;
}

function newId(): string {
  // crypto.randomUUID is unavailable in some webviews (the filter store makes the same allowance).
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `view-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Reads what storage held: only `views`, and only the views this build can read exactly. */
export function readPersistedViews(persisted: unknown): EvtxStoredView[] {
  const list =
    typeof persisted === "object" && persisted !== null
      ? (persisted as { views?: unknown }).views
      : undefined;
  return sanitizeStoredViews(list, newId).views;
}

export const useEvtxViewStore = create<EvtxViewState>()(
  persist(
    (set, get) => {
      /** The body as the library would read it back, or why it would not. */
      const checked = (
        body: EvtxViewBody,
      ): { ok: true; body: EvtxViewBody } | { ok: false; reason: EvtxViewFailure } => {
        const name = cleanViewName(body.name);
        if (name === null) return { ok: false, reason: "invalid-name" };
        // Through the same reader as an import, so a view made here is one that survives a restart.
        const read = sanitizeViewBody(JSON.parse(JSON.stringify({ ...body, name })));
        return read ? { ok: true, body: read } : { ok: false, reason: "unreadable" };
      };

      return {
        views: [],

        create: (name, criteria, layout) => {
          const views = get().views;
          const result = checked({ name, criteria, layout });
          if (!result.ok) return result;
          if (viewNameTaken(result.body.name, views)) return { ok: false, reason: "name-taken" };
          if (views.length >= MAX_CUSTOM_VIEWS) return { ok: false, reason: "library-full" };
          const view: EvtxStoredView = { id: newId(), ...result.body };
          set({ views: [...views, view] });
          return { ok: true, view };
        },

        rename: (id, name) => {
          const views = get().views;
          const current = views.find((view) => view.id === id);
          if (!current) return { ok: false, reason: "not-found" };
          const result = checked({ ...current, name });
          if (!result.ok) return result;
          if (viewNameTaken(result.body.name, views.filter((view) => view.id !== id))) {
            return { ok: false, reason: "name-taken" };
          }
          const view: EvtxStoredView = { ...current, name: result.body.name };
          set({ views: views.map((candidate) => (candidate.id === id ? view : candidate)) });
          return { ok: true, view };
        },

        update: (id, criteria, layout) => {
          const views = get().views;
          const current = views.find((view) => view.id === id);
          if (!current) return { ok: false, reason: "not-found" };
          const result = checked({
            name: current.name,
            criteria,
            layout: current.layout === null ? null : layout,
          });
          if (!result.ok) return result;
          const view: EvtxStoredView = { id, ...result.body };
          set({ views: views.map((candidate) => (candidate.id === id ? view : candidate)) });
          return { ok: true, view };
        },

        duplicate: (source) => {
          const views = get().views;
          if (views.length >= MAX_CUSTOM_VIEWS) return { ok: false, reason: "library-full" };
          const wanted = `${source.name} copy`.slice(0, MAX_VIEW_NAME_LENGTH).trimEnd();
          const result = checked({ ...source, name: uniqueViewName(wanted, views) });
          if (!result.ok) return result;
          const view: EvtxStoredView = { id: newId(), ...result.body };
          set({ views: [...views, view] });
          return { ok: true, view };
        },

        remove: (id) => set({ views: get().views.filter((view) => view.id !== id) }),

        importViews: (imported) => {
          // Through the same reader as every other way in, so a body that did not come from
          // `parseViewExport` is read as strictly as one that did.
          const readable: EvtxViewBody[] = [];
          for (const body of imported) {
            const result = checked(body);
            if (result.ok) readable.push(result.body);
          }
          const merged = mergeViews(get().views, readable, newId);
          set({ views: merged.views });
          return { ...merged, skipped: merged.skipped + imported.length - readable.length };
        },
      };
    },
    {
      name: EVTX_VIEWS_STORAGE_KEY,
      version: SAVED_VIEW_SCHEMA,
      partialize: (state) => ({ views: state.views }),
      merge: (persisted, current) => ({ ...current, views: readPersistedViews(persisted) }),
    },
  ),
);

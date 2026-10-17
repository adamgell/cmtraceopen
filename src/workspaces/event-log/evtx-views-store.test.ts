import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn().mockResolvedValue(() => undefined),
}));

import { DEFAULT_QUICK_FILTER } from "./evtx-filter";
import { useSavedFilterStore } from "./evtx-filter-store";
import { captureCriteria, sanitizeCriteria, SAVED_FILTER_SCHEMA } from "./evtx-saved-filters";
import { useEvtxStore } from "./evtx-store";
import {
  ENROLLMENT_TRIAGE_ID,
  EVTX_BUILT_IN_VIEWS,
  listViews,
  MAX_CUSTOM_VIEWS,
  MAX_VIEW_NAME_LENGTH,
  type EvtxViewBody,
  type EvtxViewLayout,
} from "./evtx-views";
import { EVTX_VIEWS_STORAGE_KEY, useEvtxViewStore } from "./evtx-views-store";

const TRANSIENT = /timeRange|startMs|endMs|recordScope|scopeRecord/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const CRITERIA = sanitizeCriteria({
  beforeLoad: { levels: ["Error"], eventIds: "41", timeWindow: "7d", selectedChannels: ["System"] },
  onLoad: { search: "provider:Kernel", quickFilter: { ...DEFAULT_QUICK_FILTER } },
  afterLoad: { groupBy: ["provider"] },
});
const OTHER_CRITERIA = sanitizeCriteria({
  beforeLoad: { levels: ["Warning"], eventIds: "", timeWindow: "24h", selectedChannels: ["Application"] },
});
const LAYOUT: EvtxViewLayout = {
  activeView: "grouped",
  panels: { channels: true, insights: false, dock: false },
};
const OTHER_LAYOUT: EvtxViewLayout = {
  activeView: "timeline",
  panels: { channels: false, insights: true, dock: false },
};

const stored = () => JSON.parse(localStorage.getItem(EVTX_VIEWS_STORAGE_KEY) ?? "null");
const state = () => useEvtxViewStore.getState();

function reset() {
  localStorage.clear();
  useEvtxViewStore.setState({ views: [] });
  useEvtxStore.getState().reset();
}

async function rehydrateFrom(raw: unknown, version = 1) {
  localStorage.setItem(EVTX_VIEWS_STORAGE_KEY, JSON.stringify({ state: raw, version }));
  await useEvtxViewStore.persist.rehydrate();
}

describe("the view library", () => {
  beforeEach(reset);

  describe("persistence", () => {
    it("is its own key, at version 1 with no migrate, holding only the views", () => {
      const options = useEvtxViewStore.persist.getOptions();
      expect(options.name).toBe("cmtraceopen-evtx-views");
      expect(options.version).toBe(1);
      expect(options.migrate).toBeUndefined();
      state().create("One", CRITERIA, LAYOUT);
      expect(Object.keys(stored())).toEqual(["state", "version"]);
      expect(stored().version).toBe(1);
      expect(Object.keys(stored().state)).toEqual(["views"]);
    });

    it("leaves the saved-filter store at version 2 and its own key alone", () => {
      state().create("One", CRITERIA, null);
      expect(SAVED_FILTER_SCHEMA).toBe(2);
      expect(useSavedFilterStore.persist.getOptions().version).toBe(2);
      expect(useSavedFilterStore.persist.getOptions().name).not.toBe(EVTX_VIEWS_STORAGE_KEY);
    });

    it("never writes a built-in, or the word builtIn, to storage", () => {
      state().create("One", CRITERIA, LAYOUT);
      state().duplicate(EVTX_BUILT_IN_VIEWS[0]);
      const text = localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)!;
      expect(text).not.toMatch(/builtIn|builtin:/);
      expect(stored().state.views.map((v: { name: string }) => v.name)).toEqual(["One", "Enrollment triage copy"]);
    });

    it("reads back what it wrote", async () => {
      state().create("One", CRITERIA, LAYOUT);
      state().create("Two", OTHER_CRITERIA, null);
      const before = JSON.stringify(state().views);
      const written = localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)!;
      // Setting state writes it too, so put back what the two views wrote.
      useEvtxViewStore.setState({ views: [] });
      localStorage.setItem(EVTX_VIEWS_STORAGE_KEY, written);
      await useEvtxViewStore.persist.rehydrate();
      expect(state().views).toHaveLength(2);
      expect(JSON.stringify(state().views)).toBe(before);
    });

    describe("an envelope of another version is discarded, not migrated", () => {
      let errors: ReturnType<typeof vi.spyOn>;
      beforeEach(() => {
        errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
      });
      afterEach(() => errors.mockRestore());

      const good = { views: [{ id: "a", name: "Old", criteria: CRITERIA, layout: null }] };
      it.each([0, 2, 99])("version %i", async (version) => {
        await rehydrateFrom(good, version);
        expect(state().views).toEqual([]);
      });

      it("keeps version 1", async () => {
        await rehydrateFrom(good, 1);
        expect(state().views.map((v) => v.name)).toEqual(["Old"]);
      });
    });

    it.each([
      ["a string", "garbage"],
      ["null", null],
      ["a list", []],
      ["an object with no views", {}],
      ["views that is not a list", { views: "x" }],
    ])("reads %s as an empty library", async (_label, raw) => {
      await rehydrateFrom(raw);
      expect(state().views).toEqual([]);
    });

    it("reads storage that is not JSON as an empty library", async () => {
      localStorage.setItem(EVTX_VIEWS_STORAGE_KEY, "{not json");
      await useEvtxViewStore.persist.rehydrate();
      expect(state().views).toEqual([]);
    });

    it("sanitizes a current-version envelope too: storage is an untrusted boundary", async () => {
      const view = { id: "ok", name: "Fine", criteria: CRITERIA, layout: LAYOUT };
      await rehydrateFrom({
        views: [
          view,
          { ...view, id: ENROLLMENT_TRIAGE_ID, name: "Pose", builtIn: true },
          { ...view, id: "same", name: "enrollment TRIAGE" },
          { ...view, id: "bad-mode", name: "Bad", criteria: { ...CRITERIA, onLoad: { search: "", quickFilter: { ...DEFAULT_QUICK_FILTER, mode: "futureMode" } } } },
          { ...view, id: "hostile", name: "Hostile", timeRange: { startMs: 1, endMs: 2 }, criteria: { ...CRITERIA, recordScope: { kind: "finding" }, scopeRecordIds: [1] } },
          "junk",
          { name: "" },
        ],
      });
      const names = state().views.map((v) => v.name);
      expect(names).toEqual(["Fine", "Pose", "enrollment TRIAGE (2)", "Hostile"]);
      expect(state().views.some((v) => v.id === ENROLLMENT_TRIAGE_ID)).toBe(false);
      expect(listViews(state().views).filter((v) => v.builtIn)).toHaveLength(1);
      expect(JSON.stringify(state().views)).not.toMatch(TRANSIENT);
      expect(JSON.stringify(state().views)).not.toMatch(/builtIn/);
    });

    it("makes ids anew from storage unless they have the shape the library makes", async () => {
      const uuid = "0b3d3a58-6a34-4c8e-9f0b-2c1d7e5a9b01";
      const view = { name: "Fine", criteria: CRITERIA, layout: null };
      await rehydrateFrom({
        views: [
          { id: uuid, ...view },
          { id: "a b", ...view, name: "Space" },
          { id: "x".repeat(1_048_576), ...view, name: "Huge" },
        ],
      });
      expect(state().views.map((v) => v.name)).toEqual(["Fine", "Space", "Huge"]);
      expect(state().views[0].id).toBe(uuid);
      for (const view of state().views.slice(1)) expect(view.id).toMatch(UUID);
      // The next write does not carry the megabyte.
      state().create("Another", CRITERIA, null);
      expect(localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)!.length).toBeLessThan(20_000);
    });

    it("gives every view the library makes a UUID", () => {
      const made = state().create("One", CRITERIA, null);
      const copy = state().duplicate(state().views[0]);
      const merged = state().importViews([{ name: "Two", criteria: CRITERIA, layout: null }]);
      expect(made.ok && made.view.id).toMatch(UUID);
      expect(copy.ok && copy.view.id).toMatch(UUID);
      expect(merged.views.every((v) => UUID.test(v.id))).toBe(true);
    });

    it("keeps at most the limit from storage", async () => {
      const many = Array.from({ length: MAX_CUSTOM_VIEWS + 4 }, (_, i) => ({
        id: `v${i}`,
        name: `View ${i}`,
        criteria: CRITERIA,
        layout: null,
      }));
      await rehydrateFrom({ views: many });
      expect(state().views).toHaveLength(MAX_CUSTOM_VIEWS);
    });
  });

  describe("create", () => {
    it("stores a view with a new id, in order", () => {
      const a = state().create("  First  ", CRITERIA, LAYOUT);
      const b = state().create("Second", OTHER_CRITERIA, null);
      expect(a.ok && b.ok).toBe(true);
      expect(state().views.map((v) => [v.name, v.layout === null])).toEqual([["First", false], ["Second", true]]);
      expect(new Set(state().views.map((v) => v.id)).size).toBe(2);
      expect(state().views[0].criteria).toEqual(CRITERIA);
    });

    it.each([
      ["an empty name", ""],
      ["a blank name", "   "],
      ["an over-long name", "n".repeat(MAX_VIEW_NAME_LENGTH + 1)],
    ])("refuses %s", (_label, name) => {
      expect(state().create(name, CRITERIA, null)).toEqual({ ok: false, reason: "invalid-name" });
      expect(state().views).toEqual([]);
    });

    it("refuses a name that is taken, ignoring case, by a view or by a built-in", () => {
      state().create("Mine", CRITERIA, null);
      expect(state().create("MINE", CRITERIA, null)).toEqual({ ok: false, reason: "name-taken" });
      expect(state().create("enrollment triage", CRITERIA, null)).toEqual({ ok: false, reason: "name-taken" });
      expect(state().views).toHaveLength(1);
    });

    it("keeps the name that shows: invisible characters are removed, so a look-alike of a built-in is refused", () => {
      const spoof = `Enrollment triage${String.fromCodePoint(0x61c)}`;
      expect(state().create(spoof, CRITERIA, null)).toEqual({ ok: false, reason: "name-taken" });
      const made = state().create(`Mine${String.fromCodePoint(0x200b)} ${String.fromCodePoint(0xe0041)}view`, CRITERIA, null);
      expect(made.ok && made.view.name).toBe("Mine view");
    });

    it("refuses a view when the library is full", () => {
      for (let i = 0; i < MAX_CUSTOM_VIEWS; i += 1) state().create(`V${i}`, CRITERIA, null);
      expect(state().create("One more", CRITERIA, null)).toEqual({ ok: false, reason: "library-full" });
      expect(state().views).toHaveLength(MAX_CUSTOM_VIEWS);
    });

    it("refuses a view that would not be read back as written", () => {
      const invalid = { ...CRITERIA, beforeLoad: { ...CRITERIA.beforeLoad, eventIds: "4624,abc" } };
      expect(state().create("Bad IDs", invalid, null)).toEqual({ ok: false, reason: "unreadable" });
      expect(state().views).toEqual([]);
    });
  });

  describe("the transient criteria are never stored in a view (Q-2)", () => {
    it("holds none from a capture of a store that has them, in the state or in storage", () => {
      useEvtxStore.setState({
        timeRange: { startMs: 1_700_000_000_000, endMs: 1_700_000_060_000 },
        recordScope: {
          kind: "finding",
          title: "A finding",
          records: new Set(),
          counts: { notLoaded: 0, noUsableIdentity: 0, ambiguous: 0, bounded: false },
        },
      });
      // They are there to be captured: a store that held neither would prove nothing.
      expect(useEvtxStore.getState().timeRange).not.toBeNull();
      expect(useEvtxStore.getState().recordScope).not.toBeNull();
      const captured = captureCriteria(useEvtxStore.getState());
      state().create("Made", captured, LAYOUT);
      const id = state().views[0].id;
      state().update(id, captureCriteria(useEvtxStore.getState()), OTHER_LAYOUT);
      state().duplicate(state().views[0]);
      expect(state().views).toHaveLength(2);
      expect(JSON.stringify(state().views)).not.toMatch(TRANSIENT);
      expect(localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)).not.toMatch(TRANSIENT);
    });

    it("holds none when a caller hands it criteria that carry them", () => {
      const hostile = { ...CRITERIA, timeRange: { startMs: 1, endMs: 2 }, recordScope: { kind: "chain" } } as typeof CRITERIA;
      state().create("Hostile", hostile, LAYOUT);
      const merged = state().importViews([{ name: "Imported", criteria: hostile, layout: null }]);
      expect(merged.added).toBe(1);
      expect(state().views).toHaveLength(2);
      expect(JSON.stringify(state().views)).not.toMatch(TRANSIENT);
      expect(localStorage.getItem(EVTX_VIEWS_STORAGE_KEY)).not.toMatch(TRANSIENT);
    });
  });

  describe("rename", () => {
    it("renames, keeping the id and the position", () => {
      state().create("A", CRITERIA, null);
      state().create("B", CRITERIA, null);
      const [a] = state().views;
      const result = state().rename(a.id, "  Renamed ");
      expect(result.ok).toBe(true);
      expect(state().views.map((v) => [v.id, v.name])).toEqual([[a.id, "Renamed"], [state().views[1].id, "B"]]);
    });

    it("accepts a change of case to its own name", () => {
      state().create("Mine", CRITERIA, null);
      expect(state().rename(state().views[0].id, "MINE").ok).toBe(true);
    });

    it("refuses a name another view or a built-in has, and an empty one", () => {
      state().create("A", CRITERIA, null);
      state().create("B", CRITERIA, null);
      const [a] = state().views;
      expect(state().rename(a.id, "b")).toEqual({ ok: false, reason: "name-taken" });
      expect(state().rename(a.id, "Enrollment Triage")).toEqual({ ok: false, reason: "name-taken" });
      expect(state().rename(a.id, " ")).toEqual({ ok: false, reason: "invalid-name" });
      expect(state().views[0].name).toBe("A");
    });

    it("cannot rename a built-in, or a view that is not there", () => {
      expect(state().rename(ENROLLMENT_TRIAGE_ID, "Mine")).toEqual({ ok: false, reason: "not-found" });
      expect(state().rename("missing", "Mine")).toEqual({ ok: false, reason: "not-found" });
    });
  });

  describe("update", () => {
    it("replaces the criteria and the layout of a view that has a layout", () => {
      state().create("With", CRITERIA, LAYOUT);
      const id = state().views[0].id;
      expect(state().update(id, OTHER_CRITERIA, OTHER_LAYOUT).ok).toBe(true);
      expect(state().views[0]).toMatchObject({ id, name: "With", criteria: OTHER_CRITERIA, layout: OTHER_LAYOUT });
    });

    it("keeps a view without a layout without one", () => {
      state().create("Without", CRITERIA, null);
      state().update(state().views[0].id, OTHER_CRITERIA, OTHER_LAYOUT);
      expect(state().views[0].criteria).toEqual(OTHER_CRITERIA);
      expect(state().views[0].layout).toBeNull();
    });

    it("cannot change a built-in, or a view that is not there", () => {
      expect(state().update(ENROLLMENT_TRIAGE_ID, OTHER_CRITERIA, OTHER_LAYOUT)).toEqual({ ok: false, reason: "not-found" });
      expect(state().update("missing", OTHER_CRITERIA, OTHER_LAYOUT)).toEqual({ ok: false, reason: "not-found" });
      expect(EVTX_BUILT_IN_VIEWS[0].criteria.beforeLoad.timeWindow).toBe("all");
    });
  });

  describe("duplicate", () => {
    it("copies a built-in into an ordinary view", () => {
      const result = state().duplicate(EVTX_BUILT_IN_VIEWS[0]);
      expect(result.ok).toBe(true);
      const [copy] = state().views;
      expect(copy.name).toBe("Enrollment triage copy");
      expect(copy.id).not.toBe(ENROLLMENT_TRIAGE_ID);
      expect(copy.criteria).toEqual(EVTX_BUILT_IN_VIEWS[0].criteria);
      expect(listViews(state().views)[1].builtIn).toBe(false);
    });

    it("makes the copy's name unique, and keeps it inside the limit", () => {
      state().create("Mine", CRITERIA, LAYOUT);
      const source = state().views[0];
      state().duplicate(source);
      state().duplicate(source);
      expect(state().views.map((v) => v.name)).toEqual(["Mine", "Mine copy", "Mine copy (2)"]);
      state().create("n".repeat(MAX_VIEW_NAME_LENGTH), CRITERIA, null);
      const long = state().views[3];
      expect(state().duplicate(long).ok).toBe(true);
      expect(state().views[4].name.length).toBeLessThanOrEqual(MAX_VIEW_NAME_LENGTH);
    });

    it("refuses when the library is full", () => {
      for (let i = 0; i < MAX_CUSTOM_VIEWS; i += 1) state().create(`V${i}`, CRITERIA, null);
      expect(state().duplicate(state().views[0])).toEqual({ ok: false, reason: "library-full" });
    });
  });

  describe("remove", () => {
    it("removes one view and leaves the others in order", () => {
      for (const name of ["A", "B", "C"]) state().create(name, CRITERIA, null);
      state().remove(state().views[1].id);
      expect(state().views.map((v) => v.name)).toEqual(["A", "C"]);
      expect(stored().state.views.map((v: { name: string }) => v.name)).toEqual(["A", "C"]);
    });

    it("cannot remove a built-in, and ignores an id it does not have", () => {
      state().create("A", CRITERIA, null);
      state().remove(ENROLLMENT_TRIAGE_ID);
      state().remove("missing");
      expect(state().views).toHaveLength(1);
      expect(listViews(state().views).map((v) => v.name)).toEqual(["Enrollment triage", "A"]);
    });
  });

  describe("importViews", () => {
    const body = (name: string, layout: EvtxViewBody["layout"] = null): EvtxViewBody => ({ name, criteria: CRITERIA, layout });

    it("adds, replaces and counts, and writes the result to storage", () => {
      state().create("Mine", OTHER_CRITERIA, LAYOUT);
      const mineId = state().views[0].id;
      const merged = state().importViews([body("Mine", null), body("Shared")]);
      expect(merged).toMatchObject({ added: 1, replaced: 1, skipped: 0 });
      expect(state().views.map((v) => v.name)).toEqual(["Mine", "Shared"]);
      expect(state().views[0].id).toBe(mineId);
      expect(state().views[0].layout).toBeNull();
      expect(stored().state.views).toHaveLength(2);
    });

    it("skips and counts a body it cannot read, as strictly as a file's", () => {
      const unreadable = { name: "Bad IDs", criteria: { ...CRITERIA, beforeLoad: { ...CRITERIA.beforeLoad, eventIds: "x,y" } }, layout: null };
      const merged = state().importViews([unreadable, body("Fine")]);
      expect(merged).toMatchObject({ added: 1, replaced: 0, skipped: 1 });
      expect(state().views.map((v) => v.name)).toEqual(["Fine"]);
    });

    it("gives an imported view that poses as a built-in a different name", () => {
      state().importViews([body("Enrollment triage")]);
      expect(state().views.map((v) => v.name)).toEqual(["Enrollment triage (2)"]);
      expect(state().views[0].id).not.toBe(ENROLLMENT_TRIAGE_ID);
    });
  });
});

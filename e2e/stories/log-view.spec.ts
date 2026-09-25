/**
 * Story-mapped browser coverage for the log view (list, find, filter, quick
 * stats, merge/diff, sources, info pane).
 *
 * Every test names the user-story ids it verifies (see
 * `docs/qa/user-stories.csv`). The suite runs in a plain browser against the
 * Tauri IPC shim, so it needs no Rust build and no Windows host; unmodified
 * commands are forwarded to the real backend when `npm run app:dev` happens to
 * be running behind the debug IPC bridge.
 *
 * Real components are driven wherever possible: the boot path uses
 * `get_initial_file_paths` + `open_log_file`/`parse_files_batch` overrides so
 * the app's own load pipeline runs, and the UI is then exercised through the
 * real toolbar, find bar, dialogs and list. Pure store/view semantics are
 * pushed through the live Vite store singletons with `seedStore`.
 *
 * Native dialogs (`plugin:dialog`) are never opened — they are replaced with
 * per-test IPC overrides, which is the only way a browser run can supply a
 * chosen path.
 */
import type { Page } from "@playwright/test";

import { expect, test } from "../fixtures";
import { DEMO_LOG_ABS_PATH } from "../fixtures/screenshot-data";
import { bootApp, seedStore, selectWorkspace } from "./harness";
import type { LogEntry, ParseResult, Severity } from "../../src/types/log";

const LOG_STORE = "/src/stores/log-store.ts";
const FILTER_STORE = "/src/stores/filter-store.ts";
const UI_STORE = "/src/stores/ui-store.ts";
const TIMELINE_STORE = "/src/stores/timeline-store.ts";
const COMMANDS = "/src/lib/commands.ts";
const LOG_SOURCE = "/src/lib/log-source.ts";
const SESSION_SAVE = "/src/lib/session-save.ts";

/** The virtualized log list container — the element that would scroll. */
const LIST = '[data-log-list="true"]';

/** October 2031 — a distinctive instant so timestamp finds cannot collide. */
const BASE_EPOCH_MS = Date.UTC(2031, 9, 4, 12, 0, 0);

interface EntrySpec {
  message: string;
  severity?: Severity;
  component?: string | null;
  lineNumber?: number;
  timestamp?: number | null;
  errorCodeSpans?: LogEntry["errorCodeSpans"];
}

function two(value: number): string {
  return String(value).padStart(2, "0");
}

function three(value: number): string {
  return String(value).padStart(3, "0");
}

function formatStamp(epochMs: number): string {
  const d = new Date(epochMs);
  return `${d.getUTCFullYear()}-${two(d.getUTCMonth() + 1)}-${two(d.getUTCDate())} ${two(
    d.getUTCHours(),
  )}:${two(d.getUTCMinutes())}:${two(d.getUTCSeconds())}.${three(d.getUTCMilliseconds())}`;
}

function buildEntries(filePath: string, specs: EntrySpec[]): LogEntry[] {
  return specs.map((spec, index) => {
    const timestamp =
      spec.timestamp === undefined ? BASE_EPOCH_MS + index * 1000 : spec.timestamp;
    const entry: LogEntry = {
      id: index,
      lineNumber: spec.lineNumber ?? index + 1,
      message: spec.message,
      component: spec.component === undefined ? "AppEnforce" : spec.component,
      timestamp,
      timestampDisplay: timestamp === null ? null : formatStamp(timestamp),
      severity: spec.severity ?? "Info",
      thread: 4820,
      threadDisplay: "4820",
      sourceFile: "appexcnlib.cpp",
      format: "Ccm",
      filePath,
      timezoneOffset: 0,
    };
    if (spec.errorCodeSpans) {
      entry.errorCodeSpans = spec.errorCodeSpans;
    }
    return entry;
  });
}

function buildResult(filePath: string, specs: EntrySpec[]): ParseResult {
  const entries = buildEntries(filePath, specs);
  return {
    entries,
    formatDetected: "Ccm",
    parserSelection: {
      parser: "ccm",
      implementation: "ccm",
      provenance: "dedicated",
      parseQuality: "structured",
      recordFraming: "logicalRecord",
      dateOrder: "monthFirst",
    },
    totalLines: entries.length,
    parseErrors: 0,
    filePath,
    fileSize: 4096,
    byteOffset: 4096,
  };
}

/**
 * Module URLs the page has actually fetched for `modulePath`.
 *
 * Vite serves a hot-updated module under `<path>?t=<stamp>`, and the app's
 * importers hold whichever variant was current when they were transformed. A
 * plain-URL import would then create a second, independent store instance, so
 * every seed writes to all variants the page knows about.
 */
async function moduleUrls(page: Page, modulePath: string): Promise<string[]> {
  const fetched = await page.evaluate(
    (target) =>
      performance
        .getEntriesByType("resource")
        .map((entry) => entry.name)
        .filter((name) => name.includes(target))
        .map((name) => name.slice(name.indexOf(target))),
    modulePath,
  );
  // A hot-updated variant is the URL the app's own importers hold, so it wins;
  // the plain path stays last as the fallback for a freshly started server.
  const variants = [...new Set(fetched)].filter((url) => url.includes("?"));
  variants.sort(
    (a, b) => Number(b.split("?t=")[1] ?? 0) - Number(a.split("?t=")[1] ?? 0),
  );
  return [...variants, modulePath];
}

/** The module path to import in the page so it shares the app's own instance. */
async function appModule(page: Page, modulePath: string): Promise<string> {
  return (await moduleUrls(page, modulePath))[0];
}

/** Pushes state into every live instance of a store the page may be using. */
async function seedEverywhere<T>(
  page: Page,
  modulePath: string,
  storeName: string,
  state: T,
): Promise<void> {
  for (const url of await moduleUrls(page, modulePath)) {
    await seedStore(page, url, storeName, state);
  }
}

/** Push entries + totalLines into the live log store (the view reads both). */
async function seedEntries(page: Page, entries: LogEntry[]): Promise<void> {
  await seedEverywhere(page, LOG_STORE, "useLogStore", {
    entries,
    totalLines: entries.length,
  });
}

/** Boot the log view with a synthetic parse result for one file. */
async function bootWithLog(
  page: Page,
  filePath: string,
  specs: EntrySpec[],
  options: Omit<Parameters<typeof bootApp>[1], "overrides"> = {},
): Promise<ParseResult> {
  const result = buildResult(filePath, specs);
  await bootApp(page, {
    ...options,
    overrides: {
      get_initial_file_paths: [filePath],
      open_log_file: result,
      inspect_path_kind: "file",
    },
  });
  return result;
}

/**
 * Waits for the boot file load to finish applying.
 *
 * The launch flow clears the filter store when it starts and the load replaces
 * the entry set when it lands, so anything seeded before it settles can be
 * wiped by a late load. `single-file` is written at the end of that flow.
 */
async function settleLogLoad(page: Page, expectedEntries: number): Promise<void> {
  await expect(
    page.locator(`${LIST} .log-row`),
    "the booted log must finish rendering before the test seeds state",
  ).toHaveCount(expectedEntries, { timeout: 15_000 });
  await expect(page.getByRole("status").first()).toContainText("Loaded ");
}

function parseRgb(color: string): { r: number; g: number; b: number } {
  const match = /rgba?\((\d+),\s*(\d+),\s*(\d+)/.exec(color);
  if (!match) throw new Error(`not an rgb colour: ${color}`);
  return { r: Number(match[1]), g: Number(match[2]), b: Number(match[3]) };
}

/**
 * Reads one store value out of the instance the running app is using.
 *
 * The candidates come from `moduleUrls`, so a hot-updated module URL is
 * preferred over the plain path the spec would otherwise import.
 */
async function readStore<T>(
  page: Page,
  modulePath: string,
  storeName: string,
  project: string,
): Promise<T> {
  const urls = await moduleUrls(page, modulePath);
  return page.evaluate(
    async ({ candidates, name, body }) => {
      const read = (state: unknown) =>
        // eslint-disable-next-line no-new-func
        new Function("state", `return (${body});`)(state) as unknown;
      const values: unknown[] = [];
      for (const path of candidates) {
        const mod = (await import(/* @vite-ignore */ path)) as Record<string, unknown>;
        const store = mod[name] as { getState: () => unknown };
        values.push(read(store.getState()));
      }
      // A store the app has advanced past its defaults is the app's instance;
      // otherwise every candidate agrees and the first value is representative.
      return (values.find((value) => value !== undefined && value !== null) ??
        values[0]) as T;
    },
    { candidates: urls, name: storeName, body: project },
  ) as Promise<T>;
}

// ---------------------------------------------------------------------------
// Find
// ---------------------------------------------------------------------------

test.describe("log: find", () => {
  test("[LOG-030] find searches the message plus every active column", async ({ page }) => {
    const entries = buildEntries(DEMO_LOG_ABS_PATH, [
      {
        message: "Bootstrapping the deployment pipeline",
        component: "SpecialComponent",
      },
      { message: "Policy refresh finished", component: "PolicyAgent" },
    ]);
    await bootWithLog(page, DEMO_LOG_ABS_PATH, [
      {
        message: "Bootstrapping the deployment pipeline",
        component: "SpecialComponent",
      },
      { message: "Policy refresh finished", component: "PolicyAgent" },
    ]);
    await settleLogLoad(page, entries.length);
    await seedEntries(page, entries);
    await seedEverywhere(page, LOG_STORE, "useLogStore", {
      activeColumns: ["severity", "dateTime", "message", "component", "thread"],
    });

    // Entry point: the real find bar.
    await seedEverywhere(page, UI_STORE, "useUiStore", { showFindBar: true });
    const findInput = page.getByPlaceholder("Find...");
    await expect(findInput).toBeVisible();
    await findInput.fill("SpecialComponent");
    await expect(page.getByText("1 of 1")).toBeVisible({ timeout: 10_000 });
    await findInput.fill("NothingMatchesThis");
    await expect(page.getByText("No results", { exact: true })).toBeVisible();

    // Store semantics: the haystack is rebuilt from the active column set.
    const probe = await page.evaluate(
      async ({ storePath }) => {
        const { useLogStore } = await import(/* @vite-ignore */ storePath);
        const store = useLogStore;
        const settle = () => new Promise((resolve) => setTimeout(resolve, 250));

        store.getState().setActiveColumns([
          "severity",
          "dateTime",
          "message",
          "component",
          "thread",
        ]);
        store.getState().setFindQuery("SpecialComponent");
        await settle();
        const componentMatch = [...store.getState().findMatchIds];

        store.getState().setActiveColumns(["message", "severity", "lineNumber"]);
        const componentDropped = [...store.getState().findMatchIds];

        // Reaches the second entry's timestamp but not the first's, and appears
        // in no message.
        store.getState().setFindQuery("12:00:01");
        await settle();
        const stampWithoutDateColumn = [...store.getState().findMatchIds];

        store.getState().setActiveColumns(["dateTime", "message", "severity", "lineNumber"]);
        const stampWithDateColumn = [...store.getState().findMatchIds];

        // Regex mode compiles with the "i" flag unless case-sensitive.
        store.getState().setFindUseRegex(true);
        store.getState().setFindCaseSensitive(false);
        store.getState().setFindQuery("^bootstrapping");
        await settle();
        const regexCaseInsensitive = [...store.getState().findMatchIds];
        store.getState().setFindCaseSensitive(true);
        const regexCaseSensitive = [...store.getState().findMatchIds];

        // An invalid pattern yields an empty match list instead of throwing.
        store.getState().setFindCaseSensitive(false);
        store.getState().setFindQuery("(");
        await settle();
        const invalidRegex = {
          matches: [...store.getState().findMatchIds],
          error: store.getState().findRegexError,
        };

        return {
          componentMatch,
          componentDropped,
          stampWithoutDateColumn,
          stampWithDateColumn,
          regexCaseInsensitive,
          regexCaseSensitive,
          invalidRegex,
        };
      },
      { storePath: await appModule(page, LOG_STORE) },
    );

    expect(probe.componentMatch).toEqual([0]);
    expect(probe.componentDropped).toEqual([]);
    expect(probe.stampWithoutDateColumn).toEqual([]);
    expect(probe.stampWithDateColumn).toEqual([1]);
    expect(probe.regexCaseInsensitive).toEqual([0]);
    expect(probe.regexCaseSensitive).toEqual([]);
    expect(probe.invalidRegex.matches).toEqual([]);
    expect(probe.invalidRegex.error).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// Filter dialog, toolbar button, selection reconciliation, error navigation
// ---------------------------------------------------------------------------

const FILTER_SPECS: EntrySpec[] = [
  { message: "Installing Contoso VPN Client", severity: "Info" },
  { message: "Deployment failed with error 0x80070643", severity: "Error" },
  { message: "Retry scheduled after back-off", severity: "Warning" },
];

test.describe("log: filter", () => {
  test("[LOG-032] Apply drops blank clauses and reports filter state", async ({ page }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, FILTER_SPECS);
    await settleLogLoad(page, FILTER_SPECS.length);

    // Matches both the idle "Filter..." label and the active "Filter (N)" one,
    // because the button relabels itself once a clause is applied.
    const filterButton = page.getByRole("button", { name: /^Filter(\.\.\.| \()/ });
    await expect(filterButton).toBeEnabled({ timeout: 15_000 });
    await filterButton.click();

    const dialog = page.getByRole("dialog", { name: "Filter" });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("No filter currently active")).toBeVisible();
    await expect(dialog.getByText("Draft clauses ready: 0")).toBeVisible();

    await dialog.getByPlaceholder("Value...").first().fill("0x80070643");
    await expect(dialog.getByText("Draft clauses ready: 1")).toBeVisible();
    await dialog.getByRole("button", { name: "+ Add Clause" }).click();
    await dialog.getByPlaceholder("Value...").nth(1).fill("   ");
    await expect(
      dialog.getByText("Draft clauses ready: 1"),
      "a whitespace-only clause is not a ready draft clause",
    ).toBeVisible();

    // apply_filter is stubbed with a delay so the in-flight status is observable.
    await page.evaluate((errorIds) => {
      const w = window as unknown as {
        __applyFilterCalls?: unknown[];
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__applyFilterCalls = [];
      w.__e2e_ipc_overrides__["apply_filter"] = (args) => {
        w.__applyFilterCalls!.push(args);
        return new Promise((resolve) => window.setTimeout(() => resolve(errorIds), 400));
      };
    }, [1]);

    await dialog.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(dialog.getByText("Applying filter...")).toBeVisible();
    await expect(dialog.getByRole("button", { name: "Applying...", exact: true })).toBeVisible();
    await expect(page.getByRole("dialog", { name: "Filter" })).toHaveCount(0, { timeout: 10_000 });

    const calls = await page.evaluate(
      () =>
        (window as unknown as { __applyFilterCalls?: { clauses: unknown[] }[] })
          .__applyFilterCalls ?? [],
    );
    expect(calls).toHaveLength(1);
    expect(calls[0].clauses).toEqual([
      { field: "Message", op: "Contains", value: "0x80070643" },
    ]);

    const applied = await readStore<{ filteredIds: number[] | null; clauses: unknown[] }>(
      page,
      FILTER_STORE,
      "useFilterStore",
      "({ clauses: state.clauses, filteredIds: state.filteredIds ? [...state.filteredIds] : null })",
    );
    expect(applied.clauses).toHaveLength(1);
    expect(applied.filteredIds).toEqual([1]);

    // Re-opening reports the applied clause count. Ctrl+Shift+L is the only way
    // back into the dialog while a filter is active — the toolbar button clears
    // it instead (LOG-036).
    await page.keyboard.press("Control+Shift+L");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText("1 clause(s) currently active")).toBeVisible();

    // A failed apply stays in the dialog and names the failure.
    await dialog.getByPlaceholder("Value...").first().fill("Retry scheduled");
    await page.evaluate(() => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["apply_filter"] = () => {
        throw new Error("filter backend exploded");
      };
    });
    await dialog.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(dialog.getByText("Filter failed: filter backend exploded")).toBeVisible({
      timeout: 10_000,
    });
    await expect(dialog).toBeVisible();

    // Clear Filter applies an empty clause list and closes.
    await dialog.getByRole("button", { name: "Clear Filter" }).click();
    await expect(page.getByRole("dialog", { name: "Filter" })).toHaveCount(0);
    const cleared = await readStore<{ clauses: unknown[]; filteredIds: number[] | null }>(
      page,
      FILTER_STORE,
      "useFilterStore",
      "({ clauses: state.clauses, filteredIds: state.filteredIds ? [...state.filteredIds] : null })",
    );
    expect(cleared.clauses).toEqual([]);
    expect(cleared.filteredIds).toBeNull();
  });

  test("[LOG-036] the toolbar Filter button opens the dialog or clears the filter", async ({
    page,
  }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, FILTER_SPECS);
    await settleLogLoad(page, FILTER_SPECS.length);

    const button = page.getByRole("button", { name: "Filter...", exact: true });
    await expect(button).toBeEnabled({ timeout: 15_000 });
    await expect(button).toHaveAttribute("title", "Filter... (Ctrl+Shift+L)");
    await expect(button).toHaveAttribute("aria-pressed", "false");

    /** Computed background of the toolbar button whose label is exactly `name`. */
    const buttonBackground = (name: string) =>
      page.evaluate((label) => {
        const element = Array.from(document.querySelectorAll("button")).find(
          (candidate) => candidate.textContent?.trim() === label,
        );
        return element ? getComputedStyle(element).backgroundColor : null;
      }, name);
    const idleFilterBackground = await buttonBackground("Filter...");

    await page.evaluate(
      async ({ storePath }) => {
        const { useFilterStore } = await import(/* @vite-ignore */ storePath);
        const store = useFilterStore;
        store.getState().addQuickFilter("Message", "Installing", "Contains");
        store.getState().addQuickFilter("Severity", "Info", "Equals");
      },
      { storePath: await appModule(page, FILTER_STORE) },
    );

    const active = page.getByRole("button", { name: "Filter (2)", exact: true });
    await expect(active).toBeVisible();
    await expect(active).toHaveAttribute("aria-pressed", "true");
    const title = await active.getAttribute("title");
    expect(title).toContain("Clear active filter (2 clauses)");
    expect(title).toContain("click to remove");
    // Primary appearance: the active button paints the brand surface while the
    // secondary "Error lookup" button keeps the neutral one.
    const activeBackground = await buttonBackground("Filter (2)");
    const secondaryBackground = await buttonBackground("Error lookup");
    expect(activeBackground).not.toBeNull();
    expect(secondaryBackground).not.toBeNull();
    // Primary appearance: the button leaves the neutral secondary surface for a
    // tinted brand one, which no secondary button paints.
    expect(activeBackground).not.toBe(secondaryBackground);
    expect(activeBackground).not.toBe(idleFilterBackground);
    const activeRgb = parseRgb(activeBackground!);
    expect(activeRgb.g).toBeGreaterThan(activeRgb.r);
    expect(activeRgb.b).toBeGreaterThan(activeRgb.r);
    const secondaryRgb = parseRgb(secondaryBackground!);
    expect(secondaryRgb.r).toBe(secondaryRgb.g);
    expect(secondaryRgb.g).toBe(secondaryRgb.b);

    // Clicking clears instead of opening the dialog.
    await active.click();
    await expect(page.getByRole("dialog", { name: "Filter" })).toHaveCount(0);
    const after = await readStore<{ clauses: unknown[]; filteredIds: number[] | null }>(
      page,
      FILTER_STORE,
      "useFilterStore",
      "({ clauses: state.clauses, filteredIds: state.filteredIds ? [...state.filteredIds] : null })",
    );
    expect(after.clauses).toEqual([]);
    expect(after.filteredIds).toBeNull();
    await expect(page.getByRole("button", { name: "Filter...", exact: true })).toBeVisible();
  });

  test("[LOG-036] the Filter button is disabled with no entries loaded", async ({ page }) => {
    await bootApp(page);
    await expect(page.getByRole("button", { name: "Filter...", exact: true })).toBeDisabled();
  });

  test("[LOG-037] selection moves to the nearest visible row after filtering", async ({
    page,
  }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, FILTER_SPECS);
    await settleLogLoad(page, FILTER_SPECS.length);
    await seedEntries(page, buildEntries(DEMO_LOG_ABS_PATH, FILTER_SPECS));

    const result = await page.evaluate(
      async ({ logPath, filterPath }) => {
        const { useLogStore } = await import(/* @vite-ignore */ logPath);
        const { useFilterStore } = await import(/* @vite-ignore */ filterPath);
        const log = useLogStore;
        const filter = useFilterStore;
        const selected = () => log.getState().selectedId;

        log.getState().selectEntry(1);
        filter.getState().setFilteredIds(new Set([0, 2]));
        const nearestFollows = selected();

        log.getState().selectEntry(2);
        filter.getState().setFilteredIds(new Set([0, 1]));
        const nearestPrecedes = selected();

        filter.getState().setFilteredIds(new Set([]));
        const nothingMatches = selected();

        // Passing null (filter cleared) leaves the selection untouched.
        log.getState().selectEntry(0);
        filter.getState().setFilteredIds(null);
        const clearedKeepsSelection = selected();

        return { nearestFollows, nearestPrecedes, nothingMatches, clearedKeepsSelection };
      },
      { logPath: await appModule(page, LOG_STORE), filterPath: await appModule(page, FILTER_STORE) },
    );

    expect(result.nearestFollows).toBe(2);
    expect(result.nearestPrecedes).toBe(1);
    expect(result.nothingMatches).toBeNull();
    expect(result.clearedKeepsSelection).toBe(0);
  });

  test("[LOG-039] error navigation counts and steps the visible errors", async ({ page }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, FILTER_SPECS);
    await settleLogLoad(page, FILTER_SPECS.length);

    const toolbar = page.getByRole("toolbar", { name: "Error navigation" });
    await expect(toolbar).toBeVisible({ timeout: 15_000 });
    // 1 error in the booted log.
    await expect(toolbar.getByText("1 error", { exact: true })).toBeVisible();

    const previous = toolbar.getByRole("button", { name: "Previous error" });
    const next = toolbar.getByRole("button", { name: "Next error" });
    await expect(previous).toBeEnabled();
    await next.click();

    await expect
      .poll(() =>
        readStore<number | null>(page, LOG_STORE, "useLogStore", "state.selectedId"),
      )
      .toBe(1);

    const list = page.getByRole("listbox", { name: "Log entries" });
    await expect(list).toHaveAttribute("aria-activedescendant", "log-list-row-1");
    await expect(list).toBeFocused();

    // Keyboard focus paints the inset brand ring.
    await expect
      .poll(async () => (await list.evaluate((el) => getComputedStyle(el).boxShadow)).trim())
      .not.toBe("none");

    // Filtering the error out of view drops the count and disables navigation.
    await page.evaluate(
      async ({ filterPath }) => {
        const { useFilterStore } = await import(/* @vite-ignore */ filterPath);
        useFilterStore.getState().setFilteredIds(new Set([0, 2]));
      },
      { filterPath: await appModule(page, FILTER_STORE) },
    );
    await expect(toolbar.getByText("0 errors", { exact: true })).toBeVisible();
    await expect(previous).toBeDisabled();
    await expect(next).toBeDisabled();
  });
});

// ---------------------------------------------------------------------------
// Column auto-fit
// ---------------------------------------------------------------------------

const WIDE_MESSAGE = `${"C:\\Windows\\CCM\\Logs\\AppEnforce.log ".repeat(30)}done`;

test.describe("log: column fit", () => {
  test("[LOG-041] the severity header auto-fits every column past the viewport", async ({
    page,
  }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, [
      { message: WIDE_MESSAGE, severity: "Info" },
      { message: "short line", severity: "Warning" },
    ]);
    await seedEntries(
      page,
      buildEntries(DEMO_LOG_ABS_PATH, [
        { message: WIDE_MESSAGE, severity: "Info" },
        { message: "short line", severity: "Warning" },
      ]),
    );
    await expect(page.locator(`${LIST} .log-row`).first()).toBeVisible({ timeout: 15_000 });

    const fitAll = page.getByRole("button", {
      name: "Auto-fit all columns to content width",
    });
    await expect(fitAll).toBeVisible();
    // The severity header hosts it; every other header advertises double-click fit.
    await expect(page.getByTitle("Double-click to auto-fit this column").first()).toBeVisible();

    await fitAll.click();

    await expect
      .poll(() =>
        readStore<number | undefined>(
          page,
          UI_STORE,
          "useUiStore",
          "state.columnWidths.message",
        ),
      )
      .toBeGreaterThan(0);

    const metrics = await page.evaluate((selector) => {
      const element = document.querySelector<HTMLElement>(selector);
      return element ? { clientWidth: element.clientWidth } : null;
    }, LIST);
    const messageWidth = await readStore<number>(
      page,
      UI_STORE,
      "useUiStore",
      "state.columnWidths.message",
    );
    expect(metrics).not.toBeNull();
    // A deliberate fit is not clamped to the viewport.
    expect(messageWidth).toBeGreaterThan(metrics!.clientWidth);

    // The same control is keyboard-activatable: after a reset, Enter re-fits.
    await seedEverywhere(page, UI_STORE, "useUiStore", { columnWidths: { message: 300 } });
    await fitAll.focus();
    await page.keyboard.press("Enter");
    await expect
      .poll(() =>
        readStore<number | undefined>(page, UI_STORE, "useUiStore", "state.columnWidths.message"),
      )
      .toBeGreaterThan(300);

    // Double-clicking a single header fits only that column.
    await page.evaluate(
      async ({ storePath }) => {
        const { useUiStore } = await import(/* @vite-ignore */ storePath);
        useUiStore.getState().setColumnWidth("component", 111);
      },
      { storePath: await appModule(page, UI_STORE) },
    );
    await page
      .getByTitle("Double-click to auto-fit this column")
      .filter({ hasText: "Log Text" })
      .first()
      .dblclick();
    await expect
      .poll(() =>
        readStore<number>(page, UI_STORE, "useUiStore", "state.columnWidths.component"),
      )
      .toBe(111);
  });

  test("[LOG-042] the message column auto-expands without a horizontal scrollbar", async ({
    page,
  }) => {
    const specs: EntrySpec[] = Array.from({ length: 30 }, (_, index) => ({
      message: `${WIDE_MESSAGE} #${index}`,
      severity: index === 3 ? "Error" : "Info",
    }));
    await bootWithLog(page, DEMO_LOG_ABS_PATH, specs);
    await seedEntries(page, buildEntries(DEMO_LOG_ABS_PATH, specs));
    await expect(page.locator(`${LIST} .log-row`).first()).toBeVisible({ timeout: 15_000 });

    await expect
      .poll(
        () =>
          page.evaluate((selector) => {
            const element = document.querySelector<HTMLElement>(selector);
            if (!element) return null;
            return element.scrollWidth - element.clientWidth;
          }, LIST),
        { message: "the log list must not overflow horizontally" },
      )
      .toBeLessThanOrEqual(1);

    const clamped = await readStore<number | undefined>(
      page,
      UI_STORE,
      "useUiStore",
      "state.columnWidths.message",
    );
    expect(clamped).toBeGreaterThan(0);

    // A user-sized message column is left alone by the auto-expand attempt.
    await page.evaluate(
      async ({ storePath }) => {
        const { useUiStore } = await import(/* @vite-ignore */ storePath);
        useUiStore.getState().setColumnWidth("message", 333);
      },
      { storePath: await appModule(page, UI_STORE) },
    );
    await page.waitForTimeout(400);
    expect(
      await readStore<number>(page, UI_STORE, "useUiStore", "state.columnWidths.message"),
    ).toBe(333);
  });
});

// ---------------------------------------------------------------------------
// Quick stats
// ---------------------------------------------------------------------------

const SEVERITY_SPECS: EntrySpec[] = [
  { message: "Install failed with 0x80070643", severity: "Error" },
  { message: "Second install failure 0x80070643", severity: "Error" },
  { message: "Deferring content download", severity: "Warning" },
  { message: "Detection complete", severity: "Info" },
  { message: "Enforcement completed successfully", severity: "Success" },
];

test.describe("log: quick stats", () => {
  test("[LOG-051] the Quick Stats header shows totals and collapses", async ({ page }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, SEVERITY_SPECS);
    await settleLogLoad(page, SEVERITY_SPECS.length);
    await seedEntries(page, buildEntries(DEMO_LOG_ABS_PATH, SEVERITY_SPECS));

    const header = page.getByRole("button", { name: /Quick Stats/ });
    await expect(header).toBeVisible({ timeout: 15_000 });
    await expect(header).toHaveAttribute("aria-expanded", "false");
    await expect(header).toContainText("5 total");
    await expect(header).not.toContainText("filtered");

    await header.click();
    await expect(header).toHaveAttribute("aria-expanded", "true");

    // A filter that reduces the visible set adds the filtered count.
    await page.evaluate(
      async ({ filterPath }) => {
        const { useFilterStore } = await import(/* @vite-ignore */ filterPath);
        useFilterStore.getState().setFilteredIds(new Set([0, 2]));
      },
      { filterPath: await appModule(page, FILTER_STORE) },
    );
    await expect(header).toContainText("5 total (2 filtered)");

    // Closing the last log auto-collapses (and hides) the panel.
    await page.evaluate(
      async ({ logPath }) => {
        const { useLogStore } = await import(/* @vite-ignore */ logPath);
        useLogStore.getState().clearActiveFile();
      },
      { logPath: await appModule(page, LOG_STORE) },
    );
    await expect(page.getByRole("button", { name: /Quick Stats/ })).toHaveCount(0);
  });

  test("[LOG-053] a severity card filters the list without IPC", async ({ page }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, SEVERITY_SPECS);
    await settleLogLoad(page, SEVERITY_SPECS.length);
    await seedEntries(page, buildEntries(DEMO_LOG_ABS_PATH, SEVERITY_SPECS));

    const header = page.getByRole("button", { name: /Quick Stats/ });
    await expect(header).toBeVisible({ timeout: 15_000 });
    await header.click();

    await page.getByRole("button", { name: /ERRORS/i }).click();
    await expect
      .poll(() =>
        readStore<number[] | null>(
          page,
          FILTER_STORE,
          "useFilterStore",
          "state.filteredIds ? [...state.filteredIds] : null",
        ),
      )
      .toEqual([0, 1]);

    // The list now shows only the two Error rows.
    await expect(page.locator(`${LIST} .log-row`)).toHaveCount(2);
  });

  test("[LOG-053] the active severity card shows its outline and toggles off", async ({
    page,
  }) => {
    await bootWithLog(page, DEMO_LOG_ABS_PATH, SEVERITY_SPECS);
    await settleLogLoad(page, SEVERITY_SPECS.length);
    await seedEntries(page, buildEntries(DEMO_LOG_ABS_PATH, SEVERITY_SPECS));

    await page.getByRole("button", { name: /Quick Stats/ }).click();
    const card = page.getByRole("button", { name: /ERRORS/i });
    await card.click();

    await expect
      .poll(
        async () =>
          card.evaluate((el) => {
            const style = getComputedStyle(el);
            const value = el.querySelector("span, div > div > span");
            return {
              borderWidth: style.borderTopWidth,
              borderColor: style.borderTopColor,
              valueColor: value ? getComputedStyle(value).color : null,
            };
          }),
        { message: "the clicked severity card must be marked active" },
      )
      .toMatchObject({ borderWidth: "2px" });
    const active = await card.evaluate((el) => {
      const style = getComputedStyle(el);
      const value = el.querySelector("span");
      return {
        borderColor: style.borderTopColor,
        valueColor: value ? getComputedStyle(value).color : null,
      };
    });
    expect(active.borderColor).toBe(active.valueColor);

    // Clicking the active card clears the filter again.
    await card.click();
    await expect
      .poll(() =>
        readStore<number[] | null>(
          page,
          FILTER_STORE,
          "useFilterStore",
          "state.filteredIds ? [...state.filteredIds] : null",
        ),
      )
      .toBeNull();

    // An external clearFilter resets the card too.
    await card.click();
    await page.evaluate(
      async ({ filterPath }) => {
        const { useFilterStore } = await import(/* @vite-ignore */ filterPath);
        useFilterStore.getState().clearFilter();
      },
      { filterPath: await appModule(page, FILTER_STORE) },
    );
    await expect
      .poll(async () => card.evaluate((el) => getComputedStyle(el).borderTopWidth))
      .toBe("1px");
  });

  test("[LOG-054] the error-code table sorts and opens the lookup", async ({ page }) => {
    const spans: EntrySpec[] = [
      {
        message: "Install failed with 0x80070643",
        severity: "Error",
        errorCodeSpans: [
          {
            start: 19,
            end: 29,
            codeHex: "0x80070643",
            codeDecimal: "-2147023293",
            description: "Fatal error during installation.",
            category: "Windows",
            outcome: "failure",
          },
        ],
      },
      {
        message: "Retry failed with 0x80070643",
        severity: "Error",
        errorCodeSpans: [
          {
            start: 17,
            end: 27,
            codeHex: "0x80070643",
            codeDecimal: "-2147023293",
            description: "Fatal error during installation.",
            category: "Windows",
            outcome: "failure",
          },
        ],
      },
      {
        message: "Detection failed with 0x87D00269",
        severity: "Error",
        errorCodeSpans: [
          {
            start: 21,
            end: 31,
            codeHex: "0x87D00269",
            codeDecimal: "-2016410007",
            description: "",
            category: "ConfigMgr",
            outcome: "failure",
          },
        ],
      },
    ];
    await bootWithLog(page, DEMO_LOG_ABS_PATH, spans);
    await settleLogLoad(page, spans.length);

    await page.getByRole("button", { name: /Quick Stats/ }).click();
    await expect(page.getByText("Error Codes (2)")).toBeVisible();

    for (const column of ["Code", "Description", "Category", "Count"]) {
      await expect(page.getByRole("button", { name: `Sort by ${column}` })).toBeVisible();
    }

    const codes = () =>
      page
        .locator('tr[title="Click to look up this error code"] td:first-child')
        .allTextContents();
    // Default: Count descending — 0x80070643 has two occurrences.
    expect(await codes()).toEqual(["0x80070643", "0x87D00269"]);
    await page.getByRole("button", { name: "Sort by Count" }).click();
    expect(await codes()).toEqual(["0x87D00269", "0x80070643"]);
    await page.getByRole("button", { name: "Sort by Code" }).click();
    expect(await codes()).toEqual(["0x80070643", "0x87D00269"]);

    // An empty description renders "Unknown", and the range line is present
    // because every entry carries a timestamp.
    await expect(page.locator('tr[title="Click to look up this error code"]').last()).toContainText(
      "Unknown",
    );
    await expect(page.getByText(/^Time Range: /)).toBeVisible();

    await page.evaluate(() => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["search_error_codes"] = () => [];
    });
    await page.locator('tr[title="Click to look up this error code"]').first().click();

    const lookup = page.getByRole("dialog");
    await expect(lookup).toBeVisible();
    await expect(
      lookup.getByPlaceholder("Search by code (0x80070005) or description (access denied)"),
    ).toHaveValue("0x80070643");
  });
});

// ---------------------------------------------------------------------------
// Merge and diff
// ---------------------------------------------------------------------------

const MERGE_FILE_A = "C:\\Logs\\Merge\\alpha.log";
const MERGE_FILE_B = "C:\\Logs\\Merge\\beta.log";

test.describe("log: merge and diff", () => {
  test("[LOG-058] createMergedTab builds a colour-assigned aggregate", async ({ page }) => {
    await bootApp(page);

    const result = await page.evaluate(
      async ({ logPath, fileA, fileB, missing }) => {
        const { useLogStore, setCachedTabSnapshot } = await import(
          /* @vite-ignore */ logPath
        );
        const store = useLogStore;
        const pk = {
          parser: "ccm",
          implementation: "ccm",
          provenance: "dedicated",
          parseQuality: "structured",
          recordFraming: "logicalRecord",
          dateOrder: "monthFirst",
        };
        const entry = (filePath: string, id: number, line: number, ts: number | null, msg: string) => ({
          id,
          lineNumber: line,
          message: msg,
          component: "AppEnforce",
          timestamp: ts,
          timestampDisplay: ts === null ? null : String(ts),
          severity: "Info",
          thread: 1,
          threadDisplay: "1",
          sourceFile: "appexcnlib.cpp",
          format: "Ccm",
          filePath,
          timezoneOffset: 0,
        });
        const cache = (filePath: string, entries: ReturnType<typeof entry>[]) =>
          setCachedTabSnapshot(filePath, {
            entries,
            formatDetected: "Ccm",
            parserSelection: pk,
            totalLines: entries.length,
            byteOffset: 0,
            selectedSourceFilePath: filePath,
            sourceOpenMode: "single-file",
            activeColumns: ["severity", "dateTime", "message", "component"],
          });

        // A: ts 300 (line 2), ts 100 (line 1), and one null timestamp.
        cache(fileA, [
          entry(fileA, 0, 2, 300, "A-late"),
          entry(fileA, 1, 1, 100, "A-early"),
          entry(fileA, 2, 3, null, "A-untimed"),
        ]);
        cache(fileB, [entry(fileB, 0, 1, 200, "B-middle")]);

        store.getState().createMergedTab([missing, fileA]);
        const fewerThanTwo = store.getState().mergedTabState;

        store.getState().selectEntry(0);
        store.getState().createMergedTab([fileA, fileB]);
        const merged = store.getState();

        store.getState().setFileVisibility(fileB, false);
        const afterHidingB = (store.getState().entries as { message: string }[]).map(
          (e) => e.message,
        );

        return {
          fewerThanTwo,
          sourceOpenMode: merged.sourceOpenMode,
          ids: (merged.entries as { id: number }[]).map((e) => e.id),
          messages: (merged.entries as { message: string }[]).map((e) => e.message),
          colorKeys: merged.mergedTabState?.colorAssignments
            ? Object.keys(merged.mergedTabState.colorAssignments)
            : null,
          fileVisibility: merged.mergedTabState?.fileVisibility ?? null,
          selectedId: merged.selectedId,
          correlated: merged.correlatedEntries.length,
          afterHidingB,
        };
      },
      {
        logPath: await appModule(page, LOG_STORE),
        fileA: MERGE_FILE_A,
        fileB: MERGE_FILE_B,
        missing: "C:\\Logs\\Merge\\ghost.log",
      },
    );

    expect(result.fewerThanTwo).toBeNull();
    expect(result.sourceOpenMode).toBe("merged");
    // Timestamp order, nulls last, ids renumbered from 0.
    expect(result.messages).toEqual(["A-early", "B-middle", "A-late", "A-untimed"]);
    expect(result.ids).toEqual([0, 1, 2, 3]);
    expect(result.colorKeys).toEqual([MERGE_FILE_A, MERGE_FILE_B]);
    expect(result.fileVisibility).toEqual({ [MERGE_FILE_A]: true, [MERGE_FILE_B]: true });
    expect(result.selectedId).toBeNull();
    expect(result.correlated).toBe(0);
    expect(result.afterHidingB).toEqual(["A-early", "A-late", "A-untimed"]);
  });

  test("[LOG-058] the sidebar merges the loaded folder's cached files and clears the filter", async ({
    page,
  }) => {
    await bootApp(page);
    await seedEverywhere(page, LOG_STORE, "useLogStore", {
      activeSource: { kind: "folder", path: "C:\\Logs\\Merge" },
      sourceEntries: [
        { name: "alpha.log", path: MERGE_FILE_A, isDir: false, sizeBytes: 10, modifiedUnixMs: 0 },
        { name: "beta.log", path: MERGE_FILE_B, isDir: false, sizeBytes: 10, modifiedUnixMs: 0 },
      ],
      sourceOpenMode: "aggregate-folder",
    });

    await page.evaluate(
      async ({ logPath, fileA, fileB, filterPath }) => {
        const { setCachedTabSnapshot } = await import(/* @vite-ignore */ logPath);
        const { useFilterStore } = await import(/* @vite-ignore */ filterPath);
        const pk = {
          parser: "ccm",
          implementation: "ccm",
          provenance: "dedicated",
          parseQuality: "structured",
          recordFraming: "logicalRecord",
          dateOrder: "monthFirst",
        };
        const entry = (filePath: string, ts: number, msg: string) => ({
          id: 0,
          lineNumber: 1,
          message: msg,
          component: "AppEnforce",
          timestamp: ts,
          timestampDisplay: String(ts),
          severity: "Info",
          thread: 1,
          threadDisplay: "1",
          sourceFile: "appexcnlib.cpp",
          format: "Ccm",
          filePath,
          timezoneOffset: 0,
        });
        setCachedTabSnapshot(fileA, {
          entries: [entry(fileA, 100, "A-line")],
          formatDetected: "Ccm",
          parserSelection: pk,
          totalLines: 1,
          byteOffset: 0,
          selectedSourceFilePath: fileA,
          sourceOpenMode: "single-file",
          activeColumns: ["severity", "dateTime", "message", "component"],
        });
        setCachedTabSnapshot(fileB, {
          entries: [entry(fileB, 200, "B-line")],
          formatDetected: "Ccm",
          parserSelection: pk,
          totalLines: 1,
          byteOffset: 0,
          selectedSourceFilePath: fileB,
          sourceOpenMode: "single-file",
          activeColumns: ["severity", "dateTime", "message", "component"],
        });
        useFilterStore.getState().addQuickFilter("Message", "A-line", "Contains");
      },
      { logPath: await appModule(page, LOG_STORE), fileA: MERGE_FILE_A, fileB: MERGE_FILE_B, filterPath: await appModule(page, FILTER_STORE) },
    );

    const mergeButton = page.getByRole("button", { name: "Merge loaded files" });
    await expect(mergeButton).toBeVisible();
    await expect(mergeButton).toHaveText("Merge into Timeline");
    await mergeButton.click();

    const state = await readStore<{ mode: string | null; messages: string[] }>(
      page,
      LOG_STORE,
      "useLogStore",
      "({ mode: state.sourceOpenMode, messages: state.entries.map((e) => e.message) })",
    );
    expect(state.mode).toBe("merged");
    expect(state.messages).toEqual(["A-line", "B-line"]);
  });

  test("[LOG-058] the sidebar merge clears the active filter first", async ({ page }) => {
    await bootApp(page);
    await seedEverywhere(page, LOG_STORE, "useLogStore", {
      activeSource: { kind: "folder", path: "C:\\Logs\\Merge" },
      sourceEntries: [
        { name: "alpha.log", path: MERGE_FILE_A, isDir: false, sizeBytes: 10, modifiedUnixMs: 0 },
        { name: "beta.log", path: MERGE_FILE_B, isDir: false, sizeBytes: 10, modifiedUnixMs: 0 },
      ],
      sourceOpenMode: "aggregate-folder",
    });
    await page.evaluate(
      async ({ logPath, fileA, fileB, filterPath }) => {
        const { setCachedTabSnapshot } = await import(/* @vite-ignore */ logPath);
        const { useFilterStore } = await import(/* @vite-ignore */ filterPath);
        const entry = (filePath: string, ts: number, msg: string) => ({
          id: 0,
          lineNumber: 1,
          message: msg,
          component: "AppEnforce",
          timestamp: ts,
          timestampDisplay: String(ts),
          severity: "Info",
          thread: 1,
          threadDisplay: "1",
          sourceFile: "appexcnlib.cpp",
          format: "Ccm",
          filePath,
          timezoneOffset: 0,
        });
        const snapshot = (filePath: string, msg: string, ts: number) => ({
          entries: [entry(filePath, ts, msg)],
          formatDetected: "Ccm" as const,
          parserSelection: {
            parser: "ccm" as const,
            implementation: "ccm" as const,
            provenance: "dedicated" as const,
            parseQuality: "structured" as const,
            recordFraming: "logicalRecord" as const,
            dateOrder: "monthFirst" as const,
          },
          totalLines: 1,
          byteOffset: 0,
          selectedSourceFilePath: filePath,
          sourceOpenMode: "single-file" as const,
          activeColumns: ["severity", "dateTime", "message", "component"],
        });
        setCachedTabSnapshot(fileA, snapshot(fileA, "A-line", 100));
        setCachedTabSnapshot(fileB, snapshot(fileB, "B-line", 200));
        useFilterStore.getState().addQuickFilter("Message", "A-line", "Contains");
      },
      { logPath: await appModule(page, LOG_STORE), fileA: MERGE_FILE_A, fileB: MERGE_FILE_B, filterPath: await appModule(page, FILTER_STORE) },
    );

    await page.getByRole("button", { name: "Merge loaded files" }).click();
    await expect
      .poll(() =>
        readStore<string | null>(page, LOG_STORE, "useLogStore", "state.sourceOpenMode"),
      )
      .toBe("merged");
    expect(
      await readStore<unknown[]>(page, FILTER_STORE, "useFilterStore", "state.clauses"),
    ).toEqual([]);
  });

  const DIFF_FILE_A = "C:\\Logs\\Diff\\alpha.log";
  const DIFF_FILE_B = "C:\\Logs\\Diff\\beta.log";

  test("[LOG-061] createDiff classifies common and unique lines", async ({ page }) => {
    await bootApp(page);

    const result = await page.evaluate(
      async ({ logPath, fileA, fileB, missing }) => {
        const { useLogStore, setCachedTabSnapshot } = await import(
          /* @vite-ignore */ logPath
        );
        const store = useLogStore;
        const pk = {
          parser: "ccm",
          implementation: "ccm",
          provenance: "dedicated",
          parseQuality: "structured",
          recordFraming: "logicalRecord",
          dateOrder: "monthFirst",
        };
        const entry = (filePath: string, id: number, line: number, ts: number, msg: string, sev = "Info") => ({
          id,
          lineNumber: line,
          message: msg,
          component: "AppEnforce",
          timestamp: ts,
          timestampDisplay: String(ts),
          severity: sev,
          thread: 1,
          threadDisplay: "1",
          sourceFile: "appexcnlib.cpp",
          format: "Ccm",
          filePath,
          timezoneOffset: 0,
        });
        const cache = (filePath: string, entries: ReturnType<typeof entry>[]) =>
          setCachedTabSnapshot(filePath, {
            entries,
            formatDetected: "Ccm",
            parserSelection: pk,
            totalLines: entries.length,
            byteOffset: 0,
            selectedSourceFilePath: filePath,
            sourceOpenMode: "single-file",
            activeColumns: ["severity", "dateTime", "message", "component"],
          });

        // Same normalized pattern in both files -> common; one each -> only A / only B.
        cache(fileA, [
          entry(fileA, 0, 1, 1000, "Detection started for 4f2b1a90-1111-4a2b-9c3d-aaaaaaaaaaaa"),
          entry(fileA, 1, 2, 2000, "Only in A"),
          entry(fileA, 2, 3, 9000, "Late A line"),
        ]);
        cache(fileB, [
          entry(fileB, 0, 1, 1100, "Detection started for 7a1c2b90-2222-4b3c-8d4e-bbbbbbbbbbbb"),
          entry(fileB, 1, 2, 2100, "Only in B"),
        ]);

        store.getState().selectEntry(0);
        store.getState().createDiff(
          { filePath: fileA, label: "alpha" },
          { filePath: fileB, label: "beta" },
        );
        const twoFile = store.getState();
        const classification = twoFile.diffState
          ? Object.fromEntries(twoFile.diffState.entryClassification)
          : null;

        // Same file on both sides is the only route to time-range mode.
        store.getState().createDiff(
          { filePath: fileA, label: "alpha", startTime: 1500, endTime: 3000 },
          { filePath: fileA, label: "alpha", startTime: 8000, endTime: 9500 },
        );
        const timeRange = store.getState().diffState;

        store.getState().closeDiff();
        store.getState().createDiff(
          { filePath: missing, label: "ghost" },
          { filePath: fileB, label: "beta" },
        );

        return {
          twoFile: {
            mode: twoFile.diffState?.mode,
            displayMode: twoFile.diffState?.displayMode,
            stats: twoFile.diffState?.stats,
            idsA: (twoFile.diffState?.entriesA as { id: number }[] | undefined)?.map((e) => e.id),
            idsB: (twoFile.diffState?.entriesB as { id: number }[] | undefined)?.map((e) => e.id),
            classification,
            sourceOpenMode: twoFile.sourceOpenMode,
            selectedId: twoFile.selectedId,
          },
          timeRange: {
            mode: timeRange?.mode,
            messagesA: (timeRange?.entriesA as { message: string }[] | undefined)?.map(
              (e) => e.message,
            ),
            messagesB: (timeRange?.entriesB as { message: string }[] | undefined)?.map(
              (e) => e.message,
            ),
            idsA: (timeRange?.entriesA as { id: number }[] | undefined)?.map((e) => e.id),
            idsB: (timeRange?.entriesB as { id: number }[] | undefined)?.map((e) => e.id),
          },
          afterMissing: store.getState().diffState,
        };
      },
      {
        logPath: await appModule(page, LOG_STORE),
        fileA: DIFF_FILE_A,
        fileB: DIFF_FILE_B,
        missing: "C:\\Logs\\Diff\\ghost.log",
      },
    );

    expect(result.twoFile.mode).toBe("two-file");
    expect(result.twoFile.displayMode).toBe("side-by-side");
    expect(result.twoFile.sourceOpenMode).toBe("diff");
    expect(result.twoFile.selectedId).toBeNull();
    expect(result.twoFile.stats).toEqual({ common: 1, onlyA: 2, onlyB: 1 });
    // Ids are renumbered uniquely across both sets.
    expect(result.twoFile.idsA).toEqual([0, 1, 2]);
    expect(result.twoFile.idsB).toEqual([3, 4]);
    expect(result.twoFile.classification).toEqual({
      0: "common",
      1: "only-a",
      2: "only-a",
      3: "common",
      4: "only-b",
    });

    expect(result.timeRange.mode).toBe("time-range");
    expect(result.timeRange.messagesA).toEqual(["Only in A"]);
    expect(result.timeRange.messagesB).toEqual(["Late A line"]);
    expect(result.timeRange.idsA).toEqual([0]);
    expect(result.timeRange.idsB).toEqual([1]);

    // Either snapshot missing -> no diff is built.
    expect(result.afterMissing).toBeNull();
  });

  test("[LOG-063] diff panes render A/B with unique-line highlight and synced scroll", async ({
    page,
  }) => {
    // The unique lines sit inside the first rendered window; the common lines
    // after them give both panes enough height to scroll.
    const specsA: EntrySpec[] = [
      { message: "COMMON-0", timestamp: BASE_EPOCH_MS },
      { message: "ONLY-A-MARKER", timestamp: BASE_EPOCH_MS + 500, lineNumber: 2 },
    ];
    const specsB: EntrySpec[] = [
      { message: "COMMON-0", timestamp: BASE_EPOCH_MS },
      { message: "ONLY-B-MARKER", timestamp: BASE_EPOCH_MS + 500, lineNumber: 2 },
    ];
    for (let index = 1; index <= 60; index += 1) {
      const timestamp = BASE_EPOCH_MS + index * 1000;
      specsA.push({ message: `COMMON-${index}`, timestamp, lineNumber: index + 2 });
      specsB.push({ message: `COMMON-${index}`, timestamp, lineNumber: index + 2 });
    }

    await bootApp(page);
    await page.evaluate(
      async ({ logPath, fileA, fileB, entriesA, entriesB, pk }) => {
        const { useLogStore, setCachedTabSnapshot } = await import(
          /* @vite-ignore */ logPath
        );
        setCachedTabSnapshot(fileA, {
          entries: entriesA,
          formatDetected: "Ccm",
          parserSelection: pk,
          totalLines: entriesA.length,
          byteOffset: 0,
          selectedSourceFilePath: fileA,
          sourceOpenMode: "single-file",
          activeColumns: ["severity", "dateTime", "message", "component"],
        });
        setCachedTabSnapshot(fileB, {
          entries: entriesB,
          formatDetected: "Ccm",
          parserSelection: pk,
          totalLines: entriesB.length,
          byteOffset: 0,
          selectedSourceFilePath: fileB,
          sourceOpenMode: "single-file",
          activeColumns: ["severity", "dateTime", "message", "component"],
        });
        useLogStore.getState().createDiff(
          { filePath: fileA, label: "alpha" },
          { filePath: fileB, label: "beta" },
        );
      },
      {
        logPath: await appModule(page, LOG_STORE),
        fileA: DIFF_FILE_A,
        fileB: DIFF_FILE_B,
        entriesA: buildEntries(DIFF_FILE_A, specsA),
        entriesB: buildEntries(DIFF_FILE_B, specsB),
        pk: {
          parser: "ccm",
          implementation: "ccm",
          provenance: "dedicated",
          parseQuality: "structured",
          recordFraming: "logicalRecord",
          dateOrder: "monthFirst",
        },
      },
    );

    const headerA = page.getByText(`A: alpha.log (${specsA.length})`, { exact: true });
    const headerB = page.getByText(`B: beta.log (${specsB.length})`, { exact: true });
    await expect(headerA).toBeVisible({ timeout: 15_000 });
    await expect(headerB).toBeVisible();
    await expect(page.getByText("61 common", { exact: true })).toBeVisible();
    await expect(page.getByText("1 only A", { exact: true })).toBeVisible();
    await expect(page.getByText("1 only B", { exact: true })).toBeVisible();

    const paneA = headerA.locator("xpath=following-sibling::div[1]");
    const paneB = headerB.locator("xpath=following-sibling::div[1]");

    /** Innermost row element carrying `text` — the DiffRow, not its ancestors. */
    const rowStyleIn = (pane: typeof paneB, text: string) =>
      pane.evaluate((element, needle) => {
        const candidates = Array.from(element.querySelectorAll("div")).filter((candidate) =>
          (candidate.textContent ?? "").includes(needle),
        );
        const row = candidates[candidates.length - 1];
        if (!row) return null;
        const style = getComputedStyle(row);
        return {
          borderWidth: style.borderLeftWidth,
          border: style.borderLeftColor,
          background: style.backgroundColor,
        };
      }, text);

    const onlyB = await rowStyleIn(paneB, "ONLY-B-MARKER");
    const commonB = await rowStyleIn(paneB, "COMMON-12");
    expect(onlyB).not.toBeNull();
    expect(commonB).not.toBeNull();
    // Only-B lines are red-tinted with a red left border; common lines are not.
    expect(onlyB!.borderWidth).toBe("3px");
    const onlyBRgb = parseRgb(onlyB!.border);
    expect(onlyBRgb.r).toBeGreaterThan(onlyBRgb.g);
    expect(onlyBRgb.r).toBeGreaterThan(onlyBRgb.b);
    expect(onlyB!.background).not.toBe(commonB!.background);
    expect(commonB!.background).toBe("rgba(0, 0, 0, 0)");

    const onlyA = await rowStyleIn(paneA, "ONLY-A-MARKER");
    expect(onlyA).not.toBeNull();
    expect(onlyA!.borderWidth).toBe("3px");
    const onlyARgb = parseRgb(onlyA!.border);
    expect(onlyARgb.g).toBeGreaterThan(onlyARgb.r);
    expect(onlyARgb.g).toBeGreaterThan(onlyARgb.b);

    // Clicking a row selects it; clicking the selected row deselects it.
    const rowB = page.getByText("ONLY-B-MARKER", { exact: true });
    await rowB.click();
    await expect
      .poll(() => readStore<number | null>(page, LOG_STORE, "useLogStore", "state.selectedId"))
      .not.toBeNull();
    await rowB.click();
    await expect
      .poll(() => readStore<number | null>(page, LOG_STORE, "useLogStore", "state.selectedId"))
      .toBeNull();

    // Scrolling one pane mirrors into the other.
    await paneA.evaluate((pane) => {
      pane.scrollTop = 240;
      pane.dispatchEvent(new Event("scroll"));
    });
    await expect.poll(async () => paneB.evaluate((pane) => pane.scrollTop)).toBe(240);
    // The mirroring guard clears on the next animation frame.
    await page.waitForTimeout(100);
    await paneB.evaluate((pane) => {
      pane.scrollTop = 100;
      pane.dispatchEvent(new Event("scroll"));
    });
    await expect.poll(async () => paneA.evaluate((pane) => pane.scrollTop)).toBe(100);

    // Unified mode merges both sets and badges each row with its source.
    await page.getByRole("button", { name: "Unified", exact: true }).click();
    await expect(page.getByText("ONLY-A-MARKER")).toBeVisible();
    await expect(page.getByText("ONLY-B-MARKER")).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Sources: aggregate loads, known sources, failure status
// ---------------------------------------------------------------------------

const AGG_FILE_A = "C:\\Logs\\Aggregate\\alpha.log";
const AGG_FILE_B = "C:\\Logs\\Aggregate\\beta.log";
const AGG_SPECS_A: EntrySpec[] = [
  { message: "alpha one", lineNumber: 1 },
  { message: "alpha two", lineNumber: 2 },
];
const AGG_SPECS_B: EntrySpec[] = [
  { message: "beta one", lineNumber: 1 },
  { message: "beta two", lineNumber: 2 },
  { message: "beta three", lineNumber: 3 },
];

test.describe("log: sources", () => {
  test("[LOG-072] several files at once become one aggregate stream", async ({ page }) => {
    await bootApp(page, {
      overrides: {
        get_initial_file_paths: [AGG_FILE_A, AGG_FILE_B],
        parse_files_batch: [buildResult(AGG_FILE_A, AGG_SPECS_A), buildResult(AGG_FILE_B, AGG_SPECS_B)],
        inspect_path_kind: "file",
      },
    });

    await expect(page.getByText("Loaded 2 files.", { exact: true }).first()).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByText(/^Parsed in \d+ ms \(parallel\)\.$/)).toBeVisible();

    const state = await readStore<{
      mode: string | null;
      sourcePath: string | null;
      files: string[];
      ids: number[];
      messages: string[];
      statusKind: string;
    }>(
      page,
      LOG_STORE,
      "useLogStore",
      `({
        mode: state.sourceOpenMode,
        sourcePath: state.activeSource ? state.activeSource.path : null,
        files: state.aggregateFiles.map((f) => f.filePath),
        ids: state.entries.map((e) => e.id),
        messages: state.entries.map((e) => e.message),
        statusKind: state.sourceStatus.kind,
      })`,
    );

    expect(state.mode).toBe("aggregate-folder");
    expect(state.statusKind).toBe("loaded");
    // Longest common parent directory becomes the source.
    expect(state.sourcePath).toBe("C:/Logs/Aggregate");
    expect(state.files).toEqual([AGG_FILE_A, AGG_FILE_B]);
    expect(state.ids).toEqual([0, 1, 2, 3, 4]);
    expect(state.messages).toEqual(["alpha one", "alpha two", "beta one", "beta two", "beta three"]);

    // A single path keeps the ordinary single-file lane.
    const single = await page.evaluate(
      async ({ logSourcePath, logStorePath, singlePath, resultData }) => {
        const w = window as unknown as {
          __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
        };
        w.__e2e_ipc_overrides__["inspect_path_kind"] = () => "file";
        w.__e2e_ipc_overrides__["open_log_file"] = () => resultData;
        const { loadFilesAsLogSource } = await import(/* @vite-ignore */ logSourcePath);
        await loadFilesAsLogSource([singlePath]);
        const { useLogStore } = await import(/* @vite-ignore */ logStorePath);
        const state = useLogStore.getState();
        return {
          mode: state.sourceOpenMode,
          sourceKind: state.activeSource ? state.activeSource.kind : null,
          aggregateFiles: state.aggregateFiles.length,
        };
      },
      {
        logSourcePath: await appModule(page, LOG_SOURCE),
        logStorePath: await appModule(page, LOG_STORE),
        singlePath: "C:\\Logs\\Aggregate\\solo.log",
        resultData: buildResult("C:\\Logs\\Aggregate\\solo.log", [{ message: "solo line" }]),
      },
    );
    expect(single.mode).toBe("single-file");
    expect(single.sourceKind).toBe("file");
    expect(single.aggregateFiles).toBe(0);
  });

  const CATALOG_FOLDER = "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs";

  test("[LOG-086] known sources are grouped, and Open all expands a family", async ({ page }) => {
    const catalog = [
      {
        id: "ime-logs",
        label: "Intune Management Extension",
        description: "IME logs",
        platform: "windows",
        sourceKind: "folder",
        source: {
          kind: "known",
          sourceId: "ime-logs",
          defaultPath: CATALOG_FOLDER,
          pathKind: "folder",
        },
        filePatterns: ["*.log"],
        grouping: {
          familyId: "intune",
          familyLabel: "Intune",
          groupId: "ime",
          groupLabel: "IME Logs",
          groupOrder: 2,
          sourceOrder: 1,
        },
      },
      {
        id: "ime-agent",
        label: "Agent Executor",
        description: "AgentExecutor.log",
        platform: "windows",
        sourceKind: "folder",
        source: {
          kind: "known",
          sourceId: "ime-agent",
          defaultPath: CATALOG_FOLDER,
          pathKind: "folder",
        },
        filePatterns: ["AgentExecutor.log"],
        grouping: {
          familyId: "intune",
          familyLabel: "Intune",
          groupId: "ime",
          groupLabel: "IME Logs",
          groupOrder: 2,
          sourceOrder: 2,
        },
      },
      {
        id: "ccm-logs",
        label: "ConfigMgr Client",
        description: "CCM logs",
        platform: "windows",
        sourceKind: "folder",
        source: {
          kind: "known",
          sourceId: "ccm-logs",
          defaultPath: "C:\\Windows\\CCM\\Logs",
          pathKind: "folder",
        },
        filePatterns: [],
        grouping: {
          familyId: "sccm",
          familyLabel: "ConfigMgr",
          groupId: "client",
          groupLabel: "Client logs",
          groupOrder: 1,
          sourceOrder: 1,
        },
      },
      {
        id: "ungrouped-source",
        label: "Zeta source",
        description: "no grouping metadata",
        platform: "windows",
        sourceKind: "file",
        source: {
          kind: "known",
          sourceId: "ungrouped-source",
          defaultPath: "C:\\Logs\\zeta.log",
          pathKind: "file",
        },
        filePatterns: [],
      },
    ];

    await bootApp(page, {
      overrides: {
        get_known_log_sources: catalog,
        list_log_folder: {
          sourceKind: "folder",
          source: { kind: "folder", path: CATALOG_FOLDER },
          entries: [
            {
              name: "IntuneManagementExtension.log",
              path: `${CATALOG_FOLDER}\\IntuneManagementExtension.log`,
              isDir: false,
              sizeBytes: 100,
              modifiedUnixMs: 0,
            },
            {
              name: "AgentExecutor.log",
              path: `${CATALOG_FOLDER}\\AgentExecutor.log`,
              isDir: false,
              sizeBytes: 100,
              modifiedUnixMs: 0,
            },
            {
              name: "notes.txt",
              path: `${CATALOG_FOLDER}\\notes.txt`,
              isDir: false,
              sizeBytes: 100,
              modifiedUnixMs: 0,
            },
            {
              name: "Archive",
              path: `${CATALOG_FOLDER}\\Archive`,
              isDir: true,
              sizeBytes: null,
              modifiedUnixMs: null,
            },
          ],
        },
        parse_files_batch: [
          buildResult(`${CATALOG_FOLDER}\\IntuneManagementExtension.log`, [{ message: "ime line" }]),
          buildResult(`${CATALOG_FOLDER}\\AgentExecutor.log`, [{ message: "agent line" }]),
        ],
      },
    });

    await expect
      .poll(() =>
        readStore<unknown[]>(
          page,
          LOG_STORE,
          "useLogStore",
          "state.knownSourceToolbarFamilies",
        ),
      )
      .not.toHaveLength(0);

    const tree = await readStore<
      { id: string; label: string; groups: { label: string; sources: string[] }[] }[]
    >(
      page,
      LOG_STORE,
      "useLogStore",
      "state.knownSourceToolbarFamilies.map((f) => ({ id: f.id, label: f.label, groups: f.groups.map((g) => ({ label: g.label, sources: g.sources.map((s) => s.id) })) }))",
    );
    // Families sort by groupOrder (ConfigMgr first), then the ungrouped family.
    expect(tree.map((family) => family.id)).toEqual(["sccm", "intune", "ungrouped"]);
    expect(tree[2].label).toBe("Other Sources");
    // Sources within a group sort by sourceOrder.
    expect(tree[1].groups[0].sources).toEqual(["ime-logs", "ime-agent"]);

    // The family menu offers "Open all <family label>".
    await page.getByRole("button", { name: "Open known log source..." }).click();
    await page.getByRole("menuitem", { name: "Intune", exact: true }).click();
    await page.getByRole("menuitem", { name: "Open all Intune", exact: true }).click();

    await expect(page.getByText("Loaded 2 files.", { exact: true }).first()).toBeVisible({
      timeout: 15_000,
    });
    const loaded = await readStore<{ files: string[]; messages: string[] }>(
      page,
      LOG_STORE,
      "useLogStore",
      "({ files: state.aggregateFiles.map((f) => f.filePath), messages: state.entries.map((e) => e.message) })",
    );
    // Only pattern-matching files, and the unavailable file source is skipped.
    expect(loaded.files).toEqual([
      `${CATALOG_FOLDER}\\IntuneManagementExtension.log`,
      `${CATALOG_FOLDER}\\AgentExecutor.log`,
    ]);
    expect(loaded.messages).toEqual(["ime line", "agent line"]);
  });

  test("[LOG-087] unknown known-sources fail loudly", async ({ page }) => {
    await bootApp(page, { overrides: { get_known_log_sources: [] } });

    const result = await page.evaluate(
      async ({ logSourcePath }) => {
        const { resolveKnownSourceIdFromCatalogAction, loadLogSource } = await import(
          /* @vite-ignore */ logSourcePath
        );
        const explicit = resolveKnownSourceIdFromCatalogAction({ sourceId: "  ime-logs  " });
        const fromPreset = resolveKnownSourceIdFromCatalogAction({
          presetMenuId: "preset.windows.ime",
        });
        const unresolved = resolveKnownSourceIdFromCatalogAction({ menuId: "nope" });

        let notFound = "";
        try {
          await loadLogSource({
            kind: "known",
            sourceId: "does-not-exist",
            defaultPath: "C:\\Logs\\missing.log",
            pathKind: "file",
          });
        } catch (error) {
          notFound = error instanceof Error ? error.message : String(error);
        }
        return { explicit, fromPreset, unresolved, notFound };
      },
      { logSourcePath: await appModule(page, LOG_SOURCE) },
    );

    expect(result.explicit).toBe("ime-logs");
    expect(result.fromPreset).toBe("windows-intune-ime-logs");
    expect(result.unresolved).toBeNull();
    expect(result.notFound).toBe("Known source 'does-not-exist' was not found.");
  });

  test("[LOG-088] folder known sources open whole with no preferred-file selection", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: {
        get_known_log_sources: [
          {
            id: "ime-folder",
            label: "IME logs",
            description: "whole folder",
            platform: "windows",
            sourceKind: "folder",
            source: {
              kind: "known",
              sourceId: "ime-folder",
              defaultPath: CATALOG_FOLDER,
              pathKind: "folder",
            },
            filePatterns: ["*.log"],
            defaultFileIntent: {
              selectionBehavior: "preferFileNameThenPattern",
              preferredFileNames: ["IntuneManagementExtension.log"],
            },
          },
        ],
        list_log_folder: {
          sourceKind: "folder",
          source: { kind: "folder", path: CATALOG_FOLDER },
          entries: [
            {
              name: "AgentExecutor.log",
              path: `${CATALOG_FOLDER}\\AgentExecutor.log`,
              isDir: false,
              sizeBytes: 100,
              modifiedUnixMs: 0,
            },
            {
              name: "IntuneManagementExtension.log",
              path: `${CATALOG_FOLDER}\\IntuneManagementExtension.log`,
              isDir: false,
              sizeBytes: 100,
              modifiedUnixMs: 0,
            },
            {
              name: "AppWorkload.log",
              path: `${CATALOG_FOLDER}\\AppWorkload.log`,
              isDir: false,
              sizeBytes: 100,
              modifiedUnixMs: 0,
            },
          ],
        },
        parse_files_batch: [
          buildResult(`${CATALOG_FOLDER}\\AgentExecutor.log`, [{ message: "agent line" }]),
          buildResult(`${CATALOG_FOLDER}\\IntuneManagementExtension.log`, [{ message: "ime line" }]),
          buildResult(`${CATALOG_FOLDER}\\AppWorkload.log`, [{ message: "workload line" }]),
        ],
      },
    });

    await expect
      .poll(() =>
        readStore<unknown[]>(page, LOG_STORE, "useLogStore", "state.knownSources"),
      )
      .toHaveLength(1);
    expect(
      await readStore<{ behavior: string | null; preferred: string[] }[]>(
        page,
        LOG_STORE,
        "useLogStore",
        "state.knownSources.map((s) => ({ behavior: s.defaultFileIntent ? s.defaultFileIntent.selectionBehavior : null, preferred: s.defaultFileIntent ? s.defaultFileIntent.preferredFileNames : [] }))",
      ),
    ).toEqual([{ behavior: "preferFileNameThenPattern", preferred: ["IntuneManagementExtension.log"] }]);

    const loaded = await page.evaluate(
      async ({ logSourcePath, logStorePath, folder }) => {
        const { loadLogSource } = await import(/* @vite-ignore */ logSourcePath);
        await loadLogSource({
          kind: "known",
          sourceId: "ime-folder",
          defaultPath: folder,
          pathKind: "folder",
        });
        const { useLogStore } = await import(/* @vite-ignore */ logStorePath);
        const state = useLogStore.getState();
        return {
          messages: (state.entries as { message: string }[]).map((e) => e.message),
          selected: state.selectedSourceFilePath,
          mode: state.sourceOpenMode,
        };
      },
      { logSourcePath: await appModule(page, LOG_SOURCE), logStorePath: await appModule(page, LOG_STORE), folder: CATALOG_FOLDER },
    );

    // Every file is loaded; the preferred file name does not narrow anything.
    expect(loaded.messages).toEqual(["agent line", "ime line", "workload line"]);
    expect(loaded.selected).toBeNull();
  });

  test("[LOG-082] the sidebar distinguishes empty, missing and denied sources", async ({
    page,
  }) => {
    await bootApp(page, {
      overrides: { get_app_elevation_state: { platformSupported: true, isElevated: false } },
    });

    const loadFolder = async (path: string) =>
      page.evaluate(
        async ({ logSourcePath, folderPath }) => {
          const { loadLogSource } = await import(/* @vite-ignore */ logSourcePath);
          try {
            await loadLogSource({ kind: "folder", path: folderPath });
            return "resolved";
          } catch {
            return "rejected";
          }
        },
        { logSourcePath: await appModule(page, LOG_SOURCE), folderPath: path },
      );

    // Empty folder.
    await page.evaluate(() => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["list_log_folder"] = () => ({
        sourceKind: "folder",
        source: { kind: "folder", path: "C:\\Logs\\Empty" },
        entries: [],
      });
    });
    await loadFolder("C:\\Logs\\Empty");
    await expect(page.getByText("Source loaded, but no files were found.").first()).toBeVisible();
    expect(
      await readStore<string>(page, LOG_STORE, "useLogStore", "state.sourceStatus.kind"),
    ).toBe("empty");

    // Missing path — the backend's not-found wording classifies as "missing".
    await page.evaluate(() => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["list_log_folder"] = () => {
        throw { message: "The system cannot find the path specified. (os error 2)" };
      };
    });
    expect(await loadFolder("C:\\Logs\\Missing")).toBe("rejected");
    await expect(
      page.getByText("Source path is missing or inaccessible: C:\\Logs\\Missing").first(),
    ).toBeVisible();

    // Access refusal — a structured verdict, plus an elevation offer.
    await page.evaluate(() => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["list_log_folder"] = () => {
        throw {
          kind: "accessDenied",
          operation: "listFolder",
          path: "C:\\Logs\\Locked",
          message: "Access to the path 'C:\\Logs\\Locked' is denied.",
        };
      };
    });
    expect(await loadFolder("C:\\Logs\\Locked")).toBe("rejected");
    await expect(page.getByText("Access to this source was denied: C:\\Logs\\Locked").first()).toBeVisible();
    expect(
      await readStore<string>(page, LOG_STORE, "useLogStore", "state.sourceStatus.kind"),
    ).toBe("error");
    await expect
      .poll(() =>
        readStore<boolean>(
          page,
          UI_STORE,
          "useUiStore",
          "state.elevationPrompt !== null",
        ),
      )
      .toBe(true);

    // A selected file inside a loaded folder that will not load.
    await page.evaluate((folder) => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["list_log_folder"] = () => ({
        sourceKind: "folder",
        source: { kind: "folder", path: folder },
        entries: [
          {
            name: "locked.log",
            path: `${folder}\\locked.log`,
            isDir: false,
            sizeBytes: 10,
            modifiedUnixMs: 0,
          },
        ],
      });
      w.__e2e_ipc_overrides__["open_log_file"] = () => {
        throw {
          kind: "accessDenied",
          operation: "readFile",
          path: `${folder}\\locked.log`,
          message: "Access is denied.",
        };
      };
    }, "C:\\Logs\\Folder");
    const deniedFile = await page.evaluate(
      async ({ logSourcePath, logStorePath }) => {
        const { loadLogSource } = await import(/* @vite-ignore */ logSourcePath);
        await loadLogSource(
          { kind: "folder", path: "C:\\Logs\\Folder" },
          { selectedFilePath: "C:\\Logs\\Folder\\locked.log" },
        );
        const { useLogStore } = await import(/* @vite-ignore */ logStorePath);
        const state = useLogStore.getState();
        return { kind: state.sourceStatus.kind, message: state.sourceStatus.message };
      },
      { logSourcePath: await appModule(page, LOG_SOURCE), logStorePath: await appModule(page, LOG_STORE) },
    );
    expect(deniedFile).toEqual({
      kind: "awaiting-file-selection",
      message: "Access to this file was denied: locked.log.",
    });
    await expect(page.getByText("Access to this file was denied: locked.log.").first()).toBeVisible();

    // A file that vanished reports the missing-selection wording instead.
    await page.evaluate(() => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["open_log_file"] = () => {
        // A plain data object survives the command layer's rejection
        // normalization with its message intact; an Error instance does not.
        throw { message: "The system cannot find the file specified. (os error 2)" };
      };
    });
    const goneFile = await page.evaluate(
      async ({ logSourcePath, logStorePath }) => {
        const { loadLogSource } = await import(/* @vite-ignore */ logSourcePath);
        await loadLogSource(
          { kind: "folder", path: "C:\\Logs\\Folder" },
          { selectedFilePath: "C:\\Logs\\Folder\\locked.log" },
        );
        const { useLogStore } = await import(/* @vite-ignore */ logStorePath);
        return useLogStore.getState().sourceStatus.message;
      },
      { logSourcePath: await appModule(page, LOG_SOURCE), logStorePath: await appModule(page, LOG_STORE) },
    );
    expect(goneFile).toBe("Selected file is no longer available: locked.log.");
  });

  test("[LOG-082] the sidebar offers Retry for the last failed file selection", async ({
    page,
  }) => {
    await bootApp(page);
    await seedEverywhere(page, LOG_STORE, "useLogStore", {
      activeSource: { kind: "folder", path: "C:\\Logs\\Folder" },
      sourceEntries: [
        {
          name: "alpha.log",
          path: "C:\\Logs\\Folder\\alpha.log",
          isDir: false,
          sizeBytes: 10,
          modifiedUnixMs: 0,
        },
        {
          name: "locked.log",
          path: "C:\\Logs\\Folder\\locked.log",
          isDir: false,
          sizeBytes: 10,
          modifiedUnixMs: 0,
        },
      ],
    });

    await page.evaluate(() => {
      const w = window as unknown as {
        __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
      };
      w.__e2e_ipc_overrides__["open_log_file"] = () => {
        throw { message: "Could not read the selected file." };
      };
    });

    await page.getByRole("button", { name: "locked.log" }).click();
    await expect(page.getByRole("button", { name: "Retry locked.log" })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByText("Could not read the selected file.").first()).toBeVisible();
  });

  test("[LOG-069] an unsupported binary trace surfaces the conversion guidance", async ({
    page,
  }) => {
    await bootApp(page, { overrides: { get_known_log_sources: [] } });

    // The message is produced by the Rust parser (src-tauri/src/parser/mod.rs);
    // a browser run can only verify that a rejection reaches the user unchanged.
    const guidance =
      'ETL analytical logs are not yet supported. Convert to XML with: tracerpt "<file>" -of XML -o output.xml — then open the XML file.';

    await page.evaluate(
      ({ message }) => {
        const w = window as unknown as {
          __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
        };
        w.__e2e_ipc_overrides__["inspect_path_kind"] = () => "file";
        w.__e2e_ipc_overrides__["open_log_file"] = () => {
          throw { message };
        };
      },
      { message: guidance },
    );

    const outcome = await page.evaluate(
      async ({ logSourcePath, path }) => {
        const { loadPathAsLogSource } = await import(/* @vite-ignore */ logSourcePath);
        try {
          await loadPathAsLogSource(path, { fallbackToFolder: false });
          return "resolved";
        } catch {
          return "rejected";
        }
      },
      { logSourcePath: await appModule(page, LOG_SOURCE), path: "C:\\Logs\\capture.etl" },
    );

    expect(outcome).toBe("rejected");
    await expect(page.getByText(guidance).first()).toBeVisible();
    expect(
      await readStore<string>(page, LOG_STORE, "useLogStore", "state.sourceStatus.kind"),
    ).toBe("error");
  });
});

// ---------------------------------------------------------------------------
// Session save and text output
// ---------------------------------------------------------------------------

test.describe("log: session and output", () => {
  test("[LOG-078] saving a session fingerprints every open tab", async ({ page }) => {
    await bootApp(page, { overrides: { get_known_log_sources: [] } });

    const tabA = "C:\\Logs\\Session\\alpha.log";
    const tabB = "C:\\Logs\\Session\\beta.log";
    await seedEverywhere(page, UI_STORE, "useUiStore", {
      openTabs: [
        {
          id: "tab-a",
          filePath: tabA,
          fileName: "alpha.log",
          scrollPosition: 0,
          selectedLineId: null,
          sourceContext: null,
          fileKind: "log",
        },
        {
          id: "tab-b",
          filePath: tabB,
          fileName: "beta.log",
          scrollPosition: 0,
          selectedLineId: null,
          sourceContext: null,
          fileKind: "log",
        },
      ],
      activeTabIndex: 0,
    });

    const result = await page.evaluate(
      async ({ sessionPath, fileA }) => {
        const w = window as unknown as {
          __hashCalls?: string[];
          __written?: string;
          __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
        };
        w.__hashCalls = [];
        w.__e2e_ipc_overrides__["compute_file_hash"] = (args) => {
          const path = (args as { path?: string } | undefined)?.path ?? "";
          w.__hashCalls!.push(path);
          return {
            hash: path === fileA ? `sha256:${"a".repeat(64)}` : `sha256:${"b".repeat(64)}`,
            sizeBytes: path === fileA ? 11 : 22,
          };
        };
        w.__e2e_ipc_overrides__["plugin:dialog|save"] = () => "C:\\Temp\\session.cmtrace";
        // writeTextFile encodes the body and passes it as the raw argument.
        const capture = (args: unknown) => {
          w.__written = new TextDecoder().decode(args as Uint8Array);
          return null;
        };
        w.__e2e_ipc_overrides__["plugin:fs|write_text_file"] = capture;
        w.__e2e_ipc_overrides__["plugin:fs|write_file"] = capture;

        const { saveSession } = await import(/* @vite-ignore */ sessionPath);
        const saved = await saveSession();
        return { saved, hashCalls: w.__hashCalls, written: w.__written };
      },
      { sessionPath: await appModule(page, SESSION_SAVE), fileA: tabA },
    );

    expect(result.saved).toBe("C:\\Temp\\session.cmtrace");
    expect(result.hashCalls?.slice().sort()).toEqual([tabA, tabB].sort());
    expect(result.written).toBeTruthy();
    const session = JSON.parse(result.written!);
    expect(session.tabs).toEqual([
      {
        filePath: tabA,
        fileHash: `sha256:${"a".repeat(64)}`,
        fileSize: 11,
        selectedId: null,
        scrollPosition: null,
        activeColumns: [],
      },
      {
        filePath: tabB,
        fileHash: `sha256:${"b".repeat(64)}`,
        fileSize: 22,
        selectedId: null,
        scrollPosition: null,
        activeColumns: [],
      },
    ]);
    expect(session.tabs[0].fileHash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  test("[LOG-079] write_text_output_file forwards the chosen path and contents", async ({
    page,
  }) => {
    await bootApp(page, { overrides: { get_known_log_sources: [] } });

    const result = await page.evaluate(
      async ({ commandsPath }) => {
        const w = window as unknown as {
          __writeCalls?: { path: string; contents: string }[];
          __e2e_ipc_overrides__: Record<string, (args: unknown) => unknown>;
        };
        w.__writeCalls = [];
        w.__e2e_ipc_overrides__["write_text_output_file"] = (args) => {
          w.__writeCalls!.push(args as { path: string; contents: string });
          return null;
        };
        const { writeTextOutputFile } = await import(/* @vite-ignore */ commandsPath);
        await writeTextOutputFile("C:\\Exports\\dsregcmd.txt", "status text");
        const accepted = w.__writeCalls;

        // A response the command cannot interpret is rejected, not accepted.
        w.__e2e_ipc_overrides__["write_text_output_file"] = () => ({ written: true });
        let rejected = "";
        try {
          await writeTextOutputFile("C:\\Exports\\dsregcmd.txt", "again");
        } catch (error) {
          rejected = error instanceof Error ? error.message : String(error);
        }
        return { accepted, rejected };
      },
      { commandsPath: await appModule(page, COMMANDS) },
    );

    expect(result.accepted).toEqual([
      { path: "C:\\Exports\\dsregcmd.txt", contents: "status text" },
    ]);
    expect(result.rejected).not.toBe("");
  });
});

// ---------------------------------------------------------------------------
// Info pane
// ---------------------------------------------------------------------------

test.describe("log: info pane", () => {
  test("[LOG-083] the info pane summarises the parser that read the file", async ({ page }) => {
    await bootApp(page);
    const entries = buildEntries(DEMO_LOG_ABS_PATH, [
      {
        message: "Installing Contoso VPN Client",
        severity: "Error",
        component: "AppEnforce",
      },
    ]);
    await seedEverywhere(page, LOG_STORE, "useLogStore", {
      entries,
      totalLines: entries.length,
      parserSelection: {
        parser: "ccm",
        implementation: "ccm",
        provenance: "dedicated",
        parseQuality: "structured",
        recordFraming: "physicalLine",
        dateOrder: "monthFirst",
      },
    });
    // Nothing is printed without a selection.
    await expect(page.getByText(/^Parser /)).toHaveCount(0);

    await page.evaluate(
      async ({ logPath }) => {
        const { useLogStore } = await import(/* @vite-ignore */ logPath);
        useLogStore.getState().selectEntry(0);
      },
      { logPath: await appModule(page, LOG_STORE) },
    );

    await expect(
      page.getByText(
        "Parser CCM | Dedicated | Structured | CCM parser | Physical lines | Month-first dates",
        { exact: true },
      ),
    ).toBeVisible({ timeout: 15_000 });
    const summaryLine = await page.evaluate(() => {
      const node = Array.from(document.querySelectorAll("div")).find((candidate) =>
        (candidate.textContent ?? "").startsWith("Line 1 | Error"),
      );
      return node?.textContent ?? null;
    });
    // "Line <n> | <severity> | <component> | <timestamp>" — the timestamp is
    // rendered from the entry's epoch via the system preferences.
    expect(summaryLine).toMatch(
      /^Line 1 \| Error \| AppEnforce \| \d{1,2}\/\d{1,2}\/\d{2,4}[,\s]+\d{1,2}:\d{2}:\d{2}/,
    );
    await expect(
      page.getByText(`File ${DEMO_LOG_ABS_PATH}`, { exact: true }),
    ).toBeVisible();
    // No Result/GLE/Phase/Op line for an entry without those fields.
    await expect(page.getByText(/^Result /)).toHaveCount(0);
  });

  test("[LOG-096] the info pane decodes AppWorkload Get policies payloads", async ({ page }) => {
    await bootApp(page);
    const script = "# decoded-script-body\nGet-ItemProperty -Path 'HKLM:\\Software\\Contoso'";
    const encoded = Buffer.from(script, "utf8").toString("base64");
    // The sentinel becomes a bare single-backslash Windows path, which makes the
    // raw payload invalid JSON: the sanitizer has to double it before parsing.
    const payload = JSON.stringify([
      {
        Id: "policy-1",
        Name: "Contoso VPN Client",
        Intent: 3,
        TargetType: 2,
        InstallCommandLine: "msiexec /i ContosoVPN.msi /q",
        UninstallCommandLine: "msiexec /x __BS__ProgramData\\Contoso\\VPN.msi /q",
        ReturnCodes: JSON.stringify([
          { ReturnCode: 0, Type: 1 },
          { ReturnCode: 3010, Type: 3 },
        ]),
        DetectionRule: JSON.stringify([
          {
            DetectionType: 3,
            DetectionText: JSON.stringify({
              ScriptBody: encoded,
              EnforceSignatureCheck: 1,
              RunAs32Bit: 0,
            }),
          },
        ]),
      },
    ]).replace("__BS__", "\\");
    const entries = buildEntries(DEMO_LOG_ABS_PATH, [
      { message: `Get policies = ${payload}`, severity: "Info", component: "AppWorkload" },
      { message: "Nothing to decode here", severity: "Info", component: "AppWorkload" },
    ]);
    await seedEverywhere(page, LOG_STORE, "useLogStore", {
      entries,
      totalLines: entries.length,
    });

    await page.evaluate(
      async ({ logPath }) => {
        const { useLogStore } = await import(/* @vite-ignore */ logPath);
        useLogStore.getState().selectEntry(0);
      },
      { logPath: await appModule(page, LOG_STORE) },
    );

    await expect(page.getByText("1 App Policy", { exact: true })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByText("Contoso VPN Client", { exact: true })).toBeVisible();
    await expect(page.getByText("policy-1", { exact: true })).toBeVisible();
    await expect(page.getByText("Required", { exact: true })).toBeVisible();
    await expect(page.getByText("Device", { exact: true })).toBeVisible();
    await expect(page.getByText("msiexec /i ContosoVPN.msi /q", { exact: true })).toBeVisible();
    await expect(page.getByText("PowerShell Script", { exact: true })).toBeVisible();
    await expect(page.getByText("0=Success, 3010=Hard Reboot", { exact: true })).toBeVisible();
    // The repaired backslash survives into the rendered command line.
    await expect(
      page.getByText("msiexec /x \\ProgramData\\Contoso\\VPN.msi /q", { exact: true }),
    ).toBeVisible();
    await expect(page.getByText(/decoded-script-body/)).toBeVisible();

    // A message that is not a policies payload renders nothing.
    await page.evaluate(
      async ({ logPath }) => {
        const { useLogStore } = await import(/* @vite-ignore */ logPath);
        useLogStore.getState().selectEntry(1);
      },
      { logPath: await appModule(page, LOG_STORE) },
    );
    await expect(page.getByText(/App Polic/)).toHaveCount(0);
    await expect(page.getByText(/decoded-script-body/)).toHaveCount(0);
  });

  test("[LOG-097] the info pane shows script-detection sidecar banners", async ({ page }) => {
    await bootApp(page);
    const entries = buildEntries(DEMO_LOG_ABS_PATH, [
      {
        message: "Start DetectionManager SidecarScriptDetectionManager",
        severity: "Info",
      },
      {
        message:
          "Completed DetectionManager SidecarScriptDetectionManager applicationdetectedbycurrentrule:true",
        severity: "Info",
      },
      {
        message: "SidecarScriptDetectionManager powershell ExitCode:0",
        severity: "Info",
      },
      {
        message: "SidecarScriptDetectionManager powershell ExitCode:1",
        severity: "Error",
      },
      {
        message: "SidecarScriptDetectionManager applicationdetectedbycurrentrule:false",
        severity: "Info",
      },
      {
        message: "SidecarScriptDetectionManager Process ID = 4242",
        severity: "Info",
      },
      {
        message: "SidecarScriptDetectionManager heartbeat",
        severity: "Info",
      },
    ]);
    await seedEverywhere(page, LOG_STORE, "useLogStore", {
      entries,
      totalLines: entries.length,
    });

    /** Selects one entry and returns its banner plus the accent colour. */
    const banner = async (index: number) => {
      await page.evaluate(
        async ({ logPath, id }) => {
          const { useLogStore } = await import(/* @vite-ignore */ logPath);
          useLogStore.getState().selectEntry(id);
        },
        { logPath: await appModule(page, LOG_STORE), id: index },
      );
      const locator = page
        .locator('div[style*="border-left"]')
        .filter({ hasText: /Script Detection|PowerShell Exit Code|Detection Result|Script Process/ })
        .last();
      await expect(locator).toBeVisible();
      const accent = await locator.evaluate((el) => getComputedStyle(el).borderLeftColor);
      return { locator, accent: parseRgb(accent) };
    };

    const started = await banner(0);
    await expect(started.locator.getByText("Script Detection Started", { exact: true })).toBeVisible();

    const complete = await banner(1);
    await expect(
      complete.locator.getByText("Script Detection Complete", { exact: true }),
    ).toBeVisible();
    await expect(complete.locator.getByText("App Detected", { exact: true })).toBeVisible();

    const exitZero = await banner(2);
    await expect(exitZero.locator.getByText("PowerShell Exit Code", { exact: true })).toBeVisible();
    await expect(exitZero.locator.getByText("Exit Code: 0", { exact: true })).toBeVisible();

    const exitOne = await banner(3);
    await expect(exitOne.locator.getByText("Exit Code: 1", { exact: true })).toBeVisible();

    const detectedFalse = await banner(4);
    await expect(detectedFalse.locator.getByText("Detection Result", { exact: true })).toBeVisible();
    await expect(
      detectedFalse.locator.getByText("App Not Detected", { exact: true }),
    ).toBeVisible();

    const process = await banner(5);
    await expect(process.locator.getByText("Script Process", { exact: true })).toBeVisible();
    await expect(process.locator.getByText("PID: 4242", { exact: true })).toBeVisible();

    const other = await banner(6);
    await expect(other.locator.getByText("Script Detection", { exact: true })).toBeVisible();

    // Green for a clean exit, red otherwise — compared by channel dominance so
    // the assertion does not pin Fluent's palette values.
    expect(exitZero.accent).toEqual(complete.accent);
    expect(exitOne.accent.r).toBeGreaterThan(exitOne.accent.g);
    expect(exitOne.accent.r).toBeGreaterThan(exitOne.accent.b);
    expect(complete.accent.g).toBeGreaterThan(complete.accent.r);
    expect(exitOne.accent).not.toEqual(complete.accent);
  });
});

// ---------------------------------------------------------------------------
// Alternate data source (timeline log-stream pane)
// ---------------------------------------------------------------------------

test.describe("log: alternate data source", () => {
  test("[LOG-065] the log list renders an alternate source with a range filter", async ({
    page,
  }) => {
    const t0 = Date.UTC(2031, 9, 4, 12, 0, 0);
    const stamps = [t0, t0 + 10_000, t0 + 20_000, t0 + 30_000, null];
    const timelineEntries = stamps.map((ts, index) => ({
      kind: "log" as const,
      sourceIdx: 3,
      entry: {
        id: 0,
        lineNumber: index + 1,
        message: `TIMELINE-ROW-${index}`,
        component: "AppEnforce",
        timestamp: ts,
        timestampDisplay: ts === null ? null : formatStamp(ts),
        severity: "Info",
        thread: 1,
        threadDisplay: "1",
        sourceFile: "appexcnlib.cpp",
        format: "Ccm",
        filePath: "C:\\Logs\\Timeline\\alpha.log",
        timezoneOffset: 0,
      },
    }));

    await bootApp(page, {
      overrides: {
        get_known_log_sources: [],
        query_timeline_entries_cmd: timelineEntries,
        query_lane_buckets_cmd: [],
      },
    });

    await page.evaluate(
      async ({ timelinePath, entries }) => {
        const { useTimelineStore } = await import(/* @vite-ignore */ timelinePath);
        const store = useTimelineStore;
        store.getState().setBundle({
          id: "bundle-1",
          sources: [
            {
              idx: 3,
              kind: { logFile: { parserKind: "ccm" } },
              path: "C:\\Logs\\Timeline\\alpha.log",
              displayName: "alpha.log",
              color: "#107C10",
              entryCount: entries.length,
            },
          ],
          timeRangeMs: [entries[0].entry.timestamp, entries[3].entry.timestamp],
          totalEntries: entries.length,
          incidents: [
            {
              id: 7,
              tsStartMs: entries[2].entry.timestamp,
              tsEndMs: entries[2].entry.timestamp,
              signalCount: 1,
              sourceCount: 1,
              confidence: 1,
              summary: "incident",
            },
          ],
          deniedGuids: [],
          errors: [],
          tunables: {
            overlapWindowMs: 1000,
            minSourceCount: 1,
            maxIncidentSpanMs: 60000,
            enabledSignalKinds: ["errorSeverity"],
          },
        });
      },
      { timelinePath: await appModule(page, TIMELINE_STORE), entries: timelineEntries },
    );

    await selectWorkspace(page, "Timeline");

    const rows = page.locator('[id^="log-list-row-"]');
    // The adapter synthesises unique ids from the source index and line number.
    await expect(page.locator('[id="log-list-row-30000001"]')).toBeVisible({ timeout: 15_000 });
    await expect(rows).toHaveCount(5);
    await expect(page.getByText("TIMELINE-ROW-3")).toBeVisible();

    // The alternate source supplies no find matches: a log-store find session
    // covering the same synthesised ids leaves the timeline rows unpainted.
    await page.evaluate(
      async ({ logPath, ids }) => {
        const { useLogStore } = await import(/* @vite-ignore */ logPath);
        useLogStore.setState({ findQuery: "TIMELINE-ROW", findMatchIds: ids });
      },
      { logPath: await appModule(page, LOG_STORE), ids: [30000001, 30000002, 30000003, 30000004, 30000005] },
    );
    await expect
      .poll(() =>
        page
          .locator('[id="log-list-row-30000001"]')
          .evaluate((el) => getComputedStyle(el).backgroundImage),
      )
      .toBe("none");

    // Row selection is a no-op for the alternate source: clicking a row does
    // not become the timeline's selected incident.
    await page.getByText("TIMELINE-ROW-1", { exact: true }).click();
    expect(
      await readStore<number | null>(
        page,
        TIMELINE_STORE,
        "useTimelineStore",
        "state.selectedIncidentId",
      ),
    ).toBeNull();

    // The brush range is an external filter: rows outside it disappear, and a
    // null timestamp drops out too.
    await page.evaluate(
      async ({ timelinePath, from, to }) => {
        const { useTimelineStore } = await import(/* @vite-ignore */ timelinePath);
        useTimelineStore.getState().setBrushRange([from, to]);
      },
      { timelinePath: await appModule(page, TIMELINE_STORE), from: stamps[1]!, to: stamps[3]! },
    );
    await expect(rows).toHaveCount(3);
    await expect(page.getByText("TIMELINE-ROW-0")).toHaveCount(0);
    await expect(page.getByText("TIMELINE-ROW-1")).toBeVisible();
    await expect(page.getByText("TIMELINE-ROW-3")).toBeVisible();
    // No incident is selected yet, so no row carries the highlight. The
    // attribute sits on the positioned wrapper around each row.
    await expect(
      page.locator('[id="log-list-row-30000002"]').locator("xpath=.."),
    ).not.toHaveAttribute("data-highlighted", "true");

    // The selected incident paints a brand stripe on the rows inside it.
    await page.evaluate(
      async ({ timelinePath }) => {
        const { useTimelineStore } = await import(/* @vite-ignore */ timelinePath);
        useTimelineStore.getState().selectIncident(7);
      },
      { timelinePath: await appModule(page, TIMELINE_STORE) },
    );
    // The incident's own range becomes the brush, so only the row inside it
    // survives — and it carries the highlight.
    await expect(rows).toHaveCount(1);
    const highlightedRow = page
      .locator('[id="log-list-row-30000003"]')
      .locator("xpath=..");
    await expect(highlightedRow).toHaveAttribute("data-highlighted", "true");
    const stripe = await highlightedRow.evaluate((el) => getComputedStyle(el).boxShadow);
    expect(stripe).toContain("inset");
  });
});

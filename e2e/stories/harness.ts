/**
 * Shared helpers for the story-mapped browser suites in `e2e/stories/`.
 *
 * Each test in these suites names the user-story ids from
 * `docs/qa/user-stories.csv` it verifies, so a run can be mapped back onto the
 * canonical feature spreadsheet. Everything here works with the Tauri IPC shim
 * (`../fixtures/index.ts`) and therefore runs unchanged in CI, where no Rust
 * build and no IPC bridge exist. When `npm run app:dev` is running, unmodified
 * commands are forwarded to the real backend automatically by the shim.
 */
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

/** Page globals installed by `e2e/fixtures/tauri-shim.ts`. */
export interface ShimWindow {
  __TAURI_OS_PLUGIN_INTERNALS__?: { platform?: string };
  __e2e_ipc_overrides__?: Record<string, (args?: unknown) => unknown>;
  __e2e_emit__?: (event: string, payload: unknown) => void;
}

export interface BootOptions {
  /** Value `@tauri-apps/plugin-os` reports; the shim seeds "windows". */
  platform?: "windows" | "macos" | "linux";
  /** Workspace ids `get_available_workspaces` should answer with. */
  workspaces?: string[];
  /**
   * Per-command IPC overrides. Values must be serializable: Playwright passes
   * them into the page as JSON, so a function here is dropped silently.
   * For a response that depends on the request, install it yourself before
   * booting — `page.addInitScript((args) => { ... }, serializableArgs)` runs
   * after the shim's script and may assign `window.__e2e_ipc_overrides__[cmd]`
   * to a real function whose closure holds only its serializable argument:
   *
   *   await page.addInitScript(
   *     ({ second }) => {
   *       window.__e2e_ipc_overrides__["open_log_file"] = (args) =>
   *         args?.path === "/b.log" ? second : null;
   *     },
   *     { second: SECOND_PARSE_RESULT },
   *   );
   *   await bootApp(page, { overrides: { get_initial_file_paths: ["/a.log"] } });
   */
  overrides?: Record<string, unknown>;
}

const ALL_WORKSPACES = [
  "log",
  "intune",
  "new-intune",
  "dsregcmd",
  "deployment",
  "event-log",
  "sysmon",
  "secureboot",
  "esp-diagnostics",
  "sccm",
  "timeline",
  "dns-dhcp",
];

/** Waits for the splash screen to be removed, i.e. React has mounted. */
export async function dismissSplash(page: Page): Promise<void> {
  await page.waitForSelector("#splash", { state: "detached", timeout: 20_000 });
}

/**
 * Boots the app with deterministic IPC: platform, workspace allowlist and any
 * per-command overrides are installed before the app's first script runs.
 */
export async function bootApp(page: Page, options: BootOptions = {}): Promise<void> {
  const { platform = "windows", workspaces = ALL_WORKSPACES, overrides = {} } = options;
  const commandOverrides: Record<string, unknown> = {
    // The harness emulates Windows, so rendered timestamps use the Windows
    // preferences that platform would report. Without this the development
    // host's own answer (ISO on macOS, straight from the debug IPC bridge)
    // leaks into every Date/Time column. A spec that is about the format itself
    // overrides this by name.
    get_system_date_time_preferences: {
      datePattern: "M/d/yyyy",
      timePattern: "h:mm:ss tt",
      amDesignator: "AM",
      pmDesignator: "PM",
    },
    ...overrides,
  };
  await page.addInitScript(
    ({ platformValue, workspaceList, commandOverrides: values }) => {
      const shimmed = window as unknown as ShimWindow;
      const os = shimmed.__TAURI_OS_PLUGIN_INTERNALS__;
      const ipc = shimmed.__e2e_ipc_overrides__;
      if (!os || !ipc) {
        throw new Error("Tauri IPC shim must run before bootApp()");
      }
      os.platform = platformValue;
      ipc["get_available_workspaces"] = () => workspaceList;
      for (const [command, value] of Object.entries(values)) {
        ipc[command] = () => value;
      }
    },
    { platformValue: platform, workspaceList: workspaces, commandOverrides },
  );
  await page.goto("/");
  await dismissSplash(page);

  // A module the dev server invalidated is served under a `?t=` URL, which is a
  // second module instance: a spec that imports the bare path would then assert
  // a shadow store instead of the app's. Fail loudly rather than pass on the
  // wrong instance; restart the dev server to clear the invalidations.
  const stamped = await page.evaluate(() =>
    performance
      .getEntriesByType("resource")
      .map((entry) => new URL(entry.name, window.location.href))
      .filter((url) => url.pathname.startsWith("/src/") && url.searchParams.has("t"))
      .map((url) => url.pathname)
      .slice(0, 5),
  );
  if (stamped.length > 0) {
    throw new Error(
      `Vite HMR timestamps are active for ${stamped.join(", ")}; restart the dev server ` +
        "so story specs act on the app's own module instances",
    );
  }
}

/** Selects a workspace in the toolbar's "Workspace" combobox. */
export async function selectWorkspace(page: Page, optionName: string): Promise<void> {
  const combo = page.getByRole("combobox", { name: "Workspace" });
  await expect(combo).toBeVisible({ timeout: 15_000 });
  await combo.click();
  const option = page.getByRole("option", { name: optionName, exact: true });
  await expect(option).toBeVisible({ timeout: 10_000 });
  await option.click();
  await expect(page.getByRole("option", { name: optionName, exact: true })).toHaveCount(0);
}

/**
 * Pushes state straight into a live Vite store singleton (real store logic).
 *
 * Vite serves an HMR-invalidated module under a `?t=` URL, which is a *different
 * module instance* from the bare path. The app may hold either, so the seed is
 * applied to every instance of the module the page has loaded. `bootApp` fails
 * loudly when such timestamps exist, so a stale dev-server session cannot
 * silently test a shadow instance.
 */
export async function seedStore<T>(
  page: Page,
  modulePath: string,
  storeName: string,
  state: T,
): Promise<void> {
  await page.evaluate(
    async ({ path, name, value }) => {
      // Dynamic import is the point of this helper: the spec names the module at
      // call time, and Vite's dev server resolves the URL to a module instance
      // the app also holds, so real store logic runs.
      const candidates = new Set<string>([path]);
      for (const entry of performance.getEntriesByType("resource")) {
        const url = new URL(entry.name, window.location.href);
        if (url.pathname === path && url.search !== "") {
          candidates.add(`${url.pathname}${url.search}`);
        }
      }
      for (const candidate of candidates) {
        const mod = (await import(/* @vite-ignore */ candidate)) as Record<
          string,
          { setState: (partial: unknown) => void }
        >;
        const store = mod[name];
        if (!store || typeof store.setState !== "function") continue;
        store.setState(value);
      }
    },
    { path: modulePath, name: storeName, value: state },
  );
}

/** Emits a backend → frontend event through the shim's event plumbing. */
export async function emitBackendEvent(
  page: Page,
  event: string,
  payload: unknown,
): Promise<void> {
  await page.evaluate(
    ({ name, body }) => {
      const shimmed = window as unknown as ShimWindow;
      const emit = shimmed.__e2e_emit__;
      if (!emit) throw new Error("shim did not install __e2e_emit__");
      emit(name, body);
    },
    { name: event, body: payload },
  );
}

/** True when the real Rust IPC bridge from `npm run app:dev` is reachable. */
export async function bridgeIsUp(): Promise<boolean> {
  try {
    const res = await fetch("http://127.0.0.1:1422/", { signal: AbortSignal.timeout(700) });
    return res.ok;
  } catch {
    return false;
  }
}

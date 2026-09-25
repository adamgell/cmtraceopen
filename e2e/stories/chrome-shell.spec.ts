/**
 * Story-mapped browser coverage for the application shell and chrome.
 *
 * Every test names the user-story ids it verifies (see
 * `docs/qa/user-stories.csv`). The suite runs in a plain browser against the
 * Tauri IPC shim, so it needs no Rust build and no Windows host; unmodified
 * commands are forwarded to the real backend when `npm run app:dev` happens to
 * be running behind the debug IPC bridge.
 */
import { test, expect } from "../fixtures";
import { DEMO_LOG_ABS_PATH, MOCK_LOG_PARSE_RESULT } from "../fixtures/screenshot-data";
import { bootApp, bridgeIsUp, seedStore, selectWorkspace } from "./harness";

const UI_STORE = "/src/stores/ui-store.ts";

test.describe("chrome: sidebar", () => {
  test("[CHROME-034] sidebar collapses to a rail, and Ctrl+B is equivalent", async ({ page }) => {
    await bootApp(page);

    const collapse = page.getByRole("button", { name: "Collapse sidebar" });
    await expect(collapse).toBeVisible();
    await collapse.click();

    // Collapsed: only the rail button remains, and the aside is gone.
    await expect(page.getByRole("button", { name: "Expand sidebar" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Collapse sidebar" })).toHaveCount(0);

    // Ctrl+B is the keyboard equivalent of the rail button.
    await page.keyboard.press("Control+b");
    await expect(page.getByRole("button", { name: "Collapse sidebar" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Expand sidebar" })).toHaveCount(0);
  });

  test("[CHROME-044] sidebar explains that no source is open", async ({ page }) => {
    await bootApp(page);

    await expect(page.getByText("No file source open")).toBeVisible();
    await expect(page.getByText("Open a log file or folder")).toBeVisible();
  });

  test("[CHROME-045] sidebar reports a failed file selection and offers Retry", async ({ page }) => {
    const folder = "/e2e/fixtures/folder";
    const failingPath = `${folder}/two.log`;
    const listing = {
      sourceKind: "folder",
      source: { kind: "folder", path: folder },
      entries: [
        { name: "one.log", path: `${folder}/one.log`, isDir: false, sizeBytes: 64, modifiedUnixMs: 1_700_000_000_000 },
        { name: "two.log", path: failingPath, isDir: false, sizeBytes: 64, modifiedUnixMs: 1_700_000_000_000 },
      ],
    };

    // The first attempt on two.log fails, the retry succeeds (the retry button is
    // only offered when the selection itself failed).
    await page.addInitScript(
      ({ demo, path }) => {
        const ipc = window.__e2e_ipc_overrides__;
        if (!ipc) throw new Error("shim overrides missing");
        let failed = false;
        ipc["open_log_file"] = (args) => {
          const requested =
            args && typeof args === "object" && "path" in args ? args.path : "";
          if (requested === path && !failed) {
            failed = true;
            // Rust command failures arrive as plain data objects; the frontend
            // deliberately refuses to trust Error instances (hostile-Proxy guard).
            throw { message: "Access is denied." };
          }
          return demo;
        };
      },
      { demo: MOCK_LOG_PARSE_RESULT, path: failingPath },
    );
    await bootApp(page, {
      overrides: {
        get_initial_file_paths: [],
        inspect_path_kind: "folder",
        "plugin:dialog|open": folder,
        list_log_folder: listing,
        // Only the first file parses in the folder batch, so two.log has no cached
        // snapshot and selecting it goes through open_log_file.
        parse_files_batch: [{ ...MOCK_LOG_PARSE_RESULT, filePath: `${folder}/one.log` }],
      },
    });

    // A single launch path is always read as a file, so reach the folder source
    // through the real toolbar flow instead.
    await page.getByRole("button", { name: "Open..." }).click();
    await page.getByRole("menuitem", { name: "Open folder..." }).click();
    await expect(page.getByText("Folder Source", { exact: true })).toBeVisible({
      timeout: 15_000,
    });

    await page.getByText("two.log", { exact: true }).first().click();
    const alert = page.getByRole("alert").first();
    await expect(alert).toBeVisible({ timeout: 15_000 });
    await expect(alert).toContainText("Access is denied.");

    const retry = page.getByRole("button", { name: "Retry two.log" });
    await expect(retry).toBeEnabled();
    await retry.click();
    await expect(page.getByRole("alert")).toHaveCount(0, { timeout: 15_000 });
  });

  test("[CHROME-043] sidebar summarises the open file source", async ({ page }) => {
    await bootApp(page, {
      overrides: {
        get_initial_file_paths: [DEMO_LOG_ABS_PATH],
        open_log_file: MOCK_LOG_PARSE_RESULT,
      },
    });

    await expect(page.getByText("File Source", { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("ConfigMgr_AppEnforce_demo.log").first()).toBeVisible();
  });
});

test.describe("chrome: status bar", () => {
  test("[CHROME-047] status bar counts the loaded entries", async ({ page }) => {
    await bootApp(page, {
      overrides: {
        get_initial_file_paths: [DEMO_LOG_ABS_PATH],
        open_log_file: MOCK_LOG_PARSE_RESULT,
      },
    });

    const expected = MOCK_LOG_PARSE_RESULT.entries.length;
    await expect(
      page.getByText(`${expected} entr${expected === 1 ? "y" : "ies"}`),
    ).toBeVisible({ timeout: 15_000 });
  });

  test("[CHROME-048] status bar reports every non-disconnected Graph phase", async ({ page }) => {
    await bootApp(page);
    const graphLabel = (phase: string, label: string) =>
      seedStore(page, UI_STORE, "useUiStore", { graphApiStatus: phase }).then(() =>
        expect(page.getByText(label, { exact: true })).toBeVisible(),
      );

    await graphLabel("signingIn", "Graph API: Connecting...");
    await graphLabel("cancelling", "Graph API: Cancelling...");
    await graphLabel("connected", "Graph API: Connected");
    await graphLabel("unsupported", "Graph API: Unavailable");
    await graphLabel("error", "Graph API: Error");
    await seedStore(page, UI_STORE, "useUiStore", { graphApiStatus: "disconnected" });
    await expect(page.getByText(/^Graph API:/)).toHaveCount(0);
  });
});

test.describe("chrome: workspace capabilities and tabs", () => {
  test("[CHROME-033] workspace capabilities decide which chrome mounts", async ({ page }) => {
    await bootApp(page, {
      overrides: {
        get_initial_file_paths: [DEMO_LOG_ABS_PATH],
        open_log_file: MOCK_LOG_PARSE_RESULT,
      },
    });

    // The log workspace declares tabStrip and a sidebar, so both mount.
    await expect(page.getByRole("tablist", { name: "Open log files" })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByRole("button", { name: "Collapse sidebar" })).toBeVisible();

    // The Event Log workspace declares sidebar: false and no tabStrip.
    await selectWorkspace(page, "Event Log Viewer (Preview)");
    await expect(page.getByRole("button", { name: "Collapse sidebar" })).toHaveCount(0);
    await expect(page.getByRole("tablist", { name: "Open log files" })).toHaveCount(0);
  });

  test("[CHROME-035] switching tabs reloads that file's content", async ({ page }) => {
    const secondPath = "/e2e/fixtures/second.log";
    const second = {
      ...MOCK_LOG_PARSE_RESULT,
      filePath: secondPath,
      entries: MOCK_LOG_PARSE_RESULT.entries.map((entry, index) => ({
        ...entry,
        id: index + 1000,
        filePath: secondPath,
        message: `SECOND FILE MESSAGE ${index}`,
      })),
    };
    // A response that depends on the request cannot travel through bootApp's
    // serializable overrides: install it as an init script, which the shim's own
    // script has already prepared by the time this one runs.
    await page.addInitScript(
      ({ demo, second, path }) => {
        const ipc = window.__e2e_ipc_overrides__;
        if (!ipc) throw new Error("shim overrides missing");
        ipc["open_log_file"] = (args) =>
          args && typeof args === "object" && "path" in args && args.path === path
            ? second
            : demo;
      },
      { demo: MOCK_LOG_PARSE_RESULT, second, path: secondPath },
    );
    await bootApp(page, {
      overrides: {
        get_initial_file_paths: [DEMO_LOG_ABS_PATH],
        inspect_path_kind: "file",
        "plugin:dialog|open": secondPath,
      },
    });
    await expect(page.getByRole("tab")).toHaveCount(1, { timeout: 15_000 });
    await expect(page.getByText(/SECOND FILE MESSAGE/)).toHaveCount(0);

    // Open a second file through the real toolbar flow.
    await page.getByRole("button", { name: "Open..." }).click();
    await page.getByRole("menuitem", { name: "Open file..." }).click();
    await expect(page.getByRole("tab")).toHaveCount(2, { timeout: 15_000 });

    const tabs = page.getByRole("tab");
    await tabs.nth(1).click();
    await expect(page.getByText(/SECOND FILE MESSAGE 0/).first()).toBeVisible({
      timeout: 15_000,
    });
    await tabs.nth(0).click();
    await expect(page.getByText(/SECOND FILE MESSAGE/)).toHaveCount(0);
  });

  test("[CHROME-036] closing the last tab clears the log content and filters", async ({ page }) => {
    await bootApp(page);
    const after = await page.evaluate(
      async ({ storePath, filterPath }) => {
        const ui = (await import(/* @vite-ignore */ storePath)) as {
          useUiStore: {
            getState: () => {
              openTab: (p: string, n: string, c?: null, k?: string) => void;
              closeTab: (i: number) => void;
              openTabs: { id: string; filePath: string }[];
              activeTabIndex: number;
            };
          };
        };
        const filter = (await import(/* @vite-ignore */ filterPath)) as {
          useFilterStore: { getState: () => { clauses: unknown[] } };
        };
        const store = ui.useUiStore;
        store.getState().openTab("/tmp/one.log", "one.log", null, "log");
        store.getState().closeTab(0);
        return {
          tabCount: store.getState().openTabs.length,
          activeTabIndex: store.getState().activeTabIndex,
          clauses: filter.useFilterStore.getState().clauses.length,
        };
      },
      { storePath: UI_STORE, filterPath: "/src/stores/filter-store.ts" },
    );

    expect(after.tabCount).toBe(0);
    expect(after.activeTabIndex).toBe(-1);
    expect(after.clauses).toBe(0);
  });

  test("[CHROME-037] reopening an already-open file focuses its tab instead of duplicating it", async ({
    page,
  }) => {
    await bootApp(page);
    const result = await page.evaluate(
      async ({ storePath }) => {
        const mod = (await import(/* @vite-ignore */ storePath)) as {
          useUiStore: {
            getState: () => {
              openTab: (p: string, n: string, c?: null, k?: string) => void;
              openTabs: { id: string; filePath: string }[];
            };
          };
        };
        const store = mod.useUiStore;
        store.getState().openTab("", "empty.log", null, "log");
        const afterEmpty = store.getState().openTabs.length;
        store.getState().openTab("/tmp/one.log", "one.log", null, "log");
        store.getState().openTab("/tmp/two.log", "two.log", null, "log");
        store.getState().openTab("/tmp/one.log", "one.log", null, "log");
        const tabs = store.getState().openTabs;
        return {
          afterEmpty,
          paths: tabs.map((t) => t.filePath),
          firstId: tabs[0]?.id ?? "",
        };
      },
      { storePath: UI_STORE },
    );

    expect(result.afterEmpty).toBe(0);
    expect(result.paths).toEqual(["/tmp/one.log", "/tmp/two.log"]);
    expect(result.firstId).toMatch(/^[0-9a-f-]{36}$/);
  });

  test("[CHROME-038] closing a merged tab exits that view", async ({ page }) => {
    await bootApp(page);
    await page.evaluate(
      async ({ uiPath, logPath, entries }) => {
        const ui = (await import(/* @vite-ignore */ uiPath)) as {
          useUiStore: { setState: (s: unknown) => void };
        };
        const log = (await import(/* @vite-ignore */ logPath)) as {
          useLogStore: { setState: (s: unknown) => void };
        };
        ui.useUiStore.setState({
          openTabs: [
            {
              id: "merged-tab",
              filePath: "merged",
              fileName: "Merged",
              scrollPosition: 0,
              selectedId: null,
              sourceContext: null,
              fileKind: "log",
            },
          ],
          activeTabIndex: 0,
        });
        log.useLogStore.setState({
          sourceOpenMode: "merged",
          mergedTabState: {
            sourceFilePaths: ["/tmp/a.log"],
            colorAssignments: { "/tmp/a.log": "#ff0000" },
            fileVisibility: { "/tmp/a.log": true },
            mergedEntries: entries,
            cacheKey: "e2e-merged",
          },
        });
      },
      {
        uiPath: UI_STORE,
        logPath: "/src/stores/log-store.ts",
        entries: MOCK_LOG_PARSE_RESULT.entries,
      },
    );

    await expect(page.getByText("Merged (1 files)")).toBeVisible();
    await page.getByRole("button", { name: "Close Merged" }).click();
    await expect(page.getByText("Merged (1 files)")).toHaveCount(0);
    const mode = await page.evaluate(
      async ({ logPath }) => {
        const log = (await import(/* @vite-ignore */ logPath)) as {
          useLogStore: { getState: () => { sourceOpenMode: string | null } };
        };
        return log.useLogStore.getState().sourceOpenMode;
      },
      { logPath: "/src/stores/log-store.ts" },
    );
    expect(mode).toBeNull();
  });

  test("[CHROME-081] a launch carrying several files loads them as one source", async ({ page }) => {
    await bootApp(page, {
      overrides: {
        get_initial_file_paths: [
          DEMO_LOG_ABS_PATH,
          "/e2e/fixtures/second.log",
          "/e2e/fixtures/third.log",
        ],
        inspect_path_kind: () => ({ kind: "file", exists: true }),
        open_log_file: MOCK_LOG_PARSE_RESULT,
        parse_files_batch: () => [
          MOCK_LOG_PARSE_RESULT,
          { ...MOCK_LOG_PARSE_RESULT, filePath: "/e2e/fixtures/second.log" },
          { ...MOCK_LOG_PARSE_RESULT, filePath: "/e2e/fixtures/third.log" },
        ],
      },
    });

    // Several launch paths become one aggregate stream: the status bar reports the
    // stream's file count and the filter is cleared for the new source.
    await expect(page.getByText("3 files")).toBeVisible({ timeout: 15_000 });
    await expect(page.getByRole("button", { name: "Filter...", exact: true })).toBeVisible();
    await expect(page.getByRole("combobox", { name: "Workspace" })).toHaveText(/Log/);
  });

  test("[CHROME-059] displayed timestamps follow the system date/time format", async ({ page }) => {
    await bootApp(page, {
      overrides: {
        get_system_date_time_preferences: {
          datePattern: "dd/MM/yyyy",
          timePattern: "HH:mm:ss",
          amDesignator: "AM",
          pmDesignator: "PM",
        },
        get_initial_file_paths: [DEMO_LOG_ABS_PATH],
        open_log_file: MOCK_LOG_PARSE_RESULT,
      },
    });

    // Timestamps are re-formatted with the reported Windows pattern.
    await expect(page.getByText(/\b\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}:\d{2}\b/).first()).toBeVisible({
      timeout: 15_000,
    });
  });
});

test.describe("chrome: workspace and preference state", () => {
  test("[CHROME-049] an unavailable workspace cannot be activated", async ({ page }) => {
    await bootApp(page);

    const result = await page.evaluate(
      async ({ storePath }) => {
        const mod = (await import(/* @vite-ignore */ storePath)) as {
          useUiStore: {
            getState: () => {
              setEnabledWorkspaces: (ids: string[]) => void;
              setActiveWorkspace: (id: string) => void;
              activeWorkspace: string;
              enabledWorkspaces: string[] | null;
            };
          };
        };
        const store = mod.useUiStore;
        store.getState().setEnabledWorkspaces(["log", "event-log"]);
        store.getState().setActiveWorkspace("sysmon");
        const afterUnavailable = store.getState().activeWorkspace;
        store.getState().setActiveWorkspace("event-log");
        const afterAvailable = store.getState().activeWorkspace;
        // Dropping the active workspace from the list falls back to "log".
        store.getState().setEnabledWorkspaces(["log"]);
        return { afterUnavailable, afterAvailable, afterDrop: store.getState().activeWorkspace };
      },
      { storePath: UI_STORE },
    );

    expect(result.afterUnavailable).toBe("log");
    expect(result.afterAvailable).toBe("event-log");
    expect(result.afterDrop).toBe("log");
  });

  test("[CHROME-051] persisted preferences are sanitized on rehydration", async ({ page }) => {
    await page.addInitScript(
      ({ key }) => {
        window.localStorage.setItem(
          key,
          JSON.stringify({
            state: {
              themeId: "definitely-not-a-theme",
              fontFamily: 42,
              uiFontSize: 999,
              monoFontSize: 0,
              sidebarCollapsed: true,
              graphApiStatus: "connected",
              dismissedDnsBannerPaths: ["C:/tmp/a.log"],
              logSeverityPaletteMode: "light",
            },
            version: 0,
          }),
        );
      },
      { key: "cmtraceopen-ui-preferences" },
    );
    await bootApp(page);

    const state = await page.evaluate(
      async ({ storePath }) => {
        const mod = (await import(/* @vite-ignore */ storePath)) as {
          useUiStore: { getState: () => Record<string, unknown> };
        };
        const s = mod.useUiStore.getState();
        return {
          themeId: s.themeId,
          fontFamily: s.fontFamily,
          graphApiStatus: s.graphApiStatus,
          sidebarCollapsed: s.sidebarCollapsed,
        };
      },
      { storePath: UI_STORE },
    );

    expect(state.themeId).not.toBe("definitely-not-a-theme");
    expect(state.fontFamily).toBeNull();
    expect(state.graphApiStatus).toBe("disconnected");
    expect(state.sidebarCollapsed).toBe(true);
  });

  test("[CHROME-040] an unknown persisted workspace falls back to the log view", async ({ page }) => {
    await bootApp(page, { workspaces: ["log", "event-log"] });

    // Only the reported workspaces are offered, and the log view stays active.
    await expect(page.getByText(/Log view/)).toBeVisible();
    await selectWorkspace(page, "Log Explorer");
    await expect(page.getByRole("combobox", { name: "Workspace" })).toHaveText(/Log/);
  });
});

test.describe("chrome: appearance", () => {
  test("[CHROME-057] choosing a theme repaints the app immediately", async ({ page }) => {
    await bootApp(page);

    // The toolbar picker shows the active theme label and lists every theme.
    const picker = page.getByRole("button", { name: "Light", exact: true });
    await expect(picker).toBeVisible();
    await picker.click();
    await page.getByRole("menuitem", { name: /^Dark/ }).click();

    await expect(page.getByRole("button", { name: "Dark", exact: true })).toBeVisible();
    await expect
      .poll(async () => page.evaluate(() => document.documentElement.style.colorScheme))
      .toBe("dark");
  });

  test("[CHROME-100] the debug IPC bridge serves browser sessions", async ({ page }) => {
    test.skip(!(await bridgeIsUp()), "requires the debug IPC bridge from `npm run app:dev`");

    const call = (body: string, method = "POST") =>
      page.evaluate(
        async ({ url, payload, verb }) => {
          const res = await fetch(url, {
            method: verb,
            headers: { "Content-Type": "application/json" },
            body: verb === "POST" ? payload : undefined,
          });
          return { status: res.status, text: await res.text() };
        },
        { url: "http://127.0.0.1:1422/invoke", payload: body, verb: method },
      );

    // A real command is executed by the Rust backend, not mocked.
    const version = await call(JSON.stringify({ cmd: "get_app_version", args: {} }));
    expect(version.status).toBe(200);
    expect(JSON.parse(version.text)).toHaveProperty("result");

    // Unknown commands and native-only commands fail explicitly, never silently.
    const unknown = await call(JSON.stringify({ cmd: "definitely_not_a_command", args: {} }));
    expect(JSON.parse(unknown.text).error).toContain("does not implement command");
    const native = await call(
      JSON.stringify({ cmd: "register_log_file_handler", args: {} }),
    );
    expect(JSON.parse(native.text).error).toContain("require the Tauri runtime");

    // Malformed bodies and missing arguments are reported, not crashed.
    const malformed = await call("{not json");
    expect(JSON.parse(malformed.text).error).toContain("request parse error");
    const missing = await call(JSON.stringify({ cmd: "inspect_path_kind" }));
    expect(JSON.parse(missing.text).error).toContain("missing `path` argument");

    // GET and OPTIONS are answered; the browser needs the CORS response headers.
    const get = await call("", "GET");
    expect(get.status).toBe(200);
    const options = await call("", "OPTIONS");
    expect([200, 204]).toContain(options.status);
  });

  test("[CHROME-058] the chosen font family reaches the UI and mono stacks", async ({ page }) => {
    await bootApp(page);

    const readVars = () =>
      page.evaluate(() => {
        const style = getComputedStyle(document.documentElement);
        return {
          ui: style.getPropertyValue("--cmtrace-font-family-ui").trim(),
          mono: style.getPropertyValue("--cmtrace-font-family-mono").trim(),
        };
      });
    const setFamily = (family: string | null) =>
      page.evaluate(
        async ({ storePath, value }) => {
          const mod = (await import(/* @vite-ignore */ storePath)) as {
            useUiStore: { getState: () => { setFontFamily: (f: string | null) => void } };
          };
          mod.useUiStore.getState().setFontFamily(value);
        },
        { storePath: UI_STORE, value: family },
      );

    await setFamily("Comic Sans MS");
    await expect.poll(async () => (await readVars()).ui).toContain("Comic Sans MS");
    expect((await readVars()).mono).toContain("Comic Sans MS");

    await setFamily(null);
    await expect.poll(async () => (await readVars()).ui).not.toContain("Comic Sans MS");
    expect((await readVars()).mono).not.toContain("Comic Sans MS");
  });
});

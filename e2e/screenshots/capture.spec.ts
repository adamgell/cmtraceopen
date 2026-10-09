/**
 * Repository screenshot harness.
 *
 * Captures the flagship workspaces into `screenshots/*.png` for the README and
 * wiki. Run it with `npm run screenshots` (see playwright.screenshots.config.ts).
 *
 * How data gets in
 * ----------------
 * The app runs in a plain browser at :1420 with the Tauri IPC shim
 * (e2e/fixtures/tauri-shim.ts). Every capture is fully mocked, never live:
 * requests to the IPC bridge (127.0.0.1:1422) are blocked, so a bridge started
 * by `npm run app:dev` anywhere on the machine cannot change what is captured.
 *
 *  - Log Viewer  -> the real open-file flow. `get_initial_file_paths` returns a
 *    synthetic Windows path and `open_log_file` returns a mock ParseResult, so
 *    the sidebar shows the synthetic path and the grid shows parsed rows. The
 *    readiness wait requires a parsed grid row, so an error state (for example
 *    "Source path is missing or inaccessible") can never be captured.
 *
 *  - Intune / DSRegCmd -> curated synthetic data injected straight into the live
 *    Vite store singletons (`await import("/src/...")` resolves to the same
 *    module instances the app uses). A real dsregcmd capture would bake the
 *    host's device + tenant identifiers into a committed public screenshot.
 *
 * Before every capture, `assertNoHostPaths` fails the run if the page text
 * shows the home directory, user name, host name or repo path.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "../fixtures";
import {
  DEMO_LOG_DISPLAY_PATH,
  MOCK_LOG_PARSE_RESULT,
  MOCK_INTUNE,
  MOCK_DSREGCMD,
} from "../fixtures/screenshot-data";
import {
  buildBaseEspSnapshot,
  buildDevicePreparationSnapshot,
  buildElevatedEspSnapshot,
} from "../fixtures/esp-diagnostics-data";
import type { EspDiagnosticsSnapshot } from "../../src/workspaces/esp-diagnostics/types";
import { assertNoHostPaths } from "../fixtures/host-path-guard";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.resolve(HERE, "..", "..", "screenshots");
const outPath = (name: string) => path.join(OUT_DIR, name);

async function dismissSplash(
  page: import("@playwright/test").Page,
): Promise<void> {
  await page.waitForSelector("#splash", { state: "detached", timeout: 15_000 });
}

/** Let virtual-scroll rows, fonts, and any mount transitions settle. */
async function settle(page: import("@playwright/test").Page): Promise<void> {
  await page.waitForTimeout(500);
}

async function showEspCapture(
  page: import("@playwright/test").Page,
  snapshot: EspDiagnosticsSnapshot,
  viewMode: "collapsed" | "docked" | "full",
  phase: "live" | "ready" = "live",
): Promise<void> {
  await page.evaluate(
    async ({ value, mode, workspacePhase }) => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const { useEspDiagnosticsStore } =
        await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
      useUiStore.getState().setActiveWorkspace("esp-diagnostics");
      useEspDiagnosticsStore.setState({
        phase: workspacePhase,
        requestId: "screenshot-esp",
        sessionId: workspacePhase === "live" ? "screenshot-session" : null,
        sequence: 1,
        snapshot: value,
        error: null,
        graphPhase: "disabled",
        graphUnavailableReason: "graphDisabled",
        graphError: null,
        evidenceViewMode: mode,
        unreadEvidenceCount:
          mode === "collapsed" ? value.rawEvidence.length : 0,
        evidenceBoundaryMarkers: [],
        evidenceRecordRows: new Map(),
        nextEvidenceOrder: 0,
      });
    },
    { value: snapshot, mode: viewMode, workspacePhase: phase },
  );
  await expect(
    page.getByRole("heading", { name: "ESP Diagnostics" }),
  ).toBeVisible({ timeout: 15_000 });
  if (viewMode === "collapsed") {
    await expect(
      page.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveCount(0);
  } else {
    await expect(
      page.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveAttribute("data-view-mode", viewMode);
  }
  await settle(page);
}

/** One row of a status-bar composite: a label and the bar captured as PNG. */
interface StatusBarStrip {
  label: string;
  png: Buffer;
}

/**
 * Puts the active workspace's global status bar into a given state and
 * captures just the 24px bar.
 */
async function captureStatusBar(
  page: import("@playwright/test").Page,
  state: {
    workspaceId: string;
    platform: string;
    /** The workspace renders lazy `statusBarContent` instead of the default. */
    hasStatusContent?: boolean;
    graphApiStatus?: string;
    filterError?: string;
    /** Text that proves the requested state has rendered. */
    expectText?: string;
  },
): Promise<Buffer> {
  await page.evaluate(async (next) => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    const { useFilterStore } = await import("/src/stores/filter-store.ts");
    useUiStore.setState({
      currentPlatform: next.platform as never,
      enabledWorkspaces: null,
      activeWorkspace: next.workspaceId as never,
      activeView: next.workspaceId as never,
      graphApiStatus: (next.graphApiStatus ?? "disconnected") as never,
    });
    useFilterStore.setState({ filterError: next.filterError ?? null });
  }, state);
  const bar = page.getByTestId("global-status-bar");
  await expect(bar).toHaveAttribute("data-workspace", state.workspaceId, {
    timeout: 15_000,
  });
  if (state.hasStatusContent) {
    // The Suspense fallback shows the default bar until the lazy content loads.
    await expect(
      bar.locator(`[data-status-content="${state.workspaceId}"]`),
    ).toBeVisible({ timeout: 15_000 });
  }
  if (state.expectText) {
    await expect(bar.getByText(state.expectText)).toBeVisible();
  }
  await assertNoHostPaths(page, "status bar");
  return bar.screenshot({ animations: "disabled" });
}

/** Stacks labelled status-bar strips into one PNG for side-by-side review. */
async function writeStatusBarComposite(
  page: import("@playwright/test").Page,
  themeLabel: string,
  strips: StatusBarStrip[],
  fileName: string,
): Promise<void> {
  const sheet = await page.context().newPage();
  const rows = strips
    .map(
      (strip) => `
        <div class="row">
          <div class="label">${strip.label}</div>
          <img src="data:image/png;base64,${strip.png.toString("base64")}" />
        </div>`,
    )
    .join("");
  await sheet.setContent(`
    <html>
      <body style="margin:0;padding:16px;background:#d0d0d0;font:13px 'Segoe UI',sans-serif;color:#000000">
        <h1 style="font-size:15px;margin:0 0 12px">Global status bar: ${themeLabel}</h1>
        <style>
          .row { display:flex; align-items:center; gap:12px; margin-bottom:8px; }
          .label { width:220px; flex-shrink:0; }
          img { width:1440px; height:24px; display:block; outline:1px solid #606060; }
        </style>
        ${rows}
      </body>
    </html>`);
  await assertNoHostPaths(sheet, fileName);
  await sheet.screenshot({ path: outPath(fileName), fullPage: true });
  await sheet.close();
}

test.describe("repo screenshots", () => {
  test.beforeEach(async ({ page }) => {
    await page.route("http://127.0.0.1:1422/**", (route) => route.abort());
  });

  test("log-viewer", async ({ page }) => {
    // Applied before the app boots; useFileAssociation() reads get_initial_file_paths
    // on mount and auto-opens the returned path through the real load pipeline.
    await page.addInitScript(
      ({ displayPath, mockResult }) => {
        const overrides =
          window.__e2e_ipc_overrides__ ?? (window.__e2e_ipc_overrides__ = {});
        overrides["get_initial_file_paths"] = () => [displayPath];
        overrides["open_log_file"] = () => mockResult;
      },
      {
        displayPath: DEMO_LOG_DISPLAY_PATH,
        mockResult: MOCK_LOG_PARSE_RESULT,
      },
    );

    await page.goto("/");
    await dismissSplash(page);

    // Readiness is a parsed grid row. The sidebar file name or an error notice
    // that mentions the file must not satisfy it.
    await expect(
      page.getByRole("option").filter({ hasText: "AppEnforce" }).first(),
    ).toBeVisible({ timeout: 15_000 });

    // Select the error row so the info pane shows entry details + the recognized
    // Windows error code. Best-effort — never fail the capture over selection.
    try {
      await page.getByText("0x80070643").first().click({ timeout: 3_000 });
    } catch {
      // No selectable error row in this data set — capture the list as-is.
    }

    await settle(page);
    await assertNoHostPaths(page);
    await page.screenshot({ path: outPath("log-viewer.png") });
  });

  test("intune-diagnostics", async ({ page }) => {
    await page.goto("/");
    await dismissSplash(page);

    await page.evaluate(async (mock) => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const { useIntuneStore } =
        await import("/src/workspaces/intune/intune-store.ts");
      useUiStore.getState().setActiveWorkspace("intune");
      useIntuneStore
        .getState()
        .setResults(
          mock.events as never,
          mock.downloads as never,
          mock.summary as never,
          mock.diagnostics as never,
          mock.sourceFile,
          mock.sourceFiles,
        );
    }, MOCK_INTUNE);

    // Timeline tab nav button appears once the populated dashboard renders.
    await expect(
      page.getByRole("button", { name: /Timeline/ }).first(),
    ).toBeVisible({
      timeout: 15_000,
    });

    await settle(page);
    await assertNoHostPaths(page);
    await page.screenshot({ path: outPath("intune-diagnostics.png") });
  });

  test("dsregcmd", async ({ page }) => {
    await page.goto("/");
    await dismissSplash(page);

    await page.evaluate(async (mock) => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const { useDsregcmdStore } =
        await import("/src/workspaces/dsregcmd/dsregcmd-store.ts");
      useUiStore.getState().setActiveWorkspace("dsregcmd");
      useDsregcmdStore
        .getState()
        .setResults(mock.rawInput, mock.result as never, mock.context as never);
    }, MOCK_DSREGCMD);

    await expect(page.getByText(/Microsoft Entra joined/).first()).toBeVisible({
      timeout: 15_000,
    });

    await settle(page);
    await assertNoHostPaths(page);
    await page.screenshot({ path: outPath("dsregcmd.png") });
  });

  for (const viewport of [
    { width: 1200, height: 800 },
    { width: 1440, height: 900 },
  ]) {
    test(`ESP Diagnostics ${viewport.width}x${viewport.height}`, async ({
      page,
    }) => {
      await page.setViewportSize(viewport);
      await page.goto("/");
      await dismissSplash(page);

      const elevated = buildElevatedEspSnapshot();
      await showEspCapture(page, elevated, "collapsed");
      await expect(page.getByLabel("ESP session summary")).toContainText(
        "3 / 3 sources",
      );
      await expect(
        page.getByRole("region", {
          name: "Administrator coverage recommendation",
        }),
      ).toHaveCount(0);
      await assertNoHostPaths(page);
      await page.screenshot({
        path: outPath(
          `esp-diagnostics-${viewport.width}x${viewport.height}-collapsed.png`,
        ),
        animations: "disabled",
      });

      await showEspCapture(page, elevated, "docked");
      await assertNoHostPaths(page);
      await page.screenshot({
        path: outPath(
          `esp-diagnostics-${viewport.width}x${viewport.height}-docked.png`,
        ),
        animations: "disabled",
      });

      await showEspCapture(page, elevated, "full");
      await assertNoHostPaths(page);
      await page.screenshot({
        path: outPath(
          `esp-diagnostics-${viewport.width}x${viewport.height}-full-logs.png`,
        ),
        animations: "disabled",
      });

      await showEspCapture(page, buildBaseEspSnapshot(), "collapsed", "ready");
      const recommendation = page.getByRole("region", {
        name: "Administrator coverage recommendation",
      });
      await expect(recommendation).toContainText(
        "2 restricted evidence sources are unavailable",
      );
      await expect(recommendation).not.toContainText(
        "MDM diagnostic event logs",
      );
      await assertNoHostPaths(page);
      await page.screenshot({
        path: outPath(
          `esp-diagnostics-${viewport.width}x${viewport.height}-non-elevated.png`,
        ),
        animations: "disabled",
      });

      const devicePreparation = buildDevicePreparationSnapshot();
      expect(devicePreparation.profile?.devicePreparation).not.toBeNull();
      expect(
        devicePreparation.workloads.map((workload) => workload.kind),
      ).toEqual([
        "devicePreparationWorkload",
        "platformScript",
        "scepCertificate",
      ]);
      expect(
        devicePreparation.activity.map((entry) => entry.title),
      ).not.toEqual(
        expect.arrayContaining([
          "VPN installer started",
          "Endpoint Security failed",
        ]),
      );
      expect(
        devicePreparation.rawEvidence.every(
          (record) =>
            record.provenance.sourceArtifactId === "device-preparation-v2",
        ),
      ).toBe(true);
      await showEspCapture(page, devicePreparation, "collapsed");
      await assertNoHostPaths(page);
      await page.screenshot({
        path: outPath(
          `esp-diagnostics-${viewport.width}x${viewport.height}-device-preparation.png`,
        ),
        animations: "disabled",
      });
    });
  }

  // Phase 0b (#826, spec section 8.18): every workspace's status bar in the
  // three themes the acceptance names. One composite per theme keeps the
  // review to three files instead of one strip per workspace and theme.
  for (const theme of [
    { id: "light", label: "Light" },
    { id: "dark", label: "Dark" },
    { id: "high-contrast", label: "High contrast" },
  ]) {
    test(`status bar ${theme.id}`, async ({ page }) => {
      await page.goto("/");
      await dismissSplash(page);

      const workspaces = await page.evaluate(async (themeId) => {
        const { useUiStore } = await import("/src/stores/ui-store.ts");
        const { workspaceRegistry } =
          await import("/src/workspaces/registry.ts");
        useUiStore.getState().setThemeId(themeId as never);
        return Array.from(workspaceRegistry.values()).map((ws) => {
          if (ws.platforms !== "all" && ws.platforms.length === 0) {
            throw new Error(`Workspace "${ws.id}" declares no platforms`);
          }
          return {
            id: ws.id,
            label: ws.label,
            hasStatusContent: Boolean(ws.statusBarContent),
            platform:
              ws.platforms === "all" ? "windows" : (ws.platforms[0] as string),
          };
        });
      }, theme.id);

      const strips: StatusBarStrip[] = [];
      for (const ws of workspaces) {
        strips.push({
          label: ws.label,
          png: await captureStatusBar(page, {
            workspaceId: ws.id,
            platform: ws.platform,
            hasStatusContent: ws.hasStatusContent,
          }),
        });
      }

      // States that only exist with data: the Graph API ring and a tone icon.
      strips.push({
        label: "Log, Graph API connected",
        png: await captureStatusBar(page, {
          workspaceId: "log",
          platform: "windows",
          graphApiStatus: "connected",
          expectText: "Graph API: Connected",
        }),
      });
      strips.push({
        label: "Log, filter error",
        png: await captureStatusBar(page, {
          workspaceId: "log",
          platform: "windows",
          filterError: "Invalid clause",
          expectText: "Filter error: Invalid clause",
        }),
      });

      await writeStatusBarComposite(
        page,
        theme.label,
        strips,
        `status-bar-${theme.id}.png`,
      );
    });
  }
});

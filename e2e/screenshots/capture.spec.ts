/**
 * Repository screenshot harness.
 *
 * Captures the flagship workspaces into `screenshots/*.png` for the README and
 * wiki. Run it with `npm run screenshots` (see playwright.screenshots.config.ts).
 *
 * How data gets in
 * ----------------
 * The app runs in a plain browser at :1420 with the Tauri IPC shim
 * (e2e/fixtures/tauri-shim.ts). Two population strategies are used:
 *
 *  - Log Viewer  → the real open-file flow. We override `get_initial_file_paths`
 *    to point at the committed demo CCM log. When the real Rust IPC bridge
 *    (:1422, started by `npm run app:dev`) is reachable, the genuine parser
 *    parses that file — otherwise we also override `open_log_file` with a mock
 *    ParseResult so the shot still works with no Rust build / in CI.
 *
 *  - Intune / DSRegCmd → curated synthetic data injected straight into the live
 *    Vite store singletons (`await import("/src/...")` resolves to the same
 *    module instances the app uses). Always mock: driving the real backend for
 *    these needs real IME logs / a real device capture, and a real dsregcmd
 *    capture would bake the host's device + tenant identifiers into a committed
 *    public screenshot.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "../fixtures";
import {
  DEMO_LOG_ABS_PATH,
  MOCK_LOG_PARSE_RESULT,
  MOCK_INTUNE,
  MOCK_DSREGCMD,
} from "../fixtures/screenshot-data";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.resolve(HERE, "..", "..", "screenshots");
const outPath = (name: string) => path.join(OUT_DIR, name);

/** Probe the real Rust IPC bridge started by `npm run app:dev`. */
async function bridgeIsUp(): Promise<boolean> {
  try {
    const res = await fetch("http://127.0.0.1:1422/", {
      signal: AbortSignal.timeout(700),
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function dismissSplash(page: import("@playwright/test").Page): Promise<void> {
  await page.waitForSelector("#splash", { state: "detached", timeout: 15_000 });
}

/** Let virtual-scroll rows, fonts, and any mount transitions settle. */
async function settle(page: import("@playwright/test").Page): Promise<void> {
  await page.waitForTimeout(500);
}

test.describe("repo screenshots", () => {
  test("log-viewer", async ({ page }) => {
    const live = await bridgeIsUp();
    if (!live) {
      console.log("[screenshots] IPC bridge (:1422) not detected — log view uses mock ParseResult.");
    } else {
      console.log("[screenshots] IPC bridge detected — log view parses the demo log via the real backend.");
    }

    // Applied before the app boots; useFileAssociation() reads get_initial_file_paths
    // on mount and auto-opens the returned path through the real load pipeline.
    await page.addInitScript(
      ({ demoPath, mockResult, useMock }) => {
        const overrides =
          window.__e2e_ipc_overrides__ ?? (window.__e2e_ipc_overrides__ = {});
        overrides["get_initial_file_paths"] = () => [demoPath];
        if (useMock) {
          overrides["open_log_file"] = () => mockResult;
        }
      },
      { demoPath: DEMO_LOG_ABS_PATH, mockResult: MOCK_LOG_PARSE_RESULT, useMock: !live }
    );

    await page.goto("/");
    await dismissSplash(page);

    // Wait for parsed rows to render (component cell is present in both modes).
    await expect(page.getByText("AppEnforce").first()).toBeVisible({ timeout: 15_000 });

    // Select the error row so the info pane shows entry details + the recognized
    // Windows error code. Best-effort — never fail the capture over selection.
    try {
      await page.getByText("0x80070643").first().click({ timeout: 3_000 });
    } catch {
      // No selectable error row in this data set — capture the list as-is.
    }

    await settle(page);
    await page.screenshot({ path: outPath("log-viewer.png") });
  });

  test("intune-diagnostics", async ({ page }) => {
    await page.goto("/");
    await dismissSplash(page);

    await page.evaluate(async (mock) => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const { useIntuneStore } = await import("/src/workspaces/intune/intune-store.ts");
      useUiStore.getState().setActiveWorkspace("intune");
      useIntuneStore
        .getState()
        .setResults(
          mock.events as never,
          mock.downloads as never,
          mock.summary as never,
          mock.diagnostics as never,
          mock.sourceFile,
          mock.sourceFiles
        );
    }, MOCK_INTUNE);

    // Timeline tab nav button appears once the populated dashboard renders.
    await expect(page.getByRole("button", { name: /Timeline/ }).first()).toBeVisible({
      timeout: 15_000,
    });

    await settle(page);
    await page.screenshot({ path: outPath("intune-diagnostics.png") });
  });

  test("dsregcmd", async ({ page }) => {
    await page.goto("/");
    await dismissSplash(page);

    await page.evaluate(async (mock) => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const { useDsregcmdStore } = await import(
        "/src/workspaces/dsregcmd/dsregcmd-store.ts"
      );
      useUiStore.getState().setActiveWorkspace("dsregcmd");
      useDsregcmdStore
        .getState()
        .setResults(mock.rawInput, mock.result as never, mock.context as never);
    }, MOCK_DSREGCMD);

    await expect(page.getByText(/Microsoft Entra joined/).first()).toBeVisible({
      timeout: 15_000,
    });

    await settle(page);
    await page.screenshot({ path: outPath("dsregcmd.png") });
  });
});

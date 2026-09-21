/**
 * macOS JAMF workspace end-to-end coverage (#314).
 *
 * The workspace shipped in 1.5.1 with fixture and unit coverage but nothing that
 * drives it in a browser — the other specs exercise the log view and a
 * diagnostic workspace, never JAMF. Two things make that harder than the
 * existing specs:
 *
 *  - It is gated to macOS twice: `platforms: ["macos"]` in the workspace
 *    registry (filtered against the `@tauri-apps/plugin-os` platform) and the
 *    `macos-diag` feature flag in `get_available_workspaces()`. This suite runs
 *    on Linux in CI, where the workspace is not in the dropdown at all.
 *    `@tauri-apps/plugin-os` reads its platform straight off
 *    `window.__TAURI_OS_PLUGIN_INTERNALS__.platform`, so an init script replaces
 *    the shim's "windows" value with "macos" and answers
 *    `get_available_workspaces` with the macOS build's allowlist. Only the gate
 *    and the backend commands are stubbed — the workspace components, its store
 *    and the log sidebar are the real ones.
 *
 *  - The `jamf_*` commands need a Rust build, which the E2E job does not have
 *    (see `.github/workflows/cmtrace-ci.yml`). They are answered from
 *    `e2e/fixtures/jamf-data.ts`, which encodes the committed JAMF fixture logs
 *    and their parser contracts.
 *
 * Not covered here, and not claimable from a browser: everything that depends on
 * real macOS APIs (`system_profiler`, `plutil`, Full Disk Access, the `jamf`
 * binary) and the run against a live JAMF-managed Mac.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";
import {
  DEMO_LOG_ABS_PATH,
  MOCK_LOG_PARSE_RESULT,
} from "./fixtures/screenshot-data";
import {
  JAMF_CONNECT_EVENTS,
  JAMF_ENVIRONMENT,
  JAMF_IPC_OVERRIDES,
  JAMF_LOG_SCAN,
  JAMF_POLICY_LOG,
  JAMF_PROFILES,
  MACOS_JAMF_WORKSPACES,
} from "./fixtures/jamf-data";

const DEMO_LOG_NAME = "ConfigMgr_AppEnforce_demo.log";

/** The page globals the Tauri IPC shim installs before the app boots. */
interface ShimmedWindow {
  __TAURI_OS_PLUGIN_INTERNALS__?: { platform?: string };
  __e2e_ipc_overrides__?: Record<string, () => unknown>;
}

async function dismissSplash(page: Page): Promise<void> {
  await page.waitForSelector("#splash", { state: "detached", timeout: 15_000 });
}

/**
 * Boots the app as a macOS build and loads the JAMF backend fixtures.
 *
 * The init script runs after the shim's (init scripts evaluate in the order they
 * are added), so it patches the platform the shim seeded — asserting that is
 * better than silently emulating nothing if that ever changes.
 */
async function openJamfApp(page: Page): Promise<void> {
  await page.addInitScript(
    ({ workspaces, overrides, logResult }) => {
      const shimmed = window as unknown as ShimmedWindow;
      const os = shimmed.__TAURI_OS_PLUGIN_INTERNALS__;
      const ipc = shimmed.__e2e_ipc_overrides__;
      if (!os || !ipc) {
        throw new Error("Tauri IPC shim must run before the JAMF init script");
      }

      os.platform = "macos";
      ipc["get_available_workspaces"] = () => workspaces;
      // Off-bridge (CI), the demo log comes from the same fixture the
      // screenshot harness uses; with a bridge the real parser would answer.
      ipc["open_log_file"] = () => logResult;
      for (const [command, value] of Object.entries(overrides)) {
        ipc[command] = () => value;
      }
    },
    {
      workspaces: MACOS_JAMF_WORKSPACES,
      overrides: JAMF_IPC_OVERRIDES,
      logResult: MOCK_LOG_PARSE_RESULT,
    },
  );

  await page.goto("/");
  await dismissSplash(page);
}

async function openJamfWorkspace(page: Page): Promise<void> {
  const workspace = page.getByRole("combobox", { name: "Workspace" });
  await workspace.click();
  await page.getByRole("option", { name: "macOS JAMF" }).click();
  // The JAMF tab strip exists only inside this workspace, so it is the cheapest
  // proof that the switch landed. (The status bar badge falls through to the raw
  // view id for this workspace, so it is no use as a label.)
  await expect(
    page.getByRole("tab", { name: "JAMF Connect", exact: true }),
  ).toBeVisible();
}

async function selectJamfTab(page: Page, name: string): Promise<void> {
  await page.getByRole("tab", { name, exact: true }).click();
}

test.describe("macOS JAMF workspace", () => {
  test("renders the environment and every tab from the JAMF data", async ({
    page,
  }) => {
    await openJamfApp(page);
    await openJamfWorkspace(page);

    // Overview is the landing tab, populated by `jamf_collect_environment`.
    await expect(page.getByText("JAMF detected")).toBeVisible();
    await expect(page.getByText(JAMF_ENVIRONMENT.summary)).toBeVisible();
    await expect(page.getByText("JAMF Pro")).toBeVisible();
    await expect(
      page.getByText(`JSS URL: ${JAMF_ENVIRONMENT.jssUrl}`),
    ).toBeVisible();
    await expect(
      page.getByText(`IdP: ${JAMF_ENVIRONMENT.jamfConnectIdp}`),
    ).toBeVisible();

    // Logs — `jamf_scan_logs`.
    await selectJamfTab(page, "Logs");
    await expect(page.getByText("JAMF Logs")).toBeVisible();
    await expect(
      page.getByText(`${JAMF_LOG_SCAN.files.length} file(s)`),
    ).toBeVisible();
    await expect(page.getByText("/var/log/jamf.log")).toBeVisible();

    // Policies — the parse of the committed jamf.log fixture.
    await selectJamfTab(page, "Policies");
    await expect(page.getByText("Policy events")).toBeVisible();
    await expect(
      page.getByText(
        `${JAMF_POLICY_LOG.events.length} event(s) · ${JAMF_POLICY_LOG.unparsedLines} unparsed · ${JAMF_POLICY_LOG.sourcePath}`,
      ),
    ).toBeVisible();
    await expect(
      page.getByRole("cell", { name: "Google Chrome Installer" }),
    ).toBeVisible();
    await expect(
      page.getByRole("cell", { name: "Recurring check-in" }).first(),
    ).toBeVisible();
    // Elapsed time is measured across the invocation, not reported by JAMF.
    await expect(page.getByRole("cell", { name: "25.0 s" })).toBeVisible();

    // Profiles — `jamf_filter_profiles`, then the shared payload drill-down.
    await selectJamfTab(page, "Profiles");
    await expect(page.getByText("JAMF-deployed profiles")).toBeVisible();
    await page
      .getByRole("button", {
        name: JAMF_PROFILES.profiles[0].profileDisplayName,
      })
      .click();
    await expect(page.getByText("Payloads (1)")).toBeVisible();
    await expect(
      page.getByText(JAMF_PROFILES.profiles[0].payloads[0].payloadIdentifier),
    ).toBeVisible();

    // Self Service — `jamf_parse_self_service_log`.
    await selectJamfTab(page, "Self Service");
    await expect(page.getByText("Self Service usage")).toBeVisible();
    await expect(page.getByRole("cell", { name: "triggerPolicy" }).first()).toBeVisible();
    await expect(page.getByRole("cell", { name: "doRecon" })).toBeVisible();

    // JAMF Connect — `jamf_parse_connect_log`.
    await selectJamfTab(page, "JAMF Connect");
    await expect(page.getByText("JAMF Connect events")).toBeVisible();
    await expect(
      page.getByText(`${JAMF_CONNECT_EVENTS.length} event(s)`),
    ).toBeVisible();
    // Connection timestamps carry their own offset, so they render verbatim.
    await expect(page.getByText(JAMF_CONNECT_EVENTS[0].timestamp)).toBeVisible();
    await expect(
      page.getByText(JAMF_CONNECT_EVENTS[3].message),
    ).toBeVisible();
  });

  test("loads a log into the JAMF workspace", async ({ page }) => {
    await openJamfApp(page);

    // The JAMF workspace keeps the standard log sidebar, so a log opens through
    // the real single-file pipeline (`loadFilesAsLogSource` → `open_log_file`).
    await page.evaluate(async (demoPath) => {
      // Inside the page, not the test process: the import must resolve through
      // the Vite dev server to reach the module instance the running app holds
      // (same technique as esp-diagnostics.spec.ts and log-view-fit.spec.ts).
      const { loadFilesAsLogSource } = await import("/src/lib/log-source.ts");
      await loadFilesAsLogSource([demoPath]);
    }, DEMO_LOG_ABS_PATH);

    // Opening a log takes the app to the log view (the tab it opens becomes
    // active), so the JAMF workspace is entered with that log loaded — which is
    // the state its sidebar has to carry.
    await openJamfWorkspace(page);
    await expect(page.getByText(`Selected: ${DEMO_LOG_NAME}`)).toBeVisible();
    await expect(
      page.getByText(`Loaded ${DEMO_LOG_NAME}.`).first(),
    ).toBeVisible();

    // A loaded log does not disable the workspace body.
    await selectJamfTab(page, "Policies");
    await expect(page.getByText("Policy events")).toBeVisible();
    await expect(
      page.getByRole("cell", { name: "Google Chrome Installer" }),
    ).toBeVisible();
  });
});

import { test, expect } from "./fixtures";
import { MACOS_JAMF_WORKSPACES } from "./fixtures/jamf-data";
import type { MacosDiagEnvironment } from "../src/workspaces/macos-diag/types";

// The ready-environment fixture from MacosDiagWorkspace.test.tsx. Native
// collection is stubbed; focus, keyboard activation and tab rendering are real.
const environment: MacosDiagEnvironment = {
  macosVersion: "15.3",
  macosBuild: "24D70",
  fullDiskAccess: "granted",
  tools: { profiles: true, mdatp: true, pkgutil: true, logCommand: true },
  directories: {
    intuneSystemLogs: true,
    intuneUserLogs: true,
    companyPortalLogs: true,
    intuneScriptsLogs: true,
    defenderLogs: true,
    defenderDiag: true,
  },
  summary: "macOS diagnostics ready",
};

test("macOS diagnostics tabs separate keyboard focus from activation", async ({ page }) => {
  await page.addInitScript(({ environment, workspaces }) => {
    const shimmed = window as unknown as {
      __TAURI_OS_PLUGIN_INTERNALS__: { platform: string };
      __e2e_ipc_overrides__: Record<string, () => unknown>;
    };
    shimmed.__TAURI_OS_PLUGIN_INTERNALS__.platform = "macos";
    const ipc = shimmed.__e2e_ipc_overrides__;
    ipc.get_available_workspaces = () => workspaces;
    ipc.macos_scan_environment = () => environment;
    ipc.macos_scan_intune_logs = () => ({
      files: [], scannedDirectories: [], totalSizeBytes: 0,
    });
    ipc.macos_list_profiles = () => ({
      profiles: [],
      enrollmentStatus: {
        enrolled: true, mdmServer: "https://manage.microsoft.com",
        enrollmentType: "Device", rawOutput: "",
      },
      rawOutput: "",
    });
  }, { environment, workspaces: MACOS_JAMF_WORKSPACES });

  await page.goto("/");
  await page.waitForSelector("#splash", { state: "detached" });
  await page.getByRole("combobox", { name: "Workspace" }).click();
  await page.getByRole("option", { name: "macOS Diagnostics" }).click();

  const first = page.getByRole("tab", { name: /Intune Logs/ });
  const profiles = page.getByRole("tab", { name: /Profiles & MDM/ });
  const last = page.getByRole("tab", { name: "Unified Log", exact: true });
  const list = page.getByRole("tablist").filter({ has: first });
  await expect(list.getByRole("tab")).toHaveCount(5);
  await expect(first).toHaveAttribute("aria-selected", "true");

  await first.focus();
  await page.keyboard.press("ArrowRight");
  await expect(profiles).toBeFocused();
  await expect(profiles).toHaveAttribute("aria-selected", "false");
  await expect(first).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("Enter");
  await expect(profiles).toHaveAttribute("aria-selected", "true");
  await expect(first).toHaveAttribute("aria-selected", "false");
  await expect(page.getByText(/Installed Configuration Profiles/)).toBeVisible();

  // End/Home and circular arrows move focus without selecting another body.
  await page.keyboard.press("End");
  await expect(last).toBeFocused();
  await expect(profiles).toHaveAttribute("aria-selected", "true");
  await page.keyboard.press("ArrowRight");
  await expect(first).toBeFocused();
  await page.keyboard.press("ArrowLeft");
  await expect(last).toBeFocused();
  await page.keyboard.press("Home");
  await expect(first).toBeFocused();
  await page.keyboard.press("Space");
  await expect(first).toHaveAttribute("aria-selected", "true");
  await expect(profiles).toHaveAttribute("aria-selected", "false");
  await expect(page.getByText("Discovered Log Files")).toBeVisible();

  await page.keyboard.press("Tab");
  await expect(list.locator(":focus")).toHaveCount(0);
  await page.keyboard.press("Shift+Tab");
  await expect(first).toBeFocused();
});

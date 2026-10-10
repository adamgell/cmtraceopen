import os from "node:os";
import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

/**
 * Dedicated config for the repository screenshot harness (`npm run screenshots`).
 *
 * Separate from playwright.config.ts so the capture run is opt-in: it writes
 * committed PNGs into `screenshots/` and must not run as part of `npm run test:e2e`.
 * The main e2e config ignores this directory (see `testIgnore` there).
 *
 * Captures are always fully mocked. The specs block the IPC bridge (:1422), so a
 * running `npm run app:dev` cannot change what is captured. Playwright reuses a
 * dev server already listening on :1420, so make sure it belongs to this checkout.
 */
export default defineConfig({
  testDir: "./e2e/screenshots",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: [["list"]],
  // Keep transient traces/artifacts out of the repo tree.
  outputDir: path.join(os.tmpdir(), "cmtrace-screenshots-artifacts"),

  use: {
    baseURL: "http://localhost:1420",
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
    trace: "off",
    video: "off",
    screenshot: "off",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 },
    },
  ],

  webServer: {
    command: "npm run frontend:dev",
    url: "http://localhost:1420",
    reuseExistingServer: true,
    timeout: 60_000,
  },
});

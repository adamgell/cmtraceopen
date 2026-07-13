import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  // The screenshot harness has its own opt-in config (playwright.screenshots.config.ts)
  // and writes committed PNGs, so it must not run as part of the normal e2e suite.
  testIgnore: "**/screenshots/**",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "html",

  use: {
    baseURL: "http://localhost:1420",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  // Auto-start the Vite dev server when running e2e tests.
  // If it's already running on :1420, Playwright re-uses it.
  webServer: {
    command: "npm run frontend:dev",
    url: "http://localhost:1420",
    reuseExistingServer: true,
    timeout: 30_000,
  },
});

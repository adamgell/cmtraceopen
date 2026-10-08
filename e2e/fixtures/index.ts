import { test as base, expect } from "@playwright/test";
import { TAURI_SHIM_SCRIPT } from "./tauri-shim";

/**
 * Extended Playwright `test` with the Tauri IPC shim pre-applied.
 *
 * Every test using this fixture automatically gets:
 *  - `window.__TAURI_INTERNALS__` stubbed before React loads
 *  - `window.__e2e_ipc_overrides__` available for per-test command overrides
 */
const test = base.extend({
  page: async ({ page }, use) => {
    if (process.env.CMTRACE_E2E_MOCK_ONLY === "1") {
      await page.route("http://127.0.0.1:1422/**", route => route.abort("connectionrefused"));
    }
    await page.addInitScript(TAURI_SHIM_SCRIPT);
    await use(page);
  },
});

export { test, expect };

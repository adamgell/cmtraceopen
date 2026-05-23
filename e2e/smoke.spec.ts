import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

async function openApp(page: Page) {
  await page.goto("/");
  await page.waitForSelector("#splash", { state: "detached", timeout: 10_000 });
}

test.describe("App smoke tests", () => {
  test("app loads at :1420 without JS errors", async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => consoleErrors.push(err.message));

    await openApp(page);

    const realErrors = consoleErrors.filter(
      (e) =>
        !e.includes("WebSocket") &&
        !e.includes("ws://") &&
        !e.includes("ERR_CONNECTION_REFUSED")
    );

    expect(realErrors, `Unexpected JS errors:
${realErrors.join("\n")}`).toHaveLength(0);
  });

  test("toolbar renders the Open button", async ({ page }) => {
    await openApp(page);
    await expect(page.getByRole("button", { name: "Open..." })).toBeVisible({ timeout: 10_000 });
  });

  test("workspace selector defaults to Log Explorer", async ({ page }) => {
    await openApp(page);
    await expect(page.getByRole("combobox", { name: "Workspace" })).toContainText("Log Explorer", { timeout: 10_000 });
  });

  test("log view is the default active workspace", async ({ page }) => {
    await openApp(page);
    await expect(page.getByText("Log view")).toBeVisible({ timeout: 10_000 });
  });

  test("page title is CMTrace Open", async ({ page }) => {
    await openApp(page);
    await expect(page).toHaveTitle("CMTrace Open");
  });
});

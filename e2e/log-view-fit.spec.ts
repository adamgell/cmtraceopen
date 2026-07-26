/**
 * Layout regression guard for #254 — "Log view opens with a horizontal scrollbar".
 *
 * These assertions cannot live in vitest: jsdom performs no layout, so
 * scrollWidth/clientWidth are always 0 there and a unit test can only check the
 * width arithmetic (see src/lib/column-config.test.ts). Real layout is the only
 * way to prove the acceptance criterion, so it is asserted in a real browser.
 *
 * Entries are injected straight into the live Vite store singletons — the same
 * technique the screenshot harness uses, where `await import("/src/...")`
 * resolves to the module instances the running app already holds.
 */
import { test, expect } from "./fixtures";

/** Comfortably wider than MAX_AUTOFIT_WIDTH (1200px) once rendered. */
const VERY_WIDE_MESSAGE =
  "Failed to install application: " +
  "C:\\Windows\\CCM\\Logs\\AppEnforce.log ".repeat(40) +
  "exit code 0x80070005";

async function seedWideLog(page: import("@playwright/test").Page, rows = 200) {
  await page.evaluate(
    async ({ message, count }) => {
      const { useLogStore } = await import("/src/stores/log-store.ts");
      const entries = Array.from({ length: count }, (_, index) => ({
        id: index + 1,
        lineNumber: index + 1,
        message: `${message} #${index}`,
        component: "AppEnforce",
        timestamp: 1_700_000_000_000 + index * 1000,
        timestampDisplay: "2026-07-26 12:00:00.000",
        severity: index % 7 === 0 ? "Error" : "Info",
        thread: "1234",
        threadDisplay: "1234",
        sourceFile: null,
        format: "Timestamped",
        filePath: "C:/Windows/CCM/Logs/AppEnforce.log",
        timezoneOffset: null,
      }));
      useLogStore.getState().setActiveColumns([
        "severity",
        "dateTime",
        "message",
        "component",
        "thread",
      ]);
      useLogStore.getState().setEntries(entries as never);
    },
    { message: VERY_WIDE_MESSAGE, count: rows },
  );

  // The auto-expand effect is debounced by 100ms and then writes a width.
  await page.waitForTimeout(400);
}

/** The virtualized log list container is the element that would scroll. */
const LIST = '[data-log-list="true"]';

async function overflow(page: import("@playwright/test").Page) {
  return page.evaluate((selector) => {
    const element = document.querySelector<HTMLElement>(selector);
    if (!element) return null;
    return {
      scrollWidth: element.scrollWidth,
      clientWidth: element.clientWidth,
    };
  }, LIST);
}

test.describe("log view fit-to-window (#254)", () => {
  test("opening a log with very wide lines does not overflow horizontally", async ({
    page,
  }) => {
    await page.goto("/");
    await page.waitForSelector("#splash", { state: "detached", timeout: 10_000 });
    await seedWideLog(page);

    await expect(page.locator(`${LIST} .log-row`).first()).toBeVisible({
      timeout: 10_000,
    });

    const metrics = await overflow(page);
    expect(metrics).not.toBeNull();
    // Allow a 1px rounding tolerance from fractional device pixels.
    expect(
      metrics!.scrollWidth,
      `log list overflows: scrollWidth=${metrics!.scrollWidth} clientWidth=${metrics!.clientWidth}`,
    ).toBeLessThanOrEqual(metrics!.clientWidth + 1);
  });

  test("a narrow window still opens without a horizontal scrollbar", async ({
    page,
  }) => {
    // Narrower than the 1200px auto-fit cap, which is the case that used to
    // guarantee an overflow.
    await page.setViewportSize({ width: 1024, height: 768 });
    await page.goto("/");
    await page.waitForSelector("#splash", { state: "detached", timeout: 10_000 });
    await seedWideLog(page);

    await expect(page.locator(`${LIST} .log-row`).first()).toBeVisible({
      timeout: 10_000,
    });

    const metrics = await overflow(page);
    expect(metrics).not.toBeNull();
    expect(
      metrics!.scrollWidth,
      `log list overflows at 1024px: scrollWidth=${metrics!.scrollWidth} clientWidth=${metrics!.clientWidth}`,
    ).toBeLessThanOrEqual(metrics!.clientWidth + 1);
  });

  test("double-click Fit can still widen a column past the viewport", async ({
    page,
  }) => {
    // The clamp must not remove the deliberate, user-initiated fit action:
    // acceptance criterion 3 keeps that working for people who want it.
    await page.goto("/");
    await page.waitForSelector("#splash", { state: "detached", timeout: 10_000 });
    await seedWideLog(page);

    await expect(page.locator(`${LIST} .log-row`).first()).toBeVisible({
      timeout: 10_000,
    });

    const before = await page.evaluate(async () => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      return useUiStore.getState().columnWidths.message ?? null;
    });

    // Double-clicking anywhere on the header triggers Fit for that column.
    const header = page
      .getByTitle("Double-click to auto-fit this column")
      .filter({ hasText: "Log Text" })
      .first();
    await expect(header).toBeVisible({ timeout: 10_000 });
    await header.dblclick();
    await page.waitForTimeout(200);

    const after = await page.evaluate(async () => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      return useUiStore.getState().columnWidths.message ?? null;
    });

    expect(after).not.toBeNull();
    expect(after).not.toBe(before);
  });
});

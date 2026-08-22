import { test, expect } from "./fixtures";

test("browser IPC rejects native-only and unknown commands", async ({
  page,
}) => {
  await page.goto("/");
  await page.waitForSelector("#splash", { state: "detached", timeout: 10_000 });

  const knownErrors = await page.evaluate(async () => {
    const { registerLogFileHandler, openWindowsDefaultApps } =
      await import("/src/lib/commands.ts");
    const capture = async (operation: () => Promise<void>) => {
      try {
        await operation();
        return null;
      } catch (error) {
        return error instanceof Error ? error.message : String(error);
      }
    };
    return Promise.all([
      capture(registerLogFileHandler),
      capture(openWindowsDefaultApps),
    ]);
  });
  expect(knownErrors).toEqual([
    "Command 'register_log_file_handler' failed.",
    "Command 'open_windows_default_apps' failed.",
  ]);

  const unknownError = await page.evaluate(async () => {
    try {
      await window.__TAURI_INTERNALS__.invoke("definitely_not_a_command");
      return null;
    } catch (error) {
      return error instanceof Error ? error.message : String(error);
    }
  });
  expect(unknownError).toContain("definitely_not_a_command");
});

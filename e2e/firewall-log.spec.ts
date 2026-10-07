import { test, expect } from "./fixtures";

test.beforeEach(async ({ page }) => {
  // This acceptance flow is entirely synthetic, even if a native bridge exists.
  await page.route("http://127.0.0.1:1422/**", route => route.abort());
  await page.goto("/");
  await page.waitForSelector("#splash", { state: "detached", timeout: 10_000 });
});

test("synthetic firewall open, raw fields, coverage, replacement and empty reset", async ({ page }) => {
  await page.evaluate(async () => {
    const { firewallSnapshot, firewallCoverage } = await import("/src/test-utils/firewall.ts");
    const { loadLogSource } = await import("/src/lib/log-source.ts");
    const snapshot = firewallSnapshot();
    snapshot.firewallCoverage = firewallCoverage({ padding: { count: "12", lines: [1] }, unplacedTimestamps: { count: "1", lines: [4] } });
    const testWindow = window as typeof window & { firewallControl?: unknown; copiedRaw?: string };
    window.__e2e_ipc_overrides__["open_log_file"] = () => snapshot;
    window.__e2e_ipc_overrides__["start_tail"] = (args: { firewallControl: unknown }) => { testWindow.firewallControl = args.firewallControl; };
    window.__e2e_ipc_overrides__["stop_tail"] = () => {};
    window.__e2e_ipc_overrides__["resume_tail"] = () => {};
    window.__e2e_ipc_overrides__["plugin:clipboard-manager|write_text"] = (args: { text: string }) => { testWindow.copiedRaw = args.text; };
    await loadLogSource({ kind: "file", path: snapshot.filePath });
  });
  const row = page.getByRole("option").filter({ hasText: "ALLOW TCP" });
  await expect(row).toBeVisible();
  await expect(row).toContainText("2042-04-05 06:07:09");
  await row.click();
  const fields = page.getByRole("region", { name: "Windows Firewall fields" });
  await expect(fields).toContainText("Local (source timezone unknown)");
  await expect(fields).toContainText("8801");
  await page.getByRole("button", { name: "Copy raw line", exact: true }).click();
  await expect.poll(() => page.evaluate(() => (window as typeof window & { copiedRaw?: string }).copiedRaw)).toBe("2042-04-05 06:07:09 ALLOW 192.0.2.11 203.0.113.21 8801");
  await expect(page.getByRole("status", { name: "Windows Firewall coverage" })).toContainText("12 NUL padding characters skipped");
  await expect.poll(() => page.evaluate(() => Boolean((window as typeof window & { firewallControl?: unknown }).firewallControl))).toBe(true);
  await page.evaluate(async () => {
    const { firewallEntry, firewallPayload, firewallCoverage } = await import("/src/test-utils/firewall.ts");
    const replacement = firewallEntry({ message: "DROP TCP 192.0.2.11 → 203.0.113.21" });
    replacement.firewall!.fields[2].value = "DROP";
    replacement.firewall!.rawLine = replacement.firewall!.rawLine.replace("ALLOW", "DROP");
    const control = (window as typeof window & { firewallControl: never }).firewallControl;
    const payload = firewallPayload({ firewallControl: control, firewallReplacements: [{ expectedId: 0, expectedLineNumber: 4, entry: replacement }], firewallCoverage: firewallCoverage({ unplacedTimestamps: { count: "1", lines: [4] } }) });
    window.__e2e_emit__("tail-new-entries", payload);
    window.__e2e_emit__("tail-new-entries", payload);
  });
  await expect(page.getByRole("option").filter({ hasText: "DROP TCP" })).toHaveCount(1);
  await expect(fields).toContainText("DROP");
  await page.evaluate(async () => {
    const { firewallPayload } = await import("/src/test-utils/firewall.ts");
    window.__e2e_emit__("tail-new-entries", firewallPayload({ firewallControl: (window as typeof window & { firewallControl: never }).firewallControl, reset: true, observedThroughLine: 0 }));
  });
  await expect(page.getByRole("option").filter({ hasText: "DROP TCP" })).toHaveCount(0);
  await expect(page.getByRole("status", { name: "Windows Firewall coverage" })).toHaveCount(0);
});

test("synthetic timeline exclusions and changed source stay visible until rebuild", async ({ page }) => {
  await page.evaluate(async () => {
    const { syntheticTimeline, firewallTimelineError } = await import("/src/test-utils/timeline.ts");
    const { openTimelineFiles } = await import("/src/workspaces/timeline/open-timeline-source.ts");
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    window.__e2e_ipc_overrides__["build_timeline_cmd"] = () => syntheticTimeline();
    window.__e2e_ipc_overrides__["query_lane_buckets_cmd"] = () => [];
    window.__e2e_ipc_overrides__["query_timeline_entries_cmd"] = () => { throw firewallTimelineError(); };
    await openTimelineFiles(["/synthetic/firewall.log"]);
    useUiStore.getState().setEnabledWorkspaces([...(useUiStore.getState().enabledWorkspaces ?? []), "timeline"]);
    useUiStore.getState().setActiveWorkspace("timeline");
  });
  await expect(page.getByText(/3 firewall records were excluded/)).toBeVisible();
  await expect(page.getByText("Source changed. Rebuild the timeline to continue.", { exact: true })).toBeVisible();
  await expect(page.getByText("Counts and lanes are stale until the timeline is rebuilt.")).toBeVisible();
  await page.evaluate(() => { window.__e2e_ipc_overrides__["query_timeline_entries_cmd"] = () => []; });
  await page.getByRole("button", { name: "Rebuild timeline", exact: true }).click();
  await expect(page.getByText("Source changed. Rebuild the timeline to continue.", { exact: true })).toHaveCount(0);
  await expect(page.getByText(/3 firewall records were excluded/)).toBeVisible();
});

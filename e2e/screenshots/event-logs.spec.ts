/**
 * Event Logs screenshot captures (`npm run screenshots -- -g event-logs`).
 *
 * Kept apart from capture.spec.ts so the two files can change independently. The `outPath` and
 * `dismissSplash` helpers below are copies of the ones there; consolidate them once both files
 * settle.
 *
 * Data path
 * ---------
 * The workspace is driven through its real file-open path: `openEventLogSource({ kind: "file" })`
 * calls `evtx_parse_files`, then the analysis pump calls the `evtx_*_analysis_*` commands. All of
 * them are answered by `window.__e2e_ipc_overrides__` with the synthetic dataset from
 * e2e/fixtures/event-log-data.ts, so no Rust backend and no real .evtx file is involved.
 *
 * These captures are the baseline of the CURRENT Event Logs UI.
 */
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test, expect } from "../fixtures";
import {
  buildEventLogFixture,
  EVENT_LOG_FIXTURE_PATHS,
} from "../fixtures/event-log-data";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.resolve(HERE, "..", "..", "screenshots");
const outPath = (name: string) => path.join(OUT_DIR, name);

async function dismissSplash(
  page: import("@playwright/test").Page,
): Promise<void> {
  await page.waitForSelector("#splash", { state: "detached", timeout: 15_000 });
}

// Timestamps render in local time; pin the zone and locale so the PNGs do not depend on the host.
test.use({ timezoneId: "UTC", locale: "en-US" });

test.describe("event-logs screenshots", () => {
  test.beforeEach(async ({ page }) => {
    const fixture = buildEventLogFixture();

    await page.addInitScript(
      ({ parseResult, items, diagnosis }) => {
        const overrides = window.__e2e_ipc_overrides__;
        const total = items.length;
        const status = (finalized: boolean) => ({
          sessionId: "fixture-session",
          revision: 1,
          totalItems: total,
          eventItems: total,
          logItems: 0,
          totalUnplaced: 0,
          totalEdges: 0,
          totalCoverageGaps: parseResult.coverageGaps?.length ?? 0,
          finalized,
        });
        overrides["evtx_parse_files"] = () => parseResult;
        overrides["evtx_create_analysis_session"] = () => status(false);
        overrides["evtx_append_analysis_chunk"] = () => status(false);
        overrides["evtx_finalize_analysis_session"] = () => status(true);
        overrides["evtx_query_analysis_timeline"] = (args: {
          offset: number;
          limit: number;
        }) => {
          const page = items.slice(args.offset, args.offset + args.limit);
          const next = args.offset + page.length;
          return {
            ...status(true),
            finalized: undefined,
            offset: args.offset,
            nextOffset: next < total ? next : null,
            serializedBytes: JSON.stringify(page).length,
            items: page,
            unplacedPreview: [],
            edgesPreview: [],
            coverageGapsPreview: (parseResult.coverageGaps ?? []).map((gap) => ({
              source: gap.source,
              reason: gap.reason,
            })),
          };
        };
        overrides["evtx_diagnose_analysis_session"] = () => diagnosis;
        overrides["evtx_close_analysis_session"] = () => null;
        // No saved markers for the fictional files.
        overrides["load_markers"] = () => null;
      },
      {
        parseResult: fixture.parseResult,
        items: fixture.timelineItems,
        diagnosis: fixture.diagnosis,
      },
    );

    await page.goto("/");
    await dismissSplash(page);

    await page.evaluate(async (paths) => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const { openEventLogSource } = await import(
        "/src/workspaces/event-log/open-event-log-source.ts"
      );
      useUiStore.getState().setActiveWorkspace("event-log");
      await openEventLogSource({ kind: "file", path: paths[0] });
    }, EVENT_LOG_FIXTURE_PATHS);

    // The grid, the diagnosis card and a loaded unified-timeline row all depend on the full
    // parse and analysis round trip, so together they mean the workspace has settled.
    await expect(
      page.getByRole("grid", {
        name: `Event log timeline - ${fixture.parseResult.records.length} records`,
      }),
    ).toBeVisible({ timeout: 15_000 });
    await expect(page.getByLabel("Operational diagnosis")).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByText("Loading timeline row")).toHaveCount(0);
  });

  test("event-logs table", async ({ page }) => {
    await expect(page.getByText("Select a record to view details.")).toHaveCount(0);
    await page.screenshot({
      path: outPath("event-logs-table.png"),
      animations: "disabled",
    });
  });

  test("event-logs selected record", async ({ page }) => {
    await page
      .getByRole("grid")
      .getByRole("row")
      .filter({ hasText: "Fault bucket 2187364520" })
      .first()
      .click();
    await expect(
      page.getByRole("region", { name: "Event log details" }),
    ).toContainText("Fault bucket 2187364520");
    await page.screenshot({
      path: outPath("event-logs-selected.png"),
      animations: "disabled",
    });
  });
});

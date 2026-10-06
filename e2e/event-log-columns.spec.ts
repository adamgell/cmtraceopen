import type { Page } from "@playwright/test";
import type { EvtxRecord } from "../src/workspaces/event-log/types";
import { expect, test } from "./fixtures";

// Event envelope from EventLogWorkspace.test.tsx; fields from the native
// parser's an_empty_field_still_holds_its_insertion_position fixture.
// This exercises the browser UI with normalized fixtures, not native parsing.
const wideRecord: EvtxRecord = {
  id: 1,
  eventRecordId: 101,
  timestamp: "2026-08-18T12:00:00Z",
  timestampEpoch: Date.parse("2026-08-18T12:00:00Z"),
  provider: "Example Provider",
  channel: "Application",
  eventId: 42,
  level: "Information",
  computer: "TEST-PC",
  message: "Example event message",
  eventData: [
    { name: "Data1", value: "alpha" },
    { name: "Data3", value: "gamma" },
  ],
  insertionStrings: ["alpha", "", "gamma"],
  rawXml: "<Event><EventData><Data>alpha</Data><Data></Data><Data>gamma</Data></EventData></Event>",
  sourceLabel: "sample.evtx",
};
const shortRecord: EvtxRecord = {
  ...wideRecord,
  id: 2,
  eventRecordId: 102,
  eventData: wideRecord.eventData.slice(0, 1),
  insertionStrings: ["alpha"],
  rawXml: "<Event><EventData><Data>alpha</Data></EventData></Event>",
};

async function loadRecords(page: Page, records: EvtxRecord[]) {
  await page.evaluate(async (rows) => {
    const { useEvtxStore } = await import("/src/workspaces/event-log/evtx-store.ts");
    useEvtxStore.setState({
      records: rows,
      channels: [{ name: "Application", eventCount: rows.length, sourceType: { file: { path: "sample.evtx" } } }],
      selectedChannels: new Set(["Application"]),
      loadedChannels: new Set(["Application"]),
      sourceMode: "files",
      timeWindow: "all",
      selectedRecordId: null,
    });
  }, records);
}

test("string columns survive narrower records, hiding and layout restoration", async ({ page, baseURL }, testInfo) => {
  // The shared shim can probe a native bridge. This test is fixture-only and
  // must never contact that bridge or any unrelated network service.
  const origin = new URL(baseURL!).origin;
  await page.route("**/*", (route) =>
    new URL(route.request().url()).origin === origin ? route.continue() : route.abort(),
  );
  await page.goto("/");
  await page.waitForSelector("#splash", { state: "detached" });
  await page.evaluate(async () => {
    window.__e2e_ipc_overrides__.load_markers = () => null;
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    useUiStore.getState().setActiveWorkspace("event-log");
  });
  await loadRecords(page, [wideRecord, shortRecord]);

  const chooser = page.getByTitle("Choose which columns the list shows.");
  const cells = page.getByRole("gridcell", { name: /^String 3:/ });
  await expect(cells).toHaveCount(0);
  await chooser.click();
  await page.getByRole("menuitemcheckbox", { name: "String 3", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("gridcell", { name: "String 3: gamma", exact: true })).toHaveText("gamma");
  await expect(page.getByRole("gridcell", { name: "String 3: Empty", exact: true })).toHaveText("");
  await chooser.click();
  await page.getByRole("menuitemcheckbox", { name: "String 2", exact: true }).click();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("gridcell", { name: "String 2: Empty", exact: true })).toHaveCount(2);
  await chooser.click();
  await page.getByRole("menuitemcheckbox", { name: "String 2", exact: true }).click();
  await page.keyboard.press("Escape");
  await testInfo.attach("string-column-and-short-record", { body: await page.screenshot(), contentType: "image/png" });

  // Exercise the actual visible-column quick filter against the enabled string.
  await page.getByRole("combobox", { name: "Quick filter column scope", exact: true }).click();
  await page.getByText("Visible columns", { exact: true }).click();
  await page.getByRole("textbox", { name: "Quick filter query", exact: true }).fill("gamma");
  await expect(page.getByRole("grid", { name: "Event log timeline - 1 records", exact: true })).toBeVisible();
  await expect(page.getByRole("gridcell", { name: "String 3: gamma", exact: true })).toBeVisible();
  await page.getByRole("textbox", { name: "Quick filter query", exact: true }).fill("");

  await loadRecords(page, [shortRecord]);
  await expect(cells).toHaveCount(1);
  await expect(cells).toHaveText("");
  await chooser.click();
  const stringOption = page.getByRole("menuitemcheckbox", { name: "String 3", exact: true });
  await expect(stringOption).toHaveAttribute("aria-checked", "true");
  await stringOption.click();
  await expect(cells).toHaveCount(0);
  await expect(stringOption).toBeVisible();
  await expect(stringOption).toHaveAttribute("aria-checked", "false");
  await page.keyboard.press("Escape");

  // Round-trip the supported configuration boundary. There is no claim here
  // that event-log column layouts persist automatically across app launches.
  const savedLayout = await page.evaluate(async () => {
    const { useEvtxStore } = await import("/src/workspaces/event-log/evtx-store.ts");
    return JSON.stringify(useEvtxStore.getState().columnConfig);
  });
  await page.getByRole("button", { name: "Reset columns", exact: true }).click();
  await page.evaluate(async (serialized) => {
    const { useEvtxStore } = await import("/src/workspaces/event-log/evtx-store.ts");
    const { sanitizeColumnConfig } = await import("/src/workspaces/event-log/evtx-columns.ts");
    useEvtxStore.setState({ columnConfig: sanitizeColumnConfig(JSON.parse(serialized)) });
  }, savedLayout);
  await chooser.click();
  await expect(stringOption).toBeVisible();
  await stringOption.click();
  await page.keyboard.press("Escape");
  await expect(cells).toHaveCount(1);
  await expect(cells).toHaveText("");
  await loadRecords(page, [{ ...shortRecord, insertionStrings: undefined }]);
  await expect(cells).toHaveText("Unavailable");
  await expect(cells).toHaveAttribute("title", "Insertion-string positions are unavailable for this record.");
  await page.getByRole("textbox", { name: "Quick filter query", exact: true }).fill("Unavailable");
  await expect(cells).toHaveCount(0);
  await page.getByRole("textbox", { name: "Quick filter query", exact: true }).fill("");
  await loadRecords(page, [wideRecord, shortRecord]);
  await expect(page.getByRole("gridcell", { name: "String 3: gamma", exact: true })).toHaveText("gamma");
  await page.getByRole("button", { name: "Reset columns", exact: true }).click();
  await expect(cells).toHaveCount(0);
});

import { test, expect } from "./fixtures";
import espFixture from "./fixtures/demo/esp-diagnostics.json" with { type: "json" };
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
} from "../src/workspaces/esp-diagnostics/types";

const baseSnapshot =
  espFixture.baseSnapshot as unknown as EspDiagnosticsSnapshot;
const fullGraph = espFixture.graph.full as unknown as EspGraphOverlay;

function cloneSnapshot(): EspDiagnosticsSnapshot {
  return structuredClone(baseSnapshot);
}

async function dismissSplash(
  page: import("@playwright/test").Page,
): Promise<void> {
  await page.waitForSelector("#splash", {
    state: "detached",
    timeout: 15_000,
  });
}

async function openEspWorkspace(
  page: import("@playwright/test").Page,
): Promise<void> {
  const workspace = page.getByRole("combobox", { name: "Workspace" });
  await workspace.click();
  await page.getByRole("option", { name: "ESP Diagnostics" }).click();
  await expect(
    page.getByRole("heading", { name: "ESP Diagnostics" }),
  ).toBeVisible();
}

async function showLiveSnapshot(
  page: import("@playwright/test").Page,
  snapshot: EspDiagnosticsSnapshot = cloneSnapshot(),
): Promise<void> {
  await page.evaluate(async (value) => {
    const { useEspDiagnosticsStore } =
      await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
    const store = useEspDiagnosticsStore.getState();
    store.beginLiveStart("e2e-live");
    store.applySessionUpdate({
      sessionId: "session-live",
      requestId: "e2e-live",
      sequence: 1,
      state: "live",
      reason: "initialSnapshot",
      emittedAtUtc: value.generatedAtUtc,
      snapshot: value,
    });
  }, snapshot);
}

test.describe("ESP Diagnostics workspace", () => {
  test("is exposed by the browser shim and uses the full-width app chrome", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);

    const workspace = page.getByRole("combobox", { name: "Workspace" });
    await workspace.click();
    await expect(
      page.getByRole("option", { name: "ESP Diagnostics" }),
    ).toBeVisible();

    await page.getByRole("option", { name: "ESP Diagnostics" }).click();
    await expect(
      page.getByRole("heading", { name: "ESP Diagnostics" }),
    ).toBeVisible();
    await expect(
      page.getByRole("complementary", { name: "Source files" }),
    ).toHaveCount(0);
    await expect(
      page.getByRole("button", { name: "Expand sidebar" }),
    ).toHaveCount(0);
  });

  test("renders actionable local ESP, MSIEXEC, workload, activity, and admin evidence", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await openEspWorkspace(page);
    await showLiveSnapshot(page);

    await expect(
      page.getByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: "Restart as administrator" }),
    ).toBeVisible();
    await expect(
      page.getByRole("region", { name: "What MSIEXEC is doing now" }),
    ).toContainText("PID 8044");
    await expect(
      page.getByText("Required security application is blocking ESP"),
    ).toBeVisible();
    await expect(page.getByText("Contoso Endpoint Security")).toBeVisible();
    await expect(
      page.getByRole("region", { name: "Live activity" }),
    ).toContainText("VPN installer started");
    await expect(
      page
        .getByText("66666666-6666-4666-8666-666666666666", {
          exact: true,
        })
        .first(),
    ).toBeVisible();
  });

  test("keeps live evidence collapsed, collecting, resizable, full-page, filterable, and persistent", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await openEspWorkspace(page);
    await showLiveSnapshot(page);

    const openLogs = page.getByRole("button", { name: /^Open live logs,/ });
    await expect(openLogs).toBeVisible();
    await expect(
      page.getByRole("region", { name: "Live evidence and logs" }),
    ).toHaveCount(0);

    await openLogs.click();
    const dock = page.getByRole("region", { name: "Live evidence and logs" });
    await expect(dock).toHaveAttribute("data-view-mode", "docked");
    await expect(
      page.getByText("MSI action InstallFiles returned success"),
    ).toBeVisible();

    const sourceFilter = page.getByRole("combobox", {
      name: "Filter live evidence by source",
    });
    await sourceFilter.selectOption("msi-contoso-vpn");
    await expect(
      page.getByText("MSI action InstallFiles returned success"),
    ).toBeVisible();
    await expect(page.getByText(/Win32 app enforcement started/)).toHaveCount(
      0,
    );

    const separator = page.getByRole("separator", {
      name: "Resize live evidence and logs",
    });
    const initialHeight = Number(await separator.getAttribute("aria-valuenow"));
    await separator.press("ArrowUp");
    await expect(separator).toHaveAttribute(
      "aria-valuenow",
      String(initialHeight + 24),
    );

    await page.getByRole("button", { name: "Expand live logs" }).click();
    await expect(dock).toHaveAttribute("data-view-mode", "full");
    await page
      .getByRole("button", { name: "Restore docked live logs" })
      .click();
    await expect(dock).toHaveAttribute("data-view-mode", "docked");
    await page.getByRole("button", { name: "Close live logs" }).click();

    await page.evaluate(async () => {
      const { useEspDiagnosticsStore } =
        await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
      const state = useEspDiagnosticsStore.getState();
      if (!state.snapshot) throw new Error("missing e2e ESP snapshot");
      const added = {
        ...state.snapshot.rawEvidence[0],
        recordId: "raw-ime-after-rotation",
        rawValue: { text: "IME log continued after bounded source rotation" },
        observedAtUtc: "2026-07-15T20:09:00Z",
      };
      state.applySessionUpdate({
        sessionId: "session-live",
        requestId: "e2e-live",
        sequence: 2,
        state: "live",
        reason: "sourceReset",
        emittedAtUtc: "2026-07-15T20:09:00Z",
        snapshot: {
          ...state.snapshot,
          generatedAtUtc: "2026-07-15T20:09:00Z",
          rawEvidence: [...state.snapshot.rawEvidence, added],
        },
      });
    });

    await expect(
      page.getByRole("button", { name: /4 evidence records, 1 unread/ }),
    ).toBeVisible();

    const workspace = page.getByRole("combobox", { name: "Workspace" });
    await workspace.click();
    await page.getByRole("option", { name: "Log Explorer" }).click();
    await workspace.click();
    await page.getByRole("option", { name: "ESP Diagnostics" }).click();
    await expect(
      page.getByRole("button", { name: /4 evidence records, 1 unread/ }),
    ).toBeVisible();

    await page.getByRole("button", { name: /^Open live logs,/ }).click();
    await expect(
      page.getByText("IME log continued after bounded source rotation"),
    ).toBeVisible();
    await expect(
      page.getByRole("cell", { name: "Source reset", exact: true }),
    ).toBeVisible();
  });

  test("imports a sanitized captured bundle through the production workspace flow", async ({
    page,
  }) => {
    const imported = cloneSnapshot();
    imported.scenario = "espOnly";
    imported.phase = "unknown";
    imported.elevation = {
      isElevated: true,
      restartSupported: true,
      restrictedSources: [],
    };

    await page.goto("/");
    await dismissSplash(page);
    await page.evaluate((snapshot) => {
      window.__e2e_ipc_overrides__["plugin:dialog|open"] = () =>
        "C:\\Evidence\\esp-demo.zip";
      window.__e2e_ipc_overrides__["analyze_esp_evidence"] = () => snapshot;
    }, imported);
    await openEspWorkspace(page);

    await page
      .getByRole("button", { name: "Import captured evidence" })
      .click();
    await expect(page.getByText("ESP only")).toBeVisible();
    await expect(page.getByText("Contoso Endpoint Security")).toBeVisible();
    await expect(
      page.getByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).toHaveCount(0);
  });

  test("starts and stops a live session through the typed IPC contract", async ({
    page,
  }) => {
    const snapshot = cloneSnapshot();
    snapshot.elevation.isElevated = true;
    snapshot.elevation.restrictedSources = [];

    await page.goto("/");
    await dismissSplash(page);
    await page.evaluate((value) => {
      window.__e2e_ipc_overrides__["start_esp_diagnostics_session"] = (args: {
        requestId: string;
      }) => ({
        sessionId: "session-from-ipc",
        requestId: args.requestId,
        sequence: 0,
        state: "live",
        snapshot: value,
      });
      window.__e2e_ipc_overrides__["stop_esp_diagnostics_session"] = () => null;
    }, snapshot);
    await openEspWorkspace(page);

    await page.getByRole("button", { name: "Start live diagnostics" }).click();
    await expect(
      page.getByRole("button", { name: "Stop live diagnostics" }),
    ).toBeVisible();
    await expect(page.getByText("Live session", { exact: true })).toBeVisible();

    await page.getByRole("button", { name: "Stop live diagnostics" }).click();
    await expect(
      page.getByRole("button", { name: "Start live diagnostics" }),
    ).toBeVisible();
    await expect(page.getByTitle("Analysis ready")).toBeVisible();
  });

  test("keeps raw local IDs visible while Graph adds a friendly name", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await page.evaluate((overlay) => {
      window.__e2e_ipc_overrides__["graph_fetch_esp_diagnostics"] = (args: {
        request: { requestId: string };
      }) => ({ ...overlay, requestId: args.request.requestId });
    }, fullGraph);
    await openEspWorkspace(page);

    await page.evaluate(
      async ({ snapshot, overlay }) => {
        const { useUiStore } = await import("/src/stores/ui-store.ts");
        useUiStore.setState({
          graphApiEnabled: true,
          graphApiStatus: "connected",
        });
        const { useEspDiagnosticsStore } =
          await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
        const store = useEspDiagnosticsStore.getState();
        store.beginAnalysis("e2e-graph-local");
        store.applyAnalysis("e2e-graph-local", snapshot);
        store.beginGraph(overlay.requestId);
        store.applyGraphOverlay(overlay.requestId, overlay);
      },
      { snapshot: cloneSnapshot(), overlay: fullGraph },
    );

    await expect(page.getByText("Contoso VPN Client from Graph")).toBeVisible();
    await expect(
      page
        .getByText("66666666-6666-4666-8666-666666666666", {
          exact: true,
        })
        .first(),
    ).toBeVisible();
    await expect(page.getByText("Graph ready")).toBeVisible();
  });

  test("rejects accidental live Graph IPC when no explicit fixture is installed", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);

    const message = await page.evaluate(async () => {
      try {
        await window.__TAURI_INTERNALS__.invoke(
          "graph_fetch_esp_diagnostics",
          {},
        );
        return "unexpected success";
      } catch (error) {
        return error instanceof Error ? error.message : String(error);
      }
    });

    expect(message).toContain("rejected live ESP Graph command");
  });
});

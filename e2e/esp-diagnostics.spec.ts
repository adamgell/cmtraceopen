import { test, expect } from "./fixtures";
import espFixture from "./fixtures/demo/esp-diagnostics.json" with { type: "json" };
import {
  buildBaseEspSnapshot,
  buildDevicePreparationSnapshot,
  buildElevatedEspSnapshot,
  buildSparseBundleSnapshot,
} from "./fixtures/esp-diagnostics-data";
import type {
  EspDiagnosticsSnapshot,
  EspGraphOverlay,
  EspGraphRequest,
  EspInstallerCorrelation,
} from "../src/workspaces/esp-diagnostics/types";

const fullGraph = espFixture.graph.full as unknown as EspGraphOverlay;
const partialGraph = espFixture.graph.partial as unknown as EspGraphOverlay;
const ambiguousMsi = espFixture.variants
  .ambiguousMsi as unknown as EspInstallerCorrelation;

const evidenceSections = [
  ["identity-profile", "Identity and profile"],
  ["oobe-flags", "OOBE flags"],
  ["esp-configuration", "ESP configuration"],
  ["enrollment-sessions", "Enrollment and sessions"],
  ["apps", "Apps"],
  ["scripts", "Scripts"],
  ["policies", "Policies"],
  ["certificates", "Certificates"],
  ["join-registration", "Join and registration"],
  ["delivery-optimization", "Delivery Optimization"],
  ["hardware", "Hardware"],
  ["node-cache", "NodeCache"],
  ["source-coverage", "Source coverage"],
  ["raw-provenance", "Raw provenance"],
] as const;

function cloneSnapshot(): EspDiagnosticsSnapshot {
  return buildBaseEspSnapshot();
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

async function installGraphFixture(
  page: import("@playwright/test").Page,
  overlay: EspGraphOverlay | null,
  failureMessage: string | null = null,
): Promise<void> {
  await page.evaluate(
    ({ value, failure }) => {
      const testWindow = window as typeof window & {
        __e2e_esp_graph_requests__: EspGraphRequest[];
      };
      testWindow.__e2e_esp_graph_requests__ = [];
      window.__e2e_ipc_overrides__["graph_fetch_esp_diagnostics"] = (args: {
        request: EspGraphRequest;
      }) => {
        testWindow.__e2e_esp_graph_requests__.push(args.request);
        if (failure) throw new Error(failure);
        if (!value) throw new Error("missing deterministic Graph fixture");
        return { ...value, requestId: args.request.requestId };
      };
    },
    { value: overlay, failure: failureMessage },
  );
}

async function analyzeWithConnectedGraph(
  page: import("@playwright/test").Page,
  snapshot: EspDiagnosticsSnapshot,
): Promise<void> {
  await expect
    .poll(() =>
      page.evaluate(async () => {
        const { useUiStore } = await import("/src/stores/ui-store.ts");
        return useUiStore.persist.hasHydrated();
      }),
    )
    .toBe(true);
  await page.evaluate(async (value) => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    const ui = useUiStore.getState();
    ui.setGraphApiEnabled(true);
    ui.setGraphApiStatus("connected");
    const { useEspDiagnosticsStore } =
      await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
    const store = useEspDiagnosticsStore.getState();
    store.beginAnalysis("e2e-graph-local");
    store.applyAnalysis("e2e-graph-local", value);
  }, snapshot);
}

async function graphRequests(
  page: import("@playwright/test").Page,
): Promise<EspGraphRequest[]> {
  return page.evaluate(() => {
    const testWindow = window as typeof window & {
      __e2e_esp_graph_requests__: EspGraphRequest[];
    };
    return testWindow.__e2e_esp_graph_requests__;
  });
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
      page.getByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).toContainText("2 restricted evidence sources are unavailable");
    await expect(
      page.getByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).not.toContainText("MDM diagnostic event logs");
    const msiexec = page.getByRole("region", {
      name: "What MSIEXEC is doing now",
    });
    await expect(msiexec).toContainText("PID 8044");
    await expect(msiexec).toContainText("Exact match");
    await expect(msiexec).toContainText(
      "MSI log path and product code match the active workload.",
    );
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

  test("applies live phase and activity updates without replacing the workspace", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await openEspWorkspace(page);
    await showLiveSnapshot(page);

    const progress = page.getByRole("region", { name: "ESP phase progress" });
    await expect(progress).toContainText("Device setup · Current");
    const workspaceRoot = page.locator("main.esp-diagnostics-workspace");
    const mountedWorkspace = await workspaceRoot.elementHandle();
    if (!mountedWorkspace) throw new Error("missing mounted ESP workspace");

    await page.evaluate(async () => {
      const { useEspDiagnosticsStore } =
        await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
      const state = useEspDiagnosticsStore.getState();
      if (!state.snapshot) throw new Error("missing e2e ESP snapshot");
      const next = structuredClone(state.snapshot);
      next.generatedAtUtc = "2026-07-15T20:09:30Z";
      next.phase = "accountSetup";
      next.sessions = next.sessions.map((session) =>
        session.isLatest ? { ...session, phase: "accountSetup" } : session,
      );
      next.activity = [
        {
          ...next.activity[0],
          entryId: "activity-account-setup",
          timestamp: {
            rawText: "2026-07-15T20:09:30Z",
            originalOffset: "+00:00",
            normalizedUtc: "2026-07-15T20:09:30Z",
            kind: "utc",
          },
          title: "Account setup workload evaluation started",
          detail: "The live session advanced without remounting the workspace.",
        },
        ...next.activity,
      ];
      state.applySessionUpdate({
        sessionId: "session-live",
        requestId: "e2e-live",
        sequence: 2,
        state: "live",
        reason: "evidenceChanged",
        emittedAtUtc: next.generatedAtUtc,
        snapshot: next,
      });
    });

    await expect(progress).toContainText("Device setup · Complete");
    await expect(progress).toContainText("Account setup · Current");
    await expect(
      page.getByRole("region", { name: "Live activity" }),
    ).toContainText("Account setup workload evaluation started");
    await expect(page.getByText("Live session", { exact: true })).toBeVisible();
    expect(
      await page.evaluate(
        (original) =>
          document.querySelector("main.esp-diagnostics-workspace") === original,
        mountedWorkspace,
      ),
    ).toBe(true);
  });

  test("drills an actionable finding into canonical evidence and exposes every evidence section", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await openEspWorkspace(page);
    await showLiveSnapshot(page);

    for (const [sectionId, title] of evidenceSections) {
      const summary = page.locator(
        `#esp-evidence-section-${sectionId} > summary`,
      );
      await expect(summary).toContainText(title);
    }

    await page
      .getByRole("link", { name: "Open evidence ev-workload-security" })
      .first()
      .click();
    await expect(page.locator("#esp-evidence-section-apps")).toHaveAttribute(
      "open",
      "",
    );
    const canonicalEvidence = page.locator("#evidence-ev-workload-security");
    await expect(canonicalEvidence).toBeVisible();
    await expect(canonicalEvidence).toBeFocused();
  });

  test("renders a sampled ambiguous MSIEXEC correlation without guessing a workload", async ({
    page,
  }) => {
    const snapshot = cloneSnapshot();
    snapshot.installerCorrelations = [structuredClone(ambiguousMsi)];

    await page.goto("/");
    await dismissSplash(page);
    await openEspWorkspace(page);
    await showLiveSnapshot(page, snapshot);

    const msiexec = page.getByRole("region", {
      name: "What MSIEXEC is doing now",
    });
    await expect(msiexec).toContainText("PID 9055");
    await expect(msiexec).toContainText("Ambiguous — 2 candidates");
    await expect(msiexec).toContainText(
      "Two active workloads overlap the sampled installer window.",
    );
    await expect(msiexec).toContainText("Unknown installer workload");
  });

  test("presents Device Preparation phases with mixed workload kinds", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await openEspWorkspace(page);
    await showLiveSnapshot(page, buildDevicePreparationSnapshot());

    await expect(page.getByLabel("ESP session summary")).toContainText(
      "Autopilot Device Preparation",
    );
    const progress = page.getByRole("region", { name: "ESP phase progress" });
    await expect(progress).toContainText("Device Preparation phases");
    await expect(progress).toContainText("Agent bootstrap · Current");
    const workloads = page.getByRole("region", { name: "Tracked workloads" });
    await expect(workloads).toContainText("Device Preparation workload");
    await expect(workloads).toContainText("Platform script");
    await expect(workloads).toContainText("SCEP certificate");
    const activity = page.getByRole("region", { name: "Live activity" });
    await expect(activity).toContainText("Device Preparation bootstrap");
    await expect(activity).not.toContainText("VPN installer started");
    await expect(activity).not.toContainText("Endpoint Security failed");

    const scenarioFacts = await page.evaluate(async () => {
      const { useEspDiagnosticsStore } =
        await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
      const snapshot = useEspDiagnosticsStore.getState().snapshot;
      if (!snapshot) throw new Error("missing Device Preparation snapshot");
      return {
        identity: snapshot.identity,
        rawSources: snapshot.rawEvidence.map(
          (record) => record.provenance.sourceArtifactId,
        ),
        coverageFamilies: snapshot.coverage.map((source) => source.family),
        deliveryOptimization: snapshot.deliveryOptimization,
        hardware: snapshot.hardware,
      };
    });
    expect(scenarioFacts.identity).toEqual({
      deviceName: null,
      managedDeviceId: null,
      entraDeviceId: null,
      entdmId: null,
      tenantId: null,
      tenantDomain: null,
      userPrincipalName: null,
      serialNumber: null,
      evidence: [],
    });
    expect(scenarioFacts.rawSources).toEqual([
      "device-preparation-v2",
      "device-preparation-v2",
      "device-preparation-v2",
    ]);
    expect(scenarioFacts.coverageFamilies).toEqual(["Device Preparation v2"]);
    expect(scenarioFacts.deliveryOptimization).toBeNull();
    expect(scenarioFacts.hardware).toBeNull();
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
    await expect(page.getByText("Live session", { exact: true })).toBeVisible();

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
    const imported = buildElevatedEspSnapshot();
    imported.scenario = "espOnly";
    imported.phase = "unknown";

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

  test("keeps a sparse ESP-only bundle useful when IME text logs are absent", async ({
    page,
  }) => {
    const imported = buildSparseBundleSnapshot();

    await page.goto("/");
    await dismissSplash(page);
    await page.evaluate((snapshot) => {
      window.__e2e_ipc_overrides__["plugin:dialog|open"] = () =>
        "C:\\Evidence\\esp-sparse-demo.zip";
      window.__e2e_ipc_overrides__["analyze_esp_evidence"] = () => snapshot;
    }, imported);
    await openEspWorkspace(page);

    await page
      .getByRole("button", { name: "Import captured evidence" })
      .click();
    await expect(page.getByText("ESP only")).toBeVisible();
    await expect(
      page.getByText("No workload records were observed"),
    ).toBeVisible();

    await page
      .locator("#esp-evidence-section-source-coverage > summary")
      .click();
    const coverage = page.locator("#esp-evidence-section-source-coverage");
    await expect(coverage).toContainText("Autopilot profile JSON");
    await expect(coverage).toContainText("IME logs");
    await expect(coverage).toContainText("No IME text logs were present");

    await page
      .locator("#esp-evidence-section-raw-provenance > summary")
      .click();
    await expect(
      page.getByText("Captured Autopilot profile remains available"),
    ).toBeVisible();

    const sparseFacts = await page.evaluate(async () => {
      const { useEspDiagnosticsStore } =
        await import("/src/workspaces/esp-diagnostics/esp-diagnostics-store.ts");
      const snapshot = useEspDiagnosticsStore.getState().snapshot;
      if (!snapshot) throw new Error("missing sparse ESP snapshot");
      return {
        identity: snapshot.identity,
        deliveryOptimization: snapshot.deliveryOptimization,
        hardware: snapshot.hardware,
        rawSources: snapshot.rawEvidence.map(
          (record) => record.provenance.sourceArtifactId,
        ),
      };
    });
    expect(sparseFacts.identity).toEqual({
      deviceName: null,
      managedDeviceId: null,
      entraDeviceId: null,
      entdmId: null,
      tenantId: null,
      tenantDomain: null,
      userPrincipalName: null,
      serialNumber: null,
      evidence: [],
    });
    expect(sparseFacts.deliveryOptimization).toBeNull();
    expect(sparseFacts.hardware).toBeNull();
    expect(sparseFacts.rawSources).toEqual(["captured-profile"]);
    await expect(
      page.locator("#esp-evidence-section-delivery-optimization > summary"),
    ).toContainText(/No records/i);
    await expect(
      page.locator("#esp-evidence-section-hardware > summary"),
    ).toContainText(/No records/i);
  });

  test("starts and stops a live session through the typed IPC contract", async ({
    page,
  }) => {
    const snapshot = buildElevatedEspSnapshot();

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
    await expect(page.getByLabel("ESP session summary")).toContainText(
      "3 / 3 sources",
    );
    await expect(
      page.getByRole("region", {
        name: "Administrator coverage recommendation",
      }),
    ).toHaveCount(0);
    await page
      .locator("#esp-evidence-section-source-coverage > summary")
      .click();
    await expect(
      page.locator("#esp-evidence-section-source-coverage"),
    ).not.toContainText("Administrator rights required");

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
    await installGraphFixture(page, fullGraph);
    await openEspWorkspace(page);
    await analyzeWithConnectedGraph(page, cloneSnapshot());

    await expect(
      page.getByText("Contoso VPN Client from Graph", { exact: true }),
    ).toBeVisible();
    await expect(
      page
        .getByText("66666666-6666-4666-8666-666666666666", {
          exact: true,
        })
        .first(),
    ).toBeVisible();
    await expect(page.getByText("Graph ready")).toBeVisible();
    await expect.poll(async () => (await graphRequests(page)).length).toBe(1);
    expect((await graphRequests(page))[0]?.workloadIds).toEqual([
      "66666666-6666-4666-8666-666666666666",
      "77777777-7777-4777-8777-777777777777",
    ]);
  });

  test("preserves local findings and raw IDs when Graph enrichment is partial", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await installGraphFixture(page, partialGraph);
    await openEspWorkspace(page);
    await analyzeWithConnectedGraph(page, cloneSnapshot());

    await expect(page.getByText("Graph partial")).toBeVisible();
    await expect(
      page.getByText("Required security application is blocking ESP"),
    ).toBeVisible();
    await expect(
      page
        .getByText("66666666-6666-4666-8666-666666666666", {
          exact: true,
        })
        .first(),
    ).toBeVisible();
    await page.getByRole("button", { name: /^Open live logs,/ }).click();
    await expect(
      page.getByText(
        "Win32 app enforcement started for 66666666-6666-4666-8666-666666666666",
      ),
    ).toBeVisible();
    await expect.poll(async () => (await graphRequests(page)).length).toBe(1);
  });

  test("rejects accidental Graph IPC and preserves local evidence on transport failure", async ({
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

    await installGraphFixture(
      page,
      null,
      "Deterministic Graph transport failed",
    );
    await openEspWorkspace(page);
    await analyzeWithConnectedGraph(page, cloneSnapshot());

    await expect(page.getByText("Graph error", { exact: true })).toBeVisible();
    await expect(
      page.getByRole("alert", { name: "Graph enrichment error" }),
    ).toContainText(
      "Graph enrichment failed. Local evidence remains available; check the Graph connection and retry.",
    );
    await expect(
      page.getByText("Required security application is blocking ESP"),
    ).toBeVisible();
    await expect(
      page
        .getByText("66666666-6666-4666-8666-666666666666", { exact: true })
        .first(),
    ).toBeVisible();
    await page.getByRole("button", { name: /^Open live logs,/ }).click();
    await expect(
      page.getByText(
        "Win32 app enforcement started for 66666666-6666-4666-8666-666666666666",
      ),
    ).toBeVisible();
    await expect.poll(async () => (await graphRequests(page)).length).toBe(1);
  });
});

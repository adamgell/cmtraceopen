import { test, expect } from "./fixtures";

async function openApp(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.waitForSelector("#splash", { state: "detached", timeout: 10_000 });
}

test("AppShell presents queued payload dialogs one at a time in arrival order", async ({
  page,
}) => {
  await openApp(page);

  await page.evaluate(async () => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    const ui = useUiStore.getState();
    ui.setShowAboutDialog(true);
    ui.setElevationPrompt({
      request: {
        reason: "explicitMenu",
        workspace: "log",
        target: { kind: "workspace" },
      },
    });
    ui.setCollectionResult({
      bundlePath: "C:/Temp/diagnostics.zip",
      bundleId: "e2e-collection",
      artifactCounts: { collected: 2, missing: 0, failed: 0, total: 2 },
      durationMs: 100,
      gaps: [],
    });
  });

  await expect(page.getByRole("dialog", { name: "About CMTrace Open" })).toBeVisible();
  await expect(page.locator('[aria-modal="true"]')).toHaveCount(1);
  expect(
    await page.evaluate(async () => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const state = useUiStore.getState();
      return {
        owner: state.modalOwner,
        queue: state.modalQueue,
        hasElevation: state.elevationPrompt !== null,
        resultId: state.collectionResult?.bundleId,
      };
    }),
  ).toEqual({
    owner: "about",
    queue: ["elevationPrompt", "collectionResult"],
    hasElevation: true,
    resultId: "e2e-collection",
  });

  await page.evaluate(async () => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    useUiStore.getState().setShowAboutDialog(false);
  });
  await expect(
    page.getByRole("dialog", { name: "Restart as administrator?" }),
  ).toBeVisible();
  await expect(page.locator('[aria-modal="true"]')).toHaveCount(1);

  await page.evaluate(async () => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    useUiStore.getState().setElevationPrompt(null);
  });
  await expect(page.getByRole("dialog", { name: "Collection Complete" })).toBeVisible();
  await expect(page.locator('[aria-modal="true"]')).toHaveCount(1);
});

test("ChannelPicker queues its local clear confirmation behind AppShell About", async ({
  page,
}) => {
  await openApp(page);

  await page.evaluate(async () => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    const { useEvtxStore } = await import(
      "/src/workspaces/event-log/evtx-store.ts"
    );
    useUiStore.getState().setActiveWorkspace("event-log");
    useEvtxStore.setState({
      sourceMode: "live",
      channels: [{ name: "Application", eventCount: 1, sourceType: "live" }],
      loadedChannels: new Set(["Application"]),
      selectedChannels: new Set(["Application"]),
      tailMode: null,
      isLoading: false,
    });
  });

  const channelSelect = page.getByRole("combobox", { name: "Channel to clear" });
  await expect(channelSelect).toBeVisible();
  await page.evaluate(async () => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    useUiStore.getState().setShowAboutDialog(true);
  });
  await expect(page.getByRole("dialog", { name: "About CMTrace Open" })).toBeVisible();

  await channelSelect.evaluate((element) => {
    const select = element as HTMLSelectElement;
    select.value = "Application";
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await page
    .getByRole("button", { name: "Clear", exact: true })
    .evaluate((element) => (element as HTMLButtonElement).click());

  await expect(page.locator('[aria-modal="true"]')).toHaveCount(1);
  await expect(page.getByText("Clear event channel?")).toHaveCount(0);
  expect(
    await page.evaluate(async () => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const state = useUiStore.getState();
      return { owner: state.modalOwner, queue: state.modalQueue };
    }),
  ).toEqual({ owner: "about", queue: ["eventLogChannelClear"] });

  await page.evaluate(async () => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    useUiStore.getState().setShowAboutDialog(false);
  });

  await expect(page.getByText("Clear event channel?")).toBeVisible();
  await expect(page.locator('[aria-modal="true"]')).toHaveCount(1);
});

test("AppShell external dismissal cannot release a registration continuation", async ({
  page,
}) => {
  await openApp(page);

  await page.evaluate(async () => {
    let finishRegistration: (() => void) | null = null;
    window.__e2e_ipc_overrides__.register_log_file_handler = () =>
      new Promise<void>((resolve) => {
        finishRegistration = resolve;
      });
    window.__e2e_ipc_overrides__.get_file_association_prompt_status = () => ({
      supported: true,
      shouldPrompt: false,
      isRegistered: true,
    });
    window.__e2e_ipc_overrides__.open_windows_default_apps = () => null;
    Object.assign(window, {
      __e2e_finish_registration__: () => finishRegistration?.(),
    });

    const { useUiStore } = await import("/src/stores/ui-store.ts");
    useUiStore.getState().setShowFileAssociationPrompt(true);
  });

  const prompt = page.getByRole("dialog", {
    name: "Make CMTrace Open available for log files?",
  });
  await expect(prompt).toBeVisible();
  await page
    .getByRole("button", { name: "Register and open Default Apps" })
    .click();
  await expect(page.getByRole("button", { name: "Working..." })).toBeDisabled();

  await page.evaluate(async () => {
    const { useUiStore } = await import("/src/stores/ui-store.ts");
    useUiStore.getState().closeTransientDialogs("e2e-native-action");
  });

  await expect(prompt).toBeVisible();
  expect(
    await page.evaluate(async () => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      const state = useUiStore.getState();
      return {
        owner: state.modalOwner,
        requested: state.showFileAssociationPrompt,
        busy: state.fileAssociationPromptBusy,
      };
    }),
  ).toEqual({
    owner: "fileAssociationPrompt",
    requested: true,
    busy: true,
  });

  await page.evaluate(() => {
    (
      window as typeof window & {
        __e2e_finish_registration__: () => void;
      }
    ).__e2e_finish_registration__();
  });

  await expect(prompt).toHaveCount(0);
  await expect
    .poll(() =>
      page.evaluate(async () => {
        const { useUiStore } = await import("/src/stores/ui-store.ts");
        const state = useUiStore.getState();
        return {
          owner: state.modalOwner,
          requested: state.showFileAssociationPrompt,
          busy: state.fileAssociationPromptBusy,
        };
      }),
    )
    .toEqual({ owner: null, requested: false, busy: false });
});

test("explicit association prompt outcomes consume the pending request", async ({
  page,
}) => {
  await openApp(page);
  await page.evaluate(() => {
    window.__e2e_ipc_overrides__.set_file_association_prompt_suppressed = () =>
      null;
  });

  const prompt = page.getByRole("dialog", {
    name: "Make CMTrace Open available for log files?",
  });
  const openPrompt = async () => {
    await page.evaluate(async () => {
      const { useUiStore } = await import("/src/stores/ui-store.ts");
      useUiStore.getState().setShowFileAssociationPrompt(true);
    });
    await expect(prompt).toBeVisible();
  };
  const expectConsumed = async () => {
    await expect(prompt).toHaveCount(0);
    await expect
      .poll(() =>
        page.evaluate(async () => {
          const { useUiStore } = await import("/src/stores/ui-store.ts");
          const state = useUiStore.getState();
          return {
            owner: state.modalOwner,
            queue: state.modalQueue,
            requested: state.showFileAssociationPrompt,
            busy: state.fileAssociationPromptBusy,
          };
        }),
      )
      .toEqual({ owner: null, queue: [], requested: false, busy: false });
  };

  await openPrompt();
  await page.getByRole("button", { name: "Ask Later" }).click();
  await expectConsumed();

  await openPrompt();
  await page.keyboard.press("Escape");
  await expectConsumed();

  await openPrompt();
  await prompt.locator("..").click({ position: { x: 5, y: 5 } });
  await expectConsumed();

  await openPrompt();
  await page.getByRole("button", { name: "Don't Ask Again" }).click();
  await expectConsumed();
});

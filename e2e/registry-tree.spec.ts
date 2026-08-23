import type { Page } from "@playwright/test";
import { expect, test } from "./fixtures";

const REGISTRY_PATH = "C:/Windows/Temp/virtualized-registry.reg";

async function dismissSplash(page: Page): Promise<void> {
  await page.waitForSelector("#splash", {
    state: "detached",
    timeout: 15_000,
  });
}

async function seedRegistry(page: Page, branchCount: number): Promise<void> {
  await page.evaluate(
    async ({ filePath, count }) => {
      const keys = Array.from({ length: count }, (_, index) => {
        const branch = `Branch${String(index).padStart(3, "0")}`;
        return {
          path: `HKEY_LOCAL_MACHINE\\${branch}\\Leaf`,
          lineNumber: index + 2,
          isDelete: false,
          values: [],
        };
      });
      const data = {
        filePath,
        fileSize: 4096,
        totalKeys: keys.length,
        totalValues: 0,
        parseErrors: 0,
        keys,
      };

      const { setCachedRegistry, useRegistryStore } =
        await import("/src/stores/registry-store.ts");
      const { useLogStore } = await import("/src/stores/log-store.ts");
      const { useUiStore } = await import("/src/stores/ui-store.ts");

      setCachedRegistry(filePath, data);
      useRegistryStore.getState().setRegistryData(data);
      useLogStore.getState().setOpenFilePath(filePath);
      useUiStore.getState().clearTabs();
      useUiStore.getState().ensureLogViewVisible("registry-tree-e2e");
      useUiStore
        .getState()
        .openTab(filePath, "virtualized-registry.reg", null, "registry");
    },
    { filePath: REGISTRY_PATH, count: branchCount },
  );

  await expect(page.getByText("Registry Keys", { exact: true })).toBeVisible();
}

test.describe("registry tree interaction", () => {
  test("a scrolled lower disclosure toggles before focus can virtualize it away", async ({
    page,
  }) => {
    await page.goto("/");
    await dismissSplash(page);
    await seedRegistry(page, 150);

    const targetPath = "HKEY_LOCAL_MACHINE\\Branch120";
    const tree = page.getByRole("tree", { name: "Registry keys" });
    const rowHeight = await tree
      .getByRole("treeitem")
      .first()
      .evaluate((element) => element.getBoundingClientRect().height);
    await tree.evaluate((element, scrollTop) => {
      element.scrollTop = scrollTop;
      element.dispatchEvent(new Event("scroll"));
    }, 241 * rowHeight);

    const target = page.getByTitle(targetPath, { exact: true }).locator("..");
    await expect(target).toBeVisible();
    await expect(target).toHaveAttribute("aria-expanded", "true");
    const disclosure = target.getByRole("button", { name: "Collapse Branch120" });
    const box = await disclosure.boundingBox();
    if (!box) throw new Error("Lower disclosure did not have a browser layout box");

    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.up();

    await expect
      .poll(() =>
        page.evaluate(async (path) => {
          const { useRegistryStore } =
            await import("/src/stores/registry-store.ts");
          return {
            expanded: useRegistryStore.getState().expandedPaths.has(path),
            selected: useRegistryStore.getState().selectedKeyPath,
          };
        }, targetPath),
      )
      .toEqual({ expanded: false, selected: null });
  });

  test("keyboard focus has a visible focus indicator", async ({ page }) => {
    await page.goto("/");
    await dismissSplash(page);
    await seedRegistry(page, 3);

    const tree = page.getByRole("tree", { name: "Registry keys" });
    await tree.focus();
    await page.keyboard.press("Tab");
    await page.keyboard.press("Shift+Tab");
    await expect(tree).toBeFocused();

    const focusStyle = await tree.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        focusVisible: element.matches(":focus-visible"),
        outlineStyle: style.outlineStyle,
        outlineWidth: Number.parseFloat(style.outlineWidth),
      };
    });
    expect(focusStyle.focusVisible).toBe(true);
    expect(focusStyle.outlineStyle).not.toBe("none");
    expect(focusStyle.outlineWidth).toBeGreaterThan(0);
  });
});

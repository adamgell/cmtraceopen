import { save } from "@tauri-apps/plugin-dialog";
import { writeTextFile } from "@tauri-apps/plugin-fs";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useUiStore } from "../stores/ui-store";
import { saveSession } from "./session-save";

describe("saveSession", () => {
  beforeEach(() => {
    vi.mocked(save).mockReset();
    vi.mocked(writeTextFile).mockReset();
    useUiStore.setState({
      activeWorkspace: "esp-diagnostics",
      activeView: "esp-diagnostics",
      openTabs: [],
      activeTabIndex: -1,
    });
  });

  it("does not offer to save a tabless non-Log workspace", async () => {
    await expect(saveSession()).resolves.toBeNull();

    expect(save).not.toHaveBeenCalled();
    expect(writeTextFile).not.toHaveBeenCalled();
  });
});

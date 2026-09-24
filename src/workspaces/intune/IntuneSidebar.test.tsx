import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IntuneSidebar } from "./IntuneSidebar";
import { getWorkspace, workspaceRegistry } from "../registry";
import { useUiStore } from "../../stores/ui-store";

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    commandState: {
      canOpenSources: true,
      canOpenKnownSources: true,
      canRefresh: true,
    },
    openSourceFileDialog: vi.fn(),
    openSourceFolderDialog: vi.fn(),
  }),
}));

const NEW_INTUNE = "new-intune" as const;
const asDefined = getWorkspace(NEW_INTUNE);

afterEach(() => {
  cleanup();
  workspaceRegistry.set(NEW_INTUNE, asDefined);
  useUiStore.setState({ activeView: useUiStore.getInitialState().activeView });
});

describe("IntuneSidebar workspace name", () => {
  it("takes the name from the workspace definition, not a second copy", () => {
    useUiStore.setState({ activeView: NEW_INTUNE });
    workspaceRegistry.set(NEW_INTUNE, { ...asDefined, label: "Renamed In Test" });

    render(<IntuneSidebar />);

    // The sidebar used to carry its own copy of the name, which is how the
    // workspace's development name reached users. Renaming the definition alone
    // must be enough to change what the sidebar says.
    // Both the title and the badge render it, and neither has its own copy.
    expect(screen.getAllByText("Renamed In Test").length).toBeGreaterThan(0);
    expect(screen.queryByText(asDefined.label)).toBeNull();
  });
});

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IntuneSidebar } from "./IntuneSidebar";
import { getWorkspace, workspaceRegistry } from "../registry";
import { useUiStore } from "../../stores/ui-store";
import { useIntuneStore } from "./intune-store";

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
    // The sidebar names the workspace in two places: the title and the badge. The
    // title falls back to the workspace name only when no source path is set, so
    // state that precondition rather than assuming it.
    expect(useIntuneStore.getState().analysisState.requestedPath).toBeNull();

    // A count, not a presence check: presence passes when only one of the two
    // reads the definition, which is the drift this test exists to catch.
    expect(screen.getAllByText("Renamed In Test")).toHaveLength(2);
    expect(screen.queryByText(asDefined.label)).toBeNull();
  });
});

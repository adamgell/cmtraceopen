import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AboutDialog } from "../../components/dialogs/AboutDialog";
import { useUiStore } from "../../stores/ui-store";
import { EspActions } from "./EspActions";
import { makeEspWorkload } from "./esp-session-fixtures";
import type { EspWorkload } from "./types";

const { flipMock, restoreMock } = vi.hoisted(() => ({
  flipMock: vi.fn(),
  restoreMock: vi.fn(),
}));
vi.mock("../../lib/commands", () => ({
  espFlipAppInstalled: flipMock,
  espRestoreAppState: restoreMock,
}));

function failedApp(): EspWorkload {
  return makeEspWorkload({
    rawIdentifier: "Win32App_431bae97-f077-4f2d-9102-78ed781451e9_1",
    displayName: "Citrix Workspace",
    status: { raw: "failed", normalized: "failed", display: "Failed", detail: null },
    enforcementErrorCode: {
      raw: "0x80079C69",
      decimal: 2147982441,
      hex: "0x80079C69",
    },
  });
}

function AboutAndEspActions() {
  const showAboutDialog = useUiStore((state) => state.showAboutDialog);
  const setShowAboutDialog = useUiStore((state) => state.setShowAboutDialog);
  return (
    <>
      <AboutDialog
        isOpen={showAboutDialog}
        onClose={() => setShowAboutDialog(false)}
      />
      <EspActions failedApps={[failedApp()]} graphNames={new Map()} elevated />
    </>
  );
}

describe("EspActions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useUiStore.setState(useUiStore.getInitialState(), true);
  });

  it("renders nothing when there are no failed apps", () => {
    const { container } = render(
      <EspActions failedApps={[]} graphNames={new Map()} elevated />,
    );
    expect(container.textContent).toBe("");
  });

  it("gates the action behind elevation", () => {
    render(
      <EspActions failedApps={[failedApp()]} graphNames={new Map()} elevated={false} />,
    );
    expect(
      screen.getByText(/Run CMTrace Open as administrator/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Force past ESP/i }),
    ).toBeDisabled();
  });

  it("flips a failed app after confirmation and then offers restore", async () => {
    flipMock.mockResolvedValue({
      appId: "Win32App_431bae97-f077-4f2d-9102-78ed781451e9_1",
      installationState: 3,
      backup: {
        appId: "Win32App_431bae97-f077-4f2d-9102-78ed781451e9_1",
        installationState: 4,
        errorHresult: 2147982441,
      },
    });
    render(
      <EspActions failedApps={[failedApp()]} graphNames={new Map()} elevated />,
    );
    expect(screen.getByText("Citrix Workspace")).toBeInTheDocument();
    expect(screen.getByText("0x80079C69")).toBeInTheDocument();

    // Row button opens the confirmation dialog.
    fireEvent.click(screen.getByRole("button", { name: /Force past ESP/i }));
    expect(screen.getByText("Force ESP past this app?")).toBeInTheDocument();

    // Confirm (the dialog adds a second "Force past ESP" button).
    const confirm = screen.getAllByRole("button", {
      name: /Force past ESP/i,
      hidden: true,
    });
    fireEvent.click(confirm[confirm.length - 1]);

    await waitFor(() => expect(flipMock).toHaveBeenCalledWith(
      "Win32App_431bae97-f077-4f2d-9102-78ed781451e9_1",
    ));
    expect(await screen.findByText(/Forced to Installed/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Restore/i, hidden: true }),
    ).toBeInTheDocument();
  });

  it("queues force confirmation behind the app modal and releases ownership on unmount", async () => {
    useUiStore.getState().setShowAboutDialog(true);
    const view = render(<AboutAndEspActions />);

    fireEvent.click(screen.getByRole("button", { name: /Force past ESP/i }));

    expect(document.querySelectorAll('[aria-modal="true"]')).toHaveLength(1);
    expect(useUiStore.getState().modalOwner).toBe("about");
    expect(useUiStore.getState().modalQueue).toEqual(["espForceAction"]);
    expect(screen.queryByText("Force ESP past this app?")).toBeNull();

    act(() => {
      useUiStore.getState().setShowAboutDialog(false);
    });

    await waitFor(() => {
      expect(screen.getByText("Force ESP past this app?")).toBeInTheDocument();
      expect(document.querySelectorAll('[aria-modal="true"]')).toHaveLength(1);
    });

    view.unmount();

    expect(useUiStore.getState().modalOwner).toBeNull();
    expect(useUiStore.getState().modalQueue).toEqual([]);
  });
});

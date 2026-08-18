import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FileAssociationsTab } from "./FileAssociationsTab";
import { FileAssociationPromptDialog } from "../FileAssociationPromptDialog";
import { useUiStore } from "../../../stores/ui-store";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async () => ({ supported: true, shouldPrompt: false, isAssociated: false })),
}));

describe("FileAssociationsTab", () => {
  beforeEach(() => {
    useUiStore.setState(useUiStore.getInitialState(), true);
  });

  afterEach(() => {
    cleanup();
  });

  it("shows a static note off Windows", () => {
    useUiStore.setState({ currentPlatform: "macos" });
    render(<FileAssociationsTab />);
    expect(
      screen.getByText(/File associations are only available on Windows/),
    ).toBeInTheDocument();
  });

  it("offers Associate on Windows when not registered", () => {
    useUiStore.setState({ currentPlatform: "windows" });
    render(<FileAssociationsTab />);
    expect(
      screen.getByRole("button", { name: /Associate \.log files with CMTrace Open/ }),
    ).toBeInTheDocument();
  });
});

describe("FileAssociationPromptDialog", () => {
  afterEach(() => {
    cleanup();
  });

  it("exposes a dialog landmark when open", () => {
    render(<FileAssociationPromptDialog isOpen onClose={() => {}} />);
    const dialog = screen.getByRole("dialog", { name: "Associate log files with CMTrace Open?" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("offers Associate, Don't Ask Again, and Ask Later", () => {
    render(<FileAssociationPromptDialog isOpen onClose={vi.fn()} />);
    expect(screen.getByText(/Associate log files with CMTrace Open/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Associate" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Don't Ask Again" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Ask Later" })).toBeInTheDocument();
  });
});

import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

const bootstrap = vi.hoisted(() => ({ render: vi.fn() }));
vi.mock("react-dom/client", () => ({
  default: { createRoot: () => ({ render: bootstrap.render }) },
}));
vi.mock("./App", () => ({
  default: () => { throw new Error("shell startup failed"); },
}));
vi.mock("./hooks/use-app-menu", () => ({ useAppMenu: () => {} }));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => ({ onFocusChanged: async () => () => {} }),
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
  document.getElementById("splash")?.remove();
});

it("shows an app fallback and dismisses the splash when startup rendering fails", async () => {
  vi.spyOn(console, "error").mockImplementation(() => {});
  const splash = document.createElement("div");
  splash.id = "splash";
  document.body.appendChild(splash);
  await import("./main");
  vi.useFakeTimers();
  render(bootstrap.render.mock.calls[0][0] as ReactNode);
  expect(screen.getByRole("alert").textContent).toContain("shell startup failed");
  expect(screen.getByRole("button", { name: "Reload application" })).toBeTruthy();
  await act(async () => vi.advanceTimersByTime(500));
  expect(document.getElementById("splash")).toBeNull();
}, 30_000);

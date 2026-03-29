import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// Ensure localStorage is available for Zustand persist middleware.
// jsdom may provide a broken or missing localStorage in some configs.
// Zustand 5 persist defaults to createJSONStorage(() => window.localStorage).
const memoryStore: Record<string, string> = {};
const storageMock: Storage = {
  getItem: (key: string) => memoryStore[key] ?? null,
  setItem: (key: string, value: string) => { memoryStore[key] = value; },
  removeItem: (key: string) => { delete memoryStore[key]; },
  clear: () => { for (const key of Object.keys(memoryStore)) delete memoryStore[key]; },
  get length() { return Object.keys(memoryStore).length; },
  key: (index: number) => Object.keys(memoryStore)[index] ?? null,
};

Object.defineProperty(globalThis, "localStorage", { value: storageMock, writable: true });
Object.defineProperty(window, "localStorage", { value: storageMock, writable: true });

// Mock Tauri IPC bridge
vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: vi.fn(),
  readText: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
  save: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-fs", () => ({
  readTextFile: vi.fn(),
  writeTextFile: vi.fn(),
}));

vi.mock("@tauri-apps/plugin-os", () => ({
  platform: vi.fn().mockResolvedValue("windows"),
}));

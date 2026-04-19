/**
 * Detects whether the app is running inside Tauri (desktop) or as a plain web
 * page (WASM / browser mode).
 *
 * Returns 'tauri' when Tauri's internal bridge is present (injected by the
 * Tauri WebView) and 'wasm' otherwise (plain browser, Playwright, etc.).
 */
export function getRuntime(): "tauri" | "wasm" {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
    ? "tauri"
    : "wasm";
}

/** True when running in a real Tauri WebView. */
export const isTauri = getRuntime() === "tauri";

/** True when running in a plain browser (WASM mode). */
export const isWasm = !isTauri;

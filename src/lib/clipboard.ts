/**
 * Unified clipboard helpers that work in both Tauri (desktop) and plain-browser
 * (WASM) environments.
 *
 * In Tauri: delegates to the `@tauri-apps/plugin-clipboard-manager` which has
 * native OS clipboard access and works without HTTPS.
 *
 * In browser (WASM mode): falls back to the standard `navigator.clipboard` API.
 */
import { isWasm } from "./runtime";

export async function writeText(text: string): Promise<void> {
  if (isWasm) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const { writeText: tauriWrite } = await import("@tauri-apps/plugin-clipboard-manager");
  await tauriWrite(text);
}

export async function readText(): Promise<string> {
  if (isWasm) {
    return navigator.clipboard.readText();
  }
  const { readText: tauriRead } = await import("@tauri-apps/plugin-clipboard-manager");
  return tauriRead();
}

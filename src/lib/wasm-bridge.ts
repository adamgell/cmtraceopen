/**
 * Lazy-loading bridge to the cmtrace_wasm WebAssembly module.
 *
 * The module is only imported (and the .wasm binary fetched) the first time a
 * WASM function is called, so Tauri builds are completely unaffected — they
 * never trigger this import.
 */
import type { ParseResult } from "../types/log";

let wasmModule: typeof import("../wasm/cmtrace_wasm") | null = null;

async function getWasm() {
  if (!wasmModule) {
    const mod = await import("../wasm/cmtrace_wasm");
    await mod.default(); // initialise WASM (loads the .wasm binary)
    mod.init();          // install Rust panic → console.error hook
    wasmModule = mod;
  }
  return wasmModule;
}

/**
 * Parse raw file bytes entirely in the browser via the Rust WASM parser.
 *
 * @param bytes    Raw file content as a Uint8Array (from File.arrayBuffer())
 * @param filename Original filename — used for format-detection heuristics
 */
export async function parseBytesWasm(bytes: Uint8Array, filename: string): Promise<ParseResult> {
  const wasm = await getWasm();
  return wasm.parse_bytes(bytes, filename) as ParseResult;
}

/**
 * Look up a single Windows / SCCM / Intune error code in the browser.
 * Accepts decimal or hex strings (e.g. "0x80070005" or "2147942405").
 */
export async function lookupErrorCodeWasm(code: string): Promise<unknown> {
  const wasm = await getWasm();
  return wasm.lookup_error_code(code);
}

export async function searchErrorCodesWasm(query: string): Promise<unknown[]> {
  const wasm = await getWasm();
  return wasm.search_error_codes(query) as unknown[];
}

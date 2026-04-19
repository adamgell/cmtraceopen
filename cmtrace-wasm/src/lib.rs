//! WebAssembly bindings for CMTrace Open.
//!
//! Exposes the Rust log parser, error lookup, and error search APIs to
//! JavaScript via wasm-bindgen so the full app can run in a browser without
//! any server-side component.

use wasm_bindgen::prelude::*;

/// Initialise the WASM module: install a panic hook that forwards Rust panics
/// to the browser console as readable messages.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Parse raw file bytes in the browser.
///
/// `bytes`    — the raw content of the file as a `Uint8Array`
/// `filename` — the original file name (used for format detection heuristics)
///
/// Returns a JSON-serialised `ParseResult` on success, or throws a JS error.
#[wasm_bindgen]
pub fn parse_bytes(bytes: &[u8], filename: &str) -> Result<JsValue, JsValue> {
    let encoding = cmtrace_open::parser::detect_encoding(bytes);
    let content = cmtrace_open::parser::decode_bytes(bytes, encoding)
        .map_err(|e| JsValue::from_str(&e))?;

    let file_size = bytes.len() as u64;
    let selection = cmtrace_open::parser::detect::detect_parser(filename, &content);
    let chunk = cmtrace_open::parser::parse_content_with_selection(&content, filename, &selection);

    let result = cmtrace_open::models::log_entry::ParseResult {
        entries: chunk.entries,
        format_detected: selection.compatibility_format(),
        parser_selection: selection.to_info(),
        total_lines: chunk.total_lines,
        parse_errors: chunk.parse_errors,
        file_path: filename.to_string(),
        file_size,
        byte_offset: file_size,
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Look up a single Windows / SCCM / Intune error code.
///
/// `code` — decimal or hex string (e.g. `"0x80070005"` or `"2147942405"`)
///
/// Returns a JSON-serialised `ErrorLookupResult`.
#[wasm_bindgen]
pub fn lookup_error_code(code: &str) -> Result<JsValue, JsValue> {
    let result = cmtrace_open::error_db::lookup::lookup_error_code(code);
    serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Search the error code database by keyword or code fragment.
///
/// Returns a JSON-serialised `Vec<ErrorSearchResult>`.
#[wasm_bindgen]
pub fn search_error_codes(query: &str) -> Result<JsValue, JsValue> {
    let results = cmtrace_open::error_db::lookup::search_error_codes(query);
    serde_wasm_bindgen::to_value(&results).map_err(|e| JsValue::from_str(&e.to_string()))
}


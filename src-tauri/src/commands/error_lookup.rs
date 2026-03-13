use crate::error_db::lookup::{lookup_error_code as do_lookup, ErrorLookupResult};

/// Look up an error code and return its description.
#[tauri::command]
pub fn lookup_error_code(code: String) -> ErrorLookupResult {
    do_lookup(&code)
}

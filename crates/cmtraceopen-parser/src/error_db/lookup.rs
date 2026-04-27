use regex::Regex;
use std::collections::HashMap;

use super::codes::{ErrorCode, ERROR_CODES};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Pre-built HashMap from error code values to their ErrorCode entries.
/// Provides O(1) lookup instead of linear scan over the array.
fn code_map() -> &'static HashMap<u32, &'static ErrorCode> {
    static CELL: OnceLock<HashMap<u32, &'static ErrorCode>> = OnceLock::new();
    CELL.get_or_init(|| {
    ERROR_CODES.iter().map(|ec| (ec.code, ec)).collect()
})
}

/// Look up an error code with HRESULT decomposition.
/// Tries direct hit first. If miss and code is FACILITY_WIN32 (0x8007xxxx),
/// extracts lower 16 bits as a Win32 code and looks that up.
/// Conversely, if the code is a small Win32 value (<=0xFFFF), tries its
/// HRESULT form (0x80070000 | code).
fn find_error_code(code: u32) -> Option<&'static ErrorCode> {
    // Direct table hit (O(1) via HashMap)
    if let Some(ec) = code_map().get(&code) {
        return Some(ec);
    }

    // FACILITY_WIN32 decomposition: if code is 0x8007xxxx, the lower 16 bits
    // are a Win32 error code. Some Win32 codes may be stored without the
    // HRESULT wrapper in the table.
    if (code & 0xFFFF_0000) == 0x8007_0000 {
        let win32_code = code & 0x0000_FFFF;
        if let Some(ec) = code_map().get(&win32_code) {
            return Some(ec);
        }
    }

    // Reverse: if user typed a small Win32 code (e.g., 5), try its HRESULT form
    if code <= 0xFFFF {
        let hresult = 0x8007_0000 | code;
        if let Some(ec) = code_map().get(&hresult) {
            return Some(ec);
        }
    }

    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorCodeSpan {
    pub start: usize,
    pub end: usize,
    pub code_hex: String,
    pub code_decimal: String,
    pub description: String,
    pub category: String,
}

fn hex_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"0[xX][0-9A-Fa-f]{8}").unwrap())
}

/// Scan a message string for recognized error codes and return their spans.
/// Only returns spans for codes that exist in the error database.
/// Short-circuits if the message contains no "0x" or "0X" prefix (common case).
pub fn detect_error_code_spans(message: &str) -> Vec<ErrorCodeSpan> {
    // Fast pre-check: skip the regex entirely if no hex prefix exists.
    // Most log lines have no error codes, so this avoids regex overhead.
    if !message.contains("0x") && !message.contains("0X") {
        return Vec::new();
    }

    hex_code_re()
        .find_iter(message)
        .filter_map(|m| {
            // Skip matches followed by more hex digits (e.g., GUIDs, longer hex values)
            let after = &message[m.end()..];
            if after.starts_with(|c: char| c.is_ascii_hexdigit()) {
                return None;
            }
            let hex_str = &message[m.start()..m.end()];
            let code_val = u32::from_str_radix(&hex_str[2..], 16).ok()?;
            let ec = find_error_code(code_val)?;
            // Convert byte offsets to UTF-16 code unit offsets for JavaScript interop.
            // JS String.slice() uses UTF-16 indices, but regex::Match returns byte offsets.
            let utf16_start = message[..m.start()].encode_utf16().count();
            // The match itself is all ASCII hex digits, so its UTF-16 length equals byte length.
            let char_start = utf16_start;
            let char_end = utf16_start + (m.end() - m.start());
            Some(ErrorCodeSpan {
                start: char_start,
                end: char_end,
                code_hex: format!("0x{:08X}", ec.code),
                code_decimal: format!("{}", ec.code as i32),
                description: ec.description.to_string(),
                category: ec.category.label().to_string(),
            })
        })
        .collect()
}

/// Result type shared by both exact lookup and search operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorLookupResult {
    pub code_hex: String,
    pub code_decimal: String,
    pub description: String,
    pub category: String,
    pub found: bool,
}

/// Alias for backward compatibility with IPC commands that reference `ErrorSearchResult`.
pub type ErrorSearchResult = ErrorLookupResult;

/// Try to parse an input string as an error code (hex or decimal).
/// Accepts formats: "0x80070005", "80070005", "-2147024891", "2147942405"
fn try_parse_error_code(input: &str) -> Option<u32> {
    if input.starts_with("0x") || input.starts_with("0X") {
        u32::from_str_radix(&input[2..], 16).ok()
    } else if input.starts_with('-') {
        // Negative decimal (signed representation of HRESULT)
        input.parse::<i32>().ok().map(|v| v as u32)
    } else if let Ok(hex_val) = u32::from_str_radix(input, 16) {
        // Try as raw hex without prefix (if it looks like hex)
        if input.len() >= 6 && input.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(hex_val)
        } else {
            // Try as decimal first
            input.parse::<u32>().ok().or(Some(hex_val))
        }
    } else {
        input.parse::<u32>().ok()
    }
}

/// Look up an error code by its hex or decimal value.
/// Accepts formats: "0x80070005", "80070005", "-2147024891", "2147942405"
pub fn lookup_error_code(input: &str) -> ErrorLookupResult {
    let input = input.trim();

    match try_parse_error_code(input) {
        Some(c) => {
            if let Some(ec) = find_error_code(c) {
                ErrorLookupResult {
                    code_hex: format!("0x{:08X}", ec.code),
                    code_decimal: format!("{}", ec.code as i32),
                    description: ec.description.to_string(),
                    category: ec.category.label().to_string(),
                    found: true,
                }
            } else {
                // Code not in database — still show the formatted values
                ErrorLookupResult {
                    code_hex: format!("0x{:08X}", c),
                    code_decimal: format!("{}", c as i32),
                    description: "Unknown error code".to_string(),
                    category: String::new(),
                    found: false,
                }
            }
        }
        None => ErrorLookupResult {
            code_hex: String::new(),
            code_decimal: String::new(),
            description: "Invalid error code format".to_string(),
            category: String::new(),
            found: false,
        },
    }
}

/// Search error codes by exact hex/decimal match or by description substring.
/// Returns up to 50 results sorted by relevance.
pub fn search_error_codes(query: &str) -> Vec<ErrorSearchResult> {
    let query = query.trim();
    if query.is_empty() {
        return Vec::new();
    }

    // Try exact code lookup first
    if let Some(code_val) = try_parse_error_code(query) {
        if let Some(ec) = find_error_code(code_val) {
            return vec![ErrorSearchResult {
                code_hex: format!("0x{:08X}", ec.code),
                code_decimal: format!("{}", ec.code as i32),
                description: ec.description.to_string(),
                category: ec.category.label().to_string(),
                found: true,
            }];
        }
        // Known code format but not in DB
        return vec![ErrorSearchResult {
            code_hex: format!("0x{:08X}", code_val),
            code_decimal: format!("{}", code_val as i32),
            description: "Unknown error code".to_string(),
            category: String::new(),
            found: false,
        }];
    }

    // Substring search across descriptions and category labels
    let query_lower = query.to_lowercase();
    let mut results: Vec<(usize, &super::codes::ErrorCode)> = ERROR_CODES
        .iter()
        .filter_map(|ec| {
            let desc_lower = ec.description.to_lowercase();
            let cat_lower = ec.category.label().to_lowercase();
            if desc_lower.starts_with(&query_lower) {
                Some((0, ec)) // description prefix match (highest priority)
            } else if desc_lower.contains(&query_lower) {
                Some((1, ec)) // description substring match
            } else if cat_lower.contains(&query_lower) {
                Some((2, ec)) // category label match (lowest priority)
            } else {
                None
            }
        })
        .collect();

    results.sort_by_key(|(priority, _)| *priority);
    results.truncate(50);

    results
        .into_iter()
        .map(|(_, ec)| ErrorSearchResult {
            code_hex: format!("0x{:08X}", ec.code),
            code_decimal: format!("{}", ec.code as i32),
            description: ec.description.to_string(),
            category: ec.category.label().to_string(),
            found: true,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup_hex_prefix() {
        let result = lookup_error_code("0x80070005");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
    }

    #[test]
    fn test_lookup_hex_no_prefix() {
        let result = lookup_error_code("80070005");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
    }

    #[test]
    fn test_lookup_negative_decimal() {
        // 0x80070005 = -2147024891 as signed i32
        let result = lookup_error_code("-2147024891");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
    }

    #[test]
    fn test_lookup_success_code() {
        let result = lookup_error_code("0x00000000");
        assert!(result.found);
        assert!(result.description.contains("S_OK"));
    }

    #[test]
    fn test_lookup_unknown() {
        let result = lookup_error_code("0xDEADBEEF");
        assert!(!result.found);
        assert_eq!(result.code_hex, "0xDEADBEEF");
    }

    #[test]
    fn test_error_codes_have_categories() {
        use super::super::codes::{ERROR_CODES, ErrorCategory};
        let intune_count = ERROR_CODES
            .iter()
            .filter(|ec| matches!(ec.category, ErrorCategory::Intune))
            .count();
        assert!(intune_count > 0, "Should have Intune-categorized codes");
    }

    #[test]
    fn test_no_duplicate_error_codes() {
        use super::super::codes::ERROR_CODES;
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for ec in ERROR_CODES.iter() {
            assert!(
                seen.insert(ec.code),
                "Duplicate error code: 0x{:08X}",
                ec.code
            );
        }
    }

    #[test]
    fn test_lookup_includes_category() {
        let result = lookup_error_code("0x87D00215");
        assert!(result.found);
        assert_eq!(result.category, "Intune");
    }

    #[test]
    fn test_search_exact_hex() {
        let results = search_error_codes("0x80070005");
        assert_eq!(results.len(), 1);
        assert!(results[0].found);
        assert!(results[0].description.contains("Access is denied"));
        assert_eq!(results[0].category, "Windows");
    }

    #[test]
    fn test_search_by_description() {
        let results = search_error_codes("Access is denied");
        assert!(!results.is_empty());
        assert!(results
            .iter()
            .any(|r| r.description.contains("Access is denied")));
    }

    #[test]
    fn test_search_empty_query() {
        let results = search_error_codes("");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_no_match() {
        let results = search_error_codes("xyznonexistentxyz");
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_max_results() {
        let results = search_error_codes("error");
        assert!(results.len() <= 50, "Should cap at 50 results");
    }

    #[test]
    fn test_detect_error_code_spans() {
        let spans = detect_error_code_spans("Failed with error 0x80070005 during install");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start, 18);
        assert_eq!(spans[0].end, 28);
        assert_eq!(spans[0].code_hex, "0x80070005");
        assert!(spans[0].description.contains("Access is denied"));
        assert_eq!(spans[0].category, "Windows");
    }

    #[test]
    fn test_detect_multiple_error_code_spans() {
        let spans = detect_error_code_spans("Error 0x80070005 and then 0x80070002");
        assert_eq!(spans.len(), 2);
    }

    #[test]
    fn test_detect_no_error_code_spans() {
        let spans = detect_error_code_spans("Everything is fine, no errors here");
        assert!(spans.is_empty());
    }

    #[test]
    fn test_detect_unrecognized_code_ignored() {
        let spans = detect_error_code_spans("Code 0xDEADBEEF is not in our database");
        assert!(spans.is_empty());
    }

    // --- HRESULT decomposition tests ---

    #[test]
    fn test_lookup_win32_code_finds_hresult_entry() {
        // Win32 code 5 should resolve via HRESULT form 0x80070005
        let result = lookup_error_code("5");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
        // Should show the canonical HRESULT form, not 0x00000005
        assert_eq!(result.code_hex, "0x80070005");
    }

    #[test]
    fn test_lookup_hresult_facility_win32_direct() {
        // 0x80070005 should resolve directly
        let result = lookup_error_code("0x80070005");
        assert!(result.found);
        assert!(result.description.contains("Access is denied"));
    }

    #[test]
    fn test_search_win32_code_finds_hresult_entry() {
        // Searching for "5" as a code should find 0x80070005
        let results = search_error_codes("5");
        assert_eq!(results.len(), 1);
        assert!(results[0].found);
        assert!(results[0].description.contains("Access is denied"));
    }

    #[test]
    fn test_find_error_code_direct_hit() {
        let ec = find_error_code(0x80070005);
        assert!(ec.is_some());
        assert!(ec.unwrap().description.contains("Access is denied"));
    }

    #[test]
    fn test_find_error_code_win32_to_hresult() {
        // Small Win32 code 2 should map to 0x80070002
        let ec = find_error_code(2);
        assert!(ec.is_some());
        assert!(ec.unwrap().description.contains("file"));
    }

    #[test]
    fn test_find_error_code_no_match() {
        let ec = find_error_code(0xDEADBEEF);
        assert!(ec.is_none());
    }

    #[test]
    fn test_expanded_database_size() {
        use super::super::codes::ERROR_CODES;
        assert!(
            ERROR_CODES.len() >= 400,
            "Expected at least 400 error codes, got {}",
            ERROR_CODES.len()
        );
    }

    /// Helper: simulate JS String.slice(start, end) using UTF-16 code unit offsets.
    fn js_slice(s: &str, start: usize, end: usize) -> String {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        String::from_utf16(&utf16[start..end]).unwrap()
    }

    #[test]
    fn test_detect_spans_with_non_ascii_prefix() {
        // "Ñoño" has multi-byte UTF-8 chars, so byte offsets diverge from char offsets
        let msg = "Ñoño error: 0x80070005 failed";
        let spans = detect_error_code_spans(msg);
        assert_eq!(spans.len(), 1);
        // Verify UTF-16 offsets work correctly with JS String.slice() semantics
        assert_eq!(js_slice(msg, spans[0].start, spans[0].end), "0x80070005");
    }

    #[test]
    fn test_detect_spans_with_emoji_prefix() {
        // Emoji like 🔥 are non-BMP: 4 bytes in UTF-8, 2 code units in UTF-16,
        // but only 1 Rust char. This test ensures we count UTF-16 code units,
        // not Unicode scalar values.
        let msg = "🔥🔥 error 0x80070005 done";
        let spans = detect_error_code_spans(msg);
        assert_eq!(spans.len(), 1);
        // 🔥 = 2 UTF-16 code units each, so prefix "🔥🔥 error " = 4 + 7 = 11 UTF-16 units
        assert_eq!(spans[0].start, 11);
        assert_eq!(spans[0].end, 21);
        assert_eq!(js_slice(msg, spans[0].start, spans[0].end), "0x80070005");
    }
}

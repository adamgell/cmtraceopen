use crate::error_db::lookup::{
    detect_error_code_mentions, lookup_error_code as do_lookup, search_error_codes as do_search,
    ErrorCodeMention, ErrorLookupResult, ErrorSearchResult,
};

/// Look up an error code and return its description.
#[tauri::command]
pub fn lookup_error_code(code: String) -> ErrorLookupResult {
    do_lookup(&code)
}

/// Search error codes by exact match or description substring.
#[tauri::command]
pub fn search_error_codes(query: String) -> Vec<ErrorSearchResult> {
    do_search(&query)
}

/// Report every error code in `text`, with whatever the database knows about it.
///
/// Detection stays in the parser crate, so the frontend never grows a second idea
/// of what a code looks like. A code the database does not hold comes back marked
/// unknown rather than absent: an operator reading one event needs to tell "no
/// code here" from "a code we cannot explain".
#[tauri::command]
pub fn resolve_error_codes_in_text(text: String) -> Vec<ErrorCodeMention> {
    detect_error_code_mentions(&text)
}

#[cfg(test)]
mod tests {
    use super::resolve_error_codes_in_text;

    #[test]
    fn a_known_code_in_event_text_comes_back_with_its_meaning() {
        let mentions = resolve_error_codes_in_text("Update failed with 0x80070005".to_string());

        assert_eq!(mentions.len(), 1);
        assert!(mentions[0].known);
        assert_eq!(mentions[0].code_hex, "0x80070005");
        assert!(!mentions[0].description.is_empty());
    }

    #[test]
    fn an_unknown_code_in_event_text_comes_back_marked_unknown() {
        let mentions = resolve_error_codes_in_text("Vendor agent returned 0xDEADBEEF".to_string());

        assert_eq!(mentions.len(), 1);
        assert!(
            !mentions[0].known,
            "an unexplainable code is evidence, not silence"
        );
        assert_eq!(mentions[0].code_hex, "0xDEADBEEF");
        assert!(
            mentions[0].outcome.is_none(),
            "nothing known about its outcome"
        );
    }

    #[test]
    fn event_text_without_a_code_reports_nothing() {
        let mentions = resolve_error_codes_in_text("Policy applied in 12 seconds".to_string());

        assert!(mentions.is_empty());
    }
}

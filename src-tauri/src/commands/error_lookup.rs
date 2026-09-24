use crate::error_db::lookup::{
    detect_error_code_spans as do_detect, lookup_error_code as do_lookup,
    search_error_codes as do_search, ErrorCodeSpan, ErrorLookupResult, ErrorSearchResult,
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

/// Every error code this build's own detection finds in `text`.
///
/// Detection lives in the parser crate so one span rule serves every surface;
/// this command is an adapter over it, not a second pattern. Each span carries
/// the database's description and category. Detection reports the codes it can
/// *describe*: a code absent from the database is omitted rather than surfaced
/// with no meaning, and this adapter does not guess at code shapes to find one.
/// Callers therefore receive a possibly-empty list that means "nothing readable
/// here", not "no code was present".
#[tauri::command]
pub fn detect_error_codes(text: String) -> Vec<ErrorCodeSpan> {
    do_detect(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_code_is_detected_with_its_description() {
        let spans = detect_error_codes("Install failed with 0x80070005 for the package".to_owned());

        assert_eq!(spans.len(), 1, "{spans:?}");
        assert_eq!(spans[0].code_hex, "0x80070005");
        assert!(
            !spans[0].description.is_empty() && spans[0].description != "Unknown error code",
            "a code in the database carries its description: {spans:?}"
        );
    }

    #[test]
    fn a_code_the_database_does_not_know_is_not_invented() {
        // Detection reports the codes it can describe. A code absent from the
        // database is left alone rather than surfaced as an entry with no
        // meaning, and this command does not guess at code shapes to find it --
        // widening that is a change to the shared detection module, not to this
        // adapter.
        let spans = detect_error_codes("Failure 0xDEADBEEF is not in the database".to_owned());

        assert!(spans.is_empty(), "{spans:?}");
    }

    #[test]
    fn text_without_a_code_detects_nothing() {
        assert!(detect_error_codes("No codes in this event at all".to_owned()).is_empty());
    }
}

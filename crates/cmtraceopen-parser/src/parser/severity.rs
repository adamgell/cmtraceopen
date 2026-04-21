use crate::models::log_entry::Severity;

/// Case-insensitive substring check without allocating a lowercased copy.
/// Uses byte-level ASCII case folding since all keywords are ASCII.
#[inline]
fn contains_ci(haystack: &str, needle: &[u8]) -> bool {
    let h = haystack.as_bytes();
    let n_len = needle.len();
    if h.len() < n_len {
        return false;
    }
    for window in h.windows(n_len) {
        if window
            .iter()
            .zip(needle.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == *b)
        {
            return true;
        }
    }
    false
}

/// Centralized text-based severity detection.
/// Checks message content for keywords indicating error, warning, or info severity.
/// Uses zero-allocation case-insensitive matching instead of `.to_lowercase()`.
pub fn detect_severity_from_text(text: &str) -> Severity {
    // Error keywords
    if contains_ci(text, b"error")
        || contains_ci(text, b"exception")
        || contains_ci(text, b"critical")
        || contains_ci(text, b"fatal")
    {
        return Severity::Error;
    }

    // "fail" family — exclude "failover" (legitimate networking term)
    if contains_ci(text, b"fail") && !contains_ci(text, b"failover") {
        return Severity::Error;
    }

    // Warning keywords
    if contains_ci(text, b"warn") {
        return Severity::Warning;
    }

    Severity::Info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_keyword() {
        assert_eq!(
            detect_severity_from_text("An error occurred"),
            Severity::Error
        );
    }

    #[test]
    fn test_exception_keyword() {
        assert_eq!(
            detect_severity_from_text("NullPointerException thrown"),
            Severity::Error
        );
    }

    #[test]
    fn test_critical_keyword() {
        assert_eq!(
            detect_severity_from_text("CRITICAL: disk full"),
            Severity::Error
        );
    }

    #[test]
    fn test_fatal_keyword() {
        assert_eq!(
            detect_severity_from_text("Fatal: cannot continue"),
            Severity::Error
        );
    }

    #[test]
    fn test_fail_keyword() {
        assert_eq!(
            detect_severity_from_text("Operation failed"),
            Severity::Error
        );
    }

    #[test]
    fn test_failover_excluded() {
        assert_eq!(
            detect_severity_from_text("Failover to secondary node"),
            Severity::Info
        );
    }

    #[test]
    fn test_warning_keyword() {
        assert_eq!(
            detect_severity_from_text("Warning: low memory"),
            Severity::Warning
        );
    }

    #[test]
    fn test_warn_keyword() {
        assert_eq!(
            detect_severity_from_text("[WARN] config missing"),
            Severity::Warning
        );
    }

    #[test]
    fn test_info_default() {
        assert_eq!(
            detect_severity_from_text("Service started successfully"),
            Severity::Info
        );
    }

    #[test]
    fn test_case_insensitive() {
        assert_eq!(
            detect_severity_from_text("ERROR: something broke"),
            Severity::Error
        );
        assert_eq!(
            detect_severity_from_text("WARNING: check this"),
            Severity::Warning
        );
    }
}

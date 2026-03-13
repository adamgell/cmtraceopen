use crate::models::log_entry::Severity;

/// Centralized text-based severity detection.
/// Checks message content for keywords indicating error, warning, or info severity.
pub fn detect_severity_from_text(text: &str) -> Severity {
    let lower = text.to_lowercase();

    // Error keywords
    if lower.contains("error")
        || lower.contains("exception")
        || lower.contains("critical")
        || lower.contains("fatal")
    {
        return Severity::Error;
    }

    // "fail" family — exclude "failover" (legitimate networking term)
    if lower.contains("fail") && !lower.contains("failover") {
        return Severity::Error;
    }

    // Warning keywords
    if lower.contains("warn") {
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

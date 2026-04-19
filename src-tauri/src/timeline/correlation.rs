/// Normalize a GUID-ish string for cross-source comparison.
/// Lowercases, strips surrounding braces, tolerates hyphenless form by re-inserting.
pub fn normalize_guid(s: &str) -> Option<String> {
    let trimmed = s.trim().trim_start_matches('{').trim_end_matches('}');
    let only_hex: String = trimmed
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if only_hex.len() != 32 {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &only_hex[0..8],
        &only_hex[8..12],
        &only_hex[12..16],
        &only_hex[16..20],
        &only_hex[20..32],
    ))
}

/// Extract all GUID-shaped substrings from a message, normalized.
pub fn extract_guids(msg: &str) -> Vec<String> {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"(?i)\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?")
            .expect("guid regex")
    });
    re.captures_iter(msg)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .filter_map(|s| normalize_guid(&s))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_braces_and_case() {
        assert_eq!(
            normalize_guid("{AB12CD34-56EF-7890-ABCD-EF0123456789}").as_deref(),
            Some("ab12cd34-56ef-7890-abcd-ef0123456789")
        );
    }

    #[test]
    fn normalizes_hyphenless_form() {
        assert_eq!(
            normalize_guid("AB12CD3456EF7890ABCDEF0123456789").as_deref(),
            Some("ab12cd34-56ef-7890-abcd-ef0123456789")
        );
    }

    #[test]
    fn rejects_too_short() {
        assert!(normalize_guid("abc").is_none());
    }

    #[test]
    fn extracts_multiple_guids_from_message() {
        let msg = "Starting app {AB12CD34-56EF-7890-ABCD-EF0123456789} for tenant ff000000-1111-2222-3333-444444444444";
        let g = extract_guids(msg);
        assert_eq!(g.len(), 2);
        assert!(g.contains(&"ab12cd34-56ef-7890-abcd-ef0123456789".to_string()));
        assert!(g.contains(&"ff000000-1111-2222-3333-444444444444".to_string()));
    }
}

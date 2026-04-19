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

use std::collections::{HashMap, HashSet};

/// Given a per-source sample of message texts, return the set of GUIDs that
/// appear in more than `threshold` fraction (0..=1) of sampled messages across
/// at least `min_sources` distinct sources.
pub fn high_frequency_guids(
    samples: &HashMap<u16, Vec<&str>>,
    threshold: f32,
    min_sources: usize,
) -> HashSet<String> {
    let mut per_source_hit: HashMap<String, HashMap<u16, (u32, u32)>> = HashMap::new();
    for (src, msgs) in samples {
        let total = msgs.len() as u32;
        for msg in msgs {
            let guids = extract_guids(msg);
            let unique: HashSet<String> = guids.into_iter().collect();
            for g in unique {
                let entry = per_source_hit.entry(g).or_default();
                let counts = entry.entry(*src).or_insert((0, 0));
                counts.0 += 1;
                counts.1 = total;
            }
        }
    }

    let mut out: HashSet<String> = HashSet::new();
    for (guid, srcs) in per_source_hit {
        let qualifying = srcs
            .values()
            .filter(|(h, t)| *t > 0 && (*h as f32 / *t as f32) >= threshold)
            .count();
        if qualifying >= min_sources {
            out.insert(guid);
        }
    }
    out
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

#[cfg(test)]
mod tests_hf {
    use super::*;
    use std::collections::HashMap;

    const TENANT: &str = "ff000000-1111-2222-3333-444444444444";
    const APP_A: &str = "ab12cd34-56ef-7890-abcd-ef0123456789";

    #[test]
    fn tenant_guid_appearing_everywhere_is_denied() {
        // Source 0: 4 messages all mention the tenant GUID; only 1 mentions APP_A.
        let src0 = vec![
            "msg for tenant ff000000-1111-2222-3333-444444444444",
            "another tenant ff000000-1111-2222-3333-444444444444 event",
            "again tenant ff000000-1111-2222-3333-444444444444",
            "tenant ff000000-1111-2222-3333-444444444444 and app ab12cd34-56ef-7890-abcd-ef0123456789",
        ];
        // Source 1: 3 messages all mention the tenant GUID; none mention APP_A.
        let src1 = vec![
            "sync tenant ff000000-1111-2222-3333-444444444444",
            "tenant ff000000-1111-2222-3333-444444444444 auth",
            "again ff000000-1111-2222-3333-444444444444",
        ];
        let mut samples: HashMap<u16, Vec<&str>> = HashMap::new();
        samples.insert(0, src0);
        samples.insert(1, src1);

        let denied = high_frequency_guids(&samples, 0.8, 2);
        assert!(
            denied.contains(TENANT),
            "tenant GUID should be denied, got {:?}",
            denied
        );
        assert!(
            !denied.contains(APP_A),
            "per-app GUID should NOT be denied, got {:?}",
            denied
        );
    }

    #[test]
    fn guid_in_only_one_source_not_denied_even_if_frequent() {
        // Source 0: GUID APP_A appears in every message.
        let src0 = vec![
            "app ab12cd34-56ef-7890-abcd-ef0123456789 step 1",
            "app ab12cd34-56ef-7890-abcd-ef0123456789 step 2",
            "app ab12cd34-56ef-7890-abcd-ef0123456789 step 3",
        ];
        // Source 1: APP_A does not appear.
        let src1 = vec!["unrelated log line", "another unrelated line"];

        let mut samples: HashMap<u16, Vec<&str>> = HashMap::new();
        samples.insert(0, src0);
        samples.insert(1, src1);

        let denied = high_frequency_guids(&samples, 0.8, 2);
        assert!(
            !denied.contains(APP_A),
            "GUID present in only one source must not be denied, got {:?}",
            denied
        );
    }
}

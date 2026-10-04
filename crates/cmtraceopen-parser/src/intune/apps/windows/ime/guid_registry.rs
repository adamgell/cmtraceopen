pub use crate::intune::common::identity::GuidNameSource;
use crate::intune::common::identity::{
    enrich_event_name_with_name, identity_name_pairs, is_fallback_name, normalize_guid_key,
};
use crate::parser::ccm::logical::ImeLine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A resolved identity for a GUID observed in IME logs.
#[derive(Debug, Clone)]
pub struct GuidEntry {
    /// Human-readable display name.
    pub name: String,
    /// Source of the name — used for confidence ranking during merges.
    pub source: GuidNameSource,
}

/// A global GUID→name registry built by scanning IME log lines.
///
/// Any module that needs to translate a GUID into an application/script/policy
/// name can use this registry. It is built per-file during parallel analysis
/// and then merged into a single global instance.
#[derive(Debug, Clone, Default)]
pub struct GuidRegistry {
    entries: HashMap<String, GuidEntry>,
}

impl GuidRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan all lines from a single log file, accumulating GUID→name pairs.
    pub fn ingest_lines(&mut self, lines: &[ImeLine]) {
        for line in lines {
            self.ingest_message(&line.message);
        }
    }

    /// Extract GUID→name pairs from a single message string.
    fn ingest_message(&mut self, msg: &str) {
        for (guid, name, source) in identity_name_pairs(msg) {
            self.insert_if_dominated(guid, name, source);
        }
    }

    /// Insert an entry if no higher-confidence entry already exists for this GUID.
    fn insert_if_dominated(&mut self, guid: String, name: String, source: GuidNameSource) {
        let guid = normalize_guid_key(&guid);
        let dominated = self
            .entries
            .get(&guid)
            .is_none_or(|existing| source > existing.source);
        if dominated {
            self.entries.insert(guid, GuidEntry { name, source });
        }
    }

    /// Merge another registry into this one.
    /// Keeps the higher-confidence entry when the same GUID appears in both.
    pub fn merge(&mut self, other: &GuidRegistry) {
        for (guid, entry) in &other.entries {
            self.insert_if_dominated(guid.clone(), entry.name.clone(), entry.source.clone());
        }
    }

    /// Look up the display name for a GUID.
    pub fn resolve(&self, guid: &str) -> Option<&str> {
        self.entries
            .get(&normalize_guid_key(guid))
            .map(|entry| entry.name.as_str())
    }

    /// If `current_name` looks like a short-id fallback (e.g. "Download (a1b2c3d4...)"),
    /// return the resolved name for the GUID. Otherwise return `None`.
    pub fn resolve_fallback_name(&self, current_name: &str, guid: &str) -> Option<String> {
        if is_fallback_name(current_name) {
            self.resolve(guid).map(|name| name.to_string())
        } else {
            None
        }
    }

    /// Enrich an event name that ends with a short-GUID suffix like `(00591936...)`.
    ///
    /// For example:
    /// - `"AppWorkload Download Retry (00591936...)"` → `"AppWorkload Download Retry — Contoso App"`
    /// - `"Win32 App (a1b2c3d4...)"` → `"Win32 App — Contoso App"`
    ///
    /// Returns `None` if the name doesn't match the pattern or the GUID is unknown.
    pub fn enrich_event_name(&self, current_name: &str, guid: &str) -> Option<String> {
        let resolved = self.resolve(guid)?;
        enrich_event_name_with_name(current_name, resolved)
    }

    /// Number of entries in the registry.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the registry contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert a GUID→name entry from an external source (e.g. Graph API).
    pub fn insert(&mut self, guid: String, name: String, source: GuidNameSource) {
        self.insert_if_dominated(guid, name, source);
    }

    /// Collect all GUIDs that have no resolved name.
    pub fn unresolved_guids_from<'a>(&self, guids: impl Iterator<Item = &'a str>) -> Vec<String> {
        guids
            .filter(|guid| self.resolve(guid).is_none())
            .map(|g| g.to_string())
            .collect()
    }

    /// Iterate over all `(guid, entry)` pairs in the registry.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &GuidEntry)> {
        self.entries.iter()
    }

    /// Convert to a serializable map for the frontend.
    pub fn to_serializable(&self) -> HashMap<String, GuidRegistryEntry> {
        self.entries
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    GuidRegistryEntry {
                        name: v.name.clone(),
                        source: v.source.clone(),
                    },
                )
            })
            .collect()
    }
}

/// Serializable entry for the frontend GUID registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuidRegistryEntry {
    pub name: String,
    pub source: GuidNameSource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::common::identity::*;
    fn line(msg: &str) -> ImeLine {
        ImeLine {
            line_number: 1,
            timestamp: None,
            timestamp_utc: None,
            message: msg.to_string(),
            component: None,
            thread: None,
            timezone_offset: None,
        }
    }

    #[test]
    fn ingest_direct_json() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Processing app: {"AppId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","ApplicationName":"Contoso App"}"#,
        )]);
        assert_eq!(
            reg.resolve("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            Some("Contoso App")
        );
    }

    #[test]
    fn ingest_escaped_json() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Payload: {\"AppId\":\"a1b2c3d4-e5f6-7890-abcd-ef1234567890\",\"ApplicationName\":\"Remote Desktop\"}"#,
        )]);
        assert_eq!(
            reg.resolve("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            Some("Remote Desktop")
        );
    }

    #[test]
    fn higher_confidence_wins_on_merge() {
        let mut a = GuidRegistry::new();
        a.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "setup.exe".to_string(),
                source: GuidNameSource::SetUpFilePath,
            },
        );

        let mut b = GuidRegistry::new();
        b.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        a.merge(&b);
        assert_eq!(a.resolve("guid-1"), Some("Contoso App"));
    }

    #[test]
    fn lower_confidence_does_not_overwrite() {
        let mut a = GuidRegistry::new();
        a.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        let mut b = GuidRegistry::new();
        b.entries.insert(
            "guid-1".to_string(),
            GuidEntry {
                name: "setup.exe".to_string(),
                source: GuidNameSource::SetUpFilePath,
            },
        );

        a.merge(&b);
        assert_eq!(a.resolve("guid-1"), Some("Contoso App"));
    }

    #[test]
    fn resolve_fallback_name_replaces_short_id() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.resolve_fallback_name(
                "Download (a1b2c3d4...)",
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            ),
            Some("Contoso App".to_string())
        );
    }

    #[test]
    fn resolve_fallback_name_preserves_real_name() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Other App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.resolve_fallback_name("Contoso App", "a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            None
        );
    }

    #[test]
    fn empty_registry() {
        let reg = GuidRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert_eq!(reg.resolve("anything"), None);
    }

    #[test]
    fn setup_file_path_extraction() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Download started: {"AppId":"a1b2c3d4-e5f6-7890-abcd-ef1234567890","SetUpFilePath":"C:\\Cache\\MyInstaller.exe"}"#,
        )]);
        assert_eq!(
            reg.resolve("a1b2c3d4-e5f6-7890-abcd-ef1234567890"),
            Some("MyInstaller.exe")
        );
    }

    #[test]
    fn policy_payload_id_and_name_extracted() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{"Id":"00591936-3d7f-4c79-bd9e-550b09c2e8d9","Name":"Update for Remote Desktop Manager 2026.1.12.0","Version":1}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for Remote Desktop Manager 2026.1.12.0")
        );
    }

    #[test]
    fn escaped_policy_payload_id_and_name_extracted() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{\"Id\":\"00591936-3d7f-4c79-bd9e-550b09c2e8d9\",\"Name\":\"Update for Remote Desktop Manager 2026.1.12.0\",\"Version\":1}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for Remote Desktop Manager 2026.1.12.0")
        );
    }

    #[test]
    fn multi_entry_policy_array_extracts_all_guids() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{"Id":"00591936-3d7f-4c79-bd9e-550b09c2e8d9","Name":"Update for Remote Desktop Manager 2026.1.12.0","Version":1},{"Id":"bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d","Name":"7-Zip 24.09","Version":3}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for Remote Desktop Manager 2026.1.12.0")
        );
        assert_eq!(
            reg.resolve("bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d"),
            Some("7-Zip 24.09")
        );
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn multi_entry_escaped_policy_array_extracts_all_guids() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[line(
            r#"Get policies = [{\"Id\":\"00591936-3d7f-4c79-bd9e-550b09c2e8d9\",\"Name\":\"Update for RDM\",\"Version\":1},{\"Id\":\"bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d\",\"Name\":\"7-Zip\",\"Version\":3}]"#,
        )]);
        assert_eq!(
            reg.resolve("00591936-3d7f-4c79-bd9e-550b09c2e8d9"),
            Some("Update for RDM")
        );
        assert_eq!(
            reg.resolve("bf98868f-45ed-49bd-b0b9-1e0b14b1dd9d"),
            Some("7-Zip")
        );
    }

    #[test]
    fn enrich_event_name_replaces_full_guid_suffix() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "00591936-aaaa-bbbb-cccc-ddddeeeeeeee".to_string(),
            GuidEntry {
                name: "Remote Desktop Manager".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "AppWorkload Download Retry (00591936-aaaa-bbbb-cccc-ddddeeeeeeee)",
                "00591936-aaaa-bbbb-cccc-ddddeeeeeeee"
            ),
            Some("AppWorkload Download Retry — Remote Desktop Manager".to_string())
        );
    }

    #[test]
    fn enrich_event_name_replaces_legacy_short_guid_suffix() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "00591936-aaaa-bbbb-cccc-ddddeeeeeeee".to_string(),
            GuidEntry {
                name: "Remote Desktop Manager".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "AppWorkload Download Retry (00591936...)",
                "00591936-aaaa-bbbb-cccc-ddddeeeeeeee"
            ),
            Some("AppWorkload Download Retry — Remote Desktop Manager".to_string())
        );
    }

    #[test]
    fn enrich_event_name_works_for_win32_app() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Contoso App".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "Win32 App (a1b2c3d4-e5f6-7890-abcd-ef1234567890)",
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            ),
            Some("Win32 App — Contoso App".to_string())
        );
    }

    #[test]
    fn enrich_event_name_returns_none_for_real_name() {
        let mut reg = GuidRegistry::new();
        reg.entries.insert(
            "a1b2c3d4-e5f6-7890-abcd-ef1234567890".to_string(),
            GuidEntry {
                name: "Other".to_string(),
                source: GuidNameSource::ApplicationName,
            },
        );

        assert_eq!(
            reg.enrich_event_name(
                "ClientHealth Heartbeat Failed",
                "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            ),
            None
        );
    }

    #[test]
    fn enrich_event_name_returns_none_for_unknown_guid() {
        let reg = GuidRegistry::new();
        assert_eq!(
            reg.enrich_event_name(
                "AppWorkload Download (00591936-aaaa-bbbb-cccc-ddddeeeeeeee)",
                "00591936-aaaa-bbbb-cccc-ddddeeeeeeee"
            ),
            None
        );
    }

    #[test]
    fn to_serializable_preserves_entries_and_sources() {
        let mut reg = GuidRegistry::new();
        reg.ingest_lines(&[
            line(r#"Processing app: {"AppId":"aaaa1111-2222-3333-4444-555566667777","ApplicationName":"Contoso App"}"#),
            line(r#"Download started: {"AppId":"bbbb1111-2222-3333-4444-555566667777","SetUpFilePath":"C:\\Cache\\installer.exe"}"#),
        ]);

        let map = reg.to_serializable();
        assert_eq!(map.len(), 2);

        let contoso = &map["aaaa1111-2222-3333-4444-555566667777"];
        assert_eq!(contoso.name, "Contoso App");
        assert_eq!(contoso.source, GuidNameSource::ApplicationName);

        let installer = &map["bbbb1111-2222-3333-4444-555566667777"];
        assert_eq!(installer.name, "installer.exe");
        assert_eq!(installer.source, GuidNameSource::SetUpFilePath);

        // Verify JSON serialization contract
        let json = serde_json::to_value(&map).expect("serialize registry map");
        assert_eq!(
            json["aaaa1111-2222-3333-4444-555566667777"]["name"].as_str(),
            Some("Contoso App")
        );
        assert_eq!(
            json["aaaa1111-2222-3333-4444-555566667777"]["source"].as_str(),
            Some("ApplicationName")
        );
        assert_eq!(
            json["bbbb1111-2222-3333-4444-555566667777"]["source"].as_str(),
            Some("SetUpFilePath")
        );
    }

    #[test]
    fn app_id_fields_only_supply_valid_guid_identities() {
        let valid_guid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

        assert_eq!(
            extract_app_id(&format!(r#"launch {{"AppId":"{valid_guid}"}}"#)),
            Some(valid_guid.to_string())
        );
        assert_eq!(extract_app_id(r#"launch {"AppId":"script-你好"}"#), None);
        assert_eq!(
            extract_app_id(r#"launch {"AppId":"zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"}"#),
            None
        );

        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&[line(
            r#"Processing app: {"AppId":"script-你好","ApplicationName":"Contoso Script"}"#,
        )]);
        assert!(registry.is_empty());
    }

    #[test]
    fn spaced_app_id_fallback_rejects_malformed_guid_shapes() {
        let malformed_values = [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "a1b2c3d-e5f67-890a-abcd-ef1234567890",
        ];

        for value in malformed_values {
            let message = format!(
                r#"Processing app: {{"AppId" : "{value}","ApplicationName":"Contoso App"}}"#
            );
            assert_eq!(extract_app_id(&message), None, "accepted {value}");

            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert!(registry.is_empty(), "registered {value}");
        }
    }

    #[test]
    fn invalid_explicit_identity_fields_suppress_line_wide_guid_fallback() {
        let unrelated_guid = "11111111-2222-3333-4444-555555555555";
        let messages = [
            format!(
                r#"tenant {unrelated_guid} {{"AppId":"not-an-app-guid","ApplicationName":"Contoso"}}"#
            ),
            format!(
                r#"tenant {unrelated_guid} {{\"AppId\":\"not-an-app-guid\",\"ApplicationName\":\"Contoso\"}}"#
            ),
            format!(r#"tenant {unrelated_guid} {{"Id":"not-an-app-guid","Name":"Contoso"}}"#),
            format!(
                r#"tenant {unrelated_guid} {{\"Id\" : \"not-an-app-guid\",\"Name\":\"Contoso\"}}"#
            ),
        ];

        for message in messages {
            assert_eq!(extract_app_id(&message), None, "accepted {message}");

            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert!(registry.is_empty(), "registered from {message}");
        }
    }

    #[test]
    fn app_id_syntaxes_precede_id_in_registry_identity_selection() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let id_guid = "11111111-2222-3333-4444-555555555555";
        let messages = [
            format!(r#"{{"AppId":"{app_guid}","Id":"{id_guid}","Name":"Contoso"}}"#),
            format!(r#"{{\"AppId\":\"{app_guid}\",\"Id\":\"{id_guid}\",\"Name\":\"Contoso\"}}"#),
            format!(r#"{{"AppId" : "{app_guid}","Id":"{id_guid}","Name":"Contoso"}}"#),
            format!(r#"{{\"AppId\" : \"{app_guid}\",\"Id\":\"{id_guid}\",\"Name\":\"Contoso\"}}"#),
            format!(r#"{{"AppId":"Win32App_{app_guid}_1","Id":"{id_guid}","Name":"Contoso"}}"#),
            format!(
                r#"{{\"AppId\":\"Win32App_{app_guid}_1\",\"Id\":\"{id_guid}\",\"Name\":\"Contoso\"}}"#
            ),
            format!(r#"{{"Id":"{id_guid}","AppId" : "{app_guid}","Name":"Contoso"}}"#),
            format!(
                r#"{{\"Id\":\"{id_guid}\",\"AppId\":\"Win32App_{app_guid}_1\",\"Name\":\"Contoso\"}}"#
            ),
        ];

        for message in messages {
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);

            assert_eq!(
                registry.resolve(app_guid),
                Some("Contoso"),
                "AppId was not selected for {message}"
            );
            assert_eq!(
                registry.resolve(id_guid),
                None,
                "lower-priority Id was also registered for {message}"
            );
            assert_eq!(registry.len(), 1, "unexpected identities for {message}");
        }
    }

    #[test]
    fn invalid_app_id_still_allows_valid_id_registry_fallback() {
        let id_guid = "11111111-2222-3333-4444-555555555555";
        let message = format!(r#"{{"AppId":"invalid","Id":"{id_guid}","Name":"Contoso"}}"#);
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&[line(&message)]);

        assert_eq!(registry.resolve(id_guid), Some("Contoso"));
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn duplicate_explicit_identity_conflicts_fail_closed() {
        let first = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let second = "11111111-2222-3333-4444-555555555555";
        let messages = [
            format!(r#"{{"AppId":"{first}","AppId":"{second}","Name":"Contoso"}}"#),
            format!(r#"{{"Id":"{first}","Id":"{second}","Name":"Contoso"}}"#),
            format!(r#"{{"AppId":"{first}",\"AppId\":\"{second}\","Name":"Contoso"}}"#),
            format!(r#"{{"Id":"{first}",\"Id\":\"{second}\","Name":"Contoso"}}"#),
            format!(r#"{{"AppId":"invalid","AppId":"{first}","Name":"Contoso"}}"#),
            format!(r#"{{"Id":"invalid","Id":"{first}","Name":"Contoso"}}"#),
        ];

        for message in messages {
            assert_eq!(
                explicit_app_identity(&message),
                ExplicitAppIdentity::Invalid,
                "did not fail closed for {message}"
            );

            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert!(registry.is_empty(), "registered identity from {message}");
        }
    }

    #[test]
    fn registry_keeps_independent_id_name_objects_alongside_app_id() {
        let app_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let first_id = "11111111-2222-3333-4444-555555555555";
        let second_id = "66666666-7777-8888-9999-000000000000";
        let messages = [
            format!(
                r#"App {{"AppId":"{app_guid}","ApplicationName":"Shared Name"}} Policies [{{"Id":"{first_id}","Name":"Shared Name"}},{{"Id":"{second_id}","Name":"Policy Two"}}]"#
            ),
            format!(
                r#"App {{\"AppId\":\"{app_guid}\",\"ApplicationName\":\"Contoso App\"}} Policies [{{\"Id\":\"{first_id}\",\"Name\":\"Policy One\"}},{{\"Id\":\"{second_id}\",\"Name\":\"Policy Two\"}}]"#
            ),
        ];

        for message in messages {
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);

            assert!(
                registry.resolve(app_guid).is_some(),
                "missing AppId mapping"
            );
            assert!(
                registry.resolve(first_id).is_some(),
                "missing first Id mapping"
            );
            assert_eq!(registry.resolve(second_id), Some("Policy Two"));
            assert_eq!(
                registry.len(),
                3,
                "wrong object-boundary result for {message}"
            );
        }
    }

    #[test]
    fn registry_keeps_id_pair_on_object_with_nested_metadata() {
        let outer_id = "11111111-2222-3333-4444-555555555555";
        let inner_id = "66666666-7777-8888-9999-000000000000";
        let messages = [
            format!(
                r#"{{"Id":"{outer_id}","Name":"Outer Policy","Metadata":{{"Id":"{inner_id}","Name":"Inner Policy"}}}}"#
            ),
            format!(
                r#"{{\"Id\":\"{outer_id}\",\"Name\":\"Outer Policy\",\"Metadata\":{{\"Id\":\"{inner_id}\",\"Name\":\"Inner Policy\"}}}}"#
            ),
        ];

        for message in messages {
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert_eq!(
                registry.resolve(outer_id),
                Some("Outer Policy"),
                "lost outer object fields for {message}"
            );
            assert_eq!(registry.resolve(inner_id), Some("Inner Policy"));
        }
    }

    #[test]
    fn registry_keys_are_case_insensitive_and_serialize_once() {
        let lower = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let upper = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";

        let mut graph = GuidRegistry::new();
        graph.insert(
            upper.to_string(),
            "Graph Name".to_string(),
            GuidNameSource::GraphApi,
        );
        assert_eq!(graph.resolve(lower), Some("Graph Name"));
        assert_eq!(graph.resolve(upper), Some("Graph Name"));
        assert_eq!(
            graph.resolve_fallback_name("Download (aaaaaaaa...)", lower),
            Some("Graph Name".to_string())
        );
        assert_eq!(
            graph.enrich_event_name("Win32 App (aaaaaaaa...)", upper),
            Some("Win32 App — Graph Name".to_string())
        );
        assert!(graph
            .unresolved_guids_from([lower, upper].into_iter())
            .is_empty());

        let mut parsed = GuidRegistry::new();
        parsed.insert(
            lower.to_string(),
            "Parsed Name".to_string(),
            GuidNameSource::NameField,
        );
        assert_eq!(parsed.resolve(upper), Some("Parsed Name"));
        parsed.merge(&graph);

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed.resolve(lower), Some("Graph Name"));
        let serialized = parsed.to_serializable();
        assert_eq!(serialized.len(), 1);
        assert!(serialized.contains_key(lower));
        assert!(!serialized.contains_key(upper));
    }

    #[test]
    fn registry_never_binds_an_identity_to_a_sibling_name() {
        let app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let policy = "11111111-2222-3333-4444-555555555555";
        let laundering_attempts = [
            format!(r#"[{{"AppId":"{app}"}},{{"Name":"Wrong Name"}}]"#),
            format!(r#"[{{"Name":"Wrong Name"}},{{"AppId":"{app}"}}]"#),
            format!(r#"[{{"Id":"{policy}"}},{{"Name":"Wrong Name"}}]"#),
            format!(r#"[{{"Name":"Wrong Name"}},{{"Id":"{policy}"}}]"#),
        ];

        for message in laundering_attempts {
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert!(registry.is_empty(), "laundered sibling name for {message}");
        }

        let valid_orders = [
            format!(
                r#"[{{"AppId":"{app}","Name":"App Name"}},{{"Id":"{policy}","Name":"Policy Name"}}]"#
            ),
            format!(
                r#"[{{"Id":"{policy}","Name":"Policy Name"}},{{"AppId":"{app}","Name":"App Name"}}]"#
            ),
        ];
        for message in valid_orders {
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert_eq!(registry.resolve(app), Some("App Name"));
            assert_eq!(registry.resolve(policy), Some("Policy Name"));
            assert_eq!(registry.len(), 2);
        }
    }

    #[test]
    fn registry_rejects_conflicting_duplicate_names() {
        let app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let messages = [
            format!(r#"{{"AppId":"{app}","Name":"First Name","Name":"Second Name"}}"#),
            format!(r#"{{"AppId":"{app}","Name":"Second Name","Name":"First Name"}}"#),
        ];

        for message in messages {
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert_eq!(
                registry.resolve(app),
                None,
                "accepted conflicting name from {message}"
            );
        }
    }

    #[test]
    fn registry_keeps_identical_names_and_application_name_precedence() {
        let app = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let cases = [
            (
                format!(r#"{{"AppId":"{app}","Name":"Same Name","Name":"Same Name"}}"#),
                "Same Name",
            ),
            (
                format!(r#"{{"AppId":"{app}","ApplicationName":"Preferred","Name":"Fallback"}}"#),
                "Preferred",
            ),
            (
                format!(r#"{{"AppId":"{app}","Name":"Fallback","ApplicationName":"Preferred"}}"#),
                "Preferred",
            ),
        ];

        for (message, expected) in cases {
            let mut registry = GuidRegistry::new();
            registry.ingest_lines(&[line(&message)]);
            assert_eq!(registry.resolve(app), Some(expected));
        }
    }

    #[test]
    fn registry_keeps_independent_root_and_object_local_pairs() {
        let root = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let object = "11111111-2222-3333-4444-555555555555";
        let message = format!(
            r#""AppId":"{root}","Name":"Root Name" [{{"Id":"{object}","Name":"Object Name"}}]"#
        );

        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&[line(&message)]);

        assert_eq!(registry.resolve(root), Some("Root Name"));
        assert_eq!(registry.resolve(object), Some("Object Name"));
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn over_depth_json_fails_closed() {
        let guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let depth = 129;
        let mut message = format!(r#"{{"AppId":"{guid}","Name":"Outer""#);
        for _ in 1..depth {
            message.push_str(r#", "Metadata":{"#);
        }
        for _ in 0..depth {
            message.push('}');
        }

        assert_eq!(
            explicit_app_identity(&message),
            ExplicitAppIdentity::Invalid
        );
        let mut registry = GuidRegistry::new();
        registry.ingest_lines(&[line(&message)]);
        assert!(registry.is_empty());
    }
}

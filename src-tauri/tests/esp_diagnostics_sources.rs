use std::cell::RefCell;
use std::collections::HashMap;

use app_lib::esp::registry::{
    classify_registry_scope, collect_registry_evidence, RegistryProvider, RegistryReadError,
    RegistrySnapshotKey, RegistryTarget, RegistryValueSnapshot, ESP_REGISTRY_TARGETS,
    MAX_REGISTRY_DEPTH, MAX_REGISTRY_VALUE_BYTES, REGISTRY_READ_ACCESS,
};
use cmtraceopen_parser::esp::{EspObservationValue, EspScope, EspSourceAccessState, EspSourceKind};

#[derive(Default)]
struct FakeRegistryProvider {
    trees: HashMap<String, Result<Vec<RegistrySnapshotKey>, RegistryReadError>>,
    display_names: HashMap<String, String>,
    reads: RefCell<Vec<(String, u32)>>,
    uninstall_lookups: RefCell<Vec<(String, u32)>>,
}

impl FakeRegistryProvider {
    fn with_tree(mut self, key: &str, entries: Vec<RegistrySnapshotKey>) -> Self {
        self.trees.insert(key.to_string(), Ok(entries));
        self
    }

    fn with_error(mut self, key: &str, error: RegistryReadError) -> Self {
        self.trees.insert(key.to_string(), Err(error));
        self
    }

    fn with_display_name(mut self, product_code: &str, display_name: &str) -> Self {
        self.display_names
            .insert(product_code.to_ascii_uppercase(), display_name.to_string());
        self
    }
}

impl RegistryProvider for FakeRegistryProvider {
    fn read_tree(
        &self,
        target: &RegistryTarget,
        access: u32,
    ) -> Result<Vec<RegistrySnapshotKey>, RegistryReadError> {
        self.reads
            .borrow_mut()
            .push((target.key.to_string(), access));
        self.trees
            .get(target.key)
            .cloned()
            .unwrap_or(Err(RegistryReadError::Missing))
    }

    fn lookup_uninstall_display_name(
        &self,
        product_code: &str,
        access: u32,
    ) -> Result<Option<String>, RegistryReadError> {
        let normalized = product_code.to_ascii_uppercase();
        self.uninstall_lookups
            .borrow_mut()
            .push((normalized.clone(), access));
        Ok(self.display_names.get(&normalized).cloned())
    }
}

fn snapshot_key(relative_key: &str, values: Vec<RegistryValueSnapshot>) -> RegistrySnapshotKey {
    RegistrySnapshotKey {
        relative_key: relative_key.to_string(),
        values,
    }
}

#[test]
fn registry_uses_read_only_64_bit_access_for_every_fixed_root() {
    let provider = FakeRegistryProvider::default();

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");

    assert_eq!(evidence.roots.len(), ESP_REGISTRY_TARGETS.len());
    let reads = provider.reads.borrow();
    assert_eq!(reads.len(), ESP_REGISTRY_TARGETS.len());
    assert!(reads
        .iter()
        .all(|(_, access)| *access == REGISTRY_READ_ACCESS));
    assert_eq!(
        reads
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>(),
        ESP_REGISTRY_TARGETS
            .iter()
            .map(|target| target.key)
            .collect::<Vec<_>>()
    );

    let source = include_str!("../src/esp/registry.rs");
    for forbidden in [
        "create_subkey",
        "set_raw_value",
        ".set_value",
        "delete_subkey",
        "delete_value",
        "reg.exe import",
    ] {
        assert!(
            !source.contains(forbidden),
            "registry acquisition must not expose mutation API {forbidden}"
        );
    }
}

#[test]
fn registry_enforces_depth_and_value_size_caps_and_retains_provenance() {
    let target = &ESP_REGISTRY_TARGETS[0];
    let too_deep = (0..=MAX_REGISTRY_DEPTH)
        .map(|index| format!("level-{index}"))
        .collect::<Vec<_>>()
        .join("\\");
    let provider = FakeRegistryProvider::default().with_tree(
        target.key,
        vec![
            snapshot_key(
                "Profile",
                vec![RegistryValueSnapshot::text("TenantDomain", "contoso.com")],
            ),
            snapshot_key(
                &too_deep,
                vec![RegistryValueSnapshot::text("IgnoredDepth", "value")],
            ),
            snapshot_key(
                "Profile",
                vec![RegistryValueSnapshot::text_with_size(
                    "IgnoredLargeValue",
                    "truncated-at-source",
                    MAX_REGISTRY_VALUE_BYTES + 1,
                )],
            ),
        ],
    );

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");

    assert_eq!(evidence.observations.len(), 1);
    let observation = &evidence.observations[0].observation;
    assert_eq!(observation.hive, "HKLM");
    assert_eq!(
        observation.key,
        format!("{}\\Profile", ESP_REGISTRY_TARGETS[0].key)
    );
    assert_eq!(observation.value_name, "TenantDomain");
    assert_eq!(
        observation.value,
        EspObservationValue::Text("contoso.com".to_string())
    );
    assert_eq!(
        observation.context.provenance.source_kind,
        EspSourceKind::Registry
    );
    let provenance = observation
        .context
        .provenance
        .registry
        .as_ref()
        .expect("registry provenance");
    assert_eq!(provenance.hive, "HKLM");
    assert_eq!(provenance.key, observation.key);
    assert_eq!(provenance.value_name.as_deref(), Some("TenantDomain"));
}

#[test]
fn registry_orders_numeric_node_cache_entries_without_stopping_at_gaps() {
    let target = ESP_REGISTRY_TARGETS
        .iter()
        .find(|target| target.key.ends_with(r"NodeCache\CSP"))
        .expect("NodeCache target");
    let provider = FakeRegistryProvider::default().with_tree(
        target.key,
        vec![
            snapshot_key(
                "10",
                vec![RegistryValueSnapshot::text("NodeURI", "./Vendor/MSFT/Ten")],
            ),
            snapshot_key(
                "0",
                vec![RegistryValueSnapshot::text("NodeURI", "./Vendor/MSFT/Zero")],
            ),
            snapshot_key(
                "2",
                vec![
                    RegistryValueSnapshot::text("NodeURI", "./Vendor/MSFT/Two"),
                    RegistryValueSnapshot::text("ExpectedValue", "2"),
                ],
            ),
        ],
    );

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");

    assert_eq!(
        evidence
            .node_cache
            .iter()
            .map(|entry| entry.index)
            .collect::<Vec<_>>(),
        vec![0, 2, 10]
    );
    assert_eq!(evidence.node_cache[1].expected_value.as_deref(), Some("2"));
}

#[test]
fn registry_distinguishes_missing_and_permission_denied_per_root() {
    let provider = FakeRegistryProvider::default()
        .with_error(ESP_REGISTRY_TARGETS[0].key, RegistryReadError::Missing)
        .with_error(
            ESP_REGISTRY_TARGETS[1].key,
            RegistryReadError::PermissionDenied,
        );

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");

    assert_eq!(
        evidence.roots[0].access_state,
        EspSourceAccessState::Missing
    );
    assert_eq!(
        evidence.roots[1].access_state,
        EspSourceAccessState::PermissionDenied
    );
}

#[test]
fn registry_keeps_device_and_user_enrollment_branches_separate() {
    assert_eq!(
        classify_registry_scope(
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\Device\Setup"
        ),
        Some(EspScope::Device)
    );
    assert_eq!(
        classify_registry_scope(
            r"SOFTWARE\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\User\S-1-5-21\Setup"
        ),
        Some(EspScope::User)
    );

    let target = ESP_REGISTRY_TARGETS
        .iter()
        .find(|target| target.key.ends_with("EnrollmentStatusTracking"))
        .expect("ESP target");
    let provider = FakeRegistryProvider::default().with_tree(
        target.key,
        vec![
            snapshot_key(
                "Device\\Setup",
                vec![RegistryValueSnapshot::integer("Status", 3)],
            ),
            snapshot_key(
                "User\\S-1-5-21\\Setup",
                vec![RegistryValueSnapshot::integer("Status", 4)],
            ),
        ],
    );

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");
    let scoped = evidence
        .observations
        .iter()
        .filter_map(|observation| observation.scope.clone())
        .collect::<Vec<_>>();
    assert_eq!(scoped, vec![EspScope::Device, EspScope::User]);
}

#[test]
fn registry_queries_uninstall_names_only_for_observed_product_codes() {
    let provider = FakeRegistryProvider::default()
        .with_display_name("{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", "Contoso Agent")
        .with_display_name("{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}", "Contoso Helper");

    let observed = vec![
        "{bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb}".to_string(),
        "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}".to_string(),
        "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}".to_string(),
    ];
    let evidence = collect_registry_evidence(&provider, &observed, "2026-07-15T12:00:00Z");

    assert_eq!(
        provider.uninstall_lookups.borrow().as_slice(),
        &[
            (
                "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}".to_string(),
                REGISTRY_READ_ACCESS,
            ),
            (
                "{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}".to_string(),
                REGISTRY_READ_ACCESS,
            ),
        ]
    );
    assert_eq!(evidence.uninstall_names.len(), 2);
    assert_eq!(evidence.uninstall_names[0].display_name, "Contoso Agent");
    assert_eq!(evidence.uninstall_names[1].display_name, "Contoso Helper");
}

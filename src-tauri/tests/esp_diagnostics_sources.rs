use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier, Condvar, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use app_lib::esp::archive::{
    extract_captured_archive, extract_captured_archive_with_cancel_in, validate_archive_manifest,
    ArchiveEntryKind, ArchiveEntryMetadata, ArchiveError, ArchiveFormat, MAX_ARCHIVE_ENTRIES,
    MAX_ARCHIVE_FILE_BYTES, MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES,
};
use app_lib::esp::bundle::{
    analyze_captured_evidence_at, BundleError, MAX_JSON_SCALAR_RECORDS, MAX_LEGACY_BUNDLE_DEPTH,
    MAX_LEGACY_BUNDLE_ENTRIES,
};
#[cfg(target_os = "windows")]
use app_lib::esp::discovery::default_known_source_specs;
use app_lib::esp::discovery::{
    build_runtime_temp_roots, discover_bounded_logs, embedded_known_source_specs,
    DiscoveredLogSource, DiscoveryInput, DiscoveryPathFailureKind, DiscoveryRootKind,
    DiscoveryRootState, DiscoverySourceOrigin, KnownSourceSpec, DISCOVERY_INTERVAL,
    MAX_ACTIVE_TAILS, MAX_INITIAL_READ_BYTES, MAX_KNOWN_ENTRIES_PROBED_PER_ROOT,
    MAX_ROTATIONS_PER_KNOWN_LOG, MAX_SESSION_DURATION, MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT,
    MAX_TEMP_ENTRIES_PROBED_PER_ROOT, TEMP_LOOKBACK, UPDATE_DEBOUNCE,
};
use app_lib::esp::event_logs::{
    collect_event_evidence, required_event_id_xpath, EventLogProvider, EventSourceError,
    ESP_EVENT_CHANNELS, MAX_ESP_EVENT_RECORDS_PER_CHANNEL, REQUIRED_EVENT_IDS,
};
use app_lib::esp::live_session::{
    discovery_result_to_batch, event_evidence_to_batch, registry_evidence_to_batch,
    tail_poll_to_batch, tail_reconcile_to_batch,
};
use app_lib::esp::process::sanitize_command_line;
use app_lib::esp::registry::{
    classify_registry_scope, collect_registry_evidence, RegistryProvider, RegistryReadError,
    RegistrySnapshotKey, RegistryTarget, RegistryValueSnapshot, ESP_REGISTRY_TARGETS,
    MAX_REGISTRY_DEPTH, MAX_REGISTRY_VALUE_BYTES, REGISTRY_READ_ACCESS,
};
use app_lib::esp::session::{
    EspCancellation, EspClockReading, EspDiscoveryBatch, EspDiscoveryProvider, EspEvidenceProvider,
    EspProviderBatch, EspSessionClock, EspSessionDependencies, EspSessionError,
    EspSessionEventSink, EspSessionManager, EspSessionState, EspSessionTail, EspSessionTailFactory,
    EspTailEvidenceBatch, EspUpdateReason,
};
use app_lib::esp::system::{delivery_optimization_from_rows, SystemEvidence, SystemRow};
use app_lib::esp::tailing::{
    EspTailResetReason, EspTailSet, MAX_DORMANT_TAIL_CURSORS, MAX_SESSION_TAIL_SOURCES,
    WINDOWS_SHARED_READ_WRITE_DELETE,
};
use app_lib::intune::evtx_parser::{
    parse_esp_event_xml, EventLogProperty, ParsedEspEventRecord, MAX_ESP_EVTX_RECORD_BYTES,
};
use cmtraceopen_parser::esp::{
    EspArtifactCoverage, EspArtifactStatus, EspDiagnosticsReducer, EspElevationState,
    EspEvidenceProvenance, EspEvidenceRecord, EspEvidenceRef, EspGraphObservation,
    EspGraphObservationSection, EspHardwareEvidence, EspObservationContext, EspObservationValue,
    EspParseState, EspRegistryObservation, EspRegistryProvenance, EspScope, EspSensitivity,
    EspSourceAccessState, EspSourceKind, EspSystemFact, EspSystemObservation, GraphApiVersion,
};
use tempfile::tempdir;

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
        access_error: None,
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
fn registry_excludes_hardware_hash_keys_and_values_before_evidence_is_created() {
    let target = &ESP_REGISTRY_TARGETS[0];
    let provider = FakeRegistryProvider::default().with_tree(
        target.key,
        vec![
            snapshot_key(
                "Safe",
                vec![
                    RegistryValueSnapshot::text("TenantDomain", "contoso.com"),
                    RegistryValueSnapshot::text("HARDWARE_HASH", "value-secret-sentinel"),
                    RegistryValueSnapshot::text(
                        "device.hardware-data",
                        "second-value-secret-sentinel",
                    ),
                ],
            ),
            snapshot_key(
                "Device-Hardware_Data\\Child",
                vec![RegistryValueSnapshot::text(
                    "SafeLookingName",
                    "key-secret-sentinel",
                )],
            ),
            snapshot_key(
                "hardware/hash",
                vec![RegistryValueSnapshot::text(
                    "AnotherSafeName",
                    "second-key-secret-sentinel",
                )],
            ),
        ],
    );

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");
    let serialized = serde_json::to_string(&evidence).expect("serialize registry evidence");

    assert_eq!(evidence.observations.len(), 1);
    assert_eq!(
        evidence.observations[0].observation.value_name,
        "TenantDomain"
    );
    for forbidden in [
        "value-secret-sentinel",
        "second-value-secret-sentinel",
        "key-secret-sentinel",
        "second-key-secret-sentinel",
        "HARDWARE_HASH",
        "device.hardware-data",
        "Device-Hardware_Data",
        "hardware/hash",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "excluded hardware identity material leaked through {forbidden}"
        );
    }
}

#[test]
fn registry_excludes_node_cache_hardware_payloads_identified_by_node_uri() {
    let target = ESP_REGISTRY_TARGETS
        .iter()
        .find(|target| target.key.ends_with(r"NodeCache\CSP"))
        .expect("NodeCache target");
    let provider = FakeRegistryProvider::default().with_tree(
        target.key,
        vec![
            snapshot_key(
                "1",
                vec![
                    RegistryValueSnapshot::text("NodeURI", "./DevDetail/Ext/Device-Hardware_Data"),
                    RegistryValueSnapshot::text(
                        "ExpectedValue",
                        "raw-device-hardware-data-sentinel",
                    ),
                ],
            ),
            snapshot_key(
                "2",
                vec![
                    RegistryValueSnapshot::text(
                        "NodeURI",
                        "./Vendor/MSFT/Policy/Config/Contoso/SafeSetting",
                    ),
                    RegistryValueSnapshot::text("ExpectedValue", "safe-neighbor-value"),
                ],
            ),
            snapshot_key(
                "3",
                vec![
                    RegistryValueSnapshot::text("NodeURI", "./Vendor/MSFT/Autopilot/HARDWARE_HASH"),
                    RegistryValueSnapshot::text("ExpectedValue", "raw-hardware-hash-sentinel"),
                ],
            ),
        ],
    );

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");
    let serialized = serde_json::to_string(&evidence).expect("serialize registry evidence");

    assert_eq!(evidence.node_cache.len(), 1);
    assert_eq!(evidence.node_cache[0].index, 2);
    assert_eq!(
        evidence.node_cache[0].expected_value.as_deref(),
        Some("safe-neighbor-value")
    );
    assert!(serialized.contains("safe-neighbor-value"));
    for forbidden in [
        "raw-device-hardware-data-sentinel",
        "raw-hardware-hash-sentinel",
        "Device-Hardware_Data",
        "HARDWARE_HASH",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "NodeCache hardware identity material leaked through {forbidden}"
        );
    }
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
fn registry_preserves_descendant_failures_while_root_remains_available() {
    let target = &ESP_REGISTRY_TARGETS[0];
    let provider = FakeRegistryProvider::default().with_tree(
        target.key,
        vec![
            snapshot_key(
                "Readable",
                vec![RegistryValueSnapshot::text("TenantDomain", "contoso.com")],
            ),
            snapshot_key(
                r"User\S-1-5-21-111111111-222222222-333333333-1001\Readable",
                vec![RegistryValueSnapshot::integer("Status", 3)],
            ),
            RegistrySnapshotKey {
                relative_key: "Restricted".to_string(),
                values: Vec::new(),
                access_error: Some(RegistryReadError::PermissionDenied),
            },
            RegistrySnapshotKey {
                relative_key: r"User\S-1-5-21-111111111-222222222-333333333-1001\Restricted"
                    .to_string(),
                values: Vec::new(),
                access_error: Some(RegistryReadError::PermissionDenied),
            },
            RegistrySnapshotKey {
                relative_key: "Broken".to_string(),
                values: Vec::new(),
                access_error: Some(RegistryReadError::Failed(
                    "subkey enumeration failed".to_string(),
                )),
            },
        ],
    );

    let evidence = collect_registry_evidence(&provider, &[], "2026-07-15T12:00:00Z");

    assert_eq!(
        evidence.roots[0].access_state,
        EspSourceAccessState::Available
    );
    assert_eq!(evidence.observations.len(), 2);
    let sid_observation = evidence
        .observations
        .iter()
        .find(|observation| observation.observation.key.contains("S-1-5-21-"))
        .expect("readable SID observation");
    assert_eq!(
        sid_observation.observation.context.sensitivity,
        EspSensitivity::Sensitive
    );
    assert_eq!(evidence.descendant_coverage.len(), 3);
    assert_eq!(
        evidence.descendant_coverage[0].key,
        format!("{}\\Broken", target.key)
    );
    assert_eq!(
        evidence.descendant_coverage[0].access_state,
        EspSourceAccessState::Failed
    );
    assert_eq!(
        evidence.descendant_coverage[0].sensitivity,
        EspSensitivity::Public
    );
    assert!(evidence.descendant_coverage[0]
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("subkey enumeration failed")));
    assert_eq!(
        evidence.descendant_coverage[1].key,
        format!("{}\\Restricted", target.key)
    );
    assert_eq!(
        evidence.descendant_coverage[1].access_state,
        EspSourceAccessState::PermissionDenied
    );
    assert_eq!(
        evidence.descendant_coverage[1].sensitivity,
        EspSensitivity::Public
    );
    assert!(evidence.descendant_coverage[1]
        .detail
        .as_deref()
        .is_some_and(|detail| detail.to_ascii_lowercase().contains("administrator")));
    assert_eq!(
        evidence.descendant_coverage[2].key,
        format!(
            r"{}\User\S-1-5-21-111111111-222222222-333333333-1001\Restricted",
            target.key
        )
    );
    assert_eq!(
        evidence.descendant_coverage[2].access_state,
        EspSourceAccessState::PermissionDenied
    );
    assert_eq!(
        evidence.descendant_coverage[2].sensitivity,
        EspSensitivity::Sensitive
    );
    assert!(evidence.descendant_coverage[2]
        .detail
        .as_deref()
        .is_some_and(|detail| detail.to_ascii_lowercase().contains("administrator")));
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

#[derive(Default)]
struct FakeEventLogProvider {
    channels: HashMap<String, Result<Vec<ParsedEspEventRecord>, EventSourceError>>,
    requests: RefCell<Vec<(String, Vec<u32>, usize)>>,
}

impl FakeEventLogProvider {
    fn with_records(mut self, channel: &str, records: Vec<ParsedEspEventRecord>) -> Self {
        self.channels.insert(channel.to_string(), Ok(records));
        self
    }

    fn with_error(mut self, channel: &str, error: EventSourceError) -> Self {
        self.channels.insert(channel.to_string(), Err(error));
        self
    }
}

impl EventLogProvider for FakeEventLogProvider {
    fn read_channel(
        &self,
        channel: &str,
        required_event_ids: &[u32],
        record_limit: usize,
    ) -> Result<Vec<ParsedEspEventRecord>, EventSourceError> {
        self.requests.borrow_mut().push((
            channel.to_string(),
            required_event_ids.to_vec(),
            record_limit,
        ));
        self.channels
            .get(channel)
            .cloned()
            .unwrap_or(Err(EventSourceError::Missing))
    }
}

fn parsed_event(
    channel: &str,
    event_id: u32,
    record_id: u64,
    event_data: Vec<EventLogProperty>,
) -> ParsedEspEventRecord {
    ParsedEspEventRecord {
        channel: channel.to_string(),
        event_id,
        record_id: Some(record_id),
        source_timestamp: "2026-07-15T12:00:00Z".to_string(),
        event_data,
        message: Some(format!("raw message for event {event_id}")),
        source_file: format!("captured/{record_id}.evtx"),
        raw_xml: format!("<Event><System><EventID>{event_id}</EventID></System></Event>"),
    }
}

fn event_property(name: &str, value: &str) -> EventLogProperty {
    EventLogProperty {
        name: name.to_string(),
        value: value.to_string(),
    }
}

#[test]
fn event_required_ids_are_complete_and_stable() {
    assert_eq!(
        REQUIRED_EVENT_IDS,
        &[72, 100, 101, 107, 109, 110, 111, 304, 306, 1905, 1906, 1920, 1922, 1924]
    );
}

#[test]
fn event_provider_receives_exact_ids_and_xpath_before_the_record_limit() {
    let provider = FakeEventLogProvider::default()
        .with_records(ESP_EVENT_CHANNELS[0], Vec::new())
        .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

    collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    assert_eq!(
        provider.requests.borrow().as_slice(),
        &[
            (
                ESP_EVENT_CHANNELS[0].to_string(),
                REQUIRED_EVENT_IDS.to_vec(),
                MAX_ESP_EVENT_RECORDS_PER_CHANNEL,
            ),
            (
                ESP_EVENT_CHANNELS[1].to_string(),
                REQUIRED_EVENT_IDS.to_vec(),
                MAX_ESP_EVENT_RECORDS_PER_CHANNEL,
            ),
        ]
    );
    assert_eq!(
        required_event_id_xpath(),
        "*[System[(EventID=72 or EventID=100 or EventID=101 or EventID=107 or EventID=109 or EventID=110 or EventID=111 or EventID=304 or EventID=306 or EventID=1905 or EventID=1906 or EventID=1920 or EventID=1922 or EventID=1924)]]"
    );
}

#[test]
fn event_filters_required_ids_before_applying_the_channel_record_cap() {
    let channel = ESP_EVENT_CHANNELS[0];
    let mut records = (0..MAX_ESP_EVENT_RECORDS_PER_CHANNEL)
        .map(|index| parsed_event(channel, 9_999, index as u64 + 1, Vec::new()))
        .collect::<Vec<_>>();
    records.push(parsed_event(channel, 1_924, 9_000, Vec::new()));
    let provider = FakeEventLogProvider::default()
        .with_records(channel, records)
        .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

    let evidence = collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    assert_eq!(evidence.observations.len(), 1);
    assert_eq!(evidence.observations[0].observation.event_id, 1_924);
    assert_eq!(evidence.observations[0].observation.record_id, Some(9_000));
}

#[test]
fn event_output_is_deterministic_when_provider_order_changes() {
    let channel = ESP_EVENT_CHANNELS[0];
    let provider = FakeEventLogProvider::default()
        .with_records(
            channel,
            vec![
                parsed_event(channel, 110, 30, Vec::new()),
                parsed_event(channel, 109, 10, Vec::new()),
                parsed_event(channel, 111, 20, Vec::new()),
            ],
        )
        .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

    let evidence = collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    assert_eq!(
        evidence
            .observations
            .iter()
            .map(|event| event.observation.record_id)
            .collect::<Vec<_>>(),
        vec![Some(10), Some(20), Some(30)]
    );
}

#[test]
fn event_parser_retains_ordered_named_properties_and_record_id() {
    let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>109</EventID>
    <EventRecordID>808</EventRecordID>
    <TimeCreated SystemTime='2026-07-15T12:34:56.789Z'/>
    <Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>
  </System>
  <EventData>
    <Data Name='State'>2</Data>
    <Data Name='ProductCode'>{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}</Data>
    <Data Name='AppId'>app-guid</Data>
    <Data Name='PolicyId'>policy-guid</Data>
    <Data Name='ResultCode'>0x80070005</Data>
  </EventData>
  <RenderingInfo><Message>Waiting &amp; processing</Message></RenderingInfo>
</Event>"#;

    let event = parse_esp_event_xml(xml, "captured/admin.evtx", None, None, "fallback")
        .expect("parsed ESP event");

    assert_eq!(event.event_id, 109);
    assert_eq!(event.record_id, Some(808));
    assert_eq!(event.source_timestamp, "2026-07-15T12:34:56.789Z");
    assert_eq!(
        event.event_data,
        vec![
            event_property("State", "2"),
            event_property("ProductCode", "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
            event_property("AppId", "app-guid"),
            event_property("PolicyId", "policy-guid"),
            event_property("ResultCode", "0x80070005"),
        ]
    );
    assert_eq!(event.message.as_deref(), Some("Waiting & processing"));

    let double_quoted_xml = xml.replace('\'', "\"");
    let double_quoted = parse_esp_event_xml(
        &double_quoted_xml,
        "captured/admin.evtx",
        None,
        None,
        "fallback",
    )
    .expect("double-quoted EVTX XML");
    assert_eq!(double_quoted.record_id, Some(808));
    assert_eq!(double_quoted.event_data, event.event_data);
}

#[test]
fn event_parser_keeps_self_closing_data_separate_from_the_following_property() {
    let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>72</EventID>
    <EventRecordID>909</EventRecordID>
    <TimeCreated SystemTime='2026-07-15T12:34:56.789Z'/>
    <Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>
  </System>
  <EventData>
    <Data Name='Empty'/>
    <Data Name='ResultCode'>0x80070005</Data>
  </EventData>
</Event>"#;

    let event = parse_esp_event_xml(xml, "captured/admin.evtx", None, None, "fallback")
        .expect("parsed ESP event");

    assert_eq!(
        event.event_data,
        vec![
            event_property("Empty", ""),
            event_property("ResultCode", "0x80070005"),
        ]
    );
}

#[test]
fn command_line_sanitizer_redacts_complete_escaped_json_secrets_with_escaped_quotes() {
    for raw in [
        r#"installer.exe --payload {\"refresh_token\":\"prefix\\\"quoted-secret-suffix\",\"safe\":\"keep-escaped-json-control\"}"#,
        r#"installer.exe --payload {\"password\":\"prefix\\\\\\\"quoted-password-suffix\",\"safe\":\"keep-escaped-json-control\"}"#,
    ] {
        let sanitized = sanitize_command_line(raw);

        assert!(
            !sanitized.contains("secret-suffix") && !sanitized.contains("password-suffix"),
            "escaped JSON secret suffix leaked: {sanitized}"
        );
        assert!(sanitized.contains(r#"\"[REDACTED]\""#));
        assert!(sanitized.contains(r#"\"safe\":\"keep-escaped-json-control\""#));
    }
}

#[test]
fn command_line_sanitizer_keeps_escaped_json_key_boundaries_and_redacts_two_layers() {
    let ending_backslash = concat!(
        r#"installer.exe --payload {\"password\":\"ends-with-literal-backslash\\\","#,
        r#"\"refresh_token\":\"following-refresh-secret\","#,
        r#"\"safe\":\"keep-adjacent-json-control\"}"#
    );
    let sanitized = sanitize_command_line(ending_backslash);

    for secret in ["ends-with-literal-backslash", "following-refresh-secret"] {
        assert!(
            !sanitized.contains(secret),
            "adjacent escaped JSON secret leaked {secret}: {sanitized}"
        );
    }
    assert!(sanitized.contains(r#"\"password\":\"[REDACTED]\""#));
    assert!(sanitized.contains(r#"\"refresh_token\":\"[REDACTED]\""#));
    assert!(sanitized.contains(r#"\"safe\":\"keep-adjacent-json-control\""#));

    let twice_escaped = concat!(
        r#"installer.exe --payload {\\\"password\\\":\\\"twice-escaped-password-secret\\\","#,
        r#"\\\"safe\\\":\\\"keep-twice-escaped-control\\\"}"#
    );
    let sanitized = sanitize_command_line(twice_escaped);

    assert!(!sanitized.contains("twice-escaped-password-secret"));
    assert!(sanitized.contains(r#"\\\"password\\\":\\\"[REDACTED]\\\""#));
    assert!(sanitized.contains(r#"\\\"safe\\\":\\\"keep-twice-escaped-control\\\""#));

    let general_safe_keys = concat!(
        r#"installer.exe --payload {\"password\":\"general-key-secret\","#,
        r#"\"safe.name\":\"keep-dotted-safe-value\","#,
        r#"\"display name\":\"keep-spaced-safe-value\"}"#
    );
    let sanitized = sanitize_command_line(general_safe_keys);
    assert!(!sanitized.contains("general-key-secret"));
    assert!(sanitized.contains(r#"\"safe.name\":\"keep-dotted-safe-value\""#));
    assert!(sanitized.contains(r#"\"display name\":\"keep-spaced-safe-value\""#));
}

#[test]
fn command_line_sanitizer_keeps_wider_escaped_quotes_inside_json_secret_values() {
    for marker in ["}", "]"] {
        let raw = r#"installer.exe --payload {\"password\":\"first-secret-segment\\\"MARKERsecond-secret-segment\",\"safe\":\"keep-boundary-control\"}"#
            .replace("MARKER", marker);
        let sanitized = sanitize_command_line(&raw);

        for secret in ["first-secret-segment", "second-secret-segment"] {
            assert!(
                !sanitized.contains(secret),
                "one-layer escaped JSON secret leaked {secret}: {sanitized}"
            );
        }
        assert!(sanitized.contains(r#"\"password\":\"[REDACTED]\""#));
        assert!(sanitized.contains(r#"\"safe\":\"keep-boundary-control\""#));
    }

    let twice_inner_quote = format!("{}\"", "\\".repeat(7));
    for marker in ["}", "]"] {
        let twice_escaped = [
            r#"installer.exe --payload {\\\"password\\\":\\\"twice-secret-prefix"#,
            twice_inner_quote.as_str(),
            marker,
            r#"twice-secret-suffix\\\",\\\"safe\\\":\\\"keep-twice-control\\\"}"#,
        ]
        .concat();
        let sanitized = sanitize_command_line(&twice_escaped);

        assert!(!sanitized.contains("twice-secret-prefix"));
        assert!(!sanitized.contains("twice-secret-suffix"));
        assert!(sanitized.contains(r#"\\\"password\\\":\\\"[REDACTED]\\\""#));
        assert!(sanitized.contains(r#"\\\"safe\\\":\\\"keep-twice-control\\\""#));
    }

    let option_shaped_suffix = concat!(
        r#"installer.exe --payload {\"password\":\"secret-prefix\\\"} "#,
        r#"--still-secret suffix\",\"safe\":\"keep-option-shaped-control\"}"#
    );
    let sanitized = sanitize_command_line(option_shaped_suffix);
    assert!(!sanitized.contains("secret-prefix"));
    assert!(!sanitized.contains("--still-secret suffix"));
    assert!(sanitized.contains(r#"\"safe\":\"keep-option-shaped-control\""#));

    let twice_option_shaped_suffix = [
        r#"installer.exe --payload {\\\"password\\\":\\\"twice-secret-prefix"#,
        twice_inner_quote.as_str(),
        r#"} --twice-still-secret suffix\\\",\\\"safe\\\":\\\"keep-twice-option-control\\\"}"#,
    ]
    .concat();
    let sanitized = sanitize_command_line(&twice_option_shaped_suffix);
    assert!(!sanitized.contains("twice-secret-prefix"));
    assert!(!sanitized.contains("--twice-still-secret suffix"));
    assert!(sanitized.contains(r#"\\\"safe\\\":\\\"keep-twice-option-control\\\""#));

    let comma_quote_not_member = concat!(
        r#"installer.exe --payload {\"password\":\"comma-secret-prefix\\\", "#,
        r#"\"not-a-member\" comma-secret-suffix\","#,
        r#"\"safe\":\"keep-comma-control\"}"#
    );
    let sanitized = sanitize_command_line(comma_quote_not_member);
    assert!(!sanitized.contains("comma-secret-prefix"));
    assert!(!sanitized.contains("comma-secret-suffix"));
    assert!(sanitized.contains(r#"\"safe\":\"keep-comma-control\""#));
}

#[test]
fn command_line_sanitizer_finds_secret_after_safe_escaped_json_backslash_value() {
    let raw = concat!(
        r#"installer.exe --payload {\"safe\":\"keep-literal-backslash\\\","#,
        r#"\"password\":\"following-password-secret\","#,
        r#"\"control\":\"keep-safe-boundary-control\"}"#
    );
    let sanitized = sanitize_command_line(raw);

    assert!(sanitized.contains("keep-literal-backslash"));
    assert!(!sanitized.contains("following-password-secret"));
    assert!(sanitized.contains(r#"\"password\":\"[REDACTED]\""#));
    assert!(sanitized.contains(r#"\"control\":\"keep-safe-boundary-control\""#));

    let twice_literal_backslash_close = format!("{}\"", "\\".repeat(7));
    let twice_escaped = [
        r#"installer.exe --payload {\\\"safe\\\":\\\"keep-twice-literal-backslash"#,
        twice_literal_backslash_close.as_str(),
        r#",\\\"password\\\":\\\"following-twice-password-secret\\\",\\\"control\\\":\\\"keep-twice-safe-control\\\"}"#,
    ]
    .concat();
    let sanitized = sanitize_command_line(&twice_escaped);

    assert!(sanitized.contains("keep-twice-literal-backslash"));
    assert!(!sanitized.contains("following-twice-password-secret"));
    assert!(sanitized.contains(r#"\\\"password\\\":\\\"[REDACTED]\\\""#));
    assert!(sanitized.contains(r#"\\\"control\\\":\\\"keep-twice-safe-control\\\""#));
}

#[test]
fn command_line_sanitizer_stops_at_terminal_escaped_json_object_boundaries() {
    let raw = concat!(
        r#"installer.exe --a {\"password\":\"ends-with-backslash\\\"} --b {"#,
        r#"\"refresh_token\":\"following-object-secret\","#,
        r#"\"safe\":\"keep-separate-object-control\"}"#
    );
    let sanitized = sanitize_command_line(raw);

    assert!(!sanitized.contains("ends-with-backslash"));
    assert!(!sanitized.contains("following-object-secret"));
    assert!(sanitized.contains(r#"\"password\":\"[REDACTED]\"} --b {"#));
    assert!(sanitized.contains(r#"\"refresh_token\":\"[REDACTED]\""#));
    assert!(sanitized.contains(r#"\"safe\":\"keep-separate-object-control\""#));

    let safe_first = concat!(
        r#"installer.exe --a {\"password\":\"ends-with-backslash\\\"} --b {"#,
        r#"\"safe\":\"keep-leading-safe-control\","#,
        r#"\"refresh_token\":\"safe-first-following-secret\"}"#
    );
    let sanitized = sanitize_command_line(safe_first);

    assert!(!sanitized.contains("safe-first-following-secret"));
    assert!(sanitized.contains(r#"} --b {\"safe\":\"keep-leading-safe-control\""#));
    assert!(sanitized.contains(r#"\"refresh_token\":\"[REDACTED]\""#));

    let twice_terminal_close = format!("{}\"", "\\".repeat(7));
    let twice_escaped = [
        r#"installer.exe --a {\\\"password\\\":\\\"twice-terminal-backslash"#,
        twice_terminal_close.as_str(),
        r#"} --b {\\\"refresh_token\\\":\\\"twice-following-object-secret\\\",\\\"safe\\\":\\\"keep-twice-object-control\\\"}"#,
    ]
    .concat();
    let sanitized = sanitize_command_line(&twice_escaped);

    assert!(!sanitized.contains("twice-terminal-backslash"));
    assert!(!sanitized.contains("twice-following-object-secret"));
    assert!(sanitized.contains(r#"\\\"password\\\":\\\"[REDACTED]\\\"} --b {"#));
    assert!(sanitized.contains(r#"\\\"refresh_token\\\":\\\"[REDACTED]\\\""#));
    assert!(sanitized.contains(r#"\\\"safe\\\":\\\"keep-twice-object-control\\\""#));

    let quoted_argument_between_objects = concat!(
        r#"installer.exe --a {\"password\":\"ends-with-backslash\\\"} "#,
        r#"--note \"keep-quoted-note\" --b {"#,
        r#"\"refresh_token\":\"following-quoted-argument-secret\","#,
        r#"\"safe\":\"keep-quoted-argument-control\"}"#
    );
    let sanitized = sanitize_command_line(quoted_argument_between_objects);

    assert_eq!(
        sanitized,
        concat!(
            r#"installer.exe --a {\"password\":\"[REDACTED]\"} "#,
            r#"--note \"keep-quoted-note\" --b {"#,
            r#"\"refresh_token\":\"[REDACTED]\","#,
            r#"\"safe\":\"keep-quoted-argument-control\"}"#
        )
    );
}

#[test]
fn command_line_sanitizer_fails_closed_on_unterminated_escaped_secret_suffixes() {
    for raw in [
        r#"installer.exe --payload {\"password\":\"unterminated-one-layer-at-eof"#,
        r#"installer.exe --payload {\\\"password\\\":\\\"unterminated-two-layer-at-eof"#,
    ] {
        let sanitized = sanitize_command_line(raw);
        assert!(!sanitized.contains("unterminated-one-layer-at-eof"));
        assert!(!sanitized.contains("unterminated-two-layer-at-eof"));
        assert!(sanitized.ends_with("[REDACTED]"));
    }

    for (malformed, following) in [
        (
            r#"{\"password\":\"unterminated-one-layer-secret}"#,
            r#"{\"refresh_token\":\"following-one-layer-secret\",\"safe\":\"keep-one-layer-safe\"}"#,
        ),
        (
            r#"{\\\"password\\\":\\\"unterminated-two-layer-secret}"#,
            r#"{\"refresh_token\":\"following-one-layer-after-two-layer-secret\",\"safe\":\"keep-cross-layer-safe\"}"#,
        ),
    ] {
        let raw = format!(
            "installer.exe --malformed {malformed} --keep-real-arg yes --following {following}"
        );
        let sanitized = sanitize_command_line(&raw);

        for secret in [
            "unterminated-one-layer-secret",
            "following-one-layer-secret",
            "unterminated-two-layer-secret",
            "following-two-layer-secret",
            "following-one-layer-after-two-layer-secret",
        ] {
            assert!(
                !sanitized.contains(secret),
                "malformed escaped JSON leaked {secret}: {sanitized}"
            );
        }
        assert!(!sanitized.contains("--keep-real-arg yes"));
        assert!(!sanitized.contains("keep-one-layer-safe"));
        assert!(!sanitized.contains("keep-cross-layer-safe"));
        assert!(sanitized.ends_with("[REDACTED]"));
    }
}

#[test]
fn command_line_sanitizer_fails_closed_on_ambiguous_wider_quote_at_end_of_scan() {
    let one_layer = concat!(
        r#"installer.exe --payload {\"password\":\"one-layer-secret-prefix\\\"}"#,
        r#"one-layer-visible-secret-suffix --keep-real-arg yes"#,
    );
    let sanitized = sanitize_command_line(one_layer);
    assert!(!sanitized.contains("one-layer-secret-prefix"));
    assert!(!sanitized.contains("one-layer-visible-secret-suffix"));
    assert!(!sanitized.contains(" --keep-real-arg yes"));
    assert!(sanitized.ends_with("[REDACTED]"));

    let twice_layer_wider_quote = format!("{}\"", "\\".repeat(7));
    let twice_layer = [
        r#"installer.exe --payload {\\\"password\\\":\\\"twice-layer-secret-prefix"#,
        twice_layer_wider_quote.as_str(),
        r#"}twice-layer-visible-secret-suffix --keep-real-arg yes"#,
    ]
    .concat();
    let sanitized = sanitize_command_line(&twice_layer);
    assert!(!sanitized.contains("twice-layer-secret-prefix"));
    assert!(!sanitized.contains("twice-layer-visible-secret-suffix"));
    assert!(!sanitized.contains(" --keep-real-arg yes"));
    assert!(sanitized.ends_with("[REDACTED]"));
}

#[test]
fn command_line_sanitizer_does_not_trust_option_shaped_ambiguous_secret_suffixes() {
    let exact_review_seed = r#"installer.exe --payload {\"password\":\"PREFIX_SECRET\\\"} -STILL_SECRET SECRET_VALUE --keep-real-arg yes"#;
    let sanitized = sanitize_command_line(exact_review_seed);
    for secret in ["PREFIX_SECRET", "STILL_SECRET", "SECRET_VALUE"] {
        assert!(
            !sanitized.contains(secret),
            "exact review seed leaked {secret}: {sanitized}"
        );
    }
    assert!(!sanitized.contains(" --keep-real-arg yes"));
    assert!(sanitized.ends_with("[REDACTED]"));

    let one_layer_wider_quote = format!("{}\"", "\\".repeat(3));
    let twice_layer_wider_quote = format!("{}\"", "\\".repeat(7));
    for (prefix, wider_quote) in [
        (
            r#"installer.exe --payload {\"password\":\"PREFIX_SECRET"#,
            one_layer_wider_quote.as_str(),
        ),
        (
            r#"installer.exe --payload {\\\"password\\\":\\\"PREFIX_SECRET"#,
            twice_layer_wider_quote.as_str(),
        ),
    ] {
        for secret_option in ["-STILL_SECRET", "--STILL_SECRET", "/STILL_SECRET"] {
            let raw =
                format!("{prefix}{wider_quote}}} {secret_option} SECRET_VALUE --keep-real-arg yes");
            let sanitized = sanitize_command_line(&raw);

            for secret in ["PREFIX_SECRET", "STILL_SECRET", "SECRET_VALUE"] {
                assert!(
                    !sanitized.contains(secret),
                    "ambiguous suffix leaked {secret} for {secret_option}: {sanitized}"
                );
            }
            assert!(!sanitized.contains(" --keep-real-arg yes"));
            assert!(sanitized.ends_with("[REDACTED]"));
        }
    }
}

#[test]
fn command_line_sanitizer_fails_closed_regardless_of_ambiguous_option_order() {
    let quote = |width: usize| format!("{}\"", "\\".repeat(width));

    for (value_width, closer_width) in [(1, 3), (1, 7), (3, 7)] {
        let member_quote = quote(value_width);
        let wider_quote = quote(closer_width);
        let prefix = format!(
            "installer.exe --payload {{{member_quote}password{member_quote}:{member_quote}PREFIX_SECRET{wider_quote}}}"
        );

        for secret_option in ["-STILL_SECRET", "--STILL_SECRET", "/STILL_SECRET"] {
            for suffix in [
                format!(" {secret_option} SECRET_VALUE"),
                format!(" {secret_option} SECRET_VALUE --keep-real-arg yes --other-real-arg two"),
                format!(" --keep-real-arg yes {secret_option} SECRET_VALUE"),
                format!(" --keep-real-arg yes {secret_option} SECRET_VALUE --other-real-arg two"),
                format!(" --keep-real-arg yes --other-real-arg two {secret_option} SECRET_VALUE"),
            ] {
                let sanitized = sanitize_command_line(&format!("{prefix}{suffix}"));
                for secret in ["PREFIX_SECRET", "STILL_SECRET", "SECRET_VALUE"] {
                    assert!(
                        !sanitized.contains(secret),
                        "wider-close suffix leaked {secret} for {value_width}/{closer_width} {secret_option}: {sanitized}"
                    );
                }
                assert!(!sanitized.contains("--keep-real-arg yes"));
                assert!(!sanitized.contains("--other-real-arg two"));
                assert!(sanitized.ends_with("[REDACTED]"));
            }
        }
    }

    for value_width in [1, 3, 7] {
        let member_quote = quote(value_width);
        let prefix = format!(
            "installer.exe --payload {{{member_quote}password{member_quote}:{member_quote}PREFIX_SECRET}}"
        );

        for secret_option in ["-STILL_SECRET", "--STILL_SECRET", "/STILL_SECRET"] {
            for suffix in [
                format!(" {secret_option} SECRET_VALUE"),
                format!(" {secret_option} SECRET_VALUE --keep-real-arg yes --other-real-arg two"),
                format!(" --keep-real-arg yes {secret_option} SECRET_VALUE"),
                format!(" --keep-real-arg yes {secret_option} SECRET_VALUE --other-real-arg two"),
                format!(" --keep-real-arg yes --other-real-arg two {secret_option} SECRET_VALUE"),
            ] {
                let sanitized = sanitize_command_line(&format!("{prefix}{suffix}"));
                for secret in ["PREFIX_SECRET", "STILL_SECRET", "SECRET_VALUE"] {
                    assert!(
                        !sanitized.contains(secret),
                        "raw-close suffix leaked {secret} for width {value_width} {secret_option}: {sanitized}"
                    );
                }
                assert!(!sanitized.contains("--keep-real-arg yes"));
                assert!(!sanitized.contains("--other-real-arg two"));
                assert!(sanitized.ends_with("[REDACTED]"));
            }
        }
    }
}

#[test]
fn command_line_sanitizer_never_uses_option_names_to_end_malformed_secret_values() {
    let quote = |width: usize| format!("{}\"", "\\".repeat(width));
    let aliases = [
        "-opaque-fragment",
        "--pass",
        "/auth",
        "--private-key",
        "/subscription-key",
        "--päss",
        "--opaque.fragment",
    ];
    let separators = [" ", "=", ":"];

    let mut prefixes = Vec::new();
    for value_width in [1, 3, 7] {
        let member_quote = quote(value_width);
        prefixes.push(format!(
            "installer.exe --payload {{{member_quote}password{member_quote}:{member_quote}PREFIX_SECRET}}"
        ));
    }
    for (value_width, closer_width) in [(1, 3), (1, 7), (3, 7)] {
        let member_quote = quote(value_width);
        let wider_quote = quote(closer_width);
        prefixes.push(format!(
            "installer.exe --payload {{{member_quote}password{member_quote}:{member_quote}PREFIX_SECRET{wider_quote}}}"
        ));
    }

    for prefix in prefixes {
        for alias in aliases {
            for separator in separators {
                let raw = format!(
                    "{prefix} {alias}{separator}SECRET_VALUE --keep-real-arg KEEP_AFTER_SECRET"
                );
                let sanitized = sanitize_command_line(&raw);

                for secret in ["PREFIX_SECRET", "SECRET_VALUE", "KEEP_AFTER_SECRET"] {
                    assert!(
                        !sanitized.contains(secret),
                        "malformed secret leaked {secret} for {alias}{separator}: {sanitized}"
                    );
                }
                assert!(
                    sanitized.ends_with("[REDACTED]"),
                    "ambiguous malformed suffix did not fail closed for {alias}{separator}: {sanitized}"
                );
            }
        }
    }
}

#[test]
fn command_line_sanitizer_fails_closed_after_raw_closer_suffix() {
    let exact_review_seed =
        r#"{\"password\":\"PREFIX_SECRET}VISIBLE_SECRET_SUFFIX -keep-real-arg yes"#;
    let sanitized = sanitize_command_line(exact_review_seed);
    assert!(!sanitized.contains("PREFIX_SECRET"));
    assert!(!sanitized.contains("VISIBLE_SECRET_SUFFIX"));
    assert!(!sanitized.contains(" -keep-real-arg yes"));
    assert!(sanitized.ends_with("[REDACTED]"));

    let neighboring_members = concat!(
        r#"{\"password\":\"PREFIX_SECRET}VISIBLE_SECRET_SUFFIX -keep-real-arg yes {"#,
        r#"\"refresh_token\":\"FOLLOWING_MEMBER_SECRET\","#,
        r#"\"safe.name\":\"KEEP_SAFE_MEMBER\"}"#,
    );
    let sanitized = sanitize_command_line(neighboring_members);
    for secret in [
        "PREFIX_SECRET",
        "VISIBLE_SECRET_SUFFIX",
        "FOLLOWING_MEMBER_SECRET",
    ] {
        assert!(
            !sanitized.contains(secret),
            "raw closer variant leaked {secret}: {sanitized}"
        );
    }
    assert!(!sanitized.contains(" -keep-real-arg yes"));
    assert!(!sanitized.contains(r#"\"safe.name\":\"KEEP_SAFE_MEMBER\""#));
    assert!(sanitized.ends_with("[REDACTED]"));
}

#[test]
fn command_line_sanitizer_fails_closed_on_sensitive_key_value_escape_width_mismatch() {
    for (raw, secret, safe_value) in [
        (
            concat!(
                r#"installer.exe --payload {\"password\":\\\"key-one-value-two-secret\\\","#,
                r#"\"safe.name\":\"keep-key-one-value-two-safe\"} --keep-real-arg yes"#,
            ),
            "key-one-value-two-secret",
            "keep-key-one-value-two-safe",
        ),
        (
            concat!(
                r#"installer.exe --payload {\\\"password\\\":\"key-two-value-one-secret\","#,
                r#"\\\"safe.name\\\":\\\"keep-key-two-value-one-safe\\\"} --keep-real-arg yes"#,
            ),
            "key-two-value-one-secret",
            "keep-key-two-value-one-safe",
        ),
    ] {
        let sanitized = sanitize_command_line(raw);
        assert!(
            !sanitized.contains(secret),
            "escape-width mismatch leaked {secret}: {sanitized}"
        );
        assert!(
            sanitized.contains(safe_value),
            "escape-width mismatch consumed safe data: {sanitized}"
        );
        assert!(sanitized.contains("safe.name"));
        assert!(sanitized.contains("--keep-real-arg yes"));
    }
}

#[test]
fn command_line_sanitizer_fails_closed_before_single_dash_option() {
    let raw = concat!(
        r#"installer.exe --malformed {\"password\":\"malformed-single-dash-secret} "#,
        r#"-keep-real-arg yes --following {\"refresh_token\":\"following-single-dash-secret\","#,
        r#"\"safe.name\":\"keep-single-dash-safe\"}"#,
    );
    let sanitized = sanitize_command_line(raw);

    assert!(!sanitized.contains("malformed-single-dash-secret"));
    assert!(!sanitized.contains("following-single-dash-secret"));
    assert!(!sanitized.contains("-keep-real-arg yes"));
    assert!(!sanitized.contains(r#"\"safe.name\":\"keep-single-dash-safe\""#));
    assert!(sanitized.ends_with("[REDACTED]"));
}

#[test]
fn command_line_sanitizer_redacts_escaped_secret_aliases_with_safe_punctuation() {
    for raw in [
        concat!(
            r#"installer.exe --payload {\"access.token\":\"dot-access-secret\","#,
            r#"\"refresh token\":\"space-refresh-secret\","#,
            r#"\"client.secret\":\"dot-client-secret\","#,
            r#"\"safe.name\":\"keep-dotted-safe-value\"}"#,
        ),
        concat!(
            r#"installer.exe --payload {\\\"access.token\\\":\\\"twice-dot-access-secret\\\","#,
            r#"\\\"refresh token\\\":\\\"twice-space-refresh-secret\\\","#,
            r#"\\\"client.secret\\\":\\\"twice-dot-client-secret\\\","#,
            r#"\\\"safe.name\\\":\\\"keep-twice-dotted-safe-value\\\"}"#,
        ),
    ] {
        let sanitized = sanitize_command_line(raw);

        for secret in [
            "dot-access-secret",
            "space-refresh-secret",
            "dot-client-secret",
            "twice-dot-access-secret",
            "twice-space-refresh-secret",
            "twice-dot-client-secret",
        ] {
            assert!(
                !sanitized.contains(secret),
                "escaped JSON alias leaked {secret}: {sanitized}"
            );
        }
        assert!(sanitized.contains("safe.name"));
        assert!(
            sanitized.contains("keep-dotted-safe-value")
                || sanitized.contains("keep-twice-dotted-safe-value")
        );
    }
}

#[test]
fn command_line_sanitizer_preserves_arguments_across_mixed_escape_width_objects() {
    let raw = concat!(
        r#"installer.exe --one {\"password\":\"one-layer-secret-ending-backslash\\\"} "#,
        r#"--keep-real-arg yes --two {\\\"password\\\":\\\"twice-layer-secret\\\","#,
        r#"\\\"safe.name\\\":\\\"keep-safe-name-value\\\"}"#,
    );
    let sanitized = sanitize_command_line(raw);

    assert!(!sanitized.contains("one-layer-secret-ending-backslash"));
    assert!(!sanitized.contains("twice-layer-secret"));
    assert!(
        sanitized.contains("--keep-real-arg yes"),
        "mixed-width redaction consumed a real argument: {sanitized}"
    );
    assert!(
        sanitized.contains(r#"\\\"safe.name\\\":\\\"keep-safe-name-value\\\""#),
        "mixed-width redaction consumed a safe member: {sanitized}"
    );
}

#[test]
fn command_line_sanitizer_redacts_quoted_and_unpadded_basic_credentials() {
    for credential in ["Zm9vOmJhcg", "\"Zm9vOmJhcg==\""] {
        let raw =
            format!("installer.exe Basic {credential} /i {{12345678-1234-1234-1234-1234567890AB}}");
        let sanitized = sanitize_command_line(&raw);

        assert!(
            !sanitized.contains("Zm9vOmJhcg"),
            "Basic credential leaked: {sanitized}"
        );
        assert!(sanitized.contains("Basic [REDACTED]"));
        assert!(sanitized.contains("/i {12345678-1234-1234-1234-1234567890AB}"));
    }

    for narrative in [
        "Basic c2FmZS1uYXJyYXRpdmU= authentication is supported",
        "Basic \"c2FmZS1uYXJyYXRpdmU=\" authentication is supported",
    ] {
        assert_eq!(sanitize_command_line(narrative), narrative);
    }
}

#[test]
fn command_line_sanitizer_redacts_punctuation_delimited_basic_credentials() {
    for (raw, expected) in [
        ("Basic Zm9vOmJhcg==, next", "Basic [REDACTED], next"),
        ("Basic \"Zm9vOmJhcg==\", next", "Basic [REDACTED], next"),
        ("Basic Zm9vOmJhcg==. Next", "Basic [REDACTED]. Next"),
        ("Basic 'Zm9vOmJhcg=='. Next", "Basic [REDACTED]. Next"),
    ] {
        assert_eq!(sanitize_command_line(raw), expected);
    }

    for narrative in [
        "Basic c2FmZS1uYXJyYXRpdmU=, authentication is supported",
        "Basic \"c2FmZS1uYXJyYXRpdmU=\". Authentication is supported",
    ] {
        assert_eq!(sanitize_command_line(narrative), narrative);
    }
}

#[test]
fn command_line_sanitizer_redacts_basic_credentials_before_closing_punctuation() {
    for (raw, expected) in [
        ("Basic Zm9vOmJhcg==; next", "Basic [REDACTED]; next"),
        ("Basic \"Zm9vOmJhcg==\": next", "Basic [REDACTED]: next"),
        ("Basic Zm9vOmJhcg==! next", "Basic [REDACTED]! next"),
        ("Basic 'Zm9vOmJhcg=='? next", "Basic [REDACTED]? next"),
        ("Basic Zm9vOmJhcg==) next", "Basic [REDACTED]) next"),
        ("Basic \"Zm9vOmJhcg==\"] next", "Basic [REDACTED]] next"),
        ("Basic Zm9vOmJhcg==} next", "Basic [REDACTED]} next"),
    ] {
        assert_eq!(sanitize_command_line(raw), expected);
    }

    for delimiter in [';', ':', '!', '?', ')', ']', '}'] {
        let narrative =
            format!("Basic c2FmZS1uYXJyYXRpdmU={delimiter} authentication is supported");
        assert_eq!(sanitize_command_line(&narrative), narrative);
    }
}

#[test]
fn command_line_sanitizer_preserves_punctuated_bearer_authentication_narratives() {
    for narrative in [
        "The Bearer authentication, mode is supported",
        "The Bearer authentication. Next step",
        "The Bearer authentication; mode is supported",
        "The Bearer (authentication) mode is supported",
        "The (Bearer authentication) mode is supported",
    ] {
        assert_eq!(sanitize_command_line(narrative), narrative);
    }

    let credential = "Bearer authentication-token-secret";
    let sanitized = sanitize_command_line(credential);
    assert_eq!(sanitized, "Bearer [REDACTED]");
    assert!(!sanitized.contains("authentication-token-secret"));
}

#[test]
fn event_parser_rejects_malformed_nesting_and_accepts_empty_self_closing_event_data() {
    let malformed = concat!(
        "<Event><System><EventID>72</EventID>",
        "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
        "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
        "<EventData></EventData></Event>"
    );
    assert!(
        parse_esp_event_xml(malformed, "malformed.evtx", Some(1), None, "Unknown").is_none(),
        "malformed System/EventData nesting was accepted"
    );

    for event_data in ["<EventData />", "<EventData/>"] {
        let valid = format!(
            concat!(
                "<Event><System><EventID>72</EventID>",
                "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
                "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
                "</System>{}</Event>"
            ),
            event_data,
        );
        let parsed = parse_esp_event_xml(&valid, "empty.evtx", Some(2), None, "Unknown")
            .expect("valid self-closing EventData");
        assert!(parsed.event_data.is_empty());
    }
}

#[test]
fn event_parser_rejects_illegal_entities_nulls_and_misplaced_declarations() {
    let event_with_payload = |payload: &str| {
        format!(
            concat!(
                "<Event><System><EventID>72</EventID>",
                "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
                "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
                "</System><EventData><Data Name='Payload'>{}</Data></EventData></Event>"
            ),
            payload,
        )
    };
    let invalid_records = [
        event_with_payload("&undefined;"),
        event_with_payload("&#0;"),
        event_with_payload("&#x0;"),
        event_with_payload("raw\0null"),
        format!(
            "<!--before-declaration--><?xml version='1.0'?>{}",
            event_with_payload("valid")
        ),
    ];

    for (index, xml) in invalid_records.iter().enumerate() {
        assert!(
            parse_esp_event_xml(xml, "invalid.evtx", Some(index as u64 + 1), None, "Unknown")
                .is_none(),
            "invalid XML record {index} was accepted"
        );
    }
}

#[test]
fn event_parser_ignores_event_id_markup_inside_comments() {
    let xml = concat!(
        "<Event><!-- <EventID>999</EventID> -->",
        "<System><EventID>72</EventID>",
        "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
        "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
        "</System><EventData /></Event>"
    );

    let parsed = parse_esp_event_xml(xml, "commented.evtx", Some(1), None, "Unknown")
        .expect("valid event with a comment");
    assert_eq!(parsed.event_id, 72);
}

#[test]
fn event_parser_reads_identity_fields_only_from_direct_system_children() {
    let xml = concat!(
        "<Event>",
        "<EventID>999</EventID>",
        "<EventRecordID>9999</EventRecordID>",
        "<TimeCreated SystemTime='1900-01-01T00:00:00Z'/>",
        "<Channel>Top-Level/Shadow</Channel>",
        "<EventData>",
        "<EventID>998</EventID>",
        "<EventRecordID>9988</EventRecordID>",
        "<TimeCreated SystemTime='1901-01-01T00:00:00Z'/>",
        "<Channel>EventData/Shadow</Channel>",
        "</EventData>",
        "<System>",
        "<EventID>72</EventID>",
        "<EventRecordID>909</EventRecordID>",
        "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
        "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
        "</System>",
        "</Event>"
    );
    let parsed = parse_esp_event_xml(xml, "shadowed.evtx", None, None, "Fallback")
        .expect("valid event with shadow elements");

    assert_eq!(parsed.event_id, 72);
    assert_eq!(parsed.record_id, Some(909));
    assert_eq!(parsed.source_timestamp, "2026-07-16T13:00:00Z");
    assert_eq!(
        parsed.channel,
        "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
    );

    let missing_system_fields = concat!(
        "<Event>",
        "<EventID>72</EventID>",
        "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
        "<System></System><EventData />",
        "</Event>"
    );
    assert!(
        parse_esp_event_xml(
            missing_system_fields,
            "missing-system-fields.evtx",
            Some(2),
            None,
            "Fallback"
        )
        .is_none(),
        "top-level fields satisfied required System fields"
    );

    let top_level_channel_only = concat!(
        "<Event><Channel>Top-Level/Shadow</Channel><System>",
        "<EventID>72</EventID>",
        "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
        "</System><EventData /></Event>"
    );
    let parsed = parse_esp_event_xml(
        top_level_channel_only,
        "fallback-channel.evtx",
        Some(3),
        None,
        "Fallback/Channel",
    )
    .expect("valid event without a System Channel");
    assert_eq!(parsed.channel, "Fallback/Channel");
}

#[test]
fn event_parser_never_splices_identity_fields_across_sibling_system_elements() {
    let spliced = concat!(
        "<Event>",
        "<System><EventID>72</EventID></System>",
        "<System>",
        "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
        "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
        "</System>",
        "<EventData />",
        "</Event>"
    );

    assert!(
        parse_esp_event_xml(spliced, "sibling-system.evtx", Some(4), None, "Fallback").is_none(),
        "EventID and timestamp/channel from different System siblings were spliced"
    );
}

#[test]
fn event_parser_rejects_malformed_xml_declarations_and_comments() {
    let event = concat!(
        "<Event><System><EventID>72</EventID>",
        "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
        "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
        "</System><EventData /></Event>"
    );
    let malformed_comment = event.replacen("<Event>", "<Event><!-- bad--comment -->", 1);
    let invalid = [
        format!("<?xml?>{event}"),
        format!("<?XmL?>{event}"),
        format!("<?xml version='1.0' version='1.0'?>{event}"),
        format!("<?xml version='1.0' encoding='UTF-8' encoding='UTF-8'?>{event}"),
        format!("<?xml version='1.0' mode='invalid'?>{event}"),
        format!("<?xml version='1.0' standalone='maybe'?>{event}"),
        malformed_comment,
    ];

    for (index, xml) in invalid.iter().enumerate() {
        assert!(
            parse_esp_event_xml(
                xml,
                "invalid-xml.evtx",
                Some(index as u64 + 1),
                None,
                "Fallback"
            )
            .is_none(),
            "invalid XML declaration/comment record {index} was accepted"
        );
    }

    let valid_declaration =
        format!("<?xml version='1.0' encoding='UTF-8' standalone='yes'?>{event}");
    assert!(
        parse_esp_event_xml(
            &valid_declaration,
            "valid-declaration.evtx",
            Some(99),
            None,
            "Fallback"
        )
        .is_some(),
        "a valid XML 1.0 declaration was rejected"
    );
}

#[test]
fn event_parser_enforces_public_record_size_and_nesting_bounds() {
    let bounded_event = |nested_elements: usize, payload: &str| {
        format!(
            concat!(
                "<Event><System><EventID>72</EventID>",
                "<TimeCreated SystemTime='2026-07-16T13:00:00Z'/>",
                "<Channel>Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin</Channel>",
                "</System><EventData><Data Name='Payload'>{}</Data></EventData>{}{}</Event>"
            ),
            payload,
            "<Node>".repeat(nested_elements),
            "</Node>".repeat(nested_elements),
        )
    };

    let at_depth_limit = bounded_event(63, "bounded");
    assert!(
        parse_esp_event_xml(&at_depth_limit, "bounded.evtx", Some(1), None, "Unknown").is_some(),
        "the documented nesting boundary should remain usable"
    );

    let above_depth_limit = bounded_event(64, "too-deep");
    assert!(
        parse_esp_event_xml(
            &above_depth_limit,
            "too-deep.evtx",
            Some(2),
            None,
            "Unknown"
        )
        .is_none(),
        "XML nesting above the streaming validator limit was accepted"
    );

    let oversized = bounded_event(0, &"x".repeat(MAX_ESP_EVTX_RECORD_BYTES));
    assert!(oversized.len() > MAX_ESP_EVTX_RECORD_BYTES);
    assert!(
        parse_esp_event_xml(&oversized, "oversized.evtx", Some(3), None, "Unknown").is_none(),
        "public XML parsing bypassed the per-record byte limit"
    );
}

#[test]
fn event_ingestion_excludes_hardware_identity_redacts_authorization_and_marks_identity_payloads() {
    let channel = ESP_EVENT_CHANNELS[0];
    let mut record = parsed_event(
        channel,
        72,
        909,
        vec![
            event_property("DeviceHardwareData", "raw-hardware-hash-sentinel"),
            event_property(
                "Payload",
                concat!(
                    "user=alice@example.com Authorization: Custom-V1 realm=public, ",
                    "response=event-authorization-secret-sentinel"
                ),
            ),
            event_property("Data[2]", "S-1-5-21-111111111-222222222-333333333-1001"),
            event_property(
                "Data[3]",
                r#"{"Authorization":"Bearer json-authorization-secret-sentinel","safe":"keep-json-event-control"}"#,
            ),
        ],
    );
    record.message = Some(
        concat!(
            "TenantId=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee ",
            "Authorization: ApiKey message-authorization-secret-sentinel"
        )
        .to_string(),
    );
    let provider = FakeEventLogProvider::default()
        .with_records(channel, vec![record])
        .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

    let evidence = collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    assert_eq!(evidence.observations.len(), 1);
    let observation = &evidence.observations[0].observation;
    assert_eq!(observation.context.sensitivity, EspSensitivity::Sensitive);
    assert!(observation
        .named_data
        .iter()
        .all(|property| property.name != "DeviceHardwareData"));
    assert!(observation
        .named_data
        .iter()
        .any(|property| property.value.contains("alice@example.com")));
    assert!(observation.named_data.iter().any(|property| property
        .value
        .contains("S-1-5-21-111111111-222222222-333333333-1001")));
    assert!(observation
        .message
        .as_deref()
        .is_some_and(|message| message.contains("TenantId=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")));

    let serialized = serde_json::to_string(&evidence).expect("serialize event evidence");
    for forbidden in [
        "DeviceHardwareData",
        "raw-hardware-hash-sentinel",
        "event-authorization-secret-sentinel",
        "message-authorization-secret-sentinel",
        "json-authorization-secret-sentinel",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "event evidence leaked forbidden source material {forbidden}: {serialized}"
        );
    }
    for retained_identity in [
        "alice@example.com",
        "S-1-5-21-111111111-222222222-333333333-1001",
        "TenantId=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "keep-json-event-control",
    ] {
        assert!(
            serialized.contains(retained_identity),
            "sensitive raw provenance was not retained: {retained_identity}"
        );
    }
}

#[test]
fn event_identity_aliases_and_full_windows_sid_grammar_are_always_sensitive() {
    let cases = [
        ("DeviceSerialNumber", "DVC-739185"),
        ("AzureADTenantID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        ("Data[0]", "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15"),
        ("Data[0]", "S-1-0x000000000005-21"),
    ];

    for (index, (name, value)) in cases.into_iter().enumerate() {
        let channel = ESP_EVENT_CHANNELS[0];
        let record = parsed_event(
            channel,
            72,
            1_000 + index as u64,
            vec![event_property(name, value)],
        );
        let provider = FakeEventLogProvider::default()
            .with_records(channel, vec![record])
            .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

        let evidence = collect_event_evidence(&provider, "2026-07-16T13:00:00Z");

        assert_eq!(
            evidence.observations[0].observation.context.sensitivity,
            EspSensitivity::Sensitive,
            "identity value was published as Public: {name}={value}"
        );
    }
}

#[test]
fn event_identity_aliases_inside_unstructured_values_are_always_sensitive() {
    for (index, value) in [
        "AzureADTenantID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "DeviceSerialNumber=DVC-739185",
    ]
    .into_iter()
    .enumerate()
    {
        let channel = ESP_EVENT_CHANNELS[0];
        let record = parsed_event(
            channel,
            72,
            1_100 + index as u64,
            vec![event_property("Payload", value)],
        );
        let provider = FakeEventLogProvider::default()
            .with_records(channel, vec![record])
            .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

        let evidence = collect_event_evidence(&provider, "2026-07-16T13:00:00Z");

        assert_eq!(
            evidence.observations[0].observation.context.sensitivity,
            EspSensitivity::Sensitive,
            "unstructured identity value was published as Public: {value}"
        );
    }
}

#[test]
fn event_identity_aliases_inside_unstructured_messages_are_always_sensitive() {
    for (index, message) in [
        "AzureADTenantID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "DeviceSerialNumber=DVC-739185",
    ]
    .into_iter()
    .enumerate()
    {
        let channel = ESP_EVENT_CHANNELS[0];
        let mut record = parsed_event(channel, 72, 1_200 + index as u64, Vec::new());
        record.message = Some(message.to_string());
        let provider = FakeEventLogProvider::default()
            .with_records(channel, vec![record])
            .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

        let evidence = collect_event_evidence(&provider, "2026-07-16T13:00:00Z");

        assert_eq!(
            evidence.observations[0].observation.context.sensitivity,
            EspSensitivity::Sensitive,
            "unstructured identity message was published as Public: {message}"
        );
    }
}

#[test]
fn event_hardware_redaction_preserves_positional_field_indexes() {
    let channel = ESP_EVENT_CHANNELS[0];
    let record = parsed_event(
        channel,
        1924,
        910,
        vec![
            event_property("Data[0]", "unrelated"),
            event_property("DeviceHardwareData", "raw-hardware-hash-sentinel"),
            event_property("Data[2]", "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
        ],
    );
    let provider = FakeEventLogProvider::default()
        .with_records(channel, vec![record])
        .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

    let evidence = collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    assert_eq!(
        evidence.observations[0].fields.product_code.as_deref(),
        Some("{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}")
    );
    let serialized = serde_json::to_string(&evidence).expect("serialize event evidence");
    assert!(!serialized.contains("raw-hardware-hash-sentinel"));
    assert!(!serialized.contains("DeviceHardwareData"));
}

#[test]
fn event_collects_all_required_ids_and_deterministic_fields() {
    let admin_channel = ESP_EVENT_CHANNELS[0];
    let registration_channel = ESP_EVENT_CHANNELS[1];
    let admin_records = REQUIRED_EVENT_IDS
        .iter()
        .copied()
        .filter(|event_id| !matches!(event_id, 101 | 304 | 306))
        .enumerate()
        .map(|(index, event_id)| {
            let event_data = match event_id {
                109 | 110 => vec![event_property("State", "2")],
                1905 | 1906 | 1920 | 1922 => vec![
                    event_property("ProductCode", "{PRODUCT-CODE}"),
                    event_property("AppId", "app-guid"),
                ],
                1924 => vec![
                    event_property("ProductCode", "{PRODUCT-CODE}"),
                    event_property("ResultCode", "0x80070643"),
                ],
                72 => vec![event_property("PolicyId", "policy-guid")],
                _ => Vec::new(),
            };
            parsed_event(admin_channel, event_id, index as u64 + 1, event_data)
        })
        .collect::<Vec<_>>();
    let registration_records = [101, 304, 306]
        .into_iter()
        .enumerate()
        .map(|(index, event_id)| {
            parsed_event(
                registration_channel,
                event_id,
                index as u64 + 100,
                Vec::new(),
            )
        })
        .collect::<Vec<_>>();
    let provider = FakeEventLogProvider::default()
        .with_records(admin_channel, admin_records)
        .with_records(registration_channel, registration_records);

    let evidence = collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    let mut ids = evidence
        .observations
        .iter()
        .map(|event| event.observation.event_id)
        .collect::<Vec<_>>();
    ids.sort_unstable();
    assert_eq!(ids, REQUIRED_EVENT_IDS);
    for event in &evidence.observations {
        let provenance = event
            .observation
            .context
            .provenance
            .event
            .as_ref()
            .expect("event provenance for every required ID");
        assert_eq!(provenance.channel, event.observation.channel);
        assert_eq!(provenance.event_id, event.observation.event_id);
        assert_eq!(provenance.record_id, event.observation.record_id);
        assert_eq!(provenance.named_data, event.observation.named_data);
    }

    let odj = evidence
        .observations
        .iter()
        .find(|event| event.observation.event_id == 109)
        .expect("event 109");
    assert_eq!(odj.fields.state.as_deref(), Some("2"));
    let msi = evidence
        .observations
        .iter()
        .find(|event| event.observation.event_id == 1905)
        .expect("event 1905");
    assert_eq!(msi.fields.product_code.as_deref(), Some("{PRODUCT-CODE}"));
    assert_eq!(msi.fields.app_id.as_deref(), Some("app-guid"));
    assert!(evidence
        .observations
        .iter()
        .filter(|event| matches!(event.observation.event_id, 1905 | 1906 | 1920 | 1922 | 1924))
        .all(|event| event.fields.product_code.as_deref() == Some("{PRODUCT-CODE}")));
    let enrollment = evidence
        .observations
        .iter()
        .find(|event| event.observation.event_id == 72)
        .expect("event 72");
    assert_eq!(enrollment.fields.policy_id.as_deref(), Some("policy-guid"));
    let failure = evidence
        .observations
        .iter()
        .find(|event| event.observation.event_id == 1924)
        .expect("event 1924");
    assert_eq!(failure.fields.result_code.as_deref(), Some("0x80070643"));
}

#[test]
fn event_retains_exact_provenance_and_raw_message() {
    let channel = ESP_EVENT_CHANNELS[0];
    let record = parsed_event(
        channel,
        1924,
        44,
        vec![event_property("ResultCode", "0x80070643")],
    );
    let provider = FakeEventLogProvider::default()
        .with_records(channel, vec![record])
        .with_records(ESP_EVENT_CHANNELS[1], Vec::new());

    let evidence = collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    let event = &evidence.observations[0].observation;
    assert_eq!(event.channel, channel);
    assert_eq!(event.event_id, 1924);
    assert_eq!(event.record_id, Some(44));
    assert_eq!(event.message.as_deref(), Some("raw message for event 1924"));
    assert_eq!(
        event.context.provenance.file_path.as_deref(),
        Some("captured/44.evtx")
    );
    assert_eq!(event.context.provenance.record_number, Some(44));
    assert_eq!(
        event
            .context
            .source_timestamp
            .as_ref()
            .and_then(|timestamp| timestamp.normalized_utc.as_deref()),
        Some("2026-07-15T12:00:00Z")
    );
    let provenance = event
        .context
        .provenance
        .event
        .as_ref()
        .expect("event provenance");
    assert_eq!(provenance.channel, channel);
    assert_eq!(provenance.event_id, 1924);
    assert_eq!(provenance.record_id, Some(44));
    assert_eq!(provenance.named_data[0].name, "ResultCode");
}

#[test]
fn event_distinguishes_missing_channels_from_permission_denied() {
    let provider = FakeEventLogProvider::default()
        .with_error(ESP_EVENT_CHANNELS[0], EventSourceError::PermissionDenied)
        .with_error(ESP_EVENT_CHANNELS[1], EventSourceError::Missing);

    let evidence = collect_event_evidence(&provider, "2026-07-15T13:00:00Z");

    assert_eq!(
        evidence.channels[0].access_state,
        EspSourceAccessState::PermissionDenied
    );
    assert_eq!(
        evidence.channels[1].access_state,
        EspSourceAccessState::Missing
    );
    assert!(evidence.observations.is_empty());
}

fn write_discovery_file(path: &Path, bytes: &[u8], modified: SystemTime) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create discovery fixture parent");
    }
    fs::write(path, bytes).expect("write discovery fixture");
    File::options()
        .write(true)
        .open(path)
        .expect("open discovery fixture")
        .set_times(FileTimes::new().set_modified(modified))
        .expect("set discovery fixture time");
}

fn canonical_discovery_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).expect("canonical discovery fixture path")
}

fn discovery_input(now: SystemTime) -> DiscoveryInput {
    DiscoveryInput {
        known_sources: Vec::new(),
        temp_roots: Vec::new(),
        active_process_logs: Vec::new(),
        now,
    }
}

#[test]
fn discovery_uses_embedded_known_source_families_and_fixed_limits() {
    let specs = embedded_known_source_specs();
    for family in [
        "intune-ime",
        "configmgr",
        "msi",
        "panther",
        "setup",
        "windows-update",
        "wpm",
    ] {
        assert!(
            specs.iter().any(|spec| spec.family == family),
            "embedded deployment discovery omitted {family}"
        );
    }

    assert_eq!(MAX_ROTATIONS_PER_KNOWN_LOG, 3);
    assert_eq!(MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT, 128);
    assert_eq!(MAX_ACTIVE_TAILS, 16);
    assert_eq!(MAX_INITIAL_READ_BYTES, 8 * 1024 * 1024);
    assert_eq!(TEMP_LOOKBACK, Duration::from_secs(30 * 60));
    assert_eq!(DISCOVERY_INTERVAL, Duration::from_secs(2));
    assert_eq!(UPDATE_DEBOUNCE, Duration::from_millis(250));
    assert_eq!(MAX_SESSION_DURATION, Duration::from_secs(8 * 60 * 60));
}

#[cfg(target_os = "windows")]
#[test]
fn discovery_windows_catalog_covers_required_deployment_sources() {
    let specs = default_known_source_specs();
    let source_ids = specs
        .iter()
        .map(|spec| spec.source_id.as_str())
        .collect::<std::collections::HashSet<_>>();

    for required in [
        "ime-logs",
        "windows-configmgr-ccm-logs",
        "windows-configmgr-ccmsetup-logs",
        "msi-logs-windir",
        "winget-state",
        "windows-panther-setupact-log",
        "windows-reporting-events-log",
        "windows-deployment-logs-software",
        "windows-deployment-psadt",
        "windows-deployment-patchmypc-logs",
        "windows-deployment-patchmypc-install-logs",
        "windows-deployment-patchmypc-intune-logs",
    ] {
        assert!(
            source_ids.contains(required),
            "Windows deployment discovery omitted {required}"
        );
    }
}

#[test]
fn discovery_builds_only_the_fixed_runtime_temp_roots() {
    let roots = build_runtime_temp_roots(
        Path::new("C:/Windows"),
        Some(Path::new("C:/Users/current/AppData/Local/Temp")),
        &[
            PathBuf::from("C:/Users/alice"),
            PathBuf::from("C:/Users/bob"),
        ],
    );

    assert_eq!(
        roots,
        vec![
            PathBuf::from("C:/Windows/Temp"),
            PathBuf::from("C:/Windows/System32/config/systemprofile/AppData/Local/Temp"),
            PathBuf::from("C:/Users/current/AppData/Local/Temp"),
            PathBuf::from("C:/Users/alice/AppData/Local/Temp"),
            PathBuf::from("C:/Users/bob/AppData/Local/Temp"),
        ]
    );
}

#[test]
fn temp_discovery_is_non_recursive() {
    let temp = tempdir().expect("temp root");
    let now = SystemTime::now();
    let top = temp.path().join("MSI-top.log");
    let nested = temp.path().join("nested/MSI-hidden.log");
    write_discovery_file(&top, b"top", now);
    write_discovery_file(&nested, b"nested", now);
    let mut input = discovery_input(now);
    input.temp_roots.push(temp.path().to_path_buf());

    let result = discover_bounded_logs(&input);

    assert!(result
        .sources
        .iter()
        .any(|source| source.path == canonical_discovery_path(&top)));
    assert!(!result
        .sources
        .iter()
        .any(|source| source.path == canonical_discovery_path(&nested)));
}

#[test]
fn temp_discovery_inspects_only_128_newest_entries() {
    let temp = tempdir().expect("temp root");
    let now = SystemTime::now();
    for index in 0..130u64 {
        write_discovery_file(
            &temp.path().join(format!("MSI-{index:03}.log")),
            b"candidate",
            now - Duration::from_secs(index),
        );
    }
    let mut input = discovery_input(now);
    input.temp_roots.push(temp.path().to_path_buf());

    let result = discover_bounded_logs(&input);

    assert_eq!(result.temp_entries_probed, 130);
    assert_eq!(result.temp_entries_inspected, 128);
    assert_eq!(result.sources.len(), 128);
    assert!(result
        .sources
        .iter()
        .any(|source| source.path.ends_with("MSI-000.log")));
    assert!(!result
        .sources
        .iter()
        .any(|source| source.path.ends_with("MSI-129.log")));
}

#[test]
fn temp_discovery_reports_truncated_probe_coverage_at_hard_bound() {
    let temp = tempdir().expect("temp root");
    let now = SystemTime::now();
    for index in 0..=MAX_TEMP_ENTRIES_PROBED_PER_ROOT {
        write_discovery_file(
            &temp.path().join(format!("MSI-{index:04}.log")),
            b"candidate",
            now - Duration::from_secs(index as u64),
        );
    }
    let mut input = discovery_input(now);
    input.temp_roots.push(temp.path().to_path_buf());

    let result = discover_bounded_logs(&input);
    let coverage = result.root_coverage.first().expect("temp root coverage");

    assert_eq!(coverage.kind, DiscoveryRootKind::Temp);
    assert_eq!(coverage.state, DiscoveryRootState::Available);
    assert_eq!(coverage.entries_probed, MAX_TEMP_ENTRIES_PROBED_PER_ROOT);
    assert_eq!(
        coverage.entries_inspected,
        MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT
    );
    assert!(coverage.truncated);
    assert!(coverage
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("newest coverage is partial")));
    assert_eq!(result.temp_entries_probed, MAX_TEMP_ENTRIES_PROBED_PER_ROOT);
}

#[test]
fn temp_discovery_reports_missing_root_coverage() {
    let container = tempdir().expect("temp root container");
    let missing = container.path().join("missing-temp-root");
    let mut input = discovery_input(SystemTime::now());
    input.temp_roots.push(missing.clone());

    let result = discover_bounded_logs(&input);
    let coverage = result.root_coverage.first().expect("missing root coverage");

    assert_eq!(coverage.root, missing);
    assert_eq!(coverage.kind, DiscoveryRootKind::Temp);
    assert_eq!(coverage.state, DiscoveryRootState::Missing);
    assert_eq!(coverage.entries_probed, 0);
    assert!(!coverage.truncated);
    assert!(result.sources.is_empty());
}

#[test]
fn known_discovery_reports_missing_root_coverage_with_source_identity() {
    let container = tempdir().expect("known root container");
    let missing = container.path().join("missing-ime-root");
    let mut input = discovery_input(SystemTime::now());
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        &missing,
        ["*.log"],
    ));

    let result = discover_bounded_logs(&input);
    let coverage = result.root_coverage.first().expect("known root coverage");

    assert_eq!(coverage.root, missing);
    assert_eq!(coverage.kind, DiscoveryRootKind::Known);
    assert_eq!(coverage.source_id.as_deref(), Some("ime-logs"));
    assert_eq!(coverage.state, DiscoveryRootState::Missing);
    assert!(result.sources.is_empty());
}

#[test]
fn known_discovery_reports_truncated_coverage_at_hard_bound() {
    let root = tempdir().expect("known root");
    let now = SystemTime::now();
    for index in 0..=MAX_KNOWN_ENTRIES_PROBED_PER_ROOT {
        write_discovery_file(
            &root.path().join(format!("Known-{index:04}.log")),
            b"known",
            now,
        );
    }
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "bounded-known",
        "windows-deployment",
        root.path(),
        ["*.log"],
    ));

    let result = discover_bounded_logs(&input);
    let coverage = result.root_coverage.first().expect("known root coverage");

    assert_eq!(coverage.entries_probed, MAX_KNOWN_ENTRIES_PROBED_PER_ROOT);
    assert!(coverage.truncated);
    assert!(coverage
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("known-source coverage is partial")));
}

#[test]
fn temp_discovery_excludes_files_older_than_30_minutes() {
    let temp = tempdir().expect("temp root");
    let now = SystemTime::now();
    let recent = temp.path().join("MSI-recent.log");
    let old = temp.path().join("MSI-old.log");
    write_discovery_file(&recent, b"recent", now - TEMP_LOOKBACK);
    write_discovery_file(&old, b"old", now - TEMP_LOOKBACK - Duration::from_secs(1));
    let mut input = discovery_input(now);
    input.temp_roots.push(temp.path().to_path_buf());

    let result = discover_bounded_logs(&input);

    assert!(result
        .sources
        .iter()
        .any(|source| source.path == canonical_discovery_path(&recent)));
    assert!(!result
        .sources
        .iter()
        .any(|source| source.path == canonical_discovery_path(&old)));
}

#[test]
fn discovery_classifies_timestamped_ime_file_as_a_rotation() {
    let root = tempdir().expect("known root");
    let now = SystemTime::now();
    let current = root.path().join("AppWorkload.log");
    let rotation = root.path().join("AppWorkload-20260715-143022.log");
    write_discovery_file(&current, b"current", now - Duration::from_secs(30));
    write_discovery_file(&rotation, b"rotation", now);
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        root.path(),
        ["AppWorkload*.log"],
    ));

    let result = discover_bounded_logs(&input);

    let current_source = result
        .sources
        .iter()
        .find(|source| source.path == canonical_discovery_path(&current))
        .expect("current IME source");
    let rotation_source = result
        .sources
        .iter()
        .find(|source| source.path == canonical_discovery_path(&rotation))
        .expect("timestamped IME rotation");
    assert!(current_source.is_current);
    assert!(!rotation_source.is_current);
    assert!(current_source.priority < rotation_source.priority);
}

#[test]
fn discovery_keeps_current_plus_three_newest_rotations_per_stem() {
    let root = tempdir().expect("known root");
    let now = SystemTime::now();
    let file_names = [
        "AppWorkload.log",
        "AppWorkload-20260715-143022.log",
        "AppWorkload-20260715-143021.log",
        "AppWorkload-20260715-143020.log",
        "AppWorkload-20260715-143019.log",
    ];
    for (index, file_name) in file_names.into_iter().enumerate() {
        write_discovery_file(
            &root.path().join(file_name),
            b"known",
            now - Duration::from_secs(index as u64),
        );
    }
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        root.path(),
        ["AppWorkload*.log"],
    ));

    let result = discover_bounded_logs(&input);
    let workload = result
        .sources
        .iter()
        .filter(|source| {
            source
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("AppWorkload"))
        })
        .collect::<Vec<_>>();

    assert_eq!(workload.len(), MAX_ROTATIONS_PER_KNOWN_LOG + 1);
    assert_eq!(
        workload[0].path.file_name().and_then(|name| name.to_str()),
        Some("AppWorkload.log")
    );
    assert!(workload
        .iter()
        .any(|source| source.path.ends_with("AppWorkload-20260715-143020.log")));
    assert!(!workload
        .iter()
        .any(|source| source.path.ends_with("AppWorkload-20260715-143019.log")));
}

#[test]
fn discovery_keeps_numeric_ime_rotations_under_the_same_three_file_cap() {
    let root = tempdir().expect("known root");
    let now = SystemTime::now();
    for (index, suffix) in ["", ".1", ".2", ".3", ".4"].into_iter().enumerate() {
        write_discovery_file(
            &root.path().join(format!("AppWorkload.log{suffix}")),
            b"known",
            now - Duration::from_secs(index as u64),
        );
    }
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        root.path(),
        ["AppWorkload.log*"],
    ));

    let result = discover_bounded_logs(&input);
    let workload = result
        .sources
        .iter()
        .filter(|source| {
            source
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("AppWorkload.log"))
        })
        .collect::<Vec<_>>();

    assert_eq!(workload.len(), MAX_ROTATIONS_PER_KNOWN_LOG + 1);
    assert!(!workload
        .iter()
        .any(|source| source.path.ends_with("AppWorkload.log.4")));
}

#[test]
fn discovery_rejects_unsupported_log_suffixes_instead_of_treating_them_as_current() {
    let root = tempdir().expect("known root");
    let now = SystemTime::now();
    for file_name in [
        "AppWorkload.log",
        "AppWorkload.log.1",
        "AppWorkload.log.bak",
        "AppWorkload.log.gz",
    ] {
        write_discovery_file(&root.path().join(file_name), b"known", now);
    }
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        root.path(),
        ["AppWorkload.log*"],
    ));

    let result = discover_bounded_logs(&input);
    let names = result
        .sources
        .iter()
        .filter_map(|source| source.path.file_name()?.to_str())
        .collect::<Vec<_>>();

    assert!(names.contains(&"AppWorkload.log"));
    assert!(names.contains(&"AppWorkload.log.1"));
    assert!(!names.contains(&"AppWorkload.log.bak"));
    assert!(!names.contains(&"AppWorkload.log.gz"));
}

#[test]
fn discovery_groups_log_old_with_other_rotations_for_the_same_stem() {
    let root = tempdir().expect("known root");
    let now = SystemTime::now();
    for (index, file_name) in [
        "AppEnforce.log",
        "AppEnforce.log.old",
        "AppEnforce.log.1",
        "AppEnforce.log.2",
        "AppEnforce.log.3",
    ]
    .into_iter()
    .enumerate()
    {
        write_discovery_file(
            &root.path().join(file_name),
            b"known",
            now - Duration::from_secs(index as u64),
        );
    }
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "configmgr-logs",
        "configmgr",
        root.path(),
        ["AppEnforce*"],
    ));

    let result = discover_bounded_logs(&input);
    let app_enforce = result
        .sources
        .iter()
        .filter(|source| {
            source
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("AppEnforce"))
        })
        .collect::<Vec<_>>();

    assert_eq!(app_enforce.len(), MAX_ROTATIONS_PER_KNOWN_LOG + 1);
    assert!(!app_enforce
        .iter()
        .any(|source| source.path.ends_with("AppEnforce.log.3")));
}

#[test]
fn discovery_prioritizes_current_ime_then_process_before_rotations_and_temp_logs() {
    let root = tempdir().expect("discovery root");
    let now = SystemTime::now();
    let current = root.path().join("AppWorkload.log");
    let rotation = root.path().join("AppWorkload.log.1");
    let process = root.path().join("custom-process.data");
    let temp_log = root.path().join("MSI-temp.log");
    write_discovery_file(&current, b"current", now - Duration::from_secs(5));
    write_discovery_file(&rotation, b"rotation", now);
    write_discovery_file(&process, b"process", now);
    write_discovery_file(&temp_log, b"temp", now);
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        root.path(),
        ["AppWorkload.log*"],
    ));
    input.temp_roots.push(root.path().to_path_buf());
    input.active_process_logs.push(process.clone());

    let result = discover_bounded_logs(&input);

    assert_eq!(result.sources[0].path, canonical_discovery_path(&current));
    assert_eq!(result.sources[1].path, canonical_discovery_path(&process));
    assert_eq!(result.sources[2].path, canonical_discovery_path(&rotation));
    assert_eq!(
        result.sources.last().map(|source| &source.path),
        Some(&canonical_discovery_path(&temp_log))
    );
}

#[test]
fn discovery_keeps_active_process_log_inside_sixteen_tail_priority_window() {
    let root = tempdir().expect("discovery root");
    let now = SystemTime::now();
    let stems = [
        "IntuneManagementExtension",
        "AppWorkload",
        "AppActionProcessor",
        "AgentExecutor",
        "Win32AppInventory",
    ];
    for (stem_index, stem) in stems.into_iter().enumerate() {
        write_discovery_file(
            &root.path().join(format!("{stem}.log")),
            b"current",
            now - Duration::from_secs(100 + stem_index as u64),
        );
        for rotation_index in 0..MAX_ROTATIONS_PER_KNOWN_LOG {
            write_discovery_file(
                &root
                    .path()
                    .join(format!("{stem}-20260715-14302{rotation_index}.log")),
                b"rotation",
                now - Duration::from_secs(rotation_index as u64),
            );
        }
    }
    let process = root.path().join("active-msiexec-output.data");
    write_discovery_file(&process, b"active process", now);
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        root.path(),
        ["*.log"],
    ));
    input.active_process_logs.push(process.clone());

    let result = discover_bounded_logs(&input);
    let priority_window = result
        .sources
        .iter()
        .take(MAX_ACTIVE_TAILS)
        .collect::<Vec<_>>();

    assert_eq!(priority_window.len(), MAX_ACTIVE_TAILS);
    assert!(priority_window
        .iter()
        .any(|source| source.path == canonical_discovery_path(&process)));
}

#[cfg(unix)]
#[test]
fn discovery_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let root = tempdir().expect("temp root");
    let outside = tempdir().expect("outside root");
    let now = SystemTime::now();
    let target = outside.path().join("MSI-escape.log");
    write_discovery_file(&target, b"outside", now);
    let link = root.path().join("MSI-link.log");
    symlink(&target, &link).expect("create escape symlink");
    let mut input = discovery_input(now);
    input.temp_roots.push(root.path().to_path_buf());

    let result = discover_bounded_logs(&input);

    assert!(result.sources.is_empty());
}

#[cfg(unix)]
#[test]
fn known_discovery_reports_rejected_symlink_entry_coverage() {
    use std::os::unix::fs::symlink;

    let root = tempdir().expect("known root");
    let outside = tempdir().expect("outside root");
    let now = SystemTime::now();
    let target = outside.path().join("AppWorkload.log");
    write_discovery_file(&target, b"outside", now);
    symlink(&target, root.path().join("AppWorkload.log")).expect("create escape symlink");
    let mut input = discovery_input(now);
    input.known_sources.push(KnownSourceSpec::folder(
        "ime-logs",
        "intune-ime",
        root.path(),
        ["*.log"],
    ));

    let result = discover_bounded_logs(&input);
    let coverage = result.root_coverage.first().expect("known root coverage");

    assert_eq!(coverage.state, DiscoveryRootState::Available);
    assert_eq!(coverage.entries_probed, 1);
    assert_eq!(coverage.entries_rejected, 1);
    assert!(result.sources.is_empty());
    assert_eq!(result.path_failures.len(), 1);
    assert_eq!(
        result.path_failures[0].kind,
        DiscoveryPathFailureKind::ReparseRejected
    );
    assert_eq!(
        result.path_failures[0].source_id.as_deref(),
        Some("ime-logs")
    );
}

#[cfg(unix)]
#[test]
fn discovery_rejects_symlink_root_escape() {
    use std::os::unix::fs::symlink;

    let container = tempdir().expect("root container");
    let outside = tempdir().expect("outside root");
    let now = SystemTime::now();
    let target = outside.path().join("MSI-escaped-root.log");
    write_discovery_file(&target, b"outside", now);
    let linked_root = container.path().join("linked-temp");
    symlink(outside.path(), &linked_root).expect("create root symlink");
    let mut input = discovery_input(now);
    input.temp_roots.push(linked_root);

    let result = discover_bounded_logs(&input);

    assert!(result.sources.is_empty());
    assert_eq!(result.temp_entries_inspected, 0);
    let coverage = result
        .root_coverage
        .first()
        .expect("reparse-rejected root coverage");
    assert_eq!(coverage.state, DiscoveryRootState::ReparseRejected);
    assert!(coverage
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("reparse")));
}

#[test]
fn discovery_accepts_msi_signature_in_first_4k_only() {
    let temp = tempdir().expect("temp root");
    let now = SystemTime::now();
    let signed = temp.path().join("opaque.bin");
    let late = temp.path().join("late.bin");
    write_discovery_file(
        &signed,
        b"=== Verbose logging started: Windows Installer transaction",
        now,
    );
    let mut late_bytes = vec![b'x'; 4_096];
    late_bytes.extend_from_slice(b"Windows Installer");
    write_discovery_file(&late, &late_bytes, now);
    let mut input = discovery_input(now);
    input.temp_roots.push(temp.path().to_path_buf());

    let result = discover_bounded_logs(&input);

    assert!(result
        .sources
        .iter()
        .any(|source| source.path == canonical_discovery_path(&signed)));
    assert!(!result
        .sources
        .iter()
        .any(|source| source.path == canonical_discovery_path(&late)));
}

#[test]
fn discovery_accepts_explicit_running_process_log_outside_temp_lookback() {
    let root = tempdir().expect("process root");
    let now = SystemTime::now();
    let process_log = root.path().join("custom-output.data");
    write_discovery_file(
        &process_log,
        b"not otherwise recognizable",
        now - Duration::from_secs(24 * 60 * 60),
    );
    let mut input = discovery_input(now);
    input.active_process_logs.push(process_log.clone());

    let result = discover_bounded_logs(&input);

    let source = result
        .sources
        .iter()
        .find(|source| source.path == canonical_discovery_path(&process_log))
        .expect("active process log");
    assert_eq!(source.origin, DiscoverySourceOrigin::ActiveProcess);
}

#[test]
fn discovery_reports_missing_explicit_process_log_with_typed_coverage() {
    let root = tempdir().expect("process root");
    let missing = root.path().join("missing-active-msi.log");
    let mut input = discovery_input(SystemTime::now());
    input.active_process_logs.push(missing.clone());

    let result = discover_bounded_logs(&input);

    assert!(result.sources.is_empty());
    assert_eq!(result.path_failures.len(), 1);
    let failure = &result.path_failures[0];
    assert_eq!(failure.path, missing);
    assert_eq!(failure.source_id.as_deref(), Some("active-process-log"));
    assert_eq!(failure.origin, DiscoverySourceOrigin::ActiveProcess);
    assert_eq!(failure.kind, DiscoveryPathFailureKind::Missing);
}

#[cfg(unix)]
#[test]
fn discovery_reports_reparse_explicit_process_log_with_typed_coverage() {
    use std::os::unix::fs::symlink;

    let root = tempdir().expect("process root");
    let outside = tempdir().expect("outside root");
    let target = outside.path().join("outside-active-msi.log");
    fs::write(&target, b"outside\n").expect("write outside target");
    let link = root.path().join("active-msi.log");
    symlink(&target, &link).expect("create process-log symlink");
    let mut input = discovery_input(SystemTime::now());
    input.active_process_logs.push(link.clone());

    let result = discover_bounded_logs(&input);

    assert!(result.sources.is_empty());
    assert_eq!(result.path_failures.len(), 1);
    assert_eq!(result.path_failures[0].path, link);
    assert_eq!(
        result.path_failures[0].kind,
        DiscoveryPathFailureKind::ReparseRejected
    );
}

#[test]
fn discovery_canonicalizes_and_deduplicates_active_process_paths() {
    let root = tempdir().expect("process root");
    let now = SystemTime::now();
    let process_log = root.path().join("active-installer.log");
    write_discovery_file(&process_log, b"active", now);
    let lexical_alias = root.path().join(".").join("active-installer.log");
    let mut input = discovery_input(now);
    input
        .active_process_logs
        .extend([process_log.clone(), lexical_alias]);

    let result = discover_bounded_logs(&input);
    let active = result
        .sources
        .iter()
        .filter(|source| source.origin == DiscoverySourceOrigin::ActiveProcess)
        .collect::<Vec<_>>();

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].path, canonical_discovery_path(&process_log));
}

#[test]
fn discovery_has_no_arbitrary_root_or_deep_mode() {
    let source = include_str!("../src/esp/discovery.rs");
    for forbidden in [
        "WalkDir",
        "walkdir",
        "follow_links",
        "deep_scan",
        "deepScan",
        "arbitrary_root",
    ] {
        assert!(
            !source.contains(forbidden),
            "bounded discovery exposed forbidden behavior: {forbidden}"
        );
    }
}

#[cfg(unix)]
#[test]
fn temp_discovery_counts_signature_read_failure_as_rejected_path() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempdir().expect("temp root");
    let path = root.path().join("candidate.data");
    fs::write(&path, b"candidate without a high-signal name\n").expect("write candidate");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000))
        .expect("make candidate unreadable");
    let mut input = discovery_input(SystemTime::now());
    input.temp_roots.push(root.path().to_path_buf());

    let result = discover_bounded_logs(&input);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .expect("restore candidate permissions");
    let coverage = result.root_coverage.first().expect("temp coverage");
    assert_eq!(coverage.entries_inspected, 1);
    assert_eq!(coverage.entries_rejected, 1);
    assert_eq!(result.path_failures.len(), 1);
    assert_eq!(
        result.path_failures[0].kind,
        DiscoveryPathFailureKind::PermissionDenied
    );
}

fn tail_source(
    path: PathBuf,
    source_id: impl Into<String>,
    priority: u8,
    origin: DiscoverySourceOrigin,
    is_current: bool,
) -> DiscoveredLogSource {
    DiscoveredLogSource {
        path,
        source_id: source_id.into(),
        family: "tail-test".to_string(),
        origin,
        priority,
        is_current,
        modified: Some(SystemTime::now()),
    }
}

#[test]
fn tail_initial_context_is_limited_to_final_eight_mib() {
    let root = tempdir().expect("tail root");
    let path = root.path().join("large.log");
    let mut bytes = b"discarded-marker ".to_vec();
    bytes.resize(MAX_INITIAL_READ_BYTES as usize + 32, b'x');
    bytes.extend_from_slice(b"\nretained-tail\n");
    fs::write(&path, bytes).expect("write large tail fixture");

    let mut tails = EspTailSet::new();
    let result = tails.reconcile(&[tail_source(
        path.clone(),
        "large",
        0,
        DiscoverySourceOrigin::CuratedKnown,
        true,
    )]);

    assert!(result.failures.is_empty());
    assert_eq!(result.attachments.len(), 1);
    let attachment = &result.attachments[0];
    assert_eq!(attachment.end_offset - attachment.start_offset, 14);
    assert_eq!(attachment.entries.len(), 1);
    assert_eq!(attachment.entries[0].message, "retained-tail");
    assert!(attachment.start_offset > 0);
}

#[test]
fn tail_emits_appended_utf8_and_windows_1252_without_partial_records() {
    let root = tempdir().expect("tail root");
    let utf8_path = root.path().join("utf8.log");
    let cp1252_path = root.path().join("cp1252.log");
    fs::write(&utf8_path, b"initial\n").expect("write utf8 fixture");
    fs::write(&cp1252_path, b"initial\n").expect("write cp1252 fixture");
    let mut tails = EspTailSet::new();
    let started = tails.reconcile(&[
        tail_source(
            utf8_path.clone(),
            "utf8",
            0,
            DiscoverySourceOrigin::CuratedKnown,
            true,
        ),
        tail_source(
            cp1252_path.clone(),
            "cp1252",
            1,
            DiscoverySourceOrigin::CuratedKnown,
            true,
        ),
    ]);
    assert_eq!(started.attachments.len(), 2);

    OpenOptions::new()
        .append(true)
        .open(&utf8_path)
        .expect("open utf8 fixture")
        .write_all("caf\u{00e9}\npartial".as_bytes())
        .expect("append utf8");
    OpenOptions::new()
        .append(true)
        .open(&cp1252_path)
        .expect("open cp1252 fixture")
        .write_all(b"caf\xe9\n")
        .expect("append cp1252");

    let first = tails.poll();
    assert!(first.failures.is_empty());
    assert_eq!(first.updates.len(), 2);
    assert!(first.updates.iter().all(|update| update.entries.len() == 1));
    assert!(first
        .updates
        .iter()
        .all(|update| update.entries[0].message == "caf\u{00e9}"));

    OpenOptions::new()
        .append(true)
        .open(&utf8_path)
        .expect("reopen utf8 fixture")
        .write_all(b" complete\n")
        .expect("finish partial line");
    let second = tails.poll();
    assert_eq!(second.updates.len(), 1);
    assert_eq!(second.updates[0].entries[0].message, "partial complete");
}

#[test]
fn tail_distinguishes_truncation_from_file_rotation() {
    let root = tempdir().expect("tail root");
    let truncated_path = root.path().join("truncated.log");
    let rotated_path = root.path().join("rotated.log");
    fs::write(&truncated_path, b"original content is deliberately long\n")
        .expect("write truncation fixture");
    fs::write(&rotated_path, b"old generation\n").expect("write rotation fixture");
    let mut tails = EspTailSet::new();
    tails.reconcile(&[
        tail_source(
            truncated_path.clone(),
            "truncated",
            0,
            DiscoverySourceOrigin::CuratedKnown,
            true,
        ),
        tail_source(
            rotated_path.clone(),
            "rotated",
            1,
            DiscoverySourceOrigin::CuratedKnown,
            true,
        ),
    ]);

    fs::write(&truncated_path, b"fresh\n").expect("truncate fixture");
    fs::rename(&rotated_path, root.path().join("rotated.log.1")).expect("rotate fixture");
    fs::write(
        &rotated_path,
        b"new generation with at least the old length\n",
    )
    .expect("write new generation");

    let result = tails.poll();
    assert!(result.failures.is_empty());
    assert_eq!(result.updates.len(), 2);
    let truncated = result
        .updates
        .iter()
        .find(|update| update.path == truncated_path)
        .expect("truncation update");
    assert_eq!(truncated.reset_reason, Some(EspTailResetReason::Truncated));
    assert_eq!(truncated.entries[0].message, "fresh");
    let rotated = result
        .updates
        .iter()
        .find(|update| update.path == rotated_path)
        .expect("rotation update");
    assert_eq!(rotated.reset_reason, Some(EspTailResetReason::Rotated));
    assert_eq!(
        rotated.entries[0].message,
        "new generation with at least the old length"
    );
}

#[test]
fn tail_reads_bytes_appended_while_source_is_temporarily_deselected() {
    let root = tempdir().expect("tail root");
    let path = root.path().join("temporarily-deselected.log");
    fs::write(&path, b"initial\n").expect("write tail fixture");
    let source = tail_source(
        path.clone(),
        "temporarily-deselected",
        0,
        DiscoverySourceOrigin::CuratedKnown,
        true,
    );
    let mut tails = EspTailSet::new();
    let initial = tails.reconcile(std::slice::from_ref(&source));
    let initial_id = initial.attachments[0].entries[0].id;

    tails.reconcile(&[]);
    OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open deselected source")
        .write_all(b"written during gap\n")
        .expect("append during gap");
    let rediscovered = tails.reconcile(std::slice::from_ref(&source));
    let update = tails.poll();

    assert!(rediscovered.attachments.is_empty());
    assert!(update.failures.is_empty());
    assert_eq!(update.updates.len(), 1);
    assert_eq!(update.updates[0].entries[0].message, "written during gap");
    assert!(update.updates[0].entries[0].id > initial_id);
    assert_eq!(update.updates[0].reset_reason, None);
}

#[test]
fn tail_reports_rotation_and_preserves_identity_when_source_returns_after_disappearing() {
    let root = tempdir().expect("tail root");
    let path = root.path().join("temporarily-missing.log");
    fs::write(&path, b"old generation\n").expect("write tail fixture");
    let source = tail_source(
        path.clone(),
        "temporarily-missing",
        0,
        DiscoverySourceOrigin::CuratedKnown,
        true,
    );
    let mut tails = EspTailSet::new();
    let initial = tails.reconcile(std::slice::from_ref(&source));
    let initial_id = initial.attachments[0].entries[0].id;

    tails.reconcile(&[]);
    fs::rename(&path, root.path().join("temporarily-missing.log.1"))
        .expect("rotate missing source");
    fs::write(&path, b"new generation\n").expect("replace missing source");
    let rediscovered = tails.reconcile(std::slice::from_ref(&source));
    let update = tails.poll();

    assert!(rediscovered.attachments.is_empty());
    assert!(update.failures.is_empty());
    assert_eq!(update.updates.len(), 1);
    assert_eq!(
        update.updates[0].reset_reason,
        Some(EspTailResetReason::Rotated)
    );
    assert_eq!(update.updates[0].entries[0].message, "new generation");
    assert!(update.updates[0].entries[0].id > initial_id);
}

#[test]
fn tail_attaches_sources_once_and_enforces_priority_and_sixteen_tail_cap() {
    let root = tempdir().expect("tail root");
    let mut sources = Vec::new();
    for priority in (0..20u8).rev() {
        let path = root.path().join(format!("source-{priority:02}.log"));
        fs::write(&path, format!("source {priority}\n")).expect("write tail source");
        sources.push(tail_source(
            path,
            format!("source-{priority:02}"),
            priority,
            DiscoverySourceOrigin::CuratedKnown,
            true,
        ));
    }
    let rotation_path = root.path().join("known.log.1");
    fs::write(&rotation_path, b"snapshot only\n").expect("write known rotation");
    sources.push(tail_source(
        rotation_path.clone(),
        "known-rotation",
        0,
        DiscoverySourceOrigin::CuratedKnown,
        false,
    ));
    let temp_path = root.path().join("MSI-temp.log");
    fs::write(&temp_path, b"snapshot only\n").expect("write temp candidate");
    sources.push(tail_source(
        temp_path.clone(),
        "temp",
        0,
        DiscoverySourceOrigin::Temp,
        true,
    ));

    let mut tails = EspTailSet::new();
    let first = tails.reconcile(&sources);
    assert!(first.failures.is_empty());
    assert_eq!(first.attachments.len(), sources.len());
    assert!(first
        .attachments
        .iter()
        .any(|attachment| attachment.source.path == rotation_path));
    assert!(first
        .attachments
        .iter()
        .any(|attachment| attachment.source.path == temp_path));
    assert_eq!(tails.active_tail_count(), MAX_ACTIVE_TAILS);
    let active = tails.active_paths();
    for priority in 0..MAX_ACTIVE_TAILS as u8 {
        assert!(active
            .iter()
            .any(|path| path.ends_with(format!("source-{priority:02}.log"))));
    }
    assert!(!active.contains(&rotation_path));
    assert!(!active.contains(&temp_path));

    let second = tails.reconcile(&sources);
    assert!(second.attachments.is_empty());
    assert!(second.failures.is_empty());

    tails.reconcile(&[]);
    assert_eq!(tails.active_tail_count(), 0);
    let rediscovered = tails.reconcile(&sources);
    assert!(rediscovered.attachments.is_empty());
    assert_eq!(tails.active_tail_count(), MAX_ACTIVE_TAILS);
}

#[test]
fn tail_stop_drops_all_owned_state_and_prevents_restart() {
    let root = tempdir().expect("tail root");
    let path = root.path().join("stop.log");
    fs::write(&path, b"initial\n").expect("write stop fixture");
    let source = tail_source(path, "stop", 0, DiscoverySourceOrigin::ActiveProcess, true);
    let mut tails = EspTailSet::new();
    assert_eq!(
        tails
            .reconcile(std::slice::from_ref(&source))
            .attachments
            .len(),
        1
    );

    tails.stop();

    assert!(tails.is_stopped());
    assert_eq!(tails.active_tail_count(), 0);
    assert!(tails.poll().updates.is_empty());
    assert!(tails.reconcile(&[source]).attachments.is_empty());
}

#[test]
fn tail_reports_missing_selected_file_with_typed_failure() {
    let root = tempdir().expect("tail root");
    let path = root.path().join("removed.log");
    fs::write(&path, b"initial\n").expect("write tail fixture");
    let source = tail_source(
        path.clone(),
        "removed",
        0,
        DiscoverySourceOrigin::ActiveProcess,
        true,
    );
    let mut tails = EspTailSet::new();
    tails.reconcile(std::slice::from_ref(&source));
    fs::remove_file(&path).expect("remove selected file");

    let result = tails.poll();

    assert!(result.updates.is_empty());
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].path, path);
    assert_eq!(result.failures[0].kind, DiscoveryPathFailureKind::Missing);
}

#[cfg(unix)]
#[test]
fn tail_rejects_reparse_replacement_with_typed_failure() {
    use std::os::unix::fs::symlink;

    let root = tempdir().expect("tail root");
    let outside = tempdir().expect("outside root");
    let path = root.path().join("selected.log");
    let outside_path = outside.path().join("outside.log");
    fs::write(&path, b"initial\n").expect("write tail fixture");
    fs::write(&outside_path, b"must not be read\n").expect("write outside fixture");
    let source = tail_source(
        path.clone(),
        "selected",
        0,
        DiscoverySourceOrigin::ActiveProcess,
        true,
    );
    let mut tails = EspTailSet::new();
    tails.reconcile(std::slice::from_ref(&source));
    fs::remove_file(&path).expect("remove selected file");
    symlink(&outside_path, &path).expect("replace selected file with symlink");

    let result = tails.poll();

    assert!(result.updates.is_empty());
    assert_eq!(result.failures.len(), 1);
    assert_eq!(
        result.failures[0].kind,
        DiscoveryPathFailureKind::ReparseRejected
    );
}

#[test]
fn tail_bounds_an_incomplete_record_to_eight_mib() {
    let root = tempdir().expect("tail root");
    let path = root.path().join("unterminated.log");
    fs::write(&path, vec![b'x'; MAX_INITIAL_READ_BYTES as usize])
        .expect("write unterminated fixture");
    let mut tails = EspTailSet::new();
    let started = tails.reconcile(&[tail_source(
        path.clone(),
        "unterminated",
        0,
        DiscoverySourceOrigin::ActiveProcess,
        true,
    )]);
    assert!(started.failures.is_empty());
    assert!(started.attachments[0].entries.is_empty());

    OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("open unterminated fixture")
        .write_all(b"x")
        .expect("grow unterminated fixture");
    let result = tails.poll();

    assert!(result.updates.is_empty());
    assert_eq!(result.failures.len(), 1);
    assert_eq!(
        result.failures[0].kind,
        DiscoveryPathFailureKind::ResourceLimit
    );
    assert!(result.failures[0].detail.contains("pending record"));
}

#[test]
fn tail_bounds_unique_source_attachments_for_the_session() {
    let root = tempdir().expect("tail root");
    let mut sources = Vec::new();
    for index in 0..=MAX_SESSION_TAIL_SOURCES {
        let path = root.path().join(format!("MSI-{index:03}.log"));
        fs::write(&path, b"snapshot\n").expect("write bounded source");
        sources.push(tail_source(
            path,
            format!("bounded-{index:03}"),
            5,
            DiscoverySourceOrigin::Temp,
            true,
        ));
    }
    let mut tails = EspTailSet::new();

    let result = tails.reconcile(&sources);

    assert_eq!(result.attachments.len(), MAX_SESSION_TAIL_SOURCES);
    assert!(result.source_limit_reached);
    assert_eq!(tails.active_tail_count(), 0);
}

#[test]
fn tail_attachment_budget_evicts_deterministically_for_a_later_active_msi_log() {
    let root = tempdir().expect("tail root");
    let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let mut snapshots = Vec::new();
    for index in 0..MAX_SESSION_TAIL_SOURCES {
        let path = root.path().join(format!("MSI-{index:03}.log"));
        fs::write(&path, b"snapshot\n").expect("write bounded snapshot");
        let mut source = tail_source(
            path,
            format!("bounded-{index:03}"),
            5,
            DiscoverySourceOrigin::Temp,
            true,
        );
        source.modified = Some(modified);
        snapshots.push(source);
    }
    let mut tails = EspTailSet::new();
    let initial = tails.reconcile(&snapshots);
    assert_eq!(initial.attachments.len(), MAX_SESSION_TAIL_SOURCES);

    let active_path = root.path().join("active-msiexec.log");
    fs::write(&active_path, b"active MSI\n").expect("write active MSI log");
    let active = tail_source(
        active_path.clone(),
        "active-msiexec",
        1,
        DiscoverySourceOrigin::ActiveProcess,
        true,
    );
    let mut next_sources = snapshots;
    next_sources.push(active);
    let result = tails.reconcile(&next_sources);

    assert!(result
        .attachments
        .iter()
        .any(|attachment| attachment.source.path == active_path));
    assert!(tails.active_paths().contains(&active_path));
    assert_eq!(result.evicted_sources.len(), 1);
    assert!(result.evicted_sources[0].path.ends_with("MSI-511.log"));
    assert!(result.source_limit_reached);
}

#[test]
fn tail_selected_current_source_precedes_snapshot_attachment_budget() {
    let root = tempdir().expect("tail root");
    let mut sources = Vec::new();
    for index in 0..MAX_SESSION_TAIL_SOURCES {
        let path = root.path().join(format!("rotation-{index:03}.log.1"));
        fs::write(&path, b"snapshot\n").expect("write snapshot");
        sources.push(tail_source(
            path,
            format!("rotation-{index:03}"),
            2,
            DiscoverySourceOrigin::CuratedKnown,
            false,
        ));
    }
    let current_path = root.path().join("current-configmgr.log");
    fs::write(&current_path, b"current\n").expect("write current source");
    sources.push(tail_source(
        current_path.clone(),
        "current-configmgr",
        3,
        DiscoverySourceOrigin::CuratedKnown,
        true,
    ));
    let mut tails = EspTailSet::new();

    let result = tails.reconcile(&sources);

    assert!(result.source_limit_reached);
    assert!(result
        .attachments
        .iter()
        .any(|attachment| attachment.source.path == current_path));
    assert!(tails.active_paths().contains(&current_path));
}

#[test]
fn tail_failed_priority_attachment_preserves_existing_budget_entry() {
    let root = tempdir().expect("tail root");
    let mut snapshots = Vec::new();
    for index in 0..MAX_SESSION_TAIL_SOURCES {
        let path = root.path().join(format!("MSI-{index:03}.log"));
        fs::write(&path, b"snapshot\n").expect("write bounded snapshot");
        snapshots.push(tail_source(
            path,
            format!("bounded-{index:03}"),
            5,
            DiscoverySourceOrigin::Temp,
            true,
        ));
    }
    let mut tails = EspTailSet::new();
    assert_eq!(
        tails.reconcile(&snapshots).attachments.len(),
        MAX_SESSION_TAIL_SOURCES
    );

    let missing_path = root.path().join("missing-active-msiexec.log");
    snapshots.push(tail_source(
        missing_path.clone(),
        "missing-active-msiexec",
        1,
        DiscoverySourceOrigin::ActiveProcess,
        true,
    ));
    let result = tails.reconcile(&snapshots);

    assert!(result.source_limit_reached);
    assert_eq!(result.failures.len(), 1);
    assert_eq!(result.failures[0].path, missing_path);
    assert!(result.attachments.is_empty());
    assert!(result.evicted_sources.is_empty());
}

#[test]
fn tail_dormant_cursor_cache_is_bounded_and_reattachment_is_an_explicit_reset() {
    let root = tempdir().expect("tail root");
    let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000);
    let mut sources = Vec::new();
    for index in 0..(MAX_ACTIVE_TAILS * 3) {
        let path = root.path().join(format!("current-{index:02}.log"));
        fs::write(&path, format!("source {index}\n")).expect("write current source");
        let mut source = tail_source(
            path,
            format!("current-{index:02}"),
            if index < MAX_ACTIVE_TAILS { 0 } else { 10 },
            DiscoverySourceOrigin::CuratedKnown,
            true,
        );
        source.modified = Some(modified);
        sources.push(source);
    }
    let mut tails = EspTailSet::new();
    let initial = tails.reconcile(&sources);
    assert_eq!(initial.attachments.len(), sources.len());

    for (index, source) in sources.iter_mut().enumerate() {
        source.priority = if (MAX_ACTIVE_TAILS..MAX_ACTIVE_TAILS * 2).contains(&index) {
            0
        } else {
            10
        };
    }
    let second = tails.reconcile(&sources);
    assert_eq!(second.attachments.len(), MAX_ACTIVE_TAILS);
    assert!(second
        .attachments
        .iter()
        .all(|attachment| { attachment.reset_reason == Some(EspTailResetReason::Reattached) }));

    for (index, source) in sources.iter_mut().enumerate() {
        source.priority = if (MAX_ACTIVE_TAILS * 2..MAX_ACTIVE_TAILS * 3).contains(&index) {
            0
        } else {
            10
        };
    }
    let third = tails.reconcile(&sources);

    assert_eq!(third.attachments.len(), MAX_ACTIVE_TAILS);
    assert!(third
        .attachments
        .iter()
        .all(|attachment| { attachment.reset_reason == Some(EspTailResetReason::Reattached) }));
    assert_eq!(third.failures.len(), MAX_ACTIVE_TAILS);
    assert!(third.failures.iter().all(|failure| {
        failure.kind == DiscoveryPathFailureKind::ResourceLimit
            && failure.detail.contains("dormant")
            && failure.detail.contains(&MAX_INITIAL_READ_BYTES.to_string())
    }));
    assert_eq!(tails.active_tail_count(), MAX_ACTIVE_TAILS);
    assert!(tails.retained_tail_cursor_count() <= MAX_ACTIVE_TAILS + MAX_DORMANT_TAIL_CURSORS);
}

#[test]
fn tail_windows_file_opens_request_read_write_delete_sharing() {
    assert_eq!(WINDOWS_SHARED_READ_WRITE_DELETE, 0x1 | 0x2 | 0x4);
    let source = include_str!("../src/esp/tailing.rs");
    assert!(source.contains("share_mode(WINDOWS_SHARED_READ_WRITE_DELETE)"));
}

#[derive(Default)]
struct ManualSessionClock {
    elapsed: Mutex<Duration>,
    changed: Condvar,
}

impl ManualSessionClock {
    fn advance(&self, duration: Duration) {
        let mut elapsed = self.elapsed.lock().expect("manual clock");
        *elapsed += duration;
        self.changed.notify_all();
    }
}

impl EspSessionClock for ManualSessionClock {
    fn now(&self) -> EspClockReading {
        EspClockReading {
            monotonic: *self.elapsed.lock().expect("manual clock"),
            utc: "2026-07-16T06:30:00Z".to_string(),
        }
    }

    fn wait(&self, cancellation: &EspCancellation, _duration: Duration) {
        if cancellation.is_cancelled() {
            return;
        }
        let elapsed = self.elapsed.lock().expect("manual clock");
        let _ = self
            .changed
            .wait_timeout(elapsed, Duration::from_millis(5))
            .expect("manual clock wait");
    }
}

#[derive(Clone)]
struct FakeSessionProvider {
    artifact_id: &'static str,
    calls: Arc<AtomicUsize>,
    coverage: Vec<EspArtifactCoverage>,
    panic_on_call: Option<usize>,
}

impl FakeSessionProvider {
    fn available(artifact_id: &'static str) -> Self {
        Self {
            artifact_id,
            calls: Arc::new(AtomicUsize::new(0)),
            coverage: Vec::new(),
            panic_on_call: None,
        }
    }

    fn with_coverage(mut self, coverage: EspArtifactCoverage) -> Self {
        self.coverage.push(coverage);
        self
    }

    fn panics_on_call(mut self, call: usize) -> Self {
        self.panic_on_call = Some(call);
        self
    }
}

impl EspEvidenceProvider for FakeSessionProvider {
    fn collect(&self, observed_at_utc: &str) -> EspProviderBatch {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        assert_ne!(self.panic_on_call, Some(call), "fake provider panic");
        EspProviderBatch {
            records: vec![session_system_record(
                self.artifact_id,
                &format!("{}-{call}", self.artifact_id),
                observed_at_utc,
            )],
            coverage: self.coverage.clone(),
        }
    }
}

#[derive(Clone)]
struct StaticSessionProvider {
    records: Vec<EspEvidenceRecord>,
}

#[derive(Clone)]
struct BlockingSessionProvider {
    calls: Arc<AtomicUsize>,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl EspEvidenceProvider for BlockingSessionProvider {
    fn collect(&self, observed_at_utc: &str) -> EspProviderBatch {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.wait();
            self.release.wait();
        }
        EspProviderBatch {
            records: vec![session_system_record(
                "blocking-provider",
                "blocking-provider-evidence",
                observed_at_utc,
            )],
            coverage: Vec::new(),
        }
    }
}

impl EspEvidenceProvider for StaticSessionProvider {
    fn collect(&self, _observed_at_utc: &str) -> EspProviderBatch {
        EspProviderBatch {
            records: self.records.clone(),
            coverage: Vec::new(),
        }
    }
}

#[derive(Clone, Default)]
struct FakeSessionDiscovery {
    calls: Arc<AtomicUsize>,
}

impl EspDiscoveryProvider for FakeSessionDiscovery {
    fn discover(&self, _observed_at_utc: &str) -> EspDiscoveryBatch {
        self.calls.fetch_add(1, Ordering::SeqCst);
        EspDiscoveryBatch::default()
    }
}

#[derive(Clone, Default)]
struct FakeSessionTailFactory {
    queued: Arc<Mutex<VecDeque<EspTailEvidenceBatch>>>,
    reconciles: Arc<AtomicUsize>,
    stops: Arc<AtomicUsize>,
}

impl EspSessionTailFactory for FakeSessionTailFactory {
    fn create(&self) -> Box<dyn EspSessionTail> {
        Box::new(FakeSessionTail {
            queued: Arc::clone(&self.queued),
            reconciles: Arc::clone(&self.reconciles),
            stops: Arc::clone(&self.stops),
        })
    }
}

struct FakeSessionTail {
    queued: Arc<Mutex<VecDeque<EspTailEvidenceBatch>>>,
    reconciles: Arc<AtomicUsize>,
    stops: Arc<AtomicUsize>,
}

impl EspSessionTail for FakeSessionTail {
    fn reconcile(
        &mut self,
        _sources: &[DiscoveredLogSource],
        _observed_at_utc: &str,
    ) -> EspTailEvidenceBatch {
        self.reconciles.fetch_add(1, Ordering::SeqCst);
        EspTailEvidenceBatch::default()
    }

    fn poll(&mut self, _observed_at_utc: &str) -> EspTailEvidenceBatch {
        self.queued
            .lock()
            .expect("tail queue")
            .pop_front()
            .unwrap_or_default()
    }

    fn stop(&mut self) {
        self.stops.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Default)]
struct RecordingSessionSink {
    updates: Arc<Mutex<Vec<app_lib::esp::session::EspSessionUpdate>>>,
}

#[derive(Default)]
struct ReentrantSessionSink {
    manager: Mutex<Option<Weak<EspSessionManager>>>,
    callbacks: Mutex<Vec<bool>>,
}

impl EspSessionEventSink for ReentrantSessionSink {
    fn emit(&self, update: app_lib::esp::session::EspSessionUpdate) -> Result<(), String> {
        let manager = self
            .manager
            .lock()
            .map_err(|error| error.to_string())?
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| "session manager unavailable".to_string())?;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let _ = sender.send(manager.get(&update.session_id));
        });
        let completed_without_waiting_for_emit =
            receiver.recv_timeout(Duration::from_millis(250)).is_ok();
        self.callbacks
            .lock()
            .map_err(|error| error.to_string())?
            .push(completed_without_waiting_for_emit);
        Ok(())
    }
}

impl EspSessionEventSink for RecordingSessionSink {
    fn emit(&self, update: app_lib::esp::session::EspSessionUpdate) -> Result<(), String> {
        self.updates.lock().expect("session updates").push(update);
        Ok(())
    }
}

fn session_system_record(
    artifact_id: &str,
    evidence_id: &str,
    observed_at_utc: &str,
) -> EspEvidenceRecord {
    let evidence_ref = EspEvidenceRef {
        evidence_id: evidence_id.to_string(),
        source_artifact_id: artifact_id.to_string(),
    };
    EspEvidenceRecord::System(EspSystemObservation {
        context: EspObservationContext {
            evidence_ref: evidence_ref.clone(),
            provenance: EspEvidenceProvenance {
                source_kind: EspSourceKind::System,
                source_artifact_id: artifact_id.to_string(),
                file_path: None,
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: observed_at_utc.to_string(),
            sensitivity: EspSensitivity::Public,
            parse_state: EspParseState::Parsed,
            access_state: EspSourceAccessState::Available,
        },
        fact: EspSystemFact::Hostname(evidence_ref.evidence_id),
    })
}

fn session_graph_record(observed_at_utc: &str) -> EspEvidenceRecord {
    let evidence_ref = EspEvidenceRef {
        evidence_id: "forbidden-local-graph".to_string(),
        source_artifact_id: "graph.managed-device".to_string(),
    };
    EspEvidenceRecord::Graph(EspGraphObservation {
        context: EspObservationContext {
            evidence_ref: evidence_ref.clone(),
            provenance: EspEvidenceProvenance {
                source_kind: EspSourceKind::Graph,
                source_artifact_id: evidence_ref.source_artifact_id.clone(),
                file_path: None,
                line_number: None,
                record_number: None,
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: observed_at_utc.to_string(),
            sensitivity: EspSensitivity::Public,
            parse_state: EspParseState::Parsed,
            access_state: EspSourceAccessState::Available,
        },
        section: EspGraphObservationSection::ManagedDevice,
        api_version: GraphApiVersion::V1_0,
        record_id: "managed-device-id".to_string(),
        display_name: Some("Graph-only name".to_string()),
        status: None,
    })
}

fn session_coverage(artifact_id: &str, status: EspArtifactStatus) -> EspArtifactCoverage {
    EspArtifactCoverage {
        artifact_id: artifact_id.to_string(),
        family: "test-source".to_string(),
        status,
        detail: Some("partial source evidence".to_string()),
        observed_at_utc: "2026-07-16T06:30:00Z".to_string(),
        evidence: vec![],
    }
}

fn session_dependencies(
    clock: Arc<ManualSessionClock>,
    registry: FakeSessionProvider,
    discovery: FakeSessionDiscovery,
    tails: FakeSessionTailFactory,
    sink: RecordingSessionSink,
) -> EspSessionDependencies {
    EspSessionDependencies::new(
        clock,
        Arc::new(registry),
        Arc::new(FakeSessionProvider::available("event")),
        Arc::new(FakeSessionProvider::available("system")),
        Arc::new(FakeSessionProvider::available("process")),
        Arc::new(discovery),
        Arc::new(tails),
        Arc::new(sink),
    )
    .with_live_supported_for_tests(true)
}

fn wait_for_session_updates(sink: &RecordingSessionSink, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while sink.updates.lock().expect("session updates").len() < count {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for update {count}"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn session_enforces_one_live_owner_debounces_and_emits_monotonic_sequences() {
    let clock = Arc::new(ManualSessionClock::default());
    let discovery = FakeSessionDiscovery::default();
    let tails = FakeSessionTailFactory::default();
    let sink = RecordingSessionSink::default();
    let manager = EspSessionManager::new(session_dependencies(
        Arc::clone(&clock),
        FakeSessionProvider::available("registry"),
        discovery,
        tails.clone(),
        sink.clone(),
    ));

    let initial = manager
        .start("11111111-1111-4111-8111-111111111111")
        .expect("start session");
    assert_eq!(initial.request_id, "11111111-1111-4111-8111-111111111111");
    assert_eq!(initial.sequence, 1);
    assert_eq!(initial.state, EspSessionState::Live);
    assert!(initial.snapshot.graph.is_none());
    assert_eq!(tails.reconciles.load(Ordering::SeqCst), 1);

    let conflict = manager
        .start("22222222-2222-4222-8222-222222222222")
        .expect_err("second live session must conflict");
    assert_eq!(
        conflict,
        EspSessionError::SessionConflict {
            existing_session_id: initial.session_id.clone(),
        }
    );

    tails
        .queued
        .lock()
        .expect("tail queue")
        .push_back(EspTailEvidenceBatch {
            records: vec![session_system_record(
                "tail-source",
                "tail-update-1",
                "2026-07-16T06:30:01Z",
            )],
            ..EspTailEvidenceBatch::default()
        });
    clock.advance(Duration::from_millis(50));
    thread::sleep(Duration::from_millis(20));
    assert!(sink.updates.lock().expect("session updates").is_empty());
    clock.advance(Duration::from_millis(199));
    thread::sleep(Duration::from_millis(20));
    assert!(sink.updates.lock().expect("session updates").is_empty());
    clock.advance(Duration::from_millis(1));
    wait_for_session_updates(&sink, 1);

    let update = sink.updates.lock().expect("session updates")[0].clone();
    assert_eq!(update.sequence, 2);
    assert_eq!(update.reason, EspUpdateReason::EvidenceChanged);
    assert!(update
        .snapshot
        .raw_evidence
        .iter()
        .any(|record| record.evidence[0].evidence_id == "tail-update-1"));

    let stopped = manager.stop(&initial.session_id).expect("stop and join");
    assert_eq!(stopped.state, EspSessionState::Stopped);
    assert_eq!(stopped.sequence, 3);
    wait_for_session_updates(&sink, 2);
    assert_eq!(
        sink.updates
            .lock()
            .expect("session updates")
            .iter()
            .map(|update| update.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(tails.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager.get(&initial.session_id),
        Err(EspSessionError::SessionNotFound)
    );
}

#[test]
fn session_refreshes_every_two_seconds_and_preserves_partial_source_coverage() {
    let clock = Arc::new(ManualSessionClock::default());
    let registry = FakeSessionProvider::available("registry").with_coverage(session_coverage(
        "registry-protected",
        EspArtifactStatus::PermissionDenied,
    ));
    let registry_calls = Arc::clone(&registry.calls);
    let discovery = FakeSessionDiscovery::default();
    let discovery_calls = Arc::clone(&discovery.calls);
    let tails = FakeSessionTailFactory::default();
    let sink = RecordingSessionSink::default();
    let manager = EspSessionManager::new(session_dependencies(
        Arc::clone(&clock),
        registry,
        discovery,
        tails,
        sink.clone(),
    ));

    let initial = manager
        .start("33333333-3333-4333-8333-333333333333")
        .expect("start session");
    assert_eq!(registry_calls.load(Ordering::SeqCst), 1);
    assert_eq!(discovery_calls.load(Ordering::SeqCst), 1);
    assert!(initial.snapshot.coverage.iter().any(|coverage| {
        coverage.artifact_id == "registry-protected"
            && coverage.status == EspArtifactStatus::PermissionDenied
    }));

    clock.advance(Duration::from_millis(1_999));
    thread::sleep(Duration::from_millis(20));
    assert_eq!(registry_calls.load(Ordering::SeqCst), 1);
    assert_eq!(discovery_calls.load(Ordering::SeqCst), 1);
    clock.advance(Duration::from_millis(1));
    wait_for_session_updates(&sink, 1);
    assert_eq!(registry_calls.load(Ordering::SeqCst), 2);
    assert_eq!(discovery_calls.load(Ordering::SeqCst), 2);
    assert_eq!(sink.updates.lock().expect("session updates")[0].sequence, 2);

    manager.stop(&initial.session_id).expect("stop session");
}

#[test]
fn session_expires_at_eight_hours_rejects_late_work_and_allows_a_new_owner() {
    let clock = Arc::new(ManualSessionClock::default());
    let tails = FakeSessionTailFactory::default();
    let sink = RecordingSessionSink::default();
    let manager = EspSessionManager::new(session_dependencies(
        Arc::clone(&clock),
        FakeSessionProvider::available("registry"),
        FakeSessionDiscovery::default(),
        tails.clone(),
        sink.clone(),
    ));
    let initial = manager
        .start("44444444-4444-4444-8444-444444444444")
        .expect("start session");

    clock.advance(MAX_SESSION_DURATION);
    wait_for_session_updates(&sink, 1);
    let expired = sink.updates.lock().expect("session updates")[0].clone();
    assert_eq!(expired.reason, EspUpdateReason::Expired);
    assert_eq!(expired.state, EspSessionState::Expired);
    assert_eq!(tails.stops.load(Ordering::SeqCst), 1);

    let replacement = manager
        .start("55555555-5555-4555-8555-555555555555")
        .expect("expired session must release ownership");
    assert_ne!(replacement.session_id, initial.session_id);
    manager
        .stop(&replacement.session_id)
        .expect("stop replacement");
    let emitted_after_stop = sink.updates.lock().expect("session updates").len();
    clock.advance(Duration::from_secs(10));
    thread::sleep(Duration::from_millis(20));
    assert_eq!(
        sink.updates.lock().expect("session updates").len(),
        emitted_after_stop,
        "joined sessions must reject callbacks after stop"
    );
}

#[test]
fn session_validates_ids_and_reports_typed_unsupported_platform() {
    let clock = Arc::new(ManualSessionClock::default());
    let dependencies = session_dependencies(
        clock,
        FakeSessionProvider::available("registry"),
        FakeSessionDiscovery::default(),
        FakeSessionTailFactory::default(),
        RecordingSessionSink::default(),
    )
    .with_live_supported_for_tests(false);
    let manager = EspSessionManager::new(dependencies);

    assert_eq!(
        manager.start("not-a-uuid"),
        Err(EspSessionError::InvalidRequestId)
    );
    assert_eq!(
        manager.start("66666666-6666-4666-8666-666666666666"),
        Err(EspSessionError::UnsupportedPlatform)
    );
}

#[test]
fn session_worker_panic_becomes_terminal_and_does_not_strand_ownership() {
    let clock = Arc::new(ManualSessionClock::default());
    let tails = FakeSessionTailFactory::default();
    let sink = RecordingSessionSink::default();
    let manager = EspSessionManager::new(session_dependencies(
        Arc::clone(&clock),
        FakeSessionProvider::available("registry").panics_on_call(2),
        FakeSessionDiscovery::default(),
        tails.clone(),
        sink.clone(),
    ));
    let initial = manager
        .start("77777777-7777-4777-8777-777777777777")
        .expect("start session");

    clock.advance(DISCOVERY_INTERVAL);
    wait_for_session_updates(&sink, 1);
    let failed = sink.updates.lock().expect("session updates")[0].clone();
    assert_eq!(failed.state, EspSessionState::Failed);
    assert_eq!(failed.reason, EspUpdateReason::Failed);
    assert_eq!(tails.stops.load(Ordering::SeqCst), 1);

    let replacement = manager
        .start("88888888-8888-4888-8888-888888888888")
        .expect("failed worker must release ownership");
    assert_ne!(replacement.session_id, initial.session_id);
    manager
        .stop(&replacement.session_id)
        .expect("stop replacement");
}

#[test]
fn session_concurrent_stop_callers_never_observe_a_live_post_join_envelope() {
    let clock = Arc::new(ManualSessionClock::default());
    let manager = Arc::new(EspSessionManager::new(session_dependencies(
        clock,
        FakeSessionProvider::available("registry"),
        FakeSessionDiscovery::default(),
        FakeSessionTailFactory::default(),
        RecordingSessionSink::default(),
    )));
    let initial = manager
        .start("99999999-9999-4999-8999-999999999999")
        .expect("start session");
    let barrier = Arc::new(Barrier::new(3));
    let callers = (0..2)
        .map(|_| {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            let session_id = initial.session_id.clone();
            thread::spawn(move || {
                barrier.wait();
                manager.stop(&session_id)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = callers
        .into_iter()
        .map(|caller| caller.join().expect("stop caller"))
        .collect::<Vec<_>>();

    assert!(results.iter().any(|result| {
        matches!(result, Ok(envelope) if envelope.state == EspSessionState::Stopped)
    }));
    assert!(results.iter().all(|result| {
        matches!(
            result,
            Ok(envelope) if envelope.state == EspSessionState::Stopped
        ) || matches!(result, Err(EspSessionError::SessionNotFound))
    }));
}

#[test]
fn session_rejects_graph_records_from_every_local_provider_and_tail_batch() {
    let clock = Arc::new(ManualSessionClock::default());
    let tails = FakeSessionTailFactory::default();
    let sink = RecordingSessionSink::default();
    let graph_provider = Arc::new(StaticSessionProvider {
        records: vec![session_graph_record("2026-07-16T06:30:00Z")],
    });
    let dependencies = EspSessionDependencies::new(
        Arc::clone(&clock) as Arc<dyn EspSessionClock>,
        graph_provider.clone(),
        graph_provider.clone(),
        graph_provider.clone(),
        graph_provider,
        Arc::new(FakeSessionDiscovery::default()),
        Arc::new(tails.clone()),
        Arc::new(sink.clone()),
    )
    .with_live_supported_for_tests(true);
    let manager = EspSessionManager::new(dependencies);

    let initial = manager
        .start("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
        .expect("start local-only session");
    assert!(initial.snapshot.graph.is_none());
    assert!(initial
        .snapshot
        .raw_evidence
        .iter()
        .all(|record| record.provenance.source_kind != EspSourceKind::Graph));

    tails
        .queued
        .lock()
        .expect("tail queue")
        .push_back(EspTailEvidenceBatch {
            records: vec![session_graph_record("2026-07-16T06:30:01Z")],
            ..EspTailEvidenceBatch::default()
        });
    clock.advance(UPDATE_DEBOUNCE);
    thread::sleep(Duration::from_millis(20));
    assert!(sink.updates.lock().expect("session updates").is_empty());
    let current = manager.get(&initial.session_id).expect("current session");
    assert!(current.snapshot.graph.is_none());
    assert!(current
        .snapshot
        .raw_evidence
        .iter()
        .all(|record| record.provenance.source_kind != EspSourceKind::Graph));

    manager.stop(&initial.session_id).expect("stop session");
}

#[test]
fn session_upserts_tail_coverage_by_artifact_instead_of_growing_duplicates() {
    let clock = Arc::new(ManualSessionClock::default());
    let tails = FakeSessionTailFactory::default();
    let sink = RecordingSessionSink::default();
    let manager = EspSessionManager::new(session_dependencies(
        Arc::clone(&clock),
        FakeSessionProvider::available("registry"),
        FakeSessionDiscovery::default(),
        tails.clone(),
        sink.clone(),
    ));
    let initial = manager
        .start("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
        .expect("start session");

    for status in [EspArtifactStatus::Missing, EspArtifactStatus::Available] {
        tails
            .queued
            .lock()
            .expect("tail queue")
            .push_back(EspTailEvidenceBatch {
                coverage: vec![session_coverage("tail.same-source", status)],
                ..EspTailEvidenceBatch::default()
            });
        clock.advance(UPDATE_DEBOUNCE);
        let expected = sink.updates.lock().expect("session updates").len() + 1;
        wait_for_session_updates(&sink, expected);
    }

    let update = sink
        .updates
        .lock()
        .expect("session updates")
        .last()
        .cloned()
        .expect("latest update");
    let matching = update
        .snapshot
        .coverage
        .iter()
        .filter(|coverage| coverage.artifact_id == "tail.same-source")
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1);
    assert_eq!(matching[0].status, EspArtifactStatus::Available);

    manager.stop(&initial.session_id).expect("stop session");
}

#[test]
fn session_does_not_hold_the_control_lock_during_provider_io() {
    let clock = Arc::new(ManualSessionClock::default());
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let blocking = Arc::new(BlockingSessionProvider {
        calls: Arc::new(AtomicUsize::new(0)),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    let manager = Arc::new(EspSessionManager::new(
        EspSessionDependencies::new(
            clock,
            blocking,
            Arc::new(FakeSessionProvider::available("event")),
            Arc::new(FakeSessionProvider::available("system")),
            Arc::new(FakeSessionProvider::available("process")),
            Arc::new(FakeSessionDiscovery::default()),
            Arc::new(FakeSessionTailFactory::default()),
            Arc::new(RecordingSessionSink::default()),
        )
        .with_live_supported_for_tests(true),
    ));

    let starter = {
        let manager = Arc::clone(&manager);
        thread::spawn(move || manager.start("cccccccc-cccc-4ccc-8ccc-cccccccccccc"))
    };
    entered.wait();

    let (sender, receiver) = mpsc::channel();
    let contender = {
        let manager = Arc::clone(&manager);
        thread::spawn(move || {
            let result = manager.start("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
            let _ = sender.send(result);
        })
    };
    let conflict = receiver
        .recv_timeout(Duration::from_millis(250))
        .expect("session conflict must not wait for provider I/O")
        .expect_err("reserved session must conflict");
    assert!(matches!(conflict, EspSessionError::SessionConflict { .. }));

    release.wait();
    let started = starter
        .join()
        .expect("starter thread")
        .expect("first session");
    contender.join().expect("contender thread");
    manager.stop(&started.session_id).expect("stop session");
}

#[test]
fn session_does_not_hold_snapshot_or_control_locks_during_event_emission() {
    let clock = Arc::new(ManualSessionClock::default());
    let tails = FakeSessionTailFactory::default();
    let sink = Arc::new(ReentrantSessionSink::default());
    let dependencies = EspSessionDependencies::new(
        Arc::clone(&clock) as Arc<dyn EspSessionClock>,
        Arc::new(FakeSessionProvider::available("registry")),
        Arc::new(FakeSessionProvider::available("event")),
        Arc::new(FakeSessionProvider::available("system")),
        Arc::new(FakeSessionProvider::available("process")),
        Arc::new(FakeSessionDiscovery::default()),
        Arc::new(tails.clone()),
        sink.clone(),
    )
    .with_live_supported_for_tests(true);
    let manager = Arc::new(EspSessionManager::new(dependencies));
    *sink.manager.lock().expect("sink manager") = Some(Arc::downgrade(&manager));
    let initial = manager
        .start("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee")
        .expect("start session");

    tails
        .queued
        .lock()
        .expect("tail queue")
        .push_back(EspTailEvidenceBatch {
            records: vec![session_system_record(
                "tail-source",
                "reentrant-emission",
                "2026-07-16T06:30:01Z",
            )],
            ..EspTailEvidenceBatch::default()
        });
    clock.advance(UPDATE_DEBOUNCE);
    let deadline = Instant::now() + Duration::from_secs(2);
    while sink.callbacks.lock().expect("callbacks").is_empty() {
        assert!(Instant::now() < deadline, "timed out waiting for callback");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(*sink.callbacks.lock().expect("callbacks"), vec![true]);

    manager.stop(&initial.session_id).expect("stop session");
}

#[test]
fn session_shutdown_cancels_joins_and_rejects_late_callbacks() {
    let clock = Arc::new(ManualSessionClock::default());
    let tails = FakeSessionTailFactory::default();
    let sink = RecordingSessionSink::default();
    let manager = EspSessionManager::new(session_dependencies(
        Arc::clone(&clock),
        FakeSessionProvider::available("registry"),
        FakeSessionDiscovery::default(),
        tails.clone(),
        sink.clone(),
    ));
    let initial = manager
        .start("ffffffff-ffff-4fff-8fff-ffffffffffff")
        .expect("start session");

    manager.shutdown().expect("shutdown session manager");
    assert_eq!(tails.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        manager.get(&initial.session_id),
        Err(EspSessionError::SessionNotFound)
    );
    let emitted = sink.updates.lock().expect("updates").len();
    clock.advance(Duration::from_secs(10));
    thread::sleep(Duration::from_millis(20));
    assert_eq!(sink.updates.lock().expect("updates").len(), emitted);
}

#[test]
fn live_session_adapters_preserve_native_records_coverage_and_tail_reset_identity() {
    let observed_at_utc = "2026-07-16T06:30:00Z";
    let registry = collect_registry_evidence(
        &FakeRegistryProvider::default().with_tree(
            ESP_REGISTRY_TARGETS[0].key,
            vec![snapshot_key(
                "",
                vec![RegistryValueSnapshot::text(
                    "CloudAssignedTenantDomain",
                    "contoso.com",
                )],
            )],
        ),
        &[],
        observed_at_utc,
    );
    let registry_batch = registry_evidence_to_batch(registry, observed_at_utc);
    assert!(registry_batch
        .records
        .iter()
        .any(|record| matches!(record, EspEvidenceRecord::Registry(_))));
    assert!(registry_batch.coverage.iter().any(|coverage| {
        coverage.status == EspArtifactStatus::Available
            && coverage.artifact_id.contains(ESP_REGISTRY_TARGETS[0].key)
    }));
    assert!(registry_batch
        .coverage
        .iter()
        .any(|coverage| coverage.status == EspArtifactStatus::Missing));

    let events = collect_event_evidence(
        &FakeEventLogProvider::default().with_records(
            ESP_EVENT_CHANNELS[0],
            vec![parsed_event(
                ESP_EVENT_CHANNELS[0],
                109,
                1,
                vec![EventLogProperty {
                    name: "Status".to_string(),
                    value: "0".to_string(),
                }],
            )],
        ),
        observed_at_utc,
    );
    let event_batch = event_evidence_to_batch(events, observed_at_utc);
    assert!(event_batch
        .records
        .iter()
        .any(|record| matches!(record, EspEvidenceRecord::EventLog(_))));
    assert!(event_batch.coverage.iter().any(|coverage| {
        coverage.artifact_id.contains(ESP_EVENT_CHANNELS[0])
            && coverage.status == EspArtifactStatus::Available
    }));

    let missing_root = tempdir().expect("temp root").path().join("missing");
    let discovery = discover_bounded_logs(&DiscoveryInput {
        known_sources: vec![],
        temp_roots: vec![missing_root],
        active_process_logs: vec![],
        now: SystemTime::now(),
    });
    let discovery_batch = discovery_result_to_batch(discovery, observed_at_utc);
    assert!(discovery_batch.sources.is_empty());
    assert_eq!(discovery_batch.coverage.len(), 1);
    assert_eq!(
        discovery_batch.coverage[0].status,
        EspArtifactStatus::Missing
    );

    let root = tempdir().expect("tail root");
    let path = root.path().join("AppWorkload.log");
    fs::write(
        &path,
        "<![LOG[Initial app evidence]LOG]!><time=\"10:00:00.000+000\" date=\"07-16-2026\" component=\"AppWorkload\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n",
    )
    .expect("write initial tail");
    let source = tail_source(
        path.clone(),
        "ime-current",
        0,
        DiscoverySourceOrigin::EmbeddedKnown,
        true,
    );
    let mut tails = EspTailSet::new();
    let initial_batch = tail_reconcile_to_batch(tails.reconcile(&[source]), observed_at_utc);
    assert_eq!(initial_batch.records.len(), 1);
    let artifact_id = initial_batch
        .records
        .first()
        .and_then(record_artifact_for_test)
        .expect("tail artifact")
        .to_string();

    fs::rename(&path, root.path().join("AppWorkload.log.1")).expect("rotate tail");
    fs::write(
        &path,
        "<![LOG[Replacement app evidence]LOG]!><time=\"10:01:00.000+000\" date=\"07-16-2026\" component=\"AppWorkload\" context=\"\" type=\"1\" thread=\"1\" file=\"\">\n",
    )
    .expect("replace tail");
    let reset_batch = tail_poll_to_batch(tails.poll(), observed_at_utc);
    assert_eq!(reset_batch.replace_artifact_ids, vec![artifact_id]);
    assert_eq!(reset_batch.records.len(), 1);
}

#[test]
fn live_session_system_adapter_preserves_delivery_counters_without_transfer_events() {
    let observed_at_utc = "2026-07-16T06:30:00Z";
    let summary = delivery_optimization_from_rows(
        &[SystemRow::new([
            ("DownloadHttpBytes", "1000"),
            ("DownloadLanBytes", "250"),
            ("DownloadCacheHostBytes", "500"),
        ])],
        observed_at_utc,
    )
    .expect("Delivery Optimization counters");
    let batch = app_lib::esp::live_session::system_evidence_to_batch(
        SystemEvidence {
            elevation: EspElevationState {
                is_elevated: false,
                restart_supported: true,
                restricted_sources: Vec::new(),
            },
            hostname: None,
            hardware: EspHardwareEvidence {
                os_version: None,
                os_build: None,
                manufacturer: None,
                model: None,
                serial_number: None,
                tpm_version: None,
                evidence: Vec::new(),
            },
            ime_service: None,
            delivery_optimization: Some(summary),
            delivery_optimization_observations: Vec::new(),
            observations: Vec::new(),
            coverage: Vec::new(),
        },
        observed_at_utc,
    );
    let mut reducer = EspDiagnosticsReducer::new(observed_at_utc.to_string());
    reducer.ingest_all(batch.records);
    let snapshot = reducer.snapshot();
    let delivery = snapshot
        .delivery_optimization
        .expect("counter-only Delivery Optimization evidence");
    assert_eq!(delivery.download_http_bytes, 1000);
    assert_eq!(delivery.download_lan_bytes, 250);
    assert_eq!(delivery.download_cache_host_bytes, 500);
    assert_eq!(delivery.peer_share_percent, Some(25.0));
    assert_eq!(delivery.connected_cache_share_percent, Some(50.0));
    assert!(delivery.transfers.is_empty());
}

fn record_artifact_for_test(record: &EspEvidenceRecord) -> Option<&str> {
    match record {
        EspEvidenceRecord::Ime(value) => Some(&value.context.provenance.source_artifact_id),
        EspEvidenceRecord::DeploymentLog(value) => {
            Some(&value.context.provenance.source_artifact_id)
        }
        _ => None,
    }
}

#[derive(Clone)]
struct FakeRelaunchProvider {
    supported: bool,
    elevated: Result<bool, String>,
    executable: Result<PathBuf, String>,
    arguments: Vec<String>,
    launch_result: Result<(), app_lib::esp::relaunch::EspElevationLaunchError>,
    requests: Arc<Mutex<Vec<app_lib::esp::relaunch::EspRelaunchRequest>>>,
}

impl app_lib::esp::relaunch::EspRelaunchProvider for FakeRelaunchProvider {
    fn platform_supported(&self) -> bool {
        self.supported
    }

    fn is_elevated(&self) -> Result<bool, String> {
        self.elevated.clone()
    }

    fn current_executable(&self) -> Result<PathBuf, String> {
        self.executable.clone()
    }

    fn startup_arguments(&self) -> Vec<String> {
        self.arguments.clone()
    }

    fn launch_elevated(
        &self,
        request: &app_lib::esp::relaunch::EspRelaunchRequest,
    ) -> Result<(), app_lib::esp::relaunch::EspElevationLaunchError> {
        self.requests.lock().unwrap().push(request.clone());
        self.launch_result.clone()
    }
}

fn fake_relauncher() -> FakeRelaunchProvider {
    FakeRelaunchProvider {
        supported: true,
        elevated: Ok(false),
        executable: Ok(PathBuf::from(
            r"C:\Program Files\CMTrace Open\cmtrace-open.exe",
        )),
        arguments: Vec::new(),
        launch_result: Ok(()),
        requests: Arc::new(Mutex::new(Vec::new())),
    }
}

#[test]
fn relaunch_already_elevated_never_starts_a_child() {
    let provider = FakeRelaunchProvider {
        elevated: Ok(true),
        ..fake_relauncher()
    };
    let result = app_lib::esp::relaunch::restart_with_provider(&provider).unwrap();
    assert!(!result.launched);
    assert_eq!(
        result.reason,
        app_lib::esp::relaunch::EspRelaunchReason::AlreadyElevated
    );
    assert!(provider.requests.lock().unwrap().is_empty());
}

#[test]
fn relaunch_uses_runas_and_forwards_only_the_canonical_workspace_flag() {
    let provider = FakeRelaunchProvider {
        arguments: vec![
            "--workspace".to_string(),
            "esp-diagnostics".to_string(),
            "--unknown-flag".to_string(),
            r"C:\Users\Person\Desktop\evidence.zip".to_string(),
        ],
        ..fake_relauncher()
    };
    let result = app_lib::esp::relaunch::restart_with_provider(&provider).unwrap();
    assert!(result.launched);
    assert_eq!(
        result.reason,
        app_lib::esp::relaunch::EspRelaunchReason::Launched
    );
    let requests = provider.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].verb, "runas");
    assert_eq!(requests[0].arguments, vec!["--workspace=esp-diagnostics"]);
    assert_eq!(requests[0].parameters, "--workspace=esp-diagnostics");
    assert!(requests[0].close_process_handle);
}

#[test]
fn relaunch_rejects_nul_and_secret_bearing_arguments_without_echoing_them() {
    for unsafe_argument in [
        "--workspace=esp-diagnostics\0ignored",
        "--access-token=secret",
    ] {
        let provider = FakeRelaunchProvider {
            arguments: vec![unsafe_argument.to_string()],
            ..fake_relauncher()
        };
        let error = app_lib::esp::relaunch::restart_with_provider(&provider).unwrap_err();
        assert_eq!(
            error,
            app_lib::esp::relaunch::EspRelaunchError::UnsafeArgument
        );
        assert!(!error.to_string().contains(unsafe_argument));
        assert!(provider.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn relaunch_cancel_failure_and_unsupported_are_typed_without_false_success() {
    let cancelled = FakeRelaunchProvider {
        launch_result: Err(app_lib::esp::relaunch::EspElevationLaunchError::Cancelled),
        ..fake_relauncher()
    };
    let cancelled_result = app_lib::esp::relaunch::restart_with_provider(&cancelled).unwrap();
    assert_eq!(
        cancelled_result.reason,
        app_lib::esp::relaunch::EspRelaunchReason::ElevationCancelled
    );
    assert!(!cancelled_result.launched);

    let failed = FakeRelaunchProvider {
        launch_result: Err(app_lib::esp::relaunch::EspElevationLaunchError::Failed(
            "ShellExecuteExW failed".to_string(),
        )),
        ..fake_relauncher()
    };
    assert!(matches!(
        app_lib::esp::relaunch::restart_with_provider(&failed),
        Err(app_lib::esp::relaunch::EspRelaunchError::LaunchFailed { .. })
    ));

    let unsupported = FakeRelaunchProvider {
        supported: false,
        elevated: Err("must not probe".to_string()),
        ..fake_relauncher()
    };
    let unsupported_result = app_lib::esp::relaunch::restart_with_provider(&unsupported).unwrap();
    assert_eq!(
        unsupported_result.reason,
        app_lib::esp::relaunch::EspRelaunchReason::UnsupportedPlatform
    );
    assert!(!unsupported_result.launched);
    assert!(unsupported.requests.lock().unwrap().is_empty());
}

#[test]
fn relaunch_windows_argument_quoting_handles_spaces_quotes_and_backslashes() {
    assert_eq!(
        app_lib::esp::relaunch::build_windows_parameter_line(&[
            "plain".to_string(),
            "two words".to_string(),
            "quote\"inside".to_string(),
            r"trailing\".to_string(),
        ]),
        r#"plain "two words" "quote\"inside" trailing\"#
    );
}
fn write_test_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).expect("create ZIP fixture");
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, content) in entries {
        writer
            .start_file(*name, options)
            .expect("start ZIP fixture entry");
        writer.write_all(content).expect("write ZIP fixture entry");
    }
    writer.finish().expect("finish ZIP fixture");
}

fn write_test_cab(path: &Path, entries: &[(&str, &[u8])]) {
    let mut builder = cab::CabinetBuilder::new();
    {
        let folder = builder.add_folder(cab::CompressionType::MsZip);
        for (name, _) in entries {
            folder.add_file(*name);
        }
    }
    let file = File::create(path).expect("create CAB fixture");
    let mut writer = builder.build(file).expect("start CAB fixture");
    while let Some(mut entry) = writer.next_file().expect("next CAB fixture entry") {
        let content = entries
            .iter()
            .find(|(name, _)| *name == entry.file_name())
            .map(|(_, content)| *content)
            .expect("CAB fixture content");
        entry.write_all(content).expect("write CAB fixture entry");
    }
    writer.finish().expect("finish CAB fixture");
}

fn find_last_signature(bytes: &[u8], signature: [u8; 4]) -> usize {
    bytes
        .windows(signature.len())
        .rposition(|window| window == signature)
        .expect("fixture signature")
}

fn patch_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 fixture"))
}

fn append_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn cab_file_header_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut offset = read_u32(bytes, 16) as usize;
    let file_count = u16::from_le_bytes(bytes[28..30].try_into().expect("CAB file count"));
    let mut offsets = Vec::with_capacity(file_count as usize);
    for _ in 0..file_count {
        offsets.push(offset);
        let name_start = offset + 16;
        let name_len = bytes[name_start..]
            .iter()
            .position(|byte| *byte == 0)
            .expect("CAB filename terminator");
        offset = name_start + name_len + 1;
    }
    offsets
}

#[test]
fn archive_preflights_classic_zip_entry_count_before_constructing_the_parser() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("too-many-classic.zip");
    write_test_zip(&archive_path, &[("logs/one.log", b"one")]);

    let mut bytes = std::fs::read(&archive_path).expect("read ZIP fixture");
    let eocd = find_last_signature(&bytes, [0x50, 0x4b, 0x05, 0x06]);
    patch_u16(&mut bytes, eocd + 8, (MAX_ARCHIVE_ENTRIES + 1) as u16);
    patch_u16(&mut bytes, eocd + 10, (MAX_ARCHIVE_ENTRIES + 1) as u16);
    std::fs::write(&archive_path, bytes).expect("patch ZIP fixture");

    assert!(matches!(
        extract_captured_archive(&archive_path),
        Err(ArchiveError::EntryCountExceeded {
            count,
            maximum: MAX_ARCHIVE_ENTRIES,
        }) if count == MAX_ARCHIVE_ENTRIES + 1
    ));
}

#[test]
fn archive_preflights_zip64_entry_count_before_constructing_the_parser() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("too-many-zip64.zip");
    write_test_zip(&archive_path, &[("logs/one.log", b"one")]);

    let original = std::fs::read(&archive_path).expect("read ZIP fixture");
    let eocd = find_last_signature(&original, [0x50, 0x4b, 0x05, 0x06]);
    let mut bytes = original[..eocd].to_vec();
    let zip64_eocd_offset = bytes.len() as u64;
    append_u32(&mut bytes, 0x0606_4b50);
    append_u64(&mut bytes, 44);
    append_u16(&mut bytes, 45);
    append_u16(&mut bytes, 45);
    append_u32(&mut bytes, 0);
    append_u32(&mut bytes, 0);
    append_u64(&mut bytes, (MAX_ARCHIVE_ENTRIES + 1) as u64);
    append_u64(&mut bytes, (MAX_ARCHIVE_ENTRIES + 1) as u64);
    append_u64(&mut bytes, read_u32(&original, eocd + 12) as u64);
    append_u64(&mut bytes, read_u32(&original, eocd + 16) as u64);
    append_u32(&mut bytes, 0x0706_4b50);
    append_u32(&mut bytes, 0);
    append_u64(&mut bytes, zip64_eocd_offset);
    append_u32(&mut bytes, 1);
    let classic_eocd = bytes.len();
    bytes.extend_from_slice(&original[eocd..]);
    patch_u16(&mut bytes, classic_eocd + 8, u16::MAX);
    patch_u16(&mut bytes, classic_eocd + 10, u16::MAX);
    std::fs::write(&archive_path, bytes).expect("patch ZIP64 fixture");

    assert!(matches!(
        extract_captured_archive(&archive_path),
        Err(ArchiveError::EntryCountExceeded {
            count,
            maximum: MAX_ARCHIVE_ENTRIES,
        }) if count == MAX_ARCHIVE_ENTRIES + 1
    ));
}

#[test]
fn archive_preflights_zip64_count_when_classic_offset_is_sentinel() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("too-many-offset-sentinel.zip");
    let names = (0..=MAX_ARCHIVE_ENTRIES)
        .map(|index| format!("logs/{index:03}.log"))
        .collect::<Vec<_>>();
    let entries = names
        .iter()
        .map(|name| (name.as_str(), b"".as_slice()))
        .collect::<Vec<_>>();
    write_test_zip(&archive_path, &entries);

    let mut original = std::fs::read(&archive_path).expect("read ZIP fixture");
    let eocd = find_last_signature(&original, [0x50, 0x4b, 0x05, 0x06]);

    // Make reaching ZipArchive::new observable: a correct preflight must reject
    // the ZIP64 count before the parser encounters this malformed final entry.
    let mut central = read_u32(&original, eocd + 16) as usize;
    for _ in 0..MAX_ARCHIVE_ENTRIES {
        let name_len = u16::from_le_bytes(
            original[central + 28..central + 30]
                .try_into()
                .expect("central name length"),
        );
        let extra_len = u16::from_le_bytes(
            original[central + 30..central + 32]
                .try_into()
                .expect("central extra length"),
        );
        let comment_len = u16::from_le_bytes(
            original[central + 32..central + 34]
                .try_into()
                .expect("central comment length"),
        );
        central += 46 + usize::from(name_len) + usize::from(extra_len) + usize::from(comment_len);
    }
    original[central..central + 4].copy_from_slice(b"BAD!");

    let mut bytes = original[..eocd].to_vec();
    let zip64_eocd_offset = bytes.len() as u64;
    append_u32(&mut bytes, 0x0606_4b50);
    append_u64(&mut bytes, 44);
    append_u16(&mut bytes, 45);
    append_u16(&mut bytes, 45);
    append_u32(&mut bytes, 0);
    append_u32(&mut bytes, 0);
    append_u64(&mut bytes, (MAX_ARCHIVE_ENTRIES + 1) as u64);
    append_u64(&mut bytes, (MAX_ARCHIVE_ENTRIES + 1) as u64);
    append_u64(&mut bytes, read_u32(&original, eocd + 12) as u64);
    append_u64(&mut bytes, read_u32(&original, eocd + 16) as u64);
    append_u32(&mut bytes, 0x0706_4b50);
    append_u32(&mut bytes, 0);
    append_u64(&mut bytes, zip64_eocd_offset);
    append_u32(&mut bytes, 1);
    let classic_eocd = bytes.len();
    bytes.extend_from_slice(&original[eocd..]);
    patch_u16(&mut bytes, classic_eocd + 8, 1);
    patch_u16(&mut bytes, classic_eocd + 10, 1);
    patch_u32(&mut bytes, classic_eocd + 16, u32::MAX);
    std::fs::write(&archive_path, bytes).expect("patch ZIP64 fixture");

    assert!(matches!(
        extract_captured_archive(&archive_path),
        Err(ArchiveError::EntryCountExceeded {
            count,
            maximum: MAX_ARCHIVE_ENTRIES,
        }) if count == MAX_ARCHIVE_ENTRIES + 1
    ));
}

#[test]
fn archive_preflights_cab_entry_count_before_constructing_the_parser() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("too-many.cab");
    write_test_cab(&archive_path, &[("logs/one.log", b"one")]);

    let mut bytes = std::fs::read(&archive_path).expect("read CAB fixture");
    patch_u16(&mut bytes, 28, (MAX_ARCHIVE_ENTRIES + 1) as u16);
    std::fs::write(&archive_path, bytes).expect("patch CAB fixture");

    assert!(matches!(
        extract_captured_archive(&archive_path),
        Err(ArchiveError::EntryCountExceeded {
            count,
            maximum: MAX_ARCHIVE_ENTRIES,
        }) if count == MAX_ARCHIVE_ENTRIES + 1
    ));
}

#[test]
fn archive_rejects_cab_entry_with_uninterruptible_preseek_work() {
    const MAX_CAB_ENTRY_PRESEEK_BYTES: u32 = 64 * 1024 * 1024;

    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("preseek-amplification.cab");
    write_test_cab(&archive_path, &[("logs/evidence.log", b"evidence")]);

    let mut bytes = std::fs::read(&archive_path).expect("read CAB fixture");
    let file_header = cab_file_header_offsets(&bytes)[0];
    patch_u32(&mut bytes, file_header + 4, MAX_CAB_ENTRY_PRESEEK_BYTES + 1);
    std::fs::write(&archive_path, bytes).expect("patch CAB fixture");

    assert!(matches!(
        extract_captured_archive(&archive_path),
        Err(ArchiveError::InvalidEvidence { detail })
            if detail.contains("CAB pre-seek work exceeds")
    ));
}

#[test]
fn archive_rejects_cab_cumulative_restart_decompression_amplification() {
    const MAX_CAB_ENTRY_PRESEEK_BYTES: u32 = 64 * 1024 * 1024;
    const ENTRY_COUNT: usize = 17;

    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("cumulative-amplification.cab");
    let names = (0..ENTRY_COUNT)
        .map(|index| format!("logs/{index}.log"))
        .collect::<Vec<_>>();
    let entries = names
        .iter()
        .map(|name| (name.as_str(), b"x".as_slice()))
        .collect::<Vec<_>>();
    write_test_cab(&archive_path, &entries);

    let mut bytes = std::fs::read(&archive_path).expect("read CAB fixture");
    for file_header in cab_file_header_offsets(&bytes) {
        patch_u32(&mut bytes, file_header + 4, MAX_CAB_ENTRY_PRESEEK_BYTES);
    }
    std::fs::write(&archive_path, bytes).expect("patch CAB fixture");

    let result = extract_captured_archive(&archive_path);
    assert!(
        matches!(
            &result,
            Err(ArchiveError::InvalidEvidence { detail })
                if detail.contains("CAB cumulative decode work exceeds")
        ),
        "unexpected CAB amplification result: {result:?}"
    );
}

#[test]
fn archive_zip_extracts_only_allowlisted_evidence_and_parses_registry_in_place() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("captured.zip");
    let registry_text = r#"Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Contoso]
"Status"="Ready"
"#;
    let mut registry = vec![0xff, 0xfe];
    registry.extend(registry_text.encode_utf16().flat_map(u16::to_le_bytes));
    write_test_zip(
        &archive_path,
        &[
            ("evidence/registry/device.reg", registry.as_slice()),
            (
                "evidence/logs/IntuneManagementExtension.log",
                b"IME evidence",
            ),
            ("payload/installer.exe", b"not evidence"),
        ],
    );

    let extracted = extract_captured_archive(&archive_path).expect("extract safe ZIP");

    assert_eq!(extracted.format(), ArchiveFormat::Zip);
    assert_eq!(
        extracted
            .files()
            .iter()
            .map(|file| file.relative_path.to_string_lossy().replace('\\', "/"))
            .collect::<Vec<_>>(),
        vec![
            "evidence/logs/IntuneManagementExtension.log",
            "evidence/registry/device.reg",
        ]
    );
    assert!(!extracted.root().join("payload/installer.exe").exists());
    let registry_exports = extracted
        .parse_registry_exports()
        .expect("parse extracted registry evidence");
    assert_eq!(registry_exports.len(), 1);
    assert_eq!(registry_exports[0].total_keys, 1);
    assert_eq!(registry_exports[0].total_values, 1);

    let extraction_root = extracted.root().to_path_buf();
    assert!(extraction_root.exists());
    drop(extracted);
    assert!(
        !extraction_root.exists(),
        "successful extraction must clean on drop"
    );

    let source_code = include_str!("../src/esp/archive.rs").to_ascii_lowercase();
    assert!(!source_code.contains("reg.exe import"));
    assert!(!source_code.contains("reg import"));
}

#[test]
fn archive_parses_utf8_utf16be_and_windows1252_registry_exports() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("registry-encodings.zip");

    let utf8_text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Utf8]\r\n\"Status\"=\"Ready ✓\"\r\n";
    let utf16be_text = "Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Utf16Be]\r\n\"Status\"=\"Ready BE\"\r\n";
    let mut utf16be = vec![0xfe, 0xff];
    utf16be.extend(utf16be_text.encode_utf16().flat_map(u16::to_be_bytes));
    let windows1252 = b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Ansi]\r\n\"Status\"=\"Caf\xe9\"\r\n";

    write_test_zip(
        &archive_path,
        &[
            ("registry/utf8.reg", utf8_text.as_bytes()),
            ("registry/utf16be.reg", utf16be.as_slice()),
            ("registry/windows1252.reg", windows1252.as_slice()),
        ],
    );

    let extracted = extract_captured_archive(&archive_path).expect("extract registry encodings");
    let parsed = extracted
        .parse_registry_exports()
        .expect("parse registry encodings");
    assert_eq!(parsed.len(), 3);
    assert!(parsed.iter().all(|result| {
        result.total_keys == 1 && result.total_values == 1 && result.parse_errors == 0
    }));
    let values = parsed
        .iter()
        .map(|result| {
            (
                result.file_path.as_str(),
                result.keys[0].values[0].data.as_str(),
            )
        })
        .collect::<HashMap<_, _>>();
    assert_eq!(values["registry/utf8.reg"], "Ready ✓");
    assert_eq!(values["registry/utf16be.reg"], "Ready BE");
    assert_eq!(values["registry/windows1252.reg"], "Café");
}

#[test]
fn archive_cab_uses_the_same_bounded_allowlist_and_cleanup_contract() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("mdmdiagnostics.cab");
    write_test_cab(
        &archive_path,
        &[
            ("MDMDiagnostics/MDMDiagReport.xml", b"<report />"),
            (
                "MDMDiagnostics/DeviceManagement-Enterprise-Diagnostics-Provider.evtx",
                b"evtx",
            ),
            ("MDMDiagnostics/tool.dll", b"not evidence"),
        ],
    );

    let extracted = extract_captured_archive(&archive_path).expect("extract safe CAB");

    assert_eq!(extracted.format(), ArchiveFormat::Cab);
    assert_eq!(extracted.files().len(), 2);
    assert!(extracted.files().iter().all(|entry| {
        matches!(
            entry
                .relative_path
                .extension()
                .and_then(|value| value.to_str()),
            Some("xml" | "evtx")
        )
    }));
    let extraction_root = extracted.root().to_path_buf();
    drop(extracted);
    assert!(
        !extraction_root.exists(),
        "CAB extraction must clean on drop"
    );
}

#[test]
fn archive_cab_rejects_traversal_absolute_drive_unc_and_mixed_separators() {
    let source = tempfile::tempdir().expect("source tempdir");
    for (index, unsafe_name) in [
        "/absolute.log",
        "../parent.log",
        "C:/drive.log",
        r"\\server\share\unc.log",
        r"safe\..\mixed.log",
    ]
    .into_iter()
    .enumerate()
    {
        let archive_path = source.path().join(format!("unsafe-cab-{index}.cab"));
        write_test_cab(&archive_path, &[(unsafe_name, b"must not extract")]);
        let result = extract_captured_archive(&archive_path);
        assert!(
            matches!(result, Err(ArchiveError::UnsafeEntryPath { .. })),
            "unexpected CAB result for {unsafe_name}: {result:?}"
        );
    }
}

#[test]
fn archive_rejects_case_insensitive_duplicates_in_zip_and_cab() {
    let source = tempfile::tempdir().expect("source tempdir");
    let entries: [(&str, &[u8]); 2] =
        [("Logs/Evidence.log", b"one"), ("logs/evidence.LOG", b"two")];

    let zip_path = source.path().join("duplicates.zip");
    write_test_zip(&zip_path, &entries);
    assert!(matches!(
        extract_captured_archive(&zip_path),
        Err(ArchiveError::DuplicateEntry { .. })
    ));

    let cab_path = source.path().join("duplicates.cab");
    write_test_cab(&cab_path, &entries);
    assert!(matches!(
        extract_captured_archive(&cab_path),
        Err(ArchiveError::DuplicateEntry { .. })
    ));
}

#[test]
fn archive_rejects_cab_continuation_entries_as_special_files() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("continued.cab");
    write_test_cab(&archive_path, &[("logs/evidence.log", b"evidence")]);

    let mut bytes = std::fs::read(&archive_path).expect("read CAB fixture");
    let file_header = cab_file_header_offsets(&bytes)[0];
    patch_u16(&mut bytes, file_header + 8, 0xfffd);
    std::fs::write(&archive_path, bytes).expect("patch CAB fixture");

    assert!(matches!(
        extract_captured_archive(&archive_path),
        Err(ArchiveError::UnsupportedEntryType {
            kind: ArchiveEntryKind::Other,
            ..
        })
    ));
}

#[test]
fn archive_rejects_declared_sizes_that_exceed_produced_zip_and_cab_data() {
    let source = tempfile::tempdir().expect("source tempdir");

    let zip_path = source.path().join("declared-size.zip");
    write_test_zip(&zip_path, &[("logs/evidence.log", b"evidence")]);
    let mut zip_bytes = std::fs::read(&zip_path).expect("read ZIP fixture");
    let local = find_last_signature(&zip_bytes, [0x50, 0x4b, 0x03, 0x04]);
    let central = find_last_signature(&zip_bytes, [0x50, 0x4b, 0x01, 0x02]);
    patch_u32(&mut zip_bytes, local + 22, 9);
    patch_u32(&mut zip_bytes, central + 24, 9);
    std::fs::write(&zip_path, zip_bytes).expect("patch ZIP fixture");
    assert!(matches!(
        extract_captured_archive(&zip_path),
        Err(ArchiveError::InvalidEvidence { .. }) | Err(ArchiveError::InvalidArchive { .. })
    ));

    let cab_path = source.path().join("declared-size.cab");
    write_test_cab(&cab_path, &[("logs/evidence.log", b"evidence")]);
    let mut cab_bytes = std::fs::read(&cab_path).expect("read CAB fixture");
    let file_header = cab_file_header_offsets(&cab_bytes)[0];
    patch_u32(&mut cab_bytes, file_header, 9);
    std::fs::write(&cab_path, cab_bytes).expect("patch CAB fixture");
    assert!(matches!(
        extract_captured_archive(&cab_path),
        Err(ArchiveError::InvalidEvidence { detail })
            if detail.contains("declares range")
    ));
}

#[test]
fn archive_cab_preflight_cancellation_is_responsive_and_cleans() {
    let source = tempfile::tempdir().expect("source tempdir");
    let extraction_parent = tempfile::tempdir().expect("extraction parent");
    let archive_path = source.path().join("cancel-preflight.cab");
    write_test_cab(&archive_path, &[("logs/evidence.log", b"evidence")]);
    let checks = AtomicUsize::new(0);
    let cancelled = || checks.fetch_add(1, Ordering::SeqCst) >= 1;

    let result = extract_captured_archive_with_cancel_in(
        &archive_path,
        extraction_parent.path(),
        &cancelled,
    );
    assert_eq!(
        result.expect_err("cancel CAB preflight"),
        ArchiveError::Cancelled
    );
    assert_eq!(
        extraction_parent
            .path()
            .read_dir()
            .expect("list extraction parent")
            .count(),
        0
    );
}

#[test]
fn archive_rejects_absolute_parent_drive_unc_and_mixed_separator_escapes() {
    let source = tempfile::tempdir().expect("source tempdir");
    for (index, unsafe_name) in [
        "/absolute.log",
        "../parent.log",
        "C:/drive.log",
        r"\\server\share\unc.log",
        r"safe\..\mixed.log",
    ]
    .into_iter()
    .enumerate()
    {
        let archive_path = source.path().join(format!("unsafe-{index}.zip"));
        write_test_zip(&archive_path, &[(unsafe_name, b"must not extract")]);

        let error = extract_captured_archive(&archive_path).expect_err("reject unsafe path");
        assert!(
            matches!(error, ArchiveError::UnsafeEntryPath { .. }),
            "unexpected error for {unsafe_name}: {error:?}"
        );
    }
}

#[test]
fn archive_rejects_superscript_windows_device_names_in_zip_and_cab() {
    let source = tempfile::tempdir().expect("source tempdir");
    for (index, reserved_name) in [
        "COM¹.log",
        "COM².eVtX",
        "COM³.txt",
        "LPT¹.json",
        "LPT².xml",
        "LPT³.reg",
    ]
    .into_iter()
    .enumerate()
    {
        let zip_path = source.path().join(format!("reserved-{index}.zip"));
        write_test_zip(&zip_path, &[(reserved_name, b"must not extract")]);
        assert!(
            matches!(
                extract_captured_archive(&zip_path),
                Err(ArchiveError::UnsafeEntryPath { .. })
            ),
            "ZIP must reject Windows device name {reserved_name}"
        );

        let cab_path = source.path().join(format!("reserved-{index}.cab"));
        write_test_cab(&cab_path, &[(reserved_name, b"must not extract")]);
        assert!(
            matches!(
                extract_captured_archive(&cab_path),
                Err(ArchiveError::UnsafeEntryPath { .. })
            ),
            "CAB must reject Windows device name {reserved_name}"
        );
    }
}

#[test]
fn archive_rejects_zip_symlink_entries_before_materializing_any_evidence() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("symlink.zip");
    let file = File::create(&archive_path).expect("create symlink ZIP");
    let mut writer = zip::ZipWriter::new(file);
    writer
        .add_symlink(
            "evidence/link.log",
            "../../outside.log",
            zip::write::SimpleFileOptions::default(),
        )
        .expect("write symlink entry");
    writer.finish().expect("finish symlink ZIP");

    let error = extract_captured_archive(&archive_path).expect_err("reject symlink");
    assert!(matches!(
        error,
        ArchiveError::UnsupportedEntryType {
            kind: ArchiveEntryKind::Symlink,
            ..
        }
    ));
}

#[test]
fn archive_rejects_trailing_separator_zip_symlink_entries() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("trailing-separator-symlink.zip");
    let file = File::create(&archive_path).expect("create symlink ZIP");
    let mut writer = zip::ZipWriter::new(file);
    writer
        .add_symlink(
            "evidence/link/",
            "../../outside.log",
            zip::write::SimpleFileOptions::default(),
        )
        .expect("write trailing-separator symlink entry");
    writer.finish().expect("finish symlink ZIP");

    let error = extract_captured_archive(&archive_path)
        .expect_err("reject a symlink even when its name ends in a separator");
    assert!(matches!(
        error,
        ArchiveError::UnsupportedEntryType {
            kind: ArchiveEntryKind::Symlink,
            ..
        }
    ));
}

#[test]
fn archive_rejects_non_symlink_zip_special_entries() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("special.zip");
    write_test_zip(
        &archive_path,
        &[("evidence/fifo.log", b"not a regular file")],
    );

    let mut bytes = std::fs::read(&archive_path).expect("read ZIP fixture");
    let central = find_last_signature(&bytes, [0x50, 0x4b, 0x01, 0x02]);
    bytes[central + 5] = 3;
    patch_u32(&mut bytes, central + 38, 0o010644_u32 << 16);
    std::fs::write(&archive_path, bytes).expect("patch ZIP fixture");

    assert!(matches!(
        extract_captured_archive(&archive_path),
        Err(ArchiveError::UnsupportedEntryType {
            kind: ArchiveEntryKind::Other,
            ..
        })
    ));
}

#[test]
fn archive_rejects_trailing_separator_zip_special_entries() {
    let source = tempfile::tempdir().expect("source tempdir");
    let archive_path = source.path().join("trailing-separator-special.zip");
    write_test_zip(&archive_path, &[("evidence/fifo/", b"not a regular file")]);

    let mut bytes = std::fs::read(&archive_path).expect("read ZIP fixture");
    let central = find_last_signature(&bytes, [0x50, 0x4b, 0x01, 0x02]);
    bytes[central + 5] = 3;
    patch_u32(&mut bytes, central + 38, 0o010644_u32 << 16);
    std::fs::write(&archive_path, bytes).expect("patch ZIP fixture");

    let error = extract_captured_archive(&archive_path)
        .expect_err("reject a special entry even when its name ends in a separator");
    assert!(matches!(
        error,
        ArchiveError::UnsupportedEntryType {
            kind: ArchiveEntryKind::Other,
            ..
        }
    ));
}

#[test]
fn archive_manifest_enforces_entry_per_file_and_total_uncompressed_caps() {
    let too_many = (0..=MAX_ARCHIVE_ENTRIES)
        .map(|index| ArchiveEntryMetadata::file(format!("logs/{index}.log"), 0))
        .collect::<Vec<_>>();
    assert!(matches!(
        validate_archive_manifest(&too_many),
        Err(ArchiveError::EntryCountExceeded { .. })
    ));

    assert!(matches!(
        validate_archive_manifest(&[ArchiveEntryMetadata::file(
            "logs/oversized.log",
            MAX_ARCHIVE_FILE_BYTES + 1,
        )]),
        Err(ArchiveError::EntryTooLarge { .. })
    ));

    let total_too_large = [
        ArchiveEntryMetadata::file("logs/one.log", MAX_ARCHIVE_FILE_BYTES),
        ArchiveEntryMetadata::file("logs/two.log", MAX_ARCHIVE_FILE_BYTES),
        ArchiveEntryMetadata::file("logs/three.log", MAX_ARCHIVE_FILE_BYTES),
        ArchiveEntryMetadata::file("logs/four.log", MAX_ARCHIVE_FILE_BYTES),
        ArchiveEntryMetadata::file("logs/five.log", 1),
    ];
    assert_eq!(
        total_too_large
            .iter()
            .map(|entry| entry.uncompressed_size)
            .sum::<u64>(),
        MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES + 1
    );
    assert!(matches!(
        validate_archive_manifest(&total_too_large),
        Err(ArchiveError::TotalSizeExceeded { .. })
    ));
}

#[test]
fn archive_cancellation_removes_the_unique_partial_extraction_directory() {
    let source = tempfile::tempdir().expect("source tempdir");
    let extraction_parent = tempfile::tempdir().expect("extraction parent");
    let archive_path = source.path().join("cancel.zip");
    write_test_zip(
        &archive_path,
        &[("logs/one.log", b"one"), ("logs/two.log", b"two")],
    );
    let checks = AtomicUsize::new(0);
    let cancelled = || checks.fetch_add(1, Ordering::SeqCst) >= 2;

    let error = extract_captured_archive_with_cancel_in(
        &archive_path,
        extraction_parent.path(),
        &cancelled,
    )
    .expect_err("cancel extraction");

    assert_eq!(error, ArchiveError::Cancelled);
    assert_eq!(
        extraction_parent
            .path()
            .read_dir()
            .expect("list extraction parent")
            .count(),
        0,
        "cancelled extraction must not leave a partial directory"
    );
}

#[test]
fn archive_rejects_unsupported_extensions_and_invalid_container_bytes() {
    let source = tempfile::tempdir().expect("source tempdir");
    let tar_path = source.path().join("captured.tar");
    std::fs::write(&tar_path, b"not a supported archive").expect("write TAR fixture");
    assert!(matches!(
        extract_captured_archive(&tar_path),
        Err(ArchiveError::UnsupportedArchiveType { .. })
    ));

    let invalid_zip = source.path().join("invalid.zip");
    std::fs::write(&invalid_zip, b"not a ZIP").expect("write invalid ZIP");
    assert!(matches!(
        extract_captured_archive(&invalid_zip),
        Err(ArchiveError::InvalidArchive { .. })
    ));
}

#[test]
fn archive_failure_and_panic_unwinding_remove_unique_partial_directories() {
    let source = tempfile::tempdir().expect("source tempdir");

    let failure_parent = tempfile::tempdir().expect("failure extraction parent");
    let invalid_zip = source.path().join("invalid-for-cleanup.zip");
    std::fs::write(&invalid_zip, b"not a ZIP").expect("write invalid ZIP");
    assert!(
        extract_captured_archive_with_cancel_in(&invalid_zip, failure_parent.path(), &|| false,)
            .is_err()
    );
    assert_eq!(
        failure_parent
            .path()
            .read_dir()
            .expect("list failed extraction parent")
            .count(),
        0,
        "failed extraction must not leave its unique directory"
    );

    let panic_parent = tempfile::tempdir().expect("panic extraction parent");
    let safe_zip = source.path().join("panic-cleanup.zip");
    write_test_zip(&safe_zip, &[("logs/evidence.log", b"evidence")]);
    let checks = AtomicUsize::new(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let panic_during_extraction = || {
            if checks.fetch_add(1, Ordering::SeqCst) >= 1 {
                panic!("fixture panic after extraction directory creation");
            }
            false
        };
        let _ = extract_captured_archive_with_cancel_in(
            &safe_zip,
            panic_parent.path(),
            &panic_during_extraction,
        );
    }));

    assert!(result.is_err(), "fixture must unwind through extraction");
    assert_eq!(
        panic_parent
            .path()
            .read_dir()
            .expect("list panic extraction parent")
            .count(),
        0,
        "panic unwinding must remove the unique extraction directory"
    );
}

const BUNDLE_REQUEST_ID: &str = "5d33649d-7425-42fb-8d44-7a0ef39b0dbc";
const BUNDLE_OBSERVED_AT: &str = "2026-07-16T08:00:00.000Z";

fn write_bundle_manifest(root: &Path, artifacts: serde_json::Value) {
    let manifest = serde_json::json!({
        "bundle": { "bundleId": "bundle-fixture" },
        "collection": {
            "collectedUtc": BUNDLE_OBSERVED_AT,
            "results": { "gaps": [] }
        },
        "artifacts": artifacts,
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize bundle manifest"),
    )
    .expect("write bundle manifest");
}

#[test]
fn bundle_manifest_identity_and_family_drive_nested_sparse_intake() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    let nested = bundle.path().join("actual").join("nested");
    std::fs::create_dir_all(&nested).expect("create nested artifact folder");
    std::fs::write(
        nested.join("misleading-name.txt"),
        r#"{"DeploymentProfileName":"Manifest Profile","CloudAssignedDomainJoinMethod":0}"#,
    )
    .expect("write nested JSON artifact");
    write_bundle_manifest(
        bundle.path(),
        serde_json::json!([{
            "artifactId": "autopilot-dds-ztd-file",
            "category": "registry",
            "family": "autopilot-profile-json",
            "relativePath": "actual/nested/misleading-name.txt",
            "status": "collected",
            "parseHints": ["json", "autopilot"]
        }]),
    );

    let snapshot =
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze sparse manifest bundle");

    assert_eq!(
        snapshot
            .profile
            .as_ref()
            .and_then(|profile| profile.profile_name.as_deref()),
        Some("Manifest Profile")
    );
    assert!(snapshot.raw_evidence.iter().any(|record| {
        record
            .provenance
            .source_artifact_id
            .contains("autopilot-dds-ztd-file")
            && record
                .provenance
                .file_path
                .as_deref()
                .is_some_and(|path| path.ends_with("actual/nested/misleading-name.txt"))
    }));
    assert!(snapshot.coverage.iter().any(|coverage| {
        coverage.family == "autopilot-profile-json"
            && coverage.status == EspArtifactStatus::Available
    }));
}

#[test]
fn bundle_manifest_reports_missing_and_malformed_artifacts_without_fallback() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    std::fs::create_dir_all(bundle.path().join("evidence")).expect("create evidence folder");
    std::fs::write(bundle.path().join("evidence/bad.json"), b"{not-json")
        .expect("write malformed JSON");
    std::fs::write(
        bundle.path().join("evidence/unlisted.log"),
        b"must not be analyzed",
    )
    .expect("write unlisted fallback candidate");
    write_bundle_manifest(
        bundle.path(),
        serde_json::json!([
            {
                "artifactId": "missing-profile",
                "category": "exports",
                "family": "autopilot-profile-json",
                "relativePath": "evidence/missing.json",
                "status": "collected"
            },
            {
                "artifactId": "malformed-profile",
                "category": "exports",
                "family": "autopilot-profile-json",
                "relativePath": "evidence/bad.json",
                "status": "collected"
            }
        ]),
    );

    let snapshot =
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze partial manifest bundle");

    assert!(snapshot.coverage.iter().any(|coverage| {
        coverage.artifact_id.contains("missing-profile")
            && coverage.status == EspArtifactStatus::Missing
    }));
    assert!(snapshot.coverage.iter().any(|coverage| {
        coverage.artifact_id.contains("malformed-profile")
            && coverage.status == EspArtifactStatus::ParseFailed
    }));
    assert!(snapshot.raw_evidence.iter().all(|record| {
        record
            .provenance
            .file_path
            .as_deref()
            .map_or(true, |path| !path.ends_with("unlisted.log"))
    }));
}

#[test]
fn bundle_malformed_manifest_is_coverage_not_an_implicit_legacy_scan() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    std::fs::write(bundle.path().join("manifest.json"), b"{not-json")
        .expect("write malformed manifest");
    std::fs::write(
        bundle.path().join("AgentExecutor.log"),
        b"must not be analyzed",
    )
    .expect("write legacy candidate");

    let snapshot = analyze_captured_evidence_at(
        &bundle.path().join("manifest.json"),
        BUNDLE_REQUEST_ID,
        BUNDLE_OBSERVED_AT,
    )
    .expect("malformed manifest returns an actionable snapshot");

    assert!(snapshot.raw_evidence.is_empty());
    assert!(snapshot.coverage.iter().any(|coverage| {
        coverage.artifact_id == "bundle.manifest"
            && coverage.status == EspArtifactStatus::ParseFailed
    }));
}

#[test]
fn bundle_legacy_fallback_is_depth_extension_and_basename_allowlisted() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    let accepted = bundle.path().join("one").join("two");
    let too_deep = accepted.join("three");
    std::fs::create_dir_all(&too_deep).expect("create legacy fixture folders");
    std::fs::write(
        accepted.join("AutoPilotConfigurationFile.json"),
        r#"{"DeploymentProfileName":"Legacy Profile"}"#,
    )
    .expect("write accepted legacy JSON");
    std::fs::write(
        too_deep.join("AutoPilotConfigurationFile.json"),
        r#"{"DeploymentProfileName":"Too Deep"}"#,
    )
    .expect("write too-deep legacy JSON");
    std::fs::write(
        bundle.path().join("arbitrary.json"),
        r#"{"secret":"ignored"}"#,
    )
    .expect("write unknown JSON");
    std::fs::write(bundle.path().join("ignored.exe"), b"ignored")
        .expect("write unsupported extension");

    let snapshot =
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze legacy bundle");

    assert_eq!(MAX_LEGACY_BUNDLE_DEPTH, 3);
    assert_eq!(
        snapshot
            .profile
            .as_ref()
            .and_then(|profile| profile.profile_name.as_deref()),
        Some("Legacy Profile")
    );
    assert!(snapshot.raw_evidence.iter().all(|record| {
        record.provenance.file_path.as_deref().map_or(true, |path| {
            !path.ends_with("arbitrary.json") && !path.ends_with("ignored.exe")
        })
    }));
}

#[test]
fn bundle_legacy_fallback_stops_after_256_directory_entries() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    for index in 0..(MAX_LEGACY_BUNDLE_ENTRIES + 8) {
        std::fs::write(
            bundle.path().join(format!("evidence-{index:03}.log")),
            format!("evidence {index}"),
        )
        .expect("write bounded legacy fixture");
    }

    let snapshot =
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze bounded legacy bundle");

    assert_eq!(MAX_LEGACY_BUNDLE_ENTRIES, 256);
    assert!(snapshot.raw_evidence.len() <= MAX_LEGACY_BUNDLE_ENTRIES);
    assert!(snapshot.coverage.iter().any(|coverage| {
        coverage.artifact_id == "bundle.legacy-limit"
            && coverage.status == EspArtifactStatus::ParseFailed
    }));
}

#[test]
fn bundle_intake_never_queries_equivalent_live_machine_sources() {
    let source = include_str!("../src/esp/bundle.rs");
    for forbidden in [
        "collect_live_registry_evidence",
        "LiveSystemProvider",
        "collect_live_event_evidence",
        "runtime_discovery_input",
        "Registry::local_machine",
    ] {
        assert!(
            !source.contains(forbidden),
            "captured analysis must not query analyst-machine source {forbidden}"
        );
    }
}

#[test]
fn bundle_and_live_shaped_registry_evidence_have_equivalent_conclusions() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    std::fs::create_dir_all(bundle.path().join("evidence/registry"))
        .expect("create registry folder");
    std::fs::write(
        bundle
            .path()
            .join("evidence/registry/autopilot-settings.reg"),
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Provisioning\\AutopilotSettings]\n",
            "\"DeploymentProfileName\"=\"Equivalent Profile\"\n",
            "\"CloudAssignedDomainJoinMethod\"=dword:00000000\n",
        ),
    )
    .expect("write registry export");
    write_bundle_manifest(
        bundle.path(),
        serde_json::json!([{
            "artifactId": "autopilot-settings",
            "category": "registry",
            "family": "autopilot-settings",
            "relativePath": "evidence/registry/autopilot-settings.reg",
            "status": "collected"
        }]),
    );

    let captured =
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze captured registry evidence");
    let mut live = EspDiagnosticsReducer::new(BUNDLE_OBSERVED_AT.to_string());
    for (index, (value_name, value)) in [
        (
            "DeploymentProfileName",
            EspObservationValue::Text("Equivalent Profile".to_string()),
        ),
        (
            "CloudAssignedDomainJoinMethod",
            EspObservationValue::Integer(0),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let source_artifact_id = "registry:autopilot-settings".to_string();
        live.ingest(EspEvidenceRecord::Registry(EspRegistryObservation {
            context: EspObservationContext {
                evidence_ref: EspEvidenceRef {
                    evidence_id: format!("live-registry-{index}"),
                    source_artifact_id: source_artifact_id.clone(),
                },
                provenance: EspEvidenceProvenance {
                    source_kind: EspSourceKind::Registry,
                    source_artifact_id,
                    file_path: None,
                    line_number: Some((index + 3) as u64),
                    record_number: None,
                    registry: Some(EspRegistryProvenance {
                        hive: "HKLM".to_string(),
                        key: r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings".to_string(),
                        value_name: Some(value_name.to_string()),
                    }),
                    event: None,
                },
                source_timestamp: None,
                observed_at_utc: BUNDLE_OBSERVED_AT.to_string(),
                sensitivity: EspSensitivity::Public,
                parse_state: EspParseState::Parsed,
                access_state: EspSourceAccessState::Available,
            },
            hive: "HKLM".to_string(),
            key: r"SOFTWARE\Microsoft\Provisioning\AutopilotSettings".to_string(),
            value_name: value_name.to_string(),
            value,
        }));
    }
    let live = live.snapshot();

    assert_eq!(captured.scenario, live.scenario);
    assert_eq!(captured.phase, live.phase);
    assert_eq!(
        captured
            .profile
            .as_ref()
            .and_then(|profile| profile.profile_name.clone()),
        live.profile
            .as_ref()
            .and_then(|profile| profile.profile_name.clone())
    );
    assert_eq!(
        captured
            .profile
            .as_ref()
            .and_then(|profile| profile.join_mode.clone()),
        live.profile
            .as_ref()
            .and_then(|profile| profile.join_mode.clone())
    );
}

#[test]
fn bundle_rejects_non_uuid_request_ids_before_reading_the_source() {
    assert_eq!(
        analyze_captured_evidence_at(
            Path::new("/source-that-must-not-be-read"),
            "analysis-not-a-uuid",
            BUNDLE_OBSERVED_AT,
        )
        .expect_err("reject non-UUID request ID first"),
        BundleError::InvalidRequestId
    );
}

#[test]
fn bundle_registry_json_values_feed_device_preparation_reducer_paths() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    std::fs::create_dir_all(bundle.path().join("evidence/registry"))
        .expect("create registry folder");
    std::fs::write(
        bundle.path().join("evidence/registry/esp.reg"),
        concat!(
            "Windows Registry Editor Version 5.00\n\n",
            "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\Autopilot\\EnrollmentStatusTracking]\n",
            "\"ProvisioningProgress\"=\"{\\\"Workloads\\\":[{\\\"WorkloadId\\\":\\\"app-42\\\",\\\"FriendlyName\\\":\\\"Required App\\\",\\\"WorkloadState\\\":4}]}\"\n",
        ),
    )
    .expect("write registry JSON fixture");
    write_bundle_manifest(
        bundle.path(),
        serde_json::json!([{
            "artifactId": "autopilot-esp-diagnostics",
            "category": "registry",
            "family": "autopilot-esp-diagnostics",
            "relativePath": "evidence/registry/esp.reg",
            "status": "collected"
        }]),
    );

    let snapshot =
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze registry-embedded JSON");

    assert!(snapshot
        .workloads
        .iter()
        .any(|workload| workload.raw_identifier == "app-42"
            && workload.display_name.as_deref() == Some("Required App")));
    assert!(snapshot.raw_evidence.iter().any(|record| {
        record
            .provenance
            .registry
            .as_ref()
            .and_then(|registry| registry.value_name.as_deref())
            == Some("ProvisioningProgress")
    }));
}

#[test]
fn bundle_hardware_and_delivery_json_normalize_without_raw_hardware_hash() {
    let bundle = tempfile::tempdir().expect("bundle tempdir");
    let output = bundle.path().join("evidence/command-output");
    std::fs::create_dir_all(&output).expect("create command output folder");
    std::fs::write(
        output.join("esp-hardware-facts.json"),
        r#"{"Manufacturer":"Contoso","Model":"Model 42","SerialNumber":"SERIAL-42","DeviceHardwareData":"BASE64-HASH-SECRET"}"#,
    )
    .expect("write hardware JSON");
    std::fs::write(
        output.join("esp-os-facts.json"),
        r#"{"Version":"10.0.26100","BuildNumber":"26100"}"#,
    )
    .expect("write OS JSON");
    std::fs::write(
        output.join("delivery-optimization-perf-snap.json"),
        r#"{"DownloadHttpBytes":1000,"DownloadLanBytes":250,"DownloadCacheHostBytes":100}"#,
    )
    .expect("write DO JSON");
    write_bundle_manifest(
        bundle.path(),
        serde_json::json!([
            {
                "artifactId": "esp-hardware-facts",
                "category": "command-output",
                "family": "esp-hardware",
                "relativePath": "evidence/command-output/esp-hardware-facts.json",
                "status": "collected",
                "parseHints": ["json", "esp-hardware"]
            },
            {
                "artifactId": "esp-os-facts",
                "category": "command-output",
                "family": "esp-hardware",
                "relativePath": "evidence/command-output/esp-os-facts.json",
                "status": "collected",
                "parseHints": ["json", "esp-hardware"]
            },
            {
                "artifactId": "delivery-optimization-perf-snap",
                "category": "command-output",
                "family": "delivery-optimization-command",
                "relativePath": "evidence/command-output/delivery-optimization-perf-snap.json",
                "status": "collected",
                "parseHints": ["json", "delivery-optimization"]
            }
        ]),
    );

    let snapshot =
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze system and DO JSON");
    let hardware = snapshot.hardware.as_ref().expect("normalized hardware");
    assert_eq!(hardware.manufacturer.as_deref(), Some("Contoso"));
    assert_eq!(hardware.model.as_deref(), Some("Model 42"));
    assert_eq!(hardware.os_version.as_deref(), Some("10.0.26100"));
    assert_eq!(hardware.os_build.as_deref(), Some("26100"));
    let delivery = snapshot
        .delivery_optimization
        .as_ref()
        .expect("normalized Delivery Optimization");
    assert_eq!(delivery.download_http_bytes, 1000);
    assert_eq!(delivery.download_lan_bytes, 250);
    assert_eq!(delivery.download_cache_host_bytes, 100);
    let serialized = serde_json::to_string(&snapshot).expect("serialize captured snapshot");
    assert!(!serialized.contains("BASE64-HASH-SECRET"));
    assert!(!serialized
        .to_ascii_lowercase()
        .contains("devicehardwaredata"));
}

#[test]
fn bundle_analyzes_manifest_first_zip_inputs_through_scoped_extraction() {
    let source = tempfile::tempdir().expect("archive source tempdir");
    let archive = source.path().join("captured.zip");
    let manifest = serde_json::to_vec(&serde_json::json!({
        "collection": { "collectedUtc": BUNDLE_OBSERVED_AT, "results": { "gaps": [] } },
        "artifacts": [{
            "artifactId": "ime-logs",
            "category": "logs",
            "family": "intune-ime",
            "relativePath": "evidence/logs/AgentExecutor.log",
            "status": "collected"
        }]
    }))
    .expect("serialize archive manifest");
    write_test_zip(
        &archive,
        &[
            ("manifest.json", manifest.as_slice()),
            (
                "evidence/logs/AgentExecutor.log",
                b"<![LOG[Processing app id 00000000-0000-0000-0000-000000000042]LOG]!><time=\"08:00:00.000+000\" date=\"07-16-2026\" component=\"AgentExecutor\" context=\"\" type=\"1\" thread=\"1\" file=\"\">",
            ),
        ],
    );

    let snapshot = analyze_captured_evidence_at(&archive, BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
        .expect("analyze ZIP bundle");

    assert!(snapshot
        .raw_evidence
        .iter()
        .any(|record| { record.provenance.source_artifact_id.contains("ime-logs") }));
    assert!(snapshot.coverage.iter().any(|coverage| {
        coverage.family == "intune-ime" && coverage.status == EspArtifactStatus::Available
    }));
}

#[test]
fn bundle_json_scalar_bound_distinguishes_exact_capacity_from_truncation() {
    let analyze_count = |count: usize| {
        let bundle = tempfile::tempdir().expect("bundle tempdir");
        let values = (0..count).map(|index| index as u64).collect::<Vec<_>>();
        std::fs::write(
            bundle.path().join("AutoPilotConfigurationFile.json"),
            serde_json::to_vec(&values).expect("serialize bounded JSON"),
        )
        .expect("write bounded JSON");
        write_bundle_manifest(
            bundle.path(),
            serde_json::json!([{
                "artifactId": "autopilot-configuration-file",
                "category": "exports",
                "family": "autopilot-profile-json",
                "relativePath": "AutoPilotConfigurationFile.json",
                "status": "collected",
                "parseHints": ["json", "autopilot"]
            }]),
        );
        analyze_captured_evidence_at(bundle.path(), BUNDLE_REQUEST_ID, BUNDLE_OBSERVED_AT)
            .expect("analyze bounded JSON")
    };

    let exact = analyze_count(MAX_JSON_SCALAR_RECORDS);
    assert_eq!(exact.raw_evidence.len(), MAX_JSON_SCALAR_RECORDS);
    assert!(exact.coverage.iter().any(|coverage| {
        coverage.family == "autopilot-profile-json"
            && coverage.status == EspArtifactStatus::Available
    }));

    let truncated = analyze_count(MAX_JSON_SCALAR_RECORDS + 1);
    assert_eq!(truncated.raw_evidence.len(), MAX_JSON_SCALAR_RECORDS);
    assert!(truncated.coverage.iter().any(|coverage| {
        coverage.family == "autopilot-profile-json"
            && coverage.status == EspArtifactStatus::ParseFailed
            && coverage
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("4096-record bound"))
    }));
}

#[test]
fn signature_and_tail_reads_require_platform_no_follow_flags() {
    let discovery = include_str!("../src/esp/discovery.rs");
    let tailing = include_str!("../src/esp/tailing.rs");

    for source in [discovery, tailing] {
        assert!(source.contains("libc::O_NOFOLLOW"));
        assert!(source.contains("libc::O_NONBLOCK"));
        assert!(source.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    }
    assert!(!discovery.contains("File::open(path)"));
}

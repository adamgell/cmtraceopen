use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier, Condvar, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

#[cfg(target_os = "windows")]
use app_lib::esp::discovery::default_known_source_specs;
use app_lib::esp::discovery::{
    build_runtime_temp_roots, discover_bounded_logs, embedded_known_source_specs,
    DiscoveredLogSource, DiscoveryInput, DiscoveryRootKind, DiscoveryRootState,
    DiscoverySourceOrigin, KnownSourceSpec, DISCOVERY_INTERVAL, MAX_ACTIVE_TAILS,
    MAX_INITIAL_READ_BYTES, MAX_KNOWN_ENTRIES_PROBED_PER_ROOT, MAX_ROTATIONS_PER_KNOWN_LOG,
    MAX_SESSION_DURATION, MAX_TEMP_ENTRIES_INSPECTED_PER_ROOT, MAX_TEMP_ENTRIES_PROBED_PER_ROOT,
    TEMP_LOOKBACK, UPDATE_DEBOUNCE,
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
    EspTailResetReason, EspTailSet, MAX_SESSION_TAIL_SOURCES, WINDOWS_SHARED_READ_WRITE_DELETE,
};
use app_lib::intune::evtx_parser::{
    parse_esp_event_xml, EventLogProperty, ParsedEspEventRecord, MAX_ESP_EVTX_RECORD_BYTES,
};
use cmtraceopen_parser::esp::{
    EspArtifactCoverage, EspArtifactStatus, EspDiagnosticsReducer, EspElevationState,
    EspEvidenceProvenance, EspEvidenceRecord, EspEvidenceRef, EspGraphObservation,
    EspGraphObservationSection, EspHardwareEvidence, EspObservationContext, EspObservationValue,
    EspParseState, EspScope, EspSensitivity, EspSourceAccessState, EspSourceKind, EspSystemFact,
    EspSystemObservation, GraphApiVersion,
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

use std::cell::RefCell;
use std::collections::HashMap;

use app_lib::esp::event_logs::{
    collect_event_evidence, required_event_id_xpath, EventLogProvider, EventSourceError,
    ESP_EVENT_CHANNELS, MAX_ESP_EVENT_RECORDS_PER_CHANNEL, REQUIRED_EVENT_IDS,
};
use app_lib::esp::registry::{
    classify_registry_scope, collect_registry_evidence, RegistryProvider, RegistryReadError,
    RegistrySnapshotKey, RegistryTarget, RegistryValueSnapshot, ESP_REGISTRY_TARGETS,
    MAX_REGISTRY_DEPTH, MAX_REGISTRY_VALUE_BYTES, REGISTRY_READ_ACCESS,
};
use app_lib::intune::evtx_parser::{parse_esp_event_xml, EventLogProperty, ParsedEspEventRecord};
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

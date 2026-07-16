use std::collections::{BTreeMap, VecDeque};

use chrono::{SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};

use super::models::*;
use super::normalize::{
    decode_oobe_config, extract_guid, normalize_classic_esp_status, normalize_office_detail_status,
    normalize_office_status, normalize_policy_status, normalize_timestamp, normalize_v2_status,
    percent_decode_bounded,
};
use super::rules::derive_findings;
use super::timeline::{sort_timeline_entries, stable_record_id, stable_timeline_entry_id};

pub const MAX_RETAINED_EVIDENCE_RECORDS: usize = 25_000;
pub const MAX_RETAINED_EVIDENCE_SERIALIZED_BYTES: usize = 32 * 1024 * 1024;

const RETENTION_COVERAGE_ARTIFACT_ID: &str = "session.evidence-retention";
const RETENTION_COVERAGE_FAMILY: &str = "session-retention";
const RETENTION_COVERAGE_ORDINAL: usize = usize::MAX;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "record", rename_all = "camelCase")]
pub enum EspEvidenceRecord {
    Registry(EspRegistryObservation),
    Json(EspJsonObservation),
    EventLog(EspEventLogObservation),
    Ime(EspImeObservation),
    DeploymentLog(EspDeploymentLogObservation),
    Process(EspProcessObservation),
    System(EspSystemObservation),
    DeliveryOptimizationSummary(EspDeliveryOptimizationEvidence),
    DeliveryOptimization(EspDeliveryOptimizationObservation),
    Graph(EspGraphObservation),
    Coverage(EspArtifactCoverage),
}

#[derive(Debug, Clone)]
pub struct EspDiagnosticsReducer {
    generated_at_utc: String,
    records: VecDeque<RetainedEvidenceRecord>,
    retained_serialized_bytes: usize,
    next_ordinal: usize,
    next_occurrence_by_key: BTreeMap<(String, String), usize>,
    retained_occurrence_counts: BTreeMap<(String, String), usize>,
    discarded_records: usize,
    discarded_serialized_bytes: usize,
    max_retained_records: usize,
    max_retained_serialized_bytes: usize,
}

#[derive(Debug, Clone)]
struct RetainedEvidenceRecord {
    ordinal: usize,
    occurrence_ordinal: usize,
    occurrence_key: Option<(String, String)>,
    serialized_bytes: usize,
    record: EspEvidenceRecord,
}

impl EspDiagnosticsReducer {
    pub fn new(generated_at_utc: String) -> Self {
        Self::with_retention_limits(
            generated_at_utc,
            MAX_RETAINED_EVIDENCE_RECORDS,
            MAX_RETAINED_EVIDENCE_SERIALIZED_BYTES,
        )
    }

    #[doc(hidden)]
    pub fn with_retention_limits(
        generated_at_utc: String,
        max_retained_records: usize,
        max_retained_serialized_bytes: usize,
    ) -> Self {
        Self {
            generated_at_utc,
            records: VecDeque::new(),
            retained_serialized_bytes: 0,
            next_ordinal: 0,
            next_occurrence_by_key: BTreeMap::new(),
            retained_occurrence_counts: BTreeMap::new(),
            discarded_records: 0,
            discarded_serialized_bytes: 0,
            max_retained_records: max_retained_records.max(1),
            max_retained_serialized_bytes: max_retained_serialized_bytes.max(1),
        }
    }

    pub fn ingest(&mut self, record: EspEvidenceRecord) {
        let ordinal = self.next_ordinal;
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        let serialized_bytes = serde_json::to_vec(&record)
            .map(|serialized| serialized.len())
            .unwrap_or_else(|_| self.max_retained_serialized_bytes.saturating_add(1));
        if serialized_bytes > self.max_retained_serialized_bytes {
            self.note_discard(serialized_bytes);
            return;
        }
        let occurrence_key = record_occurrence_key(&record);
        let occurrence_ordinal = if let Some(key) = &occurrence_key {
            let next = self.next_occurrence_by_key.entry(key.clone()).or_insert(0);
            let occurrence = *next;
            *next = next.saturating_add(1);
            let retained_count = self
                .retained_occurrence_counts
                .entry(key.clone())
                .or_insert(0);
            *retained_count = retained_count.saturating_add(1);
            occurrence
        } else {
            ordinal
        };

        self.retained_serialized_bytes = self
            .retained_serialized_bytes
            .saturating_add(serialized_bytes);
        self.records.push_back(RetainedEvidenceRecord {
            ordinal,
            occurrence_ordinal,
            occurrence_key,
            serialized_bytes,
            record,
        });
        while self.records.len() > self.max_retained_records
            || self.retained_serialized_bytes > self.max_retained_serialized_bytes
        {
            let eviction_index = self
                .records
                .iter()
                .position(|retained| is_stream_evidence(&retained.record))
                .unwrap_or(0);
            let Some(discarded) = self.records.remove(eviction_index) else {
                break;
            };
            self.retained_serialized_bytes = self
                .retained_serialized_bytes
                .saturating_sub(discarded.serialized_bytes);
            self.release_occurrence_key(discarded.occurrence_key.as_ref());
            self.note_discard(discarded.serialized_bytes);
        }
    }

    pub fn ingest_all<I: IntoIterator<Item = EspEvidenceRecord>>(&mut self, records: I) {
        for record in records {
            self.ingest(record);
        }
    }

    pub fn snapshot(&self) -> EspDiagnosticsSnapshot {
        let scenario = classify_scenario(self.records.iter().map(|retained| &retained.record));
        let occurrence_ordinals = self
            .records
            .iter()
            .map(|retained| (retained.ordinal, retained.occurrence_ordinal))
            .collect();
        let mut projection =
            SnapshotProjection::new(self.generated_at_utc.clone(), scenario, occurrence_ordinals);
        for retained in &self.records {
            let ordinal = retained.ordinal;
            let record = &retained.record;
            if is_raw_hardware_hash_record(record) {
                continue;
            }
            if let Some(raw) = raw_evidence_record(record, retained.occurrence_ordinal) {
                projection.raw_evidence.push(raw);
            }
            if record_allowed_for_scenario(record, &projection.scenario) {
                projection.process_record(ordinal, record);
            }
        }
        if let Some(coverage) = self.retention_coverage() {
            projection
                .occurrence_ordinals
                .insert(RETENTION_COVERAGE_ORDINAL, 0);
            projection.process_coverage(RETENTION_COVERAGE_ORDINAL, coverage);
        }
        projection.finish()
    }

    fn note_discard(&mut self, serialized_bytes: usize) {
        self.discarded_records = self.discarded_records.saturating_add(1);
        self.discarded_serialized_bytes = self
            .discarded_serialized_bytes
            .saturating_add(serialized_bytes);
    }

    fn release_occurrence_key(&mut self, key: Option<&(String, String)>) {
        let Some(key) = key else {
            return;
        };
        let remove_key = if let Some(count) = self.retained_occurrence_counts.get_mut(key) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove_key {
            self.retained_occurrence_counts.remove(key);
            self.next_occurrence_by_key.remove(key);
        }
    }

    fn retention_coverage(&self) -> Option<EspArtifactCoverage> {
        (self.discarded_records != 0).then(|| EspArtifactCoverage {
            artifact_id: RETENTION_COVERAGE_ARTIFACT_ID.to_string(),
            family: RETENTION_COVERAGE_FAMILY.to_string(),
            status: EspArtifactStatus::ParseFailed,
            detail: Some(format!(
                "Retained evidence is capped at {} records and {} serialized bytes; {} older or oversized {} totaling {} serialized bytes were discarded. Derived conclusions use retained evidence only.",
                self.max_retained_records,
                self.max_retained_serialized_bytes,
                self.discarded_records,
                if self.discarded_records == 1 {
                    "record"
                } else {
                    "records"
                },
                self.discarded_serialized_bytes,
            )),
            observed_at_utc: self.generated_at_utc.clone(),
            evidence: Vec::new(),
        })
    }
}

fn is_stream_evidence(record: &EspEvidenceRecord) -> bool {
    matches!(
        record,
        EspEvidenceRecord::EventLog(_)
            | EspEvidenceRecord::Ime(_)
            | EspEvidenceRecord::DeploymentLog(_)
            | EspEvidenceRecord::Process(_)
            | EspEvidenceRecord::System(_)
            | EspEvidenceRecord::DeliveryOptimization(_)
            | EspEvidenceRecord::Graph(_)
    )
}

struct SnapshotProjection {
    generated_at_utc: String,
    scenario: EspScenario,
    occurrence_ordinals: BTreeMap<usize, usize>,
    elevation: EspElevationState,
    identity: EspIdentityEvidence,
    profile: Option<EspProfileEvidence>,
    enrollments: Vec<EspEnrollmentEvidence>,
    sessions: Vec<EspSession>,
    workloads: Vec<EspWorkload>,
    node_cache: BTreeMap<u64, NodeCacheAccumulator>,
    registration_events: Vec<EspRegistrationEvent>,
    delivery_optimization: Option<EspDeliveryOptimizationEvidence>,
    hardware: Option<EspHardwareEvidence>,
    activity: Vec<(usize, EspTimelineEntry)>,
    coverage: Vec<EspArtifactCoverage>,
    raw_evidence: Vec<EspRawEvidenceRecord>,
    v2_workloads: BTreeMap<(String, String, usize), V2WorkloadAccumulator>,
    platform_scripts: BTreeMap<(String, String), PlatformScriptAccumulator>,
    graph_observations: Vec<EspGraphObservation>,
    office_details: Vec<OfficeDetailObservation>,
    msi_details: Vec<MsiDetailObservation>,
    enforcement_messages: BTreeMap<String, EnforcementMessageAccumulator>,
    deferred_error_codes: Vec<DeferredErrorCode>,
}

impl SnapshotProjection {
    fn new(
        generated_at_utc: String,
        scenario: EspScenario,
        occurrence_ordinals: BTreeMap<usize, usize>,
    ) -> Self {
        Self {
            generated_at_utc,
            scenario,
            occurrence_ordinals,
            elevation: EspElevationState {
                is_elevated: false,
                restart_supported: false,
                restricted_sources: Vec::new(),
            },
            identity: EspIdentityEvidence {
                device_name: None,
                managed_device_id: None,
                entra_device_id: None,
                entdm_id: None,
                tenant_id: None,
                tenant_domain: None,
                user_principal_name: None,
                serial_number: None,
                evidence: Vec::new(),
            },
            profile: None,
            enrollments: Vec::new(),
            sessions: Vec::new(),
            workloads: Vec::new(),
            node_cache: BTreeMap::new(),
            registration_events: Vec::new(),
            delivery_optimization: None,
            hardware: None,
            activity: Vec::new(),
            coverage: Vec::new(),
            raw_evidence: Vec::new(),
            v2_workloads: BTreeMap::new(),
            platform_scripts: BTreeMap::new(),
            graph_observations: Vec::new(),
            office_details: Vec::new(),
            msi_details: Vec::new(),
            enforcement_messages: BTreeMap::new(),
            deferred_error_codes: Vec::new(),
        }
    }

    fn process_record(&mut self, ordinal: usize, record: &EspEvidenceRecord) {
        match record {
            EspEvidenceRecord::Coverage(coverage) => {
                self.process_coverage(ordinal, coverage.clone());
            }
            _ if !record_is_usable(record) => {}
            EspEvidenceRecord::Registry(observation) => self.process_registry(ordinal, observation),
            EspEvidenceRecord::Json(observation) => self.process_json(ordinal, observation),
            EspEvidenceRecord::EventLog(observation) => self.process_event(ordinal, observation),
            EspEvidenceRecord::Ime(observation) => self.process_ime(ordinal, observation),
            EspEvidenceRecord::DeploymentLog(observation) => {
                self.process_deployment_log(ordinal, observation)
            }
            EspEvidenceRecord::Process(observation) => self.process_process(ordinal, observation),
            EspEvidenceRecord::System(observation) => self.process_system(observation),
            EspEvidenceRecord::DeliveryOptimizationSummary(summary) => {
                self.process_delivery_optimization_summary(summary)
            }
            EspEvidenceRecord::DeliveryOptimization(observation) => {
                self.process_delivery_optimization(ordinal, observation)
            }
            EspEvidenceRecord::Graph(observation) => {
                self.graph_observations.push(observation.clone())
            }
        }
    }

    fn process_registry(&mut self, ordinal: usize, observation: &EspRegistryObservation) {
        if self.process_node_cache(observation) {
            return;
        }
        if self.process_enrollment(observation) {
            return;
        }
        if is_platform_script_observation(observation) {
            self.accumulate_platform_script(ordinal, observation);
            return;
        }
        if let Some(detail) = msi_detail_observation(ordinal, observation) {
            self.msi_details.push(detail);
            return;
        }
        if let Some(detail) = office_detail_observation(ordinal, observation) {
            self.office_details.push(detail);
            return;
        }
        if let Some(deferred) = deferred_error_code_observation(ordinal, observation) {
            self.deferred_error_codes.push(deferred);
            return;
        }
        if let Some(session_info) = classic_session_info(observation) {
            self.process_classic_workload(ordinal, observation, session_info);
            return;
        }

        let name = observation.value_name.to_ascii_lowercase();
        match name.as_str() {
            "deploymentprofilename" => {
                if let Some(value) = observation_text(&observation.value) {
                    self.ensure_profile().profile_name = Some(value);
                    self.add_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "cloudassignedtenantdomain" => {
                if let Some(value) = observation_text(&observation.value) {
                    let classified = sensitive_string(value);
                    self.ensure_profile().tenant_domain = Some(classified.clone());
                    self.identity.tenant_domain = Some(classified);
                    self.add_identity_and_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "cloudassignedtenantid" | "aadtenantid" => {
                if let Some(value) = observation_text(&observation.value) {
                    let classified = sensitive_string(value);
                    self.ensure_profile().tenant_id = Some(classified.clone());
                    self.identity.tenant_id = Some(classified);
                    self.add_identity_and_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "ztdcorrelationid" => {
                if let Some(value) = observation_text(&observation.value) {
                    self.ensure_profile().correlation_id = Some(value);
                    self.add_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "cloudassignedoobeconfig" => {
                if let Some(value) = observation_u64(&observation.value) {
                    self.ensure_profile().oobe_config = Some(decode_oobe_config(value));
                    self.add_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "entdmid" => {
                if let Some(value) = observation_text(&observation.value) {
                    self.identity.entdm_id = Some(sensitive_string(value));
                    self.identity
                        .evidence
                        .push(observation.context.evidence_ref.clone());
                }
            }
            "upn" | "userprincipalname" => {
                if let Some(value) = observation_text(&observation.value) {
                    self.identity.user_principal_name = Some(sensitive_string(value));
                    self.identity
                        .evidence
                        .push(observation.context.evidence_ref.clone());
                }
            }
            "odjapplied" => {
                if let Some(value) = observation_bool(&observation.value) {
                    self.ensure_profile().odj_applied = Some(value);
                    self.add_profile_evidence(&observation.context.evidence_ref);
                    self.push_timeline(
                        ordinal,
                        &observation.context,
                        EspTimelineKind::OfflineDomainJoin,
                        "Offline Domain Join".to_string(),
                        Some(
                            if value {
                                "ODJ applied"
                            } else {
                                "ODJ not applied"
                            }
                            .to_string(),
                        ),
                        Some(boolean_status(value)),
                    );
                }
            }
            "autopilotdeviceprephint" => {
                self.ensure_device_preparation()
                    .evidence
                    .push(observation.context.evidence_ref.clone());
                self.add_profile_evidence(&observation.context.evidence_ref);
            }
            _ => {}
        }
    }

    fn process_json(&mut self, ordinal: usize, observation: &EspJsonObservation) {
        if is_provisioning_progress(observation) {
            self.accumulate_v2_workload(ordinal, observation);
            return;
        }
        if is_enforcement_state_message(observation) {
            self.accumulate_enforcement_message(ordinal, observation);
            return;
        }

        let pointer = observation.json_pointer.to_ascii_lowercase();
        if is_page_settings(observation) {
            let evidence = observation.context.evidence_ref.clone();
            let device_preparation = self.ensure_device_preparation();
            match pointer.as_str() {
                "/agentdownloadtimeoutseconds" => {
                    device_preparation.agent_download_timeout_seconds =
                        observation_u64(&observation.value)
                }
                "/pagetimeoutseconds" => {
                    device_preparation.page_timeout_seconds = observation_u64(&observation.value)
                }
                "/allowskiponfailure" => {
                    device_preparation.allow_skip_on_failure = observation_bool(&observation.value)
                }
                "/allowdiagnostics" => {
                    device_preparation.allow_diagnostics = observation_bool(&observation.value)
                }
                _ if pointer.starts_with("/scripts/") => {
                    if let Some(value) = observation_text(&observation.value) {
                        device_preparation.script_ids.push(value);
                    }
                }
                _ => return,
            }
            device_preparation.evidence.push(evidence.clone());
            self.add_profile_evidence(&evidence);
            return;
        }

        match pointer.as_str() {
            "/policydownloaddate" => {
                if let Some(value) = observation_text(&observation.value) {
                    let normalized = normalize_timestamp(&value, None);
                    self.ensure_profile().profile_download_time = Some(normalized.clone());
                    self.add_profile_evidence(&observation.context.evidence_ref);
                    self.activity.push((
                        ordinal,
                        EspTimelineEntry {
                            entry_id: self.timeline_entry_id(&observation.context, ordinal),
                            timestamp: normalized,
                            kind: EspTimelineKind::ProfileDownload,
                            title: "Autopilot profile".to_string(),
                            detail: Some("Profile downloaded".to_string()),
                            status: Some(text_status(
                                "Profile downloaded",
                                EspNormalizedStatus::Processed,
                            )),
                            evidence: vec![observation.context.evidence_ref.clone()],
                        },
                    ));
                }
            }
            "/cloudassigneddomainjoinmethod" => {
                if let Some(value) = observation_i64(&observation.value) {
                    self.ensure_profile().join_mode = Some(if value == 1 {
                        EspJoinMode::HybridEntra
                    } else {
                        EspJoinMode::Entra
                    });
                    self.add_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "/hybridjoinskipdcconnectivitycheck" => {
                if let Some(value) = observation_bool(&observation.value) {
                    self.ensure_profile().skip_domain_connectivity_check = Some(value);
                    self.add_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "/deploymentprofilename" => {
                if let Some(value) = observation_text(&observation.value) {
                    self.ensure_profile().profile_name = Some(value);
                    self.add_profile_evidence(&observation.context.evidence_ref);
                }
            }
            "/ztdcorrelationid" => {
                if let Some(value) = observation_text(&observation.value) {
                    self.ensure_profile().correlation_id = Some(value);
                    self.add_profile_evidence(&observation.context.evidence_ref);
                }
            }
            _ => {}
        }
    }

    fn process_event(&mut self, ordinal: usize, observation: &EspEventLogObservation) {
        if !is_parity_event(observation.event_id) {
            return;
        }
        let odj_state = odj_state_details(observation);
        let message = odj_state
            .as_ref()
            .map(|(message, _)| (*message).to_string())
            .or_else(|| observation.message.clone())
            .unwrap_or_else(|| event_default_message(observation.event_id).to_string());
        let normalized = odj_state
            .map(|(_, normalized)| normalized)
            .unwrap_or_else(|| event_normalized_status(observation.event_id));
        let event_status = text_status(&message, normalized);
        let kind = event_timeline_kind(observation.event_id);
        let title = event_title(observation.event_id, &observation.named_data);
        self.push_timeline(
            ordinal,
            &observation.context,
            kind,
            title,
            Some(message.clone()),
            Some(event_status.clone()),
        );

        if matches!(observation.event_id, 101 | 304 | 306) {
            self.registration_events.push(EspRegistrationEvent {
                event_id: observation.event_id,
                record_id: observation.record_id,
                status: event_status,
                message,
                timestamp: context_timestamp(&observation.context),
                named_data: observation.named_data.clone(),
                evidence: vec![observation.context.evidence_ref.clone()],
            });
        }
    }

    fn process_ime(&mut self, ordinal: usize, observation: &EspImeObservation) {
        self.push_timeline(
            ordinal,
            &observation.context,
            EspTimelineKind::Workload,
            observation.message.clone(),
            observation.app_id.clone(),
            observation.status.clone(),
        );
    }

    fn process_deployment_log(
        &mut self,
        ordinal: usize,
        observation: &EspDeploymentLogObservation,
    ) {
        self.push_timeline(
            ordinal,
            &observation.context,
            EspTimelineKind::Workload,
            observation.message.clone(),
            observation.product_code.clone(),
            observation.status.clone(),
        );
    }

    fn process_process(&mut self, ordinal: usize, observation: &EspProcessObservation) {
        self.push_timeline(
            ordinal,
            &observation.context,
            EspTimelineKind::Process,
            observation.executable_name.clone(),
            Some(format!("PID {}", observation.pid)),
            None,
        );
    }

    fn process_system(&mut self, observation: &EspSystemObservation) {
        match &observation.fact {
            EspSystemFact::Elevation(value) => self.elevation = value.clone(),
            EspSystemFact::Hostname(value) => {
                self.identity.device_name = Some(value.clone());
                self.identity
                    .evidence
                    .push(observation.context.evidence_ref.clone());
            }
            EspSystemFact::OsVersion(value) => {
                self.ensure_hardware().os_version = Some(value.clone())
            }
            EspSystemFact::OsBuild(value) => self.ensure_hardware().os_build = Some(value.clone()),
            EspSystemFact::Manufacturer(value) => {
                self.ensure_hardware().manufacturer = Some(value.clone())
            }
            EspSystemFact::Model(value) => self.ensure_hardware().model = Some(value.clone()),
            EspSystemFact::SerialNumber(value) => {
                self.ensure_hardware().serial_number = Some(sensitive_string(value.clone()));
                self.identity.serial_number = Some(sensitive_string(value.clone()));
                self.identity
                    .evidence
                    .push(observation.context.evidence_ref.clone());
            }
            EspSystemFact::TpmVersion(value) => {
                self.ensure_hardware().tpm_version = Some(value.clone())
            }
        }
        if !matches!(observation.fact, EspSystemFact::Elevation(_)) {
            self.ensure_hardware()
                .evidence
                .push(observation.context.evidence_ref.clone());
        }
    }

    fn process_delivery_optimization(
        &mut self,
        ordinal: usize,
        observation: &EspDeliveryOptimizationObservation,
    ) {
        let transfer = EspDeliveryOptimizationTransfer {
            transfer_id: self.record_id("transfer", &observation.context, ordinal),
            kind: observation.kind.clone(),
            content_id: observation.content_id.clone(),
            app_id: observation.app_id.clone(),
            timestamp: context_timestamp(&observation.context),
            evidence: vec![observation.context.evidence_ref.clone()],
        };
        let delivery = self
            .delivery_optimization
            .get_or_insert_with(empty_delivery_optimization);
        if let Some(value) = observation.http_bytes {
            delivery.download_http_bytes = value;
        }
        if let Some(value) = observation.lan_bytes {
            delivery.download_lan_bytes = value;
        }
        if let Some(value) = observation.cache_host_bytes {
            delivery.download_cache_host_bytes = value;
        }
        delivery.transfers.push(transfer);
        delivery
            .evidence
            .push(observation.context.evidence_ref.clone());

        let (detail, status) = match observation.kind {
            EspDeliveryOptimizationEventKind::DownloadStarted => {
                ("Download started", EspNormalizedStatus::Downloading)
            }
            EspDeliveryOptimizationEventKind::DownloadCompleted => {
                ("Download completed", EspNormalizedStatus::Downloaded)
            }
        };
        self.push_timeline(
            ordinal,
            &observation.context,
            EspTimelineKind::DeliveryOptimization,
            observation
                .app_id
                .clone()
                .unwrap_or_else(|| "Delivery Optimization".to_string()),
            Some(detail.to_string()),
            Some(text_status(detail, status)),
        );
    }

    fn process_delivery_optimization_summary(&mut self, summary: &EspDeliveryOptimizationEvidence) {
        let delivery = self
            .delivery_optimization
            .get_or_insert_with(empty_delivery_optimization);
        delivery.download_http_bytes = summary.download_http_bytes;
        delivery.download_lan_bytes = summary.download_lan_bytes;
        delivery.download_cache_host_bytes = summary.download_cache_host_bytes;
        delivery.peer_share_percent = summary.peer_share_percent;
        delivery.connected_cache_share_percent = summary.connected_cache_share_percent;
        delivery.transfers.extend(summary.transfers.iter().cloned());
        delivery.evidence.extend(summary.evidence.iter().cloned());
    }

    fn process_coverage(&mut self, ordinal: usize, coverage: EspArtifactCoverage) {
        let source = coverage
            .evidence
            .first()
            .map(|evidence| evidence.source_artifact_id.clone())
            .unwrap_or_else(|| coverage.artifact_id.clone());
        let evidence_id = coverage
            .evidence
            .first()
            .map(|evidence| evidence.evidence_id.clone())
            .unwrap_or_else(|| coverage.artifact_id.clone());
        let context = synthetic_context(
            EspSourceKind::Coverage,
            &source,
            &evidence_id,
            &coverage.observed_at_utc,
        );
        self.push_timeline(
            ordinal,
            &context,
            EspTimelineKind::Coverage,
            coverage.family.clone(),
            coverage.detail.clone(),
            Some(text_status(
                &format!("{:?}", coverage.status),
                match coverage.status {
                    EspArtifactStatus::Available => EspNormalizedStatus::Processed,
                    EspArtifactStatus::Missing
                    | EspArtifactStatus::PermissionDenied
                    | EspArtifactStatus::ParseFailed
                    | EspArtifactStatus::Unsupported => EspNormalizedStatus::Unknown,
                },
            )),
        );
        self.coverage.push(coverage);
    }

    fn process_node_cache(&mut self, observation: &EspRegistryObservation) -> bool {
        if !observation.key.to_ascii_lowercase().contains("nodecache") {
            return false;
        }
        let Some(index) =
            last_path_component(&observation.key).and_then(|value| value.parse::<u64>().ok())
        else {
            return false;
        };
        let value_name = observation.value_name.to_ascii_lowercase();
        if !matches!(value_name.as_str(), "nodeuri" | "expectedvalue") {
            return false;
        }
        let Some(value) = observation_text(&observation.value) else {
            return false;
        };
        let entry = self
            .node_cache
            .entry(index)
            .or_insert_with(|| NodeCacheAccumulator {
                node_uri: None,
                expected_value: None,
                sensitivity: observation.context.sensitivity.clone(),
                evidence: Vec::new(),
            });
        match value_name.as_str() {
            "nodeuri" => entry.node_uri = Some(value),
            "expectedvalue" => entry.expected_value = Some(value),
            _ => unreachable!("value name was validated above"),
        }
        entry.sensitivity =
            more_restrictive_sensitivity(&entry.sensitivity, &observation.context.sensitivity);
        entry
            .evidence
            .push(observation.context.evidence_ref.clone());
        true
    }

    fn process_enrollment(&mut self, observation: &EspRegistryObservation) -> bool {
        let components = path_components(&observation.key);
        let Some(enrollments_index) = components
            .iter()
            .position(|part| part.eq_ignore_ascii_case("enrollments"))
        else {
            return false;
        };
        let Some(enrollment_id) = components.get(enrollments_index + 1) else {
            return false;
        };
        let Some(update) = enrollment_update(observation) else {
            return false;
        };
        let entry = if let Some(index) = self
            .enrollments
            .iter()
            .position(|entry| entry.enrollment_id == *enrollment_id)
        {
            &mut self.enrollments[index]
        } else {
            self.enrollments.push(EspEnrollmentEvidence {
                enrollment_id: enrollment_id.clone(),
                provider_id: None,
                tenant_id: None,
                user_principal_name: None,
                entdm_id: None,
                settings: EspEnrollmentSettings {
                    device_esp_enabled: None,
                    user_esp_enabled: None,
                    timeout_seconds: None,
                    blocking: None,
                    allow_reset: None,
                    allow_retry: None,
                    continue_anyway: None,
                },
                evidence: Vec::new(),
            });
            self.enrollments.last_mut().expect("just inserted")
        };
        match update {
            EnrollmentUpdate::ProviderId(value) => entry.provider_id = Some(value),
            EnrollmentUpdate::TenantId(value) => entry.tenant_id = Some(sensitive_string(value)),
            EnrollmentUpdate::UserPrincipalName(value) => {
                entry.user_principal_name = Some(sensitive_string(value))
            }
            EnrollmentUpdate::EntdmId(value) => entry.entdm_id = Some(sensitive_string(value)),
            EnrollmentUpdate::DeviceEspEnabled(value) => {
                entry.settings.device_esp_enabled = Some(value)
            }
            EnrollmentUpdate::UserEspEnabled(value) => {
                entry.settings.user_esp_enabled = Some(value)
            }
            EnrollmentUpdate::TimeoutSeconds(value) => entry.settings.timeout_seconds = Some(value),
            EnrollmentUpdate::Blocking(bits) => {
                entry.settings.blocking = Some(bits != 0);
                entry.settings.allow_reset = Some(bits & 1 != 0);
                entry.settings.allow_retry = Some(bits & 2 != 0);
                entry.settings.continue_anyway = Some(bits & 4 != 0);
            }
        }
        entry
            .evidence
            .push(observation.context.evidence_ref.clone());
        true
    }

    fn process_classic_workload(
        &mut self,
        ordinal: usize,
        observation: &EspRegistryObservation,
        session_info: ClassicSessionInfo,
    ) {
        let Some(kind) = classic_workload_kind(&session_info.family, &observation.value_name)
        else {
            return;
        };
        let raw_identifier = classic_raw_identifier(&kind, &observation.value_name);
        let source = &observation.context.provenance.source_artifact_id;
        let session_identity = classic_session_identity(&session_info);
        let session_id = classic_session_id(source, &session_info);
        let started_at = normalize_timestamp(&session_info.raw_time, None);
        let user_sid = session_info
            .user_sid
            .as_ref()
            .map(|value| sensitive_string(value.clone()));
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.session_id == session_id)
        {
            session
                .evidence
                .push(observation.context.evidence_ref.clone());
        } else {
            self.sessions.push(EspSession {
                session_id: session_id.clone(),
                kind: EspSessionKind::Classic,
                scope: session_info.scope.clone(),
                user_sid,
                started_at: Some(started_at),
                ended_at: None,
                phase: match session_info.scope {
                    EspScope::Device => EspPhase::DeviceSetup,
                    EspScope::User => EspPhase::AccountSetup,
                },
                is_latest: false,
                workload_ids: Vec::new(),
                evidence: vec![observation.context.evidence_ref.clone()],
            });
        }

        let workload_identity = format!(
            "{}:{}:{}",
            session_identity,
            tracked_kind_name(&kind),
            raw_identifier
        );
        let workload_id = format!(
            "workload|{}|{}|0",
            escape_component(source),
            escape_component(&workload_identity)
        );
        let raw_status = if kind == EspTrackedKind::Msi {
            EspRawStatus::Number(0)
        } else {
            observation_raw_status(&observation.value)
        };
        let normalized_status = normalize_for_kind(&kind, raw_status);
        let observed = context_timestamp(&observation.context);
        let timestamps = workload_timestamps(observed.clone(), &normalized_status.normalized);

        if let Some(workload) = self
            .workloads
            .iter_mut()
            .find(|workload| workload.workload_id == workload_id)
        {
            let replace_status = workload
                .timestamps
                .last_updated
                .as_ref()
                .map(|current| {
                    timestamp_chronology_key(&observed) >= timestamp_chronology_key(current)
                })
                .unwrap_or(true);
            merge_workload_timestamps(&mut workload.timestamps, timestamps);
            if replace_status {
                workload.status = normalized_status.clone();
            }
            workload
                .evidence
                .push(observation.context.evidence_ref.clone());
        } else {
            self.workloads.push(EspWorkload {
                workload_id: workload_id.clone(),
                session_id: session_id.clone(),
                kind: kind.clone(),
                scope: session_info.scope,
                raw_identifier: raw_identifier.clone(),
                display_name: None,
                status: normalized_status.clone(),
                timestamps,
                exit_code: None,
                enforcement_error_code: None,
                blocking: None,
                evidence: vec![observation.context.evidence_ref.clone()],
            });
        }
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|session| session.session_id == session_id)
        {
            if !session.workload_ids.contains(&workload_id) {
                session.workload_ids.push(workload_id);
            }
        }
        self.push_timeline(
            ordinal,
            &observation.context,
            EspTimelineKind::Workload,
            raw_identifier,
            Some(tracked_kind_name(&kind).to_string()),
            Some(normalized_status),
        );
    }

    fn accumulate_v2_workload(&mut self, ordinal: usize, observation: &EspJsonObservation) {
        let components: Vec<&str> = observation
            .json_pointer
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        if components.len() < 3 || !components[0].eq_ignore_ascii_case("Workloads") {
            return;
        }
        let Ok(index) = components[1].parse::<usize>() else {
            return;
        };
        let field = components[2].to_ascii_lowercase();
        if !matches!(
            field.as_str(),
            "workloadid"
                | "friendlyname"
                | "workloadstate"
                | "starttime"
                | "endtime"
                | "errorcode"
                | "enforcementerrorcode"
        ) {
            return;
        }
        let key = (
            observation.context.provenance.source_artifact_id.clone(),
            v2_document_identity(observation),
            index,
        );
        let entry = self
            .v2_workloads
            .entry(key)
            .or_insert_with(|| V2WorkloadAccumulator {
                workload_id: None,
                friendly_name: None,
                started: Vec::new(),
                ended: Vec::new(),
                exit_codes: Vec::new(),
                enforcement_error_codes: Vec::new(),
                evidence: Vec::new(),
                observations: Vec::new(),
                states: Vec::new(),
            });
        match field.as_str() {
            "workloadid" => entry.workload_id = observation_text(&observation.value),
            "friendlyname" => entry.friendly_name = observation_text(&observation.value),
            "workloadstate" => {
                entry.states.push(V2StateOccurrence {
                    ordinal,
                    context: observation.context.clone(),
                    raw_status: observation_raw_status(&observation.value),
                });
            }
            "starttime" => {
                if let Some(timestamp) = timestamp_from_observation_value(&observation.value) {
                    entry.started.push(V2TimestampOccurrence {
                        ordinal,
                        context: observation.context.clone(),
                        timestamp,
                    });
                }
            }
            "endtime" => {
                if let Some(timestamp) = timestamp_from_observation_value(&observation.value) {
                    entry.ended.push(V2TimestampOccurrence {
                        ordinal,
                        context: observation.context.clone(),
                        timestamp,
                    });
                }
            }
            "errorcode" => {
                if let Some(raw) = observation_text(&observation.value) {
                    entry.exit_codes.push(DeferredCodeOccurrence {
                        ordinal,
                        code: error_code(&raw),
                        is_enforcement: false,
                        context: observation.context.clone(),
                    });
                }
            }
            "enforcementerrorcode" => {
                if let Some(raw) = observation_text(&observation.value) {
                    entry.enforcement_error_codes.push(DeferredCodeOccurrence {
                        ordinal,
                        code: error_code(&raw),
                        is_enforcement: true,
                        context: observation.context.clone(),
                    });
                }
            }
            _ => unreachable!("field was validated above"),
        }
        entry.observations.push(observation.context.clone());
        entry
            .evidence
            .push(observation.context.evidence_ref.clone());
    }

    fn accumulate_platform_script(&mut self, ordinal: usize, observation: &EspRegistryObservation) {
        let raw_identifier =
            last_path_component(&observation.key).unwrap_or_else(|| observation.value_name.clone());
        let key = (
            observation.context.provenance.source_artifact_id.clone(),
            raw_identifier.clone(),
        );
        let entry = self
            .platform_scripts
            .entry(key)
            .or_insert_with(|| PlatformScriptAccumulator {
                raw_identifier,
                results: Vec::new(),
                last_updated: Vec::new(),
                evidence: Vec::new(),
            });
        entry
            .evidence
            .push(observation.context.evidence_ref.clone());
        if observation.value_name.eq_ignore_ascii_case("Result") {
            entry.results.push((ordinal, observation.clone()));
        } else if observation
            .value_name
            .eq_ignore_ascii_case("LastUpdatedTimeUtc")
        {
            if let Some(timestamp) = timestamp_from_observation_value(&observation.value) {
                entry.last_updated.push(V2TimestampOccurrence {
                    ordinal,
                    context: observation.context.clone(),
                    timestamp,
                });
            }
        }
    }

    fn accumulate_enforcement_message(&mut self, ordinal: usize, observation: &EspJsonObservation) {
        let field = observation
            .json_pointer
            .split('/')
            .rfind(|part| !part.is_empty())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let key = enforcement_message_group_key(observation);
        let entry =
            self.enforcement_messages
                .entry(key)
                .or_insert_with(|| EnforcementMessageAccumulator {
                    identifier: None,
                    scope: None,
                    user_sid: None,
                    codes: Vec::new(),
                });
        match field.as_str() {
            "applicationid" | "appid" | "workloadid" | "policyid" | "id" => {
                entry.identifier = observation_text(&observation.value)
            }
            "usersid" | "sid" => {
                entry.user_sid = observation_text(&observation.value);
                entry.scope = Some(EspScope::User);
            }
            "scope" => {
                entry.scope = observation_text(&observation.value).and_then(|value| {
                    if value.eq_ignore_ascii_case("device") {
                        Some(EspScope::Device)
                    } else if value.eq_ignore_ascii_case("user") {
                        Some(EspScope::User)
                    } else {
                        None
                    }
                });
            }
            "errorcode" | "enforcementerrorcode" | "exitcode" => {
                if let Some(raw) = observation_text(&observation.value) {
                    entry.codes.push(DeferredCodeOccurrence {
                        ordinal,
                        code: error_code(&raw),
                        is_enforcement: !field.eq_ignore_ascii_case("exitcode"),
                        context: observation.context.clone(),
                    });
                }
            }
            _ => {}
        }
    }

    fn push_code_timeline(
        &mut self,
        ordinal: usize,
        context: &EspObservationContext,
        title: String,
        code: &EspErrorCode,
        is_enforcement: bool,
    ) {
        let code_kind = if is_enforcement {
            "Enforcement error code"
        } else {
            "Exit code"
        };
        let detail = format!("{code_kind} {}", code.raw);
        self.push_timeline(
            ordinal,
            context,
            EspTimelineKind::Workload,
            title,
            Some(detail.clone()),
            Some(text_status(&detail, error_code_normalized_status(code))),
        );
    }

    fn push_timeline(
        &mut self,
        ordinal: usize,
        context: &EspObservationContext,
        kind: EspTimelineKind,
        title: String,
        detail: Option<String>,
        status: Option<EspStatus>,
    ) {
        self.activity.push((
            ordinal,
            EspTimelineEntry {
                entry_id: self.timeline_entry_id(context, ordinal),
                timestamp: context_timestamp(context),
                kind,
                title,
                detail,
                status,
                evidence: vec![context.evidence_ref.clone()],
            },
        ));
    }

    fn push_workload_timeline_at(
        &mut self,
        ordinal: usize,
        context: &EspObservationContext,
        timestamp: EspTimestamp,
        title: String,
        detail: Option<String>,
        status: Option<EspStatus>,
    ) {
        self.activity.push((
            ordinal,
            EspTimelineEntry {
                entry_id: self.timeline_entry_id(context, ordinal),
                timestamp,
                kind: EspTimelineKind::Workload,
                title,
                detail,
                status,
                evidence: vec![context.evidence_ref.clone()],
            },
        ));
    }

    fn ensure_profile(&mut self) -> &mut EspProfileEvidence {
        self.profile.get_or_insert_with(empty_profile)
    }

    fn occurrence_ordinal(&self, ordinal: usize) -> usize {
        self.occurrence_ordinals
            .get(&ordinal)
            .copied()
            .unwrap_or(ordinal)
    }

    fn timeline_entry_id(&self, context: &EspObservationContext, ordinal: usize) -> String {
        stable_timeline_entry_id(context, self.occurrence_ordinal(ordinal))
    }

    fn record_id(&self, prefix: &str, context: &EspObservationContext, ordinal: usize) -> String {
        stable_record_id(prefix, context, self.occurrence_ordinal(ordinal))
    }

    fn ensure_device_preparation(&mut self) -> &mut EspDevicePreparationEvidence {
        let profile = self.ensure_profile();
        profile
            .device_preparation
            .get_or_insert_with(empty_device_preparation)
    }

    fn ensure_hardware(&mut self) -> &mut EspHardwareEvidence {
        self.hardware.get_or_insert_with(empty_hardware)
    }

    fn add_profile_evidence(&mut self, evidence: &EspEvidenceRef) {
        self.ensure_profile().evidence.push(evidence.clone());
    }

    fn add_identity_and_profile_evidence(&mut self, evidence: &EspEvidenceRef) {
        self.identity.evidence.push(evidence.clone());
        self.add_profile_evidence(evidence);
    }

    fn finish(mut self) -> EspDiagnosticsSnapshot {
        self.finalize_v2_workloads();
        self.finalize_platform_scripts();
        self.apply_office_details();
        self.apply_msi_details();
        self.finalize_enforcement_messages();
        self.apply_graph_names();
        self.finalize_sessions();
        self.apply_deferred_error_codes();
        self.finalize_delivery_optimization();

        let phase = snapshot_phase(&self.scenario, &self.sessions);
        let node_cache = self
            .node_cache
            .into_iter()
            .map(|(index, entry)| EspNodeCacheEntry {
                index,
                node_uri: entry.node_uri.unwrap_or_default(),
                expected_value: entry.expected_value,
                sensitivity: entry.sensitivity,
                evidence: entry.evidence,
            })
            .collect();
        let mut snapshot = EspDiagnosticsSnapshot {
            schema_version: ESP_DIAGNOSTICS_SCHEMA_VERSION,
            scenario: self.scenario,
            phase,
            generated_at_utc: self.generated_at_utc,
            elevation: self.elevation,
            identity: self.identity,
            profile: self.profile,
            enrollments: self.enrollments,
            sessions: self.sessions,
            workloads: self.workloads,
            installer_correlations: Vec::new(),
            node_cache,
            registration_events: self.registration_events,
            delivery_optimization: self.delivery_optimization,
            hardware: self.hardware,
            activity: sort_timeline_entries(self.activity),
            findings: Vec::new(),
            coverage: self.coverage,
            raw_evidence: self.raw_evidence,
            graph: None,
        };
        snapshot.findings = derive_findings(&snapshot);
        snapshot
    }

    fn finalize_v2_workloads(&mut self) {
        let accumulators = std::mem::take(&mut self.v2_workloads);
        for ((source, _document, index), entry) in accumulators {
            let raw_identifier = entry
                .workload_id
                .clone()
                .unwrap_or_else(|| format!("unknown-{index}"));
            let latest_state = entry.states.iter().max_by(|left, right| {
                context_chronology_key(&left.context)
                    .cmp(&context_chronology_key(&right.context))
                    .then_with(|| left.ordinal.cmp(&right.ordinal))
            });
            let raw_status = latest_state
                .map(|state| state.raw_status.clone())
                .unwrap_or_else(|| EspRawStatus::Text("missing".to_string()));
            let normalized_status = normalize_v2_status(raw_status);
            let session_identity = "devicePreparationV2:device:ProvisioningProgress";
            let session_id = format!(
                "session|{}|{}|0",
                escape_component(&source),
                session_identity
            );
            let first_observed = entry
                .observations
                .iter()
                .min_by(|left, right| {
                    context_chronology_key(left).cmp(&context_chronology_key(right))
                })
                .map(context_timestamp)
                .unwrap_or_else(|| normalize_timestamp(&self.generated_at_utc, None));
            let started = entry
                .started
                .iter()
                .min_by(|left, right| {
                    timestamp_chronology_key(&left.timestamp)
                        .cmp(timestamp_chronology_key(&right.timestamp))
                        .then_with(|| left.ordinal.cmp(&right.ordinal))
                })
                .map(|occurrence| occurrence.timestamp.clone());
            let ended = entry
                .ended
                .iter()
                .max_by(|left, right| {
                    timestamp_chronology_key(&left.timestamp)
                        .cmp(timestamp_chronology_key(&right.timestamp))
                        .then_with(|| left.ordinal.cmp(&right.ordinal))
                })
                .map(|occurrence| occurrence.timestamp.clone());
            let session_started = started.clone().unwrap_or_else(|| first_observed.clone());
            if let Some(session) = self
                .sessions
                .iter_mut()
                .find(|session| session.session_id == session_id)
            {
                merge_earliest_timestamp(&mut session.started_at, Some(session_started));
                merge_latest_timestamp(&mut session.ended_at, ended.clone());
                session.evidence.extend(entry.evidence.clone());
            } else {
                self.sessions.push(EspSession {
                    session_id: session_id.clone(),
                    kind: EspSessionKind::DevicePreparationV2,
                    scope: EspScope::Device,
                    user_sid: None,
                    started_at: Some(session_started),
                    ended_at: ended.clone(),
                    phase: EspPhase::DevicePreparation,
                    is_latest: false,
                    workload_ids: Vec::new(),
                    evidence: entry.evidence.clone(),
                });
            }
            let identity = format!("devicePreparationV2:device:{index}:{raw_identifier}");
            let workload_id = format!(
                "workload|{}|{}|0",
                escape_component(&source),
                escape_component(&identity)
            );
            let timestamps = EspWorkloadTimestamps {
                first_observed,
                started,
                ended,
                last_updated: latest_state.map(|state| context_timestamp(&state.context)),
            };
            let title = entry
                .friendly_name
                .clone()
                .unwrap_or_else(|| raw_identifier.clone());
            let exit_code =
                latest_code_occurrence(&entry.exit_codes).map(|occurrence| occurrence.code.clone());
            let enforcement_error_code = latest_code_occurrence(&entry.enforcement_error_codes)
                .map(|occurrence| occurrence.code.clone());
            self.workloads.push(EspWorkload {
                workload_id: workload_id.clone(),
                session_id: session_id.clone(),
                kind: EspTrackedKind::DevicePreparationWorkload,
                scope: EspScope::Device,
                raw_identifier: raw_identifier.clone(),
                display_name: entry.friendly_name.clone(),
                status: normalized_status.clone(),
                timestamps,
                exit_code,
                enforcement_error_code,
                blocking: None,
                evidence: entry.evidence.clone(),
            });
            if let Some(session) = self
                .sessions
                .iter_mut()
                .find(|session| session.session_id == session_id)
            {
                session.workload_ids.push(workload_id);
            }
            for state in entry.states {
                self.push_timeline(
                    state.ordinal,
                    &state.context,
                    EspTimelineKind::Workload,
                    title.clone(),
                    Some("devicePreparationWorkload".to_string()),
                    Some(normalize_v2_status(state.raw_status)),
                );
            }
            for occurrence in entry.started {
                self.push_workload_timeline_at(
                    occurrence.ordinal,
                    &occurrence.context,
                    occurrence.timestamp,
                    title.clone(),
                    Some("Installation started".to_string()),
                    Some(text_status(
                        "Installation started",
                        EspNormalizedStatus::Installing,
                    )),
                );
            }
            for occurrence in entry.ended {
                self.push_workload_timeline_at(
                    occurrence.ordinal,
                    &occurrence.context,
                    occurrence.timestamp,
                    title.clone(),
                    Some("Installation ended".to_string()),
                    Some(normalized_status.clone()),
                );
            }
            for occurrence in entry
                .exit_codes
                .into_iter()
                .chain(entry.enforcement_error_codes)
            {
                self.push_code_timeline(
                    occurrence.ordinal,
                    &occurrence.context,
                    title.clone(),
                    &occurrence.code,
                    occurrence.is_enforcement,
                );
            }
        }
    }

    fn finalize_platform_scripts(&mut self) {
        let scripts = std::mem::take(&mut self.platform_scripts);
        for ((source, _), script) in scripts {
            let Some((_, latest_result)) = script.results.iter().max_by(|left, right| {
                context_chronology_key(&left.1.context)
                    .cmp(&context_chronology_key(&right.1.context))
                    .then_with(|| left.0.cmp(&right.0))
            }) else {
                continue;
            };
            let status = text_status_from_observation(&latest_result.value);
            let first_observed = script
                .results
                .iter()
                .map(|(_, observation)| context_timestamp(&observation.context))
                .chain(
                    script
                        .last_updated
                        .iter()
                        .map(|occurrence| context_timestamp(&occurrence.context)),
                )
                .min_by(|left, right| {
                    timestamp_chronology_key(left).cmp(timestamp_chronology_key(right))
                })
                .unwrap_or_else(|| normalize_timestamp(&self.generated_at_utc, None));
            let mut timestamps = workload_timestamps(
                context_timestamp(&script.results[0].1.context),
                &text_status_from_observation(&script.results[0].1.value).normalized,
            );
            for (_, observation) in script.results.iter().skip(1) {
                let occurrence_status = text_status_from_observation(&observation.value);
                merge_workload_timestamps(
                    &mut timestamps,
                    workload_timestamps(
                        context_timestamp(&observation.context),
                        &occurrence_status.normalized,
                    ),
                );
            }
            timestamps.first_observed = first_observed.clone();
            for occurrence in &script.last_updated {
                merge_latest_timestamp(
                    &mut timestamps.last_updated,
                    Some(occurrence.timestamp.clone()),
                );
            }

            let candidate_sessions = self
                .sessions
                .iter()
                .filter(|session| session.kind == EspSessionKind::DevicePreparationV2)
                .collect::<Vec<_>>();
            let session_id = candidate_sessions
                .iter()
                .copied()
                .find(|session| {
                    session
                        .evidence
                        .iter()
                        .any(|evidence| evidence.source_artifact_id == source)
                })
                .or_else(|| (candidate_sessions.len() == 1).then(|| candidate_sessions[0]))
                .map(|session| session.session_id.clone())
                .unwrap_or_else(|| {
                    format!(
                        "session|{}|devicePreparationV2:device:Policies|0",
                        escape_component(&source)
                    )
                });
            if !self
                .sessions
                .iter()
                .any(|session| session.session_id == session_id)
            {
                self.sessions.push(EspSession {
                    session_id: session_id.clone(),
                    kind: EspSessionKind::DevicePreparationV2,
                    scope: EspScope::Device,
                    user_sid: None,
                    started_at: Some(first_observed.clone()),
                    ended_at: None,
                    phase: EspPhase::DevicePreparation,
                    is_latest: false,
                    workload_ids: Vec::new(),
                    evidence: script.evidence.clone(),
                });
            } else if let Some(session) = self
                .sessions
                .iter_mut()
                .find(|session| session.session_id == session_id)
            {
                merge_earliest_timestamp(&mut session.started_at, Some(first_observed));
                session.evidence.extend(script.evidence.clone());
            }
            let workload_id = format!(
                "workload|{}|{}|0",
                escape_component(&source),
                escape_component(&format!("platformScript:{}", script.raw_identifier))
            );
            self.workloads.push(EspWorkload {
                workload_id: workload_id.clone(),
                session_id: session_id.clone(),
                kind: EspTrackedKind::PlatformScript,
                scope: EspScope::Device,
                raw_identifier: script.raw_identifier.clone(),
                display_name: None,
                status: status.clone(),
                timestamps,
                exit_code: None,
                enforcement_error_code: None,
                blocking: None,
                evidence: script.evidence.clone(),
            });
            if let Some(session) = self
                .sessions
                .iter_mut()
                .find(|session| session.session_id == session_id)
            {
                if !session.workload_ids.contains(&workload_id) {
                    session.workload_ids.push(workload_id);
                }
            }
            for (ordinal, observation) in script.results {
                self.push_timeline(
                    ordinal,
                    &observation.context,
                    EspTimelineKind::Workload,
                    script.raw_identifier.clone(),
                    Some("platformScript".to_string()),
                    Some(text_status_from_observation(&observation.value)),
                );
            }
        }
    }

    fn finalize_enforcement_messages(&mut self) {
        let messages = std::mem::take(&mut self.enforcement_messages);
        for (_, message) in messages {
            for occurrence in message.codes {
                self.deferred_error_codes.push(DeferredErrorCode {
                    identifier: message.identifier.clone(),
                    explicit_session: None,
                    scope: message.scope.clone(),
                    user_sid: message.user_sid.clone(),
                    kind: Some(EspTrackedKind::DevicePreparationWorkload),
                    code: occurrence.code,
                    is_enforcement: occurrence.is_enforcement,
                    ordinal: occurrence.ordinal,
                    context: occurrence.context,
                });
            }
        }
    }

    fn apply_deferred_error_codes(&mut self) {
        for deferred in std::mem::take(&mut self.deferred_error_codes) {
            let title = deferred
                .identifier
                .clone()
                .unwrap_or_else(|| "Uncorrelated workload".to_string());
            self.push_code_timeline(
                deferred.ordinal,
                &deferred.context,
                title,
                &deferred.code,
                deferred.is_enforcement,
            );
            let Some(identifier) = deferred.identifier.as_deref() else {
                continue;
            };
            let candidates = self
                .workloads
                .iter()
                .enumerate()
                .filter_map(|(index, workload)| {
                    if !identifiers_match(&workload.raw_identifier, identifier)
                        || deferred
                            .kind
                            .as_ref()
                            .map(|kind| kind != &workload.kind)
                            .unwrap_or(false)
                    {
                        return None;
                    }
                    let session = self
                        .sessions
                        .iter()
                        .find(|session| session.session_id == workload.session_id)?;
                    if let Some(explicit_session) = &deferred.explicit_session {
                        return deferred_session_matches(session, explicit_session)
                            .then_some(index);
                    }
                    if !session.is_latest {
                        return None;
                    }
                    if deferred
                        .scope
                        .as_ref()
                        .map(|scope| scope != &session.scope)
                        .unwrap_or(false)
                    {
                        return None;
                    }
                    if let Some(user_sid) = &deferred.user_sid {
                        if session.user_sid.as_ref().map(|sid| sid.value.as_str())
                            != Some(user_sid.as_str())
                        {
                            return None;
                        }
                    }
                    Some(index)
                })
                .collect::<Vec<_>>();
            if let [index] = candidates.as_slice() {
                let workload = &mut self.workloads[*index];
                if deferred.is_enforcement {
                    workload.enforcement_error_code = Some(deferred.code);
                } else {
                    workload.exit_code = Some(deferred.code);
                }
                workload
                    .evidence
                    .push(deferred.context.evidence_ref.clone());
            }
        }
    }

    fn apply_office_details(&mut self) {
        let mut details_by_identifier: BTreeMap<String, Vec<OfficeDetailObservation>> =
            BTreeMap::new();
        for detail in std::mem::take(&mut self.office_details) {
            details_by_identifier
                .entry(identifier_match_key(&detail.identifier))
                .or_default()
                .push(detail);
        }
        for details in details_by_identifier.into_values() {
            let Some(best) = details.into_iter().max_by(|left, right| {
                left.is_final
                    .cmp(&right.is_final)
                    .then_with(|| {
                        context_chronology_key(&left.context)
                            .cmp(&context_chronology_key(&right.context))
                    })
                    .then_with(|| left.ordinal.cmp(&right.ordinal))
            }) else {
                continue;
            };
            let matching = self
                .workloads
                .iter()
                .enumerate()
                .filter_map(|(index, workload)| {
                    if workload.kind != EspTrackedKind::Office
                        || !identifiers_match(&workload.raw_identifier, &best.identifier)
                    {
                        return None;
                    }
                    let session = self
                        .sessions
                        .iter()
                        .find(|session| session.session_id == workload.session_id)?;
                    Some((index, session_chronology(session).to_string()))
                })
                .collect::<Vec<_>>();
            let latest = matching.iter().map(|(_, key)| key).max().cloned();
            let candidates = matching
                .iter()
                .filter(|(_, key)| Some(key) == latest.as_ref())
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            let [index] = candidates.as_slice() else {
                continue;
            };
            let identifier = self.workloads[*index].raw_identifier.clone();
            let status = normalize_office_status(
                self.workloads[*index].status.raw.clone(),
                Some(best.raw_status.clone()),
            );
            let workload_evidence = self.workloads[*index].evidence.clone();
            let observed = context_timestamp(&best.context);
            let timestamps = workload_timestamps(observed, &status.normalized);
            merge_workload_timestamps(&mut self.workloads[*index].timestamps, timestamps);
            self.workloads[*index]
                .evidence
                .push(best.context.evidence_ref.clone());
            self.workloads[*index].status = status.clone();

            for (_, activity) in &mut self.activity {
                if activity.title == identifier
                    && activity
                        .evidence
                        .iter()
                        .any(|evidence| workload_evidence.contains(evidence))
                {
                    activity.status = Some(status.clone());
                }
            }
            self.push_timeline(
                best.ordinal,
                &best.context,
                EspTimelineKind::Workload,
                identifier,
                Some("Office detailed status".to_string()),
                Some(status),
            );
        }
    }

    fn apply_msi_details(&mut self) {
        for detail in std::mem::take(&mut self.msi_details) {
            let matching = self
                .workloads
                .iter()
                .enumerate()
                .filter_map(|(index, workload)| {
                    if workload.kind != EspTrackedKind::Msi
                        || !identifiers_match(&workload.raw_identifier, &detail.identifier)
                        || detail
                            .scope
                            .as_ref()
                            .map(|scope| scope != &workload.scope)
                            .unwrap_or(false)
                    {
                        return None;
                    }
                    let session = self
                        .sessions
                        .iter()
                        .find(|session| session.session_id == workload.session_id)?;
                    if let Some(user_sid) = &detail.user_sid {
                        if session.user_sid.as_ref().map(|sid| sid.value.as_str())
                            != Some(user_sid.as_str())
                        {
                            return None;
                        }
                    }
                    Some((index, session_chronology(session).to_string()))
                })
                .collect::<Vec<_>>();
            let latest = matching.iter().map(|(_, key)| key).max().cloned();
            let candidates = matching
                .iter()
                .filter(|(_, key)| Some(key) == latest.as_ref())
                .map(|(index, _)| *index)
                .collect::<Vec<_>>();
            let status = normalize_office_detail_status(detail.raw_status.clone());
            if let [index] = candidates.as_slice() {
                let workload = &mut self.workloads[*index];
                merge_workload_timestamps(
                    &mut workload.timestamps,
                    workload_timestamps(context_timestamp(&detail.context), &status.normalized),
                );
                workload.status = status.clone();
                workload.evidence.push(detail.context.evidence_ref.clone());
            }
            self.push_timeline(
                detail.ordinal,
                &detail.context,
                EspTimelineKind::Workload,
                detail.identifier,
                Some("MSI detailed status".to_string()),
                Some(status),
            );
        }
    }

    fn apply_graph_names(&mut self) {
        for graph in &self.graph_observations {
            for workload in self.workloads.iter_mut().filter(|workload| {
                graph_section_matches_workload(&graph.section, &workload.kind)
                    && identifiers_match(&workload.raw_identifier, &graph.record_id)
            }) {
                if let Some(display_name) = &graph.display_name {
                    workload.display_name = Some(display_name.clone());
                }
                workload.evidence.push(graph.context.evidence_ref.clone());
            }
        }
    }

    fn finalize_sessions(&mut self) {
        for session in &mut self.sessions {
            let session_workloads = session
                .workload_ids
                .iter()
                .filter_map(|id| {
                    self.workloads
                        .iter()
                        .find(|workload| &workload.workload_id == id)
                })
                .collect::<Vec<_>>();
            let statuses = session_workloads
                .iter()
                .map(|workload| &workload.status.normalized)
                .collect::<Vec<_>>();
            if statuses
                .iter()
                .any(|status| matches!(status, EspNormalizedStatus::Failed))
            {
                session.phase = EspPhase::Failed;
            } else if !statuses.is_empty()
                && statuses.iter().all(|status| {
                    matches!(
                        status,
                        EspNormalizedStatus::Succeeded | EspNormalizedStatus::Processed
                    )
                })
            {
                session.phase = EspPhase::Completed;
            }
            if matches!(session.phase, EspPhase::Completed | EspPhase::Failed) {
                let latest_end = session_workloads
                    .iter()
                    .filter_map(|workload| workload.timestamps.ended.as_ref())
                    .max_by(|left, right| {
                        timestamp_chronology_key(left).cmp(timestamp_chronology_key(right))
                    })
                    .cloned();
                merge_latest_timestamp(&mut session.ended_at, latest_end);
            }
        }

        self.sessions.sort_by(|left, right| {
            session_group_sort_key(left)
                .cmp(&session_group_sort_key(right))
                .then_with(|| session_chronology(left).cmp(session_chronology(right)))
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        let mut latest_by_group: BTreeMap<String, usize> = BTreeMap::new();
        for (index, session) in self.sessions.iter().enumerate() {
            latest_by_group.insert(session_group_identity(session), index);
        }
        for index in latest_by_group.into_values() {
            self.sessions[index].is_latest = true;
        }
    }

    fn finalize_delivery_optimization(&mut self) {
        if let Some(delivery) = &mut self.delivery_optimization {
            if delivery.download_http_bytes == 0 {
                delivery.peer_share_percent = None;
                delivery.connected_cache_share_percent = None;
            } else {
                let download_http_bytes = delivery.download_http_bytes as f64;
                delivery.peer_share_percent =
                    Some(delivery.download_lan_bytes as f64 / download_http_bytes * 100.0);
                delivery.connected_cache_share_percent =
                    Some(delivery.download_cache_host_bytes as f64 / download_http_bytes * 100.0);
            }
        }
    }
}

#[derive(Debug)]
struct NodeCacheAccumulator {
    node_uri: Option<String>,
    expected_value: Option<String>,
    sensitivity: EspSensitivity,
    evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug)]
struct V2WorkloadAccumulator {
    workload_id: Option<String>,
    friendly_name: Option<String>,
    started: Vec<V2TimestampOccurrence>,
    ended: Vec<V2TimestampOccurrence>,
    exit_codes: Vec<DeferredCodeOccurrence>,
    enforcement_error_codes: Vec<DeferredCodeOccurrence>,
    evidence: Vec<EspEvidenceRef>,
    observations: Vec<EspObservationContext>,
    states: Vec<V2StateOccurrence>,
}

#[derive(Debug)]
struct V2StateOccurrence {
    ordinal: usize,
    context: EspObservationContext,
    raw_status: EspRawStatus,
}

#[derive(Debug, Clone)]
struct V2TimestampOccurrence {
    ordinal: usize,
    context: EspObservationContext,
    timestamp: EspTimestamp,
}

#[derive(Debug)]
struct PlatformScriptAccumulator {
    raw_identifier: String,
    results: Vec<(usize, EspRegistryObservation)>,
    last_updated: Vec<V2TimestampOccurrence>,
    evidence: Vec<EspEvidenceRef>,
}

#[derive(Debug, Clone)]
struct OfficeDetailObservation {
    ordinal: usize,
    identifier: String,
    raw_status: EspRawStatus,
    is_final: bool,
    context: EspObservationContext,
}

#[derive(Debug, Clone)]
struct MsiDetailObservation {
    ordinal: usize,
    identifier: String,
    scope: Option<EspScope>,
    user_sid: Option<String>,
    raw_status: EspRawStatus,
    context: EspObservationContext,
}

#[derive(Debug)]
struct EnforcementMessageAccumulator {
    identifier: Option<String>,
    scope: Option<EspScope>,
    user_sid: Option<String>,
    codes: Vec<DeferredCodeOccurrence>,
}

#[derive(Debug)]
struct DeferredCodeOccurrence {
    ordinal: usize,
    code: EspErrorCode,
    is_enforcement: bool,
    context: EspObservationContext,
}

#[derive(Debug)]
struct DeferredSessionIdentity {
    scope: EspScope,
    user_sid: Option<String>,
    raw_time: String,
}

#[derive(Debug)]
struct DeferredErrorCode {
    identifier: Option<String>,
    explicit_session: Option<DeferredSessionIdentity>,
    scope: Option<EspScope>,
    user_sid: Option<String>,
    kind: Option<EspTrackedKind>,
    code: EspErrorCode,
    is_enforcement: bool,
    ordinal: usize,
    context: EspObservationContext,
}

enum EnrollmentUpdate {
    ProviderId(String),
    TenantId(String),
    UserPrincipalName(String),
    EntdmId(String),
    DeviceEspEnabled(bool),
    UserEspEnabled(bool),
    TimeoutSeconds(u64),
    Blocking(u64),
}

struct ClassicSessionInfo {
    scope: EspScope,
    user_sid: Option<String>,
    family: String,
    raw_time: String,
}

fn classify_scenario<'a>(records: impl IntoIterator<Item = &'a EspEvidenceRecord>) -> EspScenario {
    let mut has_v2 = false;
    let mut has_profile_name = false;
    let mut has_existing_device_identity = false;
    let mut has_esp = false;
    for record in records {
        if !record_is_usable(record) {
            continue;
        }
        match record {
            EspEvidenceRecord::Registry(observation) => {
                let name = observation.value_name.to_ascii_lowercase();
                if name == "autopilotdeviceprephint" {
                    has_v2 = true;
                } else if name == "deploymentprofilename"
                    && observation_text(&observation.value)
                        .map(|value| !value.is_empty())
                        .unwrap_or(false)
                {
                    has_profile_name = true;
                } else if matches!(name.as_str(), "ztdcorrelationid" | "cloudassignedtenantid") {
                    has_existing_device_identity = true;
                }
                if observation.key.to_ascii_lowercase().contains("firstsync")
                    || classic_session_info(observation).is_some()
                {
                    has_esp = true;
                }
            }
            EspEvidenceRecord::Json(observation) => {
                has_v2 |= is_provisioning_progress(observation) || is_page_settings(observation);
                let has_value = observation_text(&observation.value)
                    .map(|value| !value.trim().is_empty())
                    .unwrap_or(false);
                if observation
                    .json_pointer
                    .eq_ignore_ascii_case("/DeploymentProfileName")
                    && has_value
                {
                    has_profile_name = true;
                }
                if observation
                    .json_pointer
                    .eq_ignore_ascii_case("/ZtdCorrelationId")
                    && has_value
                {
                    has_existing_device_identity = true;
                }
            }
            _ => {}
        }
    }
    if has_v2 {
        EspScenario::AutopilotDevicePreparationV2
    } else if has_profile_name {
        EspScenario::AutopilotV1
    } else if has_existing_device_identity {
        EspScenario::ExistingDeviceJson
    } else if has_esp {
        EspScenario::EspOnly
    } else {
        EspScenario::Unknown
    }
}

fn record_allowed_for_scenario(record: &EspEvidenceRecord, scenario: &EspScenario) -> bool {
    if !record_is_usable(record) {
        return true;
    }
    if *scenario == EspScenario::AutopilotDevicePreparationV2 {
        !matches!(record, EspEvidenceRecord::Registry(observation) if classic_session_info(observation).is_some())
    } else {
        !matches!(record, EspEvidenceRecord::Json(observation) if is_provisioning_progress(observation) || is_page_settings(observation))
            && !matches!(record, EspEvidenceRecord::Registry(observation) if is_platform_script_observation(observation))
    }
}

fn record_is_usable(record: &EspEvidenceRecord) -> bool {
    let Some(context) = record_context(record) else {
        return true;
    };
    context.access_state == EspSourceAccessState::Available
        && matches!(
            context.parse_state,
            EspParseState::Parsed | EspParseState::Raw
        )
}

fn record_context(record: &EspEvidenceRecord) -> Option<&EspObservationContext> {
    match record {
        EspEvidenceRecord::Registry(value) => Some(&value.context),
        EspEvidenceRecord::Json(value) => Some(&value.context),
        EspEvidenceRecord::EventLog(value) => Some(&value.context),
        EspEvidenceRecord::Ime(value) => Some(&value.context),
        EspEvidenceRecord::DeploymentLog(value) => Some(&value.context),
        EspEvidenceRecord::Process(value) => Some(&value.context),
        EspEvidenceRecord::System(value) => Some(&value.context),
        EspEvidenceRecord::DeliveryOptimizationSummary(_) => None,
        EspEvidenceRecord::DeliveryOptimization(value) => Some(&value.context),
        EspEvidenceRecord::Graph(value) => Some(&value.context),
        EspEvidenceRecord::Coverage(_) => None,
    }
}

fn record_occurrence_key(record: &EspEvidenceRecord) -> Option<(String, String)> {
    if let Some(context) = record_context(record) {
        return Some((
            context.provenance.source_artifact_id.clone(),
            context.evidence_ref.evidence_id.clone(),
        ));
    }
    let EspEvidenceRecord::Coverage(coverage) = record else {
        return None;
    };
    let evidence = coverage.evidence.first();
    Some((
        evidence
            .map(|value| value.source_artifact_id.clone())
            .unwrap_or_else(|| coverage.artifact_id.clone()),
        evidence
            .map(|value| value.evidence_id.clone())
            .unwrap_or_else(|| coverage.artifact_id.clone()),
    ))
}

fn raw_evidence_record(record: &EspEvidenceRecord, ordinal: usize) -> Option<EspRawEvidenceRecord> {
    let context = record_context(record)?;
    Some(EspRawEvidenceRecord {
        record_id: stable_record_id("raw", context, ordinal),
        provenance: context.provenance.clone(),
        source_timestamp: context.source_timestamp.clone(),
        observed_at_utc: context.observed_at_utc.clone(),
        raw_value: raw_observation_value(record),
        sensitivity: context.sensitivity.clone(),
        parse_state: context.parse_state.clone(),
        access_state: context.access_state.clone(),
        evidence: vec![context.evidence_ref.clone()],
    })
}

fn raw_observation_value(record: &EspEvidenceRecord) -> EspObservationValue {
    match record {
        EspEvidenceRecord::Registry(value) => value.value.clone(),
        EspEvidenceRecord::Json(value) => value.value.clone(),
        EspEvidenceRecord::EventLog(value) => value
            .message
            .clone()
            .map(EspObservationValue::Text)
            .unwrap_or_else(|| {
                EspObservationValue::StringList(
                    value
                        .named_data
                        .iter()
                        .map(|item| format!("{}={}", item.name, item.value))
                        .collect(),
                )
            }),
        EspEvidenceRecord::Ime(value) => EspObservationValue::Text(value.message.clone()),
        EspEvidenceRecord::DeploymentLog(value) => EspObservationValue::Text(value.message.clone()),
        EspEvidenceRecord::Process(value) => EspObservationValue::StringList(vec![
            value.pid.to_string(),
            value.executable_name.clone(),
            value.sanitized_command_line.clone().unwrap_or_default(),
        ]),
        EspEvidenceRecord::System(value) => system_fact_value(&value.fact),
        EspEvidenceRecord::DeliveryOptimizationSummary(value) => {
            EspObservationValue::StringList(vec![
                format!("httpBytes={}", value.download_http_bytes),
                format!("lanBytes={}", value.download_lan_bytes),
                format!("cacheHostBytes={}", value.download_cache_host_bytes),
            ])
        }
        EspEvidenceRecord::DeliveryOptimization(value) => EspObservationValue::StringList(vec![
            format!("kind={:?}", value.kind),
            format!("contentId={}", value.content_id.clone().unwrap_or_default()),
            format!("appId={}", value.app_id.clone().unwrap_or_default()),
            format!("httpBytes={}", value.http_bytes.unwrap_or_default()),
            format!("lanBytes={}", value.lan_bytes.unwrap_or_default()),
            format!(
                "cacheHostBytes={}",
                value.cache_host_bytes.unwrap_or_default()
            ),
        ]),
        EspEvidenceRecord::Graph(value) => {
            let mut fields = vec![
                format!("section={}", serialized_wire_value(&value.section)),
                format!("apiVersion={}", serialized_wire_value(&value.api_version)),
                format!("recordId={}", value.record_id),
                format!(
                    "displayName={}",
                    value.display_name.clone().unwrap_or_default()
                ),
            ];
            if let Some(status) = &value.status {
                fields.extend([
                    format!("remoteStatus.raw={}", serialized_wire_value(&status.raw)),
                    format!(
                        "remoteStatus.normalized={}",
                        serialized_wire_value(&status.normalized)
                    ),
                    format!("remoteStatus.display={}", status.display),
                ]);
            }
            EspObservationValue::StringList(fields)
        }
        EspEvidenceRecord::Coverage(_) => EspObservationValue::Text(String::new()),
    }
}

fn is_raw_hardware_hash_record(record: &EspEvidenceRecord) -> bool {
    match record {
        EspEvidenceRecord::Registry(value) => {
            contains_hardware_hash(&value.key) || contains_hardware_hash(&value.value_name)
        }
        EspEvidenceRecord::Json(value) => {
            contains_hardware_hash(&value.document_type)
                || contains_hardware_hash(&value.json_pointer)
        }
        _ => false,
    }
}

fn contains_hardware_hash(value: &str) -> bool {
    let value = value.to_ascii_lowercase().replace([' ', '-', '_'], "");
    value.contains("hardwarehash") || value.contains("devicehardwaredata")
}

fn serialized_wire_value<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(value)) => value,
        Ok(value) => value.to_string(),
        Err(_) => String::new(),
    }
}

fn graph_section_matches_workload(
    section: &EspGraphObservationSection,
    kind: &EspTrackedKind,
) -> bool {
    match section {
        EspGraphObservationSection::App => matches!(
            kind,
            EspTrackedKind::ModernApp
                | EspTrackedKind::Win32App
                | EspTrackedKind::DevicePreparationWorkload
        ),
        EspGraphObservationSection::Policy => {
            matches!(
                kind,
                EspTrackedKind::Policy | EspTrackedKind::ScepCertificate
            )
        }
        EspGraphObservationSection::Script => matches!(kind, EspTrackedKind::PlatformScript),
        EspGraphObservationSection::ManagedDevice
        | EspGraphObservationSection::AutopilotIdentity
        | EspGraphObservationSection::DeploymentProfile
        | EspGraphObservationSection::EnrollmentConfiguration
        | EspGraphObservationSection::Unknown(_) => false,
    }
}

fn classic_session_info(observation: &EspRegistryObservation) -> Option<ClassicSessionInfo> {
    let components = path_components(&observation.key);
    let diagnostics = components
        .iter()
        .position(|part| part.eq_ignore_ascii_case("Diagnostics"))?;
    let mut cursor = diagnostics + 1;
    let mut user_sid = None;
    let scope = if components
        .get(cursor)
        .map(|part| part.to_ascii_uppercase().starts_with("S-"))
        .unwrap_or(false)
    {
        user_sid = components.get(cursor).cloned();
        cursor += 1;
        EspScope::User
    } else {
        EspScope::Device
    };
    let family = components.get(cursor)?.clone();
    if !is_classic_family(&family) {
        return None;
    }
    let raw_time = components.get(cursor + 1)?.clone();
    Some(ClassicSessionInfo {
        scope,
        user_sid,
        family,
        raw_time,
    })
}

fn classic_session_identity(info: &ClassicSessionInfo) -> String {
    match (&info.scope, &info.user_sid) {
        (EspScope::Device, _) => format!("classic:device:{}", info.raw_time),
        (EspScope::User, Some(sid)) => format!("classic:user:{sid}:{}", info.raw_time),
        (EspScope::User, None) => format!("classic:user:unknown:{}", info.raw_time),
    }
}

fn classic_session_id(source_artifact_id: &str, info: &ClassicSessionInfo) -> String {
    format!(
        "session|{}|{}|0",
        escape_component(source_artifact_id),
        escape_component(&classic_session_identity(info))
    )
}

fn deferred_error_code_observation(
    ordinal: usize,
    observation: &EspRegistryObservation,
) -> Option<DeferredErrorCode> {
    let is_enforcement = if observation
        .value_name
        .eq_ignore_ascii_case("EnforcementErrorCode")
    {
        true
    } else if observation.value_name.eq_ignore_ascii_case("ExitCode") {
        false
    } else {
        return None;
    };
    let raw = observation_text(&observation.value)?;
    let identifier = last_path_component(&observation.key)?;
    let explicit_session = classic_session_info(observation);
    let (scope, user_sid) = if let Some(info) = &explicit_session {
        (Some(info.scope.clone()), info.user_sid.clone())
    } else if let Some(sid) = path_components(&observation.key)
        .into_iter()
        .find(|part| part.to_ascii_uppercase().starts_with("S-"))
    {
        if is_device_scope_sid(&sid) {
            (Some(EspScope::Device), None)
        } else {
            (Some(EspScope::User), Some(sid))
        }
    } else {
        (None, None)
    };
    let key = observation.key.to_ascii_lowercase();
    let kind = if key.contains("win32apps")
        || explicit_session
            .as_ref()
            .map(|info| info.family.eq_ignore_ascii_case("Sidecar"))
            .unwrap_or(false)
    {
        Some(EspTrackedKind::Win32App)
    } else {
        None
    };
    Some(DeferredErrorCode {
        identifier: Some(identifier),
        explicit_session: explicit_session.map(|info| DeferredSessionIdentity {
            scope: info.scope,
            user_sid: info.user_sid,
            raw_time: info.raw_time,
        }),
        scope,
        user_sid,
        kind,
        code: error_code(&raw),
        is_enforcement,
        ordinal,
        context: observation.context.clone(),
    })
}

fn is_device_scope_sid(value: &str) -> bool {
    value.to_ascii_uppercase().starts_with("S-0-")
}

fn enrollment_update(observation: &EspRegistryObservation) -> Option<EnrollmentUpdate> {
    match observation.value_name.to_ascii_lowercase().as_str() {
        "providerid" => observation_text(&observation.value).map(EnrollmentUpdate::ProviderId),
        "aadtenantid" | "tenantid" => {
            observation_text(&observation.value).map(EnrollmentUpdate::TenantId)
        }
        "upn" | "userprincipalname" => {
            observation_text(&observation.value).map(EnrollmentUpdate::UserPrincipalName)
        }
        "entdmid" => observation_text(&observation.value).map(EnrollmentUpdate::EntdmId),
        "skipdevicestatuspage" => observation_i64(&observation.value)
            .map(|value| EnrollmentUpdate::DeviceEspEnabled(value == 0)),
        "skipuserstatuspage" => observation_i64(&observation.value)
            .map(|value| EnrollmentUpdate::UserEspEnabled(value == 0)),
        "syncfailuretimeout" => {
            observation_u64(&observation.value).map(EnrollmentUpdate::TimeoutSeconds)
        }
        "blockinstatuspage" => observation_u64(&observation.value).map(EnrollmentUpdate::Blocking),
        _ => None,
    }
}

fn office_detail_observation(
    ordinal: usize,
    observation: &EspRegistryObservation,
) -> Option<OfficeDetailObservation> {
    let components = path_components(&observation.key);
    let office = components
        .iter()
        .position(|part| part.eq_ignore_ascii_case("OfficeCSP"))?;
    let identifier = components.get(office + 1)?;
    let is_final = if observation.value_name.eq_ignore_ascii_case("FinalStatus") {
        true
    } else if observation.value_name.eq_ignore_ascii_case("Status") {
        false
    } else {
        return None;
    };
    Some(OfficeDetailObservation {
        ordinal,
        identifier: percent_decode_bounded(identifier).unwrap_or_else(|_| identifier.clone()),
        raw_status: observation_raw_status(&observation.value),
        is_final,
        context: observation.context.clone(),
    })
}

fn msi_detail_observation(
    ordinal: usize,
    observation: &EspRegistryObservation,
) -> Option<MsiDetailObservation> {
    if !observation.value_name.eq_ignore_ascii_case("Status") {
        return None;
    }
    let components = path_components(&observation.key);
    let root = components
        .iter()
        .position(|part| part.eq_ignore_ascii_case("EnterpriseDesktopAppManagement"))?;
    let msi = components
        .iter()
        .enumerate()
        .skip(root + 1)
        .find(|(_, part)| part.eq_ignore_ascii_case("MSI"))?
        .0;
    let identifier = components.get(msi + 1)?.clone();
    let sid = components
        .get(msi.saturating_sub(1))
        .filter(|part| part.to_ascii_uppercase().starts_with("S-"))
        .cloned();
    let (scope, user_sid) = match sid {
        Some(sid) if is_device_scope_sid(&sid) => (Some(EspScope::Device), None),
        Some(sid) => (Some(EspScope::User), Some(sid)),
        None => (None, None),
    };
    Some(MsiDetailObservation {
        ordinal,
        identifier: percent_decode_bounded(&identifier).unwrap_or(identifier),
        scope,
        user_sid,
        raw_status: observation_raw_status(&observation.value),
        context: observation.context.clone(),
    })
}

fn is_classic_family(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "expectedpolicies"
            | "expectedmsiapppackages"
            | "expectedmodernapppackages"
            | "sidecar"
            | "expectedscepcerts"
    )
}

fn classic_workload_kind(family: &str, value_name: &str) -> Option<EspTrackedKind> {
    let decoded = percent_decode_bounded(value_name).unwrap_or_else(|_| value_name.to_string());
    let decoded = decoded.to_ascii_lowercase();
    match family.to_ascii_lowercase().as_str() {
        "expectedpolicies" => Some(EspTrackedKind::Policy),
        "expectedmsiapppackages" if decoded.contains("/office/installation/") => {
            Some(EspTrackedKind::Office)
        }
        "expectedmsiapppackages" => Some(EspTrackedKind::Msi),
        "expectedmodernapppackages" => Some(EspTrackedKind::ModernApp),
        "sidecar" => Some(EspTrackedKind::Win32App),
        "expectedscepcerts" => Some(EspTrackedKind::ScepCertificate),
        _ => None,
    }
}

fn classic_raw_identifier(kind: &EspTrackedKind, value_name: &str) -> String {
    let decoded = percent_decode_bounded(value_name).unwrap_or_else(|_| value_name.to_string());
    let components: Vec<&str> = decoded.split('/').filter(|part| !part.is_empty()).collect();
    let after = match kind {
        EspTrackedKind::Msi => "MSI",
        EspTrackedKind::Office => "Installation",
        EspTrackedKind::ModernApp => "AppManagement",
        EspTrackedKind::ScepCertificate => "SCEP",
        _ => "",
    };
    if !after.is_empty() {
        if let Some(index) = components
            .iter()
            .position(|part| part.eq_ignore_ascii_case(after))
        {
            if let Some(identifier) = components.get(index + 1) {
                return (*identifier).to_string();
            }
        }
    }
    components
        .last()
        .map(|value| (*value).to_string())
        .unwrap_or(decoded)
}

fn normalize_for_kind(kind: &EspTrackedKind, raw: EspRawStatus) -> EspStatus {
    match kind {
        EspTrackedKind::Msi => normalize_office_detail_status(raw),
        EspTrackedKind::Office => normalize_office_status(raw, None),
        EspTrackedKind::ModernApp | EspTrackedKind::Policy | EspTrackedKind::ScepCertificate => {
            normalize_policy_status(raw)
        }
        EspTrackedKind::Win32App => normalize_classic_esp_status(raw),
        EspTrackedKind::PlatformScript | EspTrackedKind::DevicePreparationWorkload => {
            normalize_v2_status(raw)
        }
    }
}

fn is_provisioning_progress(observation: &EspJsonObservation) -> bool {
    observation
        .document_type
        .eq_ignore_ascii_case("ProvisioningProgress")
}

fn v2_document_identity(observation: &EspJsonObservation) -> String {
    let provenance = &observation.context.provenance;
    if let Some(registry) = &provenance.registry {
        return format!(
            "registry|{}|{}|{}",
            registry.hive,
            registry.key,
            registry.value_name.as_deref().unwrap_or_default()
        )
        .to_ascii_lowercase();
    }
    if let Some(event) = &provenance.event {
        return format!(
            "event|{}|{}|{}",
            event.channel,
            event.event_id,
            event
                .record_id
                .map(|record_id| record_id.to_string())
                .unwrap_or_default()
        )
        .to_ascii_lowercase();
    }
    if let Some(file_path) = &provenance.file_path {
        return format!("file|{file_path}|{}", observation.document_type).to_ascii_lowercase();
    }
    format!("document|{}", observation.document_type).to_ascii_lowercase()
}

fn is_enforcement_state_message(observation: &EspJsonObservation) -> bool {
    observation
        .document_type
        .eq_ignore_ascii_case("EnforcementStateMessage")
}

fn enforcement_message_group_key(observation: &EspJsonObservation) -> String {
    let provenance_key = observation
        .context
        .provenance
        .registry
        .as_ref()
        .map(|registry| registry.key.as_str())
        .or(observation.context.provenance.file_path.as_deref())
        .unwrap_or_default();
    let components = observation
        .json_pointer
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let semantic_field = components
        .iter()
        .position(|part| part.eq_ignore_ascii_case("EnforcementStateMessage"))
        .unwrap_or_else(|| components.len().saturating_sub(1));
    let record_path = components[..semantic_field].join("/");
    format!(
        "{}|{}|{}",
        observation.context.provenance.source_artifact_id, provenance_key, record_path
    )
}

fn is_page_settings(observation: &EspJsonObservation) -> bool {
    observation
        .document_type
        .eq_ignore_ascii_case("PageSettings")
        || observation
            .document_type
            .eq_ignore_ascii_case("DevicePreparationPageSettings")
}

fn is_platform_script_observation(observation: &EspRegistryObservation) -> bool {
    let key = observation.key.to_ascii_lowercase();
    key.contains("intunemanagementextension")
        && key.contains("policies")
        && (observation.value_name.eq_ignore_ascii_case("Result")
            || observation
                .value_name
                .eq_ignore_ascii_case("LastUpdatedTimeUtc"))
}

fn is_parity_event(event_id: u32) -> bool {
    matches!(
        event_id,
        72 | 100 | 101 | 107 | 109 | 110 | 111 | 304 | 306 | 1905 | 1906 | 1920 | 1922 | 1924
    )
}

fn event_timeline_kind(event_id: u32) -> EspTimelineKind {
    match event_id {
        100 | 107 | 109 | 110 | 111 => EspTimelineKind::OfflineDomainJoin,
        72 | 101 | 304 | 306 => EspTimelineKind::Registration,
        1905 | 1906 | 1920 | 1922 | 1924 => EspTimelineKind::Workload,
        _ => EspTimelineKind::Other,
    }
}

fn event_normalized_status(event_id: u32) -> EspNormalizedStatus {
    match event_id {
        100 | 304 | 1924 => EspNormalizedStatus::Failed,
        107 | 306 | 1922 => EspNormalizedStatus::Succeeded,
        101 | 72 => EspNormalizedStatus::Processed,
        1905 => EspNormalizedStatus::Downloading,
        1906 => EspNormalizedStatus::Downloaded,
        109 | 110 | 111 | 1920 => EspNormalizedStatus::InProgress,
        _ => EspNormalizedStatus::Unknown,
    }
}

fn odj_state_details(
    observation: &EspEventLogObservation,
) -> Option<(&'static str, EspNormalizedStatus)> {
    if !matches!(observation.event_id, 109 | 110) {
        return None;
    }
    let named_data = if observation.named_data.is_empty() {
        observation
            .context
            .provenance
            .event
            .as_ref()
            .map(|event| event.named_data.as_slice())
            .unwrap_or_default()
    } else {
        observation.named_data.as_slice()
    };
    let state = named_data
        .iter()
        .find(|value| {
            matches!(
                value.name.to_ascii_lowercase().as_str(),
                "state" | "odjstate" | "status"
            )
        })
        .or_else(|| named_data.first())
        .and_then(|value| value.value.trim().parse::<u8>().ok())
        .or_else(|| {
            let message = observation.message.as_deref()?.to_ascii_lowercase();
            if message.contains("timed out") {
                Some(3)
            } else if message.contains("not configured") {
                Some(0)
            } else if message.contains("waiting") {
                Some(1)
            } else if message.contains("processed") {
                Some(2)
            } else {
                None
            }
        })?;
    match state {
        0 => Some((
            "Offline domain join not configured",
            EspNormalizedStatus::NotStarted,
        )),
        1 => Some(("Waiting for ODJ blob", EspNormalizedStatus::InProgress)),
        2 => Some(("Processed ODJ blob", EspNormalizedStatus::Processed)),
        3 => Some((
            "Timed out waiting for ODJ blob or connectivity",
            EspNormalizedStatus::Failed,
        )),
        _ => None,
    }
}

fn event_default_message(event_id: u32) -> &'static str {
    match event_id {
        72 => "MDM enrollment",
        100 => "Could not establish connectivity",
        101 => "SCP discovery successful",
        107 => "Successfully applied ODJ blob",
        109 | 110 => "Offline domain join state changed",
        111 => "Starting wait for ODJ blob",
        304 => "Hybrid AADJ device registration failed",
        306 => "Hybrid AADJ device registration succeeded",
        1905 => "Download started",
        1906 => "Download finished",
        1920 => "Installation started",
        1922 => "Installation finished",
        1924 => "Installation failed",
        _ => "Unknown event",
    }
}

fn event_title(event_id: u32, named_data: &[EspNamedValue]) -> String {
    match event_timeline_kind(event_id) {
        EspTimelineKind::OfflineDomainJoin => "Offline Domain Join".to_string(),
        EspTimelineKind::Registration => {
            if event_id == 72 {
                "MDM Enrollment".to_string()
            } else {
                "Device Registration".to_string()
            }
        }
        EspTimelineKind::Workload => named_data
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case("ProductCode"))
            .map(|item| item.value.clone())
            .unwrap_or_else(|| "MSI".to_string()),
        _ => format!("Event {event_id}"),
    }
}

fn empty_profile() -> EspProfileEvidence {
    EspProfileEvidence {
        profile_name: None,
        deployment_profile_id: None,
        correlation_id: None,
        tenant_domain: None,
        tenant_id: None,
        oobe_config: None,
        profile_download_time: None,
        join_mode: None,
        odj_applied: None,
        skip_domain_connectivity_check: None,
        device_preparation: None,
        evidence: Vec::new(),
    }
}

fn empty_device_preparation() -> EspDevicePreparationEvidence {
    EspDevicePreparationEvidence {
        agent_download_timeout_seconds: None,
        page_timeout_seconds: None,
        allow_skip_on_failure: None,
        allow_diagnostics: None,
        script_ids: Vec::new(),
        evidence: Vec::new(),
    }
}

fn empty_hardware() -> EspHardwareEvidence {
    EspHardwareEvidence {
        os_version: None,
        os_build: None,
        manufacturer: None,
        model: None,
        serial_number: None,
        tpm_version: None,
        evidence: Vec::new(),
    }
}

fn empty_delivery_optimization() -> EspDeliveryOptimizationEvidence {
    EspDeliveryOptimizationEvidence {
        download_http_bytes: 0,
        download_lan_bytes: 0,
        download_cache_host_bytes: 0,
        peer_share_percent: None,
        connected_cache_share_percent: None,
        transfers: Vec::new(),
        evidence: Vec::new(),
    }
}

fn context_timestamp(context: &EspObservationContext) -> EspTimestamp {
    context
        .source_timestamp
        .clone()
        .unwrap_or_else(|| normalize_timestamp(&context.observed_at_utc, None))
}

fn timestamp_chronology_key(timestamp: &EspTimestamp) -> &str {
    timestamp
        .normalized_utc
        .as_deref()
        .unwrap_or(&timestamp.raw_text)
}

fn context_chronology_key(context: &EspObservationContext) -> String {
    timestamp_chronology_key(&context_timestamp(context)).to_string()
}

fn merge_earliest_timestamp(target: &mut Option<EspTimestamp>, incoming: Option<EspTimestamp>) {
    let Some(incoming) = incoming else {
        return;
    };
    if target
        .as_ref()
        .map(|current| timestamp_chronology_key(&incoming) < timestamp_chronology_key(current))
        .unwrap_or(true)
    {
        *target = Some(incoming);
    }
}

fn merge_latest_timestamp(target: &mut Option<EspTimestamp>, incoming: Option<EspTimestamp>) {
    let Some(incoming) = incoming else {
        return;
    };
    if target
        .as_ref()
        .map(|current| timestamp_chronology_key(&incoming) >= timestamp_chronology_key(current))
        .unwrap_or(true)
    {
        *target = Some(incoming);
    }
}

fn workload_timestamps(
    observed: EspTimestamp,
    status: &EspNormalizedStatus,
) -> EspWorkloadTimestamps {
    let started = if matches!(
        status,
        EspNormalizedStatus::Downloading
            | EspNormalizedStatus::Installing
            | EspNormalizedStatus::InProgress
    ) {
        Some(observed.clone())
    } else {
        None
    };
    let ended = if matches!(
        status,
        EspNormalizedStatus::Succeeded | EspNormalizedStatus::Failed
    ) {
        Some(observed.clone())
    } else {
        None
    };
    EspWorkloadTimestamps {
        first_observed: observed.clone(),
        started,
        ended,
        last_updated: Some(observed),
    }
}

fn merge_workload_timestamps(current: &mut EspWorkloadTimestamps, incoming: EspWorkloadTimestamps) {
    if timestamp_chronology_key(&incoming.first_observed)
        < timestamp_chronology_key(&current.first_observed)
    {
        current.first_observed = incoming.first_observed;
    }
    merge_earliest_timestamp(&mut current.started, incoming.started);
    merge_latest_timestamp(&mut current.ended, incoming.ended);
    merge_latest_timestamp(&mut current.last_updated, incoming.last_updated);
}

fn text_status(raw: &str, normalized: EspNormalizedStatus) -> EspStatus {
    EspStatus {
        raw: EspRawStatus::Text(raw.to_string()),
        normalized,
        display: raw.to_string(),
        detail: None,
    }
}

fn text_status_from_observation(value: &EspObservationValue) -> EspStatus {
    let raw = observation_text(value).unwrap_or_default();
    let normalized = if raw.eq_ignore_ascii_case("success") || raw.eq_ignore_ascii_case("completed")
    {
        EspNormalizedStatus::Succeeded
    } else if raw.eq_ignore_ascii_case("failed") {
        EspNormalizedStatus::Failed
    } else if raw.eq_ignore_ascii_case("inprogress") {
        EspNormalizedStatus::InProgress
    } else {
        EspNormalizedStatus::Unknown
    };
    text_status(&raw, normalized)
}

fn boolean_status(value: bool) -> EspStatus {
    text_status(
        if value { "true" } else { "false" },
        if value {
            EspNormalizedStatus::Processed
        } else {
            EspNormalizedStatus::NotStarted
        },
    )
}

fn observation_raw_status(value: &EspObservationValue) -> EspRawStatus {
    match value {
        EspObservationValue::Integer(value) => EspRawStatus::Number(*value),
        EspObservationValue::Unsigned(value) => i64::try_from(*value)
            .map(EspRawStatus::Number)
            .unwrap_or_else(|_| EspRawStatus::Text(value.to_string())),
        EspObservationValue::Text(value) => EspRawStatus::Text(value.clone()),
        EspObservationValue::Boolean(value) => EspRawStatus::Text(value.to_string()),
        EspObservationValue::StringList(value) => EspRawStatus::Text(value.join(",")),
    }
}

fn observation_text(value: &EspObservationValue) -> Option<String> {
    match value {
        EspObservationValue::Text(value) => Some(value.clone()),
        EspObservationValue::Integer(value) => Some(value.to_string()),
        EspObservationValue::Unsigned(value) => Some(value.to_string()),
        EspObservationValue::Boolean(value) => Some(value.to_string()),
        EspObservationValue::StringList(value) => Some(value.join(",")),
    }
}

fn observation_i64(value: &EspObservationValue) -> Option<i64> {
    match value {
        EspObservationValue::Integer(value) => Some(*value),
        EspObservationValue::Unsigned(value) => i64::try_from(*value).ok(),
        EspObservationValue::Text(value) => value.parse().ok(),
        _ => None,
    }
}

fn observation_u64(value: &EspObservationValue) -> Option<u64> {
    match value {
        EspObservationValue::Unsigned(value) => Some(*value),
        EspObservationValue::Integer(value) => u64::try_from(*value).ok(),
        EspObservationValue::Text(value) => value.parse().ok(),
        _ => None,
    }
}

fn observation_bool(value: &EspObservationValue) -> Option<bool> {
    match value {
        EspObservationValue::Boolean(value) => Some(*value),
        EspObservationValue::Integer(value) => Some(*value != 0),
        EspObservationValue::Unsigned(value) => Some(*value != 0),
        EspObservationValue::Text(value) if value.eq_ignore_ascii_case("true") => Some(true),
        EspObservationValue::Text(value) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn timestamp_from_observation_value(value: &EspObservationValue) -> Option<EspTimestamp> {
    observation_text(value).map(|value| normalize_embedded_timestamp(&value))
}

fn normalize_embedded_timestamp(raw: &str) -> EspTimestamp {
    let unescaped = raw.replace(r"\/", "/");
    if let Some(inner) = unescaped
        .strip_prefix("/Date(")
        .and_then(|value| value.strip_suffix(")/"))
    {
        let millis_text = inner
            .chars()
            .enumerate()
            .take_while(|(index, character)| {
                character.is_ascii_digit() || (*index == 0 && *character == '-')
            })
            .map(|(_, character)| character)
            .collect::<String>();
        if let Ok(milliseconds) = millis_text.parse::<i64>() {
            if let Some(timestamp) = Utc.timestamp_millis_opt(milliseconds).single() {
                return EspTimestamp {
                    raw_text: raw.to_string(),
                    original_offset: Some("Z".to_string()),
                    normalized_utc: Some(timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)),
                    kind: EspTimestampKind::Utc,
                };
            }
        }
    }
    normalize_timestamp(raw, None)
}

fn error_code(raw: &str) -> EspErrorCode {
    if raw.starts_with("0x") || raw.starts_with("0X") {
        let digits = &raw[2..];
        EspErrorCode {
            raw: raw.to_string(),
            decimal: None,
            hex: u64::from_str_radix(digits, 16)
                .ok()
                .map(|_| format!("0x{}", digits.to_ascii_uppercase())),
        }
    } else {
        let decimal = raw.parse::<i64>().ok();
        let hex = decimal.map(|value| format!("0x{:08X}", value as i32 as u32));
        EspErrorCode {
            raw: raw.to_string(),
            decimal,
            hex,
        }
    }
}

fn error_code_normalized_status(code: &EspErrorCode) -> EspNormalizedStatus {
    if code.decimal == Some(0)
        || code
            .raw
            .strip_prefix("0x")
            .or_else(|| code.raw.strip_prefix("0X"))
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            == Some(0)
    {
        EspNormalizedStatus::Succeeded
    } else if code.decimal.is_some() || code.hex.is_some() {
        EspNormalizedStatus::Failed
    } else {
        EspNormalizedStatus::Unknown
    }
}

fn sensitive_string(value: String) -> EspClassifiedString {
    EspClassifiedString {
        value,
        sensitivity: EspSensitivity::Sensitive,
    }
}

fn more_restrictive_sensitivity(
    current: &EspSensitivity,
    incoming: &EspSensitivity,
) -> EspSensitivity {
    let rank = |value: &EspSensitivity| match value {
        EspSensitivity::Public => 0,
        EspSensitivity::Sensitive => 1,
        EspSensitivity::Restricted => 2,
    };
    if rank(incoming) > rank(current) {
        incoming.clone()
    } else {
        current.clone()
    }
}

fn tracked_kind_name(kind: &EspTrackedKind) -> &'static str {
    match kind {
        EspTrackedKind::Msi => "msi",
        EspTrackedKind::Office => "office",
        EspTrackedKind::ModernApp => "modernApp",
        EspTrackedKind::Win32App => "win32App",
        EspTrackedKind::Policy => "policy",
        EspTrackedKind::ScepCertificate => "scepCertificate",
        EspTrackedKind::PlatformScript => "platformScript",
        EspTrackedKind::DevicePreparationWorkload => "devicePreparationWorkload",
    }
}

fn path_components(value: &str) -> Vec<String> {
    value
        .split(['\\', '/'])
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn last_path_component(value: &str) -> Option<String> {
    path_components(value).into_iter().last()
}

fn escape_component(value: &str) -> String {
    value.replace('%', "%25").replace('|', "%7C")
}

fn session_group_sort_key(session: &EspSession) -> (u8, u8, String) {
    (
        match session.kind {
            EspSessionKind::Classic => 0,
            EspSessionKind::DevicePreparationV2 => 1,
        },
        match session.scope {
            EspScope::Device => 0,
            EspScope::User => 1,
        },
        session
            .user_sid
            .as_ref()
            .map(|sid| sid.value.clone())
            .unwrap_or_default(),
    )
}

fn session_group_identity(session: &EspSession) -> String {
    format!(
        "{:?}:{:?}:{}:{}",
        session.kind,
        session.scope,
        session
            .user_sid
            .as_ref()
            .map(|sid| sid.value.as_str())
            .unwrap_or(""),
        session.session_id.split('|').nth(1).unwrap_or_default()
    )
}

fn session_chronology(session: &EspSession) -> &str {
    session
        .started_at
        .as_ref()
        .and_then(|timestamp| timestamp.normalized_utc.as_deref())
        .or_else(|| {
            session
                .started_at
                .as_ref()
                .map(|timestamp| timestamp.raw_text.as_str())
        })
        .unwrap_or("")
}

fn snapshot_phase(scenario: &EspScenario, sessions: &[EspSession]) -> EspPhase {
    let latest = sessions
        .iter()
        .filter(|session| session.is_latest)
        .collect::<Vec<_>>();
    if latest
        .iter()
        .any(|session| session.phase == EspPhase::Failed)
    {
        EspPhase::Failed
    } else if !latest.is_empty()
        && latest
            .iter()
            .all(|session| session.phase == EspPhase::Completed)
    {
        EspPhase::Completed
    } else if *scenario == EspScenario::AutopilotDevicePreparationV2 {
        EspPhase::DevicePreparation
    } else if latest
        .iter()
        .any(|session| session.scope == EspScope::User && session.phase != EspPhase::Completed)
    {
        EspPhase::AccountSetup
    } else if latest
        .iter()
        .any(|session| session.scope == EspScope::Device)
    {
        EspPhase::DeviceSetup
    } else {
        EspPhase::NotStarted
    }
}

fn identifiers_match(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
        || match (extract_guid(left), extract_guid(right)) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
}

fn identifier_match_key(value: &str) -> String {
    extract_guid(value).unwrap_or_else(|| value.trim().to_ascii_lowercase())
}

fn latest_code_occurrence(codes: &[DeferredCodeOccurrence]) -> Option<&DeferredCodeOccurrence> {
    codes.iter().max_by(|left, right| {
        context_chronology_key(&left.context)
            .cmp(&context_chronology_key(&right.context))
            .then_with(|| left.ordinal.cmp(&right.ordinal))
    })
}

fn deferred_session_matches(session: &EspSession, identity: &DeferredSessionIdentity) -> bool {
    if session.kind != EspSessionKind::Classic || session.scope != identity.scope {
        return false;
    }
    if identity.user_sid.as_deref() != session.user_sid.as_ref().map(|sid| sid.value.as_str()) {
        return false;
    }
    let expected = normalize_timestamp(&identity.raw_time, None);
    session.started_at.as_ref().is_some_and(|started| {
        started.raw_text.eq_ignore_ascii_case(&identity.raw_time)
            || (started.normalized_utc.is_some()
                && started.normalized_utc == expected.normalized_utc)
    })
}

fn synthetic_context(
    source_kind: EspSourceKind,
    source_artifact_id: &str,
    evidence_id: &str,
    timestamp: &str,
) -> EspObservationContext {
    EspObservationContext {
        evidence_ref: EspEvidenceRef {
            evidence_id: evidence_id.to_string(),
            source_artifact_id: source_artifact_id.to_string(),
        },
        provenance: EspEvidenceProvenance {
            source_kind,
            source_artifact_id: source_artifact_id.to_string(),
            file_path: None,
            line_number: None,
            record_number: None,
            registry: None,
            event: None,
        },
        source_timestamp: Some(normalize_timestamp(timestamp, None)),
        observed_at_utc: timestamp.to_string(),
        sensitivity: EspSensitivity::Public,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
    }
}

fn system_fact_value(fact: &EspSystemFact) -> EspObservationValue {
    match fact {
        EspSystemFact::OsVersion(value)
        | EspSystemFact::OsBuild(value)
        | EspSystemFact::Manufacturer(value)
        | EspSystemFact::Model(value)
        | EspSystemFact::SerialNumber(value)
        | EspSystemFact::TpmVersion(value)
        | EspSystemFact::Hostname(value) => EspObservationValue::Text(value.clone()),
        EspSystemFact::Elevation(value) => EspObservationValue::Boolean(value.is_elevated),
    }
}

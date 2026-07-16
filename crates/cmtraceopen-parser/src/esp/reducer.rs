use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::models::*;
use super::normalize::{
    decode_oobe_config, extract_guid, normalize_classic_esp_status, normalize_office_detail_status,
    normalize_policy_status, normalize_timestamp, normalize_v2_status, percent_decode_bounded,
};
use super::timeline::{sort_timeline_entries, stable_record_id, stable_timeline_entry_id};

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
    DeliveryOptimization(EspDeliveryOptimizationObservation),
    Graph(EspGraphObservation),
    Coverage(EspArtifactCoverage),
}

#[derive(Debug, Clone)]
pub struct EspDiagnosticsReducer {
    generated_at_utc: String,
    records: Vec<EspEvidenceRecord>,
}

impl EspDiagnosticsReducer {
    pub fn new(generated_at_utc: String) -> Self {
        Self {
            generated_at_utc,
            records: Vec::new(),
        }
    }

    pub fn ingest(&mut self, record: EspEvidenceRecord) {
        self.records.push(record);
    }

    pub fn ingest_all<I: IntoIterator<Item = EspEvidenceRecord>>(&mut self, records: I) {
        self.records.extend(records);
    }

    pub fn snapshot(&self) -> EspDiagnosticsSnapshot {
        let scenario = classify_scenario(&self.records);
        let mut projection = SnapshotProjection::new(self.generated_at_utc.clone(), scenario);
        for (ordinal, record) in self.records.iter().enumerate() {
            if record_allowed_for_scenario(record, &projection.scenario) {
                projection.process_record(ordinal, record);
            }
        }
        projection.finish()
    }
}

struct SnapshotProjection {
    generated_at_utc: String,
    scenario: EspScenario,
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
    v2_workloads: BTreeMap<(String, usize), V2WorkloadAccumulator>,
    platform_scripts: Vec<(usize, EspRegistryObservation)>,
    graph_observations: Vec<EspGraphObservation>,
    deferred_error_codes: Vec<(String, EspErrorCode, bool, EspEvidenceRef)>,
}

impl SnapshotProjection {
    fn new(generated_at_utc: String, scenario: EspScenario) -> Self {
        Self {
            generated_at_utc,
            scenario,
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
            platform_scripts: Vec::new(),
            graph_observations: Vec::new(),
            deferred_error_codes: Vec::new(),
        }
    }

    fn process_record(&mut self, ordinal: usize, record: &EspEvidenceRecord) {
        if is_raw_hardware_hash_record(record) {
            return;
        }

        if let Some(raw) = raw_evidence_record(record, ordinal) {
            self.raw_evidence.push(raw);
        }

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
            self.platform_scripts.push((ordinal, observation.clone()));
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
            "exitcode" | "enforcementerrorcode" => {
                let identifier = last_path_component(&observation.key).unwrap_or_default();
                if let Some(raw) = observation_text(&observation.value) {
                    self.deferred_error_codes.push((
                        identifier,
                        error_code(&raw),
                        name == "enforcementerrorcode",
                        observation.context.evidence_ref.clone(),
                    ));
                }
            }
            _ => {}
        }
    }

    fn process_json(&mut self, ordinal: usize, observation: &EspJsonObservation) {
        if is_provisioning_progress(observation) {
            self.accumulate_v2_workload(ordinal, observation);
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
                            entry_id: stable_timeline_entry_id(&observation.context, ordinal),
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
        let message = observation
            .message
            .clone()
            .unwrap_or_else(|| event_default_message(observation.event_id).to_string());
        let normalized = event_normalized_status(observation.event_id);
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
            transfer_id: stable_record_id("transfer", &observation.context, ordinal),
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

        let detail = match observation.kind {
            EspDeliveryOptimizationEventKind::DownloadStarted => "Download started",
            EspDeliveryOptimizationEventKind::DownloadCompleted => "Download completed",
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
            Some(text_status(detail, EspNormalizedStatus::InProgress)),
        );
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
        let entry = self
            .node_cache
            .entry(index)
            .or_insert_with(|| NodeCacheAccumulator {
                node_uri: None,
                expected_value: None,
                sensitivity: observation.context.sensitivity.clone(),
                evidence: Vec::new(),
            });
        match observation.value_name.to_ascii_lowercase().as_str() {
            "nodeuri" => entry.node_uri = observation_text(&observation.value),
            "expectedvalue" => entry.expected_value = observation_text(&observation.value),
            _ => return false,
        }
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
        match observation.value_name.to_ascii_lowercase().as_str() {
            "providerid" => entry.provider_id = observation_text(&observation.value),
            "aadtenantid" | "tenantid" => {
                entry.tenant_id = observation_text(&observation.value).map(sensitive_string)
            }
            "upn" | "userprincipalname" => {
                entry.user_principal_name =
                    observation_text(&observation.value).map(sensitive_string)
            }
            "entdmid" => {
                entry.entdm_id = observation_text(&observation.value).map(sensitive_string)
            }
            "skipdevicestatuspage" => {
                entry.settings.device_esp_enabled =
                    observation_i64(&observation.value).map(|v| v == 0)
            }
            "skipuserstatuspage" => {
                entry.settings.user_esp_enabled =
                    observation_i64(&observation.value).map(|v| v == 0)
            }
            "syncfailuretimeout" => {
                entry.settings.timeout_seconds = observation_u64(&observation.value)
            }
            "blockinstatuspage" => {
                if let Some(bits) = observation_u64(&observation.value) {
                    entry.settings.blocking = Some(bits != 0);
                    entry.settings.allow_reset = Some(bits & 1 != 0);
                    entry.settings.allow_retry = Some(bits & 2 != 0);
                    entry.settings.continue_anyway = Some(bits & 4 != 0);
                }
            }
            _ => return false,
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
        let session_identity = match (&session_info.scope, &session_info.user_sid) {
            (EspScope::Device, _) => format!("classic:device:{}", session_info.raw_time),
            (EspScope::User, Some(sid)) => {
                format!("classic:user:{sid}:{}", session_info.raw_time)
            }
            (EspScope::User, None) => format!("classic:user:unknown:{}", session_info.raw_time),
        };
        let session_id = format!(
            "session|{}|{}|0",
            escape_component(source),
            escape_component(&session_identity)
        );
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
        let raw_status = observation_raw_status(&observation.value);
        let normalized_status = normalize_for_kind(&kind, raw_status);
        let observed = context_timestamp(&observation.context);
        let timestamps = workload_timestamps(observed.clone(), &normalized_status.normalized);

        if let Some(workload) = self
            .workloads
            .iter_mut()
            .find(|workload| workload.workload_id == workload_id)
        {
            workload.status = normalized_status.clone();
            workload.timestamps.last_updated = Some(observed);
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
        let key = (
            observation.context.provenance.source_artifact_id.clone(),
            index,
        );
        let entry = self
            .v2_workloads
            .entry(key)
            .or_insert_with(|| V2WorkloadAccumulator {
                first_ordinal: ordinal,
                first_context: observation.context.clone(),
                workload_id: None,
                friendly_name: None,
                raw_status: None,
                started: None,
                ended: None,
                exit_code: None,
                enforcement_error_code: None,
                evidence: Vec::new(),
                state_context: None,
                state_ordinal: None,
            });
        match components[2].to_ascii_lowercase().as_str() {
            "workloadid" => entry.workload_id = observation_text(&observation.value),
            "friendlyname" => entry.friendly_name = observation_text(&observation.value),
            "workloadstate" => {
                entry.raw_status = Some(observation_raw_status(&observation.value));
                entry.state_context = Some(observation.context.clone());
                entry.state_ordinal = Some(ordinal);
            }
            "starttime" => entry.started = timestamp_from_observation_value(&observation.value),
            "endtime" => entry.ended = timestamp_from_observation_value(&observation.value),
            "errorcode" => {
                entry.exit_code =
                    observation_text(&observation.value).map(|value| error_code(&value))
            }
            "enforcementerrorcode" => {
                entry.enforcement_error_code =
                    observation_text(&observation.value).map(|value| error_code(&value))
            }
            _ => return,
        }
        entry
            .evidence
            .push(observation.context.evidence_ref.clone());
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
                entry_id: stable_timeline_entry_id(context, ordinal),
                timestamp: context_timestamp(context),
                kind,
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
        self.apply_deferred_error_codes();
        self.apply_graph_names();
        self.finalize_sessions();
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
        EspDiagnosticsSnapshot {
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
        }
    }

    fn finalize_v2_workloads(&mut self) {
        let accumulators = std::mem::take(&mut self.v2_workloads);
        for ((source, index), entry) in accumulators {
            let raw_identifier = entry
                .workload_id
                .clone()
                .unwrap_or_else(|| format!("unknown-{index}"));
            let raw_status = entry
                .raw_status
                .clone()
                .unwrap_or_else(|| EspRawStatus::Text("missing".to_string()));
            let normalized_status = normalize_v2_status(raw_status);
            let session_identity = "devicePreparationV2:device:ProvisioningProgress";
            let session_id = format!(
                "session|{}|{}|0",
                escape_component(&source),
                session_identity
            );
            let first_observed = context_timestamp(&entry.first_context);
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
                    started_at: entry
                        .started
                        .clone()
                        .or_else(|| Some(first_observed.clone())),
                    ended_at: entry.ended.clone(),
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
                started: entry.started.clone(),
                ended: entry.ended.clone(),
                last_updated: entry.state_context.as_ref().map(context_timestamp),
            };
            self.workloads.push(EspWorkload {
                workload_id: workload_id.clone(),
                session_id: session_id.clone(),
                kind: EspTrackedKind::DevicePreparationWorkload,
                scope: EspScope::Device,
                raw_identifier: raw_identifier.clone(),
                display_name: entry.friendly_name.clone(),
                status: normalized_status.clone(),
                timestamps,
                exit_code: entry.exit_code,
                enforcement_error_code: entry.enforcement_error_code,
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
            if let (Some(context), Some(ordinal)) = (entry.state_context, entry.state_ordinal) {
                self.push_timeline(
                    ordinal,
                    &context,
                    EspTimelineKind::Workload,
                    entry.friendly_name.unwrap_or(raw_identifier),
                    Some("devicePreparationWorkload".to_string()),
                    Some(normalized_status),
                );
            } else {
                let _ = entry.first_ordinal;
            }
        }
    }

    fn finalize_platform_scripts(&mut self) {
        let scripts = std::mem::take(&mut self.platform_scripts);
        for (ordinal, observation) in scripts {
            let raw_identifier = last_path_component(&observation.key)
                .unwrap_or_else(|| observation.value_name.clone());
            let status = text_status_from_observation(&observation.value);
            let session_id = self
                .sessions
                .iter()
                .find(|session| session.kind == EspSessionKind::DevicePreparationV2)
                .map(|session| session.session_id.clone())
                .unwrap_or_else(|| {
                    format!(
                        "session|{}|devicePreparationV2:device:Policies|0",
                        escape_component(&observation.context.provenance.source_artifact_id)
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
                    started_at: Some(context_timestamp(&observation.context)),
                    ended_at: None,
                    phase: EspPhase::DevicePreparation,
                    is_latest: false,
                    workload_ids: Vec::new(),
                    evidence: vec![observation.context.evidence_ref.clone()],
                });
            }
            let workload_id = format!(
                "workload|{}|{}|0",
                escape_component(&observation.context.provenance.source_artifact_id),
                escape_component(&format!("platformScript:{raw_identifier}"))
            );
            self.workloads.push(EspWorkload {
                workload_id: workload_id.clone(),
                session_id: session_id.clone(),
                kind: EspTrackedKind::PlatformScript,
                scope: EspScope::Device,
                raw_identifier: raw_identifier.clone(),
                display_name: None,
                status: status.clone(),
                timestamps: workload_timestamps(
                    context_timestamp(&observation.context),
                    &status.normalized,
                ),
                exit_code: None,
                enforcement_error_code: None,
                blocking: None,
                evidence: vec![observation.context.evidence_ref.clone()],
            });
            if let Some(session) = self
                .sessions
                .iter_mut()
                .find(|session| session.session_id == session_id)
            {
                session.workload_ids.push(workload_id);
            }
            self.push_timeline(
                ordinal,
                &observation.context,
                EspTimelineKind::Workload,
                raw_identifier,
                Some("platformScript".to_string()),
                Some(status),
            );
        }
    }

    fn apply_deferred_error_codes(&mut self) {
        for (identifier, code, is_enforcement, evidence) in
            std::mem::take(&mut self.deferred_error_codes)
        {
            if let Some(workload) = self.workloads.iter_mut().find(|workload| {
                workload.raw_identifier.eq_ignore_ascii_case(&identifier)
                    || workload
                        .raw_identifier
                        .to_ascii_lowercase()
                        .contains(&identifier.to_ascii_lowercase())
            }) {
                if is_enforcement {
                    workload.enforcement_error_code = Some(code);
                } else {
                    workload.exit_code = Some(code);
                }
                workload.evidence.push(evidence);
            }
        }
    }

    fn apply_graph_names(&mut self) {
        for graph in &self.graph_observations {
            if let Some(workload) = self
                .workloads
                .iter_mut()
                .find(|workload| identifiers_match(&workload.raw_identifier, &graph.record_id))
            {
                if let Some(display_name) = &graph.display_name {
                    workload.display_name = Some(display_name.clone());
                }
                workload.evidence.push(graph.context.evidence_ref.clone());
            }
        }
    }

    fn finalize_sessions(&mut self) {
        for session in &mut self.sessions {
            let statuses: Vec<&EspNormalizedStatus> = session
                .workload_ids
                .iter()
                .filter_map(|id| {
                    self.workloads
                        .iter()
                        .find(|workload| &workload.workload_id == id)
                        .map(|workload| &workload.status.normalized)
                })
                .collect();
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
                delivery.peer_share_percent = Some(0.0);
                delivery.connected_cache_share_percent = Some(0.0);
            } else {
                let total = delivery.download_http_bytes as f64;
                delivery.peer_share_percent =
                    Some(delivery.download_lan_bytes as f64 / total * 100.0);
                delivery.connected_cache_share_percent =
                    Some(delivery.download_cache_host_bytes as f64 / total * 100.0);
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
    first_ordinal: usize,
    first_context: EspObservationContext,
    workload_id: Option<String>,
    friendly_name: Option<String>,
    raw_status: Option<EspRawStatus>,
    started: Option<EspTimestamp>,
    ended: Option<EspTimestamp>,
    exit_code: Option<EspErrorCode>,
    enforcement_error_code: Option<EspErrorCode>,
    evidence: Vec<EspEvidenceRef>,
    state_context: Option<EspObservationContext>,
    state_ordinal: Option<usize>,
}

struct ClassicSessionInfo {
    scope: EspScope,
    user_sid: Option<String>,
    family: String,
    raw_time: String,
}

fn classify_scenario(records: &[EspEvidenceRecord]) -> EspScenario {
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
                if observation
                    .json_pointer
                    .eq_ignore_ascii_case("/DeploymentProfileName")
                {
                    has_profile_name = true;
                }
                if observation
                    .json_pointer
                    .eq_ignore_ascii_case("/ZtdCorrelationId")
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
        EspEvidenceRecord::DeliveryOptimization(value) => Some(&value.context),
        EspEvidenceRecord::Graph(value) => Some(&value.context),
        EspEvidenceRecord::Coverage(_) => None,
    }
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
        EspEvidenceRecord::Graph(value) => EspObservationValue::StringList(vec![
            value.record_id.clone(),
            value.display_name.clone().unwrap_or_default(),
        ]),
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
    match family.to_ascii_lowercase().as_str() {
        "expectedpolicies" => Some(EspTrackedKind::Policy),
        "expectedmsiapppackages"
            if value_name
                .to_ascii_lowercase()
                .contains("/office/installation/") =>
        {
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
        EspTrackedKind::Msi | EspTrackedKind::Office => normalize_office_detail_status(raw),
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
        && observation.value_name.eq_ignore_ascii_case("Result")
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
        109 | 110 | 111 | 1905 | 1906 | 1920 => EspNormalizedStatus::InProgress,
        _ => EspNormalizedStatus::Unknown,
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
    observation_text(value).map(|value| normalize_timestamp(&value, None))
}

fn error_code(raw: &str) -> EspErrorCode {
    if raw.starts_with("0x") || raw.starts_with("0X") {
        EspErrorCode {
            raw: raw.to_string(),
            decimal: None,
            hex: Some(format!("0x{}", &raw[2..].to_ascii_uppercase())),
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

fn sensitive_string(value: String) -> EspClassifiedString {
    EspClassifiedString {
        value,
        sensitivity: EspSensitivity::Sensitive,
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
    if sessions
        .iter()
        .any(|session| session.phase == EspPhase::Failed)
    {
        EspPhase::Failed
    } else if !sessions.is_empty()
        && sessions
            .iter()
            .all(|session| session.phase == EspPhase::Completed)
    {
        EspPhase::Completed
    } else if *scenario == EspScenario::AutopilotDevicePreparationV2 {
        EspPhase::DevicePreparation
    } else if sessions.iter().any(|session| {
        session.is_latest && session.scope == EspScope::User && session.phase != EspPhase::Completed
    }) {
        EspPhase::AccountSetup
    } else if sessions
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

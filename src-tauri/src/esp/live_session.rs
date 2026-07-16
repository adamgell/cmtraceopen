//! Concrete read-only native adapters for the ESP live-session service.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

use chrono::{SecondsFormat, TimeZone, Utc};
use cmtraceopen_parser::esp::{
    extract_guid, normalize_timestamp, EspArtifactCoverage, EspArtifactStatus,
    EspDeploymentLogObservation, EspEvidenceProvenance, EspEvidenceRecord, EspEvidenceRef,
    EspImeObservation, EspObservationContext, EspObservationValue, EspParseState,
    EspRegistryObservation, EspRegistryProvenance, EspSensitivity, EspSourceAccessState,
    EspSourceKind, EspTimestamp, EspTimestampKind,
};
#[cfg(target_os = "windows")]
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::models::log_entry::LogEntry;

use super::discovery::{
    discover_bounded_logs, runtime_discovery_input, DiscoveryResult, DiscoveryRootKind,
    DiscoveryRootState,
};
use super::event_logs::{collect_live_event_evidence, EventEvidence, EventSourceError};
use super::process::{collect_process_evidence, LiveProcessProvider, ProcessEvidence};
#[cfg(target_os = "windows")]
use super::registry::collect_live_registry_evidence;
use super::registry::RegistryEvidence;
use super::session::{
    EspDiscoveryBatch, EspDiscoveryProvider, EspEvidenceProvider, EspProviderBatch,
    EspSessionDependencies, EspSessionEventSink, EspSessionTail, EspSessionTailFactory,
    EspTailEvidenceBatch, SystemEspSessionClock,
};
use super::system::{collect_system_evidence, LiveSystemProvider, SystemEvidence, SystemSource};
use super::tailing::{EspTailFailure, EspTailPollResult, EspTailReconcileResult, EspTailSet};

const MAX_LIVE_HINTS: usize = 512;
#[cfg(target_os = "windows")]
const MAX_ACTIVE_PROFILE_DIRECTORIES: usize = 64;

#[derive(Debug, Clone, Default)]
struct LiveSessionHints {
    product_codes: BTreeSet<String>,
    installer_names: BTreeSet<String>,
    process_log_paths: BTreeSet<PathBuf>,
}

#[derive(Clone, Default)]
struct SharedLiveSessionHints(Arc<Mutex<LiveSessionHints>>);

impl SharedLiveSessionHints {
    fn snapshot(&self) -> LiveSessionHints {
        self.0.lock().map(|hints| hints.clone()).unwrap_or_default()
    }

    #[cfg(target_os = "windows")]
    fn update_registry(&self, evidence: &RegistryEvidence) {
        let installer_names = installer_names_from_registry(evidence);
        if let Ok(mut hints) = self.0.lock() {
            hints.installer_names.extend(installer_names);
            trim_set(&mut hints.installer_names, MAX_LIVE_HINTS);
        }
    }

    fn update_process(&self, evidence: &ProcessEvidence) {
        if let Ok(mut hints) = self.0.lock() {
            for observation in &evidence.observations {
                if let Some(product_code) = observation.product_code.as_ref() {
                    hints.product_codes.insert(product_code.clone());
                }
                if let Some(path) = observation.referenced_log_path.as_ref() {
                    hints.process_log_paths.insert(PathBuf::from(path));
                }
            }
            trim_set(&mut hints.product_codes, MAX_LIVE_HINTS);
            trim_set(&mut hints.process_log_paths, MAX_LIVE_HINTS);
        }
    }
}

fn trim_set<T: Ord + Clone>(values: &mut BTreeSet<T>, limit: usize) {
    while values.len() > limit {
        let Some(last) = values.iter().next_back().cloned() else {
            break;
        };
        values.remove(&last);
    }
}

struct NativeRegistryEvidenceProvider {
    hints: SharedLiveSessionHints,
}

impl EspEvidenceProvider for NativeRegistryEvidenceProvider {
    fn collect(&self, observed_at_utc: &str) -> EspProviderBatch {
        #[cfg(target_os = "windows")]
        {
            let product_codes = self
                .hints
                .snapshot()
                .product_codes
                .into_iter()
                .collect::<Vec<_>>();
            let evidence = collect_live_registry_evidence(&product_codes, observed_at_utc);
            self.hints.update_registry(&evidence);
            registry_evidence_to_batch(evidence, observed_at_utc)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = (&self.hints, observed_at_utc);
            unsupported_batch("registry.live", "registry", observed_at_utc)
        }
    }
}

struct NativeEventEvidenceProvider;

impl EspEvidenceProvider for NativeEventEvidenceProvider {
    fn collect(&self, observed_at_utc: &str) -> EspProviderBatch {
        match collect_live_event_evidence(observed_at_utc) {
            Ok(evidence) => event_evidence_to_batch(evidence, observed_at_utc),
            Err(error) => provider_error_batch(
                "event-log.live",
                "event-log",
                access_for_event_error(&error),
                event_error_detail(error),
                observed_at_utc,
            ),
        }
    }
}

struct NativeSystemEvidenceProvider;

impl EspEvidenceProvider for NativeSystemEvidenceProvider {
    fn collect(&self, observed_at_utc: &str) -> EspProviderBatch {
        system_evidence_to_batch(
            collect_system_evidence(&LiveSystemProvider, observed_at_utc),
            observed_at_utc,
        )
    }
}

struct NativeProcessEvidenceProvider {
    hints: SharedLiveSessionHints,
}

impl EspEvidenceProvider for NativeProcessEvidenceProvider {
    fn collect(&self, observed_at_utc: &str) -> EspProviderBatch {
        let installer_names = self
            .hints
            .snapshot()
            .installer_names
            .into_iter()
            .collect::<Vec<_>>();
        let evidence =
            collect_process_evidence(&LiveProcessProvider, &installer_names, observed_at_utc);
        self.hints.update_process(&evidence);
        process_evidence_to_batch(evidence, observed_at_utc)
    }
}

struct NativeDiscoveryProvider {
    hints: SharedLiveSessionHints,
}

impl EspDiscoveryProvider for NativeDiscoveryProvider {
    fn discover(&self, observed_at_utc: &str) -> EspDiscoveryBatch {
        let profiles = active_profile_directories(observed_at_utc);
        let process_logs = self
            .hints
            .snapshot()
            .process_log_paths
            .into_iter()
            .collect::<Vec<_>>();
        let mut batch = discovery_result_to_batch(
            discover_bounded_logs(&runtime_discovery_input(&profiles.paths, process_logs)),
            observed_at_utc,
        );
        batch.coverage.push(profiles.coverage);
        batch
    }
}

#[derive(Default)]
struct NativeTailFactory;

impl EspSessionTailFactory for NativeTailFactory {
    fn create(&self) -> Box<dyn EspSessionTail> {
        Box::new(NativeSessionTail::default())
    }
}

#[derive(Default)]
struct NativeSessionTail {
    tails: EspTailSet,
}

impl EspSessionTail for NativeSessionTail {
    fn reconcile(
        &mut self,
        sources: &[super::discovery::DiscoveredLogSource],
        observed_at_utc: &str,
    ) -> EspTailEvidenceBatch {
        tail_reconcile_to_batch(self.tails.reconcile(sources), observed_at_utc)
    }

    fn poll(&mut self, observed_at_utc: &str) -> EspTailEvidenceBatch {
        tail_poll_to_batch(self.tails.poll(), observed_at_utc)
    }

    fn stop(&mut self) {
        self.tails.stop();
    }
}

/// Builds the production local-only session dependency graph. Graph state is
/// deliberately absent; the frontend orchestrator owns optional enrichment.
pub fn native_session_dependencies(sink: Arc<dyn EspSessionEventSink>) -> EspSessionDependencies {
    let hints = SharedLiveSessionHints::default();
    EspSessionDependencies::new(
        Arc::new(SystemEspSessionClock::default()),
        Arc::new(NativeRegistryEvidenceProvider {
            hints: hints.clone(),
        }),
        Arc::new(NativeEventEvidenceProvider),
        Arc::new(NativeSystemEvidenceProvider),
        Arc::new(NativeProcessEvidenceProvider {
            hints: hints.clone(),
        }),
        Arc::new(NativeDiscoveryProvider { hints }),
        Arc::new(NativeTailFactory),
        sink,
    )
}

pub fn registry_evidence_to_batch(
    evidence: RegistryEvidence,
    observed_at_utc: &str,
) -> EspProviderBatch {
    let mut records = evidence
        .observations
        .into_iter()
        .map(|value| EspEvidenceRecord::Registry(value.observation))
        .collect::<Vec<_>>();
    records.extend(
        evidence
            .uninstall_names
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                EspEvidenceRecord::Registry(uninstall_name_observation(
                    index,
                    value.product_code,
                    value.display_name,
                    observed_at_utc,
                ))
            }),
    );

    let mut coverage = evidence
        .roots
        .into_iter()
        .map(|root| {
            artifact_coverage(
                format!("registry:{}\\{}", root.hive, root.key),
                "registry",
                status_for_access(&root.access_state),
                root.detail,
                observed_at_utc,
            )
        })
        .collect::<Vec<_>>();
    coverage.extend(evidence.descendant_coverage.into_iter().map(|descendant| {
        artifact_coverage(
            format!("registry:{}\\{}", descendant.hive, descendant.key),
            "registry",
            status_for_access(&descendant.access_state),
            descendant.detail,
            observed_at_utc,
        )
    }));
    deduplicate_coverage(&mut coverage);
    EspProviderBatch { records, coverage }
}

pub fn event_evidence_to_batch(evidence: EventEvidence, observed_at_utc: &str) -> EspProviderBatch {
    let records = evidence
        .observations
        .into_iter()
        .map(|value| EspEvidenceRecord::EventLog(value.observation))
        .collect();
    let mut coverage = evidence
        .channels
        .into_iter()
        .map(|channel| {
            artifact_coverage(
                format!("event-log:{}", channel.channel),
                "event-log",
                status_for_access(&channel.access_state),
                channel.detail,
                observed_at_utc,
            )
        })
        .collect::<Vec<_>>();
    deduplicate_coverage(&mut coverage);
    EspProviderBatch { records, coverage }
}

pub fn system_evidence_to_batch(
    evidence: SystemEvidence,
    observed_at_utc: &str,
) -> EspProviderBatch {
    let mut records = evidence
        .observations
        .into_iter()
        .map(EspEvidenceRecord::System)
        .collect::<Vec<_>>();
    if let Some(summary) = evidence.delivery_optimization {
        records.push(EspEvidenceRecord::DeliveryOptimizationSummary(summary));
    }
    records.extend(
        evidence
            .delivery_optimization_observations
            .into_iter()
            .map(EspEvidenceRecord::DeliveryOptimization),
    );
    let mut coverage = evidence
        .coverage
        .into_iter()
        .map(|source| {
            artifact_coverage(
                system_source_artifact_id(source.source),
                "system",
                status_for_access(&source.access_state),
                source.detail,
                observed_at_utc,
            )
        })
        .collect::<Vec<_>>();
    deduplicate_coverage(&mut coverage);
    EspProviderBatch { records, coverage }
}

pub fn process_evidence_to_batch(
    evidence: ProcessEvidence,
    observed_at_utc: &str,
) -> EspProviderBatch {
    let coverage = vec![artifact_coverage(
        "process.allowlisted-installers",
        "process",
        status_for_access(&evidence.access_state),
        evidence.detail,
        observed_at_utc,
    )];
    let records = evidence
        .observations
        .into_iter()
        .map(EspEvidenceRecord::Process)
        .collect();
    EspProviderBatch { records, coverage }
}

pub fn discovery_result_to_batch(
    result: DiscoveryResult,
    observed_at_utc: &str,
) -> EspDiscoveryBatch {
    let coverage = result
        .root_coverage
        .into_iter()
        .enumerate()
        .map(|(index, root)| {
            let kind = match root.kind {
                DiscoveryRootKind::Known => "known",
                DiscoveryRootKind::Temp => "temp",
            };
            let identity = root.source_id.unwrap_or_else(|| format!("root-{index}"));
            let mut detail = root.detail;
            if root.truncated && detail.is_none() {
                detail = Some("bounded discovery coverage is partial".to_string());
            }
            artifact_coverage(
                format!("discovery.{kind}.{identity}"),
                format!("discovery-{kind}"),
                status_for_discovery(root.state),
                detail,
                observed_at_utc,
            )
        })
        .collect();
    EspDiscoveryBatch {
        sources: result.sources,
        coverage,
    }
}

pub fn tail_reconcile_to_batch(
    result: EspTailReconcileResult,
    observed_at_utc: &str,
) -> EspTailEvidenceBatch {
    let mut batch = EspTailEvidenceBatch::default();
    for attachment in result.attachments {
        let artifact_id = log_artifact_id(&attachment.source.source_id, &attachment.source.path);
        batch.coverage.push(artifact_coverage(
            artifact_id,
            attachment.source.family.clone(),
            EspArtifactStatus::Available,
            None,
            observed_at_utc,
        ));
        batch.records.extend(log_entries_to_records(
            &attachment.source.path,
            &attachment.source.source_id,
            &attachment.source.family,
            attachment.entries,
            observed_at_utc,
        ));
    }
    append_tail_failures(&mut batch, result.failures, observed_at_utc);
    if result.source_limit_reached {
        batch.coverage.push(artifact_coverage(
            "tail.session-source-limit",
            "deployment-log",
            EspArtifactStatus::ParseFailed,
            Some("the bounded 512-source session attachment limit was reached".to_string()),
            observed_at_utc,
        ));
    }
    batch.changed = !batch.records.is_empty()
        || !batch.coverage.is_empty()
        || !batch.replace_artifact_ids.is_empty();
    batch
}

pub fn tail_poll_to_batch(
    result: EspTailPollResult,
    observed_at_utc: &str,
) -> EspTailEvidenceBatch {
    let mut batch = EspTailEvidenceBatch::default();
    for update in result.updates {
        let artifact_id = log_artifact_id(&update.source_id, &update.path);
        if update.reset_reason.is_some() {
            batch.replace_artifact_ids.push(artifact_id);
        }
        batch.records.extend(log_entries_to_records(
            &update.path,
            &update.source_id,
            &update.family,
            update.entries,
            observed_at_utc,
        ));
    }
    append_tail_failures(&mut batch, result.failures, observed_at_utc);
    batch.changed = !batch.records.is_empty()
        || !batch.coverage.is_empty()
        || !batch.replace_artifact_ids.is_empty();
    batch
}

fn append_tail_failures(
    batch: &mut EspTailEvidenceBatch,
    failures: Vec<EspTailFailure>,
    observed_at_utc: &str,
) {
    batch.coverage.extend(failures.into_iter().map(|failure| {
        artifact_coverage(
            log_artifact_id("tail-failure", &failure.path),
            "deployment-log",
            EspArtifactStatus::ParseFailed,
            Some(failure.detail),
            observed_at_utc,
        )
    }));
}

fn log_entries_to_records(
    path: &Path,
    source_id: &str,
    family: &str,
    entries: Vec<LogEntry>,
    observed_at_utc: &str,
) -> Vec<EspEvidenceRecord> {
    let artifact_id = log_artifact_id(source_id, path);
    let ime = family.eq_ignore_ascii_case("intune-ime");
    entries
        .into_iter()
        .map(|entry| {
            let context = log_context(&artifact_id, path, &entry, ime, observed_at_utc);
            if ime {
                let app_id = labeled_guid(&entry.message, &["appid", "application id"]);
                EspEvidenceRecord::Ime(EspImeObservation {
                    context,
                    component: entry.component,
                    message: entry.message,
                    app_id,
                    status: None,
                })
            } else {
                let product_code = labeled_guid(
                    &entry.message,
                    &["productcode", "product code", "product id"],
                );
                EspEvidenceRecord::DeploymentLog(EspDeploymentLogObservation {
                    context,
                    component: entry.component,
                    message: entry.message,
                    product_code,
                    log_path: Some(path.to_string_lossy().into_owned()),
                    status: None,
                })
            }
        })
        .collect()
}

fn log_context(
    artifact_id: &str,
    path: &Path,
    entry: &LogEntry,
    ime: bool,
    observed_at_utc: &str,
) -> EspObservationContext {
    let evidence_ref = EspEvidenceRef {
        evidence_id: format!("{artifact_id}:{}:{}", entry.id, entry.line_number),
        source_artifact_id: artifact_id.to_string(),
    };
    EspObservationContext {
        evidence_ref,
        provenance: EspEvidenceProvenance {
            source_kind: if ime {
                EspSourceKind::ImeLog
            } else {
                EspSourceKind::DeploymentLog
            },
            source_artifact_id: artifact_id.to_string(),
            file_path: Some(path.to_string_lossy().into_owned()),
            line_number: Some(u64::from(entry.line_number)),
            record_number: Some(entry.id),
            registry: None,
            event: None,
        },
        source_timestamp: log_timestamp(entry),
        observed_at_utc: observed_at_utc.to_string(),
        sensitivity: EspSensitivity::Sensitive,
        parse_state: EspParseState::Parsed,
        access_state: EspSourceAccessState::Available,
    }
}

fn log_timestamp(entry: &LogEntry) -> Option<EspTimestamp> {
    if let Some(timestamp) = entry.timestamp {
        let normalized = Utc
            .timestamp_millis_opt(timestamp)
            .single()
            .map(|value| value.to_rfc3339_opts(SecondsFormat::Millis, true));
        return Some(EspTimestamp {
            raw_text: entry
                .timestamp_display
                .clone()
                .unwrap_or_else(|| timestamp.to_string()),
            original_offset: entry.timezone_offset.map(format_offset),
            normalized_utc: normalized,
            kind: EspTimestampKind::Utc,
        });
    }
    let raw = entry.timestamp_display.as_ref()?;
    let offset = entry.timezone_offset.map(format_offset);
    Some(normalize_timestamp(raw, offset.as_deref()))
}

fn format_offset(minutes: i32) -> String {
    let sign = if minutes < 0 { '-' } else { '+' };
    let minutes = minutes.unsigned_abs();
    format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

fn labeled_guid(message: &str, labels: &[&str]) -> Option<String> {
    let lower = message.to_ascii_lowercase();
    labels
        .iter()
        .filter_map(|label| lower.find(label))
        .min()
        .and_then(|index| extract_guid(&message[index..]))
}

fn log_artifact_id(source_id: &str, path: &Path) -> String {
    let mut path_identity = path.to_string_lossy().replace('/', "\\");
    if cfg!(target_os = "windows") {
        path_identity.make_ascii_lowercase();
    }
    let digest = Sha256::digest(path_identity.as_bytes());
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("log:{source_id}:{suffix}")
}

fn uninstall_name_observation(
    index: usize,
    product_code: String,
    display_name: String,
    observed_at_utc: &str,
) -> EspRegistryObservation {
    let key = format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{product_code}");
    let artifact_id = format!("registry:HKLM\\{key}");
    let evidence_ref = EspEvidenceRef {
        evidence_id: format!("esp-uninstall-name-{index}"),
        source_artifact_id: artifact_id.clone(),
    };
    EspRegistryObservation {
        context: EspObservationContext {
            evidence_ref,
            provenance: EspEvidenceProvenance {
                source_kind: EspSourceKind::Registry,
                source_artifact_id: artifact_id,
                file_path: None,
                line_number: None,
                record_number: None,
                registry: Some(EspRegistryProvenance {
                    hive: "HKLM".to_string(),
                    key: key.clone(),
                    value_name: Some("DisplayName".to_string()),
                }),
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: observed_at_utc.to_string(),
            sensitivity: EspSensitivity::Public,
            parse_state: EspParseState::Parsed,
            access_state: EspSourceAccessState::Available,
        },
        hive: "HKLM".to_string(),
        key,
        value_name: "DisplayName".to_string(),
        value: EspObservationValue::Text(display_name),
    }
}

#[cfg(target_os = "windows")]
fn installer_names_from_registry(evidence: &RegistryEvidence) -> BTreeSet<String> {
    evidence
        .observations
        .iter()
        .filter(|value| {
            let key = value.observation.key.to_ascii_lowercase();
            key.contains("intunemanagementextension")
                || key.contains("enterprisedesktopappmanagement")
        })
        .filter(|value| installer_command_value_name(&value.observation.value_name))
        .flat_map(|value| observation_strings(&value.observation.value))
        .flat_map(executable_names)
        .take(MAX_LIVE_HINTS)
        .collect()
}

#[cfg(target_os = "windows")]
fn installer_command_value_name(value_name: &str) -> bool {
    let normalized = value_name
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        normalized.as_str(),
        "installcommand"
            | "installcommandline"
            | "uninstallcommand"
            | "uninstallcommandline"
            | "commandline"
            | "installer"
            | "installerpath"
            | "filename"
            | "executable"
    )
}

#[cfg(target_os = "windows")]
fn observation_strings(value: &EspObservationValue) -> Vec<&str> {
    match value {
        EspObservationValue::Text(value) => vec![value],
        EspObservationValue::StringList(values) => values.iter().map(String::as_str).collect(),
        _ => Vec::new(),
    }
}

#[cfg(target_os = "windows")]
fn executable_names(command_line: &str) -> Vec<String> {
    static EXECUTABLE: OnceLock<Regex> = OnceLock::new();
    if command_line.len() > 32 * 1024 {
        return Vec::new();
    }
    let expression = EXECUTABLE.get_or_init(|| {
        Regex::new(r#"(?i)(?:[\"']([^\"']+\.exe)[\"']|(?:^|\s)([^\s\"']+\.exe)(?:\s|$))"#)
            .expect("constant installer executable regex")
    });
    expression
        .captures_iter(command_line)
        .filter_map(|captures| captures.get(1).or_else(|| captures.get(2)))
        .filter_map(|value| normalize_executable_name(value.as_str()))
        .collect()
}

#[cfg(target_os = "windows")]
fn normalize_executable_name(value: &str) -> Option<String> {
    let name = value.rsplit(['\\', '/']).next()?.trim();
    if name.is_empty()
        || name.len() > 260
        || name.contains("..")
        || !name.to_ascii_lowercase().ends_with(".exe")
    {
        return None;
    }
    Some(name.to_string())
}

fn artifact_coverage(
    artifact_id: impl Into<String>,
    family: impl Into<String>,
    status: EspArtifactStatus,
    detail: Option<String>,
    observed_at_utc: &str,
) -> EspArtifactCoverage {
    EspArtifactCoverage {
        artifact_id: artifact_id.into(),
        family: family.into(),
        status,
        detail,
        observed_at_utc: observed_at_utc.to_string(),
        evidence: Vec::new(),
    }
}

fn status_for_access(access: &EspSourceAccessState) -> EspArtifactStatus {
    match access {
        EspSourceAccessState::Available => EspArtifactStatus::Available,
        EspSourceAccessState::Missing => EspArtifactStatus::Missing,
        EspSourceAccessState::PermissionDenied => EspArtifactStatus::PermissionDenied,
        EspSourceAccessState::Failed => EspArtifactStatus::ParseFailed,
        EspSourceAccessState::Unsupported => EspArtifactStatus::Unsupported,
    }
}

fn status_for_discovery(state: DiscoveryRootState) -> EspArtifactStatus {
    match state {
        DiscoveryRootState::Available => EspArtifactStatus::Available,
        DiscoveryRootState::Missing => EspArtifactStatus::Missing,
        DiscoveryRootState::PermissionDenied => EspArtifactStatus::PermissionDenied,
        DiscoveryRootState::ReparseRejected => EspArtifactStatus::Unsupported,
        DiscoveryRootState::Failed => EspArtifactStatus::ParseFailed,
    }
}

fn deduplicate_coverage(coverage: &mut Vec<EspArtifactCoverage>) {
    let mut by_id = BTreeMap::new();
    for item in coverage.drain(..) {
        by_id.insert(item.artifact_id.clone(), item);
    }
    coverage.extend(by_id.into_values());
}

fn system_source_artifact_id(source: SystemSource) -> &'static str {
    match source {
        SystemSource::Elevation => "system.elevation",
        SystemSource::OperatingSystem => "system.operating-system",
        SystemSource::ComputerSystem => "system.computer-system",
        SystemSource::Bios => "system.bios",
        SystemSource::Tpm => "system.tpm",
        SystemSource::ImeService => "system.ime-service",
        SystemSource::DeliveryOptimization => "system.delivery-optimization",
    }
}

#[cfg(not(target_os = "windows"))]
fn unsupported_batch(artifact_id: &str, family: &str, observed_at_utc: &str) -> EspProviderBatch {
    provider_error_batch(
        artifact_id,
        family,
        EspSourceAccessState::Unsupported,
        None,
        observed_at_utc,
    )
}

fn provider_error_batch(
    artifact_id: &str,
    family: &str,
    access: EspSourceAccessState,
    detail: Option<String>,
    observed_at_utc: &str,
) -> EspProviderBatch {
    EspProviderBatch {
        records: Vec::new(),
        coverage: vec![artifact_coverage(
            artifact_id,
            family,
            status_for_access(&access),
            detail,
            observed_at_utc,
        )],
    }
}

fn access_for_event_error(error: &EventSourceError) -> EspSourceAccessState {
    match error {
        EventSourceError::Missing => EspSourceAccessState::Missing,
        EventSourceError::PermissionDenied => EspSourceAccessState::PermissionDenied,
        EventSourceError::Failed(_) => EspSourceAccessState::Failed,
        EventSourceError::Unsupported => EspSourceAccessState::Unsupported,
    }
}

fn event_error_detail(error: EventSourceError) -> Option<String> {
    match error {
        EventSourceError::Failed(detail) => Some(detail),
        _ => None,
    }
}

struct ActiveProfileDirectories {
    paths: Vec<PathBuf>,
    coverage: EspArtifactCoverage,
}

#[cfg(target_os = "windows")]
fn active_profile_directories(observed_at_utc: &str) -> ActiveProfileDirectories {
    use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY};
    use winreg::RegKey;

    let loaded_users = RegKey::predef(HKEY_USERS);
    let profile_list = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
        KEY_READ | KEY_WOW64_64KEY,
    ) {
        Ok(key) => key,
        Err(error) => {
            return ActiveProfileDirectories {
                paths: Vec::new(),
                coverage: artifact_coverage(
                    "registry.profile-list",
                    "registry",
                    status_for_io_error(&error),
                    Some(error.to_string()),
                    observed_at_utc,
                ),
            };
        }
    };

    let mut paths = loaded_users
        .enum_keys()
        .filter_map(Result::ok)
        .filter(|sid| is_loaded_user_sid(sid))
        .take(MAX_ACTIVE_PROFILE_DIRECTORIES)
        .filter_map(|sid| profile_list.open_subkey_with_flags(sid, KEY_READ).ok())
        .filter_map(|key| key.get_value::<String, _>("ProfileImagePath").ok())
        .map(|path| {
            PathBuf::from(cmtraceopen_parser::collector::env_expand::expand_env_vars(
                &path,
            ))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    ActiveProfileDirectories {
        coverage: artifact_coverage(
            "registry.profile-list",
            "registry",
            EspArtifactStatus::Available,
            Some(format!("{} loaded user profile path(s)", paths.len())),
            observed_at_utc,
        ),
        paths,
    }
}

#[cfg(not(target_os = "windows"))]
fn active_profile_directories(observed_at_utc: &str) -> ActiveProfileDirectories {
    ActiveProfileDirectories {
        paths: Vec::new(),
        coverage: artifact_coverage(
            "registry.profile-list",
            "registry",
            EspArtifactStatus::Unsupported,
            None,
            observed_at_utc,
        ),
    }
}

#[cfg(target_os = "windows")]
fn status_for_io_error(error: &std::io::Error) -> EspArtifactStatus {
    match error.kind() {
        std::io::ErrorKind::NotFound => EspArtifactStatus::Missing,
        std::io::ErrorKind::PermissionDenied => EspArtifactStatus::PermissionDenied,
        _ => EspArtifactStatus::ParseFailed,
    }
}

#[cfg(target_os = "windows")]
fn is_loaded_user_sid(value: &str) -> bool {
    let value = value.strip_suffix("_Classes").unwrap_or(value);
    value.starts_with("S-1-")
        && value.len() <= 184
        && value
            .split('-')
            .skip(1)
            .all(|component| !component.is_empty() && component.chars().all(|c| c.is_ascii_digit()))
}

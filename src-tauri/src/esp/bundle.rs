//! Source-neutral, manifest-first intake for captured ESP evidence.
//!
//! Captured analysis reads only the selected directory or the uniquely scoped
//! archive extraction. It never falls back to equivalent registry, event-log,
//! process, discovery, or system facts from the analyst machine.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use cmtraceopen_parser::esp::{
    EspArtifactCoverage, EspArtifactStatus, EspDeliveryOptimizationEventKind,
    EspDeliveryOptimizationEvidence, EspDeliveryOptimizationObservation, EspDiagnosticsReducer,
    EspDiagnosticsSnapshot, EspEvidenceProvenance, EspEvidenceRecord, EspEvidenceRef, EspJoinMode,
    EspJsonObservation, EspObservationContext, EspObservationValue, EspParseState,
    EspRegistryObservation, EspRegistryProvenance, EspSensitivity, EspSourceAccessState,
    EspSourceKind, EspSystemFact, EspSystemObservation,
};
use cmtraceopen_parser::parser::registry::{RegistryParseResult, RegistryValue, RegistryValueKind};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use thiserror::Error;
use uuid::Uuid;

use super::archive::{
    extract_captured_archive, ExtractedArchive, MAX_ARCHIVE_FILE_BYTES,
    MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES,
};
use super::discovery::{
    open_verified_regular_file, DiscoveryPathFailureKind, VerifiedFileOpenFailure,
};
use super::event_logs::{collect_captured_evtx_files, EventEvidence};
use super::live_session::{event_evidence_to_batch, log_entries_to_records};
use super::system::{delivery_optimization_from_rows, SystemRow};

pub const MAX_BUNDLE_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_MANIFEST_ARTIFACTS: usize = 512;
pub const MAX_LEGACY_BUNDLE_DEPTH: usize = 3;
pub const MAX_LEGACY_BUNDLE_ENTRIES: usize = 256;
pub const MAX_JSON_SCALAR_RECORDS: usize = 4096;
pub const MAX_JSON_NODES: usize = 16_384;
pub const MAX_JSON_DEPTH: usize = 32;
pub const MAX_REGISTRY_RECORDS: usize = 8192;
pub const MAX_LOG_RECORDS_PER_ARTIFACT: usize = 65_536;
pub const MAX_DELIVERY_STATUS_RECORDS: usize = 64;
pub const MAX_BUNDLE_TOTAL_INPUT_BYTES: u64 = MAX_ARCHIVE_TOTAL_UNCOMPRESSED_BYTES;
pub const MAX_BUNDLE_TOTAL_RECORDS: usize = 131_072;

const SUPPORTED_MANIFEST_EXTENSIONS: &[&str] = &["evtx", "json", "log", "reg", "txt", "xml"];
const LEGACY_JSON_BASENAMES: &[&str] = &[
    "autopilotconfigurationfile.json",
    "autopilotddsztdfile.json",
    "delivery-optimization-perf-snap.json",
    "delivery-optimization-status.json",
    "esp-hardware-facts.json",
    "esp-os-facts.json",
    "esp-tpm-facts.json",
];

#[derive(Debug, Clone, Serialize, Error, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum BundleError {
    #[error("ESP diagnostics request ID must be a UUID")]
    InvalidRequestId,
    #[error("captured evidence source was not found: {path}")]
    SourceNotFound { path: String },
    #[error("unsupported captured evidence source: {path}")]
    UnsupportedSource { path: String },
    #[error("captured evidence source could not be accessed: {message}")]
    SourceAccess { message: String },
    #[error("captured archive extraction failed: {message}")]
    Archive { message: String },
}

#[derive(Debug)]
enum BundleRootOwner {
    Directory(PathBuf),
    Archive(ExtractedArchive),
}

impl BundleRootOwner {
    fn root(&self) -> &Path {
        match self {
            Self::Directory(path) => path,
            Self::Archive(archive) => archive.root(),
        }
    }
}

#[derive(Debug, Clone)]
struct BundleArtifact {
    artifact_id: String,
    family: String,
    category: String,
    relative_path: String,
    parse_hints: Vec<String>,
    status: Option<String>,
    observed_at_utc: String,
}

#[derive(Debug)]
struct PendingEventArtifact {
    staged_path: PathBuf,
    artifact: BundleArtifact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactKind {
    Registry,
    Json,
    EventLog,
    Log,
}

#[derive(Debug, Default)]
struct ArtifactParseOutcome {
    records: Vec<EspEvidenceRecord>,
    coverage: Vec<EspArtifactCoverage>,
    status: Option<EspArtifactStatus>,
    detail: Option<String>,
}

impl ArtifactParseOutcome {
    fn failed(detail: impl Into<String>) -> Self {
        Self {
            records: Vec::new(),
            coverage: Vec::new(),
            status: Some(EspArtifactStatus::ParseFailed),
            detail: Some(detail.into()),
        }
    }
}

#[derive(Debug)]
struct ArtifactStageFailure {
    status: EspArtifactStatus,
    detail: String,
    cumulative_limit: bool,
}

impl ArtifactStageFailure {
    fn from_verified(failure: VerifiedFileOpenFailure) -> Self {
        let status = match failure.kind {
            DiscoveryPathFailureKind::Missing => EspArtifactStatus::Missing,
            DiscoveryPathFailureKind::PermissionDenied => EspArtifactStatus::PermissionDenied,
            DiscoveryPathFailureKind::ReparseRejected
            | DiscoveryPathFailureKind::OutsideAllowedRoot
            | DiscoveryPathFailureKind::NotRegularFile => EspArtifactStatus::Unsupported,
            DiscoveryPathFailureKind::ResourceLimit | DiscoveryPathFailureKind::Failed => {
                EspArtifactStatus::ParseFailed
            }
        };
        Self {
            status,
            detail: failure.detail,
            cumulative_limit: false,
        }
    }

    fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: EspArtifactStatus::ParseFailed,
            detail: detail.into(),
            cumulative_limit: false,
        }
    }

    fn cumulative_limit(detail: impl Into<String>) -> Self {
        Self {
            status: EspArtifactStatus::ParseFailed,
            detail: detail.into(),
            cumulative_limit: true,
        }
    }
}

#[derive(Debug)]
struct BundleStagingArea {
    temp_dir: TempDir,
    next_stage_index: usize,
    staged_files: usize,
    staged_bytes: u64,
    input_limit: u64,
}

impl BundleStagingArea {
    fn new() -> Result<Self, String> {
        Self::new_with_input_limit(MAX_BUNDLE_TOTAL_INPUT_BYTES)
    }

    fn new_with_input_limit(input_limit: u64) -> Result<Self, String> {
        let temp_dir = tempfile::Builder::new()
            .prefix("cmtraceopen-esp-intake-")
            .tempdir()
            .map_err(|error| format!("could not create bounded intake staging: {error}"))?;
        Ok(Self {
            temp_dir,
            next_stage_index: 0,
            staged_files: 0,
            staged_bytes: 0,
            input_limit,
        })
    }

    fn stage(&mut self, root: &Path, relative: &Path) -> Result<PathBuf, ArtifactStageFailure> {
        let source_path = root.join(relative);
        let source = open_verified_regular_file(&source_path)
            .map_err(ArtifactStageFailure::from_verified)?;
        let source_size = source
            .metadata()
            .map_err(|error| ArtifactStageFailure::failed(error.to_string()))?
            .len();
        if source_size > MAX_ARCHIVE_FILE_BYTES {
            return Err(ArtifactStageFailure::failed(format!(
                "{} is {source_size} bytes; per-artifact maximum is {MAX_ARCHIVE_FILE_BYTES}",
                relative.display()
            )));
        }
        let remaining = self.input_limit.saturating_sub(self.staged_bytes);
        if source_size > remaining {
            return Err(ArtifactStageFailure::cumulative_limit(format!(
                "bounded bundle intake is partial: {} would exceed the {}-byte cumulative input limit",
                relative.display(),
                self.input_limit
            )));
        }

        let stage_index = self.next_stage_index;
        self.next_stage_index = self.next_stage_index.saturating_add(1);
        let stage_directory = self
            .temp_dir
            .path()
            .join(format!("artifact-{stage_index:03}"));
        fs::create_dir(&stage_directory)
            .map_err(|error| ArtifactStageFailure::failed(error.to_string()))?;
        let file_name = relative.file_name().ok_or_else(|| {
            ArtifactStageFailure::failed("artifact path does not contain a file name")
        })?;
        let staged_path = stage_directory.join(file_name);
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staged_path)
            .map_err(|error| ArtifactStageFailure::failed(error.to_string()))?;
        let mut bounded_source = source.take(source_size.saturating_add(1));
        let written = std::io::copy(&mut bounded_source, &mut output)
            .map_err(|error| ArtifactStageFailure::failed(error.to_string()))?;
        if written > source_size {
            return Err(ArtifactStageFailure::failed(format!(
                "{} grew beyond its {source_size}-byte verified size while being staged",
                relative.display()
            )));
        }
        output
            .flush()
            .map_err(|error| ArtifactStageFailure::failed(error.to_string()))?;
        self.staged_bytes = self.staged_bytes.saturating_add(written);
        self.staged_files = self.staged_files.saturating_add(1);
        Ok(staged_path)
    }
}

pub fn analyze_captured_evidence(
    path: &Path,
    request_id: &str,
) -> Result<EspDiagnosticsSnapshot, BundleError> {
    let observed_at_utc = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    analyze_captured_evidence_at(path, request_id, &observed_at_utc)
}

#[doc(hidden)]
pub fn analyze_captured_evidence_at(
    path: &Path,
    request_id: &str,
    observed_at_utc: &str,
) -> Result<EspDiagnosticsSnapshot, BundleError> {
    Uuid::parse_str(request_id).map_err(|_| BundleError::InvalidRequestId)?;
    let owner = open_bundle_root(path)?;
    let root = owner
        .root()
        .canonicalize()
        .map_err(|error| BundleError::SourceAccess {
            message: format!("{} ({error})", owner.root().display()),
        })?;

    let mut reducer = EspDiagnosticsReducer::new(observed_at_utc.to_string());
    let mut record_count = 0_usize;
    let mut coverage = Vec::new();
    let manifest_path = root.join("manifest.json");
    let artifacts = match open_verified_regular_file(&manifest_path) {
        Ok(manifest_file) => match read_manifest(manifest_file, &manifest_path, observed_at_utc) {
            Ok((artifacts, manifest_coverage)) => {
                coverage.extend(manifest_coverage);
                artifacts
            }
            Err(detail) => {
                coverage.push(artifact_coverage(
                    "bundle.manifest",
                    "manifest",
                    EspArtifactStatus::ParseFailed,
                    Some(detail),
                    observed_at_utc,
                ));
                Vec::new()
            }
        },
        Err(failure) if failure.kind == DiscoveryPathFailureKind::Missing => {
            let (artifacts, legacy_coverage) = resolve_legacy_artifacts(&root, observed_at_utc);
            coverage.extend(legacy_coverage);
            artifacts
        }
        Err(failure) => {
            coverage.push(artifact_coverage(
                "bundle.manifest",
                "manifest",
                status_for_verified_open_failure(failure.kind),
                Some(failure.detail),
                observed_at_utc,
            ));
            Vec::new()
        }
    };
    let mut staging =
        BundleStagingArea::new().map_err(|message| BundleError::SourceAccess { message })?;
    let mut pending_event_artifacts = Vec::new();

    for artifact in artifacts {
        if record_count >= MAX_BUNDLE_TOTAL_RECORDS {
            coverage.push(bundle_record_limit_coverage(observed_at_utc));
            break;
        }
        let source_artifact_id = source_artifact_id(&artifact);
        if let Some(status) = artifact.status.as_deref().and_then(manifest_status) {
            if status != EspArtifactStatus::Available {
                coverage.push(artifact_coverage(
                    source_artifact_id,
                    artifact.family,
                    status,
                    Some("manifest reports that the artifact was not collected".to_string()),
                    &artifact.observed_at_utc,
                ));
                continue;
            }
        }

        let relative = match safe_relative_path(&artifact.relative_path) {
            Some(relative) => relative,
            None => {
                coverage.push(artifact_coverage(
                    source_artifact_id,
                    artifact.family,
                    EspArtifactStatus::Unsupported,
                    Some("manifest artifact path is not a safe root-relative path".to_string()),
                    &artifact.observed_at_utc,
                ));
                continue;
            }
        };
        if !supported_manifest_artifact(&relative, &artifact) {
            coverage.push(artifact_coverage(
                source_artifact_id,
                artifact.family,
                EspArtifactStatus::Unsupported,
                Some("artifact type is outside the captured ESP intake allowlist".to_string()),
                &artifact.observed_at_utc,
            ));
            continue;
        }

        let staged = match staging.stage(&root, &relative) {
            Ok(staged) => staged,
            Err(failure) => {
                coverage.push(artifact_coverage(
                    source_artifact_id,
                    artifact.family,
                    failure.status,
                    Some(failure.detail),
                    &artifact.observed_at_utc,
                ));
                if failure.cumulative_limit {
                    coverage.push(artifact_coverage(
                        "bundle.intake-byte-limit",
                        "bundle-intake",
                        EspArtifactStatus::ParseFailed,
                        Some(format!(
                            "bounded bundle intake is partial after reaching the {MAX_BUNDLE_TOTAL_INPUT_BYTES}-byte cumulative input limit"
                        )),
                        observed_at_utc,
                    ));
                    break;
                }
                continue;
            }
        };

        if classify_artifact(&relative, &artifact) == ArtifactKind::EventLog {
            pending_event_artifacts.push(PendingEventArtifact {
                staged_path: staged,
                artifact,
            });
            continue;
        }

        let mut outcome = parse_artifact(&staged, &relative, &artifact);
        let remaining_records = MAX_BUNDLE_TOTAL_RECORDS.saturating_sub(record_count);
        let records_truncated = outcome.records.len() > remaining_records;
        outcome.records.truncate(remaining_records);
        record_count = record_count.saturating_add(outcome.records.len());
        reducer.ingest_all(outcome.records);
        coverage.extend(outcome.coverage);
        if records_truncated {
            outcome.status = Some(EspArtifactStatus::ParseFailed);
            outcome.detail = Some(format!(
                "bounded bundle evidence is partial: cumulative intake stopped at the {MAX_BUNDLE_TOTAL_RECORDS}-record limit"
            ));
        }
        coverage.push(artifact_coverage(
            source_artifact_id,
            artifact.family,
            outcome.status.unwrap_or(EspArtifactStatus::ParseFailed),
            outcome.detail,
            &artifact.observed_at_utc,
        ));
        if records_truncated {
            coverage.push(bundle_record_limit_coverage(observed_at_utc));
            break;
        }
    }

    if !pending_event_artifacts.is_empty() {
        let remaining_records = MAX_BUNDLE_TOTAL_RECORDS.saturating_sub(record_count);
        if remaining_records == 0 {
            coverage.push(bundle_record_limit_coverage(observed_at_utc));
        } else {
            let (mut event_records, event_coverage) =
                parse_event_artifacts(&pending_event_artifacts, observed_at_utc);
            let records_truncated = event_records.len() > remaining_records;
            event_records.truncate(remaining_records);
            reducer.ingest_all(event_records);
            coverage.extend(event_coverage);
            if records_truncated {
                coverage.push(bundle_record_limit_coverage(observed_at_utc));
            }
        }
    }

    deduplicate_coverage(&mut coverage);
    reducer.ingest_all(coverage.into_iter().map(EspEvidenceRecord::Coverage));
    Ok(reducer.snapshot())
}

fn bundle_record_limit_coverage(observed_at_utc: &str) -> EspArtifactCoverage {
    artifact_coverage(
        "bundle.intake-record-limit",
        "bundle-intake",
        EspArtifactStatus::ParseFailed,
        Some(format!(
            "bounded bundle evidence is partial: cumulative intake stopped at the {MAX_BUNDLE_TOTAL_RECORDS}-record limit"
        )),
        observed_at_utc,
    )
}

fn status_for_verified_open_failure(kind: DiscoveryPathFailureKind) -> EspArtifactStatus {
    match kind {
        DiscoveryPathFailureKind::Missing => EspArtifactStatus::Missing,
        DiscoveryPathFailureKind::PermissionDenied => EspArtifactStatus::PermissionDenied,
        DiscoveryPathFailureKind::ReparseRejected
        | DiscoveryPathFailureKind::OutsideAllowedRoot
        | DiscoveryPathFailureKind::NotRegularFile => EspArtifactStatus::Unsupported,
        DiscoveryPathFailureKind::ResourceLimit | DiscoveryPathFailureKind::Failed => {
            EspArtifactStatus::ParseFailed
        }
    }
}

fn open_bundle_root(path: &Path) -> Result<BundleRootOwner, BundleError> {
    let metadata = fs::metadata(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => BundleError::SourceNotFound {
            path: path.display().to_string(),
        },
        _ => BundleError::SourceAccess {
            message: format!("{} ({error})", path.display()),
        },
    })?;
    if metadata.is_dir() {
        return Ok(BundleRootOwner::Directory(path.to_path_buf()));
    }
    if !metadata.is_file() {
        return Err(BundleError::UnsupportedSource {
            path: path.display().to_string(),
        });
    }

    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if file_name.eq_ignore_ascii_case("manifest.json") {
        let parent = path
            .parent()
            .ok_or_else(|| BundleError::UnsupportedSource {
                path: path.display().to_string(),
            })?;
        return Ok(BundleRootOwner::Directory(parent.to_path_buf()));
    }
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("zip" | "cab") => extract_captured_archive(path)
            .map(BundleRootOwner::Archive)
            .map_err(|error| BundleError::Archive {
                message: error.to_string(),
            }),
        _ => Err(BundleError::UnsupportedSource {
            path: path.display().to_string(),
        }),
    }
}

fn read_manifest(
    manifest_file: File,
    manifest_path: &Path,
    observed_at_utc: &str,
) -> Result<(Vec<BundleArtifact>, Vec<EspArtifactCoverage>), String> {
    let bytes = read_bounded_reader(manifest_file, manifest_path, MAX_BUNDLE_MANIFEST_BYTES)?;
    let manifest: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("manifest.json is malformed: {error}"))?;
    let mut coverage = manifest_gap_coverage(&manifest, observed_at_utc);
    let manifest_observed = manifest
        .pointer("/collection/collectedUtc")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(observed_at_utc);
    let Some(values) = manifest.get("artifacts").and_then(Value::as_array) else {
        coverage.push(artifact_coverage(
            "bundle.manifest-artifacts",
            "manifest",
            EspArtifactStatus::ParseFailed,
            Some("manifest.json does not contain an artifacts array".to_string()),
            manifest_observed,
        ));
        return Ok((Vec::new(), coverage));
    };
    if values.is_empty() {
        coverage.push(artifact_coverage(
            "bundle.manifest-artifacts",
            "manifest",
            EspArtifactStatus::Missing,
            Some("manifest.json declares no captured artifacts".to_string()),
            manifest_observed,
        ));
    }
    if values.len() > MAX_MANIFEST_ARTIFACTS {
        coverage.push(artifact_coverage(
            "bundle.manifest-artifact-limit",
            "manifest",
            EspArtifactStatus::ParseFailed,
            Some(format!(
                "manifest declares {} artifacts; only the first {MAX_MANIFEST_ARTIFACTS} are analyzed",
                values.len()
            )),
            manifest_observed,
        ));
    }

    let mut artifacts = Vec::new();
    for (index, value) in values.iter().take(MAX_MANIFEST_ARTIFACTS).enumerate() {
        let fallback_id = format!("manifest-artifact-{index}");
        let artifact_id = value
            .get("artifactId")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&fallback_id)
            .to_string();
        let Some(relative_path) = value
            .get("relativePath")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        else {
            coverage.push(artifact_coverage(
                format!("bundle:{artifact_id}"),
                value
                    .get("family")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                EspArtifactStatus::ParseFailed,
                Some("manifest artifact has no relativePath".to_string()),
                manifest_observed,
            ));
            continue;
        };
        let category = value
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        let family = value
            .get("family")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| infer_family(Path::new(relative_path)));
        let parse_hints = value
            .get("parseHints")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let artifact_observed = value
            .get("collectedUtc")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(manifest_observed)
            .to_string();
        artifacts.push(BundleArtifact {
            artifact_id,
            family,
            category,
            relative_path: relative_path.to_string(),
            parse_hints,
            status: value
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string),
            observed_at_utc: artifact_observed,
        });
    }
    artifacts.sort_by(|left, right| {
        left.relative_path
            .cmp(&right.relative_path)
            .then_with(|| left.artifact_id.cmp(&right.artifact_id))
    });
    let mut unique_by_path = BTreeMap::new();
    let mut duplicate_paths = 0_usize;
    for artifact in artifacts {
        let identity = normalize_manifest_path_identity(&artifact.relative_path);
        if unique_by_path.contains_key(&identity) {
            duplicate_paths = duplicate_paths.saturating_add(1);
            continue;
        }
        unique_by_path.insert(identity, artifact);
    }
    if duplicate_paths != 0 {
        coverage.push(artifact_coverage(
            "bundle.manifest-duplicate-path",
            "manifest",
            EspArtifactStatus::ParseFailed,
            Some(format!(
                "manifest contained {duplicate_paths} duplicate artifact paths; duplicates were ignored before staging or parsing"
            )),
            manifest_observed,
        ));
    }
    let artifacts = unique_by_path.into_values().collect();
    Ok((artifacts, coverage))
}

fn normalize_manifest_path_identity(path: &str) -> String {
    path.trim()
        .replace('\\', "/")
        .split('/')
        .filter(|component| *component != ".")
        .collect::<Vec<_>>()
        .join("/")
        .to_ascii_lowercase()
}

fn manifest_gap_coverage(manifest: &Value, observed_at_utc: &str) -> Vec<EspArtifactCoverage> {
    manifest
        .pointer("/collection/results/gaps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, gap)| {
            let artifact_id = gap
                .get("artifactId")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(|value| format!("bundle:{value}"))
                .unwrap_or_else(|| format!("bundle:collection-gap-{index}"));
            let family = gap
                .get("family")
                .or_else(|| gap.get("category"))
                .and_then(Value::as_str)
                .unwrap_or("collection");
            let status = gap
                .get("status")
                .and_then(Value::as_str)
                .and_then(manifest_status)
                .unwrap_or(EspArtifactStatus::ParseFailed);
            let detail = gap
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_string);
            artifact_coverage(artifact_id, family, status, detail, observed_at_utc)
        })
        .collect()
}

fn resolve_legacy_artifacts(
    root: &Path,
    observed_at_utc: &str,
) -> (Vec<BundleArtifact>, Vec<EspArtifactCoverage>) {
    let mut artifacts = Vec::new();
    let mut coverage = Vec::new();
    let mut pending = VecDeque::from([(root.to_path_buf(), 0_usize)]);
    let mut inspected = 0_usize;
    let mut limit_reached = false;

    'walk: while let Some((directory, depth)) = pending.pop_front() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                coverage.push(artifact_coverage(
                    format!(
                        "bundle.legacy-directory:{}",
                        portable_relative(root, &directory)
                    ),
                    "legacy-discovery",
                    if error.kind() == std::io::ErrorKind::PermissionDenied {
                        EspArtifactStatus::PermissionDenied
                    } else {
                        EspArtifactStatus::ParseFailed
                    },
                    Some(error.to_string()),
                    observed_at_utc,
                ));
                continue;
            }
        };
        let remaining = MAX_LEGACY_BUNDLE_ENTRIES.saturating_sub(inspected);
        if remaining == 0 {
            limit_reached = true;
            break 'walk;
        }
        let mut selected_entries = BTreeMap::new();
        let mut successful_entries = 0_usize;
        let mut entry_errors = 0_usize;
        for (index, entry) in entries.enumerate() {
            match entry {
                Ok(entry) => {
                    successful_entries = successful_entries.saturating_add(1);
                    let exact_name = entry.file_name().to_string_lossy().into_owned();
                    selected_entries.insert((exact_name.to_ascii_lowercase(), exact_name), entry);
                    if selected_entries.len() > remaining {
                        selected_entries.pop_last();
                    }
                }
                Err(error) => {
                    if entry_errors < remaining {
                        coverage.push(artifact_coverage(
                            format!(
                                "bundle.legacy-directory:{}:entry-{index}",
                                portable_relative(root, &directory)
                            ),
                            "legacy-discovery",
                            EspArtifactStatus::ParseFailed,
                            Some(error.to_string()),
                            observed_at_utc,
                        ));
                    }
                    entry_errors = entry_errors.saturating_add(1);
                }
            }
        }
        let retained_errors = entry_errors.min(remaining);
        let retained_successes = remaining.saturating_sub(retained_errors);
        while selected_entries.len() > retained_successes {
            selected_entries.pop_last();
        }
        let entries = selected_entries.into_values().collect::<Vec<_>>();
        inspected = inspected.saturating_add(retained_errors + entries.len());
        limit_reached = successful_entries.saturating_add(entry_errors) > remaining;
        for entry in entries {
            let entry_depth = depth.saturating_add(1);
            let path = entry.path();
            let relative = portable_relative(root, &path);
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    coverage.push(artifact_coverage(
                        format!("bundle.legacy:{relative}"),
                        "legacy-discovery",
                        EspArtifactStatus::ParseFailed,
                        Some(error.to_string()),
                        observed_at_utc,
                    ));
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                coverage.push(artifact_coverage(
                    format!("bundle.legacy:{relative}"),
                    "legacy-discovery",
                    EspArtifactStatus::Unsupported,
                    Some(
                        "legacy fallback does not follow symbolic links or reparse points"
                            .to_string(),
                    ),
                    observed_at_utc,
                ));
                continue;
            }
            if metadata.is_dir() {
                if entry_depth < MAX_LEGACY_BUNDLE_DEPTH {
                    pending.push_back((path, entry_depth));
                }
                continue;
            }
            if !metadata.is_file()
                || entry_depth > MAX_LEGACY_BUNDLE_DEPTH
                || !legacy_allowed_path(&path)
            {
                continue;
            }
            let family = infer_family(&path);
            artifacts.push(BundleArtifact {
                artifact_id: format!("legacy:{relative}"),
                family,
                category: "legacy".to_string(),
                relative_path: relative,
                parse_hints: Vec::new(),
                status: Some("collected".to_string()),
                observed_at_utc: observed_at_utc.to_string(),
            });
        }
        if limit_reached {
            break 'walk;
        }
    }
    if limit_reached {
        coverage.push(artifact_coverage(
            "bundle.legacy-limit",
            "legacy-discovery",
            EspArtifactStatus::ParseFailed,
            Some(format!(
                "legacy fallback stopped after {MAX_LEGACY_BUNDLE_ENTRIES} directory entries"
            )),
            observed_at_utc,
        ));
    }
    artifacts.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    (artifacts, coverage)
}

fn parse_artifact(path: &Path, relative: &Path, artifact: &BundleArtifact) -> ArtifactParseOutcome {
    let kind = classify_artifact(relative, artifact);
    match kind {
        ArtifactKind::Registry => parse_registry_artifact(path, artifact),
        ArtifactKind::Json => parse_json_artifact(path, artifact),
        ArtifactKind::EventLog => {
            ArtifactParseOutcome::failed("event artifacts must be parsed as a reconciled batch")
        }
        ArtifactKind::Log => parse_log_artifact(path, artifact),
    }
}

fn parse_registry_artifact(path: &Path, artifact: &BundleArtifact) -> ArtifactParseOutcome {
    let bytes = match read_bounded_file(path, MAX_ARCHIVE_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return ArtifactParseOutcome::failed(error),
    };
    let content = match crate::parser::decode_bytes(&bytes, crate::parser::detect_encoding(&bytes))
    {
        Ok(content) => content,
        Err(error) => return ArtifactParseOutcome::failed(error),
    };
    let parsed = cmtraceopen_parser::parser::registry::parse_registry_content(
        &content,
        &artifact.relative_path,
        bytes.len() as u64,
    );
    let (mut records, registry_truncated) = registry_records(&parsed, artifact);
    let (embedded_json, json_truncated) = registry_embedded_json_records(&parsed, artifact);
    records.extend(embedded_json);
    let incomplete = parsed.parse_errors != 0 || registry_truncated || json_truncated;
    let mut limitations = Vec::new();
    if parsed.parse_errors != 0 {
        limitations.push(format!("{} malformed lines", parsed.parse_errors));
    }
    if registry_truncated {
        limitations.push(format!(
            "registry values reached the {MAX_REGISTRY_RECORDS}-record bound"
        ));
    }
    if json_truncated {
        limitations.push(format!(
            "embedded JSON reached a structural or {MAX_JSON_SCALAR_RECORDS}-record bound"
        ));
    }
    let detail = (!limitations.is_empty()).then(|| {
        format!(
            "registry evidence was partial: {}; parsed values were retained",
            limitations.join(", ")
        )
    });
    ArtifactParseOutcome {
        records,
        coverage: Vec::new(),
        status: Some(if incomplete {
            EspArtifactStatus::ParseFailed
        } else {
            EspArtifactStatus::Available
        }),
        detail,
    }
}

fn registry_records(
    parsed: &RegistryParseResult,
    artifact: &BundleArtifact,
) -> (Vec<EspEvidenceRecord>, bool) {
    let source_artifact_id = source_artifact_id(artifact);
    let mut records = Vec::new();
    let mut ordinal = 0_usize;
    let mut truncated = false;
    let mut inspected = 0_usize;
    'registry: for key in &parsed.keys {
        let (hive, key_path) = split_registry_path(&key.path);
        for value in &key.values {
            if inspected >= MAX_REGISTRY_RECORDS {
                truncated = true;
                break 'registry;
            }
            inspected += 1;
            if value.kind == RegistryValueKind::DeleteMarker
                || contains_hardware_hash(&key_path)
                || contains_hardware_hash(&value.name)
            {
                continue;
            }
            let observation_value = registry_observation_value(value);
            records.push(EspEvidenceRecord::Registry(EspRegistryObservation {
                context: EspObservationContext {
                    evidence_ref: EspEvidenceRef {
                        evidence_id: format!("{source_artifact_id}:registry:{ordinal}"),
                        source_artifact_id: source_artifact_id.clone(),
                    },
                    provenance: EspEvidenceProvenance {
                        source_kind: EspSourceKind::Registry,
                        source_artifact_id: source_artifact_id.clone(),
                        file_path: Some(parsed.file_path.clone()),
                        line_number: Some(u64::from(value.line_number)),
                        record_number: Some(ordinal as u64),
                        registry: Some(EspRegistryProvenance {
                            hive: hive.clone(),
                            key: key_path.clone(),
                            value_name: Some(value.name.clone()),
                        }),
                        event: None,
                    },
                    source_timestamp: None,
                    observed_at_utc: artifact.observed_at_utc.clone(),
                    sensitivity: registry_sensitivity(&key_path, &value.name),
                    parse_state: EspParseState::Parsed,
                    access_state: EspSourceAccessState::Available,
                },
                hive: hive.clone(),
                key: key_path.clone(),
                value_name: value.name.clone(),
                value: observation_value,
            }));
            ordinal += 1;
        }
    }
    (records, truncated)
}

fn registry_embedded_json_records(
    parsed: &RegistryParseResult,
    artifact: &BundleArtifact,
) -> (Vec<EspEvidenceRecord>, bool) {
    let source_artifact_id = source_artifact_id(artifact);
    let mut records = Vec::new();
    let mut ordinal = 0_usize;
    let mut truncated = false;
    let mut inspected = 0_usize;
    'registry_json: for key in &parsed.keys {
        let (hive, key_path) = split_registry_path(&key.path);
        for value in &key.values {
            if inspected >= MAX_REGISTRY_RECORDS {
                truncated = true;
                break 'registry_json;
            }
            inspected += 1;
            if contains_hardware_hash(&key_path) || contains_hardware_hash(&value.name) {
                continue;
            }
            let Some(document_type) = known_document_type(&value.name) else {
                continue;
            };
            let Ok(document) = serde_json::from_str::<Value>(&value.data) else {
                continue;
            };
            if !json_within_structure_limits(&document) {
                truncated = true;
                continue;
            }
            let provenance = EspEvidenceProvenance {
                source_kind: EspSourceKind::Json,
                source_artifact_id: source_artifact_id.clone(),
                file_path: Some(parsed.file_path.clone()),
                line_number: Some(u64::from(value.line_number)),
                record_number: None,
                registry: Some(EspRegistryProvenance {
                    hive: hive.clone(),
                    key: key_path.clone(),
                    value_name: Some(value.name.clone()),
                }),
                event: None,
            };
            flatten_json_value(
                &document,
                "",
                document_type,
                &source_artifact_id,
                provenance,
                &artifact.observed_at_utc,
                &mut ordinal,
                &mut records,
                &mut truncated,
                0,
            );
        }
    }
    (records, truncated)
}

fn parse_json_artifact(path: &Path, artifact: &BundleArtifact) -> ArtifactParseOutcome {
    let bytes = match read_bounded_file(path, MAX_ARCHIVE_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return ArtifactParseOutcome::failed(error),
    };
    let document: Value = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(error) => return ArtifactParseOutcome::failed(format!("JSON is malformed: {error}")),
    };
    if !json_within_structure_limits(&document) {
        return ArtifactParseOutcome::failed(format!(
            "JSON exceeds the {MAX_JSON_NODES}-node or {MAX_JSON_DEPTH}-depth structural bound"
        ));
    }
    let source_artifact_id = source_artifact_id(artifact);
    let provenance = EspEvidenceProvenance {
        source_kind: EspSourceKind::Json,
        source_artifact_id: source_artifact_id.clone(),
        file_path: Some(artifact.relative_path.clone()),
        line_number: None,
        record_number: None,
        registry: None,
        event: None,
    };
    let document_type = artifact_document_type(artifact);
    let mut records = Vec::new();
    let mut ordinal = 0_usize;
    let mut truncated = false;
    flatten_json_value(
        &document,
        "",
        &document_type,
        &source_artifact_id,
        provenance.clone(),
        &artifact.observed_at_utc,
        &mut ordinal,
        &mut records,
        &mut truncated,
        0,
    );
    if !is_known_document_type(&document_type) {
        flatten_known_nested_documents(
            &document,
            &source_artifact_id,
            &provenance,
            &artifact.observed_at_utc,
            &mut ordinal,
            &mut records,
            &mut truncated,
            0,
        );
    }
    records.extend(system_records_from_json(
        &document,
        artifact,
        &source_artifact_id,
    ));
    records.extend(delivery_summary_from_json(
        &document,
        artifact,
        &source_artifact_id,
    ));
    records.extend(delivery_status_from_json(
        &document,
        artifact,
        &source_artifact_id,
    ));
    ArtifactParseOutcome {
        records,
        coverage: Vec::new(),
        status: Some(if truncated {
            EspArtifactStatus::ParseFailed
        } else {
            EspArtifactStatus::Available
        }),
        detail: truncated.then(|| {
            format!("JSON scalar intake stopped at the {MAX_JSON_SCALAR_RECORDS}-record bound")
        }),
    }
}

fn parse_event_artifacts(
    pending_event_artifacts: &[PendingEventArtifact],
    observed_at_utc: &str,
) -> (Vec<EspEvidenceRecord>, Vec<EspArtifactCoverage>) {
    let paths = pending_event_artifacts
        .iter()
        .map(|pending| pending.staged_path.clone())
        .collect::<Vec<_>>();
    match collect_captured_evtx_files(&paths, observed_at_utc) {
        Ok(evidence) => normalize_event_batch(evidence, pending_event_artifacts, observed_at_utc),
        Err(_) => {
            let mut records = Vec::new();
            let mut coverage = Vec::new();
            for pending in pending_event_artifacts {
                match collect_captured_evtx_files(
                    std::slice::from_ref(&pending.staged_path),
                    observed_at_utc,
                ) {
                    Ok(evidence) => {
                        let (artifact_records, artifact_coverage) = normalize_event_batch(
                            evidence,
                            std::slice::from_ref(pending),
                            observed_at_utc,
                        );
                        records.extend(artifact_records);
                        coverage.extend(artifact_coverage);
                    }
                    Err(error) => coverage.push(artifact_coverage(
                        source_artifact_id(&pending.artifact),
                        pending.artifact.family.clone(),
                        EspArtifactStatus::ParseFailed,
                        Some(format!("{error:?}")),
                        &pending.artifact.observed_at_utc,
                    )),
                }
            }
            (records, coverage)
        }
    }
}

fn normalize_event_batch(
    evidence: EventEvidence,
    pending_event_artifacts: &[PendingEventArtifact],
    observed_at_utc: &str,
) -> (Vec<EspEvidenceRecord>, Vec<EspArtifactCoverage>) {
    let artifacts_by_staged_path = pending_event_artifacts
        .iter()
        .map(|pending| {
            (
                normalize_manifest_path_identity(&portable_path(&pending.staged_path)),
                &pending.artifact,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut batch = event_evidence_to_batch(evidence, observed_at_utc);
    batch.records.retain_mut(|record| {
        let EspEvidenceRecord::EventLog(observation) = record else {
            return false;
        };
        let Some(staged_path) = observation.context.provenance.file_path.as_deref() else {
            return false;
        };
        let identity = normalize_manifest_path_identity(staged_path);
        let Some(artifact) = artifacts_by_staged_path.get(&identity) else {
            return false;
        };
        let source_artifact_id = source_artifact_id(artifact);
        observation.context.evidence_ref.source_artifact_id = source_artifact_id.clone();
        observation.context.provenance.source_artifact_id = source_artifact_id;
        observation.context.provenance.file_path = Some(artifact.relative_path.clone());
        observation.context.observed_at_utc = artifact.observed_at_utc.clone();
        true
    });
    batch
        .coverage
        .extend(pending_event_artifacts.iter().map(|pending| {
            artifact_coverage(
                source_artifact_id(&pending.artifact),
                pending.artifact.family.clone(),
                EspArtifactStatus::Available,
                None,
                &pending.artifact.observed_at_utc,
            )
        }));
    (batch.records, batch.coverage)
}

fn parse_log_artifact(path: &Path, artifact: &BundleArtifact) -> ArtifactParseOutcome {
    let bytes = match read_bounded_file(path, MAX_ARCHIVE_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => return ArtifactParseOutcome::failed(error),
    };
    let content = match crate::parser::decode_bytes(&bytes, crate::parser::detect_encoding(&bytes))
    {
        Ok(content) => content,
        Err(error) => return ArtifactParseOutcome::failed(error),
    };
    let (mut result, _) =
        crate::parser::parse_content(&content, &artifact.relative_path, bytes.len() as u64);
    let parse_errors = result.parse_errors;
    let records_truncated = result.entries.len() > MAX_LOG_RECORDS_PER_ARTIFACT;
    result.entries.truncate(MAX_LOG_RECORDS_PER_ARTIFACT);
    result.entries.retain(|entry| {
        serde_json::to_string(entry)
            .map(|serialized| !contains_hardware_hash(&serialized))
            .unwrap_or(false)
    });
    let source_artifact_id = source_artifact_id(artifact);
    let mut records = dsregcmd_system_records(&result.entries, artifact, &source_artifact_id);
    records.extend(log_entries_to_records(
        Path::new(&artifact.relative_path),
        &source_artifact_id,
        &artifact.family,
        result.entries,
        &artifact.observed_at_utc,
    ));
    ArtifactParseOutcome {
        records,
        coverage: Vec::new(),
        status: Some(if parse_errors != 0 || records_truncated {
            EspArtifactStatus::ParseFailed
        } else {
            EspArtifactStatus::Available
        }),
        detail: match (parse_errors, records_truncated) {
            (0, false) => None,
            (errors, false) => Some(format!("text parser reported {errors} malformed records")),
            (0, true) => Some(format!(
                "text intake stopped at the {MAX_LOG_RECORDS_PER_ARTIFACT}-record bound"
            )),
            (errors, true) => Some(format!(
                "text parser reported {errors} malformed records and intake stopped at the {MAX_LOG_RECORDS_PER_ARTIFACT}-record bound"
            )),
        },
    }
}

fn dsregcmd_system_records(
    entries: &[crate::models::log_entry::LogEntry],
    artifact: &BundleArtifact,
    source_artifact_id: &str,
) -> Vec<EspEvidenceRecord> {
    if !semantic_identity(artifact).contains("dsregcmd-status") {
        return Vec::new();
    }
    let mut values = BTreeMap::new();
    for entry in entries {
        let Some((name, value)) = entry.message.split_once(':') else {
            continue;
        };
        let name = normalize_semantic(name);
        let value = value.trim();
        if !value.is_empty() {
            values.entry(name).or_insert_with(|| value.to_string());
        }
    }

    let mut facts = Vec::<(EspSystemFact, EspSensitivity)>::new();
    if let Some(value) = values.get("devicename") {
        facts.push((
            EspSystemFact::Hostname(value.clone()),
            EspSensitivity::Public,
        ));
    }
    if let Some(value) = values.get("deviceid") {
        facts.push((
            EspSystemFact::EntraDeviceId(value.clone()),
            EspSensitivity::Public,
        ));
    }
    if let Some(value) = values.get("tenantid") {
        facts.push((
            EspSystemFact::TenantId(value.clone()),
            EspSensitivity::Sensitive,
        ));
    }
    let azure_ad_joined = values
        .get("azureadjoined")
        .is_some_and(|value| value.eq_ignore_ascii_case("yes"));
    let domain_joined = values
        .get("domainjoined")
        .is_some_and(|value| value.eq_ignore_ascii_case("yes"));
    if azure_ad_joined {
        facts.push((
            EspSystemFact::JoinMode(if domain_joined {
                EspJoinMode::HybridEntra
            } else {
                EspJoinMode::Entra
            }),
            EspSensitivity::Public,
        ));
    }

    facts
        .into_iter()
        .enumerate()
        .map(|(index, (fact, sensitivity))| {
            EspEvidenceRecord::System(EspSystemObservation {
                context: EspObservationContext {
                    evidence_ref: EspEvidenceRef {
                        evidence_id: format!("{source_artifact_id}:dsregcmd:{index}"),
                        source_artifact_id: source_artifact_id.to_string(),
                    },
                    provenance: EspEvidenceProvenance {
                        source_kind: EspSourceKind::System,
                        source_artifact_id: source_artifact_id.to_string(),
                        file_path: Some(artifact.relative_path.clone()),
                        line_number: None,
                        record_number: Some(index as u64),
                        registry: None,
                        event: None,
                    },
                    source_timestamp: None,
                    observed_at_utc: artifact.observed_at_utc.clone(),
                    sensitivity,
                    parse_state: EspParseState::Parsed,
                    access_state: EspSourceAccessState::Available,
                },
                fact,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn flatten_json_value(
    value: &Value,
    pointer: &str,
    document_type: &str,
    source_artifact_id: &str,
    provenance: EspEvidenceProvenance,
    observed_at_utc: &str,
    ordinal: &mut usize,
    records: &mut Vec<EspEvidenceRecord>,
    truncated: &mut bool,
    depth: usize,
) {
    if *ordinal >= MAX_JSON_SCALAR_RECORDS || depth > MAX_JSON_DEPTH {
        *truncated = true;
        return;
    }
    match value {
        Value::Object(values) => {
            for (name, value) in values {
                if *ordinal >= MAX_JSON_SCALAR_RECORDS {
                    *truncated = true;
                    break;
                }
                let child = format!("{pointer}/{}", escape_json_pointer(name));
                flatten_json_value(
                    value,
                    &child,
                    document_type,
                    source_artifact_id,
                    provenance.clone(),
                    observed_at_utc,
                    ordinal,
                    records,
                    truncated,
                    depth + 1,
                );
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if *ordinal >= MAX_JSON_SCALAR_RECORDS {
                    *truncated = true;
                    break;
                }
                let child = format!("{pointer}/{index}");
                flatten_json_value(
                    value,
                    &child,
                    document_type,
                    source_artifact_id,
                    provenance.clone(),
                    observed_at_utc,
                    ordinal,
                    records,
                    truncated,
                    depth + 1,
                );
            }
        }
        Value::Null => {}
        scalar => {
            if contains_hardware_hash(document_type) || contains_hardware_hash(pointer) {
                return;
            }
            let Some(value) = json_observation_value(scalar) else {
                return;
            };
            let evidence_ref = EspEvidenceRef {
                evidence_id: format!("{source_artifact_id}:json:{}", *ordinal),
                source_artifact_id: source_artifact_id.to_string(),
            };
            let mut provenance = provenance;
            provenance.record_number = Some(*ordinal as u64);
            records.push(EspEvidenceRecord::Json(EspJsonObservation {
                context: EspObservationContext {
                    evidence_ref,
                    provenance,
                    source_timestamp: None,
                    observed_at_utc: observed_at_utc.to_string(),
                    sensitivity: json_sensitivity(pointer),
                    parse_state: EspParseState::Parsed,
                    access_state: EspSourceAccessState::Available,
                },
                document_type: document_type.to_string(),
                json_pointer: if pointer.is_empty() {
                    "/".to_string()
                } else {
                    pointer.to_string()
                },
                value,
            }));
            *ordinal += 1;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn flatten_known_nested_documents(
    value: &Value,
    source_artifact_id: &str,
    provenance: &EspEvidenceProvenance,
    observed_at_utc: &str,
    ordinal: &mut usize,
    records: &mut Vec<EspEvidenceRecord>,
    truncated: &mut bool,
    depth: usize,
) {
    if depth > MAX_JSON_DEPTH {
        *truncated = true;
        return;
    }
    if *ordinal >= MAX_JSON_SCALAR_RECORDS {
        if contains_known_document(value, depth) {
            *truncated = true;
        }
        return;
    }
    match value {
        Value::Object(values) => {
            for (name, value) in values {
                if let Some(document_type) = known_document_type(name) {
                    flatten_json_value(
                        value,
                        "",
                        document_type,
                        source_artifact_id,
                        provenance.clone(),
                        observed_at_utc,
                        ordinal,
                        records,
                        truncated,
                        depth + 1,
                    );
                } else {
                    flatten_known_nested_documents(
                        value,
                        source_artifact_id,
                        provenance,
                        observed_at_utc,
                        ordinal,
                        records,
                        truncated,
                        depth + 1,
                    );
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                flatten_known_nested_documents(
                    value,
                    source_artifact_id,
                    provenance,
                    observed_at_utc,
                    ordinal,
                    records,
                    truncated,
                    depth + 1,
                );
            }
        }
        _ => {}
    }
}

fn contains_known_document(value: &Value, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match value {
        Value::Object(values) => values.iter().any(|(name, value)| {
            known_document_type(name).is_some() || contains_known_document(value, depth + 1)
        }),
        Value::Array(values) => values
            .iter()
            .any(|value| contains_known_document(value, depth + 1)),
        _ => false,
    }
}

fn json_within_structure_limits(document: &Value) -> bool {
    let mut pending = vec![(document, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = pending.pop() {
        nodes += 1;
        if nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH {
            return false;
        }
        match value {
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            _ => {}
        }
    }
    true
}

fn system_records_from_json(
    document: &Value,
    artifact: &BundleArtifact,
    source_artifact_id: &str,
) -> Vec<EspEvidenceRecord> {
    let semantic = semantic_identity(artifact);
    let mut facts = Vec::new();
    if semantic.contains("esp-os-facts") {
        push_system_fact(document, "Version", EspSystemFact::OsVersion, &mut facts);
        push_system_fact(document, "BuildNumber", EspSystemFact::OsBuild, &mut facts);
    }
    if semantic.contains("esp-hardware-facts") {
        push_system_fact(
            document,
            "Manufacturer",
            EspSystemFact::Manufacturer,
            &mut facts,
        );
        push_system_fact(document, "Model", EspSystemFact::Model, &mut facts);
        push_system_fact(
            document,
            "SerialNumber",
            EspSystemFact::SerialNumber,
            &mut facts,
        );
    }
    if semantic.contains("esp-tpm-facts") {
        push_system_fact(
            document,
            "ManufacturerVersion",
            EspSystemFact::TpmVersion,
            &mut facts,
        );
    }
    facts
        .into_iter()
        .enumerate()
        .map(|(index, fact)| {
            let sensitivity = if matches!(fact, EspSystemFact::SerialNumber(_)) {
                EspSensitivity::Sensitive
            } else {
                EspSensitivity::Public
            };
            EspEvidenceRecord::System(EspSystemObservation {
                context: EspObservationContext {
                    evidence_ref: EspEvidenceRef {
                        evidence_id: format!("{source_artifact_id}:system:{index}"),
                        source_artifact_id: source_artifact_id.to_string(),
                    },
                    provenance: EspEvidenceProvenance {
                        source_kind: EspSourceKind::System,
                        source_artifact_id: source_artifact_id.to_string(),
                        file_path: Some(artifact.relative_path.clone()),
                        line_number: None,
                        record_number: Some(index as u64),
                        registry: None,
                        event: None,
                    },
                    source_timestamp: None,
                    observed_at_utc: artifact.observed_at_utc.clone(),
                    sensitivity,
                    parse_state: EspParseState::Parsed,
                    access_state: EspSourceAccessState::Available,
                },
                fact,
            })
        })
        .collect()
}

fn push_system_fact(
    document: &Value,
    name: &str,
    constructor: fn(String) -> EspSystemFact,
    facts: &mut Vec<EspSystemFact>,
) {
    if let Some(value) = object_value_case_insensitive(document, name).and_then(json_scalar_text) {
        if !value.trim().is_empty() {
            facts.push(constructor(value));
        }
    }
}

fn delivery_summary_from_json(
    document: &Value,
    artifact: &BundleArtifact,
    source_artifact_id: &str,
) -> Vec<EspEvidenceRecord> {
    if !semantic_identity(artifact).contains("delivery-optimization-perf") {
        return Vec::new();
    }
    let values = document
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| std::slice::from_ref(document));
    let rows = values
        .iter()
        .filter_map(Value::as_object)
        .map(|object| {
            SystemRow::new(object.iter().filter_map(|(name, value)| {
                json_scalar_text(value).map(|value| (name.clone(), value))
            }))
        })
        .collect::<Vec<_>>();
    let Some(mut summary) = delivery_optimization_from_rows(&rows, &artifact.observed_at_utc)
    else {
        return Vec::new();
    };
    summary.evidence.push(EspEvidenceRef {
        evidence_id: format!("{source_artifact_id}:delivery-summary"),
        source_artifact_id: source_artifact_id.to_string(),
    });
    vec![EspEvidenceRecord::DeliveryOptimizationSummary(summary)]
}

fn delivery_status_from_json(
    document: &Value,
    artifact: &BundleArtifact,
    source_artifact_id: &str,
) -> Vec<EspEvidenceRecord> {
    if !semantic_identity(artifact).contains("delivery-optimization-status") {
        return Vec::new();
    }
    let values = document
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_else(|| std::slice::from_ref(document));
    let mut observations = Vec::new();
    let mut evidence = Vec::new();
    let mut download_http_bytes = 0_u64;
    let mut download_lan_bytes = 0_u64;
    let mut download_cache_host_bytes = 0_u64;

    for (index, object) in values
        .iter()
        .filter_map(Value::as_object)
        .take(MAX_DELIVERY_STATUS_RECORDS)
        .enumerate()
    {
        let field = |name: &str| {
            object.iter().find_map(|(candidate, value)| {
                candidate
                    .eq_ignore_ascii_case(name)
                    .then(|| json_scalar_text(value))
                    .flatten()
            })
        };
        let status = field("Status").unwrap_or_default();
        let kind = if [
            "complete",
            "completed",
            "success",
            "succeeded",
            "transferred",
        ]
        .iter()
        .any(|candidate| status.eq_ignore_ascii_case(candidate))
        {
            EspDeliveryOptimizationEventKind::DownloadCompleted
        } else {
            EspDeliveryOptimizationEventKind::DownloadStarted
        };
        let http_bytes = field("BytesFromHttp").and_then(|value| value.parse::<u64>().ok());
        let lan_bytes = field("BytesFromLanPeers").and_then(|value| value.parse::<u64>().ok());
        let cache_host_bytes =
            field("BytesFromCacheServer").and_then(|value| value.parse::<u64>().ok());
        download_http_bytes = download_http_bytes.saturating_add(http_bytes.unwrap_or(0));
        download_lan_bytes = download_lan_bytes.saturating_add(lan_bytes.unwrap_or(0));
        download_cache_host_bytes =
            download_cache_host_bytes.saturating_add(cache_host_bytes.unwrap_or(0));
        let evidence_ref = EspEvidenceRef {
            evidence_id: format!("{source_artifact_id}:delivery-status:{index}"),
            source_artifact_id: source_artifact_id.to_string(),
        };
        evidence.push(evidence_ref.clone());
        observations.push(EspEvidenceRecord::DeliveryOptimization(
            EspDeliveryOptimizationObservation {
                context: EspObservationContext {
                    evidence_ref,
                    provenance: EspEvidenceProvenance {
                        source_kind: EspSourceKind::DeliveryOptimization,
                        source_artifact_id: source_artifact_id.to_string(),
                        file_path: Some(artifact.relative_path.clone()),
                        line_number: None,
                        record_number: Some(index as u64),
                        registry: None,
                        event: None,
                    },
                    source_timestamp: None,
                    observed_at_utc: artifact.observed_at_utc.clone(),
                    sensitivity: EspSensitivity::Public,
                    parse_state: EspParseState::Parsed,
                    access_state: EspSourceAccessState::Available,
                },
                kind,
                content_id: field("FileId"),
                app_id: None,
                http_bytes,
                lan_bytes,
                cache_host_bytes,
            },
        ));
    }
    if observations.is_empty() {
        return observations;
    }
    let share = |bytes: u64| {
        (download_http_bytes != 0).then(|| (bytes as f64 / download_http_bytes as f64) * 100.0)
    };
    observations.push(EspEvidenceRecord::DeliveryOptimizationSummary(
        EspDeliveryOptimizationEvidence {
            download_http_bytes,
            download_lan_bytes,
            download_cache_host_bytes,
            peer_share_percent: share(download_lan_bytes),
            connected_cache_share_percent: share(download_cache_host_bytes),
            transfers: Vec::new(),
            evidence,
        },
    ));
    observations
}

fn object_value_case_insensitive<'a>(document: &'a Value, name: &str) -> Option<&'a Value> {
    document
        .as_object()?
        .iter()
        .find_map(|(candidate, value)| candidate.eq_ignore_ascii_case(name).then_some(value))
}

fn json_observation_value(value: &Value) -> Option<EspObservationValue> {
    match value {
        Value::String(value) => Some(EspObservationValue::Text(value.clone())),
        Value::Number(value) => value
            .as_i64()
            .map(EspObservationValue::Integer)
            .or_else(|| value.as_u64().map(EspObservationValue::Unsigned))
            .or_else(|| Some(EspObservationValue::Text(value.to_string()))),
        Value::Bool(value) => Some(EspObservationValue::Boolean(*value)),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn json_scalar_text(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn registry_observation_value(value: &RegistryValue) -> EspObservationValue {
    match value.kind {
        RegistryValueKind::Dword | RegistryValueKind::Qword => decimal_registry_value(&value.data)
            .map(EspObservationValue::Unsigned)
            .unwrap_or_else(|| EspObservationValue::Text(value.data.clone())),
        RegistryValueKind::MultiString => {
            EspObservationValue::StringList(value.data.split(" | ").map(str::to_string).collect())
        }
        RegistryValueKind::String
        | RegistryValueKind::ExpandString
        | RegistryValueKind::Binary
        | RegistryValueKind::None
        | RegistryValueKind::DeleteMarker => EspObservationValue::Text(value.data.clone()),
    }
}

fn decimal_registry_value(value: &str) -> Option<u64> {
    let start = value.rfind('(')?.saturating_add(1);
    let end = value.rfind(')')?;
    (start <= end).then(|| value[start..end].trim().parse().ok())?
}

fn split_registry_path(path: &str) -> (String, String) {
    let (raw_hive, key) = path.split_once('\\').unwrap_or((path, ""));
    let hive = match raw_hive.to_ascii_uppercase().as_str() {
        "HKEY_LOCAL_MACHINE" | "HKLM" => "HKLM",
        "HKEY_CURRENT_USER" | "HKCU" => "HKCU",
        "HKEY_USERS" | "HKU" => "HKU",
        "HKEY_CLASSES_ROOT" | "HKCR" => "HKCR",
        "HKEY_CURRENT_CONFIG" | "HKCC" => "HKCC",
        _ => raw_hive,
    };
    (hive.to_string(), key.to_string())
}

fn classify_artifact(path: &Path, artifact: &BundleArtifact) -> ArtifactKind {
    let declared = format!("{} {}", artifact.artifact_id, artifact.family).to_ascii_lowercase();
    let category = artifact.category.to_ascii_lowercase();
    let hints = artifact.parse_hints.join(" ").to_ascii_lowercase();
    if declared.contains("registry")
        || declared.contains("policy-hive")
        || declared.contains("policymanager")
        || declared.contains("nodecache")
        || declared.contains("enrollment") && has_extension(path, "reg")
    {
        return ArtifactKind::Registry;
    }
    if declared.contains("curated-channel") || declared.contains("event-log") {
        return ArtifactKind::EventLog;
    }
    if hints.contains("json")
        || declared.contains("json")
        || declared.contains("autopilot-profile")
        || declared.contains("delivery-optimization")
        || declared.contains("esp-hardware")
        || declared.contains("esp-os-facts")
        || declared.contains("esp-tpm-facts")
    {
        return ArtifactKind::Json;
    }
    if declared.contains("intune-ime")
        || declared.contains("deployment-log")
        || declared.contains("panther")
        || declared.contains("diagnostic-command")
        || declared.contains("mdm-diagnostics")
    {
        return ArtifactKind::Log;
    }
    if category.contains("registry") || has_extension(path, "reg") {
        ArtifactKind::Registry
    } else if category.contains("event") || has_extension(path, "evtx") {
        ArtifactKind::EventLog
    } else if has_extension(path, "json") {
        ArtifactKind::Json
    } else {
        ArtifactKind::Log
    }
}

fn artifact_document_type(artifact: &BundleArtifact) -> String {
    let semantic = semantic_identity(artifact);
    if semantic.contains("provisioning-progress") || semantic.contains("provisioningprogress") {
        "ProvisioningProgress".to_string()
    } else if semantic.contains("device-preparation-page-settings")
        || semantic.contains("devicepreparationpagesettings")
    {
        "DevicePreparationPageSettings".to_string()
    } else if semantic.contains("page-settings") || semantic.contains("pagesettings") {
        "PageSettings".to_string()
    } else if semantic.contains("enforcement-state-message")
        || semantic.contains("enforcementstatemessage")
    {
        "EnforcementStateMessage".to_string()
    } else {
        "AutopilotProfile".to_string()
    }
}

fn known_document_type(value: &str) -> Option<&'static str> {
    let normalized = normalize_semantic(value);
    if normalized == "provisioningprogress" {
        Some("ProvisioningProgress")
    } else if normalized == "devicepreparationpagesettings" {
        Some("DevicePreparationPageSettings")
    } else if normalized == "pagesettings" {
        Some("PageSettings")
    } else if normalized == "enforcementstatemessage" {
        Some("EnforcementStateMessage")
    } else {
        None
    }
}

fn is_known_document_type(value: &str) -> bool {
    known_document_type(value).is_some()
}

fn semantic_identity(artifact: &BundleArtifact) -> String {
    format!(
        "{} {} {} {}",
        artifact.artifact_id, artifact.family, artifact.category, artifact.relative_path
    )
    .to_ascii_lowercase()
}

fn normalize_semantic(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn manifest_status(status: &str) -> Option<EspArtifactStatus> {
    match status.trim().to_ascii_lowercase().as_str() {
        "collected" | "available" | "success" | "succeeded" => Some(EspArtifactStatus::Available),
        "missing" | "notfound" | "not-found" => Some(EspArtifactStatus::Missing),
        "permissiondenied" | "permission-denied" | "accessdenied" => {
            Some(EspArtifactStatus::PermissionDenied)
        }
        "failed" | "error" | "parsefailed" | "parse-failed" => Some(EspArtifactStatus::ParseFailed),
        "skipped" | "unsupported" => Some(EspArtifactStatus::Unsupported),
        _ => None,
    }
}

fn supported_manifest_artifact(path: &Path, artifact: &BundleArtifact) -> bool {
    let extension_allowed = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .is_some_and(|extension| SUPPORTED_MANIFEST_EXTENSIONS.contains(&extension.as_str()));
    if extension_allowed {
        return true;
    }
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    artifact.family.eq_ignore_ascii_case("intune-ime") && is_log_rotation_name(&name)
}

fn legacy_allowed_path(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match extension.as_str() {
        "log" | "reg" | "evtx" => true,
        "json" => {
            LEGACY_JSON_BASENAMES.contains(&name.as_str())
                || name.starts_with("autopilot")
                || portable_path(path).contains("/autopilot/")
        }
        "txt" => name == "dsregcmd-status.txt",
        "xml" => name.contains("mdmdiag") || name.contains("event"),
        _ => is_log_rotation_name(&name),
    }
}

fn is_log_rotation_name(name: &str) -> bool {
    let Some((_, suffix)) = name.rsplit_once(".log.") else {
        return false;
    };
    !suffix.is_empty()
        && suffix.len() <= 8
        && suffix.chars().all(|character| character.is_ascii_digit())
}

fn infer_family(path: &Path) -> String {
    let portable = portable_path(path).to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    if has_extension(path, "reg") {
        "registry".to_string()
    } else if has_extension(path, "evtx") {
        "curated-channel-export".to_string()
    } else if name == "delivery-optimization-perf-snap.json"
        || name == "delivery-optimization-status.json"
    {
        "delivery-optimization-command".to_string()
    } else if matches!(
        name.as_str(),
        "esp-os-facts.json" | "esp-hardware-facts.json" | "esp-tpm-facts.json"
    ) {
        "esp-hardware".to_string()
    } else if has_extension(path, "json") {
        "autopilot-profile-json".to_string()
    } else if portable.contains("intunemanagementextension")
        || name.contains("agentexecutor")
        || name.contains("intunemanagementextension")
    {
        "intune-ime".to_string()
    } else if name == "dsregcmd-status.txt" {
        "diagnostic-command".to_string()
    } else {
        "deployment-log".to_string()
    }
}

fn source_artifact_id(artifact: &BundleArtifact) -> String {
    let relative = artifact.relative_path.replace('\\', "/");
    let digest = Sha256::digest(relative.as_bytes());
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "bundle:{}:{suffix}",
        safe_identity_component(&artifact.artifact_id),
    )
}

fn safe_identity_component(value: &str) -> String {
    let value = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .take(128)
        .collect::<String>();
    if value.is_empty() {
        "artifact".to_string()
    } else {
        value
    }
}

fn safe_relative_path(raw: &str) -> Option<PathBuf> {
    let normalized = raw.trim().replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.starts_with("//")
        || normalized
            .as_bytes()
            .get(1)
            .is_some_and(|value| *value == b':')
    {
        return None;
    }
    let path = PathBuf::from(normalized);
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(path)
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|error| error.to_string())?;
    read_bounded_reader(file, path, maximum)
}

fn read_bounded_reader(file: File, path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let size = file.metadata().map_err(|error| error.to_string())?.len();
    if size > maximum {
        return Err(format!(
            "{} is {} bytes; maximum is {maximum}",
            path.display(),
            size
        ));
    }
    let allocation = usize::try_from(size.min(maximum)).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(allocation);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > maximum {
        return Err(format!(
            "{} grew beyond the {maximum}-byte bound while being read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn portable_relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(portable_path)
        .unwrap_or_else(|_| portable_path(path))
}

fn portable_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn contains_hardware_hash(value: &str) -> bool {
    let normalized = normalize_semantic(value);
    normalized.contains("hardwarehash") || normalized.contains("devicehardwaredata")
}

fn registry_sensitivity(key: &str, value_name: &str) -> EspSensitivity {
    let normalized = format!(
        "{}{}",
        normalize_semantic(key),
        normalize_semantic(value_name)
    );
    if normalized.contains("nodecache") {
        EspSensitivity::Restricted
    } else if [
        "userprincipalname",
        "usersid",
        "tenantid",
        "tenantdomain",
        "entdmid",
        "serialnumber",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
    {
        EspSensitivity::Sensitive
    } else {
        EspSensitivity::Public
    }
}

fn json_sensitivity(pointer: &str) -> EspSensitivity {
    let normalized = normalize_semantic(pointer);
    if normalized.contains("nodecache") {
        EspSensitivity::Restricted
    } else if [
        "userprincipalname",
        "usersid",
        "tenantid",
        "tenantdomain",
        "entdmid",
        "serialnumber",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
    {
        EspSensitivity::Sensitive
    } else {
        EspSensitivity::Public
    }
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

fn deduplicate_coverage(coverage: &mut Vec<EspArtifactCoverage>) {
    let mut by_identity = BTreeMap::new();
    for item in coverage.drain(..) {
        match by_identity.entry(item.artifact_id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(item);
            }
            std::collections::btree_map::Entry::Occupied(mut entry)
                if coverage_status_priority(&item.status)
                    > coverage_status_priority(&entry.get().status) =>
            {
                entry.insert(item);
            }
            std::collections::btree_map::Entry::Occupied(_) => {}
        }
    }
    coverage.extend(by_identity.into_values());
}

fn coverage_status_priority(status: &EspArtifactStatus) -> u8 {
    match status {
        EspArtifactStatus::Available => 5,
        EspArtifactStatus::PermissionDenied => 4,
        EspArtifactStatus::ParseFailed => 3,
        EspArtifactStatus::Unsupported => 2,
        EspArtifactStatus::Missing => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_path_identity_collapses_slash_case_and_curdir_aliases() {
        let expected = normalize_manifest_path_identity("evidence/logs/agentexecutor.log");

        assert_eq!(
            normalize_manifest_path_identity("EVIDENCE\\LOGS\\AgentExecutor.log"),
            expected
        );
        assert_eq!(
            normalize_manifest_path_identity("./evidence/logs/AgentExecutor.log"),
            expected
        );
    }

    #[test]
    fn coverage_reconciliation_prefers_available_over_missing() {
        let mut coverage = vec![
            artifact_coverage(
                "event-log:channel",
                "event-log",
                EspArtifactStatus::Missing,
                Some("first EVTX did not contain the channel".to_string()),
                "2026-07-16T08:00:00.000Z",
            ),
            artifact_coverage(
                "event-log:channel",
                "event-log",
                EspArtifactStatus::Available,
                None,
                "2026-07-16T08:00:00.000Z",
            ),
        ];

        deduplicate_coverage(&mut coverage);

        assert_eq!(coverage.len(), 1);
        assert_eq!(coverage[0].status, EspArtifactStatus::Available);
    }

    #[test]
    fn staging_rejects_cumulative_bytes_before_copying_the_next_artifact() {
        let root = tempfile::tempdir().expect("bundle root");
        fs::write(root.path().join("first.log"), b"1234").expect("write first artifact");
        fs::write(root.path().join("second.log"), b"5678").expect("write second artifact");
        let root = root.path().canonicalize().expect("canonical bundle root");
        let mut staging = BundleStagingArea::new_with_input_limit(6).expect("staging area");

        staging
            .stage(&root, Path::new("first.log"))
            .expect("stage first artifact");
        let failure = staging
            .stage(&root, Path::new("second.log"))
            .expect_err("second artifact must exceed the cumulative budget");

        assert!(failure.cumulative_limit);
        assert_eq!(staging.staged_bytes, 4);
        assert_eq!(staging.staged_files, 1);
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_a_parent_replaced_with_an_outside_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("bundle root");
        let approved_parent = root.path().join("evidence");
        fs::create_dir(&approved_parent).expect("create approved parent");
        fs::write(approved_parent.join("selected.log"), b"approved")
            .expect("write approved artifact");
        let canonical_root = root.path().canonicalize().expect("canonical bundle root");
        let outside = tempfile::tempdir().expect("outside root");
        fs::write(outside.path().join("selected.log"), b"outside-secret")
            .expect("write outside artifact");
        fs::rename(&approved_parent, root.path().join("evidence-original"))
            .expect("move approved parent");
        symlink(outside.path(), &approved_parent).expect("replace parent with symlink");
        let mut staging = BundleStagingArea::new().expect("staging area");

        let failure = staging
            .stage(&canonical_root, Path::new("evidence/selected.log"))
            .expect_err("replaced parent must not expose outside bytes");

        assert_eq!(failure.status, EspArtifactStatus::Unsupported);
        assert_eq!(staging.staged_bytes, 0);
        assert_eq!(staging.staged_files, 0);
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use cmtraceopen_parser::sccm::server::windows::{
    declared_server_source_catalog, SccmServerSourceKind, SccmServerSourceSpec,
};
use cmtraceopen_parser::sccm::{classify_artifact_name, SccmRotation};
use sha2::{Digest, Sha256};

use crate::sccm::contract::{logical_artifact_ids_for_basename, sha256_bytes};
use crate::sccm::contract::{
    SccmCaptureLimitKind, SccmManifestCoverageScope, SccmManifestSourceState,
};
use crate::sccm::private_fs::is_reparse_point;
use crate::sccm::{SccmCoverageState, SccmRole};

use super::client_manifest::{
    client_relative_path, write_and_validate_client_manifest, CapturedClientArtifact,
    ClientCoverageRecord,
};
use super::discovery::normalized_private_environment;
use super::server_manifest::{
    server_relative_path, write_and_validate_server_manifest, CapturedServerArtifact,
    ServerCoverageRecord,
};
use super::{
    role_key, sort_sources, SccmCaptureResult, SccmCollectorError, SccmDiscoveryProvider,
    SccmRotationCategory, SccmSourceDetailCode, SccmSourceStatus,
};

pub const MAX_FRAGMENTS_PER_SOURCE: usize = 8;
pub const MAX_BYTES_PER_SOURCE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
struct Candidate {
    role: SccmRole,
    source_id: String,
    workflow_subject_role: Option<SccmRole>,
    source_kind: Option<&'static str>,
    root_handle: String,
    canonical_basename: String,
    physical_basename: String,
    rotation: SccmRotation,
    source_path: PathBuf,
    approved_root: PathBuf,
    relative_path: String,
}

pub fn capture_environment(
    provider: &dyn SccmDiscoveryProvider,
    bundle_root: &Path,
) -> Result<SccmCaptureResult, SccmCollectorError> {
    let environment = normalized_private_environment(provider)
        .map_err(|_| SccmCollectorError::DiscoveryFailed)?;
    prepare_private_bundle_root(bundle_root)?;
    let captured_at_utc = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut statuses = Vec::new();
    let mut candidates = Vec::new();
    let mut client_coverage = Vec::new();
    let mut server_coverage = Vec::new();

    for root in &environment.roots {
        enumerate_root(
            root,
            &mut candidates,
            &mut statuses,
            &mut client_coverage,
            &mut server_coverage,
        )?;
    }
    candidates.sort_by(|left, right| {
        (
            role_key(&left.role),
            left.source_id.as_str(),
            left.root_handle.as_str(),
            rotation_key(&left.rotation),
            left.physical_basename.to_ascii_lowercase(),
        )
            .cmp(&(
                role_key(&right.role),
                right.source_id.as_str(),
                right.root_handle.as_str(),
                rotation_key(&right.rotation),
                right.physical_basename.to_ascii_lowercase(),
            ))
    });
    preflight_destinations(bundle_root, &candidates)?;

    let mut source_totals = BTreeMap::<(String, String, String), (usize, u64)>::new();
    let mut client_artifacts = Vec::new();
    let mut server_artifacts = Vec::new();
    let mut retained_bytes = 0_u64;

    for candidate in candidates {
        let source_key = (
            role_key(&candidate.role),
            candidate.root_handle.clone(),
            candidate.source_id.clone(),
        );
        let totals = source_totals.entry(source_key).or_default();
        if totals.0 >= MAX_FRAGMENTS_PER_SOURCE {
            statuses.push(status_for(
                &candidate,
                SccmCoverageState::Capped,
                0,
                Some(SccmSourceDetailCode::FileLimitExceeded),
            ));
            record_candidate_gap(
                &candidate,
                SccmManifestSourceState::Capped,
                Some(SccmCaptureLimitKind::FileCount),
                fs::metadata(&candidate.source_path)
                    .map(|value| value.len())
                    .unwrap_or(0),
                &mut client_coverage,
                &mut server_coverage,
            );
            continue;
        }
        let remaining = MAX_BYTES_PER_SOURCE.saturating_sub(totals.1);
        if remaining == 0 {
            statuses.push(status_for(
                &candidate,
                SccmCoverageState::Capped,
                0,
                Some(SccmSourceDetailCode::ByteLimitExceeded),
            ));
            record_candidate_gap(
                &candidate,
                SccmManifestSourceState::Capped,
                Some(SccmCaptureLimitKind::Bytes),
                fs::metadata(&candidate.source_path)
                    .map(|value| value.len())
                    .unwrap_or(0),
                &mut client_coverage,
                &mut server_coverage,
            );
            continue;
        }
        let outcome = match copy_candidate(bundle_root, &candidate, remaining) {
            Ok(outcome) => outcome,
            Err(CopyFailure::AccessDenied) => {
                statuses.push(status_for(
                    &candidate,
                    SccmCoverageState::AccessDenied,
                    0,
                    Some(SccmSourceDetailCode::AccessDenied),
                ));
                record_candidate_gap(
                    &candidate,
                    SccmManifestSourceState::AccessDenied,
                    None,
                    0,
                    &mut client_coverage,
                    &mut server_coverage,
                );
                continue;
            }
            Err(CopyFailure::Unsafe) => {
                statuses.push(status_for(
                    &candidate,
                    SccmCoverageState::Skipped,
                    0,
                    Some(SccmSourceDetailCode::UnsafePath),
                ));
                record_candidate_gap(
                    &candidate,
                    SccmManifestSourceState::Skipped,
                    None,
                    0,
                    &mut client_coverage,
                    &mut server_coverage,
                );
                continue;
            }
            Err(CopyFailure::Failed) => {
                statuses.push(status_for(
                    &candidate,
                    SccmCoverageState::ParseFailed,
                    0,
                    Some(SccmSourceDetailCode::ReadFailed),
                ));
                record_candidate_gap(
                    &candidate,
                    SccmManifestSourceState::FailedUnknownDetail,
                    None,
                    0,
                    &mut client_coverage,
                    &mut server_coverage,
                );
                continue;
            }
        };
        totals.0 += 1;
        totals.1 = totals.1.saturating_add(outcome.bytes.len() as u64);
        retained_bytes = retained_bytes.saturating_add(outcome.bytes.len() as u64);
        let state = if outcome.capped {
            SccmCoverageState::Capped
        } else {
            SccmCoverageState::Captured
        };
        statuses.push(status_for(
            &candidate,
            state.clone(),
            outcome.bytes.len() as u64,
            outcome
                .capped
                .then_some(SccmSourceDetailCode::ByteLimitExceeded),
        ));
        if candidate.role == SccmRole::Client {
            client_artifacts.push(CapturedClientArtifact {
                root_handle: candidate.root_handle,
                basename: candidate.canonical_basename,
                rotation: candidate.rotation,
                state: if outcome.capped {
                    crate::sccm::SccmManifestSourceState::Capped
                } else {
                    crate::sccm::SccmManifestSourceState::Captured
                },
                relative_path: candidate.relative_path,
                retained_bytes: outcome.bytes.len() as u64,
                content_sha256: outcome.sha256,
                capped: outcome.capped,
            });
        } else {
            server_artifacts.push(CapturedServerArtifact {
                role: candidate.role,
                workflow_subject_role: candidate.workflow_subject_role,
                source_id: candidate.source_id,
                source_kind: candidate
                    .source_kind
                    .ok_or(SccmCollectorError::CaptureFailed)?,
                root_handle: candidate.root_handle,
                basename: candidate.physical_basename,
                rotation: candidate.rotation,
                relative_path: candidate.relative_path,
                retained_bytes: outcome.bytes.len() as u64,
                bytes: outcome.bytes,
                capped: outcome.capped,
            });
        }
    }

    if environment
        .roles
        .iter()
        .any(|fact| fact.role == SccmRole::Client)
    {
        write_and_validate_client_manifest(
            bundle_root,
            &captured_at_utc,
            environment.configmgr_version.as_deref(),
            client_artifacts,
            client_coverage,
        )?;
    }

    let mut server_roles = environment
        .roles
        .iter()
        .map(|fact| fact.role.clone())
        .filter(|role| *role != SccmRole::Client)
        .collect::<Vec<_>>();
    server_roles.sort_by_key(role_key);
    server_roles.dedup();
    write_and_validate_server_manifest(
        bundle_root,
        &captured_at_utc,
        &server_roles,
        environment.private_host.as_deref(),
        environment.private_site_code.as_deref(),
        server_artifacts,
        server_coverage,
    )?;

    sort_sources(&mut statuses);
    let mut roles = environment
        .roles
        .into_iter()
        .map(|fact| fact.role)
        .collect::<Vec<_>>();
    roles.sort_by_key(role_key);
    roles.dedup();
    let artifact_count = statuses
        .iter()
        .filter(|status| status.retained_bytes > 0 || status.state == SccmCoverageState::Captured)
        .count();
    Ok(SccmCaptureResult {
        bundle_root: bundle_root.to_string_lossy().into_owned(),
        captured_at_utc,
        roles,
        sources: statuses,
        artifact_count,
        retained_bytes,
    })
}

fn prepare_private_bundle_root(bundle_root: &Path) -> Result<(), SccmCollectorError> {
    fs::create_dir(bundle_root).map_err(|_| SccmCollectorError::DestinationUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(bundle_root, fs::Permissions::from_mode(0o700))
            .map_err(|_| SccmCollectorError::DestinationUnavailable)?;
    }
    Ok(())
}

fn enumerate_root(
    root: &super::SccmCaptureRoot,
    candidates: &mut Vec<Candidate>,
    statuses: &mut Vec<SccmSourceStatus>,
    client_coverage: &mut Vec<ClientCoverageRecord>,
    server_coverage: &mut Vec<ServerCoverageRecord>,
) -> Result<(), SccmCollectorError> {
    let root_handle = root_handle_for(&root.path);
    let canonical_root = match root.path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            record_expected_root_coverage(
                root,
                &root_handle,
                SccmManifestSourceState::Absent,
                SccmManifestCoverageScope::Source,
                statuses,
                client_coverage,
                server_coverage,
            );
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            record_expected_root_coverage(
                root,
                &root_handle,
                SccmManifestSourceState::AccessDenied,
                SccmManifestCoverageScope::RootEnumeration,
                statuses,
                client_coverage,
                server_coverage,
            );
            return Ok(());
        }
        Err(_) => {
            record_expected_root_coverage(
                root,
                &root_handle,
                SccmManifestSourceState::FailedUnknownDetail,
                SccmManifestCoverageScope::RootEnumeration,
                statuses,
                client_coverage,
                server_coverage,
            );
            return Ok(());
        }
    };
    let root_metadata =
        fs::symlink_metadata(&root.path).map_err(|_| SccmCollectorError::CaptureFailed)?;
    if root_metadata.file_type().is_symlink() || is_reparse_point(&root_metadata) {
        record_expected_root_coverage(
            root,
            &root_handle,
            SccmManifestSourceState::UnsafePath,
            SccmManifestCoverageScope::Source,
            statuses,
            client_coverage,
            server_coverage,
        );
        return Ok(());
    }
    let entries = match fs::read_dir(&canonical_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            record_expected_root_coverage(
                root,
                &root_handle,
                SccmManifestSourceState::AccessDenied,
                SccmManifestCoverageScope::RootEnumeration,
                statuses,
                client_coverage,
                server_coverage,
            );
            return Ok(());
        }
        Err(_) => {
            record_expected_root_coverage(
                root,
                &root_handle,
                SccmManifestSourceState::FailedUnknownDetail,
                SccmManifestCoverageScope::RootEnumeration,
                statuses,
                client_coverage,
                server_coverage,
            );
            return Ok(());
        }
    };
    let mut observed = BTreeSet::new();
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let metadata = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            if let Some(expected) = expected_source_for_name(&root.role, &name) {
                observed.insert(expected.identity());
                statuses.push(SccmSourceStatus {
                    role: root.role.clone(),
                    source_id: expected.source_id.clone(),
                    rotation: SccmRotationCategory::Unknown,
                    state: SccmCoverageState::Skipped,
                    retained_bytes: 0,
                    detail_code: Some(SccmSourceDetailCode::UnsafePath),
                });
                record_expected_coverage(
                    root,
                    &root_handle,
                    expected,
                    SccmManifestSourceState::Skipped,
                    SccmManifestCoverageScope::Source,
                    client_coverage,
                    server_coverage,
                );
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        if let Some(candidate) = classify_candidate(root, &root_handle, entry.path(), &name)? {
            observed.insert(expected_identity_for_candidate(&candidate));
            candidates.push(candidate);
        } else if let Some(expected) = expected_source_for_name(&root.role, &name) {
            observed.insert(expected.identity());
            statuses.push(SccmSourceStatus {
                role: root.role.clone(),
                source_id: expected.source_id.clone(),
                rotation: SccmRotationCategory::Unknown,
                state: SccmCoverageState::Unsupported,
                retained_bytes: 0,
                detail_code: Some(SccmSourceDetailCode::MalformedRotation),
            });
            record_expected_coverage(
                root,
                &root_handle,
                expected,
                SccmManifestSourceState::Unsupported,
                SccmManifestCoverageScope::Source,
                client_coverage,
                server_coverage,
            );
        }
    }
    for expected in expected_sources(&root.role) {
        if observed.insert(expected.identity()) {
            statuses.push(SccmSourceStatus {
                role: root.role.clone(),
                source_id: expected.source_id.clone(),
                rotation: SccmRotationCategory::Current,
                state: SccmCoverageState::Absent,
                retained_bytes: 0,
                detail_code: None,
            });
            record_expected_coverage(
                root,
                &root_handle,
                expected,
                SccmManifestSourceState::Absent,
                SccmManifestCoverageScope::Source,
                client_coverage,
                server_coverage,
            );
        }
    }
    Ok(())
}

fn classify_candidate(
    root: &super::SccmCaptureRoot,
    root_handle: &str,
    source_path: PathBuf,
    name: &str,
) -> Result<Option<Candidate>, SccmCollectorError> {
    let classified = classify_artifact_name(name, root.role.clone());
    if root.role == SccmRole::Client {
        if !classified.supported_for_diagnosis {
            return Ok(None);
        }
        let memberships = logical_artifact_ids_for_basename(&classified.basename);
        if memberships.is_empty() {
            return Ok(None);
        }
        let source_id = memberships[0].clone();
        let relative_path =
            client_relative_path(root_handle, &classified.basename, &classified.rotation);
        return Ok(Some(Candidate {
            role: SccmRole::Client,
            source_id,
            workflow_subject_role: None,
            source_kind: None,
            root_handle: root_handle.to_owned(),
            canonical_basename: classified.basename,
            physical_basename: name.to_owned(),
            rotation: classified.rotation,
            source_path,
            approved_root: root
                .path
                .canonicalize()
                .map_err(|_| SccmCollectorError::CaptureFailed)?,
            relative_path,
        }));
    }

    let Some(spec) = matching_server_spec(root.role.clone(), name) else {
        return Ok(None);
    };
    let rotation = if spec.source_kind == SccmServerSourceKind::ProfileDefined {
        SccmRotation::Current
    } else {
        classified.rotation
    };
    let source_kind = source_kind_name(spec.source_kind);
    let relative_path = server_relative_path(
        &root.role,
        spec.workflow_subject_role.as_ref(),
        spec.source_id,
        root_handle,
        name,
        &rotation,
    )?;
    Ok(Some(Candidate {
        role: root.role.clone(),
        source_id: spec.source_id.to_owned(),
        workflow_subject_role: spec.workflow_subject_role.clone(),
        source_kind: Some(source_kind),
        root_handle: root_handle.to_owned(),
        canonical_basename: if spec.source_kind == SccmServerSourceKind::ProfileDefined {
            name.to_owned()
        } else {
            classified.basename
        },
        physical_basename: name.to_owned(),
        rotation,
        source_path,
        approved_root: root
            .path
            .canonicalize()
            .map_err(|_| SccmCollectorError::CaptureFailed)?,
        relative_path,
    }))
}

fn matching_server_spec(role: SccmRole, name: &str) -> Option<&'static SccmServerSourceSpec> {
    let classified = classify_artifact_name(name, role.clone());
    declared_server_source_catalog().iter().find(|spec| {
        spec.producer_role == role
            && match spec.source_kind {
                SccmServerSourceKind::CcmLog => {
                    classified.supported_for_diagnosis
                        && spec
                            .logical_names
                            .iter()
                            .any(|logical| logical.eq_ignore_ascii_case(&classified.logical_name))
                }
                SccmServerSourceKind::ProfileDefined => spec
                    .explicit_basename
                    .is_some_and(|basename| basename.eq_ignore_ascii_case(name)),
                SccmServerSourceKind::IisW3c | SccmServerSourceKind::StructuredSupplement => false,
            }
    })
}

#[derive(Clone)]
struct ExpectedSource {
    source_id: String,
    basename: String,
    workflow_subject_role: Option<SccmRole>,
    source_kind: Option<&'static str>,
}

impl ExpectedSource {
    fn identity(&self) -> String {
        format!("{}\0{}", self.source_id, self.basename.to_ascii_lowercase())
    }
}

fn expected_sources(role: &SccmRole) -> Vec<ExpectedSource> {
    let mut expected = if *role == SccmRole::Client {
        let mut basenames = cmtraceopen_parser::sccm::declared_client_source_groups()
            .into_iter()
            .flat_map(|group| group.accepted_basenames)
            .collect::<Vec<_>>();
        basenames.sort_by_key(|value| value.to_ascii_lowercase());
        basenames.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        basenames
            .into_iter()
            .map(|basename| ExpectedSource {
                source_id: logical_artifact_ids_for_basename(&basename)
                    .into_iter()
                    .next()
                    .unwrap_or_else(|| "client-source".to_owned()),
                basename,
                workflow_subject_role: None,
                source_kind: None,
            })
            .collect::<Vec<_>>()
    } else {
        declared_server_source_catalog()
            .iter()
            .filter(|spec| spec.producer_role == *role)
            .flat_map(|spec| {
                let basenames = match spec.source_kind {
                    SccmServerSourceKind::CcmLog => spec
                        .logical_names
                        .iter()
                        .filter_map(|logical| {
                            cmtraceopen_parser::sccm::declared_source_catalog()
                                .into_iter()
                                .find(|entry| {
                                    entry.role == *role
                                        && entry.logical_name.eq_ignore_ascii_case(logical)
                                })
                                .map(|entry| entry.basename)
                        })
                        .collect::<Vec<_>>(),
                    SccmServerSourceKind::ProfileDefined => spec
                        .explicit_basename
                        .into_iter()
                        .map(str::to_owned)
                        .collect(),
                    // These supplemental contracts have no catalog basename;
                    // a separate configured root/profile must name them before
                    // collection can make a source claim.
                    SccmServerSourceKind::IisW3c | SccmServerSourceKind::StructuredSupplement => {
                        Vec::new()
                    }
                };
                basenames.into_iter().map(move |basename| ExpectedSource {
                    source_id: spec.source_id.to_owned(),
                    basename,
                    workflow_subject_role: spec.workflow_subject_role.clone(),
                    source_kind: Some(source_kind_name(spec.source_kind)),
                })
            })
            .collect::<Vec<_>>()
    };
    expected.sort_by_key(ExpectedSource::identity);
    expected.dedup_by(|left, right| left.identity() == right.identity());
    expected
}

fn expected_source_for_name(role: &SccmRole, name: &str) -> Option<ExpectedSource> {
    let classified = classify_artifact_name(name, role.clone());
    expected_sources(role).into_iter().find(|expected| {
        expected.basename.eq_ignore_ascii_case(&classified.basename)
            || name
                .to_ascii_lowercase()
                .starts_with(&expected.basename.to_ascii_lowercase())
    })
}

fn expected_identity_for_candidate(candidate: &Candidate) -> String {
    format!(
        "{}\0{}",
        candidate.source_id,
        candidate.canonical_basename.to_ascii_lowercase()
    )
}

fn source_kind_name(kind: SccmServerSourceKind) -> &'static str {
    match kind {
        SccmServerSourceKind::CcmLog => "ccmLog",
        SccmServerSourceKind::IisW3c => "iisW3c",
        SccmServerSourceKind::StructuredSupplement => "structuredSupplement",
        SccmServerSourceKind::ProfileDefined => "profileDefined",
    }
}

fn record_expected_root_coverage(
    root: &super::SccmCaptureRoot,
    root_handle: &str,
    state: SccmManifestSourceState,
    scope: SccmManifestCoverageScope,
    statuses: &mut Vec<SccmSourceStatus>,
    client_coverage: &mut Vec<ClientCoverageRecord>,
    server_coverage: &mut Vec<ServerCoverageRecord>,
) {
    for expected in expected_sources(&root.role) {
        statuses.push(SccmSourceStatus {
            role: root.role.clone(),
            source_id: expected.source_id.clone(),
            rotation: SccmRotationCategory::Current,
            state: public_coverage(state),
            retained_bytes: 0,
            detail_code: detail_for_manifest_state(state),
        });
        record_expected_coverage(
            root,
            root_handle,
            expected,
            state,
            scope,
            client_coverage,
            server_coverage,
        );
    }
}

fn record_expected_coverage(
    root: &super::SccmCaptureRoot,
    root_handle: &str,
    expected: ExpectedSource,
    state: SccmManifestSourceState,
    scope: SccmManifestCoverageScope,
    client_coverage: &mut Vec<ClientCoverageRecord>,
    server_coverage: &mut Vec<ServerCoverageRecord>,
) {
    if root.role == SccmRole::Client {
        client_coverage.push(ClientCoverageRecord {
            root_handle: root_handle.to_owned(),
            basename: expected.basename,
            rotation: SccmRotation::Current,
            state,
            coverage_scope: scope,
            gap_limit: None,
            source_bytes: 0,
        });
    } else {
        server_coverage.push(ServerCoverageRecord {
            role: root.role.clone(),
            workflow_subject_role: expected.workflow_subject_role,
            source_id: expected.source_id,
            source_kind: expected.source_kind.unwrap_or("ccmLog"),
            root_handle: root_handle.to_owned(),
            basename: expected.basename,
            rotation: SccmRotation::Current,
            state: server_nonphysical_state(state),
        });
    }
}

fn record_candidate_gap(
    candidate: &Candidate,
    state: SccmManifestSourceState,
    gap_limit: Option<SccmCaptureLimitKind>,
    source_bytes: u64,
    client_coverage: &mut Vec<ClientCoverageRecord>,
    server_coverage: &mut Vec<ServerCoverageRecord>,
) {
    if candidate.role == SccmRole::Client {
        client_coverage.push(ClientCoverageRecord {
            root_handle: candidate.root_handle.clone(),
            basename: candidate.canonical_basename.clone(),
            rotation: candidate.rotation.clone(),
            state,
            coverage_scope: SccmManifestCoverageScope::Source,
            gap_limit,
            source_bytes,
        });
    } else {
        server_coverage.push(ServerCoverageRecord {
            role: candidate.role.clone(),
            workflow_subject_role: candidate.workflow_subject_role.clone(),
            source_id: candidate.source_id.clone(),
            source_kind: candidate.source_kind.unwrap_or("ccmLog"),
            root_handle: candidate.root_handle.clone(),
            basename: candidate.physical_basename.clone(),
            rotation: candidate.rotation.clone(),
            state: server_nonphysical_state(state),
        });
    }
}

fn public_coverage(state: SccmManifestSourceState) -> SccmCoverageState {
    match state {
        SccmManifestSourceState::Captured => SccmCoverageState::Captured,
        SccmManifestSourceState::Absent => SccmCoverageState::Absent,
        SccmManifestSourceState::AccessDenied => SccmCoverageState::AccessDenied,
        SccmManifestSourceState::Capped => SccmCoverageState::Capped,
        SccmManifestSourceState::Skipped => SccmCoverageState::Skipped,
        SccmManifestSourceState::ParseFailed => SccmCoverageState::ParseFailed,
        SccmManifestSourceState::Unsupported
        | SccmManifestSourceState::UnsafePath
        | SccmManifestSourceState::FailedUnknownDetail => SccmCoverageState::Unsupported,
    }
}

fn server_nonphysical_state(state: SccmManifestSourceState) -> SccmCoverageState {
    match state {
        SccmManifestSourceState::Absent => SccmCoverageState::Absent,
        SccmManifestSourceState::AccessDenied | SccmManifestSourceState::FailedUnknownDetail => {
            SccmCoverageState::AccessDenied
        }
        SccmManifestSourceState::Skipped | SccmManifestSourceState::Capped => {
            SccmCoverageState::Skipped
        }
        SccmManifestSourceState::Unsupported | SccmManifestSourceState::UnsafePath => {
            SccmCoverageState::Unsupported
        }
        SccmManifestSourceState::Captured | SccmManifestSourceState::ParseFailed => {
            SccmCoverageState::Unsupported
        }
    }
}

fn detail_for_manifest_state(state: SccmManifestSourceState) -> Option<SccmSourceDetailCode> {
    match state {
        SccmManifestSourceState::AccessDenied => Some(SccmSourceDetailCode::AccessDenied),
        SccmManifestSourceState::UnsafePath => Some(SccmSourceDetailCode::UnsafePath),
        SccmManifestSourceState::FailedUnknownDetail | SccmManifestSourceState::ParseFailed => {
            Some(SccmSourceDetailCode::ReadFailed)
        }
        _ => None,
    }
}

fn root_handle_for(path: &Path) -> String {
    let identity = path.canonicalize().unwrap_or_else(|_| path.to_owned());
    format!(
        "root-{}",
        sha256_bytes(identity.to_string_lossy().as_bytes())
    )
}

fn preflight_destinations(
    bundle_root: &Path,
    candidates: &[Candidate],
) -> Result<(), SccmCollectorError> {
    let mut destinations = BTreeSet::new();
    for candidate in candidates {
        if !destinations.insert(candidate.relative_path.to_ascii_lowercase())
            || bundle_root.join(&candidate.relative_path).exists()
        {
            return Err(SccmCollectorError::DestinationUnavailable);
        }
    }
    Ok(())
}

struct CopyOutcome {
    bytes: Vec<u8>,
    sha256: String,
    capped: bool,
}

enum CopyFailure {
    AccessDenied,
    Unsafe,
    Failed,
}

fn copy_candidate(
    bundle_root: &Path,
    candidate: &Candidate,
    limit: u64,
) -> Result<CopyOutcome, CopyFailure> {
    let canonical_source = candidate
        .source_path
        .canonicalize()
        .map_err(map_copy_error)?;
    let canonical_parent = candidate
        .source_path
        .parent()
        .ok_or(CopyFailure::Unsafe)?
        .canonicalize()
        .map_err(map_copy_error)?;
    if canonical_source.parent() != Some(canonical_parent.as_path())
        || canonical_parent != candidate.approved_root
        || !canonical_source.starts_with(&candidate.approved_root)
    {
        return Err(CopyFailure::Unsafe);
    }
    let mut input = open_source_no_follow(&candidate.source_path).map_err(map_copy_error)?;
    let metadata = input.metadata().map_err(map_copy_error)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(CopyFailure::Unsafe);
    }
    let capped = metadata.len() > limit;
    let read_limit = metadata.len().min(limit);
    let capacity = usize::try_from(read_limit).map_err(|_| CopyFailure::Failed)?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut input)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(map_copy_error)?;
    if bytes.len() as u64 != read_limit {
        return Err(CopyFailure::Failed);
    }
    let destination = bundle_root.join(&candidate.relative_path);
    fs::create_dir_all(destination.parent().ok_or(CopyFailure::Unsafe)?).map_err(map_copy_error)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(map_copy_error)?;
    output.write_all(&bytes).map_err(map_copy_error)?;
    output.sync_all().map_err(map_copy_error)?;
    Ok(CopyOutcome {
        sha256: Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        bytes,
        capped,
    })
}

fn open_source_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
    }
    options.open(path)
}

fn map_copy_error(error: std::io::Error) -> CopyFailure {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        CopyFailure::AccessDenied
    } else {
        CopyFailure::Failed
    }
}

fn status_for(
    candidate: &Candidate,
    state: SccmCoverageState,
    retained_bytes: u64,
    detail_code: Option<SccmSourceDetailCode>,
) -> SccmSourceStatus {
    SccmSourceStatus {
        role: candidate.role.clone(),
        source_id: candidate.source_id.clone(),
        rotation: rotation_category(&candidate.rotation),
        state,
        retained_bytes,
        detail_code,
    }
}

fn rotation_category(rotation: &SccmRotation) -> SccmRotationCategory {
    match rotation {
        SccmRotation::Current => SccmRotationCategory::Current,
        SccmRotation::LoUnderscore => SccmRotationCategory::LoUnderscore,
        SccmRotation::Numbered(_) => SccmRotationCategory::Numbered,
        SccmRotation::Timestamped(_) => SccmRotationCategory::Timestamped,
        SccmRotation::Unknown(_) => SccmRotationCategory::Unknown,
    }
}

fn rotation_key(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => "0-current".to_owned(),
        SccmRotation::LoUnderscore => "1-lo".to_owned(),
        SccmRotation::Numbered(value) => format!("2-{value:010}"),
        SccmRotation::Timestamped(value) => format!("3-{value}"),
        SccmRotation::Unknown(_) => "4-unknown".to_owned(),
    }
}

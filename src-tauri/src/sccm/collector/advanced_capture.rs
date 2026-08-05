use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use cmtraceopen_parser::sccm::server::windows::{
    normalize_server_bundle, SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole, SccmRotation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::sccm::contract::sha256_bytes;

use super::{
    role_key, PrivateSccmEnvironment, SccmCaptureResult, SccmCollectorError,
    SccmEnvironmentDiscovery, SccmRotationCategory, SccmSourceDetailCode, SccmSourceStatus,
};

pub const ADVANCED_CAPTURE_BYTE_LIMIT: u64 = 4 * 1024 * 1024;
pub const ADVANCED_CAPTURE_FILE_LIMIT: usize = 2;
pub const ADVANCED_CAPABILITY_LIMIT: usize = 8;
pub const ADVANCED_CAPABILITY_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy)]
pub struct SccmAdvancedSourceContract {
    pub card_id: &'static str,
    pub card_version: &'static str,
    pub source_id: &'static str,
    pub basename: &'static str,
    pub role_scopes: &'static [&'static str],
    pub path_classes: &'static [&'static str],
    pub requires_pxe_fact: bool,
}

const ADVANCED_SOURCE_CONTRACTS: [SccmAdvancedSourceContract; 6] = [
    SccmAdvancedSourceContract {
        card_id: "osd-pxe",
        card_version: "1.0.0",
        source_id: "advanced-osd-pxe",
        basename: "smspxe.log",
        role_scopes: &["distributionPointPxe", "siteServer"],
        path_classes: &["configuredRoleLogRoot", "siteServerLogs"],
        requires_pxe_fact: true,
    },
    SccmAdvancedSourceContract {
        card_id: "certificate-enrollment-pki",
        card_version: "1.0.0",
        source_id: "advanced-certificate-enrollment-pki",
        basename: "crp.log",
        role_scopes: &["certificateRegistrationPoint"],
        path_classes: &["configuredRoleLogRoot", "siteServerLogs"],
        requires_pxe_fact: false,
    },
    SccmAdvancedSourceContract {
        card_id: "reporting",
        card_version: "1.0.0",
        source_id: "advanced-reporting",
        basename: "srsrp.log",
        role_scopes: &["reportingServicesPoint"],
        path_classes: &[
            "configuredRoleLogRoot",
            "reportServerLogs",
            "siteServerLogs",
        ],
        requires_pxe_fact: false,
    },
    SccmAdvancedSourceContract {
        card_id: "cloud-service-connection",
        card_version: "1.0.0",
        source_id: "advanced-cloud-manager",
        basename: "CloudMgr.log",
        role_scopes: &[
            "cloudManagementGatewayConnectionPoint",
            "serviceConnectionPoint",
        ],
        path_classes: &["configuredRoleLogRoot", "siteServerLogs"],
        requires_pxe_fact: false,
    },
    SccmAdvancedSourceContract {
        card_id: "cloud-service-connection",
        card_version: "1.0.0",
        source_id: "advanced-cloud-proxy-connector",
        basename: "SMS_Cloud_ProxyConnector.log",
        role_scopes: &[
            "cloudManagementGatewayConnectionPoint",
            "serviceConnectionPoint",
        ],
        path_classes: &["configuredRoleLogRoot", "siteServerLogs"],
        requires_pxe_fact: false,
    },
    SccmAdvancedSourceContract {
        card_id: "client-notification-bgb",
        card_version: "1.0.0",
        source_id: "advanced-client-notification-bgb",
        basename: "BgbServer.log",
        role_scopes: &["clientNotificationServer", "managementPoint"],
        path_classes: &["configuredRoleLogRoot", "siteServerLogs"],
        requires_pxe_fact: false,
    },
];

pub fn advanced_source_contracts() -> &'static [SccmAdvancedSourceContract] {
    &ADVANCED_SOURCE_CONTRACTS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateAdvancedSourceFact {
    pub source_id: String,
    pub role_scope: String,
    pub path_class: String,
    pub root: PathBuf,
    pub source_version: Option<String>,
    pub pxe_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmAdvancedSourceAvailability {
    Observed,
    OperatorDeclaredCandidate,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmAdvancedSourceOption {
    pub card_id: String,
    pub card_version: String,
    pub source_id: String,
    pub role_scopes: Vec<String>,
    pub path_classes: Vec<String>,
    pub source_version: Option<String>,
    pub availability: SccmAdvancedSourceAvailability,
    pub max_bytes: u64,
    pub max_files: usize,
    pub rotations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SccmAdvancedCaptureAuthorizationRequest {
    pub card_id: String,
    pub card_version: String,
    pub source_id: String,
    pub role_scope: String,
    pub path_class: String,
    pub expected_source_version: Option<String>,
    pub selected_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmAdvancedCaptureCapability {
    pub capability_handle: String,
    pub card_id: String,
    pub card_version: String,
    pub source_id: String,
    pub role_scope: String,
    pub path_class: String,
    pub source_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccmAdvancedProvenance {
    Observed,
    OperatorDeclared,
}

impl SccmAdvancedProvenance {
    fn wire(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::OperatorDeclared => "operatorDeclared",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrivateAdvancedCaptureAuthorization {
    contract: &'static SccmAdvancedSourceContract,
    canonical_root: PathBuf,
    role_scope: String,
    path_class: String,
    source_version: Option<String>,
    provenance: SccmAdvancedProvenance,
    capability_handle: String,
    authorization_handle: String,
    expires_at: Instant,
    environment: PrivateSccmEnvironment,
}

#[derive(Debug, Default)]
pub struct SccmAdvancedCapabilityStore {
    entries: HashMap<String, PrivateAdvancedCaptureAuthorization>,
}

impl SccmAdvancedCapabilityStore {
    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }

    pub fn authorize(
        &mut self,
        environment: &PrivateSccmEnvironment,
        request: SccmAdvancedCaptureAuthorizationRequest,
        now: Instant,
    ) -> Result<SccmAdvancedCaptureCapability, SccmCollectorError> {
        self.purge_expired(now);
        if self.entries.len() >= ADVANCED_CAPABILITY_LIMIT {
            return Err(SccmCollectorError::AdvancedAuthorizationRejected);
        }
        let contract = contract_for_request(&request)
            .ok_or(SccmCollectorError::AdvancedAuthorizationRejected)?;
        let canonical_root = validate_selected_root(&request.selected_root)?;
        if request.expected_source_version.is_some()
            && request.expected_source_version != environment.configmgr_version
        {
            return Err(SccmCollectorError::AdvancedAuthorizationRejected);
        }

        let observed_fact = observed_fact_for(environment, contract, &request, &canonical_root);
        let observed_management_point = contract.source_id == "advanced-client-notification-bgb"
            && request.role_scope == "managementPoint"
            && environment
                .roles
                .iter()
                .any(|role| role.role == SccmRole::ManagementPoint)
            && environment.roots.iter().any(|root| {
                root.role == SccmRole::ManagementPoint
                    && root.path.canonicalize().ok().as_deref() == Some(canonical_root.as_path())
            });
        let provenance = if observed_fact.is_some() || observed_management_point {
            SccmAdvancedProvenance::Observed
        } else {
            SccmAdvancedProvenance::OperatorDeclared
        };
        let source_version = observed_fact
            .and_then(|fact| fact.source_version.clone())
            .or_else(|| environment.configmgr_version.clone());
        let identity = format!(
            "{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            contract.card_id,
            contract.card_version,
            contract.source_id,
            request.role_scope,
            provenance.wire(),
            request.path_class,
            sha256_bytes(canonical_root.to_string_lossy().as_bytes()),
            source_version.as_deref().unwrap_or_default(),
        );
        if self.entries.values().any(|entry| {
            entry.contract.source_id == contract.source_id
                && entry.role_scope == request.role_scope
                && entry.path_class == request.path_class
                && entry.provenance == provenance
                && entry.canonical_root == canonical_root
                && entry.source_version == source_version
        }) {
            return Err(SccmCollectorError::AdvancedAuthorizationRejected);
        }

        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce)
            .map_err(|_| SccmCollectorError::AdvancedAuthorizationRejected)?;
        let capability_handle = format!(
            "cmtraceopen.capture-capability.sha256.v1:{}",
            sha256_bytes(
                [
                    b"capability\0".as_slice(),
                    nonce.as_slice(),
                    identity.as_bytes()
                ]
                .concat()
                .as_slice()
            )
        );
        let authorization_handle = format!(
            "cmtraceopen.capture-authorization.sha256.v1:{}",
            sha256_bytes(
                [
                    b"authorization\0".as_slice(),
                    nonce.as_slice(),
                    identity.as_bytes()
                ]
                .concat()
                .as_slice()
            )
        );
        let private = PrivateAdvancedCaptureAuthorization {
            contract,
            canonical_root,
            role_scope: request.role_scope.clone(),
            path_class: request.path_class.clone(),
            source_version: source_version.clone(),
            provenance,
            capability_handle: capability_handle.clone(),
            authorization_handle,
            expires_at: now + ADVANCED_CAPABILITY_TTL,
            environment: environment.clone(),
        };
        self.entries.insert(capability_handle.clone(), private);
        Ok(SccmAdvancedCaptureCapability {
            capability_handle,
            card_id: contract.card_id.to_owned(),
            card_version: contract.card_version.to_owned(),
            source_id: contract.source_id.to_owned(),
            role_scope: request.role_scope,
            path_class: request.path_class,
            source_version,
        })
    }

    pub fn consume(
        &mut self,
        capability_handle: &str,
        now: Instant,
    ) -> Result<PrivateAdvancedCaptureAuthorization, SccmCollectorError> {
        self.purge_expired(now);
        self.entries
            .remove(capability_handle)
            .ok_or(SccmCollectorError::AdvancedCapabilityUnavailable)
    }

    pub fn cancel(&mut self, capability_handle: &str, now: Instant) {
        self.purge_expired(now);
        self.entries.remove(capability_handle);
    }

    fn purge_expired(&mut self, now: Instant) {
        self.entries.retain(|_, entry| entry.expires_at > now);
    }
}

pub fn advanced_source_options(
    environment: &PrivateSccmEnvironment,
) -> Vec<SccmAdvancedSourceOption> {
    ADVANCED_SOURCE_CONTRACTS
        .iter()
        .map(|contract| {
            let availability = if !environment.supported {
                SccmAdvancedSourceAvailability::Blocked
            } else if contract_is_observed(environment, contract) {
                SccmAdvancedSourceAvailability::Observed
            } else {
                SccmAdvancedSourceAvailability::OperatorDeclaredCandidate
            };
            SccmAdvancedSourceOption {
                card_id: contract.card_id.to_owned(),
                card_version: contract.card_version.to_owned(),
                source_id: contract.source_id.to_owned(),
                role_scopes: contract
                    .role_scopes
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                path_classes: contract
                    .path_classes
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
                source_version: environment.configmgr_version.clone(),
                availability,
                max_bytes: ADVANCED_CAPTURE_BYTE_LIMIT,
                max_files: ADVANCED_CAPTURE_FILE_LIMIT,
                rotations: vec!["current".to_owned(), "lo_".to_owned()],
            }
        })
        .collect()
}

pub fn append_advanced_options(
    discovery: &mut SccmEnvironmentDiscovery,
    environment: &PrivateSccmEnvironment,
) {
    discovery.advanced_sources = advanced_source_options(environment);
}

fn contract_for_request(
    request: &SccmAdvancedCaptureAuthorizationRequest,
) -> Option<&'static SccmAdvancedSourceContract> {
    ADVANCED_SOURCE_CONTRACTS.iter().find(|contract| {
        contract.card_id == request.card_id
            && contract.card_version == request.card_version
            && contract.source_id == request.source_id
            && contract.role_scopes.contains(&request.role_scope.as_str())
            && contract.path_classes.contains(&request.path_class.as_str())
    })
}

fn contract_is_observed(
    environment: &PrivateSccmEnvironment,
    contract: &SccmAdvancedSourceContract,
) -> bool {
    environment.advanced_source_facts.iter().any(|fact| {
        fact.source_id == contract.source_id
            && contract.role_scopes.contains(&fact.role_scope.as_str())
            && contract.path_classes.contains(&fact.path_class.as_str())
            && (!contract.requires_pxe_fact || fact.pxe_enabled)
    }) || (contract.source_id == "advanced-client-notification-bgb"
        && environment
            .roles
            .iter()
            .any(|role| role.role == SccmRole::ManagementPoint)
        && environment
            .roots
            .iter()
            .any(|root| root.role == SccmRole::ManagementPoint))
}

fn observed_fact_for<'a>(
    environment: &'a PrivateSccmEnvironment,
    contract: &SccmAdvancedSourceContract,
    request: &SccmAdvancedCaptureAuthorizationRequest,
    canonical_root: &Path,
) -> Option<&'a PrivateAdvancedSourceFact> {
    environment.advanced_source_facts.iter().find(|fact| {
        fact.source_id == contract.source_id
            && fact.role_scope == request.role_scope
            && fact.path_class == request.path_class
            && (!contract.requires_pxe_fact || fact.pxe_enabled)
            && fact.root.canonicalize().ok().as_deref() == Some(canonical_root)
    })
}

fn validate_selected_root(value: &str) -> Result<PathBuf, SccmCollectorError> {
    if value.is_empty()
        || value.trim() != value
        || value.contains('\0')
        || value
            .bytes()
            .any(|byte| matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}'))
    {
        return Err(SccmCollectorError::AdvancedAuthorizationRejected);
    }
    let supplied = PathBuf::from(value);
    let metadata = fs::symlink_metadata(&supplied)
        .map_err(|_| SccmCollectorError::AdvancedAuthorizationRejected)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(SccmCollectorError::AdvancedAuthorizationRejected);
    }
    supplied
        .canonicalize()
        .map_err(|_| SccmCollectorError::AdvancedAuthorizationRejected)
}

pub fn capture_advanced_authorized(
    authorization: PrivateAdvancedCaptureAuthorization,
    bundle_root: &Path,
) -> Result<SccmCaptureResult, SccmCollectorError> {
    let environment = authorization.environment.clone();
    prepare_bundle_root(bundle_root)?;
    let collected_at_utc = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let host_handle = format!(
        "cmtraceopen.host.sha256.v1:{}",
        sha256_bytes(
            environment
                .private_host
                .as_deref()
                .unwrap_or("unavailable")
                .as_bytes()
        )
    );
    let site_handle = format!(
        "cmtraceopen.site.sha256.v1:{}",
        sha256_bytes(
            environment
                .private_site_code
                .as_deref()
                .unwrap_or("unavailable")
                .as_bytes()
        )
    );
    let root_handle = format!(
        "root-{}",
        sha256_bytes(authorization.canonical_root.to_string_lossy().as_bytes())
    );
    let path_fingerprint = format!(
        "cmtraceopen.path.sha256.v1:{}",
        sha256_bytes(
            format!(
                "advanced-path\0{}\0{}\0{}",
                authorization.contract.source_id, root_handle, authorization.path_class
            )
            .as_bytes(),
        )
    );
    let lineage = format!(
        "cmtraceopen.lineage.sha256.v1:{}",
        sha256_bytes(
            format!(
                "advanced-lineage\0{}\0{}",
                authorization.contract.source_id, root_handle
            )
            .as_bytes(),
        )
    );
    let producer_role = if authorization.provenance == SccmAdvancedProvenance::Observed {
        role_from_claim(&authorization.role_scope)
            .ok_or(SccmCollectorError::AdvancedAuthorizationRejected)?
    } else {
        SccmRole::Unknown("unclassified".to_owned())
    };

    let rotations = [
        (
            SccmRotation::Current,
            authorization.contract.basename.to_owned(),
        ),
        (
            SccmRotation::LoUnderscore,
            lo_basename(authorization.contract.basename),
        ),
    ];
    let mut artifacts = Vec::new();
    let mut payloads = Vec::new();
    let mut statuses = Vec::new();
    let mut retained_bytes = 0_u64;
    let manifest_context = AdvancedManifestContext {
        authorization: &authorization,
        producer_role: &producer_role,
        host_handle: &host_handle,
        path_fingerprint: &path_fingerprint,
        lineage: &lineage,
        collected_at_utc: &collected_at_utc,
    };
    for (rotation, basename) in rotations {
        let source_path = authorization.canonical_root.join(&basename);
        let relative_path = advanced_relative_path(
            &producer_role,
            authorization.contract.source_id,
            &root_handle,
            &basename,
            &rotation,
        )?;
        match copy_exact_source(
            &authorization.canonical_root,
            &source_path,
            &bundle_root.join(&relative_path),
        ) {
            Ok((bytes, capped)) => {
                retained_bytes += bytes.len() as u64;
                let artifact_id = advanced_artifact_id(
                    &authorization,
                    &producer_role,
                    &root_handle,
                    &basename,
                    &rotation,
                    if capped { "capped" } else { "captured" },
                );
                payloads.push(SccmServerArtifactPayload {
                    manifest_artifact_id: artifact_id.clone(),
                    bytes: bytes.clone(),
                });
                artifacts.push(advanced_manifest_row(
                    &manifest_context,
                    &artifact_id,
                    &basename,
                    &rotation,
                    if capped { "capped" } else { "captured" },
                    Some(relative_path),
                    bytes.len() as u64,
                ));
                statuses.push(SccmSourceStatus {
                    role: producer_role.clone(),
                    source_id: authorization.contract.source_id.to_owned(),
                    rotation: rotation_category(&rotation),
                    state: if capped {
                        SccmCoverageState::Capped
                    } else {
                        SccmCoverageState::Captured
                    },
                    retained_bytes: bytes.len() as u64,
                    detail_code: capped.then_some(SccmSourceDetailCode::ByteLimitExceeded),
                });
            }
            Err(CopyAdvancedFailure::AccessDenied) => {
                let artifact_id = advanced_artifact_id(
                    &authorization,
                    &producer_role,
                    &root_handle,
                    &basename,
                    &rotation,
                    "accessDenied",
                );
                artifacts.push(advanced_manifest_row(
                    &manifest_context,
                    &artifact_id,
                    &basename,
                    &rotation,
                    "accessDenied",
                    None,
                    0,
                ));
                statuses.push(SccmSourceStatus {
                    role: producer_role.clone(),
                    source_id: authorization.contract.source_id.to_owned(),
                    rotation: rotation_category(&rotation),
                    state: SccmCoverageState::AccessDenied,
                    retained_bytes: 0,
                    detail_code: Some(SccmSourceDetailCode::AccessDenied),
                });
            }
            Err(CopyAdvancedFailure::Missing) => continue,
            Err(CopyAdvancedFailure::Unsafe) => {
                return Err(SccmCollectorError::AdvancedAuthorizationRejected)
            }
            Err(CopyAdvancedFailure::Failed) => return Err(SccmCollectorError::CaptureFailed),
        }
    }

    if artifacts.is_empty() {
        let state = if authorization.provenance == SccmAdvancedProvenance::Observed {
            "absent"
        } else {
            "unsupported"
        };
        let rotation = SccmRotation::Current;
        let artifact_id = advanced_artifact_id(
            &authorization,
            &producer_role,
            &root_handle,
            authorization.contract.basename,
            &rotation,
            state,
        );
        artifacts.push(advanced_manifest_row(
            &manifest_context,
            &artifact_id,
            authorization.contract.basename,
            &rotation,
            state,
            None,
            0,
        ));
        statuses.push(SccmSourceStatus {
            role: producer_role.clone(),
            source_id: authorization.contract.source_id.to_owned(),
            rotation: SccmRotationCategory::Current,
            state: if state == "absent" {
                SccmCoverageState::Absent
            } else {
                SccmCoverageState::Unsupported
            },
            retained_bytes: 0,
            detail_code: None,
        });
    }

    artifacts.sort_by(|left, right| {
        left["artifactId"]
            .as_str()
            .cmp(&right["artifactId"].as_str())
    });
    let mut roles = environment
        .roles
        .into_iter()
        .map(|fact| fact.role)
        .collect::<Vec<_>>();
    roles.sort_by_key(role_key);
    roles.dedup();
    if authorization.provenance == SccmAdvancedProvenance::Observed
        && !roles.contains(&producer_role)
    {
        roles.push(producer_role.clone());
        roles.sort_by_key(role_key);
    }
    if roles.is_empty() {
        return Err(SccmCollectorError::NoRolesDetected);
    }
    let manifest = json!({
        "sccmManifestVersion": 1,
        "syntheticFixture": false,
        "proposalOnly": Value::Null,
        "privacy": { "synthetic": false, "rawPaths": "redacted" },
        "bundleRole": "server",
        "topology": {
            "captureHost": host_handle,
            "siteCode": site_handle,
            "rolesObserved": roles,
            "hierarchyLinks": []
        },
        "inputOrderIsDeliberatelyUnsorted": Value::Null,
        "artifacts": artifacts
    });
    let manifest_json = serde_json::to_string_pretty(&manifest)
        .map_err(|_| SccmCollectorError::ManifestValidationFailed)?;
    normalize_server_bundle(&manifest_json, &payloads)
        .map_err(|_| SccmCollectorError::ManifestValidationFailed)?;
    let manifest_path = bundle_root.join(super::server_manifest::SCCM_SERVER_MANIFEST_FILE_NAME);
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(manifest_path)
        .map_err(|_| SccmCollectorError::DestinationUnavailable)?;
    output
        .write_all(manifest_json.as_bytes())
        .and_then(|_| output.sync_all())
        .map_err(|_| SccmCollectorError::CaptureFailed)?;
    Ok(SccmCaptureResult {
        bundle_root: bundle_root.to_string_lossy().into_owned(),
        captured_at_utc: collected_at_utc,
        roles,
        artifact_count: payloads.len(),
        retained_bytes,
        sources: statuses,
    })
}

struct AdvancedManifestContext<'a> {
    authorization: &'a PrivateAdvancedCaptureAuthorization,
    producer_role: &'a SccmRole,
    host_handle: &'a str,
    path_fingerprint: &'a str,
    lineage: &'a str,
    collected_at_utc: &'a str,
}

fn advanced_manifest_row(
    context: &AdvancedManifestContext<'_>,
    artifact_id: &str,
    basename: &str,
    rotation: &SccmRotation,
    state: &str,
    relative_path: Option<String>,
    bytes_copied: u64,
) -> Value {
    let authorization = context.authorization;
    let operator_declared = authorization.provenance == SccmAdvancedProvenance::OperatorDeclared;
    json!({
        "artifactId": artifact_id,
        "producerRole": context.producer_role,
        "producerHostHandle": context.host_handle,
        "workflowSubject": Value::Null,
        "sourceId": authorization.contract.source_id,
        "sourceKind": "advancedCapture",
        "sourceVersion": authorization.source_version,
        "originalPath": "REDACTED",
        "originalBasename": basename,
        "configuredPathProvenance": {
            "state": if operator_declared { "operatorDeclared" } else { "configured" },
            "pathClass": if operator_declared { Value::Null } else { json!(authorization.path_class) },
            "pathFingerprint": context.path_fingerprint
        },
        "captureContract": {
            "cardId": authorization.contract.card_id,
            "cardVersion": authorization.contract.card_version,
            "capabilityHandle": authorization.capability_handle,
            "authorizationHandle": authorization.authorization_handle,
            "roleClaim": authorization.role_scope,
            "pathClaim": authorization.path_class,
            "roleProvenance": authorization.provenance.wire(),
            "pathProvenance": authorization.provenance.wire()
        },
        "defaultCandidateState": Value::Null,
        "rotation": {
            "kind": match rotation { SccmRotation::Current => "current", SccmRotation::LoUnderscore => "lo_", _ => "none" },
            "value": Value::Null,
            "lineageId": context.lineage
        },
        "captureState": state,
        "collectionDetail": if state == "accessDenied" { json!(opaque_reason("collection-detail", artifact_id)) } else { Value::Null },
        "skipReason": Value::Null,
        "unsupportedReason": if state == "unsupported" { json!(opaque_reason("unsupported-reason", artifact_id)) } else { Value::Null },
        "encoding": relative_path.as_ref().map(|_| "unknown"),
        "collectionLimit": {
            "byteLimit": ADVANCED_CAPTURE_BYTE_LIMIT,
            "fileLimit": ADVANCED_CAPTURE_FILE_LIMIT,
            "limitApplied": state == "capped"
        },
        "truncated": if state == "capped" { Some(true) } else { None },
        "fragmentComplete": if state == "capped" { Some(false) } else { None },
        "collectedUtc": context.collected_at_utc,
        "relativePath": relative_path,
        "bytesCopied": bytes_copied
    })
}

fn opaque_reason(domain: &str, artifact_id: &str) -> String {
    format!(
        "cmtraceopen.{domain}.sha256.v1:{}",
        sha256_bytes(format!("{domain}\0{artifact_id}").as_bytes())
    )
}

fn advanced_artifact_id(
    authorization: &PrivateAdvancedCaptureAuthorization,
    producer_role: &SccmRole,
    root_handle: &str,
    basename: &str,
    rotation: &SccmRotation,
    state: &str,
) -> String {
    format!(
        "cmtraceopen.artifact.sha256.v1:{}",
        sha256_bytes(
            format!(
                "advanced\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
                authorization.contract.card_id,
                authorization.contract.card_version,
                authorization.contract.source_id,
                role_key(producer_role),
                root_handle,
                basename,
                rotation_segment(rotation),
                state,
                authorization.capability_handle,
            )
            .as_bytes(),
        )
    )
}

fn advanced_relative_path(
    role: &SccmRole,
    source_id: &str,
    root_handle: &str,
    basename: &str,
    rotation: &SccmRotation,
) -> Result<String, SccmCollectorError> {
    let role_segment = match role {
        SccmRole::SiteServer => "site-server",
        SccmRole::ManagementPoint => "management-point",
        SccmRole::DistributionPoint => "distribution-point",
        SccmRole::Unknown(value) if value == "unclassified" => "unclassified",
        SccmRole::Unknown(value) if value == "distributionPointPxe" => "distribution-point-pxe",
        SccmRole::Unknown(value) if value == "certificateRegistrationPoint" => {
            "certificate-registration-point"
        }
        SccmRole::Unknown(value) if value == "reportingServicesPoint" => "reporting-services-point",
        SccmRole::Unknown(value) if value == "cloudManagementGatewayConnectionPoint" => {
            "cloud-management-gateway-connection-point"
        }
        SccmRole::Unknown(value) if value == "serviceConnectionPoint" => "service-connection-point",
        SccmRole::Unknown(value) if value == "clientNotificationServer" => {
            "client-notification-server"
        }
        _ => return Err(SccmCollectorError::AdvancedAuthorizationRejected),
    };
    Ok(format!(
        "evidence/sccm/server/{role_segment}/{source_id}/{root_handle}/{}/{}",
        rotation_segment(rotation),
        basename
    ))
}

fn lo_basename(basename: &str) -> String {
    basename
        .strip_suffix(".log")
        .map_or_else(|| format!("{basename}.lo_"), |stem| format!("{stem}.lo_"))
}

fn rotation_segment(rotation: &SccmRotation) -> &'static str {
    match rotation {
        SccmRotation::Current => "current",
        SccmRotation::LoUnderscore => "lo_",
        _ => "none",
    }
}

fn rotation_category(rotation: &SccmRotation) -> SccmRotationCategory {
    match rotation {
        SccmRotation::Current => SccmRotationCategory::Current,
        SccmRotation::LoUnderscore => SccmRotationCategory::LoUnderscore,
        _ => SccmRotationCategory::Unknown,
    }
}

fn role_from_claim(claim: &str) -> Option<SccmRole> {
    match claim {
        "siteServer" => Some(SccmRole::SiteServer),
        "managementPoint" => Some(SccmRole::ManagementPoint),
        "distributionPointPxe"
        | "certificateRegistrationPoint"
        | "reportingServicesPoint"
        | "cloudManagementGatewayConnectionPoint"
        | "serviceConnectionPoint"
        | "clientNotificationServer" => Some(SccmRole::Unknown(claim.to_owned())),
        _ => None,
    }
}

fn prepare_bundle_root(bundle_root: &Path) -> Result<(), SccmCollectorError> {
    fs::create_dir(bundle_root).map_err(|_| SccmCollectorError::DestinationUnavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(bundle_root, fs::Permissions::from_mode(0o700))
            .map_err(|_| SccmCollectorError::DestinationUnavailable)?;
    }
    Ok(())
}

enum CopyAdvancedFailure {
    AccessDenied,
    Missing,
    Unsafe,
    Failed,
}

fn copy_exact_source(
    canonical_root: &Path,
    source: &Path,
    destination: &Path,
) -> Result<(Vec<u8>, bool), CopyAdvancedFailure> {
    let metadata = fs::symlink_metadata(source).map_err(map_copy_error)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(CopyAdvancedFailure::Unsafe);
    }
    let canonical_source = source.canonicalize().map_err(map_copy_error)?;
    if canonical_source.parent() != Some(canonical_root)
        || !canonical_source.starts_with(canonical_root)
    {
        return Err(CopyAdvancedFailure::Unsafe);
    }
    let mut input = open_source_no_follow(source).map_err(map_copy_error)?;
    let capped = metadata.len() > ADVANCED_CAPTURE_BYTE_LIMIT;
    let read_limit = metadata.len().min(ADVANCED_CAPTURE_BYTE_LIMIT);
    let mut bytes =
        Vec::with_capacity(usize::try_from(read_limit).map_err(|_| CopyAdvancedFailure::Failed)?);
    Read::by_ref(&mut input)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(map_copy_error)?;
    if bytes.len() as u64 != read_limit {
        return Err(CopyAdvancedFailure::Failed);
    }
    fs::create_dir_all(destination.parent().ok_or(CopyAdvancedFailure::Unsafe)?)
        .map_err(map_copy_error)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .map_err(map_copy_error)?;
    output
        .write_all(&bytes)
        .and_then(|_| output.sync_all())
        .map_err(map_copy_error)?;
    Ok((bytes, capped))
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

fn map_copy_error(error: std::io::Error) -> CopyAdvancedFailure {
    match error.kind() {
        std::io::ErrorKind::NotFound => CopyAdvancedFailure::Missing,
        std::io::ErrorKind::PermissionDenied => CopyAdvancedFailure::AccessDenied,
        _ => CopyAdvancedFailure::Failed,
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

use std::fs;
use std::path::{Path, PathBuf};

use app_lib::sccm::collector::{
    capture_environment, discover_environment_with, PrivateSccmEnvironment, SccmCaptureRoot,
    SccmDetectedRole, SccmDiscoveryBasis, SccmDiscoveryFailure, SccmDiscoveryIssue,
    SccmDiscoveryIssueCode, SccmDiscoveryProvider, MAX_BYTES_PER_SOURCE, MAX_FRAGMENTS_PER_SOURCE,
};
use app_lib::sccm::{
    read_sccm_client_intake_bundle, read_sccm_manifest_or_legacy, SccmCoverageState, SccmRole,
};

#[derive(Clone)]
struct FakeProvider {
    environment: PrivateSccmEnvironment,
}

impl SccmDiscoveryProvider for FakeProvider {
    fn discover(&self) -> Result<PrivateSccmEnvironment, SccmDiscoveryFailure> {
        Ok(self.environment.clone())
    }
}

fn provider(role: SccmRole, roots: impl IntoIterator<Item = PathBuf>) -> FakeProvider {
    FakeProvider {
        environment: PrivateSccmEnvironment {
            supported: true,
            configmgr_version: Some("5.00.0001.0001".to_owned()),
            roles: vec![SccmDetectedRole {
                role: role.clone(),
                basis: SccmDiscoveryBasis::Registry,
            }],
            roots: roots
                .into_iter()
                .map(|path| SccmCaptureRoot {
                    role: role.clone(),
                    path,
                })
                .collect(),
            private_host: Some("PRIVATE-HOST-SENTINEL".to_owned()),
            private_site_code: Some("PRIVATE-SITE-SENTINEL".to_owned()),
            ..PrivateSccmEnvironment::default()
        },
    }
}

fn capture(
    provider: &FakeProvider,
    parent: &Path,
    name: &str,
) -> app_lib::sccm::collector::SccmCaptureResult {
    capture_environment(provider, &parent.join(name)).expect("native capture")
}

#[test]
fn public_result_excludes_private_discovery_sentinels() {
    let logs = tempfile::tempdir().unwrap();
    let provider = provider(SccmRole::Client, [logs.path().to_owned()]);
    let value = serde_json::to_string(&discover_environment_with(&provider).unwrap()).unwrap();
    assert!(!value.contains("PRIVATE-HOST-SENTINEL"));
    assert!(!value.contains("PRIVATE-SITE-SENTINEL"));
    assert!(!value.contains(logs.path().to_string_lossy().as_ref()));
}

#[test]
fn discovery_roles_issues_and_order_are_deterministic() {
    let root = tempfile::tempdir().unwrap();
    let mut provider = provider(
        SccmRole::Provider,
        [root.path().to_owned(), root.path().to_owned()],
    );
    provider.environment.roles.extend([
        SccmDetectedRole {
            role: SccmRole::Client,
            basis: SccmDiscoveryBasis::Service,
        },
        SccmDetectedRole {
            role: SccmRole::Provider,
            basis: SccmDiscoveryBasis::Cim,
        },
    ]);
    provider.environment.issues.extend([
        SccmDiscoveryIssue {
            code: SccmDiscoveryIssueCode::CimAccessDenied,
            role: Some(SccmRole::Provider),
        },
        SccmDiscoveryIssue {
            code: SccmDiscoveryIssueCode::RegistryAccessDenied,
            role: Some(SccmRole::Client),
        },
    ]);
    let first = discover_environment_with(&provider).unwrap();
    let second = discover_environment_with(&provider).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.roles[0].role, SccmRole::Client);
    assert_eq!(first.roles[1].basis, SccmDiscoveryBasis::Registry);
    assert_eq!(first.roles[2].basis, SccmDiscoveryBasis::Cim);
    assert_eq!(first.issues.len(), 2);
}

#[test]
fn discovery_defaults_without_role_facts_never_claim_a_role() {
    let logs = tempfile::tempdir().unwrap();
    let provider = FakeProvider {
        environment: PrivateSccmEnvironment {
            supported: true,
            roots: vec![SccmCaptureRoot {
                role: SccmRole::SiteServer,
                path: logs.path().to_owned(),
            }],
            ..PrivateSccmEnvironment::default()
        },
    };
    assert!(discover_environment_with(&provider)
        .unwrap()
        .roles
        .is_empty());
}

#[test]
fn discovery_preserves_each_explicit_server_role_fact_without_inference() {
    for role in [
        SccmRole::SiteServer,
        SccmRole::ManagementPoint,
        SccmRole::DistributionPoint,
        SccmRole::SoftwareUpdatePoint,
        SccmRole::WsUs,
        SccmRole::Provider,
        SccmRole::AdminService,
    ] {
        let discovery = discover_environment_with(&provider(role.clone(), [])).unwrap();
        assert_eq!(
            discovery
                .roles
                .iter()
                .map(|fact| fact.role.clone())
                .collect::<Vec<_>>(),
            vec![role]
        );
    }
}

#[test]
fn capture_collects_all_supported_client_rotations_and_validates_manifest() {
    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    for name in [
        "PolicyAgent.log",
        "PolicyAgent.lo_",
        "PolicyAgent.log.1",
        "PolicyAgent.log.20260804-123456",
    ] {
        fs::write(logs.path().join(name), format!("content:{name}")).unwrap();
    }
    let result = capture(
        &provider(SccmRole::Client, [logs.path().to_owned()]),
        bundles.path(),
        "bundle",
    );
    assert_eq!(result.artifact_count, 4);
    assert_eq!(
        result
            .sources
            .iter()
            .filter(|source| source.state == SccmCoverageState::Captured)
            .count(),
        4
    );
    assert!(result
        .sources
        .iter()
        .any(|source| source.state == SccmCoverageState::Absent));
    assert!(bundles.path().join("bundle/sccm-manifest.json").is_file());
    let reopened = read_sccm_manifest_or_legacy(&bundles.path().join("bundle")).unwrap();
    assert!(reopened
        .artifacts
        .iter()
        .any(|artifact| artifact.state == app_lib::sccm::SccmManifestSourceState::Absent));
}

#[test]
fn capture_reports_malformed_rotation_without_copying_it() {
    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    fs::write(logs.path().join("PolicyAgent.log.latest"), b"unsafe suffix").unwrap();
    let result = capture(
        &provider(SccmRole::Client, [logs.path().to_owned()]),
        bundles.path(),
        "bundle",
    );
    assert!(result.sources.iter().any(|source| {
        source.state == SccmCoverageState::Unsupported
            && source.detail_code
                == Some(app_lib::sccm::collector::SccmSourceDetailCode::MalformedRotation)
    }));
    assert_eq!(result.retained_bytes, 0);
    let reopened = read_sccm_manifest_or_legacy(&bundles.path().join("bundle")).unwrap();
    assert!(reopened
        .artifacts
        .iter()
        .any(|artifact| artifact.state == app_lib::sccm::SccmManifestSourceState::Unsupported));
}

#[test]
fn capture_persists_absent_and_read_failure_coverage() {
    let parent = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    capture(
        &provider(
            SccmRole::Client,
            [parent.path().join("missing-client-root")],
        ),
        bundles.path(),
        "absent-bundle",
    );
    let absent = read_sccm_manifest_or_legacy(&bundles.path().join("absent-bundle")).unwrap();
    assert!(absent
        .artifacts
        .iter()
        .all(|artifact| artifact.state == app_lib::sccm::SccmManifestSourceState::Absent));

    let not_a_directory = parent.path().join("not-a-directory");
    fs::write(&not_a_directory, b"not a root").unwrap();
    capture(
        &provider(SccmRole::Client, [not_a_directory]),
        bundles.path(),
        "failed-bundle",
    );
    let failed = read_sccm_manifest_or_legacy(&bundles.path().join("failed-bundle")).unwrap();
    assert!(failed.artifacts.iter().all(|artifact| {
        artifact.state == app_lib::sccm::SccmManifestSourceState::FailedUnknownDetail
    }));
}

#[cfg(unix)]
#[test]
fn capture_persists_access_denied_coverage() {
    use std::os::unix::fs::PermissionsExt;

    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    fs::set_permissions(logs.path(), fs::Permissions::from_mode(0o000)).unwrap();
    let result = capture(
        &provider(SccmRole::Client, [logs.path().to_owned()]),
        bundles.path(),
        "bundle",
    );
    fs::set_permissions(logs.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result
        .sources
        .iter()
        .all(|source| source.state == SccmCoverageState::AccessDenied));
    let reopened = read_sccm_manifest_or_legacy(&bundles.path().join("bundle")).unwrap();
    assert!(reopened.artifacts.iter().all(|artifact| {
        artifact.state == app_lib::sccm::SccmManifestSourceState::AccessDenied
    }));
}

#[test]
fn capture_applies_the_byte_cap_to_the_exact_retained_prefix() {
    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    let file = fs::File::create(logs.path().join("PolicyAgent.log")).unwrap();
    file.set_len(MAX_BYTES_PER_SOURCE + 1).unwrap();
    let result = capture(
        &provider(SccmRole::Client, [logs.path().to_owned()]),
        bundles.path(),
        "bundle",
    );
    assert_eq!(result.retained_bytes, MAX_BYTES_PER_SOURCE);
    assert!(result
        .sources
        .iter()
        .any(|source| source.state == SccmCoverageState::Capped));
    let reopened = read_sccm_manifest_or_legacy(&bundles.path().join("bundle")).unwrap();
    assert!(reopened
        .artifacts
        .iter()
        .any(|artifact| artifact.state == app_lib::sccm::SccmManifestSourceState::Capped));
}

#[test]
fn capture_applies_the_fragment_cap_per_source() {
    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    fs::write(logs.path().join("PolicyAgent.log"), b"current").unwrap();
    fs::write(logs.path().join("PolicyAgent.lo_"), b"lo").unwrap();
    for number in 1..=8 {
        fs::write(
            logs.path().join(format!("PolicyAgent.log.{number}")),
            b"rotation",
        )
        .unwrap();
    }
    let result = capture(
        &provider(SccmRole::Client, [logs.path().to_owned()]),
        bundles.path(),
        "bundle",
    );
    assert_eq!(
        result
            .sources
            .iter()
            .filter(|source| source.retained_bytes > 0)
            .count(),
        MAX_FRAGMENTS_PER_SOURCE
    );
    assert!(result
        .sources
        .iter()
        .any(|source| source.state == SccmCoverageState::Capped));
    let reopened = read_sccm_client_intake_bundle(&bundles.path().join("bundle")).unwrap();
    assert!(reopened
        .capture_gaps
        .iter()
        .any(|gap| gap.coverage == SccmCoverageState::Capped));
}

#[test]
fn capture_keeps_same_basename_from_two_roots_distinct() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    fs::write(first.path().join("PolicyAgent.log"), b"first").unwrap();
    fs::write(second.path().join("PolicyAgent.log"), b"second").unwrap();
    let result = capture(
        &provider(
            SccmRole::Client,
            [first.path().to_owned(), second.path().to_owned()],
        ),
        bundles.path(),
        "bundle",
    );
    assert_eq!(result.artifact_count, 2);
    let evidence = bundles.path().join("bundle/evidence/sccm/client");
    assert_eq!(
        walkdir_count_files(&evidence),
        2,
        "root handles must prevent destination collisions"
    );
}

#[test]
fn capture_rejects_a_preexisting_bundle_without_overwrite() {
    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    fs::write(logs.path().join("PolicyAgent.log"), b"policy").unwrap();
    fs::create_dir(bundles.path().join("bundle")).unwrap();
    fs::write(bundles.path().join("bundle/sentinel"), b"keep").unwrap();
    let error = capture_environment(
        &provider(SccmRole::Client, [logs.path().to_owned()]),
        &bundles.path().join("bundle"),
    )
    .unwrap_err();
    assert_eq!(error.code(), "destinationUnavailable");
    assert_eq!(
        fs::read(bundles.path().join("bundle/sentinel")).unwrap(),
        b"keep"
    );
}

#[cfg(unix)]
#[test]
fn capture_rejects_symlink_evidence() {
    use std::os::unix::fs::symlink;

    let logs = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    symlink(outside.path(), logs.path().join("PolicyAgent.log")).unwrap();
    let result = capture(
        &provider(SccmRole::Client, [logs.path().to_owned()]),
        bundles.path(),
        "bundle",
    );
    assert_eq!(result.retained_bytes, 0);
    assert!(result
        .sources
        .iter()
        .any(|source| source.state == SccmCoverageState::Skipped));
    let reopened = read_sccm_manifest_or_legacy(&bundles.path().join("bundle")).unwrap();
    assert!(reopened
        .artifacts
        .iter()
        .any(|artifact| artifact.state == app_lib::sccm::SccmManifestSourceState::Skipped));
}

#[test]
fn capture_writes_and_parser_validates_the_server_manifest() {
    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    fs::write(logs.path().join("sitecomp.log"), b"server evidence").unwrap();
    let result = capture(
        &provider(SccmRole::SiteServer, [logs.path().to_owned()]),
        bundles.path(),
        "bundle",
    );
    assert_eq!(result.artifact_count, 1);
    let manifest =
        fs::read_to_string(bundles.path().join("bundle/sccm-server-manifest.json")).unwrap();
    assert!(!manifest.contains("PRIVATE-HOST-SENTINEL"));
    assert!(!manifest.contains("PRIVATE-SITE-SENTINEL"));
    assert!(!manifest.contains(logs.path().to_string_lossy().as_ref()));
    let manifest_value: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert!(manifest_value["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["captureState"] == "absent"));
}

#[test]
fn capture_parser_validates_each_declared_server_role_manifest() {
    for (role, basename) in [
        (SccmRole::ManagementPoint, "MP_GetAuth.log"),
        (SccmRole::DistributionPoint, "SMSDPProv.log"),
        (SccmRole::SoftwareUpdatePoint, "WSUSCtrl.log"),
        (SccmRole::Provider, "Smsprov.log"),
        (SccmRole::AdminService, "AdminService.log"),
    ] {
        let logs = tempfile::tempdir().unwrap();
        let bundles = tempfile::tempdir().unwrap();
        fs::write(logs.path().join(basename), b"server evidence").unwrap();
        let result = capture(
            &provider(role.clone(), [logs.path().to_owned()]),
            bundles.path(),
            "bundle",
        );
        assert_eq!(result.roles, vec![role]);
        assert!(bundles
            .path()
            .join("bundle/sccm-server-manifest.json")
            .is_file());
    }

    let logs = tempfile::tempdir().unwrap();
    let bundles = tempfile::tempdir().unwrap();
    fs::write(logs.path().join("WsusHealth.json"), b"{}").unwrap();
    let mut wsus = provider(SccmRole::WsUs, [logs.path().to_owned()]);
    wsus.environment.roles.push(SccmDetectedRole {
        role: SccmRole::SoftwareUpdatePoint,
        basis: SccmDiscoveryBasis::Registry,
    });
    capture(&wsus, bundles.path(), "bundle");
}

fn walkdir_count_files(root: &Path) -> usize {
    let mut count = 0;
    let mut pending = vec![root.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else {
                count += 1;
            }
        }
    }
    count
}

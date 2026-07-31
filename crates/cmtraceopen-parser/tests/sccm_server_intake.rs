use cmtraceopen_parser::sccm::server::windows::{
    assess_server_intake, SccmServerArtifactPayload,
};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmRole};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn intake_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/intake")
}

fn load_bundle(scenario: &str) -> (String, Vec<SccmServerArtifactPayload>) {
    let scenario_root = intake_root().join(scenario);
    let manifest_json =
        std::fs::read_to_string(scenario_root.join("manifest.json")).expect("manifest is readable");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("manifest is valid JSON");
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("artifacts are an array")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId is a string")
                    .to_owned(),
                bytes: std::fs::read(scenario_root.join(relative_path))
                    .expect("captured artifact bytes are readable"),
            })
        })
        .collect();
    (manifest_json, payloads)
}

#[test]
fn server_intake_normalizes_role_coverage_and_logical_records() {
    let (complete_manifest, complete_payloads) = load_bundle("complete-multi-role");
    let complete =
        assess_server_intake(&complete_manifest, &complete_payloads).expect("bundle is assessed");

    assert_eq!(complete.schema_version, 1);
    assert_eq!(
        complete
            .coverage
            .iter()
            .map(|row| (
                row.producer_role.clone(),
                row.workflow_subject_role.clone(),
                row.source_id.as_str(),
                row.state.clone(),
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                SccmRole::ManagementPoint,
                None,
                "server-mp-policy",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                Some(SccmRole::DistributionPoint),
                "server-dp-distribution",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                None,
                "server-sitecomp",
                SccmCoverageState::Captured,
            ),
            (
                SccmRole::SiteServer,
                Some(SccmRole::SoftwareUpdatePoint),
                "server-sup-sync",
                SccmCoverageState::Captured,
            ),
        ]
    );
    assert_eq!(complete.evidence.len(), 4);
    assert!(complete.findings.is_empty());

    let (multiline_manifest, multiline_payloads) = load_bundle("multiline");
    let multiline =
        assess_server_intake(&multiline_manifest, &multiline_payloads).expect("bundle is assessed");
    assert_eq!(multiline.evidence.len(), 1);
    assert_eq!(multiline.evidence[0].reference.line_start, Some(1));
    assert_eq!(multiline.evidence[0].reference.line_end, Some(2));

    let (absent_manifest, absent_payloads) = load_bundle("absent-dp");
    let absent =
        assess_server_intake(&absent_manifest, &absent_payloads).expect("bundle is assessed");
    assert_eq!(absent.coverage.len(), 1);
    assert_eq!(absent.coverage[0].state, SccmCoverageState::Absent);
    assert!(absent.evidence.is_empty());
    assert!(absent.findings.is_empty());
    assert_eq!(absent.next_artifact_requests.len(), 1);
    assert_eq!(
        absent.next_artifact_requests[0].source_id,
        "server-dp-distribution"
    );

    let (unsorted_manifest, unsorted_payloads) = load_bundle("unsorted-manifest");
    let unsorted =
        assess_server_intake(&unsorted_manifest, &unsorted_payloads).expect("bundle is assessed");
    let mut reordered_manifest: Value =
        serde_json::from_str(&unsorted_manifest).expect("manifest is valid JSON");
    reordered_manifest["artifacts"]
        .as_array_mut()
        .expect("artifacts are an array")
        .reverse();
    let reordered = assess_server_intake(
        &serde_json::to_string(&reordered_manifest).expect("manifest serializes"),
        &unsorted_payloads,
    )
    .expect("reordered bundle is assessed");
    assert_eq!(
        serde_json::to_vec(&unsorted).expect("assessment serializes"),
        serde_json::to_vec(&reordered).expect("assessment serializes"),
        "manifest order must not affect normalized output"
    );
}

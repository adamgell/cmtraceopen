use cmtraceopen_parser::sccm::server::windows::{
    assess_server_intake, declared_hierarchy_source_contracts, SccmServerArtifactPayload,
    SccmServerHierarchySourceContract, SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION,
};
use cmtraceopen_parser::sccm::SccmRotation;
use serde_json::json;

fn contract_rows() -> Vec<(&'static str, &'static str, &'static str)> {
    declared_hierarchy_source_contracts()
        .iter()
        .map(|contract| {
            (
                contract.source_id,
                contract.logical_name,
                contract.expected_component,
            )
        })
        .collect()
}

#[test]
fn catalog_declares_only_observed_hierarchy_source_components() {
    let contracts = declared_hierarchy_source_contracts();
    assert_eq!(contracts.len(), 5);
    assert!(
        contracts
            .iter()
            .all(|contract| contract.contract_version
                == SCCM_SERVER_HIERARCHY_SOURCE_CONTRACT_VERSION)
    );
    assert_eq!(
        contract_rows(),
        vec![
            (
                "server-hierarchy-control",
                "replmgr",
                "SMS_REPLICATION_MANAGER"
            ),
            (
                "server-hierarchy-control",
                "rcmctrl",
                "SMS_REPLICATION_CONFIGURATION_MONITOR"
            ),
            (
                "server-hierarchy-control",
                "rcmctrl",
                "SMS_REPLICATION_CONFIGURATION_MONITOR"
            ),
            ("server-hierarchy-transfer", "sender", "SMS_LAN_SENDER"),
            ("server-hierarchy-transfer", "despool", "SMS_DESPOOLER"),
        ]
    );
    assert!(!contracts
        .iter()
        .any(|contract| contract.logical_name == "sender.lo_"));
}

#[test]
fn catalog_contract_rows_have_distinct_rotation_policies() {
    let contracts = declared_hierarchy_source_contracts();
    let rcmctrl = contracts
        .iter()
        .filter(|contract| contract.logical_name == "rcmctrl")
        .collect::<Vec<&SccmServerHierarchySourceContract>>();
    assert_eq!(rcmctrl.len(), 2);
    assert_ne!(
        rcmctrl[0].allows_rotation(&SccmRotation::Current),
        rcmctrl[1].allows_rotation(&SccmRotation::Current)
    );
    assert!(rcmctrl[0].allows_rotation(&SccmRotation::Current));
    assert!(rcmctrl[1].allows_rotation(&SccmRotation::LoUnderscore));
}

fn opaque(prefix: &str, value: u8) -> String {
    format!("{prefix}{value:064x}")
}

fn live_like_replmgr_manifest(
    direction: Option<&str>,
    hierarchy_links: serde_json::Value,
) -> (String, Vec<SccmServerArtifactPayload>) {
    live_like_replmgr_manifest_with_content(
        direction,
        hierarchy_links,
        br#"<![LOG[replication manager record]LOG]!><time="21:50:03.847+240" date="08-01-2026" component="SMS_REPLICATION_MANAGER" context="" type="1" thread="1" file="replmgr.cpp">"#,
    )
}

fn live_like_replmgr_manifest_with_content(
    direction: Option<&str>,
    hierarchy_links: serde_json::Value,
    content: &[u8],
) -> (String, Vec<SccmServerArtifactPayload>) {
    let artifact_id = opaque("cmtraceopen.artifact.sha256.v1:", 3);
    let host = opaque("cmtraceopen.host.sha256.v1:", 1);
    let site = opaque("cmtraceopen.site.sha256.v1:", 2);
    let producer_host = opaque("cmtraceopen.host.sha256.v1:", 1);
    let path = opaque("cmtraceopen.path.sha256.v1:", 4);
    let lineage = opaque("cmtraceopen.lineage.sha256.v1:", 5);
    let mut artifact = json!({
        "artifactId": artifact_id,
        "producerRole": "siteServer",
        "producerHostHandle": producer_host,
        "sourceId": "server-hierarchy-control",
        "sourceKind": "ccmLog",
        "sourceVersion": null,
        "originalPath": "REDACTED",
        "originalBasename": "replmgr.log",
        "configuredPathProvenance": {
            "state": "configured",
            "pathFingerprint": path,
        },
        "rotation": {
            "kind": "current",
            "lineageId": lineage,
        },
        "captureState": "captured",
        "encoding": "utf-8",
        "collectionLimit": {"byteLimit": 4096, "limitApplied": false},
        "collectedUtc": "2026-08-02T00:00:00Z",
        "relativePath": "evidence/sccm/server/site-server/server-hierarchy-control/root-00000001/current/replmgr.log",
        "bytesCopied": content.len(),
    });
    if let Some(direction) = direction {
        artifact["direction"] = json!(direction);
    }
    let manifest = json!({
        "sccmManifestVersion": 1,
        "hierarchyContractVersion": 1,
        "syntheticFixture": false,
        "bundleRole": "server",
        "topology": {
            "captureHost": host,
            "siteCode": site,
            "rolesObserved": ["siteServer"],
            "hierarchyLinks": hierarchy_links,
        },
        "artifacts": [artifact],
    });
    (
        serde_json::to_string(&manifest).expect("manifest serializes"),
        vec![SccmServerArtifactPayload {
            manifest_artifact_id: opaque("cmtraceopen.artifact.sha256.v1:", 3),
            bytes: content.to_vec(),
        }],
    )
}

#[test]
fn live_like_manifest_preserves_missing_version_topology_direction_and_keys() {
    let (manifest, payloads) = live_like_replmgr_manifest(Some("origin"), json!([]));
    let assessment = assess_server_intake(&manifest, &payloads).expect("intake succeeds");
    let artifact = &assessment.artifacts[0];
    let admission = artifact
        .hierarchy_admission
        .as_ref()
        .expect("hierarchy admission is present");
    assert_eq!(artifact.source_version, None);
    assert!(!artifact.profile_eligible);
    assert!(!artifact.parser_eligible);
    assert!(assessment.evidence.is_empty());
    assert_eq!(admission.direction, None);
    assert!(admission.gaps.contains(
        &cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::MissingVersion
    ));
    assert!(admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::MissingTopology));
    assert!(admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::UnvalidatedDirection));
    assert!(admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::UnvalidatedKeys));
}

#[test]
fn direction_is_validated_against_an_explicit_opaque_link() {
    let origin_site = opaque("cmtraceopen.site.sha256.v1:", 2);
    let target_site = opaque("cmtraceopen.site.sha256.v1:", 7);
    let origin_host = opaque("cmtraceopen.host.sha256.v1:", 1);
    let target_host = opaque("cmtraceopen.host.sha256.v1:", 8);
    let links = json!([{
        "originSiteCode": origin_site,
        "targetSiteCode": target_site,
        "originHostHandle": origin_host,
        "targetHostHandle": target_host,
    }]);
    let (manifest, payloads) = live_like_replmgr_manifest(Some("origin"), links);
    let assessment = assess_server_intake(&manifest, &payloads).expect("intake succeeds");
    let admission = assessment.artifacts[0]
        .hierarchy_admission
        .as_ref()
        .expect("hierarchy admission is present");
    assert_eq!(
        admission.direction,
        Some(cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyDirection::Origin)
    );
    assert!(!admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::MissingTopology));
    assert!(!admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::UnvalidatedDirection));
}

#[test]
fn direction_is_non_authoritative_when_site_or_host_does_not_match() {
    let links = json!([{
        "originSiteCode": opaque("cmtraceopen.site.sha256.v1:", 6),
        "targetSiteCode": opaque("cmtraceopen.site.sha256.v1:", 7),
        "originHostHandle": opaque("cmtraceopen.host.sha256.v1:", 8),
        "targetHostHandle": opaque("cmtraceopen.host.sha256.v1:", 9),
    }]);
    let (manifest, payloads) = live_like_replmgr_manifest(Some("origin"), links);
    let assessment = assess_server_intake(&manifest, &payloads).expect("intake succeeds");
    let artifact = &assessment.artifacts[0];
    let admission = artifact
        .hierarchy_admission
        .as_ref()
        .expect("hierarchy admission is present");
    assert_eq!(artifact.direction, None);
    assert_eq!(admission.direction, None);
    assert!(admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::UnvalidatedDirection));
}

#[test]
fn hierarchy_links_reject_equal_site_or_host_handles() {
    for links in [
        json!([{
            "originSiteCode": opaque("cmtraceopen.site.sha256.v1:", 2),
            "targetSiteCode": opaque("cmtraceopen.site.sha256.v1:", 2),
            "originHostHandle": opaque("cmtraceopen.host.sha256.v1:", 8),
            "targetHostHandle": opaque("cmtraceopen.host.sha256.v1:", 9),
        }]),
        json!([{
            "originSiteCode": opaque("cmtraceopen.site.sha256.v1:", 2),
            "targetSiteCode": opaque("cmtraceopen.site.sha256.v1:", 7),
            "originHostHandle": opaque("cmtraceopen.host.sha256.v1:", 8),
            "targetHostHandle": opaque("cmtraceopen.host.sha256.v1:", 8),
        }]),
    ] {
        let (manifest, payloads) = live_like_replmgr_manifest(None, links);
        assert!(matches!(
            assess_server_intake(&manifest, &payloads),
            Err(cmtraceopen_parser::sccm::server::windows::SccmServerIntakeError::InvalidTopology)
        ));
    }
}

#[test]
fn hierarchy_contract_version_mismatch_is_an_explicit_gap() {
    let (manifest, payloads) = live_like_replmgr_manifest(None, json!([]));
    let mut manifest = serde_json::from_str::<serde_json::Value>(&manifest).expect("manifest JSON");
    manifest["hierarchyContractVersion"] = json!(2);
    let assessment = assess_server_intake(
        &serde_json::to_string(&manifest).expect("manifest serializes"),
        &payloads,
    )
    .expect("mismatched contract remains coverage");
    let admission = assessment.artifacts[0]
        .hierarchy_admission
        .as_ref()
        .expect("hierarchy admission is present");
    assert_eq!(admission.contract_version, None);
    assert!(admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::UnsupportedContractVersion));
    assert!(assessment.evidence.is_empty());
}

#[test]
fn component_token_outside_a_valid_ccm_record_is_not_component_evidence() {
    let content = b"plain text mentions SMS_REPLICATION_MANAGER but is not a CCM record\n";
    let (manifest, payloads) = live_like_replmgr_manifest_with_content(None, json!([]), content);
    let assessment = assess_server_intake(&manifest, &payloads).expect("intake succeeds");
    let admission = assessment.artifacts[0]
        .hierarchy_admission
        .as_ref()
        .expect("hierarchy admission is present");
    assert!(admission
        .gaps
        .contains(&cmtraceopen_parser::sccm::server::windows::SccmServerHierarchyAdmissionGap::ComponentMismatch));
    assert!(assessment.evidence.is_empty());
}

fn site_database_supplement_manifest(
    schema_version: u64,
    authorized: bool,
    privacy: &str,
) -> (String, Vec<SccmServerArtifactPayload>) {
    let (manifest, payloads) = live_like_replmgr_manifest(None, json!([]));
    let mut manifest = serde_json::from_str::<serde_json::Value>(&manifest).expect("manifest JSON");
    let artifact = &mut manifest["artifacts"][0];
    artifact["sourceId"] = json!("server-hierarchy-site-database");
    artifact["sourceKind"] = json!("structuredSupplement");
    artifact["originalBasename"] = json!("site-database.supplement");
    artifact["supplementSchemaVersion"] = json!(schema_version);
    artifact["operatorAuthorized"] = json!(authorized);
    artifact["privacyClass"] = json!(privacy);
    artifact["fragmentComplete"] = json!(true);
    artifact["truncated"] = json!(false);
    artifact["relativePath"] = json!("evidence/sccm/server/site-server/server-hierarchy-site-database/root-00000001/current/site-database.supplement");
    (
        serde_json::to_string(&manifest).expect("manifest serializes"),
        payloads,
    )
}

#[test]
fn structured_supplement_is_admitted_only_as_redacted_provenance() {
    let (manifest, payloads) = site_database_supplement_manifest(1, true, "redacted");
    let assessment = assess_server_intake(&manifest, &payloads).expect("supplement intake");
    let artifact = &assessment.artifacts[0];
    assert_eq!(
        artifact.supplement_admission,
        Some(cmtraceopen_parser::sccm::server::windows::SccmServerSupplementAdmission::Admitted)
    );
    assert_eq!(
        artifact.supplement_provenance.as_deref(),
        Some("imported supplemental evidence")
    );
    assert!(!artifact.parser_eligible);
    assert!(assessment.evidence.is_empty());
}

#[test]
fn structured_supplement_unknown_schema_remains_coverage_only() {
    let (manifest, payloads) = site_database_supplement_manifest(2, true, "redacted");
    let assessment =
        assess_server_intake(&manifest, &payloads).expect("unknown schema is coverage");
    assert!(matches!(
        &assessment.artifacts[0].supplement_admission,
        Some(cmtraceopen_parser::sccm::server::windows::SccmServerSupplementAdmission::CoverageOnly {
            gaps
        }) if gaps.contains(&cmtraceopen_parser::sccm::server::windows::SccmServerSupplementGap::UnsupportedSchemaVersion)
    ));
    assert!(assessment.evidence.is_empty());
}

#[test]
fn structured_supplement_unknown_encoding_remains_coverage_only_without_digest() {
    let (manifest, payloads) = site_database_supplement_manifest(1, true, "redacted");
    let mut manifest = serde_json::from_str::<serde_json::Value>(&manifest).expect("manifest JSON");
    manifest["artifacts"][0]["encoding"] = json!("unknown");

    let assessment = assess_server_intake(
        &serde_json::to_string(&manifest).expect("manifest serializes"),
        &payloads,
    )
    .expect("unknown encoding remains coverage");
    let artifact = &assessment.artifacts[0];
    assert!(matches!(
        &artifact.supplement_admission,
        Some(cmtraceopen_parser::sccm::server::windows::SccmServerSupplementAdmission::CoverageOnly {
            gaps
        }) if gaps.contains(&cmtraceopen_parser::sccm::server::windows::SccmServerSupplementGap::MissingDigest)
    ));
    assert_eq!(artifact.content_sha256, None);
    assert!(!artifact.parser_eligible);
    assert!(assessment.evidence.is_empty());
}

#[test]
fn structured_supplement_matrix_stays_coverage_only_without_complete_integrity() {
    type SupplementMutation = fn(&mut serde_json::Value);
    let cases: &[(&str, SupplementMutation)] = &[
        ("unauthorized", |artifact: &mut serde_json::Value| {
            artifact["operatorAuthorized"] = json!(false);
        }),
        ("wrong privacy", |artifact: &mut serde_json::Value| {
            artifact["privacyClass"] = json!("raw");
        }),
        ("capped", |artifact: &mut serde_json::Value| {
            artifact["captureState"] = json!("capped");
            artifact["truncated"] = json!(true);
            artifact["fragmentComplete"] = json!(false);
            let copied = artifact["bytesCopied"].clone();
            artifact["collectionLimit"]["byteLimit"] = copied;
            artifact["collectionLimit"]["limitApplied"] = json!(true);
        }),
        ("incomplete", |artifact: &mut serde_json::Value| {
            artifact["fragmentComplete"] = json!(false);
            artifact["truncated"] = json!(false);
        }),
        ("malformed payload", |artifact: &mut serde_json::Value| {
            artifact["encoding"] = json!("not-an-encoding");
        }),
        ("oversized for cap", |artifact: &mut serde_json::Value| {
            artifact["collectionLimit"]["byteLimit"] = json!(1);
        }),
        (
            "missing collection limit",
            |artifact: &mut serde_json::Value| {
                artifact
                    .as_object_mut()
                    .expect("artifact object")
                    .remove("collectionLimit");
            },
        ),
        ("missing payload", |artifact: &mut serde_json::Value| {
            artifact["captureState"] = json!("captured");
        }),
        ("absent", |artifact: &mut serde_json::Value| {
            artifact["captureState"] = json!("absent");
            let object = artifact.as_object_mut().expect("artifact object");
            object.remove("relativePath");
            object.remove("encoding");
            object.remove("collectionLimit");
            object.remove("fragmentComplete");
            object.remove("truncated");
            artifact["bytesCopied"] = json!(0);
        }),
        ("denied", |artifact: &mut serde_json::Value| {
            artifact["captureState"] = json!("accessDenied");
            artifact["collectionDetail"] =
                json!(opaque("cmtraceopen.collection-detail.sha256.v1:", 10));
            let object = artifact.as_object_mut().expect("artifact object");
            object.remove("relativePath");
            object.remove("encoding");
            object.remove("collectionLimit");
            object.remove("fragmentComplete");
            object.remove("truncated");
            artifact["bytesCopied"] = json!(0);
        }),
        ("skipped", |artifact: &mut serde_json::Value| {
            artifact["captureState"] = json!("skipped");
            artifact["skipReason"] = json!(opaque("cmtraceopen.skip-reason.sha256.v1:", 11));
            let object = artifact.as_object_mut().expect("artifact object");
            object.remove("relativePath");
            object.remove("encoding");
            object.remove("collectionLimit");
            object.remove("fragmentComplete");
            object.remove("truncated");
            artifact["bytesCopied"] = json!(0);
        }),
    ];
    for (label, mutate) in cases {
        let (manifest, payloads) = site_database_supplement_manifest(1, true, "redacted");
        let mut manifest =
            serde_json::from_str::<serde_json::Value>(&manifest).expect("manifest JSON");
        mutate(&mut manifest["artifacts"][0]);
        let payloads = if *label == "missing payload" {
            Vec::new()
        } else {
            payloads
        };
        let assessment = assess_server_intake(
            &serde_json::to_string(&manifest).expect("manifest serializes"),
            &payloads,
        )
        .unwrap_or_else(|error| panic!("{label} must remain coverage: {error}"));
        assert!(matches!(
            assessment.artifacts[0].supplement_admission,
            Some(cmtraceopen_parser::sccm::server::windows::SccmServerSupplementAdmission::CoverageOnly { .. })
        ), "{label} was admitted");
        assert!(assessment.evidence.is_empty(), "{label} produced evidence");
    }
}

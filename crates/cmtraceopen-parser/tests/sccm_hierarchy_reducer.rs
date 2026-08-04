use cmtraceopen_parser::sccm::{
    analyze_hierarchy_replication, SccmArtifact, SccmCoverageState, SccmHierarchyArtifact,
    SccmHierarchyBundle, SccmHierarchyClassification, SccmHierarchyConfidence,
    SccmHierarchyDirection, SccmHierarchyPhase, SccmHierarchyState, SccmHierarchyTimestampOrdering,
    SccmHierarchyTopology, SccmRole, SccmRotation,
};

const PROFILE: &str = "hierarchy-server-5.00.test-v1";
const ORIGIN: &str = "safe:server:origin";
const TARGET: &str = "safe:server:target";

fn record(phase: &str, disposition: &str, terminal: bool, time: &str) -> String {
    format!(
        r#"<![LOG[SYNTHETIC FIXTURE; Phase={phase}; Disposition={disposition}; Terminal={terminal}; MessageId=msg-001; LinkId=link-001; OriginSite=LAB; TargetSite=CHD; ProfileId={PROFILE}]LOG]!><time="{time}" date="7-30-2026" component="SYNTHETIC" context="" type="1" thread="1" file="fixture.cpp">"#
    )
}

fn artifact(
    artifact_id: &str,
    source_id: &str,
    basename: &str,
    direction: SccmHierarchyDirection,
    host: &str,
    coverage: SccmCoverageState,
    content: impl Into<String>,
) -> SccmHierarchyArtifact {
    SccmHierarchyArtifact {
        artifact: SccmArtifact {
            artifact_id: artifact_id.to_owned(),
            display_name: basename.to_owned(),
            original_path: None,
            host: Some(host.to_owned()),
            role: SccmRole::SiteServer,
            configmgr_version: Some("5.00.TEST.0001".to_owned()),
            collected_at_utc: Some("2026-07-30T19:00:00Z".to_owned()),
            rotation: SccmRotation::Current,
            coverage,
            encoding: Some("utf-8".to_owned()),
        },
        source_id: source_id.to_owned(),
        direction,
        producer_host_handle: host.to_owned(),
        rotation_lineage_id: format!("lineage-{artifact_id}"),
        fragment_complete: true,
        content: content.into(),
    }
}

fn topology() -> SccmHierarchyTopology {
    SccmHierarchyTopology {
        origin_site_code: "LAB".to_owned(),
        target_site_code: "CHD".to_owned(),
        origin_host_handle: ORIGIN.to_owned(),
        target_host_handle: TARGET.to_owned(),
    }
}

fn bundle(artifacts: Vec<SccmHierarchyArtifact>) -> SccmHierarchyBundle {
    SccmHierarchyBundle {
        profile_id: PROFILE.to_owned(),
        source_version: "5.00.TEST.0001".to_owned(),
        topology: topology(),
        artifacts,
    }
}

fn healthy_artifacts() -> Vec<SccmHierarchyArtifact> {
    vec![
        artifact(
            "01-replmgr",
            "server-hierarchy-control",
            "replmgr.log",
            SccmHierarchyDirection::Origin,
            ORIGIN,
            SccmCoverageState::Captured,
            format!(
                "{}\n{}",
                record("initiate", "succeeded", false, "15:03:00.000+000"),
                record("queueOrSerialize", "succeeded", false, "15:03:01.000+000")
            ),
        ),
        artifact(
            "02-sender",
            "server-hierarchy-transfer",
            "sender.log",
            SccmHierarchyDirection::Origin,
            ORIGIN,
            SccmCoverageState::Captured,
            record("send", "succeeded", false, "15:03:02.000+000"),
        ),
        artifact(
            "03-despool",
            "server-hierarchy-transfer",
            "despool.log",
            SccmHierarchyDirection::Target,
            TARGET,
            SccmCoverageState::Captured,
            format!(
                "{}\n{}",
                record("receive", "succeeded", false, "15:03:03.000+000"),
                record("process", "succeeded", false, "15:03:04.000+000")
            ),
        ),
        artifact(
            "04-rcmctrl",
            "server-hierarchy-control",
            "rcmctrl.log",
            SccmHierarchyDirection::Target,
            TARGET,
            SccmCoverageState::Captured,
            format!(
                "{}\n{}",
                record("acknowledge", "succeeded", false, "15:03:05.000+000"),
                record("healthyOrTerminal", "succeeded", true, "15:03:06.000+000")
            ),
        ),
    ]
}

#[test]
fn healthy_link_is_exact_and_causally_ordered() {
    let result = analyze_hierarchy_replication(&bundle(healthy_artifacts())).unwrap();
    let transaction = &result.transactions[0];

    assert_eq!(result.transactions.len(), 1);
    assert_eq!(transaction.state, SccmHierarchyState::Succeeded);
    assert_eq!(
        transaction.classification,
        SccmHierarchyClassification::Success
    );
    assert_eq!(transaction.confidence, SccmHierarchyConfidence::High);
    assert_eq!(
        transaction.timestamp_ordering,
        SccmHierarchyTimestampOrdering::Usable
    );
    assert_eq!(transaction.observations.len(), 7);
    assert!(transaction.observations.iter().all(|observation| matches!(
        observation.phase,
        SccmHierarchyPhase::Initiate
            | SccmHierarchyPhase::QueueOrSerialize
            | SccmHierarchyPhase::Send
            | SccmHierarchyPhase::Receive
            | SccmHierarchyPhase::Process
            | SccmHierarchyPhase::Acknowledge
            | SccmHierarchyPhase::HealthyOrTerminal
    )));
}

#[test]
fn missing_remote_artifact_is_incomplete_coverage() {
    let mut artifacts = healthy_artifacts();
    artifacts.retain(|artifact| artifact.artifact.display_name != "despool.log");
    artifacts.push(artifact(
        "03-despool-missing",
        "server-hierarchy-transfer",
        "despool.log",
        SccmHierarchyDirection::Target,
        TARGET,
        SccmCoverageState::Absent,
        "",
    ));

    let result = analyze_hierarchy_replication(&bundle(artifacts)).unwrap();
    let transaction = &result.transactions[0];
    assert_eq!(transaction.state, SccmHierarchyState::Incomplete);
    assert_eq!(
        transaction.classification,
        SccmHierarchyClassification::InsufficientEvidence
    );
    assert_eq!(
        transaction.coverage_gap_artifact_ids,
        vec!["03-despool-missing"]
    );
    assert_eq!(
        result
            .coverage
            .iter()
            .find(|item| item.artifact_id == "03-despool-missing")
            .unwrap()
            .state,
        cmtraceopen_parser::sccm::SccmHierarchyCoverageState::Absent
    );
}

#[test]
fn unknown_offset_downgrades_cross_host_causality() {
    let mut artifacts = healthy_artifacts();
    artifacts[2].content = record("receive", "succeeded", false, "15:03:03.000");
    let result = analyze_hierarchy_replication(&bundle(artifacts)).unwrap();
    let transaction = &result.transactions[0];

    assert_eq!(
        transaction.timestamp_ordering,
        SccmHierarchyTimestampOrdering::Unknown
    );
    assert_eq!(transaction.state, SccmHierarchyState::Incomplete);
    assert_eq!(transaction.confidence, SccmHierarchyConfidence::Low);
}

#[test]
fn contradictory_observations_are_retained_without_a_failure_claim() {
    let mut artifacts = healthy_artifacts();
    artifacts[1].content = format!(
        "{}\n{}",
        record("send", "succeeded", false, "15:03:02.000+000"),
        record("send", "failed", true, "15:03:02.500+000")
    );
    let result = analyze_hierarchy_replication(&bundle(artifacts)).unwrap();
    let transaction = &result.transactions[0];

    assert_eq!(transaction.state, SccmHierarchyState::Contradictory);
    assert_eq!(
        transaction.classification,
        SccmHierarchyClassification::ContradictoryEvidence
    );
    assert_eq!(transaction.observations.len(), 8);
}

#[test]
fn topology_mismatch_cannot_create_a_transaction() {
    let mut artifacts = healthy_artifacts();
    for artifact in &mut artifacts {
        artifact.producer_host_handle = "safe:server:unrelated".to_owned();
    }
    let result = analyze_hierarchy_replication(&bundle(artifacts)).unwrap();

    assert!(result.transactions.is_empty());
    assert_eq!(
        result.topology_mismatch_artifact_ids,
        vec!["01-replmgr", "02-sender", "03-despool", "04-rcmctrl"]
    );
}

#[test]
fn artifact_order_does_not_change_public_output() {
    let mut reversed = healthy_artifacts();
    reversed.reverse();
    let first =
        serde_json::to_vec(&analyze_hierarchy_replication(&bundle(healthy_artifacts())).unwrap())
            .unwrap();
    let second =
        serde_json::to_vec(&analyze_hierarchy_replication(&bundle(reversed)).unwrap()).unwrap();
    assert_eq!(first, second);
    let output = String::from_utf8(first).unwrap();
    assert!(!output.contains(ORIGIN));
    assert!(!output.contains(TARGET));
}

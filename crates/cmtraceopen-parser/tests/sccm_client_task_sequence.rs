use cmtraceopen_parser::sccm::{
    analyze_client_task_sequence, normalize_ccm_artifact, SccmArtifact, SccmCorrelationKeyKind,
    SccmCoverageState, SccmRole, SccmRotation, SccmTaskSequenceFragment, SccmTaskSequencePathClass,
};

fn artifact(
    id: &str,
    display_name: &str,
    version: Option<&str>,
    rotation: SccmRotation,
) -> SccmArtifact {
    SccmArtifact {
        artifact_id: id.to_owned(),
        display_name: display_name.to_owned(),
        original_path: Some(format!("SYNTHETIC://{id}/{display_name}")),
        host: None,
        role: SccmRole::Client,
        configmgr_version: version.map(str::to_owned),
        collected_at_utc: Some("2026-07-30T01:10:00Z".to_owned()),
        rotation,
        coverage: SccmCoverageState::Captured,
        encoding: Some("utf-8".to_owned()),
    }
}

fn fragment(
    id: &str,
    path_class: SccmTaskSequencePathClass,
    relocation_ordinal: u32,
    execution_id: &str,
    phase: &str,
) -> SccmTaskSequenceFragment {
    let artifact = artifact(
        id,
        "smsts.log",
        Some("5.00.TEST.0000"),
        SccmRotation::Current,
    );
    let content = format!(
        "<![LOG[SYNTHETIC phase={phase} state=succeeded terminal=false executionId={execution_id} taskSequencePackageId=LAB00324 advertisementId=LAB20324 runContext=osd]LOG]!><time=\"01:10:{relocation_ordinal:02}.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:1\">"
    );
    SccmTaskSequenceFragment::new(
        artifact,
        path_class,
        relocation_ordinal,
        normalize_ccm_artifact(
            artifact_for_content(id, "smsts.log", SccmRotation::Current),
            &content,
        ),
    )
}

fn artifact_for_content(id: &str, display_name: &str, rotation: SccmRotation) -> SccmArtifact {
    artifact(id, display_name, Some("5.00.TEST.0000"), rotation)
}

#[test]
fn source_and_execution_identity_groups_relocated_fragments_deterministically() {
    let execution_id = "72400000-0000-0000-0000-000000000324";
    let fragments = vec![
        fragment(
            "ts-client",
            SccmTaskSequencePathClass::Client,
            3,
            execution_id,
            "complete",
        ),
        fragment(
            "ts-winpe",
            SccmTaskSequencePathClass::WinPe,
            0,
            execution_id,
            "preflight",
        ),
        fragment(
            "ts-full-os",
            SccmTaskSequencePathClass::FullOs,
            2,
            execution_id,
            "setupWindows",
        ),
        fragment(
            "ts-setup",
            SccmTaskSequencePathClass::Setup,
            1,
            execution_id,
            "diskOrImage",
        ),
    ];

    let result = analyze_client_task_sequence(&fragments);

    assert_eq!(result.transactions.len(), 1);
    assert_eq!(result.transactions[0].keys.len(), 1);
    assert_eq!(
        result.transactions[0].keys[0].kind,
        SccmCorrelationKeyKind::TaskSequenceExecutionId
    );
    assert_eq!(result.transactions[0].evidence.len(), 4);
    assert_eq!(
        result.transactions[0]
            .path_sequence
            .iter()
            .map(|path| path.path_class.clone())
            .collect::<Vec<_>>(),
        vec![
            SccmTaskSequencePathClass::WinPe,
            SccmTaskSequencePathClass::Setup,
            SccmTaskSequencePathClass::FullOs,
            SccmTaskSequencePathClass::Client,
        ]
    );
}

#[test]
fn same_time_different_execution_ids_never_join() {
    let a = fragment(
        "ts-a",
        SccmTaskSequencePathClass::Client,
        0,
        "72400000-0000-0000-0000-000000000001",
        "complete",
    );
    let b = fragment(
        "ts-b",
        SccmTaskSequencePathClass::Client,
        0,
        "72400000-0000-0000-0000-000000000002",
        "complete",
    );

    let result = analyze_client_task_sequence(&[a, b]);

    assert_eq!(result.transactions.len(), 2);
    assert!(result
        .transactions
        .iter()
        .all(|transaction| transaction.evidence.len() == 1));
}

#[test]
fn rotated_fragments_cannot_authorize_an_execution_key() {
    let rotated = artifact(
        "ts-rotated",
        "smsts.lo_",
        Some("5.00.TEST.0000"),
        SccmRotation::LoUnderscore,
    );
    let content = "<![LOG[executionId=72400000-0000-0000-0000-000000000324 taskSequencePackageId=LAB00324 advertisementId=LAB20324 runContext=osd]LOG]!><time=\"01:10:00.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:1\">";
    let fragment = SccmTaskSequenceFragment::new(
        rotated.clone(),
        SccmTaskSequencePathClass::WinPe,
        0,
        normalize_ccm_artifact(rotated, content),
    );

    let result = analyze_client_task_sequence(&[fragment]);

    assert!(result.transactions.is_empty());
    assert_eq!(result.unlinked_fragments.len(), 1);
}

#[test]
fn rotated_fragment_joins_only_after_current_identity_is_proven() {
    let execution_id = "72400000-0000-0000-0000-000000000325";
    let current = fragment(
        "ts-current",
        SccmTaskSequencePathClass::Client,
        1,
        execution_id,
        "complete",
    );
    let rotated_artifact = artifact(
        "ts-rotated",
        "smsts.lo_",
        Some("5.00.TEST.0000"),
        SccmRotation::LoUnderscore,
    );
    let rotated_content = format!(
        "<![LOG[executionId={execution_id} taskSequencePackageId=LAB00324 advertisementId=LAB20324 runContext=osd]LOG]!><time=\"01:10:00.000+000\" date=\"07-30-2026\" component=\"TSManager\" context=\"\" type=\"0\" thread=\"1\" file=\"synthetic.ts:1\">"
    );
    let rotated = SccmTaskSequenceFragment::new(
        rotated_artifact.clone(),
        SccmTaskSequencePathClass::WinPe,
        0,
        normalize_ccm_artifact(rotated_artifact, &rotated_content),
    );

    let result = analyze_client_task_sequence(&[current, rotated]);

    assert_eq!(result.transactions.len(), 1);
    assert_eq!(result.transactions[0].evidence.len(), 2);
    assert!(result.unlinked_fragments.is_empty());
}

#[test]
fn unknown_version_does_not_authorize_an_execution_key() {
    let known = fragment(
        "ts-unknown-version",
        SccmTaskSequencePathClass::Client,
        0,
        "72400000-0000-0000-0000-000000000326",
        "complete",
    );
    let unknown = SccmTaskSequenceFragment {
        artifact: artifact(
            "ts-unknown-version",
            "smsts.log",
            Some("5.00.UNKNOWN.0000"),
            SccmRotation::Current,
        ),
        ..known
    };

    let result = analyze_client_task_sequence(&[unknown]);

    assert!(result.transactions.is_empty());
    assert_eq!(result.unlinked_fragments.len(), 1);
}

#[test]
fn absent_candidate_is_coverage_not_no_run_claim() {
    let artifact = SccmArtifact::missing(
        "ts-absent",
        "smsts.log",
        SccmRole::Client,
        SccmCoverageState::Absent,
    );
    let fragment =
        SccmTaskSequenceFragment::new(artifact, SccmTaskSequencePathClass::Unknown, 0, Vec::new());

    let result = analyze_client_task_sequence(&[fragment]);

    assert!(result.transactions.is_empty());
    assert_eq!(result.coverage_gaps.len(), 1);
    assert_eq!(result.coverage_gaps[0].coverage, SccmCoverageState::Absent);
}

use cmtraceopen_parser::sccm::{
    admit_management_sources, normalize_ccm_artifact, resolve_management_ownership, SccmArtifact,
    SccmConfidence, SccmCoverageState, SccmManagementExtractionProfile, SccmManagementOwnership,
    SccmManagementSourceState, SccmManagementWorkload, SccmRole, SccmRotation,
};

fn artifact(
    id: &str,
    name: &str,
    version: Option<&str>,
    coverage: SccmCoverageState,
) -> SccmArtifact {
    SccmArtifact {
        artifact_id: id.to_owned(),
        display_name: name.to_owned(),
        original_path: None,
        host: None,
        role: SccmRole::Client,
        configmgr_version: version.map(str::to_owned),
        collected_at_utc: Some("2026-07-31T00:00:00Z".to_owned()),
        rotation: SccmRotation::Current,
        coverage,
        encoding: Some("utf-8".to_owned()),
    }
}

fn co_management_evidence(
    artifact: &SccmArtifact,
    message: &str,
) -> cmtraceopen_parser::sccm::SccmEvidence {
    normalize_ccm_artifact(artifact.clone(), &format!(
        "<![LOG[SYNTHETIC FIXTURE {message}]LOG]!><time=\"10:00:00.000+000\" date=\"07-31-2026\" component=\"CoManagementHandler\" context=\"\" type=\"1\" thread=\"326\" file=\"\">"
    ))
    .into_iter()
    .next()
    .expect("synthetic ownership record parses")
}

#[test]
fn capability_and_ownership_admit_only_profile_validated_client_sources() {
    let profile = SccmManagementExtractionProfile::synthetic_test();
    let artifacts = vec![
        artifact(
            "co",
            "CoManagementHandler.log",
            Some("5.00.TEST.3260"),
            SccmCoverageState::Captured,
        ),
        artifact(
            "scripts",
            "Scripts.log",
            Some("5.00.TEST.3260"),
            SccmCoverageState::Captured,
        ),
        artifact(
            "notify",
            "CcmNotificationAgent.log",
            Some("5.00.TEST.3260"),
            SccmCoverageState::Captured,
        ),
        artifact(
            "software",
            "SCClient_SYNTHETIC_1.log",
            Some("5.00.TEST.3260"),
            SccmCoverageState::Captured,
        ),
    ];

    let admissions = admit_management_sources(&profile, &artifacts).unwrap();
    assert_eq!(admissions[0].state, SccmManagementSourceState::Admitted);
    assert_eq!(admissions[1].state, SccmManagementSourceState::Admitted);
    assert_eq!(admissions[2].state, SccmManagementSourceState::Admitted);
    assert_eq!(
        admissions[3].state,
        SccmManagementSourceState::CandidateUnsupported
    );
}

#[test]
fn capability_and_ownership_classify_handoff_without_sccm_failure() {
    let profile = SccmManagementExtractionProfile::synthetic_test();
    let co = artifact(
        "co",
        "CoManagementHandler.log",
        Some("5.00.TEST.3260"),
        SccmCoverageState::Captured,
    );
    let evidence = co_management_evidence(
        &co,
        "Workload=Scripts Ownership=IntuneOwned OwnershipEpochId=OWN-326-INTUNE-1 Disposition=Handoff Terminal=true",
    );
    assert!(
        evidence.message.contains("Workload=Scripts"),
        "{}",
        evidence.message
    );

    let result = resolve_management_ownership(
        &profile,
        SccmManagementWorkload::Scripts,
        std::slice::from_ref(&co),
        &[evidence],
    )
    .unwrap();
    assert_eq!(result.classification, SccmManagementOwnership::IntuneOwned);
    assert_eq!(result.confidence, SccmConfidence::High);
    assert!(result.terminal_handoff);
    assert!(result.coverage_gap_artifact_ids.is_empty());
}

#[test]
fn capability_and_ownership_keeps_missing_and_transitioning_conservative() {
    let profile = SccmManagementExtractionProfile::synthetic_test();
    let missing = artifact(
        "missing",
        "CoManagementHandler.log",
        None,
        SccmCoverageState::Absent,
    );
    let missing_result = resolve_management_ownership(
        &profile,
        SccmManagementWorkload::Scripts,
        std::slice::from_ref(&missing),
        &[],
    )
    .unwrap();
    assert_eq!(
        missing_result.classification,
        SccmManagementOwnership::UnknownOwnership
    );
    assert_eq!(missing_result.confidence, SccmConfidence::Low);
    assert_eq!(missing_result.coverage_gap_artifact_ids, vec!["missing"]);

    let transitioning = artifact(
        "transition",
        "CoManagementHandler.log",
        Some("5.00.TEST.3260"),
        SccmCoverageState::Captured,
    );
    let evidence = co_management_evidence(
        &transitioning,
        "Workload=Scripts Ownership=SharedOrTransitioning OwnershipEpochId=OWN-326-TRANSITION-1 Disposition=Transitioning Terminal=false",
    );
    let transitioning_result = resolve_management_ownership(
        &profile,
        SccmManagementWorkload::Scripts,
        std::slice::from_ref(&transitioning),
        &[evidence],
    )
    .unwrap();
    assert_eq!(
        transitioning_result.classification,
        SccmManagementOwnership::SharedOrTransitioning
    );
    assert_eq!(transitioning_result.confidence, SccmConfidence::Moderate);
    assert!(!transitioning_result.terminal_handoff);
}

#[test]
fn capability_and_ownership_rejects_unknown_profile_and_wrong_version() {
    let mut profile = SccmManagementExtractionProfile::synthetic_test();
    profile.id = "sccm-client-management-unknown-v1".to_owned();
    let co = artifact(
        "co",
        "CoManagementHandler.log",
        Some("5.00.TEST.3260"),
        SccmCoverageState::Captured,
    );
    assert!(admit_management_sources(&profile, &[co]).is_err());

    let profile = SccmManagementExtractionProfile::synthetic_test();
    let unsupported = artifact(
        "co",
        "CoManagementHandler.log",
        Some("5.00.9999.1"),
        SccmCoverageState::Captured,
    );
    let admissions = admit_management_sources(&profile, &[unsupported]).unwrap();
    assert_eq!(
        admissions[0].state,
        SccmManagementSourceState::CandidateUnsupported
    );

    let malformed_version = artifact(
        "co",
        "CoManagementHandler.log",
        Some("5.00.TEST.BAD"),
        SccmCoverageState::Captured,
    );
    let admissions = admit_management_sources(&profile, &[malformed_version]).unwrap();
    assert_eq!(
        admissions[0].state,
        SccmManagementSourceState::CandidateUnsupported
    );
}

use cmtraceopen_parser::models::log_entry::ParserKind;
use cmtraceopen_parser::parser::detect::detect_parser;
use cmtraceopen_parser::sccm::{
    classify_artifact_name, SccmArtifact, SccmArtifactFamily, SccmCoverageState, SccmFindingClass,
    SccmRole, SccmRotation, SCCM_DIAGNOSTICS_SCHEMA_VERSION,
};

#[test]
fn sccm_contract_is_public_and_versioned() {
    assert_eq!(SCCM_DIAGNOSTICS_SCHEMA_VERSION, 1);
    let artifact = SccmArtifact::missing(
        "client-policy-agent",
        "PolicyAgent.log",
        SccmRole::Client,
        SccmCoverageState::Absent,
    );
    assert_eq!(artifact.coverage, SccmCoverageState::Absent);
    assert_eq!(
        SccmFindingClass::InsufficientEvidence.as_str(),
        "insufficientEvidence"
    );
}

#[test]
fn artifact_round_trip_preserves_capture_and_rotation_provenance() {
    let artifact = SccmArtifact {
        artifact_id: "client-content-transfer".into(),
        display_name: "ContentTransferManager.log.2".into(),
        original_path: Some(r"C:\Windows\CCM\Logs\ContentTransferManager.log.2".into()),
        host: Some("LAB-CLIENT-01".into()),
        role: SccmRole::Client,
        configmgr_version: Some("5.00.9128.1007".into()),
        collected_at_utc: Some("2026-07-30T15:00:00Z".into()),
        rotation: SccmRotation::Numbered(2),
        coverage: SccmCoverageState::Captured,
        encoding: Some("utf-8".into()),
    };

    let json = serde_json::to_value(&artifact).unwrap();
    assert_eq!(json["rotation"]["kind"], "numbered");
    assert_eq!(json["rotation"]["value"], 2);
    assert_eq!(json["coverage"], "captured");
    assert_eq!(
        serde_json::from_value::<SccmArtifact>(json).unwrap(),
        artifact
    );
}

#[test]
fn coverage_states_are_distinct_and_never_deserialize_as_captured() {
    for state in [
        SccmCoverageState::Absent,
        SccmCoverageState::AccessDenied,
        SccmCoverageState::Capped,
        SccmCoverageState::Skipped,
        SccmCoverageState::Unsupported,
        SccmCoverageState::ParseFailed,
    ] {
        assert_ne!(state, SccmCoverageState::Captured);

        let json = serde_json::to_value(&state).unwrap();
        let round_trip: SccmCoverageState = serde_json::from_value(json).unwrap();
        assert_eq!(round_trip, state);
        assert_ne!(round_trip, SccmCoverageState::Captured);
    }
}

#[test]
fn artifact_manifest_fixture_preserves_each_coverage_state() {
    let artifacts: Vec<SccmArtifact> =
        serde_json::from_str(include_str!("fixtures/sccm/spine/artifact-manifest.json")).unwrap();

    assert_eq!(artifacts.len(), 4);
    assert_eq!(artifacts[0].rotation, SccmRotation::Current);
    assert_eq!(artifacts[1].rotation, SccmRotation::Numbered(2));
    assert_eq!(
        artifacts
            .iter()
            .map(|artifact| artifact.coverage.clone())
            .collect::<Vec<_>>(),
        vec![
            SccmCoverageState::Captured,
            SccmCoverageState::Captured,
            SccmCoverageState::Absent,
            SccmCoverageState::AccessDenied,
        ]
    );
    assert_eq!(
        artifacts[0].original_path.as_deref(),
        Some(r"C:\Windows\CCM\Logs\PolicyAgent.log")
    );
    assert_eq!(artifacts[3].encoding, None);
}

#[test]
fn catalog_classifies_client_policy_without_changing_ccm_parser_kind() {
    let class = classify_artifact_name("PolicyAgent.log", SccmRole::Client);
    assert_eq!(class.family, SccmArtifactFamily::ClientPolicy);
    assert_eq!(class.logical_name, "policyAgent");
    assert!(class.uses_ccm_records);

    let ccm = r#"<![LOG[Synthetic policy record]LOG]!><time="10:00:00.000-240" date="07-30-2026" component="PolicyAgent" context="" type="1" thread="42" file="policyagent.cpp">"#;
    assert_eq!(
        detect_parser("PolicyAgent.log", ccm).parser,
        ParserKind::Ccm
    );
}

#[test]
fn catalog_recognizes_rotated_client_log_by_base_name() {
    let class = classify_artifact_name("AppEnforce.log.3", SccmRole::Client);
    assert_eq!(class.family, SccmArtifactFamily::ClientApplication);
    assert_eq!(class.rotation, SccmRotation::Numbered(3));
}

#[test]
fn catalog_leaves_unrecognized_sources_explicitly_unknown() {
    let class = classify_artifact_name("CustomVendorHook.log", SccmRole::Client);
    assert_eq!(
        class.family,
        SccmArtifactFamily::Unknown("customVendorHook".into())
    );
    assert!(!class.supported_for_diagnosis);
}

#[test]
fn catalog_recognizes_every_declared_initial_source_for_its_role() {
    let declared = [
        ("CCMSetup.log", SccmRole::Client),
        ("CcmEval.log", SccmRole::Client),
        ("CcmExec.log", SccmRole::Client),
        ("CcmRestart.log", SccmRole::Client),
        ("ClientIDManagerStartup.log", SccmRole::Client),
        ("ClientLocation.log", SccmRole::Client),
        ("LocationServices.log", SccmRole::Client),
        ("CcmMessaging.log", SccmRole::Client),
        ("PolicyAgent.log", SccmRole::Client),
        ("PolicyAgentProvider.log", SccmRole::Client),
        ("PolicyEvaluator.log", SccmRole::Client),
        ("Scheduler.log", SccmRole::Client),
        ("CAS.log", SccmRole::Client),
        ("ContentTransferManager.log", SccmRole::Client),
        ("DataTransferService.log", SccmRole::Client),
        ("AppIntentEval.log", SccmRole::Client),
        ("AppDiscovery.log", SccmRole::Client),
        ("AppEnforce.log", SccmRole::Client),
        ("ScanAgent.log", SccmRole::Client),
        ("WUAHandler.log", SccmRole::Client),
        ("UpdatesDeployment.log", SccmRole::Client),
        ("UpdatesHandler.log", SccmRole::Client),
        ("UpdatesStore.log", SccmRole::Client),
        ("smsts.log", SccmRole::Client),
        ("sitecomp.log", SccmRole::SiteServer),
        ("hman.log", SccmRole::SiteServer),
        ("statmgr.log", SccmRole::SiteServer),
        ("statesys.log", SccmRole::SiteServer),
        ("MP_CliReg.log", SccmRole::ManagementPoint),
        ("MP_GetAuth.log", SccmRole::ManagementPoint),
        ("MP_GetPolicy.log", SccmRole::ManagementPoint),
        ("MP_Location.log", SccmRole::ManagementPoint),
        ("MP_RegistrationManager.log", SccmRole::ManagementPoint),
        ("mpcontrol.log", SccmRole::ManagementPoint),
        ("distmgr.log", SccmRole::SiteServer),
        ("PkgXferMgr.log", SccmRole::SiteServer),
        ("SMSDPProv.log", SccmRole::DistributionPoint),
        ("PullDP.log", SccmRole::DistributionPoint),
        ("WCM.log", SccmRole::SoftwareUpdatePoint),
        ("WSUSCtrl.log", SccmRole::SoftwareUpdatePoint),
        ("wsyncmgr.log", SccmRole::SoftwareUpdatePoint),
        ("SUPSetup.log", SccmRole::SoftwareUpdatePoint),
        ("replmgr.log", SccmRole::SiteServer),
        ("rcmctrl.log", SccmRole::SiteServer),
        ("sender.log", SccmRole::SiteServer),
        ("despool.log", SccmRole::SiteServer),
        ("Smsprov.log", SccmRole::Provider),
        ("AdminService.log", SccmRole::Provider),
    ];

    for (name, role) in declared {
        let class = classify_artifact_name(name, role.clone());
        assert_eq!(class.role, role, "role changed for {name}");
        assert!(
            !matches!(class.family, SccmArtifactFamily::Unknown(_)),
            "{name} was not catalogued"
        );
        assert!(class.uses_ccm_records, "{name} lost CCM framing");
        assert!(class.supported_for_diagnosis, "{name} became unsupported");
    }
}

#[test]
fn catalog_requires_a_declared_role_and_rotation_shape() {
    let wrong_role = classify_artifact_name("PolicyAgent.log", SccmRole::SiteServer);
    assert!(matches!(wrong_role.family, SccmArtifactFamily::Unknown(_)));
    assert!(!wrong_role.supported_for_diagnosis);

    let rotated = classify_artifact_name("AppEnforce.lo_", SccmRole::Client);
    assert_eq!(rotated.family, SccmArtifactFamily::ClientApplication);
    assert_eq!(rotated.rotation, SccmRotation::LoUnderscore);

    let backup = classify_artifact_name("PolicyAgent.log.backup", SccmRole::Client);
    assert!(matches!(backup.family, SccmArtifactFamily::Unknown(_)));
    assert!(!backup.supported_for_diagnosis);
}

use cmtraceopen_parser::models::log_entry::ParserKind;
use cmtraceopen_parser::parser::detect::detect_parser;
use cmtraceopen_parser::sccm::{
    classify_artifact_name, declared_source_catalog, SccmArtifact, SccmArtifactFamily,
    SccmCoverageState, SccmFindingClass, SccmRole, SccmRotation, SccmUnknownRotation,
    SCCM_DIAGNOSTICS_SCHEMA_VERSION,
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
fn serde_roles_are_string_backed_and_future_tolerant() {
    assert_eq!(
        serde_json::to_string(&SccmRole::ManagementPoint).unwrap(),
        r#""managementPoint""#
    );
    assert_eq!(
        serde_json::to_string(&SccmRole::Unknown("futureEdgeRole".into())).unwrap(),
        r#""futureEdgeRole""#
    );
    assert_eq!(
        serde_json::from_str::<SccmRole>(r#""futureEdgeRole""#).unwrap(),
        SccmRole::Unknown("futureEdgeRole".into())
    );

    let admin_service = serde_json::from_str::<SccmRole>(r#""adminService""#).unwrap();
    assert_eq!(
        serde_json::to_string(&admin_service).unwrap(),
        r#""adminService""#
    );
}

#[test]
fn serde_families_are_string_backed_and_future_tolerant() {
    assert_eq!(
        serde_json::to_string(&SccmArtifactFamily::ClientPolicy).unwrap(),
        r#""clientPolicy""#
    );
    assert_eq!(
        serde_json::to_string(&SccmArtifactFamily::Unknown("futureFamily".into())).unwrap(),
        r#""futureFamily""#
    );
    assert_eq!(
        serde_json::from_str::<SccmArtifactFamily>(r#""futureFamily""#).unwrap(),
        SccmArtifactFamily::Unknown("futureFamily".into())
    );
}

#[test]
fn serde_rotations_have_exact_tags_and_preserve_future_values() {
    let known = [
        (SccmRotation::Current, r#"{"kind":"current"}"#),
        (SccmRotation::LoUnderscore, r#"{"kind":"loUnderscore"}"#),
        (
            SccmRotation::Numbered(3),
            r#"{"kind":"numbered","value":3}"#,
        ),
        (
            SccmRotation::Timestamped("20260730-150000".into()),
            r#"{"kind":"timestamped","value":"20260730-150000"}"#,
        ),
    ];

    for (rotation, expected) in known {
        assert_eq!(serde_json::to_string(&rotation).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<SccmRotation>(expected).unwrap(),
            rotation
        );
    }

    let future = r#"{"kind":"vendorArchive","value":{"lineage":"A7","sequence":4}}"#;
    let rotation = serde_json::from_str::<SccmRotation>(future).unwrap();
    let unknown: &SccmUnknownRotation = match &rotation {
        SccmRotation::Unknown(unknown) => unknown,
        other => panic!("future rotation did not remain unknown: {other:?}"),
    };
    assert_eq!(unknown.kind, "vendorArchive");
    assert_eq!(
        unknown.value,
        Some(serde_json::json!({"lineage": "A7", "sequence": 4}))
    );
    assert_eq!(serde_json::to_string(&rotation).unwrap(), future);

    let valueless_future = r#"{"kind":"vendorArchiveWithoutValue"}"#;
    let rotation = serde_json::from_str::<SccmRotation>(valueless_future).unwrap();
    assert_eq!(serde_json::to_string(&rotation).unwrap(), valueless_future);
}

#[test]
fn serde_known_rotation_tags_reject_malformed_shapes() {
    for malformed in [
        r#"{"kind":"current","value":null}"#,
        r#"{"kind":"loUnderscore","value":"unexpected"}"#,
        r#"{"kind":"numbered"}"#,
        r#"{"kind":"numbered","value":-1}"#,
        r#"{"kind":"numbered","value":4294967296}"#,
        r#"{"kind":"timestamped"}"#,
        r#"{"kind":"timestamped","value":3}"#,
        r#"{"kind":"current","unexpected":true}"#,
    ] {
        assert!(
            serde_json::from_str::<SccmRotation>(malformed).is_err(),
            "accepted malformed known rotation: {malformed}"
        );
    }
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
fn coverage_json_names_are_exact_and_never_collapse_to_captured() {
    for (state, expected) in [
        (SccmCoverageState::Captured, r#""captured""#),
        (SccmCoverageState::Absent, r#""absent""#),
        (SccmCoverageState::AccessDenied, r#""accessDenied""#),
        (SccmCoverageState::Capped, r#""capped""#),
        (SccmCoverageState::Skipped, r#""skipped""#),
        (SccmCoverageState::Unsupported, r#""unsupported""#),
        (SccmCoverageState::ParseFailed, r#""parseFailed""#),
    ] {
        assert_eq!(serde_json::to_string(&state).unwrap(), expected);
        let round_trip = serde_json::from_str::<SccmCoverageState>(expected).unwrap();
        assert_eq!(round_trip, state);
        if expected != r#""captured""# {
            assert_ne!(round_trip, SccmCoverageState::Captured);
        }
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
fn catalog_exact_declared_tuples_match_the_public_classifier() {
    let expected = expected_catalog_tuples();
    let declared = declared_source_catalog();
    assert_eq!(declared.len(), expected.len());

    for (entry, expected) in declared.iter().zip(expected.iter()) {
        assert_eq!(entry.basename, expected.0);
        assert_eq!(entry.role, expected.1);
        assert_eq!(entry.logical_name, expected.2);
        assert_eq!(entry.family, expected.3);
        assert_eq!(entry.uses_ccm_records, expected.4);
        assert_eq!(entry.supported_for_diagnosis, expected.5);
        assert_eq!(entry.rotation, SccmRotation::Current);

        let classified = classify_artifact_name(expected.0, expected.1.clone());
        assert_eq!(classified, *entry);
    }
}

#[test]
fn catalog_declared_basename_role_tuples_are_unique() {
    let mut keys = std::collections::BTreeSet::new();
    for entry in declared_source_catalog() {
        let role = serde_json::to_string(&entry.role).unwrap();
        assert!(
            keys.insert((entry.basename.to_ascii_lowercase(), role)),
            "duplicate catalog tuple: {} / {:?}",
            entry.basename,
            entry.role
        );
    }
}

#[test]
fn catalog_rejects_every_role_not_declared_by_the_exact_table() {
    let expected = expected_catalog_tuples();
    let basenames = expected
        .iter()
        .map(|entry| entry.0)
        .collect::<std::collections::BTreeSet<_>>();

    for basename in basenames {
        let allowed_roles = expected
            .iter()
            .filter(|entry| entry.0 == basename)
            .map(|entry| &entry.1)
            .collect::<Vec<_>>();
        for role in known_roles() {
            if allowed_roles.contains(&&role) {
                continue;
            }

            let class = classify_artifact_name(basename, role.clone());
            assert_eq!(class.role, role, "{basename}");
            assert!(
                matches!(class.family, SccmArtifactFamily::Unknown(_)),
                "{basename} accepted undeclared role {:?}",
                class.role
            );
            assert!(!class.supported_for_diagnosis, "{basename}");
        }
    }
}

#[test]
fn catalog_rotation_grammar_accepts_only_canonical_suffixes() {
    let canonical = [
        ("AppEnforce.log", SccmRotation::Current),
        ("AppEnforce.log.lo_", SccmRotation::LoUnderscore),
        ("AppEnforce.LOG.LO_", SccmRotation::LoUnderscore),
        ("AppEnforce.log.3", SccmRotation::Numbered(3)),
        (
            "AppEnforce.log.20260730-150000",
            SccmRotation::Timestamped("20260730-150000".into()),
        ),
    ];
    for (name, expected_rotation) in canonical {
        let class = classify_artifact_name(name, SccmRole::Client);
        assert_eq!(
            class.family,
            SccmArtifactFamily::ClientApplication,
            "{name}"
        );
        assert_eq!(class.rotation, expected_rotation, "{name}");
        assert!(class.uses_ccm_records, "{name}");
        assert!(class.supported_for_diagnosis, "{name}");
    }

    let rejected = [
        ("AppEnforce.lo_", ".lo_"),
        ("AppEnforce.log.0", ".0"),
        ("AppEnforce.log.03", ".03"),
        ("AppEnforce.log.backup", ".backup"),
        ("AppEnforce.log.20261340-996099", ".20261340-996099"),
    ];
    for (name, raw_suffix) in rejected {
        let class = classify_artifact_name(name, SccmRole::Client);
        assert_eq!(
            class.family,
            SccmArtifactFamily::ClientApplication,
            "{name}"
        );
        assert_eq!(class.logical_name, "appEnforce", "{name}");
        assert_eq!(
            serde_json::to_value(&class.rotation).unwrap(),
            serde_json::json!({"kind": "filenameSuffix", "value": raw_suffix}),
            "{name}"
        );
        assert!(class.uses_ccm_records, "{name}");
        assert!(!class.supported_for_diagnosis, "{name}");
    }
}

#[test]
fn catalog_rotation_grammar_preserves_unknown_suffix_and_initialism() {
    let class = classify_artifact_name("SMSVendorHook.log.archive", SccmRole::Client);
    assert_eq!(class.logical_name, "smsVendorHook");
    assert_eq!(
        class.family,
        SccmArtifactFamily::Unknown("smsVendorHook".into())
    );
    assert_eq!(
        serde_json::to_value(&class.rotation).unwrap(),
        serde_json::json!({"kind": "filenameSuffix", "value": ".archive"})
    );
    assert!(!class.uses_ccm_records);
    assert!(!class.supported_for_diagnosis);
}

#[test]
fn catalog_role_matrix_preserves_supplied_dp_and_sup_roles() {
    let dp_sources = [
        "distmgr.log",
        "PkgXferMgr.log",
        "SMSDPProv.log",
        "PullDP.log",
    ];
    let dp_roles = [SccmRole::SiteServer, SccmRole::DistributionPoint];
    assert_role_matrix(
        &dp_sources,
        &dp_roles,
        SccmArtifactFamily::DistributionPoint,
    );

    let sup_sources = ["WCM.log", "WSUSCtrl.log", "wsyncmgr.log", "SUPSetup.log"];
    let sup_roles = [SccmRole::SoftwareUpdatePoint, SccmRole::WsUs];
    assert_role_matrix(
        &sup_sources,
        &sup_roles,
        SccmArtifactFamily::SoftwareUpdatePoint,
    );
}

#[test]
fn catalog_role_matrix_keeps_admin_service_distinct_from_provider() {
    let admin = classify_artifact_name("AdminService.log", SccmRole::AdminService);
    assert_eq!(admin.role, SccmRole::AdminService);
    assert_eq!(admin.family, SccmArtifactFamily::AdminService);
    assert!(admin.supported_for_diagnosis);

    let provider = classify_artifact_name("AdminService.log", SccmRole::Provider);
    assert_eq!(provider.role, SccmRole::Provider);
    assert!(matches!(provider.family, SccmArtifactFamily::Unknown(_)));
    assert!(!provider.supported_for_diagnosis);
}

fn assert_role_matrix(
    sources: &[&str],
    allowed_roles: &[SccmRole],
    expected_family: SccmArtifactFamily,
) {
    for source in sources {
        for role in &known_roles() {
            let class = classify_artifact_name(source, role.clone());
            if allowed_roles.contains(role) {
                assert_eq!(class.role, *role, "{source}");
                assert_eq!(class.family, expected_family, "{source} / {role:?}");
                assert!(class.uses_ccm_records, "{source} / {role:?}");
                assert!(class.supported_for_diagnosis, "{source} / {role:?}");
            } else {
                assert_eq!(class.role, *role, "{source}");
                assert!(
                    matches!(class.family, SccmArtifactFamily::Unknown(_)),
                    "{source} / {role:?}"
                );
                assert!(!class.supported_for_diagnosis, "{source} / {role:?}");
            }
        }
    }
}

fn known_roles() -> [SccmRole; 8] {
    [
        SccmRole::Client,
        SccmRole::SiteServer,
        SccmRole::ManagementPoint,
        SccmRole::DistributionPoint,
        SccmRole::SoftwareUpdatePoint,
        SccmRole::WsUs,
        SccmRole::Provider,
        SccmRole::AdminService,
    ]
}

type ExpectedCatalogTuple = (
    &'static str,
    SccmRole,
    &'static str,
    SccmArtifactFamily,
    bool,
    bool,
);

fn expected_catalog_tuples() -> Vec<ExpectedCatalogTuple> {
    vec![
        (
            "CCMSetup.log",
            SccmRole::Client,
            "ccmSetup",
            SccmArtifactFamily::ClientSetup,
            true,
            true,
        ),
        (
            "CcmEval.log",
            SccmRole::Client,
            "ccmEval",
            SccmArtifactFamily::ClientHealth,
            true,
            true,
        ),
        (
            "CcmExec.log",
            SccmRole::Client,
            "ccmExec",
            SccmArtifactFamily::ClientHealth,
            true,
            true,
        ),
        (
            "CcmRestart.log",
            SccmRole::Client,
            "ccmRestart",
            SccmArtifactFamily::ClientHealth,
            true,
            true,
        ),
        (
            "ClientIDManagerStartup.log",
            SccmRole::Client,
            "clientIdManagerStartup",
            SccmArtifactFamily::ClientIdentity,
            true,
            true,
        ),
        (
            "ClientLocation.log",
            SccmRole::Client,
            "clientLocation",
            SccmArtifactFamily::ClientLocation,
            true,
            true,
        ),
        (
            "LocationServices.log",
            SccmRole::Client,
            "locationServices",
            SccmArtifactFamily::ClientLocation,
            true,
            true,
        ),
        (
            "CcmMessaging.log",
            SccmRole::Client,
            "ccmMessaging",
            SccmArtifactFamily::ClientLocation,
            true,
            true,
        ),
        (
            "PolicyAgent.log",
            SccmRole::Client,
            "policyAgent",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "PolicyAgentProvider.log",
            SccmRole::Client,
            "policyAgentProvider",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "PolicyEvaluator.log",
            SccmRole::Client,
            "policyEvaluator",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "Scheduler.log",
            SccmRole::Client,
            "scheduler",
            SccmArtifactFamily::ClientPolicy,
            true,
            true,
        ),
        (
            "CAS.log",
            SccmRole::Client,
            "cas",
            SccmArtifactFamily::ClientContent,
            true,
            true,
        ),
        (
            "ContentTransferManager.log",
            SccmRole::Client,
            "contentTransferManager",
            SccmArtifactFamily::ClientContent,
            true,
            true,
        ),
        (
            "DataTransferService.log",
            SccmRole::Client,
            "dataTransferService",
            SccmArtifactFamily::ClientContent,
            true,
            true,
        ),
        (
            "AppIntentEval.log",
            SccmRole::Client,
            "appIntentEval",
            SccmArtifactFamily::ClientApplication,
            true,
            true,
        ),
        (
            "AppDiscovery.log",
            SccmRole::Client,
            "appDiscovery",
            SccmArtifactFamily::ClientApplication,
            true,
            true,
        ),
        (
            "AppEnforce.log",
            SccmRole::Client,
            "appEnforce",
            SccmArtifactFamily::ClientApplication,
            true,
            true,
        ),
        (
            "ScanAgent.log",
            SccmRole::Client,
            "scanAgent",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "WUAHandler.log",
            SccmRole::Client,
            "wuaHandler",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "UpdatesDeployment.log",
            SccmRole::Client,
            "updatesDeployment",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "UpdatesHandler.log",
            SccmRole::Client,
            "updatesHandler",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "UpdatesStore.log",
            SccmRole::Client,
            "updatesStore",
            SccmArtifactFamily::ClientUpdates,
            true,
            true,
        ),
        (
            "smsts.log",
            SccmRole::Client,
            "smsts",
            SccmArtifactFamily::ClientTaskSequence,
            true,
            true,
        ),
        (
            "sitecomp.log",
            SccmRole::SiteServer,
            "sitecomp",
            SccmArtifactFamily::SiteComponent,
            true,
            true,
        ),
        (
            "hman.log",
            SccmRole::SiteServer,
            "hman",
            SccmArtifactFamily::SiteComponent,
            true,
            true,
        ),
        (
            "statmgr.log",
            SccmRole::SiteServer,
            "statmgr",
            SccmArtifactFamily::SiteStatus,
            true,
            true,
        ),
        (
            "statesys.log",
            SccmRole::SiteServer,
            "statesys",
            SccmArtifactFamily::SiteStatus,
            true,
            true,
        ),
        (
            "MP_CliReg.log",
            SccmRole::ManagementPoint,
            "mpCliReg",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_GetAuth.log",
            SccmRole::ManagementPoint,
            "mpGetAuth",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_GetPolicy.log",
            SccmRole::ManagementPoint,
            "mpGetPolicy",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_Location.log",
            SccmRole::ManagementPoint,
            "mpLocation",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "MP_RegistrationManager.log",
            SccmRole::ManagementPoint,
            "mpRegistrationManager",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "mpcontrol.log",
            SccmRole::ManagementPoint,
            "mpcontrol",
            SccmArtifactFamily::ManagementPoint,
            true,
            true,
        ),
        (
            "distmgr.log",
            SccmRole::SiteServer,
            "distmgr",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "distmgr.log",
            SccmRole::DistributionPoint,
            "distmgr",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "PkgXferMgr.log",
            SccmRole::SiteServer,
            "pkgXferMgr",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "PkgXferMgr.log",
            SccmRole::DistributionPoint,
            "pkgXferMgr",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "SMSDPProv.log",
            SccmRole::DistributionPoint,
            "smsDpProv",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "SMSDPProv.log",
            SccmRole::SiteServer,
            "smsDpProv",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "PullDP.log",
            SccmRole::DistributionPoint,
            "pullDp",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "PullDP.log",
            SccmRole::SiteServer,
            "pullDp",
            SccmArtifactFamily::DistributionPoint,
            true,
            true,
        ),
        (
            "WCM.log",
            SccmRole::SoftwareUpdatePoint,
            "wcm",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "WCM.log",
            SccmRole::WsUs,
            "wcm",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "WSUSCtrl.log",
            SccmRole::SoftwareUpdatePoint,
            "wsusCtrl",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "WSUSCtrl.log",
            SccmRole::WsUs,
            "wsusCtrl",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "wsyncmgr.log",
            SccmRole::SoftwareUpdatePoint,
            "wsyncmgr",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "wsyncmgr.log",
            SccmRole::WsUs,
            "wsyncmgr",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "SUPSetup.log",
            SccmRole::SoftwareUpdatePoint,
            "supSetup",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "SUPSetup.log",
            SccmRole::WsUs,
            "supSetup",
            SccmArtifactFamily::SoftwareUpdatePoint,
            true,
            true,
        ),
        (
            "replmgr.log",
            SccmRole::SiteServer,
            "replmgr",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "rcmctrl.log",
            SccmRole::SiteServer,
            "rcmctrl",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "sender.log",
            SccmRole::SiteServer,
            "sender",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "despool.log",
            SccmRole::SiteServer,
            "despool",
            SccmArtifactFamily::Hierarchy,
            true,
            true,
        ),
        (
            "Smsprov.log",
            SccmRole::Provider,
            "smsprov",
            SccmArtifactFamily::Provider,
            true,
            true,
        ),
        (
            "AdminService.log",
            SccmRole::AdminService,
            "adminService",
            SccmArtifactFamily::AdminService,
            true,
            true,
        ),
    ]
}

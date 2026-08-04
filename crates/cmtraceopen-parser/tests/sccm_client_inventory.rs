use cmtraceopen_parser::sccm::{
    analyze_client_extended, SccmArtifact, SccmCoverageState, SccmEvidence, SccmEvidenceRef,
    SccmRole, SccmRotation, SccmTimeOrderingState, SccmTimestamp, SccmTransactionState,
    SccmWorkflow,
};

fn artifact(id: &str, name: &str, coverage: SccmCoverageState) -> SccmArtifact {
    SccmArtifact {
        artifact_id: id.to_owned(),
        display_name: name.to_owned(),
        original_path: None,
        host: Some("synthetic-host".to_owned()),
        role: SccmRole::Client,
        configmgr_version: Some("5.00.TEST.1".to_owned()),
        collected_at_utc: Some("2026-07-30T00:00:00Z".to_owned()),
        rotation: SccmRotation::Current,
        coverage,
        encoding: Some("utf-8".to_owned()),
    }
}

fn evidence(artifact_id: &str, id: &str, millis: i64, message: &str) -> SccmEvidence {
    SccmEvidence {
        evidence_id: id.to_owned(),
        reference: SccmEvidenceRef {
            artifact_id: artifact_id.to_owned(),
            entry_id: id.to_owned(),
            line_start: Some(1),
            line_end: Some(1),
        },
        role: SccmRole::Client,
        component: None,
        ccm_source_file: None,
        message: message.to_owned(),
        timestamp: SccmTimestamp {
            original_display: Some("00:00:00.000+000".to_owned()),
            offset_minutes: Some(0),
            utc_millis: Some(millis),
            ordering_state: SccmTimeOrderingState::NormalizedUtc,
        },
        execution_context: None,
    }
}

#[test]
fn separates_inventory_compliance_and_metering_transactions() {
    let artifacts = [
        artifact(
            "inventory",
            "InventoryAgentProvider.log",
            SccmCoverageState::Captured,
        ),
        artifact(
            "compliance",
            "DCMReporting.log",
            SccmCoverageState::Captured,
        ),
        artifact(
            "metering",
            "SWMTRReportGen.log",
            SccmCoverageState::Captured,
        ),
    ];
    let evidence = vec![
        evidence(
            "inventory",
            "inventory-report",
            1_000,
            "Family=inventory InventoryCycleId=INV-CYCLE-001 ResourceHandle=safe:resource:inventory-001 ReportId=INV-REPORT-001 Phase=Report Disposition=Succeeded Terminal=true",
        ),
        evidence(
            "compliance",
            "compliance-report",
            1_000,
            "Family=compliance CiId=CI-001 BaselineId=BASELINE-001 StateId=STATE-001 ResourceHandle=safe:resource:compliance-001 Phase=Report Disposition=Succeeded ResultType=Evaluation Terminal=true",
        ),
        evidence(
            "metering",
            "metering-report",
            1_000,
            "Family=metering MeteringCycleId=METER-CYCLE-001 RuleId=RULE-001 ReportId=METER-REPORT-001 ResourceHandle=safe:resource:metering-001 Phase=Report Disposition=Succeeded Terminal=true",
        ),
    ];

    let result = analyze_client_extended(&artifacts, &evidence);

    assert_eq!(result.transactions.len(), 3);
    assert_eq!(
        result
            .transactions
            .iter()
            .map(|transaction| transaction.workflow)
            .collect::<Vec<_>>(),
        vec![
            SccmWorkflow::Inventory,
            SccmWorkflow::Compliance,
            SccmWorkflow::Metering
        ]
    );
    assert!(result
        .transactions
        .iter()
        .all(|transaction| transaction.state == SccmTransactionState::Succeeded));
    assert!(result
        .transactions
        .iter()
        .all(|transaction| transaction.keys.len() >= 3));
}

#[test]
fn joins_recovery_only_with_the_same_complete_key_tuple_and_ordering() {
    let artifacts = vec![artifact(
        "inventory",
        "InventoryAgentProvider.log",
        SccmCoverageState::Captured,
    )];
    let evidence = vec![
        evidence(
            "inventory",
            "failed",
            1_000,
            "InventoryCycleId=INV-CYCLE-002 ResourceHandle=safe:resource:inventory-002 ReportId=INV-REPORT-002 Phase=Report Disposition=Failed Terminal=true",
        ),
        evidence(
            "inventory",
            "recovered",
            2_000,
            "InventoryCycleId=INV-CYCLE-002 ResourceHandle=safe:resource:inventory-002 ReportId=INV-REPORT-002 Phase=Report Disposition=Succeeded Terminal=true",
        ),
        evidence(
            "inventory",
            "contradictory",
            2_000,
            "InventoryCycleId=INV-CYCLE-003 ResourceHandle=safe:resource:inventory-003 ReportId=INV-REPORT-003 Phase=Report Disposition=Failed Terminal=true",
        ),
        evidence(
            "inventory",
            "contradictory-success",
            2_000,
            "InventoryCycleId=INV-CYCLE-003 ResourceHandle=safe:resource:inventory-003 ReportId=INV-REPORT-003 Phase=Report Disposition=Succeeded Terminal=true",
        ),
    ];

    let result = analyze_client_extended(&artifacts, &evidence);

    assert_eq!(result.transactions.len(), 2);
    assert_eq!(
        result.transactions[0].state,
        SccmTransactionState::Recovered
    );
    assert_eq!(
        result.transactions[1].state,
        SccmTransactionState::Contradictory
    );
}

#[test]
fn keeps_missing_sources_versions_and_keys_as_explicit_gaps() {
    let artifacts = [
        artifact("absent", "CIAgent.log", SccmCoverageState::Absent),
        artifact(
            "unknown-version",
            "SWMTRReportGen.log",
            SccmCoverageState::Captured,
        ),
        artifact(
            "malformed",
            "InventoryAgent.log",
            SccmCoverageState::Captured,
        ),
    ];
    let mut unknown_version = artifacts[1].clone();
    unknown_version.configmgr_version = Some("6.00.0.0".to_owned());
    let artifacts = [artifacts[0].clone(), unknown_version, artifacts[2].clone()];
    let evidence = vec![evidence(
        "malformed",
        "missing-key",
        1_000,
        "InventoryCycleId=INV-CYCLE-004 Phase=Collect Disposition=Succeeded Terminal=false",
    )];

    let result = analyze_client_extended(&artifacts, &evidence);

    assert!(result.transactions.is_empty());
    assert_eq!(result.coverage.len(), 2);
    assert_eq!(result.coverage[0].state, SccmCoverageState::Absent);
    assert_eq!(result.coverage[1].state, SccmCoverageState::Captured);
    assert_eq!(result.source_local_observations.len(), 1);
}

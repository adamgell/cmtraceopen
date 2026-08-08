//! Reducer Framework v1, Store pilot Phase 2: semantic RED tests (issue #358).
//!
//! Each test in this file asserts the *contract* behavior decided by the
//! Reducer Framework v1 governance slice, not the current behavior of the
//! merged Store reducer:
//!
//! * plan: `docs/superpowers/plans/2026-08-07-reducer-framework-v1.md`
//!   (PR 2 / Phase 2);
//! * inventory: `docs/architecture/reducer-framework-v1-store-inventory.md`;
//! * contracts: `docs/architecture/decisions/ADR-001` through `ADR-004`.
//!
//! Tests that fail against the current reducer are marked `#[ignore]` so CI
//! stays green while recording the real defect; the verbatim failure output is
//! preserved in each test's doc comment. Production behavior is intentionally
//! unchanged in this phase. The fixes land in Store pilot Phase 3, which
//! removes the `#[ignore]` markers.
//!
//! Inputs are built through the module's public API exactly the way a native
//! collector would supply them: typed payloads inside `StoreSourceArtifact`,
//! with observation contexts constructed by the test.

use cmtraceopen_parser::intune::apps::windows::microsoft_store::{
    analyze_store_bundle, parse_error_code, StoreArtifactPayload, StoreAssignment,
    StoreAssignmentIntent, StoreDeploymentAction, StoreExecutionContext, StoreInstallerFamily,
    StoreInstallerOutcome, StorePackageFact, StorePackageIdentity, StoreSourceArtifact,
    StoreTransactionState,
};
use cmtraceopen_parser::intune::evidence::{
    IntuneAccessState, IntuneArtifactStatus, IntuneEvidenceRef, IntuneNamedValue,
    IntuneObservationContext, IntuneParseState, IntuneProvenance, IntuneSensitivity,
    IntuneSourceKind,
};
use cmtraceopen_parser::intune::normalized::{NormalizedEventLevel, NormalizedWindowsEvent};

const PRODUCT_ID: &str = "9WZSYNTH0001";
const APP_ID: &str = "11111111-2222-4333-8444-555555555555";
const PACKAGE_FAMILY: &str = "Contoso.SynthApp_9abcdef01234h";

fn context(
    artifact: &str,
    record: u64,
    source_kind: IntuneSourceKind,
) -> IntuneObservationContext {
    IntuneObservationContext {
        evidence_ref: IntuneEvidenceRef {
            evidence_id: format!("{artifact}:{record}"),
            source_artifact_id: artifact.to_owned(),
        },
        provenance: IntuneProvenance {
            source_kind,
            source_artifact_id: artifact.to_owned(),
            file_path: None,
            line_number: None,
            record_number: Some(record),
            registry: None,
            event: None,
        },
        source_timestamp: None,
        observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
        sensitivity: IntuneSensitivity::Public,
        parse_state: IntuneParseState::Parsed,
        access_state: IntuneAccessState::Available,
    }
}

fn artifact(
    id: &str,
    family: &str,
    source_kind: IntuneSourceKind,
    payload: StoreArtifactPayload,
) -> StoreSourceArtifact {
    StoreSourceArtifact {
        artifact_id: id.to_owned(),
        family: family.to_owned(),
        source_kind,
        status: IntuneArtifactStatus::Available,
        detail: None,
        observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
        file_name: None,
        file_path: None,
        payload: Some(payload),
    }
}

fn product_identity() -> StorePackageIdentity {
    StorePackageIdentity {
        store_product_id: Some(PRODUCT_ID.to_owned()),
        ..StorePackageIdentity::default()
    }
}

fn named(pairs: &[(&str, &str)]) -> Vec<IntuneNamedValue> {
    pairs
        .iter()
        .map(|(name, value)| IntuneNamedValue {
            name: (*name).to_owned(),
            value: (*value).to_owned(),
        })
        .collect()
}

/// An AppX deployment event whose evidence id and record id belong to the
/// event itself, so permuting the containing vector permutes only the caller
/// supplied order and nothing about the evidence.
fn appx_event(
    artifact_id: &str,
    record: u64,
    event_id: u32,
    level: NormalizedEventLevel,
    named_data: &[(&str, &str)],
) -> NormalizedWindowsEvent {
    NormalizedWindowsEvent {
        context: context(artifact_id, record, IntuneSourceKind::EventLog),
        channel: "Microsoft-Windows-AppXDeploymentServer/Operational".to_owned(),
        provider: "Microsoft-Windows-AppXDeployment-Server".to_owned(),
        event_id,
        level,
        task: None,
        keywords: None,
        record_id: Some(record),
        activity_id: None,
        event_version: None,
        named_data: named(named_data),
        message: None,
    }
}

// == Cluster 1: typed intent authority ======================================
//
// Contract: a typed `StoreAssignment` stating `Required` is the authoritative
// statement of Intune's intent. Caller-writable `named_data` on package or
// installer observations is raw metadata; per the Framework v1 design
// ("arbitrary named_data does not become authoritative intent") and ADR-001
// (confidence and authority are not interchangeable; untyped data is not
// authoritative), it must not override the typed intent, and it certainly must
// not flip the transaction into `NotTargeted`.

/// RED recording (2026-08-08, current reducer at the Phase 2 branch point):
///
/// ```text
/// thread 'typed_required_intent_survives_caller_writable_named_data' panicked at crates/cmtraceopen-parser/tests/intune_windows_microsoft_store_semantics.rs:193:5:
/// assertion `left == right` failed: ADR-001/design contract: typed assignment intent is authoritative; caller-writable named_data must not override it
///   left: NotTargeted
///  right: Required
/// ```
///
/// Root cause under test: `reduce_group` re-reads `IntuneIntent` from every
/// member observation's `named_data`, and the caller-supplied pair on the
/// package fact arrives after the typed assignment's own entry, so the last
/// writer wins and the forced `NotTargeted` state override fires.
#[test]
fn typed_required_intent_survives_caller_writable_named_data() {
    let assignment = StoreAssignment {
        context: context("assignment", 1, IntuneSourceKind::SuppliedFact),
        app_id: Some(APP_ID.to_owned()),
        identity: product_identity(),
        intent: StoreAssignmentIntent::Required,
        target_context: StoreExecutionContext::User,
        named_data: Vec::new(),
    };
    // Same package, reported absent by inventory. Its caller-writable
    // named_data claims the app is not targeted; nothing typed says so.
    let fact = StorePackageFact {
        context: context("inventory", 1, IntuneSourceKind::SuppliedFact),
        identity: product_identity(),
        installer_family: StoreInstallerFamily::UwpUserContext,
        execution_context: StoreExecutionContext::User,
        installed: false,
        provisioned: None,
        named_data: named(&[("IntuneIntent", "notTargeted")]),
    };

    let analysis = analyze_store_bundle(&[
        artifact(
            "assignment",
            "assignments",
            IntuneSourceKind::SuppliedFact,
            StoreArtifactPayload::Assignments {
                assignments: vec![assignment],
            },
        ),
        artifact(
            "inventory",
            "inventory",
            IntuneSourceKind::SuppliedFact,
            StoreArtifactPayload::PackageFacts { facts: vec![fact] },
        ),
    ]);

    assert_eq!(analysis.transactions.len(), 1, "one package, one transaction");
    let transaction = &analysis.transactions[0];
    assert_eq!(
        transaction.intent,
        StoreAssignmentIntent::Required,
        "ADR-001/design contract: typed assignment intent is authoritative; \
         caller-writable named_data must not override it"
    );
    assert_ne!(
        transaction.state,
        StoreTransactionState::NotTargeted,
        "a transaction with a typed Required assignment must not be reported \
         as NotTargeted on the strength of untyped metadata"
    );
}

// == Cluster 2: input order and chronology ==================================
//
// Contract (ADR-003): caller vector order is an acquisition detail, not
// chronology, unless the source contract explicitly defines it as evidence.
// Reducing the same set of observations must give the same answer regardless
// of the order the artifacts were supplied in. Contradictory equal-ranked
// terminal evidence must resolve by evidence (or stay conservative), never by
// which record the caller happened to list last.

/// RED recording (2026-08-08, current reducer at the Phase 2 branch point):
///
/// ```text
/// thread 'equivalent_input_permutation_does_not_change_the_reduction' panicked at crates/cmtraceopen-parser/tests/intune_windows_microsoft_store_semantics.rs:278:5:
/// assertion `left == right` failed: ADR-003 contract: permuting non-ordered input must not change the reduced state
///   left: InstallCompleted
///  right: RegistrationFailure
/// ```
///
/// Root cause under test: `state_rank` resolves equal-ranked candidates with
/// `>=` over members iterated in input order, so whichever terminal record the
/// caller supplied last silently wins the transaction state (and its error).
#[test]
fn equivalent_input_permutation_does_not_change_the_reduction() {
    // Two equal-ranked terminal statements about the same per-user
    // registration. Neither event carries a source timestamp here, and the
    // events keep their own record ids, so reversing the vector changes only
    // the caller-supplied order and no evidence at all.
    let failed = appx_event(
        "appx",
        1,
        404,
        NormalizedEventLevel::Error,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
            ("ErrorCode", "0x80073CF9"),
        ],
    );
    let completed = appx_event(
        "appx",
        2,
        603,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );

    let forward = analyze_store_bundle(&[artifact(
        "appx",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents {
            events: vec![failed.clone(), completed.clone()],
        },
    )]);
    let reversed = analyze_store_bundle(&[artifact(
        "appx",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents {
            events: vec![completed, failed],
        },
    )]);

    assert_eq!(forward.transactions.len(), 1);
    assert_eq!(reversed.transactions.len(), 1);
    assert_eq!(
        forward.transactions[0].state, reversed.transactions[0].state,
        "ADR-003 contract: permuting non-ordered input must not change the \
         reduced state"
    );
    assert_eq!(
        forward.transactions[0].error, reversed.transactions[0].error,
        "ADR-003 contract: permuting non-ordered input must not change the \
         reported error"
    );
}

// == Cluster 3: identity and correlation ====================================
//
// Contract (ADR-002 and the inventory's identity cluster): sharing an Intune
// app id is an Intune-level linkage. Without compatible package/product
// identity it must not produce strong correlation, and evidence that never
// named a package must not drive a package-specific terminal outcome for a
// package it never mentioned.

/// RED recording (2026-08-08, current reducer at the Phase 2 branch point):
///
/// ```text
/// thread 'an_app_id_match_without_package_identity_cannot_drive_a_package_terminal_outcome' panicked at crates/cmtraceopen-parser/tests/intune_windows_microsoft_store_semantics.rs:354:5:
/// ADR-002 contract violated: a package-identity-free installer failure was correlated onto package 9WZSYNTH0001 through an app_id match alone and produced the package-specific terminal state InstallerFailure (confidence High)
/// ```
///
/// Root cause under test: `joinable` accepts an app_id-only match as a join,
/// so the identity-free installer outcome lands in the package's group and its
/// `Win32InstallerFailed` signal becomes the transaction's terminal state.
#[test]
fn an_app_id_match_without_package_identity_cannot_drive_a_package_terminal_outcome() {
    let assignment = StoreAssignment {
        context: context("assignment", 1, IntuneSourceKind::SuppliedFact),
        app_id: Some(APP_ID.to_owned()),
        identity: product_identity(),
        intent: StoreAssignmentIntent::Required,
        target_context: StoreExecutionContext::Unknown,
        named_data: Vec::new(),
    };
    // An installer failure that shares the Intune app id but names no package
    // at all: no product id, no family name, no full name.
    let outcome = StoreInstallerOutcome {
        context: context("installer-outcome", 1, IntuneSourceKind::SuppliedFact),
        app_id: Some(APP_ID.to_owned()),
        identity: StorePackageIdentity::default(),
        action: StoreDeploymentAction::Install,
        exit_code: Some(parse_error_code("0x80070643")),
        succeeded: Some(false),
        named_data: Vec::new(),
    };

    let analysis = analyze_store_bundle(&[
        artifact(
            "assignment",
            "assignments",
            IntuneSourceKind::SuppliedFact,
            StoreArtifactPayload::Assignments {
                assignments: vec![assignment],
            },
        ),
        artifact(
            "installer-outcome",
            "installerOutcomes",
            IntuneSourceKind::SuppliedFact,
            StoreArtifactPayload::InstallerOutcomes {
                outcomes: vec![outcome],
            },
        ),
    ]);

    let false_story = analysis.transactions.iter().find(|transaction| {
        transaction.identity.store_product_id.as_deref() == Some(PRODUCT_ID)
            && transaction.state == StoreTransactionState::InstallerFailure
    });
    assert!(
        false_story.is_none(),
        "ADR-002 contract violated: a package-identity-free installer failure \
         was correlated onto package {PRODUCT_ID} through an app_id match alone \
         and produced the package-specific terminal state {:?} (confidence {:?})",
        false_story.map(|transaction| transaction.state).unwrap(),
        false_story
            .map(|transaction| transaction.confidence.clone())
            .unwrap(),
    );
}

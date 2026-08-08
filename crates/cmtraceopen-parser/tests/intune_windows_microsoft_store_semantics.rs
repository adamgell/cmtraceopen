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
//! Phase 2 recorded the three confirmed defects as `#[ignore]`d RED tests with
//! their verbatim failure output. Phase 3 (this branch) fixed the reducer,
//! removed the `#[ignore]` markers, and extended this file with the
//! adversarial pilot: targeted, active coverage for the remaining inventory
//! clusters — terminal precedence and retries, installer-family isolation,
//! source classification, evidence degradation, confidence propagation,
//! permutation/duplication/irrelevant-evidence invariants, and the
//! provisional redaction equality scope. The RED recordings are kept in the
//! doc comments as the historical record of what the reducer used to do.
//!
//! Inputs are built through the module's public API exactly the way a native
//! collector would supply them: typed payloads inside `StoreSourceArtifact`,
//! with observation contexts constructed by the test.

use cmtraceopen_parser::intune::apps::windows::microsoft_store::{
    analyze_store_bundle, parse_error_code, redact_text, redacted_export_projection,
    StoreAnalysis, StoreArtifactPayload, StoreAssignment, StoreAssignmentIntent,
    StoreDeploymentAction, StoreExecutionContext, StoreInstallerFamily, StoreInstallerOutcome,
    StorePackageFact, StorePackageIdentity, StoreSourceArtifact, StoreTransactionState,
};
use cmtraceopen_parser::intune::evidence::{
    IntuneAccessState, IntuneArtifactStatus, IntuneEvidenceRef, IntuneFindingConfidence,
    IntuneNamedValue, IntuneObservationContext, IntuneParseState, IntuneProvenance,
    IntuneSensitivity, IntuneSourceKind,
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

// ═══ Adversarial pilot (Phase 3) ════════════════════════════════════════════
//
// Targeted, active coverage for the remaining inventory clusters, exercised
// over the fixed reducer through the same public API.

/// The order-independent conclusions of an analysis: one canonical line per
/// transaction, sorted. Transaction ids and presentation order deliberately
/// follow input order, so invariance is asserted over the conclusions, not
/// over the serialized vector.
fn conclusions(analysis: &StoreAnalysis) -> Vec<String> {
    let mut lines = analysis
        .transactions
        .iter()
        .map(|transaction| {
            format!(
                "tokens={:?} app={:?} family={:?} context={:?} state={:?} intent={:?} \
                 confidence={:?} error={:?}",
                transaction.identity.correlation_tokens(),
                transaction.app_id,
                transaction.installer_family,
                transaction.execution_context,
                transaction.state,
                transaction.intent,
                transaction.confidence,
                transaction
                    .error
                    .as_ref()
                    .map(|error| error.hex.clone().unwrap_or_else(|| error.raw.clone())),
            )
        })
        .collect::<Vec<_>>();
    lines.sort();
    lines
}

fn ime_artifact(id: &str, text: &str) -> StoreSourceArtifact {
    StoreSourceArtifact {
        artifact_id: id.to_owned(),
        family: "ime".to_owned(),
        source_kind: IntuneSourceKind::ImeLog,
        status: IntuneArtifactStatus::Available,
        detail: None,
        observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
        file_name: Some("IntuneManagementExtension.log".to_owned()),
        file_path: None,
        payload: Some(StoreArtifactPayload::ImeText {
            text: text.to_owned(),
        }),
    }
}

/// A CCM-framed IME record with a confirming component.
fn ccm_line(message: &str) -> String {
    format!(
        r#"<![LOG[{message}]LOG]!><time="10:15:22.100+000" date="7-31-2026" component="Win32App" context="" type="1" thread="12" file="store.cs:1">"#
    )
}

// == Cluster 4: terminal precedence and retries =============================
//
// Contract (ADR-003): a retry may transition failure into success only when
// the two records are explicitly ordered by the source's own sequencing —
// here, monotonic record numbers within the same event-log artifact. A
// success that cannot be ordered against the failure (a supplied inventory
// fact from another artifact) is ambiguous and must not overwrite it.

#[test]
fn an_explicitly_ordered_retry_success_replaces_the_earlier_failure() {
    let failed = appx_event(
        "appx",
        3,
        404,
        NormalizedEventLevel::Error,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
            ("ErrorCode", "0x80073CF9"),
        ],
    );
    let retried = appx_event(
        "appx",
        7,
        603,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );

    for events in [
        vec![failed.clone(), retried.clone()],
        vec![retried, failed],
    ] {
        let analysis = analyze_store_bundle(&[artifact(
            "appx",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents { events },
        )]);
        assert_eq!(analysis.transactions.len(), 1);
        assert_eq!(
            analysis.transactions[0].state,
            StoreTransactionState::InstallCompleted,
            "the later record of the same sequenced source is the explicit \
             retry linkage ADR-003 requires"
        );
        assert!(analysis.transactions[0].error.is_none());
    }
}

/// The mirror image: when the source order says the *failure* came last, the
/// failure stands, no matter how the caller arranged the vector.
#[test]
fn a_source_ordered_late_failure_is_not_hidden_by_an_earlier_success() {
    let completed = appx_event(
        "appx",
        3,
        603,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );
    let failed_later = appx_event(
        "appx",
        7,
        404,
        NormalizedEventLevel::Error,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
            ("ErrorCode", "0x80073CF9"),
        ],
    );

    for events in [
        vec![completed.clone(), failed_later.clone()],
        vec![failed_later, completed],
    ] {
        let analysis = analyze_store_bundle(&[artifact(
            "appx",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents { events },
        )]);
        assert_eq!(analysis.transactions.len(), 1);
        assert_eq!(
            analysis.transactions[0].state,
            StoreTransactionState::RegistrationFailure
        );
        assert_eq!(
            analysis.transactions[0]
                .error
                .as_ref()
                .and_then(|error| error.hex.as_deref()),
            Some("0x80073CF9")
        );
    }
}

/// An inventory fact saying "installed" cannot be ordered against a failure
/// event from another artifact: they share no counter and no clock. The
/// contradiction is unresolved, so the reduction must stay conservative
/// (`InsufficientEvidence`, the module's no-single-conclusion state) instead
/// of letting the ambiguous success overwrite the failure — or the failure
/// silently swallow the fact.
#[test]
fn an_unlinked_success_fact_does_not_overwrite_a_failure_event() {
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
    let installed_fact = StorePackageFact {
        context: context("inventory", 1, IntuneSourceKind::SuppliedFact),
        identity: StorePackageIdentity {
            package_family_name: Some(PACKAGE_FAMILY.to_owned()),
            ..StorePackageIdentity::default()
        },
        installer_family: StoreInstallerFamily::UwpUserContext,
        execution_context: StoreExecutionContext::User,
        installed: true,
        provisioned: None,
        named_data: Vec::new(),
    };

    let event_artifact = artifact(
        "appx",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents {
            events: vec![failed],
        },
    );
    let fact_artifact = artifact(
        "inventory",
        "inventory",
        IntuneSourceKind::SuppliedFact,
        StoreArtifactPayload::PackageFacts {
            facts: vec![installed_fact],
        },
    );

    let forward = analyze_store_bundle(&[event_artifact.clone(), fact_artifact.clone()]);
    let reversed = analyze_store_bundle(&[fact_artifact, event_artifact]);

    for analysis in [&forward, &reversed] {
        assert_eq!(analysis.transactions.len(), 1);
        let transaction = &analysis.transactions[0];
        assert_ne!(
            transaction.state,
            StoreTransactionState::InstallCompleted,
            "an unlinked success must not overwrite a failure (ADR-003)"
        );
        assert_eq!(
            transaction.state,
            StoreTransactionState::InsufficientEvidence,
            "an unresolved authoritative contradiction stays conservative"
        );
        assert_eq!(transaction.confidence, IntuneFindingConfidence::Low);
        assert_eq!(
            transaction.evidence.len(),
            2,
            "both contradicting records stay visible on the transaction"
        );
    }
    assert_eq!(conclusions(&forward), conclusions(&reversed));
}

// == Cluster 5: installer-family isolation ==================================
//
// Contract: AppX/UWP and Store-Win32 observations about the same product are
// different installer grammars and stay separate transactions, each with
// family-appropriate findings; neither failure may inherit the other's
// terminal semantics or remediation.

#[test]
fn mixed_appx_and_win32_observations_stay_separate_with_family_appropriate_findings() {
    let appx_failure = appx_event(
        "appx",
        1,
        404,
        NormalizedEventLevel::Error,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
            ("StoreProductId", PRODUCT_ID),
            ("ErrorCode", "0x80073CF9"),
        ],
    );
    let win32_failure = StoreInstallerOutcome {
        context: context("installer-outcome", 1, IntuneSourceKind::SuppliedFact),
        app_id: None,
        identity: product_identity(),
        action: StoreDeploymentAction::Install,
        exit_code: Some(parse_error_code("1603")),
        succeeded: Some(false),
        named_data: Vec::new(),
    };

    let analysis = analyze_store_bundle(&[
        artifact(
            "appx",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents {
                events: vec![appx_failure],
            },
        ),
        artifact(
            "installer-outcome",
            "installerOutcomes",
            IntuneSourceKind::SuppliedFact,
            StoreArtifactPayload::InstallerOutcomes {
                outcomes: vec![win32_failure],
            },
        ),
    ]);

    assert_eq!(
        analysis.transactions.len(),
        2,
        "two concrete installer families never merge, even over one product id"
    );
    let appx = analysis
        .transactions
        .iter()
        .find(|transaction| transaction.installer_family == StoreInstallerFamily::UwpUserContext)
        .expect("AppX transaction");
    let win32 = analysis
        .transactions
        .iter()
        .find(|transaction| transaction.installer_family == StoreInstallerFamily::StoreWin32)
        .expect("Win32 transaction");
    assert_eq!(appx.state, StoreTransactionState::RegistrationFailure);
    assert_eq!(win32.state, StoreTransactionState::InstallerFailure);

    let registration = analysis
        .findings
        .iter()
        .find(|finding| finding.finding_id == "store-registration-failed")
        .expect("AppX registration finding");
    let installer = analysis
        .findings
        .iter()
        .find(|finding| finding.finding_id == "store-win32-installer-failed")
        .expect("Win32 installer finding");
    assert!(
        registration
            .evidence
            .iter()
            .all(|reference| reference.source_artifact_id == "appx"),
        "the AppX finding must cite only AppX evidence"
    );
    assert!(
        installer
            .evidence
            .iter()
            .all(|reference| reference.source_artifact_id == "installer-outcome"),
        "the Win32 finding must cite only installer-native evidence"
    );
}

// == Cluster 6: source classification =======================================
//
// Contract: an approved provider name pasted next to an archive or otherwise
// decorated channel is not the OS channel. Such records never become Store
// evidence, so they cannot manufacture observations, transactions, or
// terminal outcomes. (Exact/prefix matching itself is pinned by unit tests in
// `sources.rs`.)

#[test]
fn an_archive_suffixed_channel_never_becomes_store_evidence() {
    let mut archived = appx_event(
        "archive",
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
    archived.channel = "Microsoft-Windows-AppXDeploymentServer-Archive/Operational".to_owned();

    let analysis = analyze_store_bundle(&[artifact(
        "archive",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents {
            events: vec![archived],
        },
    )]);

    assert!(
        analysis.transactions.is_empty(),
        "an unapproved channel must not drive any terminal outcome"
    );
    assert!(analysis.observations.is_empty());
    assert_eq!(
        analysis.coverage.len(),
        1,
        "the artifact stays declared as coverage"
    );
}

// == Cluster 7: evidence degradation ========================================
//
// Contract (inventory row 7): an unrecognized dialect and a known record
// contradicting its own level both degrade confidence, but for distinct,
// distinctly documented reasons — not one conflated flag.

#[test]
fn unknown_version_and_level_mismatch_degrade_for_distinct_documented_reasons() {
    // A recognized provider speaking an unknown dialect.
    let unknown_dialect = appx_event(
        "appx-unknown",
        1,
        9999,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );
    // A fully recognized failure id logged at Information level.
    let contradicting = appx_event(
        "appx-mismatch",
        1,
        404,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", "Fabrikam.OtherApp_8synthh0abcd3"),
            ("ErrorCode", "0x80073CF9"),
        ],
    );

    let analysis = analyze_store_bundle(&[
        artifact(
            "appx-unknown",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents {
                events: vec![unknown_dialect],
            },
        ),
        artifact(
            "appx-mismatch",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents {
                events: vec![contradicting],
            },
        ),
    ]);

    // Both transactions are degraded to Low confidence...
    for transaction in &analysis.transactions {
        assert_eq!(transaction.confidence, IntuneFindingConfidence::Low);
    }
    // ...but each for its own documented reason.
    let unknown = analysis
        .findings
        .iter()
        .find(|finding| finding.finding_id == "store-unknown-event-version")
        .expect("unknown-version finding");
    let mismatch = analysis
        .findings
        .iter()
        .find(|finding| finding.finding_id == "store-event-level-mismatch")
        .expect("level-mismatch finding");
    assert!(unknown
        .evidence
        .iter()
        .all(|reference| reference.source_artifact_id == "appx-unknown"));
    assert!(mismatch
        .evidence
        .iter()
        .all(|reference| reference.source_artifact_id == "appx-mismatch"));

    // The level was not promoted into evidence: the stated failure stands.
    let mismatched_transaction = analysis
        .transactions
        .iter()
        .find(|transaction| {
            transaction.identity.package_family_name.as_deref()
                == Some("Fabrikam.OtherApp_8synthh0abcd3")
        })
        .expect("mismatch transaction");
    assert_eq!(
        mismatched_transaction.state,
        StoreTransactionState::RegistrationFailure
    );
}

// == Cluster 8: confidence propagation ======================================
//
// Contract (ADR-001): repetition cannot promote weak evidence, and coverage
// gaps cannot raise confidence.

#[test]
fn duplicating_device_only_evidence_cannot_raise_confidence() {
    let completed = appx_event(
        "appx",
        1,
        603,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );
    let single = analyze_store_bundle(&[artifact(
        "appx",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents {
            events: vec![completed.clone()],
        },
    )]);
    // The same statement five more times, from a second copy of the artifact.
    let mut copy_events = Vec::new();
    for _ in 0..5 {
        copy_events.push(completed.clone());
    }
    let duplicated = analyze_store_bundle(&[
        artifact(
            "appx",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents {
                events: vec![completed.clone()],
            },
        ),
        artifact(
            "appx-copy",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents {
                events: copy_events,
            },
        ),
    ]);

    assert_eq!(
        single.transactions[0].confidence,
        IntuneFindingConfidence::Medium,
        "device evidence without Intune intent is capped below High"
    );
    assert_eq!(
        duplicated.transactions[0].confidence,
        single.transactions[0].confidence,
        "ADR-001: duplication cannot promote evidence"
    );
    assert_eq!(duplicated.transactions[0].state, single.transactions[0].state);
}

#[test]
fn duplicating_degraded_evidence_cannot_lift_the_degradation() {
    let unknown_dialect = appx_event(
        "appx",
        1,
        9999,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );
    let mut events = Vec::new();
    for _ in 0..6 {
        events.push(unknown_dialect.clone());
    }
    let analysis = analyze_store_bundle(&[artifact(
        "appx",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents { events },
    )]);
    assert_eq!(analysis.transactions.len(), 1);
    assert_eq!(
        analysis.transactions[0].confidence,
        IntuneFindingConfidence::Low,
        "six copies of an unassessable record are still unassessable"
    );
    assert_eq!(
        analysis.transactions[0].state,
        StoreTransactionState::InsufficientEvidence,
        "no terminal outcome from non-assessable evidence"
    );
}

#[test]
fn coverage_gaps_cannot_raise_confidence() {
    let completed = appx_event(
        "appx",
        1,
        603,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );
    let event_artifact = artifact(
        "appx",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents {
            events: vec![completed],
        },
    );
    let mut missing = artifact(
        "ime-log",
        "ime",
        IntuneSourceKind::ImeLog,
        StoreArtifactPayload::ImeText {
            text: String::new(),
        },
    );
    missing.status = IntuneArtifactStatus::Missing;
    missing.payload = None;

    let without_gap = analyze_store_bundle(std::slice::from_ref(&event_artifact));
    let with_gap = analyze_store_bundle(&[event_artifact, missing]);

    assert_eq!(
        with_gap.transactions[0].confidence,
        without_gap.transactions[0].confidence,
        "ADR-001: a coverage gap is a gap, not corroboration"
    );
    assert!(
        with_gap
            .findings
            .iter()
            .any(|finding| finding.finding_id == "store-evidence-coverage-gap"),
        "the gap itself is reported"
    );
}

// == Cluster 9: permutation, duplication, irrelevant evidence ===============
//
// Contract (ADR-002/ADR-003 executable invariants), over a realistic bundle:
// permuting artifacts changes nothing, duplicating an artifact changes no
// conclusion, and an unrelated package's evidence cannot alter another
// transaction.

fn realistic_bundle() -> Vec<StoreSourceArtifact> {
    let assignment = StoreAssignment {
        context: context("assignment", 1, IntuneSourceKind::SuppliedFact),
        app_id: Some(APP_ID.to_owned()),
        identity: StorePackageIdentity {
            store_product_id: Some(PRODUCT_ID.to_owned()),
            package_family_name: Some(PACKAGE_FAMILY.to_owned()),
            ..StorePackageIdentity::default()
        },
        intent: StoreAssignmentIntent::Required,
        target_context: StoreExecutionContext::User,
        named_data: Vec::new(),
    };
    let staged = appx_event(
        "appx",
        1,
        400,
        NormalizedEventLevel::Information,
        &[
            ("DeploymentOperation", "Stage"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", PACKAGE_FAMILY),
        ],
    );
    let registered = appx_event(
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
    let ime = ime_artifact(
        "ime-log",
        &format!(
            "{}\n{}\n",
            ccm_line(&format!(
                "Store app AppId={APP_ID} StoreProductId={PRODUCT_ID} is targeted for this device"
            )),
            ccm_line(&format!(
                "Requesting store acquisition for StoreProductId={PRODUCT_ID}"
            )),
        ),
    );
    vec![
        artifact(
            "assignment",
            "assignments",
            IntuneSourceKind::SuppliedFact,
            StoreArtifactPayload::Assignments {
                assignments: vec![assignment],
            },
        ),
        ime,
        artifact(
            "appx",
            "appxDeployment",
            IntuneSourceKind::EventLog,
            StoreArtifactPayload::WindowsEvents {
                events: vec![staged, registered],
            },
        ),
    ]
}

#[test]
fn permuting_a_realistic_bundle_changes_no_conclusion() {
    let bundle = realistic_bundle();
    let baseline = analyze_store_bundle(&bundle);
    assert_eq!(baseline.transactions.len(), 1);
    assert_eq!(
        baseline.transactions[0].state,
        StoreTransactionState::InstallCompleted
    );
    assert_eq!(
        baseline.transactions[0].confidence,
        IntuneFindingConfidence::High
    );

    let mut reversed = bundle.clone();
    reversed.reverse();
    let mut rotated = bundle.clone();
    rotated.rotate_left(1);
    for permutation in [reversed, rotated] {
        assert_eq!(
            conclusions(&analyze_store_bundle(&permutation)),
            conclusions(&baseline),
            "ADR-003: artifact order is an acquisition detail"
        );
    }
}

#[test]
fn duplicating_an_artifact_changes_no_conclusion() {
    let bundle = realistic_bundle();
    let baseline = analyze_store_bundle(&bundle);

    let mut duplicated = bundle.clone();
    let mut copy = bundle[2].clone();
    copy.artifact_id = "appx-copy".to_owned();
    duplicated.push(copy);

    assert_eq!(
        conclusions(&analyze_store_bundle(&duplicated)),
        conclusions(&baseline),
        "a re-collected copy of the same evidence adds nothing"
    );
}

#[test]
fn an_unrelated_packages_failure_cannot_alter_another_transaction() {
    let bundle = realistic_bundle();
    let baseline = analyze_store_bundle(&bundle);

    let unrelated_failure = appx_event(
        "appx-unrelated",
        1,
        404,
        NormalizedEventLevel::Error,
        &[
            ("DeploymentOperation", "Register"),
            ("DeploymentScope", "User"),
            ("PackageFamilyName", "Fabrikam.OtherApp_8synthh0abcd3"),
            ("ErrorCode", "0x80073CF9"),
        ],
    );
    let mut widened = bundle.clone();
    widened.push(artifact(
        "appx-unrelated",
        "appxDeployment",
        IntuneSourceKind::EventLog,
        StoreArtifactPayload::WindowsEvents {
            events: vec![unrelated_failure],
        },
    ));
    let widened_analysis = analyze_store_bundle(&widened);

    // The original transaction's conclusion line is still present, unchanged.
    let baseline_lines = conclusions(&baseline);
    let widened_lines = conclusions(&widened_analysis);
    for line in &baseline_lines {
        assert!(
            widened_lines.contains(line),
            "adding unrelated evidence altered an existing conclusion:\n\
             missing {line}\nfrom {widened_lines:?}"
        );
    }
    assert_eq!(
        widened_analysis.transactions.len(),
        2,
        "the unrelated failure is its own transaction, not a merge"
    );
}

// == Cluster 10: redaction scope (ADR-004, provisional) =====================
//
// ADR-004 accepts the architecture boundary but leaves the token/equality
// scope PROVISIONAL. These tests deliberately do not add or change any token
// API; they pin the behavior the current implementation actually has so that
// a future contract change is a visible, reviewed diff.
//
// Observed equality scope, as pinned below: the token is a pure function of
// the masked value alone. The same restricted value therefore yields the same
// token across observations, artifacts, findings, separate analyses, and
// separate exports — a *global* equality scope with no caller-controlled key.
// Per ADR-004 this global scope must not be relied on for cross-artifact,
// cross-session, or cross-export correlation; it is recorded here, not
// endorsed.

#[test]
fn same_scope_redaction_preserves_equality_and_distinct_values_stay_distinct() {
    let ime = ime_artifact(
        "ime-log",
        &format!(
            "{}\n{}\n{}\n",
            ccm_line(&format!(
                "Store app StoreProductId={PRODUCT_ID} is targeted for this device for synthetic.user@example.invalid"
            )),
            ccm_line(&format!(
                "Requesting store acquisition for StoreProductId={PRODUCT_ID} for synthetic.user@example.invalid"
            )),
            ccm_line(&format!(
                "Store app StoreProductId={PRODUCT_ID} is targeted for this device for other.user@example.invalid"
            )),
        ),
    );
    let analysis = analyze_store_bundle(&[ime]);
    let export = redacted_export_projection(&analysis);

    let same_token = redact_text("synthetic.user@example.invalid");
    let other_token = redact_text("other.user@example.invalid");
    assert_ne!(
        same_token, other_token,
        "different restricted values must not accidentally become equal"
    );

    let masked_messages = export
        .observations
        .iter()
        .filter_map(|observation| observation.message.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        masked_messages
            .iter()
            .filter(|message| message.contains(&same_token))
            .count(),
        2,
        "the same value masks to the same token in every record (same-scope \
         equality preserved): {masked_messages:?}"
    );
    assert_eq!(
        masked_messages
            .iter()
            .filter(|message| message.contains(&other_token))
            .count(),
        1
    );
}

#[test]
fn restricted_values_are_absent_from_the_redacted_export_including_findings() {
    let ime = ime_artifact(
        "ime-log",
        &format!(
            "{}\n",
            ccm_line(&format!(
                r"Store app StoreProductId={PRODUCT_ID} is targeted for synthetic.user@example.invalid payload C:\Users\Synthetic User\AppData\Local\Temp\pkg"
            )),
        ),
    );
    let analysis = analyze_store_bundle(&[ime]);
    let export = redacted_export_projection(&analysis);
    let serialized = serde_json::to_string(&export).expect("export serializes");

    for restricted in ["synthetic.user@example.invalid", "Synthetic User"] {
        assert!(
            !serialized.contains(restricted),
            "restricted value {restricted:?} leaked into the redacted export"
        );
    }
    let findings_only =
        serde_json::to_string(&export.findings).expect("findings serialize");
    assert!(!findings_only.contains("synthetic.user@example.invalid"));

    // The correlation grammar survives redaction.
    assert!(serialized.contains(PRODUCT_ID));
}

/// Redaction is a projection for export: it must not change any non-sensitive
/// reducer conclusion within the analysis (ADR-004).
#[test]
fn redaction_does_not_alter_reducer_conclusions() {
    let analysis = analyze_store_bundle(&realistic_bundle());
    let export = redacted_export_projection(&analysis);
    assert_eq!(export.transactions, analysis.transactions);
    assert_eq!(export.coverage, analysis.coverage);
    assert_eq!(conclusions(&export), conclusions(&analysis));
}

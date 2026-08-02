use app_lib::sccm::{
    discover_client_sources, SccmClientDiscoveryCoverageIssueState, SccmClientDiscoveryError,
    SccmClientDiscoveryInput, SccmClientDiscoveryObservation, SccmClientDiscoveryObservationState,
    SccmClientDiscoveryRotationCategory, SccmClientDiscoveryState,
    MAX_SCCM_CLIENT_DISCOVERY_COVERAGE_ISSUES, MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
    MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS,
};
use cmtraceopen_parser::sccm::{SccmRotation, SccmUnknownRotation};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ROOT_A: &str = "root-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ROOT_B: &str = "root-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn observation(
    root_handle: &str,
    basename: &str,
    rotation: SccmRotation,
    state: SccmClientDiscoveryObservationState,
) -> SccmClientDiscoveryObservation {
    SccmClientDiscoveryObservation {
        root_handle: root_handle.to_owned(),
        basename: basename.to_owned(),
        rotation,
        state,
    }
}

fn unsupported_rotation(suffix: &str) -> SccmRotation {
    SccmRotation::Unknown(SccmUnknownRotation {
        kind: "filenameSuffix".to_owned(),
        value: Some(Value::String(suffix.to_owned())),
    })
}

fn sha256(value: impl AsRef<[u8]>) -> String {
    Sha256::digest(value)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn path_fingerprint(root_handle: &str, canonical_basename: &str) -> String {
    let root_digest = root_handle
        .strip_prefix("root-")
        .expect("synthetic root handle has the required prefix");
    format!(
        "sha256:{}",
        sha256(format!(
            "cmtraceopen.sccm.source.v1\0{root_digest}\0{canonical_basename}"
        ))
    )
}

fn rotation_segment(rotation: &SccmRotation) -> String {
    match rotation {
        SccmRotation::Current => "current".to_owned(),
        SccmRotation::LoUnderscore => "lo".to_owned(),
        SccmRotation::Numbered(number) => format!("numbered-{number}"),
        SccmRotation::Timestamped(timestamp) => format!("timestamped-{timestamp}"),
        SccmRotation::Unknown(_) => panic!("synthetic observations use known rotations"),
    }
}

fn expected_physical_artifact_id(
    fingerprint: &str,
    rotation: &SccmRotation,
    basename: &str,
) -> String {
    format!(
        "sccm-artifact:v1:sha256:{}",
        sha256(format!(
            "artifact:v1:{fingerprint}:{}:{basename}",
            rotation_segment(rotation)
        ))
    )
}

fn expected_marker_artifact_id(
    canonical_basename: &str,
    state: &str,
    fingerprint: &str,
    rotation: &SccmRotation,
    basename: &str,
) -> String {
    let catalog_entry_id = format!(
        "sccm-client-source:v1:sha256:{}",
        sha256(canonical_basename)
    );
    format!(
        "sccm-artifact:v1:sha256:{}",
        sha256(format!(
            "marker:v1:{catalog_entry_id}:{state}:{}:{basename}:{fingerprint}",
            rotation_segment(rotation)
        ))
    )
}

fn expected_catalog_entry_id(canonical_basename: &str) -> String {
    format!(
        "sccm-client-source:v1:sha256:{}",
        sha256(canonical_basename)
    )
}

fn expected_evidence_identity(
    canonical_basename: &str,
    root_handle: &str,
    rotation: &SccmRotation,
    physical_basename: &str,
) -> String {
    let catalog_entry_id = format!(
        "sccm-client-source:v1:sha256:{}",
        sha256(canonical_basename)
    );
    let fingerprint = path_fingerprint(root_handle, canonical_basename);
    let source_digest = fingerprint
        .strip_prefix("sha256:")
        .expect("path fingerprint has the expected versioned prefix");
    format!(
        "sccm-evidence:v1:sha256:{}",
        sha256(format!(
            "cmtraceopen.sccm.evidence.v1\0{catalog_entry_id}\0{source_digest}\0{}\0{physical_basename}",
            rotation_segment(rotation)
        ))
    )
}

#[test]
fn discovery_uses_one_global_declaration_budget_and_marks_the_first_omitted_rotation() {
    let mut observations = Vec::new();
    for number in 1..=2_048 {
        observations.push(observation(
            ROOT_A,
            &format!("AppEnforce.log.{number}"),
            SccmRotation::Numbered(number),
            SccmClientDiscoveryObservationState::Found,
        ));
        observations.push(observation(
            ROOT_B,
            &format!("PolicyAgent.log.{number}"),
            SccmRotation::Numbered(number),
            SccmClientDiscoveryObservationState::Found,
        ));
    }
    observations.push(observation(
        ROOT_B,
        "PolicyAgent.log.2049",
        SccmRotation::Numbered(2_049),
        SccmClientDiscoveryObservationState::Found,
    ));

    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        observations,
    })
    .expect("valid observations");

    assert_eq!(
        result.declarations.len(),
        MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        "the 4096 declaration budget must be shared by all roots and sources"
    );
    let gap = result
        .declarations
        .last()
        .expect("the globally capped result retains the first omitted declaration");
    assert_eq!(gap.basename, "PolicyAgent.log.2048");
    assert_eq!(gap.rotation, SccmRotation::Numbered(2_048));
    assert_eq!(gap.state, SccmClientDiscoveryState::Capped);
    assert_eq!(
        result
            .declarations
            .iter()
            .filter(|declaration| declaration.state == SccmClientDiscoveryState::Discovered)
            .count(),
        MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS - 1
    );
}

#[test]
fn discovery_at_the_exact_global_boundary_does_not_manufacture_a_gap() {
    let observations = (1..=MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS as u32)
        .map(|number| {
            observation(
                ROOT_A,
                &format!("AppEnforce.log.{number}"),
                SccmRotation::Numbered(number),
                SccmClientDiscoveryObservationState::Found,
            )
        })
        .collect();

    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        observations,
    })
    .expect("valid observations");

    assert_eq!(
        result.declarations.len(),
        MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS
    );
    assert!(result
        .declarations
        .iter()
        .all(|declaration| declaration.state == SccmClientDiscoveryState::Discovered));
}

#[test]
fn discovery_enforces_each_source_cap_and_retains_the_first_omitted_rotation_gap() {
    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: 2,
        observations: vec![
            observation(
                ROOT_A,
                "AppEnforce.log.2",
                SccmRotation::Numbered(2),
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "AppEnforce.lo_",
                SccmRotation::LoUnderscore,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
        ],
    })
    .expect("valid observations");

    assert_eq!(
        result
            .declarations
            .iter()
            .map(|declaration| (&declaration.rotation, declaration.state))
            .collect::<Vec<_>>(),
        vec![
            (&SccmRotation::Current, SccmClientDiscoveryState::Discovered),
            (
                &SccmRotation::LoUnderscore,
                SccmClientDiscoveryState::Discovered
            ),
            (&SccmRotation::Numbered(2), SccmClientDiscoveryState::Capped),
        ]
    );
    let fingerprint = path_fingerprint(ROOT_A, "AppEnforce.log");
    assert_eq!(
        result.declarations[0].artifact_id,
        expected_physical_artifact_id(&fingerprint, &SccmRotation::Current, "AppEnforce.log")
    );
    assert_eq!(
        result.declarations[2].artifact_id,
        expected_marker_artifact_id(
            "AppEnforce.log",
            "capped",
            &fingerprint,
            &SccmRotation::Numbered(2),
            "AppEnforce.log.2",
        )
    );
}

#[test]
fn discovery_marks_only_the_first_found_fragment_per_source_when_the_cap_is_zero() {
    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: 0,
        observations: vec![
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "AppEnforce.lo_",
                SccmRotation::LoUnderscore,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_B,
                "PolicyAgent.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_B,
                "PolicyAgent.lo_",
                SccmRotation::LoUnderscore,
                SccmClientDiscoveryObservationState::Found,
            ),
        ],
    })
    .expect("zero cap is an explicit per-source coverage boundary");

    assert_eq!(
        result
            .declarations
            .iter()
            .map(|declaration| {
                (
                    declaration.root_handle.as_str(),
                    declaration.basename.as_str(),
                    declaration.state,
                )
            })
            .collect::<Vec<_>>(),
        vec![
            (ROOT_A, "AppEnforce.log", SccmClientDiscoveryState::Capped),
            (ROOT_B, "PolicyAgent.log", SccmClientDiscoveryState::Capped),
        ]
    );
}

#[test]
fn discovery_preserves_denied_and_not_found_coverage_with_stable_collision_safe_identities() {
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                ROOT_B,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "CIAgent.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::AccessDenied,
            ),
            observation(
                ROOT_B,
                "ScanAgent.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::NotFound,
            ),
        ],
    };
    let result = discover_client_sources(&input).expect("valid observations");
    let reversed = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: input.max_found_fragments_per_source,
        observations: input.observations.into_iter().rev().collect(),
    })
    .expect("valid observations");

    assert_eq!(result.declarations, reversed.declarations);
    assert!(result
        .declarations
        .iter()
        .any(|declaration| declaration.state == SccmClientDiscoveryState::AccessDenied));
    assert!(result
        .declarations
        .iter()
        .any(|declaration| declaration.state == SccmClientDiscoveryState::NotFound));

    let collisions = result
        .declarations
        .iter()
        .filter(|declaration| {
            declaration.basename == "AppEnforce.log"
                && declaration.rotation == SccmRotation::Current
        })
        .collect::<Vec<_>>();
    assert_eq!(collisions.len(), 2);
    assert_ne!(collisions[0].artifact_id, collisions[1].artifact_id);
    assert_ne!(
        collisions[0].evidence_identity,
        collisions[1].evidence_identity
    );
    assert_ne!(
        collisions[0].path_fingerprint,
        collisions[1].path_fingerprint
    );
    for collision in collisions {
        assert_eq!(
            collision.artifact_id,
            expected_physical_artifact_id(
                &path_fingerprint(&collision.root_handle, "AppEnforce.log"),
                &SccmRotation::Current,
                "AppEnforce.log",
            )
        );
    }
    let denied = result
        .declarations
        .iter()
        .find(|declaration| declaration.state == SccmClientDiscoveryState::AccessDenied)
        .expect("access-denied observation remains explicit");
    assert_eq!(
        denied.artifact_id,
        expected_marker_artifact_id(
            "CIAgent.log",
            "accessDenied",
            &path_fingerprint(ROOT_A, "CIAgent.log"),
            &SccmRotation::Current,
            "CIAgent.log",
        )
    );
    let missing = result
        .declarations
        .iter()
        .find(|declaration| declaration.state == SccmClientDiscoveryState::NotFound)
        .expect("not-found observation remains explicit");
    assert_eq!(
        missing.artifact_id,
        expected_marker_artifact_id(
            "ScanAgent.log",
            "absent",
            &path_fingerprint(ROOT_B, "ScanAgent.log"),
            &SccmRotation::Current,
            "ScanAgent.log",
        )
    );
    assert!(result.declarations.iter().all(|declaration| {
        !declaration.artifact_id.contains(ROOT_A)
            && !declaration.artifact_id.contains(ROOT_B)
            && !declaration.evidence_identity.contains(ROOT_A)
            && !declaration.evidence_identity.contains(ROOT_B)
            && !declaration.path_fingerprint.contains(ROOT_A)
            && !declaration.path_fingerprint.contains(ROOT_B)
    }));
}

#[test]
fn discovery_coalesces_exact_duplicate_observations_without_spending_global_quota() {
    let duplicate = observation(
        ROOT_A,
        "AppEnforce.log",
        SccmRotation::Current,
        SccmClientDiscoveryObservationState::Found,
    );
    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: 1,
        observations: vec![duplicate.clone(), duplicate],
    })
    .expect("exact duplicates are valid");

    assert_eq!(result.declarations.len(), 1);
    assert_eq!(
        result.declarations[0].state,
        SccmClientDiscoveryState::Discovered
    );
}

#[test]
fn discovery_rejects_conflicting_states_for_one_canonical_physical_source() {
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::AccessDenied,
            ),
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::NotFound,
            ),
        ],
    };

    let error =
        discover_client_sources(&input).expect_err("contradictory physical evidence fails closed");
    assert_eq!(
        error.to_string(),
        "conflicting SCCM client discovery observations"
    );
    assert!(!error.to_string().contains(ROOT_A));
    assert!(!error.to_string().contains("AppEnforce.log"));
    let mut reversed = input;
    reversed.observations.reverse();
    let reversed_error = discover_client_sources(&reversed)
        .expect_err("contradictory physical evidence fails closed regardless of order");

    assert_eq!(error, reversed_error);
}

#[test]
fn discovery_rejects_late_conflicts_after_the_global_declaration_frontier() {
    let mut observations = Vec::new();
    for number in 1..=2_047 {
        observations.push(observation(
            ROOT_A,
            &format!("AppEnforce.log.{number}"),
            SccmRotation::Numbered(number),
            SccmClientDiscoveryObservationState::Found,
        ));
        observations.push(observation(
            ROOT_B,
            &format!("PolicyAgent.log.{number}"),
            SccmRotation::Numbered(number),
            SccmClientDiscoveryObservationState::Found,
        ));
    }
    observations.push(observation(
        ROOT_A,
        "AppEnforce.log.2048",
        SccmRotation::Numbered(2_048),
        SccmClientDiscoveryObservationState::Found,
    ));
    observations.extend([
        observation(
            ROOT_A,
            "CIAgent.log",
            SccmRotation::Current,
            SccmClientDiscoveryObservationState::Found,
        ),
        observation(
            ROOT_A,
            "CIAgent.log",
            SccmRotation::Current,
            SccmClientDiscoveryObservationState::AccessDenied,
        ),
    ]);
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        observations,
    };

    let error = discover_client_sources(&input)
        .expect_err("a conflict beyond the output frontier fails closed");
    assert_eq!(error, SccmClientDiscoveryError::ConflictingObservation);
    let mut reversed = input;
    reversed.observations.reverse();
    assert_eq!(
        error,
        discover_client_sources(&reversed)
            .expect_err("a late conflict fails closed regardless of input order")
    );
}

#[test]
fn discovery_rejects_conflicting_states_for_canonical_basename_aliases() {
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "appenforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::AccessDenied,
            ),
        ],
    };

    let error = discover_client_sources(&input)
        .expect_err("canonical aliases with conflicting state fail closed");
    assert_eq!(error, SccmClientDiscoveryError::ConflictingObservation);
    let mut reversed = input;
    reversed.observations.reverse();
    assert_eq!(
        error,
        discover_client_sources(&reversed)
            .expect_err("canonical alias conflict fails closed regardless of input order")
    );
}

#[test]
fn discovery_canonicalizes_supported_aliases_into_stable_physical_declarations() {
    for (canonical_basename, alias, rotation, physical_basename) in [
        (
            "AppEnforce.log",
            "appenforce.log",
            SccmRotation::Current,
            "AppEnforce.log",
        ),
        (
            "AppEnforce.log",
            "appenforce.lo_",
            SccmRotation::LoUnderscore,
            "AppEnforce.lo_",
        ),
        (
            "AppEnforce.log",
            "appenforce.log.7",
            SccmRotation::Numbered(7),
            "AppEnforce.log.7",
        ),
    ] {
        let canonical = discover_client_sources(&SccmClientDiscoveryInput {
            max_found_fragments_per_source: 8,
            observations: vec![observation(
                ROOT_A,
                physical_basename,
                rotation.clone(),
                SccmClientDiscoveryObservationState::Found,
            )],
        })
        .expect("canonical observation is supported");
        let alias = discover_client_sources(&SccmClientDiscoveryInput {
            max_found_fragments_per_source: 8,
            observations: vec![observation(
                ROOT_A,
                alias,
                rotation.clone(),
                SccmClientDiscoveryObservationState::Found,
            )],
        })
        .expect("case-equivalent observation is supported");

        assert_eq!(alias.declarations, canonical.declarations);
        let declaration = &alias.declarations[0];
        assert_eq!(declaration.basename, physical_basename);
        assert_eq!(
            declaration.artifact_id,
            expected_physical_artifact_id(
                &path_fingerprint(ROOT_A, canonical_basename),
                &rotation,
                physical_basename,
            )
        );
        assert_eq!(
            declaration.evidence_identity,
            expected_evidence_identity(canonical_basename, ROOT_A, &rotation, physical_basename,)
        );
        assert_eq!(
            declaration.evidence_identity.as_bytes(),
            canonical.declarations[0].evidence_identity.as_bytes(),
            "equivalent aliases preserve byte-identical evidence IDs"
        );
    }
}

#[test]
fn discovery_rejects_observations_beyond_its_defensive_contract() {
    let observations = (1..=MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS + 1)
        .map(|number| {
            observation(
                ROOT_A,
                &format!("AppEnforce.log.{number}"),
                SccmRotation::Numbered(number as u32),
                SccmClientDiscoveryObservationState::Found,
            )
        })
        .collect();
    let error = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        observations,
    })
    .expect_err("the API must not silently ignore input beyond its defensive contract");

    assert_eq!(error, SccmClientDiscoveryError::ObservationLimitExceeded);
    assert_eq!(
        error.to_string(),
        "SCCM client discovery observation limit exceeded"
    );
    assert!(!error.to_string().contains(ROOT_A));
}

#[test]
fn discovery_preserves_valid_coverage_and_reports_invalid_provenance_without_raw_roots() {
    let malformed_root = "C:\\private\\SCCM\\Client\\Logs";
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                malformed_root,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_B,
                "Unrelated.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "AnotherUnrelated.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_B,
                "Unrelated.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_B,
                "AppEnforce.log.1",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "CIAgent.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Skipped,
            ),
            observation(
                ROOT_A,
                "ScanAgent.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::NotFound,
            ),
            observation(
                ROOT_B,
                "PolicyAgent.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
        ],
    };
    let result = discover_client_sources(&input)
        .expect("invalid observations remain explicit coverage without aborting valid sources");
    let reversed = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: input.max_found_fragments_per_source,
        observations: input.observations.into_iter().rev().collect(),
    })
    .expect("coverage results remain deterministic under input reversal");

    assert_eq!(result, reversed);
    assert_eq!(
        result
            .declarations
            .iter()
            .map(|declaration| (declaration.basename.as_str(), declaration.state))
            .collect::<Vec<_>>(),
        vec![
            ("PolicyAgent.log", SccmClientDiscoveryState::Discovered),
            ("CIAgent.log", SccmClientDiscoveryState::Skipped),
            ("ScanAgent.log", SccmClientDiscoveryState::NotFound),
        ],
        "skipped, absent, and found remain separate coverage states"
    );
    assert_eq!(result.coverage_issues.len(), 2);
    assert!(result.coverage_issues.iter().any(|issue| {
        issue.state == SccmClientDiscoveryCoverageIssueState::InvalidProvenance
            && issue.catalog_entry_id == expected_catalog_entry_id("AppEnforce.log")
            && issue.logical_artifact_ids == ["client-app-enforce"]
    }));
    let unsupported = result
        .coverage_issues
        .iter()
        .filter(|issue| issue.state == SccmClientDiscoveryCoverageIssueState::Unsupported)
        .collect::<Vec<_>>();
    assert_eq!(unsupported.len(), 1);
    assert!(unsupported
        .iter()
        .all(|issue| issue.logical_artifact_ids.is_empty()));
    assert_eq!(
        unsupported
            .iter()
            .find(|issue| issue.catalog_entry_id == "sccm-client-source:v1:none")
            .expect("arbitrary supplied names have one privacy-safe unsupported category")
            .occurrence_count
            .get(),
        4,
        "coalesced unsupported metadata retains the bounded count of supplied observations"
    );
    assert!(result.coverage_issues.iter().all(|issue| {
        !format!("{issue:?}").contains(malformed_root)
            && !issue.artifact_id.contains(malformed_root)
            && !issue.catalog_entry_id.contains(malformed_root)
    }));
    let distinct_malformed_root = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![observation(
            "root-also-not-validated",
            "AppEnforce.log",
            SccmRotation::Current,
            SccmClientDiscoveryObservationState::Found,
        )],
    })
    .expect("invalid provenance remains coverage-only");
    let invalid_provenance = result
        .coverage_issues
        .iter()
        .find(|issue| issue.state == SccmClientDiscoveryCoverageIssueState::InvalidProvenance)
        .expect("known source with malformed provenance is explicit");
    assert_eq!(
        distinct_malformed_root.coverage_issues[0].artifact_id, invalid_provenance.artifact_id,
        "invalid-root identities must not hash or otherwise depend on raw root input"
    );
    assert!(result.declarations.iter().all(|declaration| result
        .coverage_issues
        .iter()
        .all(|issue| declaration.artifact_id != issue.artifact_id)));
}

#[test]
fn discovery_retains_coverage_issues_past_the_declaration_cap_without_admitting_them_as_capture() {
    let mut observations = (1..=MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS)
        .map(|number| {
            observation(
                ROOT_A,
                &format!("AppEnforce.log.{number}"),
                SccmRotation::Numbered(number as u32),
                SccmClientDiscoveryObservationState::Found,
            )
        })
        .collect::<Vec<_>>();
    observations.push(observation(
        "not-a-root-handle",
        "CIAgent.log",
        SccmRotation::Current,
        SccmClientDiscoveryObservationState::Found,
    ));

    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        observations,
    })
    .expect("a malformed observation cannot hide coverage behind declaration capping");

    assert_eq!(
        result.declarations.len(),
        MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS
    );
    assert_eq!(result.coverage_issues.len(), 1);
    assert!(result.coverage_issues.len() <= MAX_SCCM_CLIENT_DISCOVERY_COVERAGE_ISSUES);
    assert_eq!(
        result.coverage_issues[0].state,
        SccmClientDiscoveryCoverageIssueState::InvalidProvenance
    );
    assert_eq!(result.coverage_issues[0].occurrence_count.get(), 1);
    assert!(result
        .declarations
        .iter()
        .all(|declaration| declaration.artifact_id != result.coverage_issues[0].artifact_id));
}

#[test]
fn discovery_preserves_coverage_issue_cardinality_at_the_exact_admission_boundary() {
    let observations = (0..MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS)
        .map(|_| {
            observation(
                ROOT_A,
                "Unrelated.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            )
        })
        .collect();

    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        observations,
    })
    .expect("the admission boundary retains every coverage-only observation");

    assert!(result.declarations.is_empty());
    assert_eq!(result.coverage_issues.len(), 1);
    let single = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
        observations: vec![observation(
            ROOT_A,
            "Unrelated.log",
            SccmRotation::Current,
            SccmClientDiscoveryObservationState::Found,
        )],
    })
    .expect("one unsupported observation remains explicit");
    assert_eq!(
        result.coverage_issues[0].artifact_id, single.coverage_issues[0].artifact_id,
        "coverage issue identity must not depend on its aggregated count"
    );
    assert_eq!(
        result.coverage_issues[0].occurrence_count.get() as usize,
        MAX_SCCM_CLIENT_DISCOVERY_OBSERVATIONS,
        "privacy-safe issue coalescing must retain exact duplicate cardinality"
    );
}

#[test]
fn discovery_never_assigns_catalog_memberships_to_rejected_rotation_candidates() {
    let raw_root = "C:\\private\\ccm\\logs";
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                raw_root,
                "PolicyAgent.log.backup",
                unsupported_rotation(".backup"),
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_A,
                "PolicyAgent.log.1",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                ROOT_B,
                "PolicyAgent.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
        ],
    };

    let result = discover_client_sources(&input).expect("rejected candidates remain coverage-only");
    let reversed = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: input.max_found_fragments_per_source,
        observations: input.observations.into_iter().rev().collect(),
    })
    .expect("rejected candidate coverage is order independent");

    assert_eq!(result, reversed);
    assert_eq!(result.declarations.len(), 1);
    assert_eq!(result.coverage_issues.len(), 2);
    assert!(result.coverage_issues.iter().all(|issue| {
        issue.catalog_entry_id == "sccm-client-source:v1:none"
            && issue.logical_artifact_ids.is_empty()
            && issue.rotation_category == SccmClientDiscoveryRotationCategory::Unknown
            && !format!("{issue:?}").contains(raw_root)
            && !format!("{issue:?}").contains("PolicyAgent.log.backup")
            && !format!("{issue:?}").contains("PolicyAgent.log.1")
    }));
}

#[test]
fn discovery_rejects_conflicting_states_for_the_same_rejected_physical_observation() {
    let raw_root = "C:\\private\\ccm\\logs";
    let raw_basename = "PolicyAgent.log.backup";
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                raw_root,
                raw_basename,
                unsupported_rotation(".backup"),
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                raw_root,
                raw_basename,
                unsupported_rotation(".backup"),
                SccmClientDiscoveryObservationState::AccessDenied,
            ),
            observation(
                ROOT_A,
                "AppEnforce.log",
                SccmRotation::Current,
                SccmClientDiscoveryObservationState::Found,
            ),
        ],
    };

    let error = discover_client_sources(&input)
        .expect_err("one rejected physical observation cannot carry contradictory states");
    let mut reversed = input;
    reversed.observations.reverse();
    let reversed_error = discover_client_sources(&reversed)
        .expect_err("rejected physical conflicts remain order independent");

    assert_eq!(error, SccmClientDiscoveryError::ConflictingObservation);
    assert_eq!(reversed_error, error);
    assert!(!error.to_string().contains(raw_root));
    assert!(!error.to_string().contains(raw_basename));
}

#[test]
fn discovery_does_not_conflict_distinct_rejected_alias_spellings() {
    let raw_root = "C:\\private\\ccm\\logs";
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                raw_root,
                "PolicyAgent.log.backup",
                unsupported_rotation(".backup"),
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                raw_root,
                "policyagent.log.backup",
                unsupported_rotation(".backup"),
                SccmClientDiscoveryObservationState::AccessDenied,
            ),
        ],
    };

    let result = discover_client_sources(&input)
        .expect("distinct raw rejected spellings are not one physical observation");
    let reversed = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: input.max_found_fragments_per_source,
        observations: input.observations.into_iter().rev().collect(),
    })
    .expect("distinct rejected aliases remain nonconflicting under reversal");

    assert_eq!(result, reversed);
    assert!(result.declarations.is_empty());
    assert_eq!(result.coverage_issues.len(), 1);
    assert_eq!(result.coverage_issues[0].occurrence_count.get(), 2);
    assert_eq!(
        result.coverage_issues[0].catalog_entry_id,
        "sccm-client-source:v1:none"
    );
    assert!(result.coverage_issues[0].logical_artifact_ids.is_empty());
}

#[test]
fn discovery_conflicts_rejected_states_even_when_untrusted_rotations_differ() {
    let raw_root = "C:\\private\\ccm\\logs";
    let input = SccmClientDiscoveryInput {
        max_found_fragments_per_source: 8,
        observations: vec![
            observation(
                raw_root,
                "PolicyAgent.log.backup",
                unsupported_rotation(".backup"),
                SccmClientDiscoveryObservationState::Found,
            ),
            observation(
                raw_root,
                "PolicyAgent.log.backup",
                unsupported_rotation(".archive"),
                SccmClientDiscoveryObservationState::AccessDenied,
            ),
        ],
    };

    let error = discover_client_sources(&input)
        .expect_err("rejected physical identity ignores caller-supplied rotation metadata");
    let mut reversed = input;
    reversed.observations.reverse();
    let reversed_error = discover_client_sources(&reversed)
        .expect_err("rejected rotation metadata cannot make conflicts order-dependent");

    assert_eq!(error, SccmClientDiscoveryError::ConflictingObservation);
    assert_eq!(reversed_error, error);
    assert!(!error.to_string().contains(raw_root));
    assert!(!error.to_string().contains("PolicyAgent.log.backup"));
}

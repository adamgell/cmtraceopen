use app_lib::sccm::{
    discover_client_sources, SccmClientDiscoveryInput, SccmClientDiscoveryObservation,
    SccmClientDiscoveryObservationState, SccmClientDiscoveryState,
    MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
};
use cmtraceopen_parser::sccm::SccmRotation;
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
    });

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
    });

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
    });

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
    let result = discover_client_sources(&input);
    let reversed = discover_client_sources(&SccmClientDiscoveryInput {
        max_found_fragments_per_source: input.max_found_fragments_per_source,
        observations: input.observations.into_iter().rev().collect(),
    });

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

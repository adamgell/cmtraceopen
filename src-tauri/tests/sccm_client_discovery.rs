use app_lib::sccm::{
    discover_client_sources, SccmClientDiscoveryInput, SccmClientDiscoveryObservation,
    SccmClientDiscoveryObservationState, SccmClientDiscoveryState,
    MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
};
use cmtraceopen_parser::sccm::SccmRotation;

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

#[test]
fn discovery_uses_one_global_declaration_budget_and_marks_the_first_omitted_rotation() {
    let mut observations = Vec::new();
    for number in 1..=2_048 {
        observations.push(observation(
            ROOT_A,
            "AppEnforce.log",
            SccmRotation::Numbered(number),
            SccmClientDiscoveryObservationState::Found,
        ));
        observations.push(observation(
            ROOT_B,
            "PolicyAgent.log",
            SccmRotation::Numbered(number),
            SccmClientDiscoveryObservationState::Found,
        ));
    }

    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_declarations_per_source: MAX_SCCM_CLIENT_DISCOVERY_DECLARATIONS,
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
    assert_eq!(gap.basename, "PolicyAgent.log");
    assert_eq!(gap.rotation, SccmRotation::Numbered(2_048));
    assert_eq!(gap.state, SccmClientDiscoveryState::Capped);
}

#[test]
fn discovery_enforces_each_source_cap_and_retains_the_first_omitted_rotation_gap() {
    let result = discover_client_sources(&SccmClientDiscoveryInput {
        max_declarations_per_source: 2,
        observations: vec![
            observation(
                ROOT_A,
                "AppEnforce.log",
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
            (&SccmRotation::LoUnderscore, SccmClientDiscoveryState::Discovered),
            (&SccmRotation::Numbered(2), SccmClientDiscoveryState::Capped),
        ]
    );
}

#[test]
fn discovery_preserves_denied_and_not_found_coverage_with_stable_collision_safe_identities() {
    let input = SccmClientDiscoveryInput {
        max_declarations_per_source: 8,
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
        max_declarations_per_source: input.max_declarations_per_source,
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
    assert_ne!(collisions[0].evidence_identity, collisions[1].evidence_identity);
    assert_ne!(collisions[0].path_fingerprint, collisions[1].path_fingerprint);
    assert!(result.declarations.iter().all(|declaration| {
        !declaration.artifact_id.contains("C:\\\\")
            && !declaration.evidence_identity.contains("C:\\\\")
            && !declaration.path_fingerprint.contains("C:\\\\")
    }));
}

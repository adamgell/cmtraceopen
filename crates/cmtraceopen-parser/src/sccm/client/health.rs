use std::collections::{BTreeMap, BTreeSet};
use std::ops::Deref;

use serde::Serialize;

use crate::models::log_entry::Severity;
use crate::sccm::{
    classify_artifact_name, SccmArtifact, SccmArtifactFamily, SccmArtifactRequest, SccmConfidence,
    SccmCoverageState, SccmEvidence, SccmEvidenceRef, SccmFinding, SccmFindingBuilder,
    SccmFindingClass, SccmFindingCoverageGap, SccmPhase, SccmRole, SccmTerminalEvidence,
};

use super::SccmNormalizedBundle;

pub const SCCM_HEALTH_ANALYSIS_SCHEMA_VERSION: u32 = 1;
pub const SCCM_HEALTH_TEST_PROFILE_ID: &str = "health-client-5.00.test-v1";

const SCCM_HEALTH_TEST_VERSION: &str = "5.00.TEST.0000";
const CLIENT_SETUP_GROUP: &str = "client-ccmsetup";
const CLIENT_EVALUATION_GROUP: &str = "client-evaluation";
const CLIENT_IDENTITY_GROUP: &str = "client-identity";
const CLIENT_LOCATION_GROUP: &str = "client-location";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHealthWorkflow {
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SccmHealthPhase {
    Setup,
    Service,
    Identity,
    SiteAssignment,
    ManagementPoint,
    Transport,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHealthFinding {
    #[serde(flatten)]
    pub finding: SccmFinding,
    pub health_phase: SccmHealthPhase,
    pub last_successful_phase: Option<SccmHealthPhase>,
}

impl Deref for SccmHealthFinding {
    type Target = SccmFinding;

    fn deref(&self) -> &Self::Target {
        &self.finding
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SccmHealthAnalysis {
    pub schema_version: u32,
    pub workflow: SccmHealthWorkflow,
    pub last_successful_phase: Option<SccmHealthPhase>,
    pub findings: Vec<SccmHealthFinding>,
    pub coverage_gaps: Vec<SccmFindingCoverageGap>,
    pub artifact_requests: Vec<SccmArtifactRequest>,
}

#[derive(Debug, Clone)]
enum HealthFactKind {
    SetupSucceeded {
        bootstrap_id: String,
        client_guid: String,
    },
    SetupFailed {
        bootstrap_id: String,
    },
    ServiceSucceeded {
        client_guid: String,
    },
    IdentitySucceeded {
        client_guid: String,
    },
    IdentityFailed {
        client_guid: String,
    },
    LocationQuery {
        client_guid: String,
    },
    SiteAssigned {
        client_guid: String,
        site_code: String,
    },
    ManagementPointSelected {
        site_code: String,
        host: String,
    },
    TransportStarted {
        request_id: String,
        host: String,
    },
    TransportSucceeded {
        request_id: String,
        host: String,
    },
    TransportFailed {
        request_id: String,
        host: String,
    },
    GenericLocationSymptom,
    UnrelatedLocationText,
}

#[derive(Debug, Clone)]
struct HealthFact {
    kind: HealthFactKind,
    reference: SccmEvidenceRef,
    utc_millis: Option<i64>,
    time_comparable: bool,
}

enum SetupResolution<'a> {
    Succeeded {
        fact: &'a HealthFact,
        client_guid: &'a str,
    },
    Failed {
        failure: &'a HealthFact,
    },
    Contradictory {
        evidence: Vec<SccmEvidenceRef>,
    },
    Missing,
}

enum TransportResolution<'a> {
    Succeeded {
        started: &'a HealthFact,
        response: &'a HealthFact,
    },
    Failed {
        started: &'a HealthFact,
        failure: &'a HealthFact,
    },
    Contradictory {
        evidence: Vec<SccmEvidenceRef>,
    },
    Missing,
}

pub fn analyze_client_health(bundle: &SccmNormalizedBundle) -> SccmHealthAnalysis {
    let artifacts_by_id = bundle
        .artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id.as_str(), artifact))
        .collect::<BTreeMap<_, _>>();
    let mut facts = bundle
        .evidence
        .iter()
        .filter_map(|evidence| {
            let artifact = artifacts_by_id.get(evidence.reference.artifact_id.as_str())?;
            parse_health_fact(evidence, artifact)
        })
        .collect::<Vec<_>>();
    facts.sort_by(|left, right| compare_references(&left.reference, &right.reference));

    let mut last_successful_phase = None;
    let mut findings = Vec::new();

    let (client_guid, setup_fact) = match resolve_setup(&facts) {
        SetupResolution::Succeeded { fact, client_guid } => {
            last_successful_phase = Some(SccmHealthPhase::Setup);
            (client_guid.to_owned(), fact)
        }
        SetupResolution::Failed { failure } => {
            findings.push(terminal_finding(
                "health-setup-terminal",
                SccmHealthPhase::Setup,
                last_successful_phase,
                "Client setup recorded a terminal failure",
                "A version-profiled client setup record ended with a nonzero terminal error.",
                vec![failure.reference.clone()],
                failure.reference.clone(),
            ));
            return finalize_health_analysis(last_successful_phase, findings);
        }
        SetupResolution::Contradictory { evidence } => {
            findings.push(local_symptom_finding(
                "health-setup-contradictory",
                SccmHealthPhase::Setup,
                last_successful_phase,
                "Client setup evidence is contradictory",
                "Different bootstrap identifiers cannot prove setup recovery or failure.",
                evidence,
                Some(request_for_phase(SccmHealthPhase::Setup)),
            ));
            return finalize_health_analysis(last_successful_phase, findings);
        }
        SetupResolution::Missing => {
            let setup_artifacts = artifacts_for_family(bundle, SccmArtifactFamily::ClientSetup);
            let is_rotation_boundary = setup_artifacts.len() > 1
                && setup_artifacts
                    .iter()
                    .all(|artifact| artifact.coverage == SccmCoverageState::Captured);
            let (finding_id, title, summary) = if is_rotation_boundary {
                (
                    "health-setup-rotation-boundary",
                    "Client setup record is split across physical rotations",
                    "Physical rotation fragments cannot create a logical setup outcome.",
                )
            } else {
                (
                    "health-setup-coverage-gap",
                    "Client setup evidence is incomplete",
                    "No complete version-profiled client setup outcome was available.",
                )
            };
            findings.push(insufficient_finding(
                finding_id,
                SccmHealthPhase::Setup,
                last_successful_phase,
                title,
                summary,
                Vec::new(),
                coverage_gaps_for_missing_group(
                    &setup_artifacts,
                    CLIENT_SETUP_GROUP,
                    is_rotation_boundary,
                ),
                request_for_phase(SccmHealthPhase::Setup),
            ));
            return finalize_health_analysis(last_successful_phase, findings);
        }
    };

    let matching_service = facts.iter().find(|fact| {
        matches!(
            &fact.kind,
            HealthFactKind::ServiceSucceeded {
                client_guid: fact_client_guid
            } if fact_client_guid == &client_guid
        ) && !known_inversion(setup_fact, fact)
    });
    let Some(service_fact) = matching_service else {
        let service_artifacts = artifacts_for_family(bundle, SccmArtifactFamily::ClientHealth);
        let has_captured_without_record = service_artifacts
            .iter()
            .any(|artifact| artifact.coverage == SccmCoverageState::Captured);
        findings.push(insufficient_finding(
            if has_captured_without_record {
                "health-service-malformed"
            } else {
                "health-service-coverage-gap"
            },
            SccmHealthPhase::Service,
            last_successful_phase,
            if has_captured_without_record {
                "Client service evidence is malformed"
            } else {
                "Client service evidence is incomplete"
            },
            if has_captured_without_record {
                "A captured service artifact contained no complete version-profiled logical record."
            } else {
                "No complete version-profiled service or evaluation outcome was available."
            },
            Vec::new(),
            coverage_gaps_for_missing_group(&service_artifacts, CLIENT_EVALUATION_GROUP, false),
            request_for_phase(SccmHealthPhase::Service),
        ));
        return finalize_health_analysis(last_successful_phase, findings);
    };
    {
        last_successful_phase = Some(SccmHealthPhase::Service);
    }

    if let Some(failure) = facts.iter().find(|fact| {
        matches!(
            &fact.kind,
            HealthFactKind::IdentityFailed {
                client_guid: fact_client_guid
            } if fact_client_guid == &client_guid
        )
    }) {
        if chain_has_usable_order(&[setup_fact, service_fact, failure]) {
            findings.push(terminal_finding(
                "health-identity-terminal",
                SccmHealthPhase::Identity,
                last_successful_phase,
                "Client identity registration recorded a terminal failure",
                "A version-profiled identity record ended with a nonzero terminal error.",
                vec![failure.reference.clone()],
                failure.reference.clone(),
            ));
        } else {
            findings.push(local_symptom_finding(
                "health-identity-chronology-uncertain",
                SccmHealthPhase::Identity,
                last_successful_phase,
                "Client identity chronology is not usable",
                "A terminal-looking identity record cannot be ordered after its prerequisite evidence.",
                vec![
                    setup_fact.reference.clone(),
                    service_fact.reference.clone(),
                    failure.reference.clone(),
                ],
                Some(request_for_phase(SccmHealthPhase::Identity)),
            ));
        }
        return finalize_health_analysis(last_successful_phase, findings);
    }

    let matching_identity = facts.iter().find(|fact| {
        matches!(
            &fact.kind,
            HealthFactKind::IdentitySucceeded {
                client_guid: fact_client_guid
            } if fact_client_guid == &client_guid
        ) && !known_inversion(service_fact, fact)
    });
    let Some(identity_fact) = matching_identity else {
        let identity_artifacts = artifacts_for_family(bundle, SccmArtifactFamily::ClientIdentity);
        findings.push(insufficient_finding(
            "health-identity-coverage-gap",
            SccmHealthPhase::Identity,
            last_successful_phase,
            "Client identity evidence is incomplete",
            "No complete version-profiled identity registration outcome was available.",
            Vec::new(),
            coverage_gaps_for_missing_group(&identity_artifacts, CLIENT_IDENTITY_GROUP, false),
            request_for_phase(SccmHealthPhase::Identity),
        ));
        return finalize_health_analysis(last_successful_phase, findings);
    };
    last_successful_phase = Some(SccmHealthPhase::Identity);

    let matching_site = facts.iter().find_map(|fact| match &fact.kind {
        HealthFactKind::SiteAssigned {
            client_guid: fact_client_guid,
            site_code,
        } if fact_client_guid == &client_guid && !known_inversion(identity_fact, fact) => {
            Some((fact, site_code.as_str()))
        }
        _ => None,
    });
    let Some((site_fact, site_code)) = matching_site else {
        let query_evidence = facts
            .iter()
            .filter_map(|fact| match &fact.kind {
                HealthFactKind::LocationQuery {
                    client_guid: fact_client_guid,
                } if fact_client_guid == &client_guid => Some(fact.reference.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        findings.push(insufficient_finding(
            "health-site-assignment-insufficient",
            SccmHealthPhase::SiteAssignment,
            last_successful_phase,
            "Site-assignment evidence is incomplete",
            "A client-side location query does not prove assignment or a remote-system outcome.",
            query_evidence,
            vec![SccmFindingCoverageGap {
                artifact_id: CLIENT_LOCATION_GROUP.to_owned(),
                role: SccmRole::Client,
                coverage: SccmCoverageState::Partial,
            }],
            request_for_phase(SccmHealthPhase::SiteAssignment),
        ));

        let symptom_evidence = generic_location_symptom_evidence(&facts);
        if !symptom_evidence.is_empty() {
            findings.push(local_symptom_finding(
                "health-unkeyed-transport-symptom",
                SccmHealthPhase::Transport,
                last_successful_phase,
                "Unkeyed client transport symptom observed",
                "Source-local warning text without a validated request and host key is not a transport failure.",
                symptom_evidence,
                None,
            ));
        }
        return finalize_health_analysis(last_successful_phase, findings);
    };
    last_successful_phase = Some(SccmHealthPhase::SiteAssignment);

    let management_point_host = facts.iter().find_map(|fact| match &fact.kind {
        HealthFactKind::ManagementPointSelected {
            site_code: fact_site_code,
            host,
        } if fact_site_code == site_code && !known_inversion(site_fact, fact) => {
            Some((fact, host.as_str()))
        }
        _ => None,
    });
    let Some((management_point_fact, management_point_host)) = management_point_host else {
        let location_artifacts = artifacts_for_family(bundle, SccmArtifactFamily::ClientLocation);
        findings.push(insufficient_finding(
            "health-management-point-insufficient",
            SccmHealthPhase::ManagementPoint,
            last_successful_phase,
            "Management-point selection evidence is incomplete",
            "Site assignment does not prove that a client selected a management point.",
            Vec::new(),
            coverage_gaps_for_missing_group(&location_artifacts, CLIENT_LOCATION_GROUP, false),
            request_for_phase(SccmHealthPhase::ManagementPoint),
        ));
        return finalize_health_analysis(last_successful_phase, findings);
    };
    last_successful_phase = Some(SccmHealthPhase::ManagementPoint);

    match resolve_transport(&facts, management_point_host, management_point_fact) {
        TransportResolution::Succeeded { started, response } => {
            if !chain_has_known_inversion(&[
                setup_fact,
                service_fact,
                identity_fact,
                site_fact,
                management_point_fact,
                started,
                response,
            ]) {
                last_successful_phase = Some(SccmHealthPhase::Transport);
                return finalize_health_analysis(last_successful_phase, findings);
            }
        }
        TransportResolution::Failed { started, failure } => {
            if chain_has_usable_order(&[
                setup_fact,
                service_fact,
                identity_fact,
                site_fact,
                management_point_fact,
                started,
                failure,
            ]) {
                findings.push(terminal_finding(
                    "health-transport-terminal",
                    SccmHealthPhase::Transport,
                    last_successful_phase,
                    "Client transport recorded a terminal failure",
                    "The same validated client request and management-point host recorded a nonzero terminal error.",
                    vec![started.reference.clone(), failure.reference.clone()],
                    failure.reference.clone(),
                ));
            } else {
                findings.push(local_symptom_finding(
                    "health-transport-chronology-uncertain",
                    SccmHealthPhase::Transport,
                    last_successful_phase,
                    "Client transport chronology is not usable",
                    "Terminal-looking transport evidence cannot be ordered through the complete client-side prerequisite chain.",
                    vec![started.reference.clone(), failure.reference.clone()],
                    Some(request_for_phase(SccmHealthPhase::Transport)),
                ));
            }
            return finalize_health_analysis(last_successful_phase, findings);
        }
        TransportResolution::Contradictory { evidence } => {
            findings.push(local_symptom_finding(
                "health-transport-contradictory",
                SccmHealthPhase::Transport,
                last_successful_phase,
                "Client transport evidence is contradictory",
                "Incomparable or differently keyed transport outcomes cannot prove recovery or failure.",
                evidence,
                Some(request_for_phase(SccmHealthPhase::Transport)),
            ));
            return finalize_health_analysis(last_successful_phase, findings);
        }
        TransportResolution::Missing => {}
    }

    let location_artifacts = artifacts_for_family(bundle, SccmArtifactFamily::ClientLocation);
    findings.push(insufficient_finding(
        "health-transport-insufficient",
        SccmHealthPhase::Transport,
        last_successful_phase,
        "Client transport evidence is incomplete",
        "Management-point selection alone does not prove a completed client transport exchange.",
        Vec::new(),
        coverage_gaps_for_missing_group(&location_artifacts, CLIENT_LOCATION_GROUP, false),
        request_for_phase(SccmHealthPhase::Transport),
    ));
    finalize_health_analysis(last_successful_phase, findings)
}

fn resolve_setup(facts: &[HealthFact]) -> SetupResolution<'_> {
    let successes = facts
        .iter()
        .filter_map(|fact| match &fact.kind {
            HealthFactKind::SetupSucceeded {
                bootstrap_id,
                client_guid,
            } => Some((fact, bootstrap_id.as_str(), client_guid.as_str())),
            _ => None,
        })
        .collect::<Vec<_>>();
    let failures = facts
        .iter()
        .filter_map(|fact| match &fact.kind {
            HealthFactKind::SetupFailed { bootstrap_id } => Some((fact, bootstrap_id.as_str())),
            _ => None,
        })
        .collect::<Vec<_>>();

    if successes.is_empty() && failures.is_empty() {
        return SetupResolution::Missing;
    }

    let mut unrecovered_failures = Vec::new();
    for (failure, bootstrap_id) in &failures {
        let recovered = successes.iter().any(|(success, success_id, _)| {
            success_id == bootstrap_id
                && is_later_in_same_artifact(&failure.reference, &success.reference)
        });
        if !recovered {
            unrecovered_failures.push(*failure);
        }
    }

    if unrecovered_failures.is_empty() {
        let unique_successes = successes
            .iter()
            .map(|(_, bootstrap_id, client_guid)| (*bootstrap_id, *client_guid))
            .collect::<BTreeSet<_>>();
        if unique_successes.len() == 1 {
            return SetupResolution::Succeeded {
                fact: successes[0].0,
                client_guid: successes[0].2,
            };
        }
    }

    if successes.is_empty() && unrecovered_failures.len() == 1 {
        return SetupResolution::Failed {
            failure: unrecovered_failures[0],
        };
    }

    let evidence = successes
        .iter()
        .map(|(fact, _, _)| fact.reference.clone())
        .chain(
            unrecovered_failures
                .iter()
                .map(|fact| fact.reference.clone()),
        )
        .collect::<Vec<_>>();
    SetupResolution::Contradictory { evidence }
}

fn resolve_transport<'a>(
    facts: &'a [HealthFact],
    management_point_host: &str,
    management_point_fact: &HealthFact,
) -> TransportResolution<'a> {
    let request_ids = facts
        .iter()
        .filter_map(|fact| match &fact.kind {
            HealthFactKind::TransportStarted { request_id, host }
            | HealthFactKind::TransportSucceeded { request_id, host }
            | HealthFactKind::TransportFailed { request_id, host }
                if host == management_point_host =>
            {
                Some(request_id.as_str())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();

    let mut resolved = Vec::new();
    let mut contradictory_evidence = Vec::new();
    for request_id in request_ids {
        let starts = facts
            .iter()
            .filter(|fact| {
                matches!(
                    &fact.kind,
                    HealthFactKind::TransportStarted {
                        request_id: fact_request_id,
                        host,
                    } if fact_request_id == request_id
                        && host == management_point_host
                        && !known_inversion(management_point_fact, fact)
                )
            })
            .collect::<Vec<_>>();
        let outcomes = facts
            .iter()
            .filter(|fact| {
                matches!(
                    &fact.kind,
                    HealthFactKind::TransportSucceeded {
                        request_id: fact_request_id,
                        host,
                    } | HealthFactKind::TransportFailed {
                        request_id: fact_request_id,
                        host,
                    } if fact_request_id == request_id && host == management_point_host
                )
            })
            .filter_map(|outcome| {
                let preceding_starts = starts
                    .iter()
                    .copied()
                    .filter(|started| fact_is_strictly_after(started, outcome))
                    .collect::<Vec<_>>();
                latest_comparable_fact(&preceding_starts).map(|started| (started, outcome))
            })
            .collect::<Vec<_>>();

        if outcomes.is_empty() {
            continue;
        }
        let outcome_facts = outcomes
            .iter()
            .map(|(_, outcome)| *outcome)
            .collect::<Vec<_>>();
        let Some(latest_outcome) = latest_comparable_fact(&outcome_facts) else {
            contradictory_evidence.extend(outcome_facts.iter().map(|fact| fact.reference.clone()));
            continue;
        };
        let started = outcomes
            .iter()
            .find_map(|(started, outcome)| {
                std::ptr::eq(*outcome, latest_outcome).then_some(*started)
            })
            .expect("latest transport outcome came from an admitted pair");
        let succeeded = matches!(
            latest_outcome.kind,
            HealthFactKind::TransportSucceeded { .. }
        );
        resolved.push((started, latest_outcome, succeeded));
    }

    if !contradictory_evidence.is_empty() {
        contradictory_evidence.extend(resolved.iter().flat_map(|(started, outcome, _)| {
            [started.reference.clone(), outcome.reference.clone()]
        }));
        return TransportResolution::Contradictory {
            evidence: contradictory_evidence,
        };
    }

    match resolved.as_slice() {
        [] => TransportResolution::Missing,
        [(started, response, true)] => TransportResolution::Succeeded { started, response },
        [(started, failure, false)] => TransportResolution::Failed { started, failure },
        many if many.iter().all(|(_, _, succeeded)| *succeeded) => {
            let responses = many
                .iter()
                .map(|(_, response, _)| *response)
                .collect::<Vec<_>>();
            let Some(latest_response) = latest_comparable_fact(&responses) else {
                return TransportResolution::Contradictory {
                    evidence: many
                        .iter()
                        .flat_map(|(started, response, _)| {
                            [started.reference.clone(), response.reference.clone()]
                        })
                        .collect(),
                };
            };
            let started = many
                .iter()
                .find_map(|(started, response, _)| {
                    std::ptr::eq(*response, latest_response).then_some(*started)
                })
                .expect("latest successful response came from an admitted pair");
            TransportResolution::Succeeded {
                started,
                response: latest_response,
            }
        }
        many => TransportResolution::Contradictory {
            evidence: many
                .iter()
                .flat_map(|(started, outcome, _)| {
                    [started.reference.clone(), outcome.reference.clone()]
                })
                .collect(),
        },
    }
}

fn latest_comparable_fact<'a>(facts: &[&'a HealthFact]) -> Option<&'a HealthFact> {
    let mut latest = *facts.first()?;
    for candidate in &facts[1..] {
        match compare_fact_order(latest, candidate)? {
            std::cmp::Ordering::Less => latest = candidate,
            std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {}
        }
    }
    Some(latest)
}

fn compare_fact_order(left: &HealthFact, right: &HealthFact) -> Option<std::cmp::Ordering> {
    if left.reference.artifact_id == right.reference.artifact_id {
        return left
            .reference
            .line_start
            .cmp(&right.reference.line_start)
            .into();
    }
    if left.time_comparable && right.time_comparable {
        return left.utc_millis.cmp(&right.utc_millis).into();
    }
    None
}

fn fact_is_strictly_after(earlier: &HealthFact, later: &HealthFact) -> bool {
    compare_fact_order(earlier, later) == Some(std::cmp::Ordering::Less)
}

fn known_inversion(earlier: &HealthFact, later: &HealthFact) -> bool {
    compare_fact_order(earlier, later) == Some(std::cmp::Ordering::Greater)
}

fn chain_has_known_inversion(facts: &[&HealthFact]) -> bool {
    facts
        .windows(2)
        .any(|pair| known_inversion(pair[0], pair[1]))
}

fn chain_has_usable_order(facts: &[&HealthFact]) -> bool {
    facts
        .windows(2)
        .all(|pair| fact_is_strictly_after(pair[0], pair[1]))
}

fn parse_health_fact(evidence: &SccmEvidence, artifact: &SccmArtifact) -> Option<HealthFact> {
    if artifact.role != SccmRole::Client
        || evidence.role != SccmRole::Client
        || artifact.coverage != SccmCoverageState::Captured
        || artifact.configmgr_version.as_deref() != Some(SCCM_HEALTH_TEST_VERSION)
        || !valid_reference(&evidence.reference)
    {
        return None;
    }

    let catalog = classify_artifact_name(&artifact.display_name, SccmRole::Client);
    if !catalog.supported_for_diagnosis {
        return None;
    }
    let message = evidence.message.as_str();
    let kind = match catalog.family {
        SccmArtifactFamily::ClientSetup => parse_setup_fact(message),
        SccmArtifactFamily::ClientHealth => parse_service_fact(message),
        SccmArtifactFamily::ClientIdentity => parse_identity_fact(message),
        SccmArtifactFamily::ClientLocation => parse_location_fact(message),
        _ => None,
    }?;

    Some(HealthFact {
        kind,
        reference: evidence.reference.clone(),
        utc_millis: evidence.timestamp.utc_millis,
        time_comparable: evidence.timestamp.ordering_state
            == crate::sccm::SccmTimeOrderingState::NormalizedUtc
            && evidence.timestamp.utc_millis.is_some(),
    })
}

fn parse_setup_fact(message: &str) -> Option<HealthFactKind> {
    if message.contains("Bootstrap completed ") {
        let bootstrap_id =
            field_value(message, "bootstrapId").filter(|value| valid_bootstrap_id(value))?;
        let client_guid = field_value(message, "clientGuid").filter(|value| valid_guid(value))?;
        return Some(HealthFactKind::SetupSucceeded {
            bootstrap_id: bootstrap_id.to_owned(),
            client_guid: client_guid.to_owned(),
        });
    }
    if message.contains("Bootstrap terminal failure ") && has_nonzero_error(message) {
        let bootstrap_id =
            field_value(message, "bootstrapId").filter(|value| valid_bootstrap_id(value))?;
        return Some(HealthFactKind::SetupFailed {
            bootstrap_id: bootstrap_id.to_owned(),
        });
    }
    None
}

fn parse_service_fact(message: &str) -> Option<HealthFactKind> {
    if !message.contains("Client service evaluation succeeded ") {
        return None;
    }
    let client_guid = field_value(message, "clientGuid").filter(|value| valid_guid(value))?;
    Some(HealthFactKind::ServiceSucceeded {
        client_guid: client_guid.to_owned(),
    })
}

fn parse_identity_fact(message: &str) -> Option<HealthFactKind> {
    let client_guid = field_value(message, "clientGuid").filter(|value| valid_guid(value))?;
    if message.contains("Identity registration succeeded ")
        || message.contains("[redacted:sccm-public-message-v1] succeeded clientGuid=")
    {
        return Some(HealthFactKind::IdentitySucceeded {
            client_guid: client_guid.to_owned(),
        });
    }
    if (message.contains("Identity registration terminal failure ")
        || message.contains("[redacted:sccm-public-message-v1] terminal failure clientGuid="))
        && has_nonzero_error(message)
    {
        return Some(HealthFactKind::IdentityFailed {
            client_guid: client_guid.to_owned(),
        });
    }
    None
}

fn parse_location_fact(message: &str) -> Option<HealthFactKind> {
    if message.contains("Location query started ") {
        let client_guid = field_value(message, "clientGuid").filter(|value| valid_guid(value))?;
        return Some(HealthFactKind::LocationQuery {
            client_guid: client_guid.to_owned(),
        });
    }
    if message.contains("Site assignment succeeded ") {
        let client_guid = field_value(message, "clientGuid").filter(|value| valid_guid(value))?;
        let site_code = field_value(message, "siteCode").filter(|value| valid_site_code(value))?;
        return Some(HealthFactKind::SiteAssigned {
            client_guid: client_guid.to_owned(),
            site_code: site_code.to_owned(),
        });
    }
    if message.contains("Management point selected ") {
        let site_code = field_value(message, "siteCode").filter(|value| valid_site_code(value))?;
        let host =
            field_value(message, "managementPointHost").filter(|value| valid_test_host(value))?;
        return Some(HealthFactKind::ManagementPointSelected {
            site_code: site_code.to_owned(),
            host: host.to_owned(),
        });
    }
    if message.contains("Transport request started ") {
        let request_id =
            field_value(message, "requestId").filter(|value| valid_request_id(value))?;
        let host =
            field_value(message, "managementPointHost").filter(|value| valid_test_host(value))?;
        return Some(HealthFactKind::TransportStarted {
            request_id: request_id.to_owned(),
            host: host.to_owned(),
        });
    }
    if message.contains("Transport response completed ") && has_success_status(message) {
        let request_id =
            field_value(message, "requestId").filter(|value| valid_request_id(value))?;
        let host =
            field_value(message, "managementPointHost").filter(|value| valid_test_host(value))?;
        return Some(HealthFactKind::TransportSucceeded {
            request_id: request_id.to_owned(),
            host: host.to_owned(),
        });
    }
    if message.contains("Transport terminal failure ") && has_nonzero_error(message) {
        let request_id =
            field_value(message, "requestId").filter(|value| valid_request_id(value))?;
        let host =
            field_value(message, "managementPointHost").filter(|value| valid_test_host(value))?;
        return Some(HealthFactKind::TransportFailed {
            request_id: request_id.to_owned(),
            host: host.to_owned(),
        });
    }
    if message.contains("Generic network warning ") && has_nonzero_error(message) {
        return Some(HealthFactKind::GenericLocationSymptom);
    }
    if message.contains("Unrelated text mentions ") {
        return Some(HealthFactKind::UnrelatedLocationText);
    }
    None
}

fn field_value<'a>(message: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("{key}=");
    let mut matches = message.match_indices(&marker);
    let (first, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    let value_start = first + marker.len();
    let value = &message[value_start..];
    let value_end = value
        .find(|character: char| character.is_ascii_whitespace() || matches!(character, ',' | ';'))
        .unwrap_or(value.len());
    (!value[..value_end].is_empty()).then_some(&value[..value_end])
}

fn has_nonzero_error(message: &str) -> bool {
    field_value(message, "error")
        .and_then(parse_hex_u32)
        .is_some_and(|value| value != 0)
}

fn has_success_status(message: &str) -> bool {
    field_value(message, "status")
        .and_then(|value| value.parse::<u16>().ok())
        .is_some_and(|value| (200..300).contains(&value))
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    let hex = value.strip_prefix("0x")?;
    (hex.len() == 8 && hex.chars().all(|character| character.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(hex, 16).ok())
        .flatten()
}

fn valid_guid(value: &str) -> bool {
    value.len() == 36
        && value.chars().enumerate().all(|(index, character)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                character == '-'
            } else {
                character.is_ascii_hexdigit()
            }
        })
}

fn valid_bootstrap_id(value: &str) -> bool {
    value
        .strip_prefix("BOOT-TEST-")
        .is_some_and(valid_safe_key_suffix)
}

fn valid_request_id(value: &str) -> bool {
    value
        .strip_prefix("REQ-TEST-")
        .is_some_and(valid_safe_key_suffix)
}

fn valid_safe_key_suffix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '-'
        })
}

fn valid_site_code(value: &str) -> bool {
    value.len() == 3
        && value
            .chars()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
}

fn valid_test_host(value: &str) -> bool {
    value.len() <= 253
        && value.ends_with(".invalid")
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
        })
}

fn valid_reference(reference: &SccmEvidenceRef) -> bool {
    valid_public_id(&reference.artifact_id)
        && valid_public_id(&reference.entry_id)
        && matches!(
            (reference.line_start, reference.line_end),
            (Some(start), Some(end)) if start > 0 && end >= start
        )
}

fn valid_public_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | ':')
        })
}

fn is_later_in_same_artifact(earlier: &SccmEvidenceRef, later: &SccmEvidenceRef) -> bool {
    earlier.artifact_id == later.artifact_id
        && earlier
            .line_end
            .zip(later.line_start)
            .is_some_and(|(earlier_end, later_start)| later_start > earlier_end)
}

fn artifacts_for_family(
    bundle: &SccmNormalizedBundle,
    family: SccmArtifactFamily,
) -> Vec<&SccmArtifact> {
    let mut artifacts = bundle
        .artifacts
        .iter()
        .filter(|artifact| {
            artifact.role == SccmRole::Client
                && classify_artifact_name(&artifact.display_name, SccmRole::Client).family == family
        })
        .collect::<Vec<_>>();
    artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
    artifacts
}

fn coverage_gaps_for_missing_group(
    artifacts: &[&SccmArtifact],
    group_id: &str,
    force_partial: bool,
) -> Vec<SccmFindingCoverageGap> {
    if artifacts.is_empty() {
        return vec![SccmFindingCoverageGap {
            artifact_id: group_id.to_owned(),
            role: SccmRole::Client,
            coverage: SccmCoverageState::Absent,
        }];
    }

    artifacts
        .iter()
        .map(|artifact| SccmFindingCoverageGap {
            artifact_id: if valid_public_id(&artifact.artifact_id) {
                artifact.artifact_id.clone()
            } else {
                group_id.to_owned()
            },
            role: SccmRole::Client,
            coverage: if force_partial {
                SccmCoverageState::Partial
            } else if artifact.coverage == SccmCoverageState::Captured {
                SccmCoverageState::ParseFailed
            } else {
                artifact.coverage.clone()
            },
        })
        .collect()
}

fn request_for_phase(phase: SccmHealthPhase) -> SccmArtifactRequest {
    let (logical_id, reason) = match phase {
        SccmHealthPhase::Setup => ("ccmSetup", "Collect the complete CCMSetup file."),
        SccmHealthPhase::Service => ("ccmEval", "Collect the complete CcmEval file."),
        SccmHealthPhase::Identity => (
            "clientIdManagerStartup",
            "Collect the complete ClientIDManagerStartup file.",
        ),
        SccmHealthPhase::SiteAssignment
        | SccmHealthPhase::ManagementPoint
        | SccmHealthPhase::Transport => (
            "locationServices",
            "Collect the complete LocationServices file.",
        ),
    };
    SccmArtifactRequest {
        logical_id: logical_id.to_owned(),
        role: SccmRole::Client,
        reason: reason.to_owned(),
    }
}

#[allow(clippy::too_many_arguments)]
fn insufficient_finding(
    finding_id: &str,
    health_phase: SccmHealthPhase,
    last_successful_phase: Option<SccmHealthPhase>,
    title: &str,
    summary: &str,
    evidence: Vec<SccmEvidenceRef>,
    coverage_gaps: Vec<SccmFindingCoverageGap>,
    next_artifact: SccmArtifactRequest,
) -> SccmHealthFinding {
    wrap_health_finding(
        SccmFindingBuilder::new(finding_id)
            .class(SccmFindingClass::InsufficientEvidence)
            .phase(SccmPhase::Unknown("health".to_owned()))
            .role(SccmRole::Client)
            .severity(Severity::Warning)
            .confidence(SccmConfidence::Low)
            .title(title)
            .summary(summary)
            .evidence(evidence)
            .coverage_gaps(coverage_gaps)
            .next_artifact(next_artifact)
            .build()
            .expect("health insufficient-evidence finding must satisfy the shared contract"),
        health_phase,
        last_successful_phase,
    )
}

#[allow(clippy::too_many_arguments)]
fn local_symptom_finding(
    finding_id: &str,
    health_phase: SccmHealthPhase,
    last_successful_phase: Option<SccmHealthPhase>,
    title: &str,
    summary: &str,
    evidence: Vec<SccmEvidenceRef>,
    next_artifact: Option<SccmArtifactRequest>,
) -> SccmHealthFinding {
    let mut builder = SccmFindingBuilder::new(finding_id)
        .class(SccmFindingClass::Symptom)
        .phase(SccmPhase::Unknown("health".to_owned()))
        .role(SccmRole::Client)
        .severity(Severity::Warning)
        .confidence(SccmConfidence::Low)
        .title(title)
        .summary(summary)
        .evidence(evidence);
    if let Some(request) = next_artifact {
        builder = builder.next_artifact(request);
    }
    wrap_health_finding(
        builder
            .build()
            .expect("health symptom finding must satisfy the shared contract"),
        health_phase,
        last_successful_phase,
    )
}

#[allow(clippy::too_many_arguments)]
fn terminal_finding(
    finding_id: &str,
    health_phase: SccmHealthPhase,
    last_successful_phase: Option<SccmHealthPhase>,
    title: &str,
    summary: &str,
    evidence: Vec<SccmEvidenceRef>,
    terminal_reference: SccmEvidenceRef,
) -> SccmHealthFinding {
    wrap_health_finding(
        SccmFindingBuilder::new(finding_id)
            .class(SccmFindingClass::ConfirmedFailure)
            .phase(SccmPhase::Unknown("health".to_owned()))
            .role(SccmRole::Client)
            .severity(Severity::Error)
            .confidence(SccmConfidence::High)
            .title(title)
            .summary(summary)
            .evidence(evidence)
            .terminal_evidence(vec![SccmTerminalEvidence::observed_failure(
                terminal_reference,
            )])
            .build()
            .expect("health terminal finding must satisfy the shared contract"),
        health_phase,
        last_successful_phase,
    )
}

fn wrap_health_finding(
    finding: SccmFinding,
    health_phase: SccmHealthPhase,
    last_successful_phase: Option<SccmHealthPhase>,
) -> SccmHealthFinding {
    SccmHealthFinding {
        finding,
        health_phase,
        last_successful_phase,
    }
}

fn generic_location_symptom_evidence(facts: &[HealthFact]) -> Vec<SccmEvidenceRef> {
    if !facts
        .iter()
        .any(|fact| matches!(fact.kind, HealthFactKind::GenericLocationSymptom))
    {
        return Vec::new();
    }
    facts
        .iter()
        .filter(|fact| {
            matches!(
                fact.kind,
                HealthFactKind::GenericLocationSymptom | HealthFactKind::UnrelatedLocationText
            )
        })
        .map(|fact| fact.reference.clone())
        .collect()
}

fn finalize_health_analysis(
    last_successful_phase: Option<SccmHealthPhase>,
    mut findings: Vec<SccmHealthFinding>,
) -> SccmHealthAnalysis {
    findings.sort_by(|left, right| {
        left.health_phase
            .cmp(&right.health_phase)
            .then_with(|| left.finding.finding_id.cmp(&right.finding.finding_id))
    });

    let mut coverage_gaps = findings
        .iter()
        .flat_map(|finding| finding.finding.coverage_gaps.iter().cloned())
        .collect::<Vec<_>>();
    coverage_gaps.sort_by(|left, right| {
        left.artifact_id
            .cmp(&right.artifact_id)
            .then_with(|| coverage_order(&left.coverage).cmp(&coverage_order(&right.coverage)))
    });
    coverage_gaps.dedup();

    let mut artifact_requests = findings
        .iter()
        .flat_map(|finding| finding.finding.next_artifacts.iter().cloned())
        .collect::<Vec<_>>();
    artifact_requests.sort_by(|left, right| {
        left.logical_id
            .cmp(&right.logical_id)
            .then_with(|| left.reason.cmp(&right.reason))
    });
    artifact_requests.dedup();

    SccmHealthAnalysis {
        schema_version: SCCM_HEALTH_ANALYSIS_SCHEMA_VERSION,
        workflow: SccmHealthWorkflow::Health,
        last_successful_phase,
        findings,
        coverage_gaps,
        artifact_requests,
    }
}

fn compare_references(left: &SccmEvidenceRef, right: &SccmEvidenceRef) -> std::cmp::Ordering {
    left.artifact_id
        .cmp(&right.artifact_id)
        .then_with(|| left.line_start.cmp(&right.line_start))
        .then_with(|| left.line_end.cmp(&right.line_end))
        .then_with(|| left.entry_id.cmp(&right.entry_id))
}

fn coverage_order(coverage: &SccmCoverageState) -> u8 {
    match coverage {
        SccmCoverageState::Captured => 0,
        SccmCoverageState::Partial => 1,
        SccmCoverageState::Absent => 2,
        SccmCoverageState::AccessDenied => 3,
        SccmCoverageState::Capped => 4,
        SccmCoverageState::Skipped => 5,
        SccmCoverageState::Unsupported => 6,
        SccmCoverageState::ParseFailed => 7,
    }
}

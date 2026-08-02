use cmtraceopen_parser::sccm::server::windows::{
    analyze_site_core, assess_server_intake, SccmServerArtifactPayload, SccmServerIntakeAssessment,
    SccmSiteCoreConfidence, SccmSiteCorePhase, SccmSiteCoreState,
};
use cmtraceopen_parser::sccm::{SccmCoverageState, SccmFindingClass, SccmTimeOrderingState};
use serde_json::{json, Value};

const HEALTHY_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/healthy/evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
);
const HEALTHY_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/healthy/evidence/sccm/server/site-core/status/current/statmgr.log"
);
const COMPONENT_FAILURE: &str = include_str!(
    "fixtures/sccm/server/site_core/component-failure/evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
);
const INBOX_BACKLOG: &str = include_str!(
    "fixtures/sccm/server/site_core/inbox-backlog/evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
);
const STATUS_FAILURE_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/status-processing-failure/evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
);
const STATUS_FAILURE_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/status-processing-failure/evidence/sccm/server/site-core/status/current/statmgr.log"
);
const RECOVERY_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/recovery/evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
);
const RECOVERY_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/recovery/evidence/sccm/server/site-core/status/current/statmgr.log"
);
const CONTRADICTORY_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/contradictory/evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
);
const CONTRADICTORY_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/contradictory/evidence/sccm/server/site-core/status/current/statmgr.log"
);
const ROTATION_CURRENT_FRAGMENT: &str = include_str!(
    "fixtures/sccm/server/site_core/rotation-boundary/evidence/sccm/server/site-core/sitecomp/current/sitecomp.log"
);
const ROTATION_LO_FRAGMENT: &str = include_str!(
    "fixtures/sccm/server/site_core/rotation-boundary/evidence/sccm/server/site-core/sitecomp/lo_/sitecomp.lo_"
);

#[derive(Clone)]
struct Source<'a> {
    artifact_id: &'static str,
    source_id: &'static str,
    basename: &'static str,
    path_fingerprint: &'static str,
    lineage_id: &'static str,
    rotation_kind: &'static str,
    content: Option<&'a str>,
    capture_state: &'static str,
    configured_state: &'static str,
    path_class: Option<&'static str>,
    encoding: Option<&'static str>,
    limit_applied: bool,
    truncated: Option<bool>,
    fragment_complete: Option<bool>,
}

impl<'a> Source<'a> {
    fn sitecomp(content: &'a str) -> Self {
        Self {
            artifact_id: "sitecomp-current",
            source_id: "server-sitecomp",
            basename: "sitecomp.log",
            path_fingerprint: "synthetic:path:site-default",
            lineage_id: "sitecomp-lab",
            rotation_kind: "current",
            content: Some(content),
            capture_state: "captured",
            configured_state: "configured",
            path_class: None,
            encoding: Some("utf-8"),
            limit_applied: false,
            truncated: None,
            fragment_complete: None,
        }
    }

    fn status(content: &'a str) -> Self {
        Self {
            artifact_id: "z-site-status",
            source_id: "server-status",
            basename: "statmgr.log",
            path_fingerprint: "synthetic:path:z-site",
            lineage_id: "site-status-z",
            rotation_kind: "current",
            content: Some(content),
            capture_state: "captured",
            configured_state: "configured",
            path_class: None,
            encoding: Some("utf-8"),
            limit_applied: false,
            truncated: None,
            fragment_complete: None,
        }
    }

    fn absent_status() -> Self {
        Self {
            artifact_id: "z-site-status",
            source_id: "server-status",
            basename: "statmgr.log",
            path_fingerprint: "synthetic:path:z-site",
            lineage_id: "site-status-z",
            rotation_kind: "current",
            content: None,
            capture_state: "absent",
            configured_state: "defaultCandidate",
            path_class: None,
            encoding: None,
            limit_applied: false,
            truncated: None,
            fragment_complete: None,
        }
    }

    fn default_sitecomp_candidate() -> Self {
        Self {
            artifact_id: "b-sitecomp",
            source_id: "server-sitecomp",
            basename: "sitecomp.log",
            path_fingerprint: "synthetic:path:a-site",
            lineage_id: "sitecomp-a",
            rotation_kind: "current",
            content: None,
            capture_state: "absent",
            configured_state: "defaultCandidate",
            path_class: None,
            encoding: None,
            limit_applied: false,
            truncated: None,
            fragment_complete: None,
        }
    }

    fn capped_sitecomp(content: &'a str) -> Self {
        let mut source = Self::sitecomp(content);
        source.capture_state = "capped";
        source.limit_applied = true;
        source.truncated = Some(true);
        source.fragment_complete = Some(false);
        source
    }

    fn sitecomp_lo_fragment(content: &'a str) -> Self {
        Self {
            artifact_id: "b-sitecomp",
            source_id: "server-sitecomp",
            basename: "sitecomp.lo_",
            path_fingerprint: "synthetic:path:site-default",
            lineage_id: "sitecomp-lab",
            rotation_kind: "lo_",
            content: Some(content),
            capture_state: "captured",
            configured_state: "configured",
            path_class: None,
            encoding: Some("utf-8"),
            limit_applied: false,
            truncated: None,
            fragment_complete: None,
        }
    }

    fn relative_path(&self) -> Option<String> {
        self.content.map(|_| {
            let rotation = match self.rotation_kind {
                "current" => "current",
                "lo_" => "lo_",
                other => panic!("unsupported test rotation {other}"),
            };
            format!(
                "evidence/sccm/server/site-server/{}/{rotation}/{}",
                self.source_id, self.basename
            )
        })
    }

    fn manifest_artifact(&self) -> Value {
        let bytes_copied = self.content.map_or(0, |content| content.len() as u64);
        let collection_limit = self.content.map(|_| {
            json!({
                "byteLimit": if self.limit_applied { bytes_copied } else { bytes_copied.max(4096) },
                "limitApplied": self.limit_applied,
            })
        });
        json!({
            "artifactId": self.artifact_id,
            "producerRole": "siteServer",
            "producerHostHandle": "synthetic:host:site-01",
            "sourceId": self.source_id,
            "sourceKind": "ccmLog",
            "sourceVersion": "5.00.TEST",
            "originalPath": "REDACTED_SITE_ROOT",
            "originalBasename": self.basename,
            "configuredPathProvenance": {
                "state": self.configured_state,
                "pathClass": self.path_class,
                "pathFingerprint": self.path_fingerprint,
            },
            "defaultCandidateState": if self.configured_state == "defaultCandidate" {
                Some("absentCandidateOnly")
            } else {
                None
            },
            "rotation": {
                "kind": self.rotation_kind,
                "lineageId": self.lineage_id,
            },
            "captureState": self.capture_state,
            "encoding": self.encoding,
            "collectionLimit": collection_limit,
            "truncated": self.truncated,
            "fragmentComplete": self.fragment_complete,
            "collectedUtc": "2026-07-30T16:00:00Z",
            "relativePath": self.relative_path(),
            "bytesCopied": bytes_copied,
        })
    }
}

fn assess(sources: &[Source<'_>]) -> SccmServerIntakeAssessment {
    let manifest = json!({
        "sccmManifestVersion": 1,
        "syntheticFixture": true,
        "proposalOnly": true,
        "privacy": {"synthetic": true, "rawPaths": "redacted"},
        "bundleRole": "server",
        "topology": {
            "captureHost": "LAB-CM01",
            "siteCode": "LAB",
            "rolesObserved": ["siteServer"],
        },
        "artifacts": sources.iter().map(Source::manifest_artifact).collect::<Vec<_>>(),
    });
    let payloads = sources
        .iter()
        .filter_map(|source| {
            source.content.map(|content| SccmServerArtifactPayload {
                manifest_artifact_id: source.artifact_id.to_owned(),
                bytes: content.as_bytes().to_vec(),
            })
        })
        .collect::<Vec<_>>();

    assess_server_intake(&manifest.to_string(), &payloads)
        .expect("site-core test manifest must pass the shared server intake")
}

fn classifications(assessment: &SccmServerIntakeAssessment) -> Vec<Option<SccmFindingClass>> {
    analyze_site_core(assessment)
        .results
        .into_iter()
        .map(|result| result.finding_class)
        .collect()
}

#[test]
fn healthy_site_core_is_reduced_from_server_intake_without_raw_site_identity() {
    let assessment = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    let analysis = analyze_site_core(&assessment);

    assert_eq!(analysis.results.len(), 1);
    let result = &analysis.results[0];
    assert_eq!(result.state, SccmSiteCoreState::Healthy);
    assert_eq!(
        result.last_successful_phase,
        Some(SccmSiteCorePhase::HealthyOrTerminal)
    );
    assert_eq!(result.confidence, SccmSiteCoreConfidence::High);
    assert_eq!(result.transaction_key.site_handle, "synthetic:site:lab");
    assert_eq!(
        result.transaction_key.producer_host_handle,
        "synthetic:host:site-01"
    );
    assert!(analysis.findings.is_empty());

    let wire = serde_json::to_string(&analysis).expect("site-core analysis serializes");
    assert!(!wire.contains("siteCode"));
    assert!(!wire.contains("\"LAB\""));
    assert!(!wire.contains("/LAB/"));
    assert!(!wire.contains("clientImpact"));
    assert!(!analysis.cross_side_correlation_performed);
}

#[test]
fn configured_nondefault_sources_supersede_absent_default_candidates() {
    let mut sitecomp = Source::sitecomp(HEALTHY_SITECOMP);
    sitecomp.path_class = Some("nonDefault");
    let mut status = Source::status(HEALTHY_STATUS);
    status.path_class = Some("nonDefault");
    let assessment = assess(&[Source::default_sitecomp_candidate(), status, sitecomp]);
    assert!(assessment.artifacts.iter().any(|artifact| {
        artifact.configured_path_class
            == Some(
                cmtraceopen_parser::sccm::server::windows::SccmServerConfiguredPathClass::NonDefault,
            )
    }));

    let analysis = analyze_site_core(&assessment);
    assert_eq!(analysis.results.len(), 1);
    assert_eq!(analysis.results[0].state, SccmSiteCoreState::Healthy);
    assert_eq!(analysis.results[0].confidence, SccmSiteCoreConfidence::High);
    assert!(analysis
        .coverage_gaps
        .iter()
        .all(|gap| gap.artifact_id != "b-sitecomp"));
    assert!(analysis.findings.is_empty());
    assert!(analysis.artifact_requests.is_empty());
}

#[test]
fn terminal_component_and_status_outcomes_require_exact_cited_facts() {
    let component = analyze_site_core(&assess(&[
        Source::sitecomp(COMPONENT_FAILURE),
        Source::absent_status(),
    ]));
    assert_eq!(component.results.len(), 1);
    assert_eq!(
        component.results[0].state,
        SccmSiteCoreState::TerminalFailure
    );
    assert_eq!(
        component.results[0].last_successful_phase,
        Some(SccmSiteCorePhase::ComponentWork)
    );
    assert_eq!(
        component.results[0].finding_class,
        Some(SccmFindingClass::ConfirmedFailure)
    );
    assert_eq!(component.findings.len(), 1);
    assert_eq!(component.findings[0].finding.terminal_evidence.len(), 1);
    assert!(component.results[0]
        .evidence
        .iter()
        .any(|evidence| evidence.terminal == Some(true)));

    let status = analyze_site_core(&assess(&[
        Source::sitecomp(STATUS_FAILURE_SITECOMP),
        Source::status(STATUS_FAILURE_STATUS),
    ]));
    assert_eq!(status.results.len(), 1);
    assert_eq!(status.results[0].state, SccmSiteCoreState::TerminalFailure);
    assert_eq!(
        status.results[0].last_successful_phase,
        Some(SccmSiteCorePhase::StatusOrStateProcessing)
    );
    assert_eq!(status.findings[0].finding.terminal_evidence.len(), 1);
}

#[test]
fn backlog_is_deferred_and_same_component_terminal_recovery_is_cited() {
    let backlog = analyze_site_core(&assess(&[
        Source::sitecomp(INBOX_BACKLOG),
        Source::absent_status(),
    ]));
    assert_eq!(backlog.results.len(), 1);
    assert_eq!(
        backlog.results[0].state,
        SccmSiteCoreState::BlockedOrDeferred
    );
    assert_eq!(backlog.results[0].confidence, SccmSiteCoreConfidence::Low);
    assert_eq!(
        backlog.results[0].last_successful_phase,
        Some(SccmSiteCorePhase::ComponentWork)
    );
    assert!(backlog.results[0]
        .next_artifacts
        .iter()
        .any(|request| request.logical_name == "server-status"));

    let recovery = analyze_site_core(&assess(&[
        Source::sitecomp(RECOVERY_SITECOMP),
        Source::status(RECOVERY_STATUS),
    ]));
    assert_eq!(recovery.results.len(), 1);
    assert_eq!(recovery.results[0].state, SccmSiteCoreState::Recovered);
    assert_eq!(
        recovery.results[0].finding_class,
        Some(SccmFindingClass::Symptom)
    );
    assert!(recovery.results[0]
        .evidence
        .iter()
        .any(|evidence| evidence.recovery == Some(true)));
}

#[test]
fn unrelated_same_minute_components_and_producer_hosts_never_merge() {
    let assessment = assess(&[
        Source::sitecomp(CONTRADICTORY_SITECOMP),
        Source::status(CONTRADICTORY_STATUS),
    ]);
    let analysis = analyze_site_core(&assessment);
    assert_eq!(analysis.results.len(), 2);
    assert_ne!(
        analysis.results[0].transaction_key.component_id,
        analysis.results[1].transaction_key.component_id
    );
    assert!(analysis
        .results
        .iter()
        .any(|result| result.state == SccmSiteCoreState::Healthy));
    assert!(analysis
        .results
        .iter()
        .any(|result| result.state == SccmSiteCoreState::TerminalFailure));

    let mut split_hosts = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    split_hosts
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-status")
        .expect("status artifact")
        .producer_host_handle = Some("synthetic:host:site-02".to_owned());
    let split = analyze_site_core(&split_hosts);
    assert!(split.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            || result.confidence != SccmSiteCoreConfidence::High
    }));
    assert!(split.results.iter().all(|result| {
        result.transaction_key.producer_host_handle == "synthetic:host:site-01"
            || result.transaction_key.producer_host_handle == "synthetic:host:site-02"
    }));
}

#[test]
fn encoding_profile_coverage_fragment_cap_and_time_provenance_fail_closed() {
    let mut wrong_encoding = Source::sitecomp(COMPONENT_FAILURE);
    wrong_encoding.encoding = Some("windows-1252");
    let encoding = assess(&[wrong_encoding, Source::absent_status()]);

    let mut unknown_profile =
        assess(&[Source::sitecomp(COMPONENT_FAILURE), Source::absent_status()]);
    let profiled = unknown_profile
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact");
    profiled.profile_eligible = false;
    profiled.source_version = Some(
        "cmtraceopen.version.sha256.v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_owned(),
    );

    let mut denied = assess(&[Source::sitecomp(COMPONENT_FAILURE), Source::absent_status()]);
    denied
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact")
        .state = SccmCoverageState::AccessDenied;

    let mut incomplete_fragment =
        assess(&[Source::sitecomp(COMPONENT_FAILURE), Source::absent_status()]);
    incomplete_fragment
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact")
        .fragment_complete = Some(false);

    let capped = assess(&[
        Source::capped_sitecomp(COMPONENT_FAILURE),
        Source::absent_status(),
    ]);

    let mut invalid_time = assess(&[Source::sitecomp(COMPONENT_FAILURE), Source::absent_status()]);
    for evidence in &mut invalid_time.evidence {
        evidence.timestamp.offset_minutes = None;
        evidence.timestamp.utc_millis = None;
        evidence.timestamp.ordering_state = SccmTimeOrderingState::OffsetInvalid;
    }

    for (name, assessment) in [
        ("encoding", encoding),
        ("profile", unknown_profile),
        ("coverage", denied),
        ("fragment", incomplete_fragment),
        ("cap", capped),
        ("time", invalid_time),
    ] {
        let analysis = analyze_site_core(&assessment);
        assert!(
            analysis.results.iter().all(|result| {
                result.finding_class != Some(SccmFindingClass::ConfirmedFailure)
                    && result.confidence != SccmSiteCoreConfidence::High
            }),
            "{name} provenance produced a high-confidence terminal outcome"
        );
        assert!(analysis.findings.iter().all(|finding| {
            finding.finding.class != SccmFindingClass::ConfirmedFailure
                || finding.finding.confidence != cmtraceopen_parser::sccm::SccmConfidence::High
        }));
    }
}

#[test]
fn rotation_split_fragments_are_coverage_not_a_terminal_transaction() {
    let assessment = assess(&[
        Source::sitecomp(ROTATION_CURRENT_FRAGMENT),
        Source::sitecomp_lo_fragment(ROTATION_LO_FRAGMENT),
    ]);
    assert!(assessment
        .artifacts
        .iter()
        .all(|artifact| artifact.state == SccmCoverageState::ParseFailed));

    let analysis = analyze_site_core(&assessment);
    assert!(analysis.results.is_empty());
    assert_eq!(analysis.coverage_gaps.len(), 2);
    assert!(analysis
        .coverage_gaps
        .iter()
        .all(|gap| gap.state == SccmCoverageState::ParseFailed));
    assert!(analysis
        .findings
        .iter()
        .all(|finding| finding.finding.class != SccmFindingClass::ConfirmedFailure));
}

#[test]
fn incomplete_sources_are_coverage_states_not_role_health_claims() {
    let analysis = analyze_site_core(&assess(&[
        Source::capped_sitecomp(HEALTHY_SITECOMP),
        Source::absent_status(),
    ]));

    assert!(analysis.results.is_empty());
    assert!(analysis.coverage_gaps.iter().any(|gap| {
        gap.artifact_id == "sitecomp-current" && gap.state == SccmCoverageState::Capped
    }));
    assert!(analysis.coverage_gaps.iter().any(|gap| {
        gap.artifact_id == "z-site-status" && gap.state == SccmCoverageState::Absent
    }));
    assert!(analysis
        .findings
        .iter()
        .all(|finding| finding.finding.class != SccmFindingClass::ConfirmedFailure));
}

#[test]
fn site_core_output_is_byte_identical_after_assessment_reordering() {
    let assessment = assess(&[
        Source::sitecomp(CONTRADICTORY_SITECOMP),
        Source::status(CONTRADICTORY_STATUS),
    ]);
    let mut reordered = assessment.clone();
    reordered.artifacts.reverse();
    reordered.coverage.reverse();
    reordered.evidence.reverse();
    reordered.next_artifact_requests.reverse();

    assert_eq!(
        serde_json::to_vec(&analyze_site_core(&assessment)).expect("analysis serializes"),
        serde_json::to_vec(&analyze_site_core(&reordered)).expect("analysis serializes")
    );
}

#[test]
fn no_provenance_mutation_can_reintroduce_a_confirmed_failure() {
    let mut assessment = assess(&[Source::sitecomp(COMPONENT_FAILURE), Source::absent_status()]);
    assessment
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact")
        .capture_provenance
        .as_mut()
        .expect("captured source provenance")
        .limit_applied = true;

    assert!(classifications(&assessment)
        .into_iter()
        .all(|class| class != Some(SccmFindingClass::ConfirmedFailure)));
}

use cmtraceopen_parser::sccm::server::windows::{
    analyze_site_core, assess_server_intake, SccmServerArtifactPayload, SccmServerIntakeAssessment,
    SccmSiteCoreAnalysis, SccmSiteCoreArtifactRequest, SccmSiteCoreConfidence, SccmSiteCorePhase,
    SccmSiteCoreState,
};
use cmtraceopen_parser::sccm::{
    SccmCoverageState, SccmFindingClass, SccmRole, SccmRotation, SccmTimeOrderingState,
    SccmUnknownRotation,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const HEALTHY_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/healthy/evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log"
);
const HEALTHY_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/healthy/evidence/sccm/server/site-server/server-status/current/statmgr.log"
);
const COMPONENT_FAILURE: &str = include_str!(
    "fixtures/sccm/server/site_core/component-failure/evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log"
);
const INBOX_BACKLOG: &str = include_str!(
    "fixtures/sccm/server/site_core/inbox-backlog/evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log"
);
const STATUS_FAILURE_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/status-processing-failure/evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log"
);
const STATUS_FAILURE_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/status-processing-failure/evidence/sccm/server/site-server/server-status/current/statmgr.log"
);
const RECOVERY_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/recovery/evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log"
);
const RECOVERY_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/recovery/evidence/sccm/server/site-server/server-status/current/statmgr.log"
);
const CONTRADICTORY_SITECOMP: &str = include_str!(
    "fixtures/sccm/server/site_core/contradictory/evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log"
);
const CONTRADICTORY_STATUS: &str = include_str!(
    "fixtures/sccm/server/site_core/contradictory/evidence/sccm/server/site-server/server-status/current/statmgr.log"
);
const ROTATION_CURRENT_FRAGMENT: &str = include_str!(
    "fixtures/sccm/server/site_core/rotation-boundary/evidence/sccm/server/site-server/server-sitecomp/current/sitecomp.log"
);
const ROTATION_LO_FRAGMENT: &str = include_str!(
    "fixtures/sccm/server/site_core/rotation-boundary/evidence/sccm/server/site-server/server-sitecomp/lo_/sitecomp.lo_"
);
const OUT_OF_ORDER_SITECOMP: &str = concat!(
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-ORDER-001 statusId=SC_COMPONENT_START_OK outcome=success terminal=false]LOG]!><time=\"14:00:04.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"101\" file=\"sitecomp.cpp:101\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-ORDER-001 statusId=SC_COMPONENT_WORK_OK outcome=success terminal=false]LOG]!><time=\"14:00:01.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"101\" file=\"sitecomp.cpp:102\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-ORDER-001 statusId=SC_INBOX_ACCEPTED outcome=success terminal=false]LOG]!><time=\"14:00:03.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"101\" file=\"sitecomp.cpp:103\">\n",
);
const OUT_OF_ORDER_STATUS: &str = concat!(
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-ORDER-001 statusId=SC_STATUS_PROCESSING_OK outcome=success terminal=false]LOG]!><time=\"14:00:02.000+000\" date=\"07-30-2026\" component=\"SMS_STATUS_MANAGER\" context=\"\" type=\"1\" thread=\"111\" file=\"statmgr.cpp:201\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-ORDER-001 statusId=SC_COMPONENT_HEALTHY outcome=success terminal=true]LOG]!><time=\"14:00:05.000+000\" date=\"07-30-2026\" component=\"SMS_STATUS_MANAGER\" context=\"\" type=\"1\" thread=\"111\" file=\"statmgr.cpp:202\">\n",
);
const SUCCESS_AFTER_FAILURE: &str = concat!(
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-LATE-001 statusId=SC_COMPONENT_START_OK outcome=success terminal=false]LOG]!><time=\"14:10:01.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"201\" file=\"sitecomp.cpp:101\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-LATE-001 statusId=SC_COMPONENT_TERMINAL_FAILURE outcome=failure terminal=true]LOG]!><time=\"14:10:02.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"3\" thread=\"201\" file=\"sitecomp.cpp:190\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-LATE-001 statusId=SC_COMPONENT_WORK_OK outcome=success terminal=false]LOG]!><time=\"14:10:03.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"201\" file=\"sitecomp.cpp:102\">\n",
);
const DEFERRED_THEN_ACCEPTED: &str = concat!(
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-DEFER-001 statusId=SC_COMPONENT_START_OK outcome=success terminal=false]LOG]!><time=\"14:20:01.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"301\" file=\"sitecomp.cpp:101\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-DEFER-001 statusId=SC_COMPONENT_WORK_OK outcome=success terminal=false]LOG]!><time=\"14:20:02.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"301\" file=\"sitecomp.cpp:102\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-DEFER-001 statusId=SC_INBOX_BACKLOG outcome=deferred terminal=false queueDepth=17]LOG]!><time=\"14:20:03.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"2\" thread=\"301\" file=\"sitecomp.cpp:150\">\n",
    "<![LOG[profileId=sccm-site-core profileVersion=1 site=LAB componentId=SMS_EXECUTIVE workItemId=SC-DEFER-001 statusId=SC_INBOX_ACCEPTED outcome=success terminal=false]LOG]!><time=\"14:20:04.000+000\" date=\"07-30-2026\" component=\"SMS_SITE_COMPONENT_MANAGER\" context=\"\" type=\"1\" thread=\"301\" file=\"sitecomp.cpp:151\">\n",
);

#[derive(Clone)]
struct Source<'a> {
    artifact_id: &'static str,
    source_id: &'static str,
    basename: &'static str,
    path_fingerprint: &'static str,
    lineage_id: &'static str,
    rotation_kind: &'static str,
    rotation_value: Option<Value>,
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
            rotation_value: None,
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
            rotation_value: None,
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
            rotation_value: None,
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
            rotation_value: None,
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
            rotation_value: None,
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

    fn numbered_status(content: &'a str) -> Self {
        let mut source = Self::status(content);
        source.basename = "statmgr.log.2";
        source.rotation_kind = "numbered";
        source.rotation_value = Some(json!(2));
        source
    }

    fn relative_path(&self) -> Option<String> {
        self.content.map(|_| {
            let rotation = match self.rotation_kind {
                "current" => "current",
                "lo_" => "lo_",
                "numbered" => "numbered-2",
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
                "value": self.rotation_value,
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

fn assert_bounded_request_has_specific_scope(request: &SccmSiteCoreArtifactRequest) {
    assert!((1..=2).contains(&request.max_artifacts));
    assert!(!request.candidates.is_empty());
    assert!(request.candidates.len() <= request.max_artifacts);
    assert!(request.candidates.iter().all(|candidate| {
        !candidate.basename.trim().is_empty() && !candidate.rotation.trim().is_empty()
    }));
    assert!(
        request
            .scope
            .producer_host_handle
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
            || request
                .scope
                .component_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || request
                .scope
                .work_item_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty())
            || request
                .scope
                .rotation_lineage_handle
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
        "request {} serialized an empty or unusable scope",
        request.logical_name
    );
}

fn assert_explicit_gap_and_request(
    analysis: &SccmSiteCoreAnalysis,
    artifact_id: &str,
    source_id: &str,
) {
    assert!(analysis.coverage_gaps.iter().any(|gap| {
        gap.artifact_id == artifact_id && gap.state == SccmCoverageState::ParseFailed
    }));
    assert!(analysis.unlinked_observations.iter().any(|observation| {
        observation.finding_class == SccmFindingClass::InsufficientEvidence
            && observation
                .coverage_gap_artifact_ids
                .iter()
                .any(|candidate| candidate == artifact_id)
    }));
    let request = analysis
        .artifact_requests
        .iter()
        .find(|request| request.logical_name == source_id)
        .expect("coverage gap has a source-specific artifact request");
    assert_bounded_request_has_specific_scope(request);
    for request in &analysis.artifact_requests {
        assert_bounded_request_has_specific_scope(request);
    }
}

fn assert_gap_reason(analysis: &SccmSiteCoreAnalysis, artifact_id: &str, reason_code: &str) {
    assert!(analysis.coverage_gaps.iter().any(|gap| {
        gap.artifact_id == artifact_id
            && gap.state == SccmCoverageState::ParseFailed
            && gap.reason_code == reason_code
    }));
}

fn assert_delimiter_attached_unknown_label_fails_closed(delimiter: char) {
    for (position, outcome_field) in [
        (
            "after-known",
            format!("outcome=success{delimiter}unreviewed=x"),
        ),
        (
            "before-known",
            format!("unreviewed=x{delimiter}outcome=success"),
        ),
    ] {
        let sitecomp = HEALTHY_SITECOMP.replace("outcome=success", &outcome_field);
        let status = HEALTHY_STATUS.replace("outcome=success", &outcome_field);
        let assessment = assess(&[Source::sitecomp(&sitecomp), Source::status(&status)]);
        let expected_observations = assessment.evidence.len();
        let analysis = analyze_site_core(&assessment);

        assert!(
            analysis.results.is_empty(),
            "delimiter {delimiter:?} {position} must not create a transaction"
        );
        assert_eq!(
            analysis.unlinked_observations.len(),
            expected_observations,
            "delimiter {delimiter:?} {position} must retain every rejected record"
        );
        assert_eq!(analysis.findings.len(), expected_observations);
        assert!(analysis.unlinked_observations.iter().all(|observation| {
            observation.finding_class == SccmFindingClass::Symptom
                && observation.evidence.len() == 1
                && observation.next_artifacts.len() == 1
                && observation.next_artifacts[0].candidates.len() == 1
        }));
        assert!(analysis
            .findings
            .iter()
            .all(|finding| finding.finding.class == SccmFindingClass::Symptom));
    }
}

fn site_core_corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sccm/server/site_core")
}

fn load_corpus_scenario(scenario: &str) -> (SccmServerIntakeAssessment, Value) {
    let root = site_core_corpus_root().join(scenario);
    let manifest_path = root.join("manifest.json");
    let manifest_json = fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    let manifest: Value = serde_json::from_str(&manifest_json)
        .unwrap_or_else(|error| panic!("parse {}: {error}", manifest_path.display()));
    let payloads = manifest["artifacts"]
        .as_array()
        .expect("corpus manifest artifacts")
        .iter()
        .filter_map(|artifact| {
            let relative_path = artifact["relativePath"].as_str()?;
            let artifact_id = artifact["artifactId"].as_str().expect("corpus artifact id");
            let evidence_path = root.join(relative_path);
            Some(SccmServerArtifactPayload {
                manifest_artifact_id: artifact_id.to_owned(),
                bytes: fs::read(&evidence_path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", evidence_path.display())),
            })
        })
        .collect::<Vec<_>>();
    let assessment = assess_server_intake(&manifest_json, &payloads)
        .unwrap_or_else(|error| panic!("assess corpus scenario {scenario}: {error}"));
    let expected_path = root.join("expected.json");
    let expected = serde_json::from_str(
        &fs::read_to_string(&expected_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", expected_path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", expected_path.display()));
    (assessment, expected)
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
    assert!(analysis.coverage_gaps.is_empty());
    assert!(analysis.findings.is_empty());
    assert!(analysis.artifact_requests.is_empty());
}

#[test]
fn complete_catalogued_rotations_remain_profile_usable() {
    let assessment = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::numbered_status(HEALTHY_STATUS),
    ]);
    let analysis = analyze_site_core(&assessment);

    assert_eq!(analysis.results.len(), 1);
    assert_eq!(analysis.results[0].state, SccmSiteCoreState::Healthy);
    assert_eq!(analysis.results[0].confidence, SccmSiteCoreConfidence::High);
}

#[test]
fn phase_order_and_post_terminal_evidence_fail_closed() {
    let out_of_order = analyze_site_core(&assess(&[
        Source::sitecomp(OUT_OF_ORDER_SITECOMP),
        Source::status(OUT_OF_ORDER_STATUS),
    ]));
    assert_eq!(out_of_order.results.len(), 1);
    assert!(out_of_order.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            && result.confidence != SccmSiteCoreConfidence::High
    }));

    let later_success = analyze_site_core(&assess(&[
        Source::sitecomp(SUCCESS_AFTER_FAILURE),
        Source::absent_status(),
    ]));
    assert_eq!(later_success.results.len(), 1);
    assert!(later_success.results.iter().all(|result| {
        result.finding_class != Some(SccmFindingClass::ConfirmedFailure)
            && result.confidence != SccmSiteCoreConfidence::High
    }));
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
    assert_eq!(component.findings.len(), 2);
    let component_failure = component
        .findings
        .iter()
        .find(|finding| finding.finding.class == SccmFindingClass::ConfirmedFailure)
        .expect("confirmed component failure finding");
    assert_eq!(component_failure.finding.terminal_evidence.len(), 1);
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
    assert_eq!(
        status.results[0].finding_class,
        Some(SccmFindingClass::ConfirmedFailure)
    );
    assert_eq!(status.findings.len(), 1);
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
    assert_eq!(split.results.len(), 2);
    assert_ne!(
        split.results[0].transaction_key.producer_host_handle,
        split.results[1].transaction_key.producer_host_handle
    );
    assert!(split.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            || result.confidence != SccmSiteCoreConfidence::High
    }));
    assert!(split
        .results
        .iter()
        .any(|result| { result.transaction_key.producer_host_handle == "synthetic:host:site-01" }));
    assert!(split
        .results
        .iter()
        .any(|result| { result.transaction_key.producer_host_handle == "synthetic:host:site-02" }));

    let mut foreign_gap = assess(&[Source::sitecomp(HEALTHY_SITECOMP), Source::absent_status()]);
    foreign_gap
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-status")
        .expect("status artifact")
        .producer_host_handle = Some("synthetic:host:site-02".to_owned());
    let foreign_gap_analysis = analyze_site_core(&foreign_gap);
    assert_eq!(foreign_gap_analysis.results.len(), 1);
    assert!(foreign_gap_analysis.results[0]
        .coverage_gap_artifact_ids
        .is_empty());
    assert!(!foreign_gap_analysis.results[0].next_artifacts.is_empty());
    assert!(foreign_gap_analysis.results[0]
        .next_artifacts
        .iter()
        .all(|request| request.scope.producer_host_handle.as_deref()
            == Some("synthetic:host:site-01")));
    for request in &foreign_gap_analysis.results[0].next_artifacts {
        assert_bounded_request_has_specific_scope(request);
    }
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

    let mut missing_content_provenance =
        assess(&[Source::sitecomp(COMPONENT_FAILURE), Source::absent_status()]);
    let missing_content = missing_content_provenance
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact");
    missing_content.content_sha256 = None;
    missing_content.relative_path = None;

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
        ("content", missing_content_provenance),
        ("cap", capped),
        ("time", invalid_time),
    ] {
        let analysis = analyze_site_core(&assessment);
        assert!(
            !analysis.coverage_gaps.is_empty(),
            "{name} provenance must remain an explicit coverage gap"
        );
        assert!(
            !analysis.unlinked_observations.is_empty(),
            "{name} provenance must remain an explicit observation"
        );
        assert!(
            !analysis.artifact_requests.is_empty(),
            "{name} provenance must retain an actionable request"
        );
        assert!(
            !analysis.findings.is_empty(),
            "{name} provenance must retain a conservative finding"
        );
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
    assert_eq!(assessment.artifacts.len(), 2);
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
    assert_eq!(analysis.findings.len(), 2);
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
    assert!(!analysis.findings.is_empty());
    assert!(analysis
        .findings
        .iter()
        .all(|finding| finding.finding.class != SccmFindingClass::ConfirmedFailure));
}

#[test]
fn undeclared_status_source_is_an_explicit_host_scoped_coverage_gap() {
    let assessment = assess(&[Source::sitecomp(HEALTHY_SITECOMP)]);
    assert!(assessment
        .artifacts
        .iter()
        .all(|artifact| artifact.source_id != "server-status"));
    assert!(!assessment.evidence.is_empty());

    let analysis = analyze_site_core(&assessment);
    assert_eq!(analysis.results.len(), 1);
    let result = &analysis.results[0];
    assert_eq!(result.state, SccmSiteCoreState::Incomplete);
    assert_eq!(
        result.finding_class,
        Some(SccmFindingClass::InsufficientEvidence)
    );
    assert!(!result.evidence.is_empty());

    assert_eq!(analysis.coverage_gaps.len(), 1);
    let gap = &analysis.coverage_gaps[0];
    assert_eq!(gap.source_id, "server-status");
    assert_eq!(gap.state, SccmCoverageState::Absent);
    assert_eq!(gap.reason_code, "required-status-source-not-declared");
    assert!(gap.artifact_id.starts_with("site-core:missing-source:v1:"));
    assert_eq!(
        result.coverage_gap_artifact_ids,
        vec![gap.artifact_id.clone()]
    );

    let result_finding = analysis
        .findings
        .iter()
        .find(|finding| finding.subject_id == result.result_id)
        .expect("insufficient-evidence result has a validated finding");
    assert_eq!(
        result_finding.finding.class,
        SccmFindingClass::InsufficientEvidence
    );
    assert!(result_finding
        .finding
        .coverage_gaps
        .iter()
        .any(|finding_gap| finding_gap.artifact_id == gap.artifact_id));

    let status_requests = analysis
        .artifact_requests
        .iter()
        .filter(|request| request.logical_name == "server-status")
        .collect::<Vec<_>>();
    assert!(!status_requests.is_empty());
    for request in status_requests {
        assert_bounded_request_has_specific_scope(request);
        assert_eq!(
            request.scope.producer_host_handle.as_deref(),
            Some("synthetic:host:site-01")
        );
    }
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

    let analysis = analyze_site_core(&assessment);
    assert!(analysis.results.is_empty());
    assert!(analysis
        .coverage_gaps
        .iter()
        .any(|gap| gap.artifact_id == "sitecomp-current"));
    let request = analysis
        .artifact_requests
        .iter()
        .find(|request| request.logical_name == "server-sitecomp")
        .expect("provenance coverage gap has a request");
    assert_bounded_request_has_specific_scope(request);
}

#[test]
fn rejected_role_subject_and_duplicate_sources_become_explicit_parse_gaps() {
    let healthy = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);

    let mut wrong_role = healthy.clone();
    wrong_role
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-status")
        .expect("status artifact")
        .producer_role = SccmRole::ManagementPoint;
    assert_explicit_gap_and_request(
        &analyze_site_core(&wrong_role),
        "z-site-status",
        "server-status",
    );

    let mut wrong_subject = healthy.clone();
    let sitecomp = wrong_subject
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact");
    sitecomp.workflow_subject_role = Some(SccmRole::Client);
    sitecomp.workflow_subject_handle = Some("synthetic:subject:client-01".to_owned());
    assert_explicit_gap_and_request(
        &analyze_site_core(&wrong_subject),
        "sitecomp-current",
        "server-sitecomp",
    );

    let mut duplicate = healthy;
    let duplicate_sitecomp = duplicate
        .artifacts
        .iter()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact")
        .clone();
    duplicate.artifacts.push(duplicate_sitecomp);
    assert_explicit_gap_and_request(
        &analyze_site_core(&duplicate),
        "sitecomp-current",
        "server-sitecomp",
    );

    let mut rejected_shape = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    rejected_shape
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-status")
        .expect("status artifact")
        .original_basename = Some("future-status.bin".to_owned());
    assert_explicit_gap_and_request(
        &analyze_site_core(&rejected_shape),
        "z-site-status",
        "server-status",
    );
}

#[test]
fn rejected_evidence_contracts_become_source_gaps_with_scoped_requests() {
    let healthy = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);

    let mut wrong_role = healthy.clone();
    wrong_role.evidence[0].role = SccmRole::ManagementPoint;
    let analysis = analyze_site_core(&wrong_role);
    assert_explicit_gap_and_request(&analysis, "sitecomp-current", "server-sitecomp");
    assert_gap_reason(&analysis, "sitecomp-current", "evidence-role-rejected");
    assert!(analysis.unlinked_observations.iter().any(|observation| {
        observation.finding_class == SccmFindingClass::Symptom
            && observation
                .evidence
                .iter()
                .any(|evidence| evidence.entry_id == wrong_role.evidence[0].evidence_id)
    }));
    assert_eq!(analysis.results.len(), 1);
    assert!(analysis.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            || result.confidence != SccmSiteCoreConfidence::High
    }));

    let mut incomplete_reference = healthy.clone();
    incomplete_reference.evidence[0].reference.line_end = None;
    let analysis = analyze_site_core(&incomplete_reference);
    assert_explicit_gap_and_request(&analysis, "sitecomp-current", "server-sitecomp");
    assert_gap_reason(&analysis, "sitecomp-current", "evidence-reference-rejected");
    assert!(analysis.unlinked_observations.iter().any(|observation| {
        observation.finding_class == SccmFindingClass::Symptom && observation.evidence.is_empty()
    }));
    assert_eq!(analysis.results.len(), 1);
    assert!(analysis.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            || result.confidence != SccmSiteCoreConfidence::High
    }));

    let mut cross_source_reference = healthy.clone();
    cross_source_reference.evidence[0].reference.artifact_id = "z-site-status".to_owned();
    cross_source_reference.evidence[0].reference.line_start = Some(10_001);
    cross_source_reference.evidence[0].reference.line_end = Some(10_001);
    let analysis = analyze_site_core(&cross_source_reference);
    assert_explicit_gap_and_request(&analysis, "z-site-status", "server-status");
    assert_gap_reason(
        &analysis,
        "z-site-status",
        "evidence-source-attribution-rejected",
    );
    assert!(analysis.unlinked_observations.iter().any(|observation| {
        observation.finding_class == SccmFindingClass::Symptom
            && observation
                .evidence
                .iter()
                .any(|evidence| evidence.entry_id == cross_source_reference.evidence[0].evidence_id)
    }));
    assert_eq!(analysis.results.len(), 1);
    assert!(analysis.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            || result.confidence != SccmSiteCoreConfidence::High
    }));

    let mut unresolved_reference = healthy;
    unresolved_reference.evidence[0].reference.artifact_id = "orphan-sitecomp-record".to_owned();
    let analysis = analyze_site_core(&unresolved_reference);
    assert_explicit_gap_and_request(&analysis, "orphan-sitecomp-record", "server-sitecomp");
    assert_gap_reason(
        &analysis,
        "orphan-sitecomp-record",
        "evidence-source-unresolved",
    );
    assert_eq!(analysis.results.len(), 1);
    assert!(analysis.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            || result.confidence != SccmSiteCoreConfidence::High
    }));
}

#[test]
fn foreign_artifact_identity_cannot_scope_an_unresolved_site_core_request() {
    let mut assessment = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    let mut foreign_artifact = assessment.artifacts[0].clone();
    foreign_artifact.artifact_id = "foreign-artifact".to_owned();
    foreign_artifact.source_id = "server-foreign".to_owned();
    foreign_artifact.producer_host_handle = Some("synthetic:host:foreign".to_owned());
    foreign_artifact.rotation_lineage_handle = "foreign-lineage".to_owned();
    assessment.artifacts.push(foreign_artifact);
    assessment.evidence[0].reference.artifact_id = "foreign-artifact".to_owned();

    let analysis = analyze_site_core(&assessment);
    let gap = analysis
        .coverage_gaps
        .iter()
        .find(|gap| {
            gap.source_id == "server-sitecomp" && gap.reason_code == "evidence-source-unresolved"
        })
        .expect("foreign attribution becomes a site-core coverage gap");
    assert_ne!(gap.artifact_id, "foreign-artifact");
    assert!(gap
        .artifact_id
        .starts_with("site-core:rejected-artifact:v1:"));
    let request = analysis
        .artifact_requests
        .iter()
        .find(|request| request.logical_name == "server-sitecomp")
        .expect("unresolved site-core evidence has a bounded request");
    assert_bounded_request_has_specific_scope(request);
    assert_eq!(
        request.scope.producer_host_handle.as_deref(),
        Some("synthetic:host:site-01")
    );
    assert_ne!(
        request.scope.rotation_lineage_handle.as_deref(),
        Some("foreign-lineage")
    );
}

#[test]
fn rejected_nonprofile_prose_is_coverage_not_a_profile_symptom() {
    let mut assessment = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    assessment.evidence[0].message = "ordinary non-profile source prose".to_owned();
    assessment.evidence[0].role = SccmRole::ManagementPoint;

    let analysis = analyze_site_core(&assessment);
    assert_explicit_gap_and_request(&analysis, "sitecomp-current", "server-sitecomp");
    assert_gap_reason(&analysis, "sitecomp-current", "evidence-role-rejected");
    assert_eq!(analysis.unlinked_observations.len(), 1);
    assert_eq!(
        analysis.unlinked_observations[0].finding_class,
        SccmFindingClass::InsufficientEvidence
    );
    assert!(analysis.unlinked_observations[0].evidence.is_empty());
}

#[test]
fn colliding_evidence_identities_are_parse_gaps_not_silent_drops() {
    let mut assessment = assess(&[Source::sitecomp(HEALTHY_SITECOMP), Source::absent_status()]);
    let duplicate = assessment.evidence[0].clone();
    assessment.evidence.push(duplicate);

    let analysis = analyze_site_core(&assessment);
    assert_explicit_gap_and_request(&analysis, "sitecomp-current", "server-sitecomp");
    assert!(analysis.results.is_empty());
}

#[test]
fn closed_profile_schema_rejects_arbitrary_keys_and_retains_safe_unknown_facts() {
    let mut arbitrary_work = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    for evidence in &mut arbitrary_work.evidence {
        evidence.message = evidence
            .message
            .replace("workItemId=SC-HEALTH-001", "workItemId=ARBITRARY-001");
    }
    let arbitrary = analyze_site_core(&arbitrary_work);
    assert!(arbitrary.results.is_empty());
    assert_eq!(
        arbitrary.unlinked_observations.len(),
        arbitrary_work.evidence.len()
    );
    let arbitrary_wire = serde_json::to_string(&arbitrary).expect("analysis serializes");
    assert!(arbitrary_work
        .evidence
        .iter()
        .all(|evidence| arbitrary_wire.contains(&evidence.evidence_id)));

    let mut unknown_status = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    let rejected_id = unknown_status.evidence[0].evidence_id.clone();
    unknown_status.evidence[0].message = unknown_status.evidence[0]
        .message
        .replace("SC_COMPONENT_START_OK", "SC_UNREVIEWED_STATUS");
    let unknown = analyze_site_core(&unknown_status);
    let unknown_wire = serde_json::to_string(&unknown).expect("analysis serializes");
    assert!(unknown_wire.contains(&rejected_id));
    let observation = unknown
        .unlinked_observations
        .iter()
        .find(|observation| {
            observation
                .evidence
                .iter()
                .any(|evidence| evidence.entry_id == rejected_id)
        })
        .expect("rejected record remains a source-local observation");
    assert_eq!(observation.finding_class, SccmFindingClass::Symptom);
    assert_eq!(observation.coverage_gap_artifact_ids, Vec::<String>::new());
    assert_eq!(observation.next_artifacts.len(), 1);
    assert_eq!(observation.next_artifacts[0].candidates.len(), 1);
    assert_eq!(
        observation.next_artifacts[0].candidates[0].basename,
        "sitecomp.log"
    );
    assert_eq!(
        observation.next_artifacts[0].candidates[0].rotation,
        "current"
    );
    let finding = unknown
        .findings
        .iter()
        .find(|finding| finding.subject_id == observation.observation_id)
        .expect("rejected record has a conservative finding");
    assert_eq!(
        finding.finding.title,
        "Unrecognized site core profile record"
    );
    assert!(finding.finding.coverage_gaps.is_empty());
}

#[test]
fn semicolon_attached_unknown_profile_labels_fail_closed_in_both_orders() {
    assert_delimiter_attached_unknown_label_fails_closed(';');
}

#[test]
fn comma_attached_unknown_profile_labels_fail_closed_in_both_orders() {
    assert_delimiter_attached_unknown_label_fails_closed(',');
}

#[test]
fn ampersand_attached_unknown_profile_labels_fail_closed_in_both_orders() {
    assert_delimiter_attached_unknown_label_fails_closed('&');
}

#[test]
fn delimiter_separated_known_profile_labels_and_safe_prose_remain_accepted() {
    for delimiter in [';', ',', '&'] {
        let joined_fields =
            format!("outcome=success{delimiter}terminal=false harmless prose tokens");
        let sitecomp = HEALTHY_SITECOMP.replace("outcome=success terminal=false", &joined_fields);
        let status = HEALTHY_STATUS.replace("outcome=success terminal=false", &joined_fields);
        let analysis = analyze_site_core(&assess(&[
            Source::sitecomp(&sitecomp),
            Source::status(&status),
        ]));

        assert_eq!(analysis.results.len(), 1, "delimiter {delimiter:?}");
        assert_eq!(
            analysis.results[0].state,
            SccmSiteCoreState::Healthy,
            "delimiter {delimiter:?}"
        );
        assert!(
            analysis.unlinked_observations.is_empty(),
            "delimiter {delimiter:?}"
        );
    }
}

#[test]
fn every_required_source_coverage_state_emits_insufficient_evidence_and_a_request() {
    for state in [
        SccmCoverageState::Absent,
        SccmCoverageState::AccessDenied,
        SccmCoverageState::Skipped,
        SccmCoverageState::Unsupported,
    ] {
        let mut assessment = assess(&[
            Source::sitecomp(HEALTHY_SITECOMP),
            Source::status(HEALTHY_STATUS),
        ]);
        assessment
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.source_id == "server-sitecomp")
            .expect("sitecomp artifact")
            .state = state.clone();
        assessment
            .coverage
            .iter_mut()
            .find(|coverage| coverage.source_id == "server-sitecomp")
            .expect("sitecomp coverage")
            .state = state.clone();

        let analysis = analyze_site_core(&assessment);
        assert!(analysis
            .coverage_gaps
            .iter()
            .any(|gap| { gap.artifact_id == "sitecomp-current" && gap.state == state }));
        assert!(analysis.unlinked_observations.iter().any(|observation| {
            observation.finding_class == SccmFindingClass::InsufficientEvidence
                && observation
                    .coverage_gap_artifact_ids
                    .contains(&"sitecomp-current".to_owned())
        }));
        assert!(analysis
            .artifact_requests
            .iter()
            .any(|request| request.logical_name == "server-sitecomp"));
        assert_eq!(analysis.results.len(), 1);
        assert!(analysis.results.iter().all(|result| {
            result.state != SccmSiteCoreState::Healthy
                && result.finding_class != Some(SccmFindingClass::ConfirmedFailure)
        }));
    }
}

#[test]
fn generated_result_and_finding_ids_are_bounded_stable_and_opaque() {
    let analysis = analyze_site_core(&assess(&[
        Source::sitecomp(COMPONENT_FAILURE),
        Source::absent_status(),
    ]));
    assert_eq!(analysis.results.len(), 1);
    assert_eq!(analysis.findings.len(), 2);
    let result = &analysis.results[0];
    assert!(result.result_id.starts_with("site-core:result:v1:"));
    assert_eq!(result.result_id.len(), "site-core:result:v1:".len() + 64);
    assert!(!result
        .result_id
        .contains(&result.transaction_key.component_id));
    assert!(!result
        .result_id
        .contains(&result.transaction_key.work_item_id));
    assert!(analysis.findings.iter().all(|finding| {
        finding
            .finding
            .finding_id
            .starts_with("site-core:finding:v1:")
            && finding.finding.finding_id.len() == "site-core:finding:v1:".len() + 64
    }));
}

#[test]
fn invalid_finding_inputs_become_explicit_gaps_instead_of_clearing_class() {
    let mut assessment = assess(&[Source::sitecomp(COMPONENT_FAILURE), Source::absent_status()]);
    let oversized_id = "a".repeat(300);
    assessment
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact")
        .artifact_id = oversized_id.clone();
    for coverage in &mut assessment.coverage {
        for artifact_id in &mut coverage.artifact_ids {
            if artifact_id == "sitecomp-current" {
                *artifact_id = oversized_id.clone();
            }
        }
    }
    for evidence in &mut assessment.evidence {
        if evidence.reference.artifact_id == "sitecomp-current" {
            evidence.reference.artifact_id = oversized_id.clone();
            evidence.evidence_id = format!("{oversized_id}:{}", evidence.evidence_id);
            evidence.reference.entry_id = evidence.evidence_id.clone();
        }
    }

    let analysis = analyze_site_core(&assessment);
    assert!(analysis.results.is_empty());
    assert!(!analysis.unlinked_observations.is_empty());
    assert!(!analysis.artifact_requests.is_empty());
}

#[test]
fn committed_site_core_corpus_exactly_matches_every_serialized_output() {
    let scenarios = [
        "healthy",
        "component-failure",
        "inbox-backlog",
        "status-processing-failure",
        "recovery",
        "contradictory",
        "rotation-boundary",
        "incomplete",
        "malformed",
    ];
    let corpus = scenarios
        .iter()
        .map(|scenario| load_corpus_scenario(scenario))
        .collect::<Vec<_>>();
    for (scenario, (assessment, expected)) in scenarios.into_iter().zip(corpus) {
        assert_eq!(
            serde_json::to_value(analyze_site_core(&assessment))
                .expect("site-core analysis serializes"),
            expected,
            "corpus scenario {scenario} diverged"
        );
    }
}

#[test]
fn later_same_phase_success_clears_deferred_but_unrecovered_deferred_remains() {
    let cleared = analyze_site_core(&assess(&[
        Source::sitecomp(DEFERRED_THEN_ACCEPTED),
        Source::absent_status(),
    ]));
    assert_eq!(cleared.results.len(), 1);
    assert_eq!(cleared.results[0].state, SccmSiteCoreState::Incomplete);
    assert_eq!(
        cleared.results[0].finding_class,
        Some(SccmFindingClass::InsufficientEvidence)
    );

    let pending = analyze_site_core(&assess(&[
        Source::sitecomp(INBOX_BACKLOG),
        Source::absent_status(),
    ]));
    assert_eq!(pending.results.len(), 1);
    assert_eq!(
        pending.results[0].state,
        SccmSiteCoreState::BlockedOrDeferred
    );
}

#[test]
fn rotation_provenance_must_match_classification_and_requests_use_exact_pairs() {
    let mut mismatch = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    mismatch
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact")
        .rotation = Some(SccmRotation::LoUnderscore);
    let rejected = analyze_site_core(&mismatch);
    assert_explicit_gap_and_request(&rejected, "sitecomp-current", "server-sitecomp");
    assert_eq!(rejected.results.len(), 1);
    assert!(rejected.results.iter().all(|result| {
        result.state != SccmSiteCoreState::Healthy
            || result.confidence != SccmSiteCoreConfidence::High
    }));

    let backlog = analyze_site_core(&assess(&[
        Source::sitecomp(INBOX_BACKLOG),
        Source::absent_status(),
    ]));
    let request = backlog
        .artifact_requests
        .iter()
        .find(|request| request.logical_name == "server-status")
        .expect("bounded status request");
    let request_wire = serde_json::to_value(request).expect("request serializes");
    assert_eq!(
        request_wire["candidates"],
        json!([
            {"basename": "statmgr.log", "rotation": "current"},
            {"basename": "statmgr.lo_", "rotation": "loUnderscore"}
        ])
    );
    assert!(request_wire.get("basenames").is_none());
    assert!(request_wire.get("rotations").is_none());

    let mut unknown_rotation = assess(&[
        Source::capped_sitecomp(HEALTHY_SITECOMP),
        Source::absent_status(),
    ]);
    unknown_rotation
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.source_id == "server-sitecomp")
        .expect("sitecomp artifact")
        .rotation = Some(SccmRotation::Unknown(SccmUnknownRotation {
        kind: "future".to_owned(),
        value: None,
    }));
    let unknown = analyze_site_core(&unknown_rotation);
    assert!(!unknown.artifact_requests.is_empty());
    for request in &unknown.artifact_requests {
        assert_bounded_request_has_specific_scope(request);
    }
}

#[test]
fn intake_coverage_must_be_congruent_before_facts_can_shape_results() {
    let mut assessment = assess(&[
        Source::sitecomp(HEALTHY_SITECOMP),
        Source::status(HEALTHY_STATUS),
    ]);
    assessment.coverage.clear();

    let analysis = analyze_site_core(&assessment);
    assert!(analysis.results.is_empty());
    assert!(!analysis.coverage_gaps.is_empty());
    assert!(!analysis.unlinked_observations.is_empty());
    assert!(!analysis.artifact_requests.is_empty());
}

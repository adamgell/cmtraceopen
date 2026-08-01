//! Corpus contract tests for the Intune macOS app leaves (issue #361).
//!
//! Two corpora, two analyzers, one shared raw grammar. Each scenario is driven
//! end to end: the manifest is turned into analyzer inputs exactly as a native
//! collector would supply them, the analyzer runs, and `expected.json` is
//! asserted against the reduced snapshot.
//!
//! The shared harness in `tests/support/` owns everything every Intune corpus
//! must satisfy — manifest envelope, byte-count truth, evidence closure, the
//! synthetic marker, capture-state/coverage binding, and the privacy scan. What
//! lives here is what only issue #361 can assert: that package and script
//! transactions reduce to the right terminal states, and that the two never
//! merge.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use support::{corpus_root, load_json, mutated, scenario_names, validate_scenario, Failures};

use cmtraceopen_parser::intune::apps::macos::pkg::{
    analyze_pkg_bundle, redacted_export_projection as redact_pkg, MacAgentArtifactInput,
    MacAgentCaptureState, PkgSnapshot,
};
use cmtraceopen_parser::intune::apps::macos::shell_scripts::{
    analyze_shell_script_bundle, redacted_export_projection as redact_shell, ShellScriptSnapshot,
};

const PKG_CORPUS: &str = "apps/macos/pkg";
const SHELL_CORPUS: &str = "apps/macos/shell-scripts";

/// The package fixture matrix issue #361 requires.
///
/// Pinned as a constant so that deleting a scenario is a test failure rather
/// than a silently smaller run. The first nine are the package matrix; the rest
/// are the shared raw-grammar concerns every leaf of the epic must prove.
const PKG_SCENARIOS: &[&str] = &[
    "current-plus-rotation",
    "deterministic-ordering",
    "download-failure",
    "duplicate-record",
    "encoding-bom-variant",
    "incomplete-coverage",
    "installer-nonzero-exit",
    "malformed-pipe-record",
    "reporting-failure",
    "retry-then-install",
    "signature-validation-failure",
    "success-missing-post-detection",
    "successful-install",
    "unknown-agent-version",
    "unknown-app-type",
];

/// The shell-script fixture matrix issue #361 requires.
const SHELL_SCENARIOS: &[&str] = &[
    "current-plus-rotation",
    "deterministic-ordering",
    "duplicate-record",
    "encoding-bom-variant",
    "launch-failure",
    "malformed-pipe-record",
    "missing-output",
    "nonzero-exit",
    "privacy-redaction",
    "report-failure",
    "retry-then-success",
    "same-minute-distinct-scripts",
    "successful-system-run",
    "successful-user-run",
    "timeout",
    "unknown-agent-version",
];

// ── Loading ─────────────────────────────────────────────────────────────────

fn scenario_root(corpus: &str, scenario: &str) -> PathBuf {
    corpus_root(corpus).join(scenario)
}

fn pair(corpus: &str, scenario: &str) -> (Value, Value) {
    let root = scenario_root(corpus, scenario);
    (
        load_json(&root.join("manifest.json")),
        load_json(&root.join("expected.json")),
    )
}

/// Turn a manifest into analyzer inputs, exactly as a native collector would.
///
/// This is the point of the corpus: the analyzer is fed supplied facts and
/// decoded text, never a path it opens itself.
fn inputs_from(manifest: &Value, root: &Path) -> Vec<MacAgentArtifactInput> {
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts is an array")
        .iter()
        .map(|artifact| {
            let capture_state = artifact["captureState"]
                .as_str()
                .and_then(MacAgentCaptureState::from_wire)
                .expect("captureState is a known token");

            let content = artifact["relativePath"].as_str().map(|relative| {
                std::fs::read_to_string(root.join(relative))
                    .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
            });

            MacAgentArtifactInput {
                artifact_id: artifact["artifactId"]
                    .as_str()
                    .expect("artifactId is a string")
                    .to_owned(),
                family: artifact["family"].as_str().unwrap_or_default().to_owned(),
                file_name: artifact["originalBasename"]
                    .as_str()
                    .expect("originalBasename is a string")
                    .to_owned(),
                sanitized_source_path: artifact["sanitizedSourcePath"]
                    .as_str()
                    .map(str::to_owned),
                capture_state,
                content,
                detail: artifact["detail"].as_str().map(str::to_owned),
            }
        })
        .collect()
}

fn observed_at(manifest: &Value) -> String {
    manifest["collectedAtUtc"]
        .as_str()
        .expect("manifest declares collectedAtUtc")
        .to_owned()
}

fn pkg_snapshot(scenario: &str) -> (Value, PkgSnapshot) {
    let (manifest, expected) = pair(PKG_CORPUS, scenario);
    let root = scenario_root(PKG_CORPUS, scenario);
    let snapshot = analyze_pkg_bundle(&inputs_from(&manifest, &root), &observed_at(&manifest));
    (expected, snapshot)
}

fn shell_snapshot(scenario: &str) -> (Value, ShellScriptSnapshot) {
    let (manifest, expected) = pair(SHELL_CORPUS, scenario);
    let root = scenario_root(SHELL_CORPUS, scenario);
    let snapshot =
        analyze_shell_script_bundle(&inputs_from(&manifest, &root), &observed_at(&manifest));
    (expected, snapshot)
}

/// Serialize a snapshot field to its camelCase wire token for comparison.
fn wire(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("snapshot field serializes")
}

// ── Shared harness contract ─────────────────────────────────────────────────

#[test]
fn both_corpora_satisfy_the_shared_fixture_contract() {
    let mut failures = Failures::new();
    for (corpus, scenarios) in [(PKG_CORPUS, PKG_SCENARIOS), (SHELL_CORPUS, SHELL_SCENARIOS)] {
        for scenario in scenarios {
            let (manifest, expected) = pair(corpus, scenario);
            failures.absorb(validate_scenario(
                scenario,
                &scenario_root(corpus, scenario),
                &manifest,
                &expected,
            ));
        }
    }
    failures.assert_empty("macOS app corpora");
}

#[test]
fn the_package_matrix_is_exactly_the_scenarios_issue_361_requires() {
    assert_eq!(scenario_names(&corpus_root(PKG_CORPUS)), PKG_SCENARIOS);
}

#[test]
fn the_shell_script_matrix_is_exactly_the_scenarios_issue_361_requires() {
    assert_eq!(scenario_names(&corpus_root(SHELL_CORPUS)), SHELL_SCENARIOS);
}

#[test]
fn the_shared_validator_still_rejects_a_corrupted_macos_scenario() {
    // A corpus-specific sanity check that the harness is actually running: if
    // `validate_scenario` silently passed everything, the test above would be
    // worthless for these two corpora too.
    let (manifest, expected) = pair(PKG_CORPUS, "successful-install");
    let corrupted = mutated(&manifest, "/artifacts/0/bytesCopied", json!(1));
    let failures = validate_scenario(
        "successful-install",
        &scenario_root(PKG_CORPUS, "successful-install"),
        &corrupted,
        &expected,
    );
    assert!(
        failures
            .entries()
            .iter()
            .any(|entry| entry.contains("bytesCopied")),
        "expected a bytesCopied failure, got {:?}",
        failures.entries()
    );
}

// ── Package golden assertions ───────────────────────────────────────────────

#[test]
fn every_package_scenario_matches_its_expected_snapshot() {
    let mut failures = Failures::new();

    for scenario in PKG_SCENARIOS {
        let (expected, snapshot) = pkg_snapshot(scenario);

        failures.require(
            wire(&snapshot.grammar_recognized) == expected["grammarRecognized"],
            || {
                format!(
                    "{scenario}: grammarRecognized is {} but expected {}",
                    snapshot.grammar_recognized, expected["grammarRecognized"]
                )
            },
        );
        failures.require(
            snapshot.malformed_records == expected["malformedRecords"].as_u64().unwrap_or(0),
            || {
                format!(
                    "{scenario}: malformedRecords is {} but expected {}",
                    snapshot.malformed_records, expected["malformedRecords"]
                )
            },
        );

        let expected_transactions = expected["transactions"]
            .as_array()
            .expect("expected.json declares transactions");
        failures.require(
            snapshot.transactions.len() == expected_transactions.len(),
            || {
                format!(
                    "{scenario}: {} transaction(s) but expected {}",
                    snapshot.transactions.len(),
                    expected_transactions.len()
                )
            },
        );

        for (actual, want) in snapshot.transactions.iter().zip(expected_transactions) {
            let label = format!("{scenario}/{}", actual.key.app_id);
            failures.require(actual.key.app_id == want["appId"].as_str().unwrap_or(""), || {
                format!("{label}: appId is {} but expected {}", actual.key.app_id, want["appId"])
            });
            failures.require(
                wire(&actual.key.policy_id) == want["policyId"],
                || format!("{label}: policyId mismatch, got {:?}", actual.key.policy_id),
            );
            failures.require(wire(&actual.app_type) == want["appType"], || {
                format!("{label}: appType mismatch, got {:?}", actual.app_type)
            });
            failures.require(wire(&actual.outcome) == want["outcome"], || {
                format!(
                    "{label}: outcome is {} but expected {}",
                    wire(&actual.outcome),
                    want["outcome"]
                )
            });
            failures.require(wire(&actual.reporting) == want["reporting"], || {
                format!(
                    "{label}: reporting is {} but expected {}",
                    wire(&actual.reporting),
                    want["reporting"]
                )
            });
            failures.require(
                wire(&actual.last_confirmed_phase) == want["lastConfirmedPhase"],
                || {
                    format!(
                        "{label}: lastConfirmedPhase is {} but expected {}",
                        wire(&actual.last_confirmed_phase),
                        want["lastConfirmedPhase"]
                    )
                },
            );
            failures.require(
                actual.retry_count == want["retryCount"].as_u64().unwrap_or(0) as u32,
                || format!("{label}: retryCount is {}", actual.retry_count),
            );
            failures.absorb(compare_code(&label, actual.error_code.as_ref(), &want["errorCode"]));
        }

        failures.absorb(compare_finding_ids(scenario, &finding_ids(&snapshot), &expected));
        failures.absorb(compare_coverage(scenario, &coverage_wire(&snapshot.coverage), &expected));
    }

    failures.assert_empty("package scenarios");
}

fn finding_ids(snapshot: &PkgSnapshot) -> Vec<String> {
    snapshot
        .findings
        .iter()
        .map(|finding| finding.finding_id.clone())
        .collect()
}

fn coverage_wire(
    coverage: &[cmtraceopen_parser::intune::evidence::IntuneArtifactCoverage],
) -> Vec<(String, Value)> {
    coverage
        .iter()
        .map(|entry| (entry.artifact_id.clone(), wire(&entry.status)))
        .collect()
}

fn compare_code(label: &str, actual: Option<&cmtraceopen_parser::intune::evidence::IntuneErrorCode>, want: &Value) -> Failures {
    let mut failures = Failures::new();
    match (actual, want.as_object()) {
        (None, None) => {}
        (Some(code), Some(_)) => {
            failures.require(Some(code.raw.as_str()) == want["raw"].as_str(), || {
                format!("{label}: error raw is {:?} but expected {}", code.raw, want["raw"])
            });
            failures.require(code.decimal == want["decimal"].as_i64(), || {
                format!(
                    "{label}: error decimal is {:?} but expected {}",
                    code.decimal, want["decimal"]
                )
            });
        }
        (Some(code), None) => {
            failures.push(format!("{label}: expected no error code, got {:?}", code.raw))
        }
        (None, Some(_)) => failures.push(format!("{label}: expected error code {want}, got none")),
    }
    failures
}

fn compare_finding_ids(scenario: &str, actual: &[String], expected: &Value) -> Failures {
    let mut failures = Failures::new();
    let want = expected["findingIds"]
        .as_array()
        .expect("expected.json declares findingIds")
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    failures.require(actual == want.as_slice(), || {
        format!("{scenario}: findings are {actual:?} but expected {want:?}")
    });
    failures
}

fn compare_coverage(scenario: &str, actual: &[(String, Value)], expected: &Value) -> Failures {
    let mut failures = Failures::new();
    let want = expected["coverage"]
        .as_array()
        .expect("expected.json declares coverage");
    failures.require(actual.len() == want.len(), || {
        format!("{scenario}: {} coverage entries but expected {}", actual.len(), want.len())
    });
    for (artifact_id, status) in actual {
        let Some(entry) = want
            .iter()
            .find(|entry| entry["artifactId"].as_str() == Some(artifact_id))
        else {
            failures.push(format!("{scenario}: coverage for {artifact_id} is not expected"));
            continue;
        };
        failures.require(*status == entry["status"], || {
            format!(
                "{scenario}/{artifact_id}: coverage status is {status} but expected {}",
                entry["status"]
            )
        });
    }
    failures
}

// ── Shell-script golden assertions ──────────────────────────────────────────

#[test]
fn every_shell_script_scenario_matches_its_expected_snapshot() {
    let mut failures = Failures::new();

    for scenario in SHELL_SCENARIOS {
        let (expected, snapshot) = shell_snapshot(scenario);

        failures.require(
            wire(&snapshot.grammar_recognized) == expected["grammarRecognized"],
            || format!("{scenario}: grammarRecognized is {}", snapshot.grammar_recognized),
        );
        failures.require(
            snapshot.malformed_records == expected["malformedRecords"].as_u64().unwrap_or(0),
            || format!("{scenario}: malformedRecords is {}", snapshot.malformed_records),
        );

        let expected_runs = expected["runs"].as_array().expect("expected.json declares runs");
        failures.require(snapshot.runs.len() == expected_runs.len(), || {
            format!(
                "{scenario}: {} run(s) but expected {}",
                snapshot.runs.len(),
                expected_runs.len()
            )
        });

        for (actual, want) in snapshot.runs.iter().zip(expected_runs) {
            let label = format!("{scenario}/{}", actual.key.run_id);
            failures.require(
                actual.key.policy_id == want["policyId"].as_str().unwrap_or(""),
                || format!("{label}: policyId is {}", actual.key.policy_id),
            );
            failures.require(actual.key.run_id == want["runId"].as_str().unwrap_or(""), || {
                format!("{label}: runId is {}", actual.key.run_id)
            });
            failures.require(
                wire(&actual.execution_context) == want["executionContext"],
                || {
                    format!(
                        "{label}: executionContext is {} but expected {}",
                        wire(&actual.execution_context),
                        want["executionContext"]
                    )
                },
            );
            failures.require(wire(&actual.outcome) == want["outcome"], || {
                format!(
                    "{label}: outcome is {} but expected {}",
                    wire(&actual.outcome),
                    want["outcome"]
                )
            });
            failures.require(wire(&actual.reporting) == want["reporting"], || {
                format!("{label}: reporting is {}", wire(&actual.reporting))
            });
            failures.require(wire(&actual.output) == want["output"], || {
                format!(
                    "{label}: output is {} but expected {}",
                    wire(&actual.output),
                    want["output"]
                )
            });
            failures.require(
                wire(&actual.last_confirmed_phase) == want["lastConfirmedPhase"],
                || {
                    format!(
                        "{label}: lastConfirmedPhase is {} but expected {}",
                        wire(&actual.last_confirmed_phase),
                        want["lastConfirmedPhase"]
                    )
                },
            );
            failures.require(
                wire(&actual.timeout_seconds) == want["timeoutSeconds"],
                || format!("{label}: timeoutSeconds is {:?}", actual.timeout_seconds),
            );
            failures.require(
                actual.retry_count == want["retryCount"].as_u64().unwrap_or(0) as u32,
                || format!("{label}: retryCount is {}", actual.retry_count),
            );
            failures.absorb(compare_code(
                &format!("{label} exit"),
                actual.exit_code.as_ref(),
                &want["exitCode"],
            ));
            failures.absorb(compare_code(
                &format!("{label} error"),
                actual.error_code.as_ref(),
                &want["errorCode"],
            ));
        }

        let ids = snapshot
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>();
        failures.absorb(compare_finding_ids(scenario, &ids, &expected));
        failures.absorb(compare_coverage(
            scenario,
            &coverage_wire(&snapshot.coverage),
            &expected,
        ));
    }

    failures.assert_empty("shell script scenarios");
}

// ── Cross-cutting invariants ────────────────────────────────────────────────

#[test]
fn every_finding_in_every_scenario_cites_evidence_or_a_coverage_gap() {
    // Stronger than the harness check, which only inspects the hand-written
    // `expected.json`: this asserts the invariant on what the analyzers actually
    // produced.
    let mut failures = Failures::new();

    for scenario in PKG_SCENARIOS {
        let (_, snapshot) = pkg_snapshot(scenario);
        for finding in &snapshot.findings {
            failures.require(finding.is_evidence_backed(), || {
                format!("pkg/{scenario}: {} cites nothing", finding.finding_id)
            });
        }
    }
    for scenario in SHELL_SCENARIOS {
        let (_, snapshot) = shell_snapshot(scenario);
        for finding in &snapshot.findings {
            failures.require(finding.is_evidence_backed(), || {
                format!("shell/{scenario}: {} cites nothing", finding.finding_id)
            });
        }
    }

    failures.assert_empty("finding evidence backing");
}

#[test]
fn analysis_is_deterministic_under_artifact_permutation() {
    // Artifact arrival order is an accident of collection. If it can change a
    // snapshot, every golden assertion above is only true for one ordering.
    let mut failures = Failures::new();

    for scenario in PKG_SCENARIOS {
        let (manifest, _) = pair(PKG_CORPUS, scenario);
        let root = scenario_root(PKG_CORPUS, scenario);
        let observed = observed_at(&manifest);
        let forward = inputs_from(&manifest, &root);
        let mut reversed = forward.clone();
        reversed.reverse();
        failures.require(
            analyze_pkg_bundle(&forward, &observed) == analyze_pkg_bundle(&reversed, &observed),
            || format!("pkg/{scenario}: reversing the supplied artifacts changed the snapshot"),
        );
    }

    for scenario in SHELL_SCENARIOS {
        let (manifest, _) = pair(SHELL_CORPUS, scenario);
        let root = scenario_root(SHELL_CORPUS, scenario);
        let observed = observed_at(&manifest);
        let forward = inputs_from(&manifest, &root);
        let mut reversed = forward.clone();
        reversed.reverse();
        failures.require(
            analyze_shell_script_bundle(&forward, &observed)
                == analyze_shell_script_bundle(&reversed, &observed),
            || format!("shell/{scenario}: reversing the supplied artifacts changed the snapshot"),
        );
    }

    failures.assert_empty("determinism under permutation");
}

#[test]
fn analysis_is_idempotent() {
    for scenario in PKG_SCENARIOS {
        let (_, first) = pkg_snapshot(scenario);
        let (_, second) = pkg_snapshot(scenario);
        assert_eq!(first, second, "pkg/{scenario} is not reproducible");
    }
    for scenario in SHELL_SCENARIOS {
        let (_, first) = shell_snapshot(scenario);
        let (_, second) = shell_snapshot(scenario);
        assert_eq!(first, second, "shell/{scenario} is not reproducible");
    }
}

#[test]
fn the_two_leaves_never_claim_each_others_records() {
    // Package and script records share the agent envelope. Running each corpus
    // through the *other* analyzer must produce nothing: that is the concrete
    // form of "they cannot merge on time or component alone".
    let mut failures = Failures::new();

    for scenario in PKG_SCENARIOS {
        let (manifest, _) = pair(PKG_CORPUS, scenario);
        let root = scenario_root(PKG_CORPUS, scenario);
        let snapshot =
            analyze_shell_script_bundle(&inputs_from(&manifest, &root), &observed_at(&manifest));
        failures.require(snapshot.runs.is_empty(), || {
            format!("pkg/{scenario}: the script analyzer claimed {} run(s)", snapshot.runs.len())
        });
    }

    for scenario in SHELL_SCENARIOS {
        let (manifest, _) = pair(SHELL_CORPUS, scenario);
        let root = scenario_root(SHELL_CORPUS, scenario);
        let snapshot = analyze_pkg_bundle(&inputs_from(&manifest, &root), &observed_at(&manifest));
        failures.require(snapshot.transactions.is_empty(), || {
            format!(
                "shell/{scenario}: the package analyzer claimed {} transaction(s)",
                snapshot.transactions.len()
            )
        });
    }

    failures.assert_empty("leaf separation");
}

#[test]
fn every_cited_evidence_reference_names_a_declared_artifact() {
    // A finding that cites an evidence id belonging to no supplied artifact is
    // unauditable, which defeats the point of carrying provenance at all.
    let mut failures = Failures::new();

    for scenario in PKG_SCENARIOS {
        let (manifest, _) = pair(PKG_CORPUS, scenario);
        let (_, snapshot) = pkg_snapshot(scenario);
        let declared = declared_artifact_ids(&manifest);
        for finding in &snapshot.findings {
            for reference in &finding.evidence {
                failures.require(declared.contains(&reference.source_artifact_id), || {
                    format!(
                        "pkg/{scenario}: {} cites unknown artifact {}",
                        finding.finding_id, reference.source_artifact_id
                    )
                });
            }
            for gap in &finding.coverage_gap_ids {
                failures.require(declared.contains(gap), || {
                    format!("pkg/{scenario}: {} cites unknown gap {gap}", finding.finding_id)
                });
            }
        }
    }

    for scenario in SHELL_SCENARIOS {
        let (manifest, _) = pair(SHELL_CORPUS, scenario);
        let (_, snapshot) = shell_snapshot(scenario);
        let declared = declared_artifact_ids(&manifest);
        for finding in &snapshot.findings {
            for reference in &finding.evidence {
                failures.require(declared.contains(&reference.source_artifact_id), || {
                    format!(
                        "shell/{scenario}: {} cites unknown artifact {}",
                        finding.finding_id, reference.source_artifact_id
                    )
                });
            }
            for gap in &finding.coverage_gap_ids {
                failures.require(declared.contains(gap), || {
                    format!("shell/{scenario}: {} cites unknown gap {gap}", finding.finding_id)
                });
            }
        }
    }

    failures.assert_empty("evidence reference closure");
}

fn declared_artifact_ids(manifest: &Value) -> BTreeSet<String> {
    manifest["artifacts"]
        .as_array()
        .expect("manifest artifacts is an array")
        .iter()
        .filter_map(|artifact| artifact["artifactId"].as_str())
        .map(str::to_owned)
        .collect()
}

#[test]
fn an_unrecognized_grammar_caps_every_finding_below_high_confidence() {
    use cmtraceopen_parser::intune::evidence::IntuneFindingConfidence;

    let (_, pkg) = pkg_snapshot("unknown-agent-version");
    assert!(!pkg.grammar_recognized);
    assert!(
        pkg.findings
            .iter()
            .all(|finding| finding.confidence != IntuneFindingConfidence::High),
        "an unknown grammar must cap package confidence"
    );

    let (_, shell) = shell_snapshot("unknown-agent-version");
    assert!(!shell.grammar_recognized);
    assert!(
        shell
            .findings
            .iter()
            .all(|finding| finding.confidence != IntuneFindingConfidence::High),
        "an unknown grammar must cap script confidence"
    );
}

// ── Privacy ─────────────────────────────────────────────────────────────────

#[test]
fn the_redacted_export_withholds_everything_the_scenario_names() {
    let (expected, snapshot) = shell_snapshot("privacy-redaction");
    let exported = redact_shell(&snapshot);
    let encoded = serde_json::to_string(&exported).expect("export serializes");

    for forbidden in expected["redactionForbiddenSubstrings"]
        .as_array()
        .expect("scenario declares forbidden substrings")
        .iter()
        .filter_map(Value::as_str)
    {
        assert!(
            !encoded.contains(forbidden),
            "the redacted export leaked {forbidden:?}"
        );
    }

    // The key must survive, or the export shows nothing useful.
    assert!(encoded.contains(&exported.runs[0].key.run_id));
}

#[test]
fn redacted_exports_are_idempotent_across_both_corpora() {
    for scenario in PKG_SCENARIOS {
        let (_, snapshot) = pkg_snapshot(scenario);
        let once = redact_pkg(&snapshot);
        assert_eq!(redact_pkg(&once), once, "pkg/{scenario} export is not idempotent");
    }
    for scenario in SHELL_SCENARIOS {
        let (_, snapshot) = shell_snapshot(scenario);
        let once = redact_shell(&snapshot);
        assert_eq!(
            redact_shell(&once),
            once,
            "shell/{scenario} export is not idempotent"
        );
    }
}

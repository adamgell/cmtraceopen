//! Shared fixture-contract harness for the Intune corpora of epic #356.
//!
//! Each workload leaf ships a scenario corpus laid out as:
//!
//! ```text
//! tests/fixtures/intune/<workload path>/<scenario>/
//!     manifest.json                       inputs and provenance
//!     expected.json                       asserted outputs and coverage
//!     evidence/<artifact>/<rotation>/<file>
//! ```
//!
//! Everything every corpus shares is validated here: the manifest envelope, path
//! safety, byte-count truth, file/manifest closure, the synthetic-fixture marker,
//! and a privacy scan. Workload-specific semantics — state chains, key binding,
//! terminal outcomes — stay in each leaf's own test file, where exactly one issue
//! owns them.
//!
//! # Why `allow(dead_code)`
//!
//! Cargo compiles a separate binary per `tests/*.rs` file, and each one compiles
//! its own copy of this module. Any helper a given binary does not call is
//! genuinely dead in that binary and would fail `clippy -D warnings`.
//! `src-tauri/tests/common/mod.rs` sets the same precedent.
#![allow(dead_code)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// Envelope version every Intune fixture manifest declares.
pub const INTUNE_MANIFEST_VERSION: u64 = 1;

/// Literal the first line of every evidence file must contain.
///
/// This is the tripwire against a real customer log being pasted into the corpus.
pub const SYNTHETIC_MARKER: &str = "SYNTHETIC FIXTURE";

/// Capture states a manifest artifact may declare.
///
/// These mirror `IntuneAccessState` so a fixture can express "this source was
/// capped" or "this source was skipped" rather than collapsing both to absent.
pub const CAPTURE_STATES: [&str; 7] = [
    "captured",
    "capped",
    "absent",
    "accessDenied",
    "skipped",
    "unsupported",
    "parseFailed",
];

/// Capture states that must be backed by a real file on disk.
pub const CAPTURE_STATES_WITH_FILE: [&str; 2] = ["captured", "capped"];

// ── Paths ───────────────────────────────────────────────────────────────────

/// Root of the Intune fixture tree.
pub fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/intune")
}

/// One corpus, e.g. `corpus_root("device/windows/configuration")`.
pub fn corpus_root(corpus_relative: &str) -> PathBuf {
    let mut root = fixtures_root();
    for segment in corpus_relative.split('/').filter(|s| !s.is_empty()) {
        root.push(segment);
    }
    root
}

/// Sorted scenario directory names inside a corpus.
pub fn scenario_names(corpus: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(corpus) else {
        return Vec::new();
    };
    let mut names = entries
        .map(|entry| entry.expect("corpus directory entry is readable").path())
        .filter(|path| path.is_dir())
        .map(|path| {
            path.file_name()
                .expect("scenario directory has a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

/// Depth-first, deterministically ordered file list.
///
/// Returns empty when `root` is absent, because a scenario in which nothing was
/// captured legitimately has no `evidence/` directory.
pub fn walk_files(root: &Path) -> Vec<PathBuf> {
    if !root.exists() {
        return Vec::new();
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        if path.is_dir() {
            let mut children = std::fs::read_dir(&path)
                .expect("fixture directory is readable")
                .map(|entry| entry.expect("fixture entry is readable").path())
                .collect::<Vec<_>>();
            children.sort();
            pending.extend(children.into_iter().rev());
        } else {
            files.push(path);
        }
    }
    files
}

/// Read and parse a JSON fixture, panicking with the path on failure.
pub fn load_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} contains valid JSON: {error}", path.display()))
}

/// Return a copy of `value` with one JSON pointer replaced.
///
/// This is what makes an adversarial mutation test a one-liner: corrupt a field,
/// then assert the validator rejects the corrupted copy.
pub fn mutated(value: &Value, pointer: &str, replacement: Value) -> Value {
    let mut clone = value.clone();
    let slot = clone
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("json pointer {pointer} exists"));
    *slot = replacement;
    clone
}

// ── Failure accumulator ─────────────────────────────────────────────────────

/// Collects every contract failure so one run reports all of them.
///
/// A per-assertion `assert!` stops at the first problem, which turns fixing a
/// corpus into a serial guessing game. This reports the whole set at once.
#[derive(Debug, Default)]
pub struct Failures {
    entries: Vec<String>,
}

impl Failures {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, message: impl Into<String>) {
        self.entries.push(message.into());
    }

    /// Record `message()` when `condition` is false.
    ///
    /// The closure means the message is only formatted on failure.
    pub fn require(&mut self, condition: bool, message: impl FnOnce() -> String) {
        if !condition {
            self.entries.push(message());
        }
    }

    pub fn absorb(&mut self, other: Failures) {
        self.entries.extend(other.entries);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Panic with every accumulated failure, or return quietly.
    #[track_caller]
    pub fn assert_empty(self, context: &str) {
        if self.entries.is_empty() {
            return;
        }
        panic!(
            "{context}: {} contract failure(s)\n  - {}",
            self.entries.len(),
            self.entries.join("\n  - ")
        );
    }
}

// ── Contract validation ─────────────────────────────────────────────────────

/// Validate the manifest envelope, artifacts, evidence files, and expected
/// coverage for one scenario directory.
///
/// Returns accumulated failures rather than asserting, so callers can reuse it
/// for adversarial mutation tests that expect rejection.
pub fn validate_scenario(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    expected: &Value,
) -> Failures {
    let mut failures = Failures::new();

    validate_envelope(scenario, manifest, expected, &mut failures);
    let referenced = validate_artifacts(scenario, scenario_root, manifest, &mut failures);
    validate_evidence_closure(scenario, scenario_root, &referenced, &mut failures);
    validate_expected_coverage(scenario, manifest, expected, &mut failures);
    validate_findings_are_evidence_backed(scenario, expected, &mut failures);

    failures
}

fn validate_envelope(scenario: &str, manifest: &Value, expected: &Value, failures: &mut Failures) {
    failures.require(
        manifest["intuneManifestVersion"].as_u64() == Some(INTUNE_MANIFEST_VERSION),
        || {
            format!(
                "{scenario}: intuneManifestVersion must be {INTUNE_MANIFEST_VERSION}, got {}",
                manifest["intuneManifestVersion"]
            )
        },
    );
    failures.require(manifest["syntheticFixture"].as_bool() == Some(true), || {
        format!("{scenario}: manifest must declare syntheticFixture: true")
    });
    failures.require(manifest["scenario"].as_str() == Some(scenario), || {
        format!(
            "{scenario}: manifest scenario is {}, expected the directory name",
            manifest["scenario"]
        )
    });
    failures.require(expected["scenario"].as_str() == Some(scenario), || {
        format!(
            "{scenario}: expected scenario is {}, expected the directory name",
            expected["scenario"]
        )
    });
    failures.require(manifest["artifacts"].is_array(), || {
        format!("{scenario}: manifest artifacts must be an array")
    });
}

/// Validate each artifact and return the set of evidence files it referenced.
fn validate_artifacts(
    scenario: &str,
    scenario_root: &Path,
    manifest: &Value,
    failures: &mut Failures,
) -> BTreeSet<PathBuf> {
    let mut referenced = BTreeSet::new();
    let mut seen_ids = BTreeSet::new();

    let Some(artifacts) = manifest["artifacts"].as_array() else {
        return referenced;
    };

    for artifact in artifacts {
        let id = artifact["artifactId"].as_str().unwrap_or_default();
        failures.require(!id.is_empty(), || {
            format!("{scenario}: every artifact needs a non-empty artifactId")
        });
        failures.require(seen_ids.insert(id.to_owned()), || {
            format!("{scenario}: duplicate artifactId {id}")
        });

        let capture_state = artifact["captureState"].as_str().unwrap_or_default();
        failures.require(CAPTURE_STATES.contains(&capture_state), || {
            format!(
                "{scenario}/{id}: captureState {capture_state:?} is not one of {CAPTURE_STATES:?}"
            )
        });

        let relative_path = artifact["relativePath"].as_str();
        let needs_file = CAPTURE_STATES_WITH_FILE.contains(&capture_state);

        if !needs_file {
            failures.require(relative_path.is_none(), || {
                format!("{scenario}/{id}: captureState {capture_state} must have relativePath null")
            });
            failures.require(artifact["bytesCopied"].as_u64() == Some(0), || {
                format!("{scenario}/{id}: captureState {capture_state} must report bytesCopied 0")
            });
            continue;
        }

        let Some(relative_path) = relative_path else {
            failures.push(format!(
                "{scenario}/{id}: captureState {capture_state} requires a relativePath"
            ));
            continue;
        };

        if let Some(problem) = path_safety_problem(relative_path) {
            failures.push(format!("{scenario}/{id}: {problem}"));
            continue;
        }

        let file_path = scenario_root.join(relative_path);
        let Ok(metadata) = std::fs::metadata(&file_path) else {
            failures.push(format!(
                "{scenario}/{id}: referenced evidence file {relative_path} does not exist"
            ));
            continue;
        };

        failures.require(
            artifact["bytesCopied"].as_u64() == Some(metadata.len()),
            || {
                format!(
                    "{scenario}/{id}: bytesCopied is {} but {relative_path} is {} bytes",
                    artifact["bytesCopied"],
                    metadata.len()
                )
            },
        );

        match std::fs::read_to_string(&file_path) {
            Ok(contents) => {
                let first_line = contents.lines().next().unwrap_or_default();
                failures.require(first_line.contains(SYNTHETIC_MARKER), || {
                    format!(
                        "{scenario}/{id}: first line of {relative_path} must contain {SYNTHETIC_MARKER:?}"
                    )
                });
                failures.absorb(privacy_problems(
                    &format!("{scenario}/{id}:{relative_path}"),
                    &contents,
                ));
            }
            Err(error) => failures.push(format!(
                "{scenario}/{id}: {relative_path} is not readable as UTF-8: {error}"
            )),
        }

        if let Ok(canonical) = file_path.canonicalize() {
            failures.require(referenced.insert(canonical), || {
                format!("{scenario}/{id}: {relative_path} is referenced by more than one artifact")
            });
        }
    }

    referenced
}

/// Reject absolute paths, parent traversal, and any path not rooted at `evidence`.
fn path_safety_problem(relative_path: &str) -> Option<String> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Some(format!("relativePath {relative_path} must be relative"));
    }
    if !path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return Some(format!(
            "relativePath {relative_path} must contain only normal components"
        ));
    }
    match path.components().next() {
        Some(Component::Normal(first)) if first == "evidence" => None,
        _ => Some(format!(
            "relativePath {relative_path} must start with the evidence directory"
        )),
    }
}

/// Every file under `evidence/` must be referenced by exactly one artifact.
///
/// Without this, an orphaned file silently contributes nothing while looking like
/// coverage, and a corpus can drift out of sync with its manifest unnoticed.
fn validate_evidence_closure(
    scenario: &str,
    scenario_root: &Path,
    referenced: &BTreeSet<PathBuf>,
    failures: &mut Failures,
) {
    let on_disk = walk_files(&scenario_root.join("evidence"))
        .into_iter()
        .filter_map(|path| path.canonicalize().ok())
        .collect::<BTreeSet<_>>();

    for orphan in on_disk.difference(referenced) {
        failures.push(format!(
            "{scenario}: evidence file {} is not referenced by any manifest artifact",
            orphan.display()
        ));
    }
}

/// `expected.json` coverage must name exactly the manifest's artifacts.
fn validate_expected_coverage(
    scenario: &str,
    manifest: &Value,
    expected: &Value,
    failures: &mut Failures,
) {
    let manifest_ids = manifest["artifacts"]
        .as_array()
        .map(|artifacts| {
            artifacts
                .iter()
                .filter_map(|artifact| artifact["artifactId"].as_str())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    let Some(coverage) = expected["coverage"].as_array() else {
        failures.push(format!("{scenario}: expected.json must have a coverage array"));
        return;
    };

    let coverage_ids = coverage
        .iter()
        .filter_map(|entry| entry["artifactId"].as_str())
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();

    for missing in manifest_ids.difference(&coverage_ids) {
        failures.push(format!(
            "{scenario}: manifest artifact {missing} has no coverage entry in expected.json"
        ));
    }
    for extra in coverage_ids.difference(&manifest_ids) {
        failures.push(format!(
            "{scenario}: expected.json covers {extra}, which no manifest artifact declares"
        ));
    }
}

/// A finding must cite evidence or a coverage gap.
///
/// This is the corpus-level enforcement of the conservative-findings rule that
/// epic #356 requires of every child issue.
fn validate_findings_are_evidence_backed(
    scenario: &str,
    expected: &Value,
    failures: &mut Failures,
) {
    let Some(findings) = expected["findings"].as_array() else {
        return;
    };
    for finding in findings {
        let id = finding["findingId"].as_str().unwrap_or("<unnamed>");
        let has_evidence = finding["evidence"]
            .as_array()
            .is_some_and(|items| !items.is_empty());
        let has_gap = finding["coverageGapIds"]
            .as_array()
            .is_some_and(|items| !items.is_empty());
        failures.require(has_evidence || has_gap, || {
            format!("{scenario}: finding {id} cites neither evidence nor a coverage gap")
        });
    }
}

// ── Privacy ─────────────────────────────────────────────────────────────────

/// Shapes that must never appear in a committed fixture.
///
/// Checked as plain substrings and simple scans rather than regexes so this stays
/// cheap enough to run over every file of every corpus.
pub fn privacy_problems(context: &str, contents: &str) -> Failures {
    let mut failures = Failures::new();

    for forbidden in [
        "C:\\Users\\",
        "/Users/",
        "Authorization:",
        "Bearer ",
        "client_secret",
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    ] {
        failures.require(!contents.contains(forbidden), || {
            format!("{context}: contains forbidden fixture material {forbidden:?}")
        });
    }

    if let Some(sid) = find_windows_sid(contents) {
        failures.push(format!("{context}: contains a Windows SID {sid:?}"));
    }
    if let Some(email) = find_email(contents) {
        failures.push(format!("{context}: contains an email address {email:?}"));
    }

    failures
}

/// Find a `S-1-…` SID with at least three sub-authorities.
fn find_windows_sid(contents: &str) -> Option<String> {
    for (index, _) in contents.match_indices("S-1-") {
        let candidate = contents[index..]
            .split(|c: char| !(c.is_ascii_digit() || c == '-' || c == 'S'))
            .next()
            .unwrap_or_default();
        if candidate.matches('-').count() >= 4 && candidate.ends_with(|c: char| c.is_ascii_digit()) {
            return Some(candidate.to_owned());
        }
    }
    None
}

/// Find an email address, ignoring the reserved `.invalid` and `.example` TLDs
/// that fixtures are expected to use for synthetic identities.
///
/// The delimiter set has to be generous. Splitting only on whitespace and quotes
/// lets `a@corp.com;b@corp.com` arrive as one token, whose domain then contains
/// `;` and a second `@`; that fails the final character check and the token is
/// skipped, so *both* real addresses slip through. Semicolon-joined recipient
/// lists are exactly the shape a pasted mail header has, so this is the case the
/// scanner most needs to catch.
fn find_email(contents: &str) -> Option<String> {
    for token in contents.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | ',' | ';' | ':' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | '='
                    | '|'
            )
    }) {
        let Some((local, domain)) = token.split_once('@') else {
            continue;
        };
        if local.is_empty() || !domain.contains('.') {
            continue;
        }
        let domain = domain.trim_end_matches(|c: char| !c.is_ascii_alphanumeric());
        if domain.ends_with(".invalid") || domain.ends_with(".example") {
            continue;
        }
        if domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Some(token.to_owned());
        }
    }
    None
}

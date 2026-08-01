//! Classification of bundles and their members.
//!
//! Two rules govern everything here.
//!
//! **A name is never proof.** An importer may nominate a bundle as Android
//! Company Portal diagnostics; that produces a *candidate*, which claims
//! nothing about content. Only a verified layout in
//! [`super::contract::VERIFIED_CONTRACTS`] promotes a candidate, and that
//! registry is empty.
//!
//! **Content may refuse, never confirm.** A member recognized as an Android
//! `logcat` capture is recognized in order to be excluded: issue #371 scopes a
//! general logcat parser out, and treating a logcat line as Company Portal
//! evidence is exactly the mistake the issue names. A bundle whose members are
//! all recognized foreign formats is reported as not Company Portal
//! diagnostics no matter what the importer claimed.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use super::contract::match_verified_contract;
use super::models::{
    AndroidBundleClassification, AndroidDiagnosticBundleInput, AndroidDiagnosticMemberInput,
    AndroidImportLimits, AndroidMemberClassification, AndroidMemberSafetyFlag,
};
use crate::intune::evidence::IntuneArtifactStatus;

/// How many leading lines are inspected when recognizing a foreign format.
const FOREIGN_FORMAT_SAMPLE_LINES: usize = 40;

/// Fraction of sampled non-blank lines that must match for a logcat capture to
/// be recognized.
///
/// A single stray line that happens to look like logcat must not disqualify a
/// bundle, and a genuine capture is overwhelmingly uniform, so the bar is high.
const LOGCAT_MATCH_RATIO: f32 = 0.6;

/// `logcat -v threadtime`: `MM-DD HH:MM:SS.mmm  PID  TID L TAG: message`.
fn logcat_threadtime_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"^\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\s+\d+\s+\d+\s+[VDIWEFS]\s")
            .expect("logcat threadtime pattern is valid")
    })
}

/// `logcat -v brief`: `L/TAG( PID): message`.
///
/// The tag is right-padded by `logcat`, so trailing spaces before the `(` are
/// expected and the tag class allows them.
fn logcat_brief_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(r"^[VDIWEFS]/[^(\n]{1,64}\(\s*\d+\):").expect("logcat brief pattern is valid")
    })
}

/// Does this text read as an Android `logcat` capture?
///
/// Both documented default formats are checked. Recognition is deliberately
/// one-directional: it can only push a classification away from Company Portal.
pub fn is_logcat_capture(text: &str) -> bool {
    let mut sampled = 0usize;
    let mut matched = 0usize;
    for line in text.lines().take(FOREIGN_FORMAT_SAMPLE_LINES) {
        let line = line.trim_end();
        if line.trim().is_empty() {
            continue;
        }
        sampled += 1;
        if logcat_threadtime_regex().is_match(line) || logcat_brief_regex().is_match(line) {
            matched += 1;
        }
    }
    if sampled == 0 {
        return false;
    }
    matched as f32 / sampled as f32 >= LOGCAT_MATCH_RATIO
}

/// Safety flags derivable from an entry name alone.
///
/// The importer is expected to report these too, but a host that forgets one
/// must not thereby make a traversal entry invisible, so they are re-derived
/// here from data this crate already holds.
pub fn lexical_safety_flags(entry_name: &str) -> Vec<AndroidMemberSafetyFlag> {
    let mut flags = Vec::new();
    let normalized = entry_name.replace('\\', "/");

    if normalized
        .split('/')
        .any(|component| component == ".." || component == "...")
    {
        flags.push(AndroidMemberSafetyFlag::PathTraversal);
    }

    let looks_absolute = normalized.starts_with('/')
        || normalized
            .split_once(':')
            .is_some_and(|(prefix, rest)| prefix.len() == 1 && rest.starts_with('/'));
    if looks_absolute {
        flags.push(AndroidMemberSafetyFlag::AbsoluteEntryPath);
    }

    flags
}

/// Entry names that more than one member claims.
fn duplicate_entry_names(members: &[AndroidDiagnosticMemberInput]) -> Vec<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for member in members {
        *counts.entry(member.entry_name.as_str()).or_default() += 1;
    }
    counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(name, _)| name.to_owned())
        .collect()
}

/// Every safety flag that applies to one member: importer-reported, re-derived
/// from the name, and derived from the caller's byte limits.
///
/// Sorted and de-duplicated so the output is stable regardless of the order the
/// importer listed its own flags in.
pub fn safety_flags_for(
    member: &AndroidDiagnosticMemberInput,
    duplicates: &[String],
    limits: &AndroidImportLimits,
) -> Vec<AndroidMemberSafetyFlag> {
    let mut flags = member.safety_flags.clone();
    flags.extend(lexical_safety_flags(&member.entry_name));

    if duplicates.contains(&member.entry_name) {
        flags.push(AndroidMemberSafetyFlag::DuplicateEntryName);
    }
    if limits
        .max_member_bytes
        .is_some_and(|limit| member.declared_bytes > limit)
    {
        flags.push(AndroidMemberSafetyFlag::OversizedEntry);
    }

    flags.sort_unstable();
    flags.dedup();
    flags
}

/// Classify one member from its status, safety flags, and content.
///
/// An unsafe member is rejected before its content is looked at: reading a
/// member that arrived through a traversal entry in order to decide whether it
/// is interesting would defeat the point of flagging it.
pub fn classify_member(
    member: &AndroidDiagnosticMemberInput,
    safety_flags: &[AndroidMemberSafetyFlag],
) -> AndroidMemberClassification {
    if !safety_flags.is_empty() {
        return AndroidMemberClassification::RejectedUnsafe;
    }
    if !matches!(
        member.status,
        IntuneArtifactStatus::Available
            | IntuneArtifactStatus::Capped
            | IntuneArtifactStatus::ParseFailed
            | IntuneArtifactStatus::Unsupported
    ) {
        return AndroidMemberClassification::NotCollected;
    }
    match member.text.as_deref() {
        Some(text) if is_logcat_capture(text) => {
            AndroidMemberClassification::RecognizedForeignLogcat
        }
        _ => AndroidMemberClassification::Enumerated,
    }
}

/// Classify the bundle from the importer's claim and the member classifications.
///
/// The `classifications` slice must be parallel to `input.members`.
pub fn classify_bundle(
    input: &AndroidDiagnosticBundleInput,
    classifications: &[AndroidMemberClassification],
) -> AndroidBundleClassification {
    if input.members.is_empty() {
        return AndroidBundleClassification::EmptyBundle;
    }

    // A member that carries content is the only kind that can speak for or
    // against the bundle. One that was never collected says nothing either way.
    let speaking: Vec<&AndroidMemberClassification> = classifications
        .iter()
        .filter(|classification| {
            !matches!(classification, AndroidMemberClassification::NotCollected)
        })
        .collect();

    let all_foreign = !speaking.is_empty()
        && speaking.iter().all(|classification| {
            matches!(
                classification,
                AndroidMemberClassification::RecognizedForeignLogcat
            )
        });
    if all_foreign {
        return AndroidBundleClassification::NotCompanyPortalDiagnostics;
    }

    // The importer never nominated an app, so there is no claim to evaluate and
    // nothing in an unverified layout can supply one.
    if input.supplied.app.is_none() {
        return AndroidBundleClassification::NotCompanyPortalDiagnostics;
    }

    let entry_names: Vec<String> = input
        .members
        .iter()
        .map(|member| member.entry_name.clone())
        .collect();
    match match_verified_contract(
        input.supplied.declared_schema_token.as_deref(),
        &entry_names,
    ) {
        Some(_) => AndroidBundleClassification::VerifiedContract,
        None => AndroidBundleClassification::CandidateUnverifiedContract,
    }
}

/// Duplicate entry names across a bundle, exposed for the reducer.
pub fn duplicates_in(input: &AndroidDiagnosticBundleInput) -> Vec<String> {
    duplicate_entry_names(&input.members)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::contract::AndroidDiagnosticApp;
    use super::super::models::{
        AndroidImportLimits, AndroidSuppliedCollectionFacts,
    };

    fn member(entry_name: &str, text: Option<&str>) -> AndroidDiagnosticMemberInput {
        AndroidDiagnosticMemberInput {
            artifact_id: format!("artifact-{entry_name}"),
            entry_name: entry_name.to_owned(),
            sanitized_entry_path: None,
            status: IntuneArtifactStatus::Available,
            declared_bytes: text.map(|t| t.len() as u64).unwrap_or_default(),
            encoding: Some("utf-8".to_owned()),
            rotation: None,
            text: text.map(str::to_owned),
            safety_flags: Vec::new(),
        }
    }

    fn bundle(
        members: Vec<AndroidDiagnosticMemberInput>,
        app: Option<AndroidDiagnosticApp>,
    ) -> AndroidDiagnosticBundleInput {
        AndroidDiagnosticBundleInput {
            bundle_id: "bundle".to_owned(),
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            supplied: AndroidSuppliedCollectionFacts {
                app,
                ..Default::default()
            },
            members,
            limits: AndroidImportLimits::default(),
        }
    }

    const THREADTIME: &str = concat!(
        "07-31 09:14:02.113  4120  4120 I SynthTag: synthetic line one\n",
        "07-31 09:14:02.114  4120  4155 D SynthTag: synthetic line two\n",
        "07-31 09:14:02.220  4120  4155 W SynthTag: synthetic line three\n",
    );

    #[test]
    fn threadtime_logcat_is_recognized() {
        assert!(is_logcat_capture(THREADTIME));
    }

    #[test]
    fn brief_logcat_is_recognized() {
        let brief = concat!(
            "I/SynthTag ( 4120): synthetic line one\n",
            "D/SynthTag ( 4120): synthetic line two\n",
        );
        assert!(is_logcat_capture(brief));
    }

    #[test]
    fn ordinary_text_is_not_logcat() {
        assert!(!is_logcat_capture("key = value\nanother = value\n"));
        assert!(!is_logcat_capture(""));
    }

    #[test]
    fn one_stray_logcat_shaped_line_does_not_make_a_capture() {
        let mixed = format!(
            "07-31 09:14:02.113  4120  4120 I SynthTag: one\n{}",
            "plain = value\n".repeat(9)
        );
        assert!(!is_logcat_capture(&mixed));
    }

    #[test]
    fn traversal_and_absolute_entry_names_are_flagged_without_the_importer() {
        assert_eq!(
            lexical_safety_flags("logs/../../escape.txt"),
            vec![AndroidMemberSafetyFlag::PathTraversal]
        );
        assert_eq!(
            lexical_safety_flags("/data/data/synthetic/escape.txt"),
            vec![AndroidMemberSafetyFlag::AbsoluteEntryPath]
        );
        assert!(lexical_safety_flags("logs/diagnostic_summary.txt").is_empty());
    }

    #[test]
    fn a_windows_style_absolute_entry_name_is_flagged() {
        assert_eq!(
            lexical_safety_flags(r"D:\synthetic\escape.txt"),
            vec![AndroidMemberSafetyFlag::AbsoluteEntryPath]
        );
    }

    #[test]
    fn oversized_members_are_flagged_against_the_callers_limit() {
        let mut input = member("big.txt", Some("x"));
        input.declared_bytes = 4096;
        let flags = safety_flags_for(
            &input,
            &[],
            &AndroidImportLimits {
                max_member_bytes: Some(1024),
            },
        );
        assert_eq!(flags, vec![AndroidMemberSafetyFlag::OversizedEntry]);
    }

    #[test]
    fn duplicate_entry_names_are_flagged_on_every_copy() {
        let members = vec![member("same.txt", Some("a")), member("same.txt", Some("b"))];
        let duplicates = duplicate_entry_names(&members);
        assert_eq!(duplicates, vec!["same.txt".to_owned()]);
        for candidate in &members {
            assert!(safety_flags_for(candidate, &duplicates, &AndroidImportLimits::default())
                .contains(&AndroidMemberSafetyFlag::DuplicateEntryName));
        }
    }

    #[test]
    fn an_unsafe_member_is_rejected_before_its_content_is_considered() {
        let input = member("../escape.txt", Some(THREADTIME));
        let flags = safety_flags_for(&input, &[], &AndroidImportLimits::default());
        assert_eq!(
            classify_member(&input, &flags),
            AndroidMemberClassification::RejectedUnsafe
        );
    }

    #[test]
    fn a_bundle_of_only_logcat_is_refused_even_when_the_importer_claims_otherwise() {
        let input = bundle(
            vec![member("logcat.txt", Some(THREADTIME))],
            Some(AndroidDiagnosticApp::CompanyPortal),
        );
        let classifications = vec![AndroidMemberClassification::RecognizedForeignLogcat];
        assert_eq!(
            classify_bundle(&input, &classifications),
            AndroidBundleClassification::NotCompanyPortalDiagnostics
        );
    }

    #[test]
    fn a_bundle_with_no_claimed_app_is_not_company_portal_diagnostics() {
        let input = bundle(vec![member("notes.txt", Some("hello\n"))], None);
        let classifications = vec![AndroidMemberClassification::Enumerated];
        assert_eq!(
            classify_bundle(&input, &classifications),
            AndroidBundleClassification::NotCompanyPortalDiagnostics
        );
    }

    #[test]
    fn a_claimed_bundle_is_only_ever_a_candidate_while_no_contract_is_verified() {
        let input = bundle(
            vec![member("diagnostic_summary.txt", Some("key = value\n"))],
            Some(AndroidDiagnosticApp::CompanyPortal),
        );
        let classifications = vec![AndroidMemberClassification::Enumerated];
        assert_eq!(
            classify_bundle(&input, &classifications),
            AndroidBundleClassification::CandidateUnverifiedContract
        );
    }

    #[test]
    fn an_empty_bundle_is_reported_as_empty_rather_than_refused() {
        let input = bundle(Vec::new(), Some(AndroidDiagnosticApp::CompanyPortal));
        assert_eq!(
            classify_bundle(&input, &[]),
            AndroidBundleClassification::EmptyBundle
        );
    }

    #[test]
    fn a_bundle_whose_members_were_all_uncollected_stays_a_candidate() {
        // Nothing spoke against the claim, so refusing would be as unfounded as
        // confirming.
        let mut absent = member("diagnostic_summary.txt", None);
        absent.status = IntuneArtifactStatus::Missing;
        let input = bundle(vec![absent], Some(AndroidDiagnosticApp::CompanyPortal));
        let classifications = vec![AndroidMemberClassification::NotCollected];
        assert_eq!(
            classify_bundle(&input, &classifications),
            AndroidBundleClassification::CandidateUnverifiedContract
        );
    }
}

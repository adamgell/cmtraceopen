//! Links dsregcmd diagnostics to the event-log entries that cite the same
//! error code (issue #870).
//!
//! Two halves:
//!
//! 1. [`attach_related_error_codes`] fills `DsregcmdDiagnosticInsight::related_error_codes`
//!    for the rules that key on a specific code. The codes come from a table of
//!    rule id to the literals that rule already tests for, and a code is kept
//!    only when the capture itself contains it, so a diagnostic never claims a
//!    code the capture did not print.
//! 2. [`link_event_log_entries`] writes an `ErrorCodeMatch` correlation link for
//!    every error or warning entry whose message cites one of those codes.
//!
//! The matcher compares lowercase `0x`-prefixed hex on token boundaries. The
//! Intune path (`correlate_diagnostics`) uses a plain substring test, under which
//! `0x8018000` would match inside `0x80180001`; this path does not.

use std::collections::HashSet;

use crate::dsregcmd::models::{DsregcmdAnalysisResult, DsregcmdDiagnosticInsight, DsregcmdFacts};
use crate::intune::apps::windows::ime::models::{EventLogCorrelationKind, EventLogCorrelationLink};

use super::derive::has_code;

/// Rule id to the specific error codes that rule tests for. Rules that fire on
/// a pattern rather than a code (connectivity, enrollment state, certificate
/// validity, and so on) are intentionally absent.
const RULE_ERROR_CODES: &[(&str, &[&str])] = &[
    ("entra-sync-pending", &["0x801c03f2"]),
    ("adal-protocol-not-supported", &["0xcaa90017"]),
    ("adal-parse-xml-failed", &["0xcaa9002c"]),
    ("adal-password-endpoint-missing", &["0xcaa90023"]),
    ("adal-timeout", &["0xcaa82ee2"]),
    ("adal-connection-aborted", &["0xcaa82efe"]),
    ("adal-secure-failure", &["0xcaa82f8f"]),
    ("adal-cannot-connect", &["0xcaa82efd"]),
    ("adal-invalid-grant", &["0xcaa20003"]),
    ("adal-wstrust-request-failed", &["0xcaa90014"]),
    ("adal-token-request-failed", &["0xcaa90006"]),
    ("adal-operation-pending", &["0xcaa1002d"]),
    ("scp-read-failed", &["0x801c001d"]),
    ("drs-discovery-code", &["0x801c0021"]),
    ("drs-discovery-timeout", &["0x801c001f"]),
    ("user-realm-discovery-failed", &["0x801c003d"]),
    ("invalid-discovery-response", &["0x8007000d"]),
    ("join-device-authentication-error", &["0x801c0002"]),
    ("join-internal-service-error", &["0x801c0006"]),
    ("invalid-credentials", &["0xc000006d"]),
    ("wrong-password", &["0xc000006a"]),
    ("request-not-accepted", &["0xc00000d0"]),
    (
        "prt-network-path-error",
        &["0xc000023c", "0xc00000be", "0xc00000c4"],
    ),
    ("prt-user-realm-not-found", &["0xc000005f"]),
    ("malformed-upn", &["0xc004844c"]),
    ("missing-user-sid-in-token", &["0xc0048442"]),
    ("wstrust-empty-saml", &["0xc00484c1"]),
    ("mex-endpoint-misconfigured", &["0xc004848b", "0xc004848c"]),
    ("federation-xml-dtd-prohibited", &["0xc00cee4f"]),
    ("tpm-bad-keyset", &["0x80090016"]),
    ("tpm-internal-error", &["0x80290407"]),
    ("tpm-not-fips", &["0x80280036"]),
    ("tpm-locked-out", &["0x80090031"]),
];

/// Fill `related_error_codes` on the diagnostics whose rule is in
/// [`RULE_ERROR_CODES`], keeping only codes the capture contains.
pub(super) fn attach_related_error_codes(
    diagnostics: &mut [DsregcmdDiagnosticInsight],
    facts: &DsregcmdFacts,
) {
    for diagnostic in diagnostics {
        let Some((_, codes)) = RULE_ERROR_CODES
            .iter()
            .find(|(rule_id, _)| *rule_id == diagnostic.id)
        else {
            continue;
        };
        diagnostic.related_error_codes = codes
            .iter()
            .filter(|code| has_code(facts, code))
            .map(|code| code.to_string())
            .collect();
    }
}

/// True when `message_lower` contains `code` as a whole token: the characters
/// on either side, if any, are not ASCII alphanumeric or `_`. Both inputs must
/// already be lowercase.
fn contains_code_token(message_lower: &str, code: &str) -> bool {
    if code.is_empty() {
        return false;
    }
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    message_lower.match_indices(code).any(|(start, _)| {
        let before_ok = message_lower[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word(c));
        let after_ok = message_lower[start + code.len()..]
            .chars()
            .next()
            .is_none_or(|c| !is_word(c));
        before_ok && after_ok
    })
}

/// Append an `ErrorCodeMatch` link for every error or warning event-log entry
/// whose message cites a code in a diagnostic's `related_error_codes`. One link
/// per (entry, diagnostic) pair; links already present (for example from a
/// bundle written by a later build) are not duplicated. Does nothing when there
/// is no event-log analysis or no diagnostic carries a code.
pub(super) fn link_event_log_entries(result: &mut DsregcmdAnalysisResult) {
    let Some(analysis) = result.event_log_analysis.as_mut() else {
        return;
    };

    let coded: Vec<(&str, Vec<String>)> = result
        .diagnostics
        .iter()
        .filter(|d| !d.related_error_codes.is_empty())
        .map(|d| {
            (
                d.id.as_str(),
                d.related_error_codes
                    .iter()
                    .map(|c| c.to_ascii_lowercase())
                    .collect(),
            )
        })
        .collect();
    if coded.is_empty() {
        return;
    }

    let mut seen: HashSet<(u64, String)> = analysis
        .correlation_links
        .iter()
        .filter_map(|l| {
            l.linked_diagnostic_id
                .as_ref()
                .map(|id| (l.event_log_entry_id, id.clone()))
        })
        .collect();

    let mut new_links = Vec::new();
    for entry in &analysis.entries {
        if !entry.severity.is_error_or_warning() {
            continue;
        }
        let message_lower = entry.message.to_ascii_lowercase();
        for (diagnostic_id, codes) in &coded {
            if !codes
                .iter()
                .any(|code| contains_code_token(&message_lower, code))
            {
                continue;
            }
            if !seen.insert((entry.id, (*diagnostic_id).to_string())) {
                continue;
            }
            new_links.push(EventLogCorrelationLink {
                event_log_entry_id: entry.id,
                linked_intune_event_id: None,
                linked_diagnostic_id: Some((*diagnostic_id).to_string()),
                correlation_kind: EventLogCorrelationKind::ErrorCodeMatch,
                time_delta_secs: None,
            });
        }
    }
    analysis.correlation_links.append(&mut new_links);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsregcmd::models::DsregcmdBundleEvidence;
    use crate::intune::apps::windows::ime::models::{
        EventLogAnalysis, EventLogAnalysisSource, EventLogChannel, EventLogEntry, EventLogSeverity,
    };
    use chrono::Utc;

    const SAMPLE: &str = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 AzureAdPrt : NO
 DRS Discovery Test : FAIL [0x801c0021]
 Client ErrorCode : 0x801c0021
"#;

    fn entry(id: u64, severity: EventLogSeverity, message: &str) -> EventLogEntry {
        EventLogEntry {
            id,
            channel: EventLogChannel::SystemLog,
            channel_display: "System".to_string(),
            provider: "Synthetic".to_string(),
            event_id: 100,
            severity,
            timestamp: "2026-01-01T00:00:00.000Z".to_string(),
            computer: None,
            message: message.to_string(),
            correlation_activity_id: None,
            source_file: "System.evtx".to_string(),
        }
    }

    fn analysis(entries: Vec<EventLogEntry>) -> EventLogAnalysis {
        let total = entries.len() as u32;
        EventLogAnalysis {
            source_kind: EventLogAnalysisSource::Bundle,
            entries,
            channel_summaries: Vec::new(),
            correlation_links: Vec::new(),
            parsed_file_count: 1,
            total_entry_count: total,
            error_entry_count: 0,
            warning_entry_count: 0,
            timestamp_bounds: None,
            live_query: None,
        }
    }

    fn run(
        text: &str,
        events: Option<EventLogAnalysis>,
    ) -> crate::dsregcmd::models::DsregcmdAnalysisResult {
        let evidence = DsregcmdBundleEvidence {
            event_log_analysis: events,
            ..Default::default()
        };
        crate::dsregcmd::analyze_text_with_evidence(text, evidence, Utc::now()).expect("analyze")
    }

    fn linked_ids(result: &crate::dsregcmd::models::DsregcmdAnalysisResult) -> Vec<(u64, String)> {
        result
            .event_log_analysis
            .as_ref()
            .map(|a| {
                a.correlation_links
                    .iter()
                    .filter_map(|l| {
                        l.linked_diagnostic_id
                            .clone()
                            .map(|id| (l.event_log_entry_id, id))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn token_matcher_respects_boundaries() {
        assert!(contains_code_token("failed with 0x801c0021.", "0x801c0021"));
        assert!(contains_code_token("(0x801c0021)", "0x801c0021"));
        assert!(contains_code_token("0x801c0021", "0x801c0021"));
        assert!(!contains_code_token("code 0x801c00211", "0x801c0021"));
        assert!(!contains_code_token("code 0x801c002", "0x801c0021"));
        assert!(!contains_code_token("x0x801c0021", "0x801c0021"));
        assert!(!contains_code_token("code 0x801c0021_ext", "0x801c0021"));
        assert!(contains_code_token(
            "0x80180001 then 0x8018000",
            "0x8018000"
        ));
        assert!(!contains_code_token("only 0x80180001", "0x8018000"));
    }

    #[test]
    fn diagnostic_citing_a_code_links_the_matching_entry() {
        let events = analysis(vec![
            entry(0, EventLogSeverity::Error, "Discovery failed: 0x801C0021"),
            entry(1, EventLogSeverity::Error, "Unrelated failure 0x80070005"),
        ]);
        let result = run(SAMPLE, Some(events));
        let diagnostic = result
            .diagnostics
            .iter()
            .find(|d| d.id == "drs-discovery-code")
            .expect("drs-discovery-code fires");
        assert_eq!(diagnostic.related_error_codes, vec!["0x801c0021"]);
        assert_eq!(
            linked_ids(&result),
            vec![(0, "drs-discovery-code".to_string())]
        );
        let link = &result
            .event_log_analysis
            .as_ref()
            .unwrap()
            .correlation_links[0];
        assert_eq!(
            link.correlation_kind,
            EventLogCorrelationKind::ErrorCodeMatch
        );
        assert_eq!(link.linked_intune_event_id, None);
    }

    #[test]
    fn prefix_and_non_matching_codes_do_not_link() {
        let events = analysis(vec![
            entry(0, EventLogSeverity::Error, "longer code 0x801c00211 here"),
            entry(1, EventLogSeverity::Error, "shorter code 0x801c002 here"),
            entry(2, EventLogSeverity::Error, "other code 0x801c0022"),
        ]);
        let result = run(SAMPLE, Some(events));
        assert!(linked_ids(&result).is_empty());
    }

    #[test]
    fn informational_entries_do_not_link() {
        let events = analysis(vec![entry(
            0,
            EventLogSeverity::Information,
            "Discovery note 0x801c0021",
        )]);
        assert!(linked_ids(&run(SAMPLE, Some(events))).is_empty());
    }

    #[test]
    fn diagnostics_without_codes_never_link() {
        let sample = " AzureAdJoined : NO\n DomainJoined : NO\n AzureAdPrt : NO\n";
        let events = analysis(vec![entry(
            0,
            EventLogSeverity::Error,
            "failure 0x801c0021",
        )]);
        let result = run(sample, Some(events));
        assert!(result
            .diagnostics
            .iter()
            .all(|d| d.related_error_codes.is_empty()));
        assert!(linked_ids(&result).is_empty());
    }

    #[test]
    fn no_event_logs_leaves_the_analysis_unchanged() {
        let result = run(SAMPLE, None);
        assert!(result.event_log_analysis.is_none());
    }

    #[test]
    fn existing_links_are_kept_and_not_duplicated() {
        let mut events = analysis(vec![entry(
            0,
            EventLogSeverity::Error,
            "Discovery failed: 0x801c0021",
        )]);
        events.correlation_links.push(EventLogCorrelationLink {
            event_log_entry_id: 0,
            linked_intune_event_id: None,
            linked_diagnostic_id: Some("drs-discovery-code".to_string()),
            correlation_kind: EventLogCorrelationKind::ErrorCodeMatch,
            time_delta_secs: None,
        });
        let result = run(SAMPLE, Some(events));
        assert_eq!(
            result.event_log_analysis.unwrap().correlation_links.len(),
            1
        );
    }

    #[test]
    fn rule_table_ids_exist_and_codes_are_normalized() {
        for (rule_id, codes) in RULE_ERROR_CODES {
            assert!(!codes.is_empty(), "{rule_id}");
            for code in *codes {
                assert!(
                    code.starts_with("0x")
                        && code[2..]
                            .chars()
                            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                    "{rule_id}: {code} must be lowercase 0x hex"
                );
            }
        }
        let rules_source = include_str!("rules.rs");
        for (rule_id, _) in RULE_ERROR_CODES {
            assert!(
                rules_source.contains(&format!("\"{rule_id}\"")),
                "{rule_id} is not a rule id in rules.rs"
            );
        }
    }
}

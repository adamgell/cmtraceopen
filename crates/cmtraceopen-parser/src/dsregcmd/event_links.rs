//! Links dsregcmd diagnostics to the event-log entries that cite the same
//! error code (issue #870).
//!
//! The codes come from the rules themselves: a rule that fires on a specific
//! `0x` code builds its diagnostic with `coded(...)`, recording exactly the
//! codes it matched in the fields it read (see `derive::matched_in` and
//! `derive::matched_has_code`). This module only consumes
//! `DsregcmdDiagnosticInsight::related_error_codes`.
//!
//! [`link_event_log_entries`] writes an `ErrorCodeMatch` correlation link for
//! every error or warning entry whose message cites one of those codes, on a
//! token boundary. The Intune path (`correlate_diagnostics`) uses a plain
//! substring test, under which `0x8018000` would match inside `0x80180001`;
//! this path does not.

use std::collections::HashSet;

use super::derive::contains_code_token;

use crate::dsregcmd::models::DsregcmdAnalysisResult;
#[cfg(test)]
use crate::dsregcmd::models::DsregcmdFacts;
use crate::intune::apps::windows::ime::models::{EventLogCorrelationKind, EventLogCorrelationLink};

/// Replace the event-log analysis's correlation links with the analyzer's own:
/// an `ErrorCodeMatch` link for every error or warning entry whose message
/// cites a code in a diagnostic's `related_error_codes`, one per (entry,
/// diagnostic) pair. Links read from the input (a bundle's
/// `dsregcmd-events.json`) are dropped first, because no app path writes links
/// there and the analyzer owns the link set. Does nothing when there is no
/// event-log analysis.
pub(super) fn link_event_log_entries(result: &mut DsregcmdAnalysisResult) {
    let Some(analysis) = result.event_log_analysis.as_mut() else {
        return;
    };

    analysis.correlation_links.clear();

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

    let mut seen: HashSet<(u64, String)> = HashSet::new();

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
    fn foreign_links_in_the_input_do_not_survive_or_suppress_the_analyzers_own() {
        let mut events = analysis(vec![entry(
            0,
            EventLogSeverity::Error,
            "Discovery failed: 0x801c0021",
        )]);
        events.correlation_links.push(EventLogCorrelationLink {
            event_log_entry_id: 0,
            linked_intune_event_id: None,
            linked_diagnostic_id: Some("drs-discovery-code".to_string()),
            correlation_kind: EventLogCorrelationKind::TimeWindowChannelMatch,
            time_delta_secs: Some(9.0),
        });
        events.correlation_links.push(EventLogCorrelationLink {
            event_log_entry_id: 0,
            linked_intune_event_id: None,
            linked_diagnostic_id: Some("not-a-real-diagnostic".to_string()),
            correlation_kind: EventLogCorrelationKind::ErrorCodeMatch,
            time_delta_secs: None,
        });
        let result = run(SAMPLE, Some(events));
        let links = result.event_log_analysis.unwrap().correlation_links;
        assert_eq!(links.len(), 1, "{links:?}");
        assert_eq!(
            links[0].correlation_kind,
            EventLogCorrelationKind::ErrorCodeMatch
        );
        assert_eq!(links[0].time_delta_secs, None);
        assert_eq!(
            links[0].linked_diagnostic_id.as_deref(),
            Some("drs-discovery-code")
        );
    }

    #[test]
    fn a_code_found_only_in_a_field_the_rule_did_not_read_is_not_recorded() {
        // prt-network-path-error reads Attempt Status only; the AD Connectivity
        // Test field cites a different code that has_code would also find.
        let sample = r#"
 AzureAdJoined : YES
 DomainJoined : NO
 AzureAdPrt : NO
 Attempt Status : 0xc000023c
 AD Connectivity Test : FAIL [0xc00000be]
"#;
        let events = analysis(vec![entry(
            0,
            EventLogSeverity::Error,
            "Kerberos failure 0xc00000be",
        )]);
        let result = run(sample, Some(events));
        let diagnostic = result
            .diagnostics
            .iter()
            .find(|d| d.id == "prt-network-path-error")
            .expect("prt-network-path-error fires");
        assert_eq!(diagnostic.related_error_codes, vec!["0xc000023c"]);
        assert!(linked_ids(&result).is_empty());
    }

    /// (rule id, capture line that fires it, codes the rule must record)
    const CODE_KEYED_RULES: &[(&str, &str, &[&str])] = &[
        (
            "entra-sync-pending",
            "Client ErrorCode : 0x801c03f2",
            &["0x801c03f2"],
        ),
        (
            "adal-protocol-not-supported",
            "Client ErrorCode : 0xcaa90017",
            &["0xcaa90017"],
        ),
        (
            "adal-parse-xml-failed",
            "Client ErrorCode : 0xcaa9002c",
            &["0xcaa9002c"],
        ),
        (
            "adal-password-endpoint-missing",
            "Client ErrorCode : 0xcaa90023",
            &["0xcaa90023"],
        ),
        (
            "adal-timeout",
            "Client ErrorCode : 0xcaa82ee2",
            &["0xcaa82ee2"],
        ),
        (
            "adal-connection-aborted",
            "Client ErrorCode : 0xcaa82efe",
            &["0xcaa82efe"],
        ),
        (
            "adal-secure-failure",
            "Client ErrorCode : 0xcaa82f8f",
            &["0xcaa82f8f"],
        ),
        (
            "adal-cannot-connect",
            "Client ErrorCode : 0xcaa82efd",
            &["0xcaa82efd"],
        ),
        (
            "adal-invalid-grant",
            "Client ErrorCode : 0xcaa20003",
            &["0xcaa20003"],
        ),
        (
            "adal-wstrust-request-failed",
            "Client ErrorCode : 0xcaa90014",
            &["0xcaa90014"],
        ),
        (
            "adal-token-request-failed",
            "Client ErrorCode : 0xcaa90006",
            &["0xcaa90006"],
        ),
        (
            "adal-operation-pending",
            "Client ErrorCode : 0xcaa1002d",
            &["0xcaa1002d"],
        ),
        (
            "scp-read-failed",
            "Client ErrorCode : 0x801c001d",
            &["0x801c001d"],
        ),
        (
            "scp-read-failed",
            "AD Configuration Test : FAIL [0x801c001d]",
            &["0x801c001d"],
        ),
        (
            "drs-discovery-code",
            "Client ErrorCode : 0x801c0021",
            &["0x801c0021"],
        ),
        (
            "drs-discovery-code",
            "DRS Discovery Test : FAIL [0x801c0021]",
            &["0x801c0021"],
        ),
        (
            "drs-discovery-timeout",
            "Client ErrorCode : 0x801c001f",
            &["0x801c001f"],
        ),
        (
            "drs-discovery-timeout",
            "DRS Discovery Test : FAIL [0x801c001f]",
            &["0x801c001f"],
        ),
        (
            "user-realm-discovery-failed",
            "Client ErrorCode : 0x801c003d",
            &["0x801c003d"],
        ),
        (
            "invalid-discovery-response",
            "Client ErrorCode : 0x8007000d",
            &["0x8007000d"],
        ),
        (
            "join-device-authentication-error",
            "Client ErrorCode : 0x801c0002",
            &["0x801c0002"],
        ),
        (
            "join-internal-service-error",
            "Client ErrorCode : 0x801c0006",
            &["0x801c0006"],
        ),
        (
            "invalid-credentials",
            "Attempt Status : 0xc000006d",
            &["0xc000006d"],
        ),
        (
            "wrong-password",
            "Attempt Status : 0xc000006a",
            &["0xc000006a"],
        ),
        (
            "request-not-accepted",
            "Attempt Status : 0xc00000d0",
            &["0xc00000d0"],
        ),
        (
            "prt-network-path-error",
            "Attempt Status : 0xc000023c 0xc00000c4",
            &["0xc000023c", "0xc00000c4"],
        ),
        (
            "prt-user-realm-not-found",
            "Attempt Status : 0xc000005f",
            &["0xc000005f"],
        ),
        (
            "malformed-upn",
            "Attempt Status : 0xc004844c",
            &["0xc004844c"],
        ),
        (
            "missing-user-sid-in-token",
            "Attempt Status : 0xc0048442",
            &["0xc0048442"],
        ),
        (
            "wstrust-empty-saml",
            "Attempt Status : 0xc00484c1",
            &["0xc00484c1"],
        ),
        (
            "mex-endpoint-misconfigured",
            "Attempt Status : 0xc004848b",
            &["0xc004848b"],
        ),
        (
            "federation-xml-dtd-prohibited",
            "Attempt Status : 0xc00cee4f",
            &["0xc00cee4f"],
        ),
        (
            "tpm-bad-keyset",
            "Client ErrorCode : 0x80090016",
            &["0x80090016"],
        ),
        (
            "tpm-internal-error",
            "Client ErrorCode : 0x80290407",
            &["0x80290407"],
        ),
        (
            "tpm-not-fips",
            "Client ErrorCode : 0x80280036",
            &["0x80280036"],
        ),
        (
            "tpm-locked-out",
            "Client ErrorCode : 0x80090031",
            &["0x80090031"],
        ),
    ];

    #[test]
    fn every_code_keyed_rule_records_exactly_the_codes_it_matched() {
        for (rule_id, line, expected) in CODE_KEYED_RULES {
            let sample =
                format!("\n AzureAdJoined : NO\n DomainJoined : YES\n AzureAdPrt : NO\n {line}\n");
            let result = run(&sample, None);
            let diagnostic = result
                .diagnostics
                .iter()
                .find(|d| d.id == *rule_id)
                .unwrap_or_else(|| panic!("{rule_id} did not fire for '{line}'"));
            assert_eq!(
                &diagnostic.related_error_codes, expected,
                "{rule_id}: {line}"
            );
        }
    }

    #[test]
    fn every_coded_rule_in_rules_rs_is_covered_by_the_table() {
        let covered: HashSet<&str> = CODE_KEYED_RULES.iter().map(|(id, _, _)| *id).collect();
        let source = include_str!("rules.rs");
        let production = &source[..source.find("#[cfg(test)]").expect("test module marker")];
        assert_eq!(
            production.matches("coded(issue(").count(),
            covered.len(),
            "a rule built with coded(...) is missing from CODE_KEYED_RULES, or the reverse"
        );
        for id in covered {
            assert!(production.contains(&format!("\"{id}\"")), "{id}");
        }
    }

    #[test]
    fn has_code_and_matched_has_code_agree_on_every_field() {
        use crate::dsregcmd::derive::{has_code, matched_has_code};
        type Slot = fn(&mut DsregcmdFacts) -> &mut Option<String>;
        let slots: [Slot; 11] = [
            |f| &mut f.registration.client_error_code,
            |f| &mut f.registration.server_error_code,
            |f| &mut f.registration.server_message,
            |f| &mut f.registration.server_error_description,
            |f| &mut f.diagnostics.attempt_status,
            |f| &mut f.diagnostics.http_error,
            |f| &mut f.pre_join_tests.token_acquisition_test,
            |f| &mut f.pre_join_tests.drs_discovery_test,
            |f| &mut f.pre_join_tests.ad_configuration_test,
            |f| &mut f.pre_join_tests.drs_connectivity_test,
            |f| &mut f.pre_join_tests.ad_connectivity_test,
        ];
        for (index, slot) in slots.iter().enumerate() {
            let mut facts = DsregcmdFacts::default();
            *slot(&mut facts) = Some("FAIL [0xdeadbeef]".to_string());
            assert!(
                has_code(&facts, "0xdeadbeef"),
                "has_code misses field {index}"
            );
            let matched = matched_has_code(&facts, &["0xdeadbeef", "0x1"]);
            assert_eq!(
                matched.fired,
                vec!["0xdeadbeef"],
                "matched_has_code misses field {index}"
            );
            assert_eq!(matched.recorded, vec!["0xdeadbeef"], "field {index}");
        }
        let empty = DsregcmdFacts::default();
        assert!(!has_code(&empty, "0xdeadbeef"));
        assert!(matched_has_code(&empty, &["0xdeadbeef"]).is_empty());
    }

    #[test]
    fn entra_sync_pending_firing_on_a_non_code_operand_records_no_code() {
        let directory_error = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 AzureAdPrt : NO
 Server ErrorCode : DirectoryError
"#;
        let pending_text = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 AzureAdPrt : NO
 Server Message : Directory sync pending for this device
"#;
        for sample in [directory_error, pending_text] {
            let result = run(sample, None);
            let diagnostic = result
                .diagnostics
                .iter()
                .find(|d| d.id == "entra-sync-pending")
                .unwrap_or_else(|| panic!("entra-sync-pending did not fire for {sample}"));
            assert!(diagnostic.related_error_codes.is_empty());
        }
    }

    #[test]
    fn substring_only_hit_fires_but_records_nothing_and_links_nothing() {
        let sample = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 AzureAdPrt : NO
 Client ErrorCode : 0x801c03f21
"#;
        let events = analysis(vec![
            entry(0, EventLogSeverity::Error, "status 0x801c03f2"),
            entry(1, EventLogSeverity::Error, "status 0x801c03f21"),
        ]);
        let result = run(sample, Some(events));
        let diagnostic = result
            .diagnostics
            .iter()
            .find(|d| d.id == "entra-sync-pending")
            .expect("firing is the substring test, unchanged");
        assert!(diagnostic.related_error_codes.is_empty());
        assert!(linked_ids(&result).is_empty());
    }

    #[test]
    fn every_code_keyed_rule_fires_on_a_suffixed_code_but_records_nothing() {
        for (rule_id, line, expected) in CODE_KEYED_RULES {
            let mut suffixed = line.to_string();
            for code in *expected {
                suffixed = suffixed.replace(code, &format!("{code}a"));
            }
            let sample = format!(
                "\n AzureAdJoined : NO\n DomainJoined : YES\n AzureAdPrt : NO\n {suffixed}\n"
            );
            let result = run(&sample, None);
            let diagnostic = result
                .diagnostics
                .iter()
                .find(|d| d.id == *rule_id)
                .unwrap_or_else(|| panic!("{rule_id} must still fire for '{suffixed}'"));
            assert!(
                diagnostic.related_error_codes.is_empty(),
                "{rule_id}: '{suffixed}' recorded {:?}",
                diagnostic.related_error_codes
            );
        }
    }
}

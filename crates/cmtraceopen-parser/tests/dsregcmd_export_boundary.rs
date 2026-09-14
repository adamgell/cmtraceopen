//! End-to-end guard for the dsregcmd export boundary (issue #556).
//!
//! These tests do not call the projection directly to check it. They serialize
//! what a caller of [`analyze_text`] receives and assert that no identifier
//! planted in the capture survives into the bytes a workspace copies to the
//! clipboard or the application writes to disk.
//!
//! Two independent guards run against the same serialized text, mirroring
//! `esp_export_boundary.rs`:
//!
//! 1. Named markers. Every identity value planted in the capture is asserted
//!    absent, and a canary asserts the same markers ARE present in the
//!    unprojected analysis of the same capture, so the test can never pass
//!    vacuously.
//! 2. Shape scan. Every string in the published JSON is matched against
//!    identifier shapes (mail address, SID). A field that starts carrying an
//!    identifier fails here even if no named marker was updated.
//!
//! A bare tenant domain, device id and thumbprint have no distinctive shape, so
//! the projection scrubs the literal values it masks as typed fields out of
//! every free-text field too; the fixture plants them in fields *and* in
//! narrative so guard 1 proves both paths.

use cmtraceopen_parser::dsregcmd::{
    analyze_text, analyze_text_preserving_local_values, analyze_text_with_evidence,
    redacted_status_text, DsregcmdActiveEvidence, DsregcmdBundleEvidence,
    DsregcmdConnectivityResult, DsregcmdScpQueryResult,
};
use cmtraceopen_parser::intune::models::{
    EventLogAnalysis, EventLogAnalysisSource, EventLogChannel, EventLogEntry, EventLogSeverity,
};
use regex::Regex;
use serde_json::Value;

// Synthetic values. Nothing here belongs to a real tenant, device or user.
const UPN: &str = "adele.vance@contoso.onmicrosoft.com";
const USER_SID: &str = "S-1-5-21-3623811015-3361044348-30300820-500";
const TENANT_ID: &str = "8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90";
const TENANT_DOMAIN: &str = "contoso.onmicrosoft.com";
const ON_PREM_DOMAIN: &str = "corp.contoso.com";
const DEVICE_ID: &str = "4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b";
const THUMBPRINT: &str = "8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D";
const COMPUTER_NAME: &str = "FIN-LAPTOP-0117";

/// Every planted value that must not reach a caller of the published crate
/// from [`STATUS_CAPTURE`]. The SID has its own capture below, because one
/// capture has one user identity.
const PLANTED_IDENTIFIERS: &[(&str, &str)] = &[
    ("user principal name", UPN),
    ("tenant id", TENANT_ID),
    ("tenant domain", TENANT_DOMAIN),
    ("on-premises domain", ON_PREM_DOMAIN),
    ("device id", DEVICE_ID),
    ("certificate thumbprint", THUMBPRINT),
];

/// A `dsregcmd /status` capture carrying a planted identifier in every field
/// family the analysis can publish one in.
///
/// Field labels and value shapes follow the samples the analyzer is already
/// tested against (`crates/cmtraceopen-parser/src/dsregcmd/rules.rs`).
const STATUS_CAPTURE: &str = r#"
 AzureAdJoined : YES
 DomainJoined : YES
 WorkplaceJoined : NO
 EnterpriseJoined : YES
 NgcSet : NO
 TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 TenantName : contoso.onmicrosoft.com
 DomainName : corp.contoso.com
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 Thumbprint : 8E1B0C4A5D6F70819A2B3C4D5E6F70819A2B3C4D
 DeviceCertificateValidity : [ 2025-03-01 00:00:00.000 UTC -- 2025-03-20 00:00:00.000 UTC ]
 DeviceAuthStatus : SUCCESS
 MdmUrl : https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc
 MdmComplianceUrl : https://portal.manage.microsoft.com/Compliance
 AzureAdPrt : YES
 AzureAdPrtAuthority : https://login.microsoftonline.com/8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90/
 AzureAdPrtUpdateTime : 2025-03-10 05:00:00.000 UTC
 KerbTopLevelNames : .corp.contoso.com
 Previous Prt Attempt : 2025-03-10 08:30:00.000 UTC
 Attempt Status : 0xc000006d
 User Identity : adele.vance@contoso.onmicrosoft.com
 Credential Type : Password
 User Context : SYSTEM
 SessionIsNotRemote : NO
 Client Time : 2025-03-10 10:30:00.000 UTC
 DRS Discovery Test : FAIL [0x801c0021]
 AD Connectivity Test : FAIL [0x54b]
 DRS Connectivity Test : FAIL [0x54b]
 Token Acquisition Test : FAIL [0xcaa90017]
 Fallback to Sync-Join : ENABLED
 Endpoint URI : https://login.microsoftonline.com/8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90/oauth2/token/
 Server Message : AADSTS50126 Invalid username or password for adele.vance@contoso.onmicrosoft.com
 Server Error Description : AADSTS50126: Invalid username or password.
 CertEnrollment : enrollment authority
 LogonCertTemplateReady : Pending
 PreReqResult : WillProvision
 KeySignTest : FAILED
 AadRecoveryEnabled : YES
"#;

/// A capture whose user identity is a SID rather than a principal name, which
/// is the shape the built-in-Administrator rule reads.
const SID_CAPTURE: &str = r#"
 AzureAdJoined : NO
 DomainJoined : YES
 TenantId : 8f9b2b41-1c0d-4f3a-9a1b-7d2e5c6f8a90
 DeviceId : 4a1f7c2e-9b3d-4e5f-8a6b-1c2d3e4f5a6b
 User Identity : S-1-5-21-3623811015-3361044348-30300820-500
"#;

/// The JSON a caller of the published crate receives.
fn published_analysis_json(capture: &str) -> String {
    let analysis = analyze_text(capture).expect("the dsregcmd capture parses");
    serde_json::to_string(&analysis).expect("a dsregcmd analysis serializes")
}

#[test]
fn the_published_analysis_carries_no_planted_identity() {
    let local = {
        let analysis = analyze_text_preserving_local_values(STATUS_CAPTURE)
            .expect("the dsregcmd capture parses");
        serde_json::to_string(&analysis).expect("a dsregcmd analysis serializes")
    };
    let published = published_analysis_json(STATUS_CAPTURE);

    for (label, marker) in PLANTED_IDENTIFIERS {
        // Canary: the marker really is reachable from the unprojected analysis
        // of this capture, so a passing assertion below means the projection
        // removed it rather than the fixture never carrying it.
        assert!(
            local.contains(marker),
            "test fixture no longer plants the {label}; the export assertion below would be vacuous"
        );
        assert!(
            !published.contains(marker),
            "the published analysis leaks the {label} ({marker})"
        );
    }
}

#[test]
fn a_sid_user_identity_is_masked_without_losing_the_diagnosis_it_produced() {
    let local = analyze_text_preserving_local_values(SID_CAPTURE).expect("capture parses");
    let published = published_analysis_json(SID_CAPTURE);

    // Canary: the SID really is carried, and it really does drive a rule whose
    // input is the value's shape rather than its presence.
    assert!(
        local.facts.diagnostics.user_identity.as_deref() == Some(USER_SID),
        "got {:?}",
        local.facts.diagnostics.user_identity
    );
    assert!(
        local
            .diagnostics
            .iter()
            .any(|issue| issue.id == "builtin-admin-cannot-join"),
        "the built-in-Administrator rule no longer sees the SID; the assertions below are vacuous"
    );

    assert!(
        !published.contains(USER_SID),
        "the published analysis leaks the user SID ({USER_SID})"
    );
    assert!(
        published.contains("builtin-admin-cannot-join"),
        "the diagnosis the raw SID produced was lost when the value was masked"
    );
}

#[test]
fn the_published_analysis_carries_no_identifier_shaped_string() {
    let published: Value =
        serde_json::from_str(&published_analysis_json(STATUS_CAPTURE)).expect("export is JSON");

    let shapes = [
        (
            "mail address",
            Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
        ),
        (
            "security identifier",
            Regex::new(r"(?i)\bS-1-\d+(?:-\d+){2,}\b").unwrap(),
        ),
    ];

    let mut strings = Vec::new();
    collect_strings(&published, String::from("$"), &mut strings);
    assert!(
        strings.len() > 20,
        "the walker found only {} strings, so it is not reaching the whole export",
        strings.len()
    );

    for (path, value) in &strings {
        for (label, shape) in &shapes {
            assert!(
                !shape.is_match(value),
                "the published analysis leaks a {label} at {path}: {value}"
            );
        }
    }
}

/// A narrative mention is scrubbed even when the identity is not the whole
/// value of the field carrying it, and the diagnosis around it survives.
#[test]
fn a_narrative_mention_of_a_planted_identity_is_scrubbed() {
    let published = published_analysis_json(STATUS_CAPTURE);

    assert!(
        published.contains("AADSTS50126"),
        "over-masking: the diagnostic error code was lost: {published}"
    );
    assert!(
        published.contains("login.microsoftonline.com"),
        "over-masking: the endpoint host was lost: {published}"
    );
    assert!(
        !published.contains(UPN) && !published.contains(TENANT_ID),
        "a narrative mention of a planted identity survived: {published}"
    );
}

/// The projection masks values, not the analysis: every diagnostic the local
/// analysis produced is still present in the published one.
#[test]
fn projecting_does_not_drop_or_rename_a_diagnostic() {
    let local = analyze_text_preserving_local_values(STATUS_CAPTURE).expect("capture parses");
    let published = analyze_text(STATUS_CAPTURE).expect("capture parses");

    let local_ids: Vec<&str> = local.diagnostics.iter().map(|issue| issue.id.as_str()).collect();
    let published_ids: Vec<&str> = published
        .diagnostics
        .iter()
        .map(|issue| issue.id.as_str())
        .collect();

    assert!(!local_ids.is_empty(), "the fixture produced no diagnostics");
    assert_eq!(local_ids, published_ids);
    assert_eq!(
        local.derived.join_type_label,
        published.derived.join_type_label
    );
}

/// The user's own screen is not a boundary, so the identity classification is
/// the same one the projection applies; this pins the rule that the export is
/// never less protective than the screen.
#[test]
fn the_raw_capture_text_projects_the_same_identifiers() {
    let projected = redacted_status_text(STATUS_CAPTURE);

    for (label, marker) in PLANTED_IDENTIFIERS {
        assert!(
            !projected.contains(marker),
            "the projected status text leaks the {label} ({marker})"
        );
    }
    assert!(
        projected.contains("AADSTS50126"),
        "over-masking: the error code was lost from the status text"
    );
}

/// Text the parser cannot read still gets the shared grammar, so a pasted
/// snippet that is not a full capture is not published verbatim.
#[test]
fn status_text_that_does_not_parse_still_gets_the_shaped_rules() {
    let snippet = format!("User Identity : {UPN}\n");
    let projected = redacted_status_text(&snippet);

    assert!(!projected.contains(UPN), "got {projected:?}");
}

/// A value too short to be told apart from prose is not scrubbed out of it.
#[test]
fn a_short_value_does_not_scrub_unrelated_narrative() {
    let capture = " TenantId : ad\n TenantName : ad\n DeviceId : ad\n";
    let projected = redacted_status_text(capture);

    assert!(
        projected.contains("ad"),
        "a two-character value was scrubbed out of the capture: {projected:?}"
    );
}

/// Evidence a native collector attaches to the analysis carries the same
/// identifiers, and it is attached inside the crate so the published value is
/// projected either way. This is the path the desktop command takes.
#[test]
fn evidence_attached_from_a_bundle_is_projected_too() {
    let active = DsregcmdActiveEvidence {
        connectivity_tests: vec![DsregcmdConnectivityResult {
            endpoint: format!("https://login.microsoftonline.com/{TENANT_ID}/oauth2/token"),
            reachable: false,
            status_code: Some(0),
            latency_ms: None,
            error_message: Some(format!(
                "TLS failure contacting dc01.{ON_PREM_DOMAIN} authority for {TENANT_DOMAIN}"
            )),
            timestamp: "2026-08-11T09:15:00Z".to_string(),
        }],
        scp_query: Some(DsregcmdScpQueryResult {
            scp_found: true,
            tenant_domain: Some(TENANT_DOMAIN.to_string()),
            azuread_id: Some(TENANT_ID.to_string()),
            keywords: vec!["aADDomainName".to_string()],
            domain_controller: Some(format!("dc01.{ON_PREM_DOMAIN}")),
            error: None,
        }),
    };
    let events = EventLogAnalysis {
        source_kind: EventLogAnalysisSource::Live,
        entries: vec![EventLogEntry {
            id: 1,
            channel: EventLogChannel::AadOperational,
            channel_display: "AAD Operational".to_string(),
            provider: "Microsoft-Windows-AAD".to_string(),
            event_id: 1103,
            severity: EventLogSeverity::Error,
            timestamp: "2026-08-11T09:15:00Z".to_string(),
            computer: Some(COMPUTER_NAME.to_string()),
            message: format!(
                "PRT acquisition failed for {UPN} ({USER_SID}) on {COMPUTER_NAME}.{ON_PREM_DOMAIN}"
            ),
            correlation_activity_id: None,
            source_file: r"C:\Users\adele.vance\AppData\Local\AAD\AAD.evtx".to_string(),
        }],
        ..EventLogAnalysis::default()
    };

    // Canary: the evidence really is attached, so the assertions below mean it
    // was projected rather than never carried.
    let raw = format!(
        "{}{}",
        serde_json::to_string(&active).expect("evidence serializes"),
        serde_json::to_string(&events).expect("evidence serializes")
    );
    let published = {
        let evidence = DsregcmdBundleEvidence {
            active_evidence: Some(active),
            event_log_analysis: Some(events),
            ..DsregcmdBundleEvidence::default()
        };
        let analysis = analyze_text_with_evidence(STATUS_CAPTURE, evidence)
            .expect("the dsregcmd capture analyzes");
        serde_json::to_string(&analysis).expect("a dsregcmd analysis serializes")
    };

    for (label, marker) in [
        ("user principal name", UPN),
        ("user SID", USER_SID),
        ("tenant id", TENANT_ID),
        ("tenant domain", TENANT_DOMAIN),
        ("on-premises domain", ON_PREM_DOMAIN),
        ("computer name", COMPUTER_NAME),
        ("profile name", "adele.vance"),
    ] {
        assert!(
            raw.contains(marker),
            "test fixture no longer attaches the {label}; the assertion below would be vacuous"
        );
        assert!(
            !published.contains(marker),
            "the published analysis leaks the {label} ({marker}) from attached evidence"
        );
    }
    assert!(
        published.contains("PRT acquisition failed"),
        "over-masking: the event message itself was lost"
    );
}

/// The workspace never sees the same analysis twice from one capture, but a
/// projected status text can be pasted back in, and the shared grammar
/// documents masking as idempotent, so a second pass must be a no-op rather
/// than reaching a second token.
#[test]
fn projecting_an_already_projected_analysis_changes_nothing() {
    let once = analyze_text(STATUS_CAPTURE).expect("capture parses");
    let twice = cmtraceopen_parser::dsregcmd::redacted_analysis(&once);

    assert_eq!(
        serde_json::to_string(&once).expect("analysis serializes"),
        serde_json::to_string(&twice).expect("analysis serializes")
    );
}

fn collect_strings(value: &Value, path: String, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => out.push((path, text.clone())),
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_strings(item, format!("{path}[{index}]"), out);
            }
        }
        Value::Object(fields) => {
            for (key, field) in fields {
                collect_strings(field, format!("{path}.{key}"), out);
            }
        }
        _ => {}
    }
}

//! Public API regression for caller-supplied capture-freshness evaluation.

use chrono::{DateTime, Duration, Utc};
use cmtraceopen_parser::dsregcmd::{
    analyze_text, analyze_text_with_evidence, models::DsregcmdCaptureConfidence,
    DsregcmdBundleEvidence,
};

// The fixed recent-interactive sample from
// dsregcmd/rules.rs::derives_high_capture_confidence_for_recent_interactive_capture.
const INTERACTIVE_CAPTURE: &str = "\n AzureAdJoined : YES\n DomainJoined : YES\n AzureAdPrt : YES\n AzureAdPrtUpdateTime : 2026-03-10 10:30:00.000 UTC\n Client Time : 2026-03-10 10:30:00.000 UTC\n User Context : UN-ELEVATED User\n SessionIsNotRemote : YES\n";

fn captured_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-03-10T10:30:00Z")
        .expect("fixed fixture instant")
        .with_timezone(&Utc)
}

#[test]
fn public_analysis_uses_the_supplied_instant_at_existing_freshness_boundaries() {
    use DsregcmdCaptureConfidence::{High, Low, Medium};

    // Preserve the existing whole-minute and absolute-age semantics.
    for (elapsed_seconds, expected) in [
        (0, High),
        (15 * 60 + 59, High),
        (16 * 60, Medium),
        (24 * 60 * 60 + 59, Medium),
        (24 * 60 * 60 + 60, Low),
        (-16 * 60, Medium),
    ] {
        let evaluated_at = captured_at() + Duration::seconds(elapsed_seconds);
        let plain = analyze_text(INTERACTIVE_CAPTURE, evaluated_at).expect("capture parses");
        let with_evidence = analyze_text_with_evidence(
            INTERACTIVE_CAPTURE,
            DsregcmdBundleEvidence::default(),
            evaluated_at,
        )
        .expect("capture with evidence parses");
        assert_eq!(plain.derived.capture_confidence, expected);
        assert_eq!(with_evidence.derived.capture_confidence, expected);

        let published = serde_json::to_value(&plain).expect("analysis serializes");
        assert_eq!(
            published,
            serde_json::to_value(&with_evidence).expect("evidence analysis serializes")
        );
        assert_eq!(
            published,
            serde_json::to_value(
                analyze_text(INTERACTIVE_CAPTURE, evaluated_at).expect("repeat capture parses")
            )
            .expect("repeat analysis serializes")
        );
    }
}

#[test]
fn explicit_time_preserves_parse_errors_at_both_public_entry_points() {
    assert!(analyze_text("", captured_at()).is_err());
    assert!(
        analyze_text_with_evidence("", DsregcmdBundleEvidence::default(), captured_at()).is_err()
    );
}

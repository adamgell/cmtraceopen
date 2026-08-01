//! Turn the shared normalized inputs into typed configuration observations.
//!
//! Nothing here decides an outcome for a *setting*; it decides what one record
//! says. The reducer combines them. Keeping the two apart is what makes a
//! contradiction visible instead of being resolved by whichever record was
//! projected last.

use crate::intune::evidence::{
    IntuneErrorCode, IntuneNamedValue, IntuneObservationContext, IntuneParseState, IntuneTimestamp,
    IntuneTimestampKind,
};
use crate::intune::normalized::{
    NormalizedSettingOutcome, NormalizedSettingReport, NormalizedWindowsEvent,
};

use super::identity::{
    csp_uri_from_message, policy_uri_from_message, resolve_identity, result_token_from_message,
    source_id_from_message, ConfigurationScope, IdentityHints,
};
use super::models::{
    evidence_side, ConfigurationDisposition, ConfigurationEventKind, ConfigurationEvidenceSide,
    ConfigurationObservation,
};

/// The MDM provider family whose Admin channel this analyzer understands.
///
/// Records from any other provider are still projected — they may legitimately
/// name a CSP node — but their event IDs are never interpreted, because event ID
/// 404 means something entirely different in another provider's namespace.
pub const MDM_DIAGNOSTICS_PROVIDER: &str =
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider";

/// Event ID for `MDM ConfigurationManager: Command failure status`.
pub const EVENT_ID_COMMAND_FAILURE: u32 = 404;
/// Event ID for `MDM PolicyManager: Set policy int`.
pub const EVENT_ID_SET_POLICY_INT: u32 = 813;
/// Event ID for `MDM PolicyManager: Set policy string`.
pub const EVENT_ID_SET_POLICY_STRING: u32 = 814;
/// Event ID for `MDM PolicyManager: Delete policy`.
pub const EVENT_ID_DELETE_POLICY: u32 = 815;

/// Named-value keys carrying the CSP node path, in preference order.
const URI_KEYS: [&str; 6] = [
    "NodeUri",
    "CspUri",
    "CSPURI",
    "SettingUri",
    "Uri",
    "OmaUri",
];
const SOURCE_ID_KEYS: [&str; 4] = [
    "ConfigurationSourceId",
    "PolicyId",
    "SourceId",
    "ConfigSourceId",
];
const ENROLLMENT_KEYS: [&str; 2] = ["EnrollmentId", "EnrollmentName"];
const COMMAND_TYPE_KEYS: [&str; 2] = ["CommandType", "Command"];
const RESULT_KEYS: [&str; 4] = ["Result", "ResultCode", "ErrorCode", "Hresult"];
const VALUE_KEYS: [&str; 3] = ["Value", "SettingValue", "Data"];
const DISPLAY_NAME_KEYS: [&str; 2] = ["DisplayName", "SettingName"];
const SCOPE_KEYS: [&str; 2] = ["Scope", "TargetScope"];
const WINNING_KEYS: [&str; 3] = ["WinningPolicyId", "WinningProvider", "ConflictWinner"];
const SUPERSEDED_BY_KEYS: [&str; 2] = ["SupersededBy", "SupersedingPolicyId"];

/// Case-insensitive lookup of the first key present in `named_data`.
pub fn named<'a>(named_data: &'a [IntuneNamedValue], keys: &[&str]) -> Option<&'a str> {
    for key in keys {
        if let Some(found) = named_data
            .iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(key))
        {
            let value = found.value.trim();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Parse a status token into every form it was or could have been written in.
///
/// Hex tokens with the high bit set are also reported as the signed decimal
/// Windows uses for the same HRESULT, because the two forms show up in different
/// artifacts for the same failure and a reader should not have to convert.
pub fn build_error_code(raw: &str) -> Option<IntuneErrorCode> {
    let trimmed = raw.trim().trim_matches(['(', ')']).trim();
    if trimmed.is_empty() {
        return None;
    }

    let (decimal, hex) = if let Some(digits) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        let parsed = u64::from_str_radix(digits, 16).ok()?;
        let decimal = if parsed <= u64::from(u32::MAX) {
            Some(i64::from(parsed as u32 as i32))
        } else {
            i64::try_from(parsed).ok()
        };
        (decimal, Some(format!("0x{parsed:08X}")))
    } else {
        let parsed = trimmed.parse::<i64>().ok()?;
        let hex = u32::try_from(parsed)
            .map(|value| format!("0x{value:08X}"))
            .or_else(|_| i32::try_from(parsed).map(|value| format!("0x{:08X}", value as u32)))
            .ok();
        (Some(parsed), hex)
    };

    Some(IntuneErrorCode {
        raw: trimmed.to_owned(),
        decimal,
        hex,
    })
}

/// Whether a status code states a failure.
///
/// A code whose decimal form could not be determined is *not* treated as a
/// failure: an uninterpretable token is missing evidence, not bad news.
pub fn is_failure(code: &IntuneErrorCode) -> bool {
    matches!(code.decimal, Some(value) if value != 0)
}

/// Whether the record's own timestamp can be compared with another record's.
///
/// Local and unspecified wall-clock stamps are rejected for comparison even
/// though they are perfectly readable: without an offset there is no way to know
/// whether a device stamp precedes a service stamp, and issue #363 forbids
/// resolving a contradiction by recency without reliable provenance.
pub fn timestamp_is_reliable(timestamp: Option<&IntuneTimestamp>) -> bool {
    match timestamp {
        None => true,
        Some(stamp) => {
            matches!(
                stamp.kind,
                IntuneTimestampKind::Utc | IntuneTimestampKind::Offset
            ) && stamp.normalized_utc.is_some()
        }
    }
}

fn normalized_instant(context: &IntuneObservationContext) -> Option<String> {
    context
        .source_timestamp
        .as_ref()
        .and_then(|stamp| stamp.normalized_utc.clone())
}

fn is_uninterpretable(context: &IntuneObservationContext) -> bool {
    matches!(
        context.parse_state,
        IntuneParseState::Malformed | IntuneParseState::Unsupported
    )
}

/// Classify a recognized MDM Admin-channel event ID.
pub fn classify_event(event: &NormalizedWindowsEvent) -> ConfigurationEventKind {
    if !event.provider.eq_ignore_ascii_case(MDM_DIAGNOSTICS_PROVIDER) {
        return ConfigurationEventKind::Unrecognized;
    }
    match event.event_id {
        EVENT_ID_COMMAND_FAILURE => ConfigurationEventKind::CommandFailure,
        EVENT_ID_SET_POLICY_INT | EVENT_ID_SET_POLICY_STRING => ConfigurationEventKind::PolicySet,
        EVENT_ID_DELETE_POLICY => ConfigurationEventKind::PolicyDeleted,
        _ => ConfigurationEventKind::Unrecognized,
    }
}

fn command_type_is_removal(command_type: Option<&str>) -> bool {
    command_type.is_some_and(|value| {
        let value = value.trim().trim_matches(['(', ')']);
        value.eq_ignore_ascii_case("Delete") || value.eq_ignore_ascii_case("Remove")
    })
}

/// Project one normalized event onto a configuration observation.
///
/// Returns `None` when the record names no CSP resource at all and therefore has
/// nothing to say about configuration; such records are not evidence of anything
/// here and inventing an identity for them would fabricate a transaction.
pub fn observation_from_event(event: &NormalizedWindowsEvent) -> Option<ConfigurationObservation> {
    let context = &event.context;
    let event_kind = classify_event(event);
    let message = event.message.as_deref().unwrap_or_default();

    let uri = named(&event.named_data, &URI_KEYS)
        .map(str::to_owned)
        .or_else(|| csp_uri_from_message(message))
        .or_else(|| {
            // PolicyManager events name Policy/Area rather than a node path.
            let scope = named(&event.named_data, &SCOPE_KEYS)
                .map(ConfigurationScope::from_token)
                .unwrap_or(ConfigurationScope::Device);
            policy_uri_from_message(message, scope)
        });

    let setting_id = named(&event.named_data, &["SettingId"]).map(str::to_owned);
    if uri.is_none() && setting_id.is_none() {
        return None;
    }

    let identity = resolve_identity(&IdentityHints {
        uri: uri.as_deref(),
        setting_id: setting_id.as_deref(),
        policy_id: named(&event.named_data, &SOURCE_ID_KEYS),
        display_name: named(&event.named_data, &DISPLAY_NAME_KEYS),
        scope_token: named(&event.named_data, &SCOPE_KEYS),
        evidence_id: &context.evidence_ref.evidence_id,
    });

    let error = named(&event.named_data, &RESULT_KEYS)
        .map(str::to_owned)
        .or_else(|| result_token_from_message(message))
        .as_deref()
        .and_then(build_error_code);

    let command_type = named(&event.named_data, &COMMAND_TYPE_KEYS).map(str::to_owned);
    let uninterpretable = is_uninterpretable(context);

    let disposition = if uninterpretable {
        ConfigurationDisposition::Indeterminate
    } else {
        match event_kind {
            // 404 is the failure event. Without a readable non-zero status the
            // record still proves the CSP rejected something, but not what, so
            // it stays indeterminate rather than asserting a rejection.
            ConfigurationEventKind::CommandFailure => match error.as_ref() {
                Some(code) if is_failure(code) => ConfigurationDisposition::Rejected,
                _ => ConfigurationDisposition::Indeterminate,
            },
            ConfigurationEventKind::PolicySet => {
                if command_type_is_removal(command_type.as_deref()) {
                    ConfigurationDisposition::Removed
                } else {
                    ConfigurationDisposition::Applied
                }
            }
            ConfigurationEventKind::PolicyDeleted => ConfigurationDisposition::Removed,
            ConfigurationEventKind::Unrecognized => ConfigurationDisposition::Received,
        }
    };

    Some(ConfigurationObservation {
        evidence_ref: context.evidence_ref.clone(),
        side: evidence_side(&context.provenance.source_kind),
        source_kind: context.provenance.source_kind.clone(),
        sensitivity: context.sensitivity.clone(),
        identity,
        disposition,
        event_kind: Some(event_kind),
        event_id: Some(event.event_id),
        source_id: named(&event.named_data, &SOURCE_ID_KEYS)
            .map(str::to_owned)
            .or_else(|| source_id_from_message(message)),
        enrollment_id: named(&event.named_data, &ENROLLMENT_KEYS).map(str::to_owned),
        command_type,
        value: named(&event.named_data, &VALUE_KEYS).map(str::to_owned),
        error,
        winning_source_id: named(&event.named_data, &WINNING_KEYS).map(str::to_owned),
        superseded_by_source_id: named(&event.named_data, &SUPERSEDED_BY_KEYS).map(str::to_owned),
        occurred_at_utc: normalized_instant(context),
        time_is_reliable: timestamp_is_reliable(context.source_timestamp.as_ref()),
        record_id: event.record_id,
        is_uninterpretable: uninterpretable,
        named_data: event.named_data.clone(),
    })
}

/// Project one normalized report row onto a configuration observation.
///
/// Unlike events, a report row is always retained: the row exists because a
/// report named the setting, and even an unidentified row is coverage that a
/// reader needs to see. It keys on its own evidence id in that case.
pub fn observation_from_report(report: &NormalizedSettingReport) -> ConfigurationObservation {
    let context = &report.context;

    let identity = resolve_identity(&IdentityHints {
        uri: report.setting_uri.as_deref(),
        setting_id: report.setting_id.as_deref(),
        policy_id: report.policy_id.as_deref(),
        display_name: report.display_name.as_deref(),
        scope_token: named(&report.named_data, &SCOPE_KEYS),
        evidence_id: &context.evidence_ref.evidence_id,
    });

    let command_type = named(&report.named_data, &COMMAND_TYPE_KEYS).map(str::to_owned);
    let uninterpretable = is_uninterpretable(context);

    let disposition = if uninterpretable {
        ConfigurationDisposition::Indeterminate
    } else {
        match report.outcome {
            NormalizedSettingOutcome::Applied => {
                if command_type_is_removal(command_type.as_deref()) {
                    ConfigurationDisposition::Removed
                } else {
                    ConfigurationDisposition::Applied
                }
            }
            NormalizedSettingOutcome::Pending => ConfigurationDisposition::Pending,
            NormalizedSettingOutcome::Failed => ConfigurationDisposition::Rejected,
            NormalizedSettingOutcome::Conflict => ConfigurationDisposition::Conflict,
            NormalizedSettingOutcome::Superseded => ConfigurationDisposition::Superseded,
            NormalizedSettingOutcome::NotApplicable => ConfigurationDisposition::NotApplicable,
            NormalizedSettingOutcome::Unknown => ConfigurationDisposition::Received,
        }
    };

    let error = report.error.clone().or_else(|| {
        named(&report.named_data, &RESULT_KEYS).and_then(build_error_code)
    });

    ConfigurationObservation {
        evidence_ref: context.evidence_ref.clone(),
        side: evidence_side(&context.provenance.source_kind),
        source_kind: context.provenance.source_kind.clone(),
        sensitivity: context.sensitivity.clone(),
        identity,
        disposition,
        event_kind: None,
        event_id: None,
        source_id: report
            .policy_id
            .clone()
            .or_else(|| named(&report.named_data, &SOURCE_ID_KEYS).map(str::to_owned)),
        enrollment_id: named(&report.named_data, &ENROLLMENT_KEYS).map(str::to_owned),
        command_type,
        value: report
            .value
            .clone()
            .or_else(|| named(&report.named_data, &VALUE_KEYS).map(str::to_owned)),
        error,
        winning_source_id: named(&report.named_data, &WINNING_KEYS).map(str::to_owned),
        superseded_by_source_id: named(&report.named_data, &SUPERSEDED_BY_KEYS).map(str::to_owned),
        occurred_at_utc: normalized_instant(context),
        time_is_reliable: timestamp_is_reliable(context.source_timestamp.as_ref()),
        record_id: context.provenance.record_number,
        is_uninterpretable: uninterpretable,
        named_data: report.named_data.clone(),
    }
}

/// True when the observation was contributed by device-side evidence.
pub fn is_device_side(observation: &ConfigurationObservation) -> bool {
    observation.side == ConfigurationEvidenceSide::Device
}

/// True when the observation was contributed by imported service-side evidence.
pub fn is_service_side(observation: &ConfigurationObservation) -> bool {
    observation.side == ConfigurationEvidenceSide::Service
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_status_reports_both_the_hresult_and_its_signed_decimal() {
        let code = build_error_code("(0x82B00006)").expect("hex token parses");
        assert_eq!(code.raw, "0x82B00006");
        assert_eq!(code.hex.as_deref(), Some("0x82B00006"));
        assert_eq!(code.decimal, Some(-2102394874));
        assert!(is_failure(&code));
    }

    #[test]
    fn zero_status_is_not_a_failure() {
        let code = build_error_code("0").expect("zero parses");
        assert!(!is_failure(&code));
    }

    #[test]
    fn an_unparseable_status_yields_no_code_rather_than_a_guess() {
        assert!(build_error_code("not-a-code").is_none());
        assert!(build_error_code("   ").is_none());
    }

    #[test]
    fn a_negative_decimal_status_reports_its_hresult_form() {
        let code = build_error_code("-2016281112").expect("decimal token parses");
        assert_eq!(code.hex.as_deref(), Some("0x87D1FDE8"));
    }

    #[test]
    fn local_wall_clock_timestamps_are_not_comparable() {
        let stamp = IntuneTimestamp {
            raw_text: "7/31/2026 1:00:00 PM".to_owned(),
            original_offset: None,
            normalized_utc: Some("2026-07-31T13:00:00Z".to_owned()),
            kind: IntuneTimestampKind::Local,
        };
        assert!(!timestamp_is_reliable(Some(&stamp)));
    }

    #[test]
    fn a_missing_timestamp_is_not_a_broken_timestamp() {
        assert!(timestamp_is_reliable(None));
    }

    #[test]
    fn named_lookup_is_case_insensitive_and_skips_blank_values() {
        let data = vec![
            IntuneNamedValue {
                name: "nodeuri".to_owned(),
                value: "   ".to_owned(),
            },
            IntuneNamedValue {
                name: "SettingUri".to_owned(),
                value: "./Device/Vendor/MSFT/Policy".to_owned(),
            },
        ];
        assert_eq!(
            named(&data, &URI_KEYS),
            Some("./Device/Vendor/MSFT/Policy")
        );
    }
}

//! Classification of normalized Autopilot records into typed signals.
//!
//! # The validated event contract
//!
//! Only the event IDs Microsoft documents for the Autopilot channel carry
//! meaning here. The table below is transcribed from *Windows Autopilot
//! troubleshooting FAQ*, "What do the different Event IDs mean in the Windows
//! Autopilot event log entries in Event Viewer?".
//!
//! | ID  | Documented message                                                    |
//! |-----|-----------------------------------------------------------------------|
//! | 100 | `Autopilot policy [name] not found.` (documented as usually transient) |
//! | 101 | `AutopilotGetPolicyDwordByName succeeded`                              |
//! | 103 | `AutopilotGetPolicyStringByName succeeded`                             |
//! | 109 | `AutopilotGetOobeSettingsOverride succeeded`                           |
//! | 111 | `AutopilotRetrieveSettings succeeded.`                                 |
//! | 153 | `AutopilotManager reported the state changed from [x] to [y].`         |
//! | 160 | `AutopilotRetrieveSettings beginning acquisition.`                     |
//! | 161 | `AutopilotManager retrieve settings succeeded.`                        |
//! | 163 | download not required; device already provisioned                      |
//! | 164 | internet available to attempt policy download                          |
//! | 171 | `AutopilotManager failed to set TPM identity confirmed. HRESULT=[x]`   |
//! | 172 | `AutopilotManager failed to set Autopilot profile as available.`       |
//! | 807 | `ZtdDeviceIsNotRegistered`                                             |
//! | 809 | `ZtdDeviceHasNoAssignedProfile - Assigned profile does not exist.`     |
//! | 815 | `ZtdDeviceHasNoAssignedProfile - No profile assigned […] no default.`  |
//! | 908 | `SerialNumberMismatch` / `ProductKeyIdMismatch`                        |
//!
//! Anything outside this table classifies as
//! [`AutopilotSignal::Unclassified`]. That is the whole point: an undocumented
//! event may not be promoted into a terminal state on a guess, and an event
//! from an unrelated MDM channel may not contribute identifiers at all.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneErrorCode, IntuneNamedValue};
use crate::intune::normalized::NormalizedWindowsEvent;

use super::models::{
    AutopilotOobeSetting, AutopilotProfileStateToken, AutopilotSignal,
};
use super::sources::{AUTOPILOT_EVENT_CHANNEL, AUTOPILOT_EVENT_PROVIDER};

/// Whether a record came from the validated Autopilot channel.
///
/// Both the provider and the channel must match. A `ManagementService` record
/// from the same provider is a different contract and is not Autopilot
/// evidence, so provider alone is not enough.
pub fn is_autopilot_channel(event: &NormalizedWindowsEvent) -> bool {
    event
        .provider
        .trim()
        .eq_ignore_ascii_case(AUTOPILOT_EVENT_PROVIDER)
        && event
            .channel
            .trim()
            .eq_ignore_ascii_case(AUTOPILOT_EVENT_CHANNEL)
}

/// Classify one normalized event against the documented table.
///
/// Returns `None` when the record is not Autopilot evidence at all, which is
/// different from `Some(Unclassified)`: the former is silently ignored, the
/// latter is retained and surfaced as a visible gap.
pub fn classify_event(event: &NormalizedWindowsEvent) -> Option<AutopilotSignal> {
    if !is_autopilot_channel(event) {
        return None;
    }
    Some(match event.event_id {
        160 => AutopilotSignal::ProfileAcquisitionStarted,
        164 => AutopilotSignal::NetworkAvailableForDownload,
        100 => AutopilotSignal::ProfilePolicyNotFound,
        161 => AutopilotSignal::ProfileRetrieveSucceeded,
        153 => AutopilotSignal::ProfileStateChanged,
        111 => AutopilotSignal::ProfileSettingsRetrieved,
        101 | 103 | 109 => AutopilotSignal::OobeSettingObserved,
        163 => AutopilotSignal::DeviceAlreadyProvisioned,
        171 => AutopilotSignal::TpmIdentityFailed,
        172 => AutopilotSignal::ProfileApplicationFailed,
        807 => AutopilotSignal::DeviceNotRegistered,
        809 => AutopilotSignal::AssignedProfileMissing,
        815 => AutopilotSignal::NoAssignedProfile,
        908 => AutopilotSignal::IdentityMismatch,
        _ => AutopilotSignal::Unclassified,
    })
}

// ── Message extraction ──────────────────────────────────────────────────────

fn hresult_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bHRESULT\s*=\s*(?P<code>0x[0-9a-f]{1,16}|-?\d{1,20})")
            .expect("hresult regex must compile")
    })
}

fn profile_state_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)state changed from\s+(?P<from>ProfileState_[A-Za-z0-9_]+)\s+to\s+(?P<to>ProfileState_[A-Za-z0-9_]+)",
        )
        .expect("profile state regex must compile")
    })
}

fn oobe_setting_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // Event 109 is documented both as `OOBE setting = NAME` and as
        // `OOBE setting NAME`, so the `=` is optional.
        Regex::new(
            r"(?i)OOBE setting\s*=?\s*(?P<setting>[A-Z][A-Z0-9_]{3,})\s*;\s*state\s*=\s*(?P<state>[A-Za-z0-9_]+)",
        )
        .expect("oobe setting regex must compile")
    })
}

fn policy_pair_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)policy name\s*=\s*(?P<name>[^;]+?)\s*;\s*(?:policy )?value\s*=\s*(?P<value>[^;]+?)\s*\.?$",
        )
        .expect("policy pair regex must compile")
    })
}

/// Extract an `HRESULT=` token from a rendered message.
///
/// The raw token is always kept. Only an unambiguously parseable value gets a
/// decimal and a canonical hex form; a token we cannot read stays raw rather
/// than becoming a number the log never stated.
pub fn extract_error_code(message: Option<&str>) -> Option<IntuneErrorCode> {
    let captures = hresult_re().captures(message?)?;
    Some(error_code_from_token(captures.name("code")?.as_str()))
}

/// Build an [`IntuneErrorCode`] from a raw token in any of the forms Intune
/// uses: `0x80070002`, `-2147024894`, or an unsigned decimal.
pub fn error_code_from_token(raw: &str) -> IntuneErrorCode {
    let trimmed = raw.trim();
    let decimal = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|value| u32::try_from(value).ok())
            .map(|value| i64::from(value as i32))
            .or_else(|| u64::from_str_radix(hex, 16).ok().map(|value| value as i64))
    } else {
        trimmed.parse::<i64>().ok()
    };
    let hex = decimal.and_then(|value| {
        u32::try_from(value)
            .ok()
            .or_else(|| i32::try_from(value).ok().map(|value| value as u32))
            .map(|value| format!("0x{value:08X}"))
    });
    IntuneErrorCode {
        raw: trimmed.to_owned(),
        decimal,
        hex,
    }
}

/// Extract the `ProfileState_*` transition an event 153 message reports.
pub fn extract_profile_state(message: Option<&str>) -> Option<AutopilotProfileStateToken> {
    let captures = profile_state_re().captures(message?)?;
    Some(profile_state_token(captures.name("to")?.as_str()))
}

fn profile_state_token(raw: &str) -> AutopilotProfileStateToken {
    serde_json::from_value(serde_json::Value::String(raw.to_owned()))
        .unwrap_or_else(|_| AutopilotProfileStateToken::Unknown(raw.to_owned()))
}

/// Extract the OOBE setting name and state an event 109 message reports.
pub fn extract_oobe_setting(message: Option<&str>) -> Option<(AutopilotOobeSetting, String)> {
    let captures = oobe_setting_re().captures(message?)?;
    let setting = captures.name("setting")?.as_str();
    let state = captures.name("state")?.as_str().to_owned();
    let setting = serde_json::from_value(serde_json::Value::String(setting.to_owned()))
        .unwrap_or_else(|_| AutopilotOobeSetting::Unknown(setting.to_owned()));
    Some((setting, state))
}

/// Extract the `policy name = …; policy value = …` pair events 101 and 103
/// report, so a caller keeps the pair without this module modeling every
/// possible setting name.
pub fn extract_policy_pair(message: Option<&str>) -> Option<IntuneNamedValue> {
    let captures = policy_pair_re().captures(message?)?;
    Some(IntuneNamedValue {
        name: captures.name("name")?.as_str().trim().to_owned(),
        value: captures.name("value")?.as_str().trim().to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneObservationContext, IntuneParseState,
        IntuneProvenance, IntuneSensitivity, IntuneSourceKind,
    };
    use crate::intune::normalized::NormalizedEventLevel;

    fn event(channel: &str, provider: &str, event_id: u32) -> NormalizedWindowsEvent {
        NormalizedWindowsEvent {
            context: IntuneObservationContext {
                evidence_ref: IntuneEvidenceRef {
                    evidence_id: "e".to_owned(),
                    source_artifact_id: "a".to_owned(),
                },
                provenance: IntuneProvenance {
                    source_kind: IntuneSourceKind::EventLog,
                    source_artifact_id: "a".to_owned(),
                    file_path: None,
                    line_number: None,
                    record_number: None,
                    registry: None,
                    event: None,
                },
                source_timestamp: None,
                observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
                sensitivity: IntuneSensitivity::Public,
                parse_state: IntuneParseState::Parsed,
                access_state: IntuneAccessState::Available,
            },
            channel: channel.to_owned(),
            provider: provider.to_owned(),
            event_id,
            level: NormalizedEventLevel::Information,
            task: None,
            keywords: None,
            record_id: None,
            activity_id: None,
            named_data: Vec::new(),
            message: None,
        }
    }

    #[test]
    fn a_record_from_another_channel_of_the_same_provider_is_not_autopilot_evidence() {
        let sibling = event(
            "Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService",
            AUTOPILOT_EVENT_PROVIDER,
            161,
        );
        assert_eq!(classify_event(&sibling), None);
    }

    #[test]
    fn documented_event_ids_map_to_their_documented_meaning() {
        for (id, expected) in [
            (160, AutopilotSignal::ProfileAcquisitionStarted),
            (161, AutopilotSignal::ProfileRetrieveSucceeded),
            (100, AutopilotSignal::ProfilePolicyNotFound),
            (807, AutopilotSignal::DeviceNotRegistered),
            (815, AutopilotSignal::NoAssignedProfile),
            (908, AutopilotSignal::IdentityMismatch),
        ] {
            let record = event(AUTOPILOT_EVENT_CHANNEL, AUTOPILOT_EVENT_PROVIDER, id);
            assert_eq!(classify_event(&record), Some(expected), "event {id}");
        }
    }

    #[test]
    fn an_undocumented_event_id_stays_unclassified_rather_than_guessing() {
        let record = event(AUTOPILOT_EVENT_CHANNEL, AUTOPILOT_EVENT_PROVIDER, 4242);
        assert_eq!(
            classify_event(&record),
            Some(AutopilotSignal::Unclassified),
            "an undocumented event must never acquire terminal semantics"
        );
    }

    #[test]
    fn a_transient_policy_not_found_is_never_a_terminal_failure() {
        assert!(!AutopilotSignal::ProfilePolicyNotFound.is_terminal_failure());
        assert!(AutopilotSignal::NoAssignedProfile.is_terminal_failure());
    }

    #[test]
    fn hresult_tokens_keep_their_raw_form_and_gain_both_derived_forms() {
        let code = extract_error_code(Some(
            "AutopilotManager failed to set TPM identity confirmed. HRESULT=0x801C03EA",
        ))
        .expect("an HRESULT must be extracted");
        assert_eq!(code.raw, "0x801C03EA");
        assert_eq!(code.hex.as_deref(), Some("0x801C03EA"));
        assert_eq!(code.decimal, Some(-2_145_647_638));
    }

    #[test]
    fn a_message_without_an_hresult_yields_no_error_code() {
        assert!(extract_error_code(Some("AutopilotRetrieveSettings succeeded.")).is_none());
        assert!(extract_error_code(None).is_none());
    }

    #[test]
    fn a_profile_state_transition_reports_the_destination_state() {
        assert_eq!(
            extract_profile_state(Some(
                "AutopilotManager reported the state changed from ProfileState_Unknown to ProfileState_Available."
            )),
            Some(AutopilotProfileStateToken::Available)
        );
    }

    #[test]
    fn an_unrecognized_profile_state_round_trips_verbatim() {
        let token = extract_profile_state(Some(
            "state changed from ProfileState_Unknown to ProfileState_SomethingNew",
        ))
        .expect("a token must be extracted");
        assert_eq!(
            token,
            AutopilotProfileStateToken::Unknown("ProfileState_SomethingNew".to_owned())
        );
    }

    #[test]
    fn an_oobe_setting_override_yields_the_setting_and_its_state() {
        let (setting, state) = extract_oobe_setting(Some(
            "AutopilotGetOobeSettingsOverride succeeded: OOBE setting = AUTOPILOT_OOBE_SETTINGS_AAD_JOIN_ONLY; state = enabled.",
        ))
        .expect("an OOBE setting must be extracted");
        assert_eq!(setting, AutopilotOobeSetting::AadJoinOnly);
        assert_eq!(state, "enabled");
    }

    #[test]
    fn a_policy_pair_is_kept_without_modeling_every_setting_name() {
        let pair = extract_policy_pair(Some(
            "AutopilotGetPolicyStringByName succeeded: policy name = CloudAssignedTenantDomain; policy value = contoso.example.",
        ))
        .expect("a policy pair must be extracted");
        assert_eq!(pair.name, "CloudAssignedTenantDomain");
        assert_eq!(pair.value, "contoso.example");
    }
}

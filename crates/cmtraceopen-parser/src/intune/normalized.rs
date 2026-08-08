//! Platform-neutral normalized inputs shared by the Windows workload leaves.
//!
//! Issues #358, #363, #364, and #365 all need to reason over Windows event-log
//! records and CSP/setting report rows. The native side of the product reads
//! those from EVTX files, the live Windows event log, and MDM diagnostic reports,
//! none of which can be represented in this crate: `evtx`, `windows`, and
//! `winreg` are all excluded by the wasm32 invariant documented in `lib.rs`.
//!
//! So the boundary is drawn here. Native adapters decode their platform sources
//! and hand the pure crate the normalized shapes below. The leaves then contain
//! only pure reduction logic, which is what makes them testable from fixtures
//! with no device present.
//!
//! This module is owned by the parser-family skeleton because four separate
//! issues depend on it. If it lived in one of them, the other three could not
//! merge until that one landed.

use serde::{Deserialize, Serialize};

use crate::intune::evidence::{IntuneErrorCode, IntuneNamedValue, IntuneObservationContext};

/// Schema version for the normalized input contracts in this module.
pub const INTUNE_NORMALIZED_SCHEMA_VERSION: u32 = 1;

/// Severity level of a Windows event, as the platform reported it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NormalizedEventLevel {
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
    Unknown,
}

/// A Windows event-log record projected into a form this crate can consume.
///
/// Field choice follows what the four consuming issues actually key on:
/// `provider` + `event_id` identify the signal, `record_id` orders records within
/// a channel, `activity_id` correlates a multi-event operation, and `named_data`
/// carries the event's payload without interpretation so a leaf can extract what
/// it needs without this type growing a field per workload.
///
/// `message` is the already-rendered description. It is `Option` because
/// rendering requires the provider's message resources, which are frequently
/// unavailable when an EVTX file is read off-box.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedWindowsEvent {
    pub context: IntuneObservationContext,
    pub channel: String,
    pub provider: String,
    pub event_id: u32,
    pub level: NormalizedEventLevel,
    pub task: Option<String>,
    pub keywords: Option<String>,
    pub record_id: Option<u64>,
    pub activity_id: Option<String>,
    pub event_version: Option<u32>,
    pub named_data: Vec<IntuneNamedValue>,
    pub message: Option<String>,
}

/// Outcome the device reported for a single setting or policy row.
///
/// `NotApplicable` and `Unknown` are separate because "this device was never in
/// scope" and "we could not tell" lead to different next steps.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum NormalizedSettingOutcome {
    Applied,
    Pending,
    Failed,
    Conflict,
    Superseded,
    NotApplicable,
    Unknown,
}

/// One row of a CSP, configuration, or compliance report.
///
/// `setting_uri` is the OMA-DM node path when the source provides one; leaves
/// that key on a policy or setting GUID instead use `setting_id`. Both are
/// optional because different report sources supply different identifiers, and
/// fabricating the missing one would invent a correlation key.
///
/// `value` is deliberately `Option<String>` and classified by the enclosing
/// context's sensitivity: configuration values routinely contain tenant-specific
/// data that must not reach a redacted export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NormalizedSettingReport {
    pub context: IntuneObservationContext,
    pub setting_uri: Option<String>,
    pub setting_id: Option<String>,
    pub policy_id: Option<String>,
    pub display_name: Option<String>,
    pub outcome: NormalizedSettingOutcome,
    pub value: Option<String>,
    pub error: Option<IntuneErrorCode>,
    pub named_data: Vec<IntuneNamedValue>,
}

// Extending this module from a workload leaf:
//
// Read anything not modeled here out of `named_data`, which is carried verbatim.
// If a field is genuinely shared across leaves, append an `Option<T>` at the end
// of the struct; that is additive, keeps the schema version at 1, and does not
// disturb sibling branches.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneParseState, IntuneProvenance, IntuneSensitivity,
        IntuneSourceKind,
    };

    fn context() -> IntuneObservationContext {
        IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: "e1".to_owned(),
                source_artifact_id: "a1".to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::EventLog,
                source_artifact_id: "a1".to_owned(),
                file_path: None,
                line_number: None,
                record_number: Some(7),
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Public,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        }
    }

    #[test]
    fn windows_event_round_trips_through_json() {
        let event = NormalizedWindowsEvent {
            context: context(),
            channel: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                .to_owned(),
            provider: "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider"
                .to_owned(),
            event_id: 404,
            level: NormalizedEventLevel::Error,
            task: None,
            keywords: None,
            record_id: Some(7),
            activity_id: None,
            event_version: None,
            named_data: vec![IntuneNamedValue {
                name: "NodeUri".to_owned(),
                value: "./Device/Vendor/MSFT/Policy".to_owned(),
            }],
            message: None,
        };

        let encoded = serde_json::to_string(&event).unwrap();
        let decoded: NormalizedWindowsEvent = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, event);
    }

    #[test]
    fn setting_report_keeps_unmodeled_fields_in_named_data() {
        let report = NormalizedSettingReport {
            context: context(),
            setting_uri: Some("./Device/Vendor/MSFT/Policy/Config/Update".to_owned()),
            setting_id: None,
            policy_id: None,
            display_name: None,
            outcome: NormalizedSettingOutcome::Conflict,
            value: None,
            error: None,
            named_data: vec![IntuneNamedValue {
                name: "WinningPolicyId".to_owned(),
                value: "00000000-0000-0000-0000-000000000001".to_owned(),
            }],
        };

        let decoded: NormalizedSettingReport =
            serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        assert_eq!(decoded.named_data.len(), 1);
        assert_eq!(decoded.outcome, NormalizedSettingOutcome::Conflict);
    }

    #[test]
    fn setting_outcome_wire_values_are_camel_case() {
        assert_eq!(
            serde_json::to_string(&NormalizedSettingOutcome::NotApplicable).unwrap(),
            "\"notApplicable\""
        );
    }
}

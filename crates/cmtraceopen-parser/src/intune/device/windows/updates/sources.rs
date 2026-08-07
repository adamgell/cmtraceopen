//! Classification of normalized inputs into typed policy and update observations.
//!
//! Every function here answers one question: *which chain does this record
//! belong to, and what does it say?* Nothing in this file reduces or concludes.
//!
//! The chain a record belongs to is decided by its **provider**, never by which
//! list a caller put it in. `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider`
//! records are policy delivery. `Microsoft-Windows-WindowsUpdateClient` records
//! are update execution. A record from anywhere else is counted as unclassified
//! rather than being forced into one of the two.
//!
//! # Extending the event tables
//!
//! [`WU_CLIENT_EVENTS`] and [`MDM_EVENTS`] are the ids this build maps. An id
//! outside them is *not* dropped: it is counted in
//! [`super::models::UpdateInputCoverage`], so "this build does not understand
//! this event" stays distinguishable from "nothing happened". Adapters that
//! decode a newer schema can steer classification through the documented
//! named-data keys below without this table changing.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneErrorCode, IntuneNamedValue};
use crate::intune::normalized::{
    NormalizedEventLevel, NormalizedSettingOutcome, NormalizedSettingReport, NormalizedWindowsEvent,
};
use crate::models::log_entry::{LogEntry, Severity};
use crate::parser::{cbs, dism, reporting_events};

use super::models::{
    PolicyObservation, PolicySignal, SupplementalLogKind, UpdateKey, UpdateObservation,
    UpdateOutcome, UpdatePhase, UpdateRegistryFact, UpdateSource, UpdateSupplementalLog,
    UpdateWorkloadOwner,
};

// ── Provider identity ───────────────────────────────────────────────────────

/// MDM policy delivery: assignment receipt, CSP application, CSP failure.
pub const MDM_DIAGNOSTICS_PROVIDER: &str =
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider";

/// Windows Update client: scan, download, install, restart.
pub const WINDOWS_UPDATE_CLIENT_PROVIDER: &str = "Microsoft-Windows-WindowsUpdateClient";

// ── Documented named-data keys ──────────────────────────────────────────────
//
// These are the `EventData` element names the Windows Update client emits, plus
// a small set of keys a native adapter may supply when it decoded something this
// build's tables do not cover. Reading them out of `named_data` rather than
// widening `NormalizedWindowsEvent` is the extension path documented in
// `crate::intune::normalized`.

/// Update GUID, as `Microsoft-Windows-WindowsUpdateClient` names it.
///
/// Microsoft's own note applies: this is the UpdateId, and it is routinely
/// confused with the revision id in log text. It is kept separate from
/// [`NAMED_UPDATE_REVISION`] for that reason.
pub const NAMED_UPDATE_GUID: &str = "updateGuid";
/// Update revision number, as the update client names it.
pub const NAMED_UPDATE_REVISION: &str = "updateRevisionNumber";
/// Human-readable update title, as the update client names it.
pub const NAMED_UPDATE_TITLE: &str = "updateTitle";
/// Failure code, as the update client names it (`win:HexInt32`).
pub const NAMED_ERROR_CODE: &str = "errorCode";
/// Update service GUID, as the update client names it. This is the single most
/// load-bearing field in the leaf: it is what the client *actually scanned*.
///
/// Present only in the v1 templates of events 19, 20, 25, 26, 31, 41, and 44, so
/// its absence is normal and never treated as a fault.
pub const NAMED_SERVICE_GUID: &str = "serviceGuid";
/// Number of updates a successful detection found, as event 26 names it.
pub const NAMED_UPDATE_COUNT: &str = "updateCount";
/// KB identifiers, when the adapter extracted them.
pub const NAMED_KB_ARTICLE_IDS: &str = "kbArticleIds";

/// Adapter-supplied phase, used only for event ids this build does not map.
pub const NAMED_ADAPTER_PHASE: &str = "cmtraceUpdatePhase";
/// Adapter-supplied outcome, used only for event ids this build does not map.
pub const NAMED_ADAPTER_OUTCOME: &str = "cmtraceUpdateOutcome";
/// Adapter-supplied deferral reason, e.g. an active-hours or deadline hold.
pub const NAMED_DEFERRAL_REASON: &str = "cmtraceDeferralReason";
/// Set by an adapter when a CSP rejected a value the build does not support.
/// The normalized setting-report contract has no `Unsupported` outcome, and
/// inventing one here would fork a shared type for a single leaf.
pub const NAMED_UNSUPPORTED_VALUE: &str = "cmtraceUnsupportedValue";
/// Policy id that won a CSP conflict, when the source reported one.
pub const NAMED_WINNING_POLICY_ID: &str = "cmtraceWinningPolicyId";
/// CSP node URI carried on an MDM event.
pub const NAMED_NODE_URI: &str = "cmtraceNodeUri";

// ── Well-known update service ids ───────────────────────────────────────────

/// `serviceGuid` values and the source each identifies.
///
/// Matched case-insensitively and with braces optional, because the same id is
/// written both ways across the event payload, the registry, and the update log.
///
/// Microsoft's caveat on this table is load-bearing and is encoded in how the
/// results are used: a service id "identifies a client abstraction, not any
/// specific service in the cloud", so `9482F4B4` does *not* prove the device
/// reached the public Windows Update endpoint rather than a WUfB-managed one.
/// That is why [`UpdateSource::WindowsUpdate`] and
/// [`UpdateSource::WindowsUpdateForBusiness`] are treated as satisfying each
/// other when an expectation is checked. Only `3DA21691` reliably means a
/// managed server (WSUS or Configuration Manager).
const UPDATE_SERVICE_IDS: [(&str, UpdateSource); 6] = [
    ("9482f4b4-e343-43b6-b170-9a65bc822c77", UpdateSource::WindowsUpdate),
    ("7971f918-a847-4430-9279-4a52d1efe18d", UpdateSource::MicrosoftUpdate),
    ("855e8a7c-ecb4-4ca3-b045-1dfa50104289", UpdateSource::MicrosoftStore),
    ("117cab2d-82b1-4b5a-a08c-4d62dbee7782", UpdateSource::MicrosoftStore),
    ("8b24b027-1dee-babb-9a95-3517dfb9c552", UpdateSource::MicrosoftStore),
    ("3da21691-e39d-4da6-8a4b-b43877bcb1b7", UpdateSource::Wsus),
];

/// The all-zero service id the client emits when no service is specified. It
/// names nothing, so it must not become an `Unknown` source that then
/// participates in a mismatch comparison.
const UNSPECIFIED_SERVICE_ID: &str = "00000000-0000-0000-0000-000000000000";

/// Resolve a service GUID to the source it identifies.
///
/// An unrecognized id round-trips as [`UpdateSource::Unknown`] rather than being
/// discarded: the raw id is the only thing a human has to work from when
/// Microsoft adds a service.
pub fn source_for_service_id(raw: &str) -> Option<UpdateSource> {
    let trimmed = raw.trim().trim_start_matches('{').trim_end_matches('}');
    if trimmed.is_empty() {
        return None;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if lowered == UNSPECIFIED_SERVICE_ID {
        return None;
    }
    UPDATE_SERVICE_IDS
        .iter()
        .find(|(id, _)| *id == lowered)
        .map(|(_, source)| source.clone())
        .or_else(|| Some(UpdateSource::Unknown(raw.trim().to_owned())))
}

// ── Event tables ────────────────────────────────────────────────────────────

/// `Microsoft-Windows-WindowsUpdateClient/Operational` ids this build maps.
///
/// Taken from the provider's own ETW manifest, restricted to ids whose meaning
/// is unambiguous. An id left out of this table is counted as unmapped rather
/// than guessed at, because a wrong phase attribution here produces exactly the
/// conflation issue #365 exists to prevent. Notably absent:
///
/// * **6** — no such event exists in the manifest, despite being widely cited.
/// * **27** (`WindowsUpdateAgentStateChange`) — no template and no documented
///   meaning, so there is nothing to map it to.
/// * **23/24** (uninstall) — a different operation from the install chain.
const WU_CLIENT_EVENTS: [(u32, UpdatePhase, UpdateOutcome); 13] = [
    // Cannot reach the update service, so detection cannot proceed.
    (16, UpdatePhase::Scan, UpdateOutcome::Failed),
    // "Installation ready": the updates are downloaded and awaiting install.
    (17, UpdatePhase::Download, UpdateOutcome::Succeeded),
    (18, UpdatePhase::Download, UpdateOutcome::Succeeded),
    (19, UpdatePhase::Install, UpdateOutcome::Succeeded),
    (20, UpdatePhase::Install, UpdateOutcome::Failed),
    (21, UpdatePhase::Reboot, UpdateOutcome::Pending),
    (22, UpdatePhase::Reboot, UpdateOutcome::Pending),
    // "Failed to check for updates with error": the detect pass itself failed.
    (25, UpdatePhase::Scan, UpdateOutcome::Failed),
    // "Successfully found N updates". N is read separately; see
    // `classify_update_client_event`, where a count of zero becomes an
    // applicability statement rather than a scan statement.
    (26, UpdatePhase::Scan, UpdateOutcome::Succeeded),
    (31, UpdatePhase::Download, UpdateOutcome::Failed),
    (41, UpdatePhase::Download, UpdateOutcome::Succeeded),
    (43, UpdatePhase::Install, UpdateOutcome::Started),
    (44, UpdatePhase::Download, UpdateOutcome::Started),
];

/// What one MDM diagnostics event id says about policy delivery.
///
/// 400 and 404 are both `MDM ConfigurationManager: Command failure status`; they
/// differ only in how the command type is encoded. 813 and 814 are
/// `MDM PolicyManager: Set policy int` and `Set policy string`. The provider's
/// manifest names every symbol generically (`task_0NNN`), so this table is the
/// only place the meanings exist.
const MDM_EVENTS: [(u32, PolicySignal); 4] = [
    (400, PolicySignal::DeliveryFailed),
    (404, PolicySignal::DeliveryFailed),
    (813, PolicySignal::Applied),
    (814, PolicySignal::Applied),
];

fn wu_client_event(event_id: u32) -> Option<(UpdatePhase, UpdateOutcome)> {
    WU_CLIENT_EVENTS
        .iter()
        .find(|(id, _, _)| *id == event_id)
        .map(|(_, phase, outcome)| (*phase, *outcome))
}

fn mdm_event(event_id: u32) -> Option<PolicySignal> {
    MDM_EVENTS
        .iter()
        .find(|(id, _)| *id == event_id)
        .map(|(_, signal)| *signal)
}

// ── Registry locations ──────────────────────────────────────────────────────

/// Registry key that redirects a device to a WSUS server, and that also holds
/// the four `SetPolicyDrivenUpdateSourceFor*` scan-source values.
pub const WSUS_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
/// Registry key holding the Automatic Updates client switch, including
/// `UseWUServer`, which is what actually activates the WSUS redirection above.
pub const WSUS_AU_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";
/// PolicyManager area where Intune lands the effective Update CSP values.
///
/// Microsoft is explicit that this is the *only* hive Intune writes for update
/// rings, which is what makes it the authoritative policy-delivery location.
pub const POLICY_MANAGER_UPDATE_KEY: &str = r"SOFTWARE\Microsoft\PolicyManager\current\device\Update";

/// Value name that points at a WSUS server.
pub const WSUS_SERVER_VALUE: &str = "WUServer";
/// Value name that turns the WSUS redirection on. Absent or `0` means the device
/// scans Windows Update, not WSUS.
pub const USE_WU_SERVER_VALUE: &str = "UseWUServer";
/// Update CSP value that points update-for-Business scan-source policy at a
/// WSUS server. Without it the four values below have no effect.
pub const UPDATE_SERVICE_URL_VALUE: &str = "UpdateServiceUrl";

/// Update-for-Business value names that select a policy-driven scan source.
///
/// Documented semantics: `0` selects Windows Update, `1` (the default) selects
/// Windows Server Update Services.
const POLICY_DRIVEN_SOURCE_VALUES: [&str; 4] = [
    "SetPolicyDrivenUpdateSourceForQualityUpdates",
    "SetPolicyDrivenUpdateSourceForFeatureUpdates",
    "SetPolicyDrivenUpdateSourceForDriverUpdates",
    "SetPolicyDrivenUpdateSourceForOtherUpdates",
];

// ── Regexes ─────────────────────────────────────────────────────────────────

fn kb_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"(?i)\bKB\s*(\d{6,8})\b").unwrap())
}

fn guid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?",
        )
        .unwrap()
    })
}

fn hresult_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r"(?i)\b0x[0-9a-f]{8}\b").unwrap())
}

fn deferral_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b(active hours|deadline|deferral|deferred|paused|postponed)\b").unwrap()
    })
}

fn reboot_pending_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b(restart required|reboot required|reboot pending|pending restart)\b")
            .unwrap()
    })
}

// ── Named-data helpers ──────────────────────────────────────────────────────

/// Case-insensitive lookup, because adapters and the raw EventData disagree on
/// casing more often than they agree.
pub fn named(values: &[IntuneNamedValue], key: &str) -> Option<String> {
    values
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(key))
        .map(|entry| entry.value.clone())
}

/// Build an error code from a raw token, keeping every form it was seen in.
pub fn error_code(raw: &str) -> Option<IntuneErrorCode> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let (decimal, hex) = if let Some(stripped) = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
    {
        match u32::from_str_radix(stripped, 16) {
            Ok(value) => (Some(value as i32 as i64), Some(format!("0x{value:08X}"))),
            Err(_) => (None, None),
        }
    } else {
        match raw.parse::<i64>() {
            Ok(value) => (Some(value), Some(format!("0x{:08X}", value as i32 as u32))),
            Err(_) => (None, None),
        }
    };
    Some(IntuneErrorCode {
        raw: raw.to_owned(),
        decimal,
        hex,
    })
}

/// Extract an update identity from named data first, then from free text.
///
/// Named data wins because it is structured; free text is a fallback for
/// supplemental formats that carry no schema at all.
pub fn update_key_from(named_data: &[IntuneNamedValue], text: Option<&str>) -> UpdateKey {
    let mut key = UpdateKey {
        update_id: named(named_data, NAMED_UPDATE_GUID).map(|value| normalize_guid(&value)),
        kb_article: named(named_data, NAMED_KB_ARTICLE_IDS)
            .as_deref()
            .and_then(first_kb),
        revision: named(named_data, NAMED_UPDATE_REVISION),
    };

    if let Some(text) = text {
        if key.kb_article.is_none() {
            key.kb_article = first_kb(text);
        }
        if key.update_id.is_none() {
            key.update_id = guid_re()
                .find(text)
                .map(|found| normalize_guid(found.as_str()));
        }
    }

    if key.kb_article.is_none() {
        if let Some(title) = named(named_data, NAMED_UPDATE_TITLE) {
            key.kb_article = first_kb(&title);
        }
    }

    key
}

/// Canonical GUID form: lowercase, brace-wrapped. Sources write it both ways and
/// a key that differs only in punctuation would fail to join itself.
fn normalize_guid(raw: &str) -> String {
    let trimmed = raw.trim().trim_start_matches('{').trim_end_matches('}');
    format!("{{{}}}", trimmed.to_ascii_lowercase())
}

fn first_kb(text: &str) -> Option<String> {
    kb_re()
        .captures(text)
        .map(|caps| format!("KB{}", &caps[1]))
}

// ── Policy chain classification ─────────────────────────────────────────────

/// Whether a CSP node URI or setting id is about Windows Update.
///
/// Deliberately narrow. A device receives hundreds of policy nodes, and treating
/// an unrelated node as update policy would let an unrelated delivery failure be
/// reported as an update-policy failure.
pub fn is_update_policy_node(node: &str) -> bool {
    let lowered = node.trim().to_ascii_lowercase();
    // `Area` on MDM PolicyManager events 813/814 is the bare word "Update".
    lowered == "update"
        || lowered.starts_with("update/")
        || lowered.contains("/update/")
        || lowered.ends_with("/update")
        || lowered.contains("windowsupdate")
        || lowered.contains("area=update")
}

/// Classify one MDM diagnostics event into a policy observation.
///
/// Returns `None` when the event is not about update policy, so an unrelated CSP
/// failure never lands in this chain.
pub fn classify_mdm_event(event: &NormalizedWindowsEvent) -> Option<PolicyObservation> {
    let signal = mdm_event(event.event_id)?;
    // The provider's templates name their fields positionally (`Message1`…).
    // On 400/404 `Message5` is the CSP URI; on 813/814 `Message2` is the policy
    // area and `Message1` the policy name. An adapter that already resolved
    // those to labels can supply `cmtraceNodeUri` instead.
    let node = named(&event.named_data, NAMED_NODE_URI)
        .or_else(|| named(&event.named_data, "NodeUri"))
        .or_else(|| named(&event.named_data, "CSPURI"))
        .or_else(|| named(&event.named_data, "Area"))
        .or_else(|| match event.event_id {
            400 | 404 => named(&event.named_data, "Message5"),
            813 | 814 => named(&event.named_data, "Message2"),
            _ => None,
        });

    // Scope check: either an explicit node names Update, or the rendered message
    // does. With neither, the event is not attributable to update policy.
    let scoped = node.as_deref().is_some_and(is_update_policy_node)
        || event
            .message
            .as_deref()
            .is_some_and(is_update_policy_node);
    if !scoped {
        return None;
    }

    let error = named(&event.named_data, "Result")
        .or_else(|| named(&event.named_data, NAMED_ERROR_CODE))
        // `HexInt1` is the HRESULT on 400/404 and the int value on 813; it is
        // only read as an error for the failure ids.
        .or_else(|| match event.event_id {
            400 | 404 => named(&event.named_data, "HexInt1"),
            _ => None,
        })
        .or_else(|| {
            event
                .message
                .as_deref()
                .and_then(|message| hresult_re().find(message))
                .map(|found| found.as_str().to_owned())
        })
        .and_then(|raw| error_code(&raw));

    // An id mapped as Applied that nonetheless carries an error and an error
    // level is a failure. Trusting the id alone would report a delivery failure
    // as a successful application.
    let signal = match signal {
        PolicySignal::Applied
            if error.is_some()
                && matches!(
                    event.level,
                    NormalizedEventLevel::Error | NormalizedEventLevel::Critical
                ) =>
        {
            PolicySignal::DeliveryFailed
        }
        other => other,
    };

    Some(PolicyObservation {
        context: event.context.clone(),
        signal,
        setting_uri: node,
        setting_id: match event.event_id {
            813 | 814 => named(&event.named_data, "Message1"),
            _ => None,
        },
        // `Message1` on 400/404 is the configuration source id (the enrollment
        // GUID); `Message3` on 813/814 is the enrollment id requesting the merge.
        policy_id: named(&event.named_data, "EnrollmentID").or_else(|| match event.event_id {
            400 | 404 => named(&event.named_data, "Message1"),
            813 | 814 => named(&event.named_data, "Message3"),
            _ => None,
        }),
        value: named(&event.named_data, "Value").or_else(|| match event.event_id {
            814 => named(&event.named_data, "Message5"),
            813 => named(&event.named_data, "HexInt1"),
            _ => None,
        }),
        error,
        event_id: Some(event.event_id),
        source: None,
        named_data: event.named_data.clone(),
    })
}

/// Classify one setting-report row into a policy observation.
pub fn classify_setting_report(report: &NormalizedSettingReport) -> Option<PolicyObservation> {
    let node = report
        .setting_uri
        .clone()
        .or_else(|| report.setting_id.clone())
        .or_else(|| report.display_name.clone())?;
    if !is_update_policy_node(&node) {
        return None;
    }

    let unsupported = named(&report.named_data, NAMED_UNSUPPORTED_VALUE)
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));

    let signal = if unsupported {
        PolicySignal::UnsupportedValue
    } else {
        match report.outcome {
            NormalizedSettingOutcome::Applied => PolicySignal::Applied,
            NormalizedSettingOutcome::Pending => PolicySignal::Pending,
            NormalizedSettingOutcome::Failed => PolicySignal::DeliveryFailed,
            NormalizedSettingOutcome::Conflict => PolicySignal::Conflict,
            NormalizedSettingOutcome::Superseded => PolicySignal::Superseded,
            NormalizedSettingOutcome::NotApplicable | NormalizedSettingOutcome::Unknown => {
                PolicySignal::Informational
            }
        }
    };

    Some(PolicyObservation {
        context: report.context.clone(),
        signal,
        setting_uri: report.setting_uri.clone(),
        setting_id: report.setting_id.clone(),
        policy_id: report.policy_id.clone(),
        value: report.value.clone(),
        error: report.error.clone(),
        event_id: None,
        source: report
            .value
            .as_deref()
            .and_then(|value| source_hint_from_value(&node, value)),
        named_data: report.named_data.clone(),
    })
}

/// Classify one registry fact into a policy observation.
///
/// Only the values that decide the effective update source are modeled. Others
/// are retained by the caller as context but make no claim.
pub fn classify_registry_fact(fact: &UpdateRegistryFact) -> Option<PolicyObservation> {
    let registry = fact.context.provenance.registry.as_ref()?;
    let key = registry.key.trim_start_matches('\\');
    let value_name = registry.value_name.as_deref().unwrap_or_default();
    let value = fact.value.as_deref().unwrap_or_default();

    let source = if key.eq_ignore_ascii_case(WSUS_POLICY_KEY)
        && value_name.eq_ignore_ascii_case(WSUS_SERVER_VALUE)
        && !value.trim().is_empty()
    {
        Some(UpdateSource::Wsus)
    } else if key.eq_ignore_ascii_case(WSUS_AU_POLICY_KEY)
        && value_name.eq_ignore_ascii_case(USE_WU_SERVER_VALUE)
    {
        // `UseWUServer=0` is the fact that a WSUS server value is *inert*, which
        // is a different statement from "no WSUS is configured".
        match value.trim() {
            "1" => Some(UpdateSource::Wsus),
            "0" => Some(UpdateSource::WindowsUpdateForBusiness),
            _ => None,
        }
    } else if key.eq_ignore_ascii_case(WSUS_POLICY_KEY)
        && POLICY_DRIVEN_SOURCE_VALUES
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(value_name))
    {
        // 0 selects Windows Update, 1 (the default) selects Windows Server
        // Update Services.
        match value.trim() {
            "0" => Some(UpdateSource::WindowsUpdateForBusiness),
            "1" => Some(UpdateSource::Wsus),
            _ => None,
        }
    } else if key.eq_ignore_ascii_case(POLICY_MANAGER_UPDATE_KEY)
        && value_name.eq_ignore_ascii_case(UPDATE_SERVICE_URL_VALUE)
        && !value.trim().is_empty()
    {
        Some(UpdateSource::Wsus)
    } else {
        None
    };

    let signal = if source.is_some() {
        PolicySignal::EffectiveSource
    } else if key.eq_ignore_ascii_case(POLICY_MANAGER_UPDATE_KEY) {
        PolicySignal::Applied
    } else {
        return None;
    };

    Some(PolicyObservation {
        context: fact.context.clone(),
        signal,
        setting_uri: Some(format!("{}\\{}", registry.key, value_name)),
        setting_id: Some(value_name.to_owned()),
        policy_id: None,
        value: fact.value.clone(),
        error: None,
        event_id: None,
        source,
        named_data: fact.named_data.clone(),
    })
}

/// Interpret a policy *value* as an update source, for the CSP nodes where the
/// value is itself the source selector.
fn source_hint_from_value(node: &str, value: &str) -> Option<UpdateSource> {
    let lowered = node.to_ascii_lowercase();
    if !POLICY_DRIVEN_SOURCE_VALUES
        .iter()
        .any(|candidate| lowered.contains(&candidate.to_ascii_lowercase()))
    {
        return None;
    }
    match value.trim() {
        "0" => Some(UpdateSource::WindowsUpdateForBusiness),
        "1" => Some(UpdateSource::Wsus),
        _ => None,
    }
}

/// Read co-management workload ownership out of a supplied fact.
pub fn workload_owner_from(named_data: &[IntuneNamedValue]) -> Option<UpdateWorkloadOwner> {
    let raw = named(named_data, "coManagementUpdateWorkloadOwner")?;
    Some(match raw.trim().to_ascii_lowercase().as_str() {
        "intune" => UpdateWorkloadOwner::Intune,
        "configurationmanager" | "sccm" | "configmgr" => UpdateWorkloadOwner::ConfigurationManager,
        "notcomanaged" => UpdateWorkloadOwner::NotCoManaged,
        _ => UpdateWorkloadOwner::Unknown(raw),
    })
}

// ── Update chain classification ─────────────────────────────────────────────

/// Outcome of classifying one event that is not from a modeled provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventClassification {
    Policy(Box<PolicyObservation>),
    Update(Box<UpdateObservation>),
    /// A modeled provider, but an event id this build does not map.
    UnmappedEventId(u32),
    /// A provider this leaf does not model at all.
    UnknownProvider(String),
    /// A modeled provider and id, but the record is not about update policy.
    OutOfScope,
}

/// Route one normalized event to its chain.
pub fn classify_event(event: &NormalizedWindowsEvent) -> EventClassification {
    if event
        .provider
        .eq_ignore_ascii_case(WINDOWS_UPDATE_CLIENT_PROVIDER)
    {
        return match classify_update_client_event(event) {
            Some(observation) => EventClassification::Update(Box::new(observation)),
            None => EventClassification::UnmappedEventId(event.event_id),
        };
    }

    if event.provider.eq_ignore_ascii_case(MDM_DIAGNOSTICS_PROVIDER) {
        return match classify_mdm_event(event) {
            Some(observation) => EventClassification::Policy(Box::new(observation)),
            None if mdm_event(event.event_id).is_some() => EventClassification::OutOfScope,
            None => EventClassification::UnmappedEventId(event.event_id),
        };
    }

    EventClassification::UnknownProvider(event.provider.clone())
}

/// Classify one `Microsoft-Windows-WindowsUpdateClient` event.
///
/// Returns `None` when neither the id table nor the documented adapter keys can
/// say what phase the event belongs to. That `None` becomes an explicit unmapped
/// count, never a silent drop.
pub fn classify_update_client_event(event: &NormalizedWindowsEvent) -> Option<UpdateObservation> {
    let (mut phase, mut outcome) = match wu_client_event(event.event_id) {
        Some(mapped) => mapped,
        None => adapter_phase(&event.named_data)?,
    };

    // Event 26 reports how many updates a successful detection found. Zero is
    // the *only* first-party signal that nothing was applicable, and it is an
    // applicability statement, not a scan-health statement: the scan itself
    // succeeded.
    if event.event_id == 26 {
        if let Some(count) = named(&event.named_data, NAMED_UPDATE_COUNT)
            .and_then(|raw| raw.trim().parse::<u64>().ok())
        {
            if count == 0 {
                phase = UpdatePhase::Applicability;
                outcome = UpdateOutcome::NotApplicable;
            }
        }
    }

    let error = named(&event.named_data, NAMED_ERROR_CODE).and_then(|raw| error_code(&raw));

    // A deferral is an install that did not start, not an install that failed.
    // The reason is only ever adapter-supplied, so no message text is guessed at.
    let outcome = if named(&event.named_data, NAMED_DEFERRAL_REASON).is_some()
        && matches!(outcome, UpdateOutcome::Pending | UpdateOutcome::Started)
    {
        UpdateOutcome::Deferred
    } else {
        outcome
    };

    Some(UpdateObservation {
        context: event.context.clone(),
        phase,
        outcome,
        key: update_key_from(&event.named_data, event.message.as_deref()),
        error,
        activity_id: event.activity_id.clone(),
        event_id: Some(event.event_id),
        source: named(&event.named_data, NAMED_SERVICE_GUID)
            .as_deref()
            .and_then(source_for_service_id),
        title: named(&event.named_data, NAMED_UPDATE_TITLE),
        supplemental: None,
        named_data: event.named_data.clone(),
    })
}

/// Read an adapter-supplied phase/outcome pair for an unmapped event id.
fn adapter_phase(named_data: &[IntuneNamedValue]) -> Option<(UpdatePhase, UpdateOutcome)> {
    let phase = match named(named_data, NAMED_ADAPTER_PHASE)?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "scan" => UpdatePhase::Scan,
        "applicability" => UpdatePhase::Applicability,
        "download" => UpdatePhase::Download,
        "install" => UpdatePhase::Install,
        "reboot" => UpdatePhase::Reboot,
        "reporting" => UpdatePhase::Reporting,
        _ => return None,
    };
    let outcome = match named(named_data, NAMED_ADAPTER_OUTCOME)
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "started" => UpdateOutcome::Started,
        "succeeded" => UpdateOutcome::Succeeded,
        "failed" => UpdateOutcome::Failed,
        "deferred" => UpdateOutcome::Deferred,
        "notapplicable" => UpdateOutcome::NotApplicable,
        "pending" => UpdateOutcome::Pending,
        _ => UpdateOutcome::Unknown,
    };
    Some((phase, outcome))
}

// ── Supplemental formats ────────────────────────────────────────────────────

/// One supplemental log, reduced to corroborating observations plus its parse
/// error count.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SupplementalReading {
    pub observations: Vec<UpdateObservation>,
    pub parse_errors: u32,
}

/// Parse a supplemental log with the crate's existing generic parser for that
/// format and lift anything update-shaped into corroborating observations.
///
/// The generic parsers are consumed, never modified: they are shared with the
/// desktop viewer and with SCCM analysis, and forking their grammar here would
/// leave two versions of the same format to keep in step.
pub fn read_supplemental(log: &UpdateSupplementalLog) -> SupplementalReading {
    let lines: Vec<&str> = log.content.lines().collect();
    let path = log
        .context
        .provenance
        .file_path
        .clone()
        .unwrap_or_else(|| log.context.provenance.source_artifact_id.clone());

    let (entries, parse_errors) = match log.kind {
        SupplementalLogKind::ReportingEvents => reporting_events::parse_lines(&lines, &path),
        SupplementalLogKind::Cbs => cbs::parse_lines(&lines, &path),
        SupplementalLogKind::Dism => dism::parse_lines(&lines, &path),
        // A `Get-WindowsUpdateLog` export and any unrecognized supplemental
        // format are scanned as text: they carry no framing this crate models,
        // and inventing one would be a second, untested grammar.
        _ => (Vec::new(), 0),
    };

    let observations = if entries.is_empty() {
        lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                supplemental_observation_from_text(log, line, (index + 1) as u64, None)
            })
            .collect()
    } else {
        entries
            .iter()
            .filter_map(|entry| supplemental_observation_from_entry(log, entry))
            .collect()
    };

    SupplementalReading {
        observations,
        parse_errors,
    }
}

fn supplemental_observation_from_entry(
    log: &UpdateSupplementalLog,
    entry: &LogEntry,
) -> Option<UpdateObservation> {
    let severity = match entry.severity {
        Severity::Error => Some(UpdateOutcome::Failed),
        Severity::Success => Some(UpdateOutcome::Succeeded),
        _ => None,
    };
    supplemental_observation_from_text(
        log,
        &entry.message,
        u64::from(entry.line_number),
        severity,
    )
}

/// Lift one supplemental line into an observation, or `None` when it names no
/// update.
///
/// Two deliberate restrictions:
///
/// * A line with no update identity is dropped. A CBS error line naming no KB
///   cannot be attributed to any update, and attaching it to whichever update
///   happens to be in flight is exactly the time-only correlation issue #365
///   forbids.
/// * Only the **KB** is read out of free text, never a GUID. Supplemental
///   formats put several unrelated GUIDs on one line — `ReportingEvents.log`
///   leads with a per-record GUID that is not the UpdateId — so treating the
///   first GUID as an update identity invents a key that then fails to join the
///   real transaction, or worse, joins the wrong one.
fn supplemental_observation_from_text(
    log: &UpdateSupplementalLog,
    text: &str,
    line_number: u64,
    severity_outcome: Option<UpdateOutcome>,
) -> Option<UpdateObservation> {
    let key = UpdateKey {
        update_id: None,
        kb_article: first_kb(text),
        revision: None,
    };
    if !key.is_identified() {
        return None;
    }

    // A line that names a deferral is not reporting a failure, whatever its
    // severity: a held update and a broken one need opposite responses.
    let default_outcome = if mentions_deferral(text) {
        UpdateOutcome::Deferred
    } else {
        severity_outcome.unwrap_or(UpdateOutcome::Unknown)
    };

    let lowered = text.to_ascii_lowercase();
    let (phase, outcome) = if reboot_pending_re().is_match(text) {
        (UpdatePhase::Reboot, UpdateOutcome::Pending)
    } else if lowered.contains("install") {
        (UpdatePhase::Install, default_outcome)
    } else if lowered.contains("download") {
        (UpdatePhase::Download, default_outcome)
    } else {
        (UpdatePhase::Reporting, default_outcome)
    };

    let mut context = log.context.clone();
    context.provenance.line_number = Some(line_number);
    // A corroborating line is a distinct citation from the file as a whole, so
    // it gets its own evidence id. Reusing the file's id would make several
    // different lines indistinguishable in a finding.
    context.evidence_ref.evidence_id =
        format!("{}#{line_number}", log.context.evidence_ref.evidence_id);

    Some(UpdateObservation {
        context,
        phase,
        outcome,
        key,
        error: hresult_re()
            .find(text)
            .and_then(|found| error_code(found.as_str())),
        activity_id: None,
        event_id: None,
        source: None,
        title: None,
        supplemental: Some(log.kind.clone()),
        named_data: Vec::new(),
    })
}

/// Whether a supplemental line describes a deferral rather than a failure.
pub fn mentions_deferral(text: &str) -> bool {
    deferral_re().is_match(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneObservationContext, IntuneParseState,
        IntuneProvenance, IntuneSensitivity, IntuneSourceKind,
    };

    fn context(id: &str, artifact: &str) -> IntuneObservationContext {
        IntuneObservationContext {
            evidence_ref: IntuneEvidenceRef {
                evidence_id: id.to_owned(),
                source_artifact_id: artifact.to_owned(),
            },
            provenance: IntuneProvenance {
                source_kind: IntuneSourceKind::EventLog,
                source_artifact_id: artifact.to_owned(),
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
        }
    }

    fn event(provider: &str, event_id: u32, named_data: Vec<IntuneNamedValue>) -> NormalizedWindowsEvent {
        NormalizedWindowsEvent {
            context: context("e1", "a1"),
            channel: format!("{provider}/Operational"),
            provider: provider.to_owned(),
            event_id,
            level: NormalizedEventLevel::Information,
            task: None,
            keywords: None,
            record_id: None,
            activity_id: None,
            named_data,
            message: None,
        }
    }

    fn value(name: &str, value: &str) -> IntuneNamedValue {
        IntuneNamedValue {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn an_unknown_provider_never_lands_in_either_chain() {
        let classified = classify_event(&event("Microsoft-Windows-Kernel-General", 12, vec![]));
        assert!(matches!(
            classified,
            EventClassification::UnknownProvider(_)
        ));
    }

    #[test]
    fn an_unmapped_update_client_id_is_counted_not_dropped() {
        let classified = classify_event(&event(WINDOWS_UPDATE_CLIENT_PROVIDER, 9999, vec![]));
        assert_eq!(classified, EventClassification::UnmappedEventId(9999));
    }

    #[test]
    fn an_adapter_supplied_phase_rescues_an_unmapped_id() {
        let classified = classify_event(&event(
            WINDOWS_UPDATE_CLIENT_PROVIDER,
            9999,
            vec![
                value(NAMED_ADAPTER_PHASE, "scan"),
                value(NAMED_ADAPTER_OUTCOME, "succeeded"),
                value(NAMED_UPDATE_GUID, "{AAAAAAAA-0000-0000-0000-000000000001}"),
            ],
        ));
        match classified {
            EventClassification::Update(observation) => {
                assert_eq!(observation.phase, UpdatePhase::Scan);
                assert_eq!(observation.outcome, UpdateOutcome::Succeeded);
            }
            other => panic!("expected an update observation, got {other:?}"),
        }
    }

    #[test]
    fn service_ids_resolve_to_their_source() {
        assert_eq!(
            source_for_service_id("{3DA21691-E39D-4da6-8A4B-B43877BCB1B7}"),
            Some(UpdateSource::Wsus)
        );
        assert_eq!(
            source_for_service_id("9482f4b4-e343-43b6-b170-9a65bc822c77"),
            Some(UpdateSource::WindowsUpdate)
        );
        assert_eq!(
            source_for_service_id("{00000000-0000-0000-0000-000000000009}"),
            Some(UpdateSource::Unknown(
                "{00000000-0000-0000-0000-000000000009}".to_owned()
            ))
        );
    }

    #[test]
    fn a_non_update_csp_failure_is_out_of_scope_for_this_leaf() {
        let mut mdm = event(MDM_DIAGNOSTICS_PROVIDER, 404, vec![value("CSPURI", "./Device/Vendor/MSFT/BitLocker")]);
        mdm.level = NormalizedEventLevel::Error;
        assert_eq!(classify_event(&mdm), EventClassification::OutOfScope);
    }

    #[test]
    fn an_update_csp_failure_lands_in_the_policy_chain() {
        let mut mdm = event(
            MDM_DIAGNOSTICS_PROVIDER,
            404,
            vec![
                value("CSPURI", "./Device/Vendor/MSFT/Policy/Config/Update/DeferQualityUpdatesPeriodInDays"),
                value("Result", "0x82B00003"),
            ],
        );
        mdm.level = NormalizedEventLevel::Error;
        match classify_event(&mdm) {
            EventClassification::Policy(observation) => {
                assert_eq!(observation.signal, PolicySignal::DeliveryFailed);
                assert_eq!(
                    observation.error.as_ref().map(|code| code.raw.as_str()),
                    Some("0x82B00003")
                );
            }
            other => panic!("expected a policy observation, got {other:?}"),
        }
    }

    #[test]
    fn error_codes_keep_every_form_they_were_seen_in() {
        let code = error_code("0x80240022").expect("hex parses");
        assert_eq!(code.raw, "0x80240022");
        assert_eq!(code.hex.as_deref(), Some("0x80240022"));
        assert_eq!(code.decimal, Some(-2145124318));
    }

    #[test]
    fn a_supplemental_line_without_an_update_identity_is_not_attributed() {
        let log = UpdateSupplementalLog {
            context: context("cbs", "cbs-artifact"),
            kind: SupplementalLogKind::Cbs,
            content: "2026-07-31 00:00:00, Error CSI Cannot repair file\n".to_owned(),
        };
        assert!(read_supplemental(&log).observations.is_empty());
    }
}

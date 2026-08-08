//! Record- and event-level classification for Microsoft Store app evidence.
//!
//! Every rule here answers one question about one record: what did this record
//! *state*? Nothing here decides an outcome, merges records, or fills in a value
//! the evidence did not carry. That is the reducer's job, and it may only work
//! from what these rules could actually prove.
//!
//! The two grammars are kept apart on purpose. An IME record is free text
//! written by the Intune Management Extension; an AppX or Store event is a
//! structured record whose payload arrives in
//! [`NormalizedWindowsEvent::named_data`]. Reading the second with the first's
//! regexes is how a Store Win32 handoff ends up wearing AppX terminal
//! semantics, which the source contract forbids.

use std::sync::OnceLock;

use regex::Regex;

use crate::intune::evidence::{IntuneErrorCode, IntuneNamedValue};
use crate::intune::normalized::{NormalizedEventLevel, NormalizedWindowsEvent};

use super::models::{
    StoreAssignmentIntent, StoreDeploymentAction, StoreExecutionContext, StoreInstallerFamily,
    StorePackageIdentity, StoreSignal,
};
use super::sources::{classify_event_source, StoreEventSource};

const GUID: &str = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

/// A Store product id is a 12-character crockford-ish token, e.g. `9WZSYNTH0001`.
const PRODUCT_ID: &str = r"[0-9A-Z]{12}";

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("microsoft store regex must compile"))
}

fn product_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(
            r"(?i)\b(?:StoreProductId|ProductId|CatalogId)\s*[:=]\s*(?P<product>{PRODUCT_ID})\b"
        ),
    )
}

fn package_family_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bPackageFamilyName\s*[:=]\s*(?P<family>[A-Za-z0-9.\-]+_[A-Za-z0-9]{13})\b",
    )
}

fn package_full_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bPackageFullName\s*[:=]\s*(?P<full>[A-Za-z0-9.\-]+_[0-9.]+_[A-Za-z0-9]+__[A-Za-z0-9]{13})\b",
    )
}

fn app_id_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        &format!(r"(?i)\b(?:AppId|ApplicationId|AssignmentId)\s*[:=]\s*(?P<app>{GUID})\b"),
    )
}

fn display_name_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bDisplayName\s*[:=]\s*(?P<name>[^,;\r\n]{1,120})",
    )
}

/// The start of the next `Key=`/`Key:` field on the same line.
///
/// A display name contains spaces, so it cannot be bounded by whitespace, and
/// the regex crate has no lookahead to bound it by the next field. Capturing the
/// rest of the line and trimming here means `DisplayName=Synthetic Store App
/// PackageFamilyName=x` yields the name rather than the whole remainder of the
/// record.
fn next_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"\s+[A-Za-z][A-Za-z0-9_.\-]*\s*[:=]")
}

fn trim_at_next_field(value: &str) -> String {
    match next_field_re().find(value) {
        Some(boundary) => value[..boundary.start()].trim().to_owned(),
        None => value.trim().to_owned(),
    }
}

fn context_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:ExecutionContext|InstallContext|TargetContext)\s*[:=]\s*(?P<context>system|device|user)\b",
    )
}

fn error_code_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\b(?:error|errorCode|hResult|hr|resultCode|exitCode)\s*[:=]\s*(?P<code>-?(?:0x[0-9a-fA-F]+|\d+))",
    )
}

fn targeted_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bstore\s+app\b[^\r\n]*\b(?:is\s+targeted|policy\s+received|assignment\s+received)\b",
    )
}

fn not_applicable_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(&CELL, r"(?i)\bnot\s+applicable\b")
}

fn acquisition_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\brequest(?:ing|ed)?\s+(?:store\s+)?(?:acquisition|license)\b|\bacquiring\s+store\s+package\b",
    )
}

fn no_user_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bno\s+(?:interactive|logged[\s-]?on|signed[\s-]?in)\s+user\b|\buser\s+context\s+is\s+not\s+available\b",
    )
}

fn win32_handoff_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bhand(?:ing|ed)?[\s-]?off\b[^\r\n]*\bwin32\b|\bwin32\s+hand[\s-]?off\b",
    )
}

fn retry_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\bwill\s+retry\b|\bretry\s+scheduled\b|\bretrying\b",
    )
}

fn uninstall_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    re(
        &CELL,
        r"(?i)\buninstall\b|\bremoval\b|\bremove\s+the\s+package\b",
    )
}

/// Parse a return/exit/error token, keeping every form it was observed in.
pub fn parse_error_code(raw: &str) -> IntuneErrorCode {
    let trimmed = raw.trim();
    let (negative, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed),
    };
    let magnitude = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16)
            .ok()
            .and_then(|value| i64::try_from(value).ok()),
        None => body.parse::<i64>().ok(),
    };
    let decimal = magnitude.map(|value| if negative { -value } else { value });
    let hex = decimal.map(|value| {
        if (0..=i64::from(u32::MAX)).contains(&value) {
            format!("0x{:08X}", value as u32)
        } else if (i64::from(i32::MIN)..0).contains(&value) {
            format!("0x{:08X}", value as i32 as u32)
        } else {
            format!("0x{value:X}")
        }
    });
    IntuneErrorCode {
        raw: trimmed.to_owned(),
        decimal,
        hex,
    }
}

/// Everything one record or event could prove on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreClassification {
    pub signal: StoreSignal,
    pub identity: StorePackageIdentity,
    pub app_id: Option<String>,
    pub execution_context: StoreExecutionContext,
    pub action: StoreDeploymentAction,
    pub installer_family: StoreInstallerFamily,
    /// True when the record stated the family rather than leaving it open.
    pub family_declared: bool,
    /// Intune's typed assignment intent, present only when the record *is* a
    /// typed assignment. Free-text or caller-writable metadata never sets it:
    /// per ADR-001, untyped data is not authoritative intent.
    pub typed_intent: Option<StoreAssignmentIntent>,
    pub error: Option<IntuneErrorCode>,
    /// True when a recognized provider emitted an event id or schema version
    /// this build has no rule for.
    pub unknown_version: bool,
    /// True when a known event id's stated outcome contradicts the record's
    /// own level. Distinct from [`Self::unknown_version`]: the dialect is
    /// understood, the record contradicts itself.
    pub level_mismatch: bool,
    /// False when the record did not come from a source this leaf recognizes.
    ///
    /// An unrecognized source is not Store evidence at all, so it must not
    /// become an observation: an event from an unrelated provider that happens
    /// to name a package would otherwise manufacture a Store transaction.
    pub recognized: bool,
}

impl Default for StoreClassification {
    fn default() -> Self {
        Self {
            signal: StoreSignal::Unclassified,
            identity: StorePackageIdentity::default(),
            app_id: None,
            execution_context: StoreExecutionContext::Unknown,
            action: StoreDeploymentAction::Unknown,
            installer_family: StoreInstallerFamily::Unknown,
            family_declared: false,
            typed_intent: None,
            error: None,
            unknown_version: false,
            level_mismatch: false,
            recognized: true,
        }
    }
}

fn capture(regex: &Regex, haystack: &str, group: &str) -> Option<String> {
    regex
        .captures(haystack)
        .and_then(|caps| caps.name(group))
        .map(|value| value.as_str().trim().to_owned())
}

fn identity_from_text(message: &str) -> StorePackageIdentity {
    StorePackageIdentity {
        store_product_id: capture(product_id_re(), message, "product"),
        package_family_name: capture(package_family_re(), message, "family"),
        package_full_name: capture(package_full_re(), message, "full"),
        display_name: capture(display_name_re(), message, "name")
            .map(|name| trim_at_next_field(&name))
            .filter(|name| !name.is_empty()),
    }
}

fn context_from_text(message: &str) -> StoreExecutionContext {
    match capture(context_re(), message, "context")
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("user") => StoreExecutionContext::User,
        Some("system" | "device") => StoreExecutionContext::System,
        _ => StoreExecutionContext::Unknown,
    }
}

/// Classify one CCM-framed IME record.
///
/// The IME log states Intune's *intent* and its handoffs. It is deliberately not
/// allowed to state an AppX terminal outcome: only the OS deployment channel
/// knows whether a package registered, and inferring that from an IME line is
/// exactly the overclaim the source contract forbids.
pub fn classify_ime_record(message: &str) -> StoreClassification {
    let identity = identity_from_text(message);
    let mut classification = StoreClassification {
        identity,
        app_id: capture(app_id_re(), message, "app"),
        execution_context: context_from_text(message),
        error: capture(error_code_re(), message, "code")
            .as_deref()
            .map(parse_error_code),
        ..StoreClassification::default()
    };

    if uninstall_re().is_match(message) {
        classification.action = StoreDeploymentAction::Uninstall;
    }

    // Order matters: the most specific statement wins. A handoff record that
    // also mentions a retry is a handoff.
    classification.signal = if win32_handoff_re().is_match(message) {
        classification.installer_family = StoreInstallerFamily::StoreWin32;
        classification.family_declared = true;
        StoreSignal::Win32HandoffStarted
    } else if no_user_re().is_match(message) {
        classification.installer_family = StoreInstallerFamily::UwpUserContext;
        classification.family_declared = true;
        // Only fill in the context the record left open. A record that stated
        // its own context outranks this inference, and overwriting it would
        // silently contradict the evidence.
        if classification.execution_context == StoreExecutionContext::Unknown {
            classification.execution_context = StoreExecutionContext::User;
        }
        StoreSignal::NoInteractiveUser
    } else if not_applicable_re().is_match(message) {
        StoreSignal::NotApplicable
    } else if acquisition_re().is_match(message) {
        StoreSignal::AcquisitionRequested
    } else if retry_re().is_match(message) {
        StoreSignal::RetryScheduled
    } else if targeted_re().is_match(message) {
        StoreSignal::TargetedByIntune
    } else {
        StoreSignal::Unclassified
    };

    if classification.signal != StoreSignal::Unclassified
        && classification.action == StoreDeploymentAction::Unknown
        && !uninstall_re().is_match(message)
    {
        classification.action = StoreDeploymentAction::Install;
    }

    classification
}

// ── Windows event classification ────────────────────────────────────────────

/// What an event id said about the stage it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventOutcome {
    Started,
    Completed,
    Failed,
}

/// The deployment operation an event described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeploymentOperation {
    Acquire,
    Stage,
    Register,
    Provision,
    Install,
    Remove,
}

/// Event ids this build has rules for, per recognized source.
///
/// The table is deliberately small and closed. An id outside it under a
/// recognized provider is reported as an unknown version rather than guessed at,
/// because the alternative is inventing a terminal outcome from a number.
fn outcome_for(source: StoreEventSource, event_id: u32) -> Option<EventOutcome> {
    match source {
        StoreEventSource::AppxDeployment => match event_id {
            400 | 401 => Some(EventOutcome::Started),
            603 | 605 => Some(EventOutcome::Completed),
            404 | 606 => Some(EventOutcome::Failed),
            _ => None,
        },
        StoreEventSource::AppxPackaging => match event_id {
            150 => Some(EventOutcome::Started),
            151 => Some(EventOutcome::Completed),
            170 => Some(EventOutcome::Failed),
            _ => None,
        },
        StoreEventSource::StoreAgent => match event_id {
            8000 => Some(EventOutcome::Started),
            8001 => Some(EventOutcome::Completed),
            8002 => Some(EventOutcome::Failed),
            _ => None,
        },
        StoreEventSource::Unknown => None,
    }
}

fn named<'a>(named_data: &'a [IntuneNamedValue], key: &str) -> Option<&'a str> {
    named_data
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(key))
        .map(|entry| entry.value.as_str())
}

fn operation_from(named_data: &[IntuneNamedValue]) -> Option<DeploymentOperation> {
    match named(named_data, "DeploymentOperation")?
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "acquire" | "acquisition" | "license" => Some(DeploymentOperation::Acquire),
        "stage" | "staging" | "download" => Some(DeploymentOperation::Stage),
        "register" | "registration" => Some(DeploymentOperation::Register),
        "provision" | "provisioning" => Some(DeploymentOperation::Provision),
        "install" | "update" => Some(DeploymentOperation::Install),
        "remove" | "uninstall" => Some(DeploymentOperation::Remove),
        _ => None,
    }
}

/// Deployment scope decides the AppX family. It is read from the event payload
/// rather than inferred from the channel, because both scopes are written to the
/// same operational channel.
fn family_from(
    named_data: &[IntuneNamedValue],
    operation: Option<DeploymentOperation>,
) -> (StoreInstallerFamily, bool) {
    if operation == Some(DeploymentOperation::Provision) {
        return (StoreInstallerFamily::UwpProvisioned, true);
    }
    match named(named_data, "DeploymentScope")
        .map(|scope| scope.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("user" | "peruser") => (StoreInstallerFamily::UwpUserContext, true),
        Some("machine" | "allusers" | "device" | "system" | "provisioned") => {
            (StoreInstallerFamily::UwpProvisioned, true)
        }
        _ => (StoreInstallerFamily::Unknown, false),
    }
}

fn context_from(named_data: &[IntuneNamedValue]) -> StoreExecutionContext {
    match named(named_data, "DeploymentScope")
        .map(|scope| scope.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("user" | "peruser") => StoreExecutionContext::User,
        Some("machine" | "allusers" | "device" | "system" | "provisioned") => {
            StoreExecutionContext::System
        }
        _ => StoreExecutionContext::Unknown,
    }
}

fn signal_for(operation: DeploymentOperation, outcome: EventOutcome) -> StoreSignal {
    match (operation, outcome) {
        (DeploymentOperation::Acquire, EventOutcome::Started) => StoreSignal::AcquisitionRequested,
        (DeploymentOperation::Acquire, EventOutcome::Completed) => StoreSignal::LicenseAcquired,
        (DeploymentOperation::Acquire, EventOutcome::Failed) => StoreSignal::LicenseFailed,
        (DeploymentOperation::Stage, EventOutcome::Completed) => StoreSignal::StagingCompleted,
        (DeploymentOperation::Stage, EventOutcome::Failed) => StoreSignal::StagingFailed,
        (DeploymentOperation::Register | DeploymentOperation::Install, EventOutcome::Completed) => {
            StoreSignal::RegistrationCompleted
        }
        (DeploymentOperation::Register | DeploymentOperation::Install, EventOutcome::Failed) => {
            StoreSignal::RegistrationFailed
        }
        (DeploymentOperation::Provision, EventOutcome::Completed) => {
            StoreSignal::ProvisioningCompleted
        }
        (DeploymentOperation::Provision, EventOutcome::Failed) => StoreSignal::ProvisioningFailed,
        (DeploymentOperation::Remove, EventOutcome::Completed) => StoreSignal::RemovalCompleted,
        (DeploymentOperation::Remove, EventOutcome::Failed) => StoreSignal::RemovalFailed,
        (_, EventOutcome::Started) => StoreSignal::DeploymentStarted,
    }
}

/// Classify one normalized Windows event.
///
/// A recognized provider with an unrecognized event id yields
/// [`StoreSignal::Unclassified`] plus `unknown_version`. The identity is still
/// extracted, so the record stays correlatable and visible instead of vanishing.
pub fn classify_event(event: &NormalizedWindowsEvent) -> StoreClassification {
    let source = classify_event_source(&event.provider, &event.channel);
    let named_data = &event.named_data;

    let identity = StorePackageIdentity {
        store_product_id: named(named_data, "StoreProductId")
            .or_else(|| named(named_data, "ProductId"))
            .map(str::to_owned),
        package_family_name: named(named_data, "PackageFamilyName").map(str::to_owned),
        package_full_name: named(named_data, "PackageFullName").map(str::to_owned),
        display_name: named(named_data, "PackageDisplayName")
            .or_else(|| named(named_data, "DisplayName"))
            .map(str::to_owned),
    };

    let operation = operation_from(named_data);
    let (installer_family, family_declared) = family_from(named_data, operation);
    let error = named(named_data, "ErrorCode")
        .or_else(|| named(named_data, "HResult"))
        .or_else(|| named(named_data, "ResultCode"))
        .map(parse_error_code);

    let mut classification = StoreClassification {
        identity,
        app_id: named(named_data, "IntuneAppId").map(str::to_owned),
        execution_context: context_from(named_data),
        installer_family,
        family_declared,
        error,
        ..StoreClassification::default()
    };

    if source == StoreEventSource::Unknown {
        classification.recognized = false;
        return classification;
    }

    classification.action = match operation {
        Some(DeploymentOperation::Remove) => StoreDeploymentAction::Uninstall,
        Some(_) => StoreDeploymentAction::Install,
        None => StoreDeploymentAction::Unknown,
    };

    let Some(outcome) = outcome_for(source, event.event_id) else {
        // A known provider speaking a dialect this build does not have a rule
        // for. Surface it; do not guess an outcome from the level alone.
        classification.unknown_version = true;
        return classification;
    };

    // A payload version beyond the known set is the same problem arriving by a
    // different route.
    if let Some(version) = named(named_data, "Version") {
        if version.trim() != "1" {
            classification.unknown_version = true;
        }
    }

    let Some(operation) = operation else {
        classification.unknown_version = true;
        return classification;
    };

    classification.signal = signal_for(operation, outcome);

    // An event that reports failure without an error code is still a failure,
    // but the level must never be promoted into one. A failure id logged at
    // Information level is a *known* record contradicting itself, which is a
    // different degradation than an unrecognized dialect, so it is flagged
    // separately rather than folded into `unknown_version`.
    if outcome == EventOutcome::Failed && event.level == NormalizedEventLevel::Information {
        classification.level_mismatch = true;
    }

    classification
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneObservationContext, IntuneParseState,
        IntuneProvenance, IntuneSensitivity, IntuneSourceKind,
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
                record_number: Some(1),
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

    fn event(event_id: u32, named_data: &[(&str, &str)]) -> NormalizedWindowsEvent {
        NormalizedWindowsEvent {
            context: context(),
            channel: "Microsoft-Windows-AppXDeploymentServer/Operational".to_owned(),
            provider: "Microsoft-Windows-AppXDeployment-Server".to_owned(),
            event_id,
            level: NormalizedEventLevel::Error,
            task: None,
            keywords: None,
            record_id: Some(1),
            activity_id: None,
            event_version: None,
            named_data: named_data
                .iter()
                .map(|(name, value)| IntuneNamedValue {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                })
                .collect(),
            message: None,
        }
    }

    #[test]
    fn hex_and_decimal_error_forms_are_both_retained() {
        let code = parse_error_code("0x80073CF9");
        assert_eq!(code.raw, "0x80073CF9");
        assert_eq!(code.decimal, Some(2_147_958_009));
        assert_eq!(code.hex.as_deref(), Some("0x80073CF9"));

        // The same failure written as a signed decimal round-trips to the same
        // hex HRESULT, which is the whole reason both forms are retained.
        let negative = parse_error_code("-2147009288");
        assert_eq!(negative.decimal, Some(-2_147_009_288));
        assert_eq!(negative.hex.as_deref(), Some("0x80073CF8"));
    }

    #[test]
    fn an_unparseable_token_keeps_its_raw_text() {
        let code = parse_error_code("E_SYNTHETIC");
        assert_eq!(code.raw, "E_SYNTHETIC");
        assert_eq!(code.decimal, None);
        assert_eq!(code.hex, None);
    }

    #[test]
    fn a_provision_operation_declares_the_provisioned_family() {
        let classification = classify_event(&event(
            404,
            &[
                ("DeploymentOperation", "Provision"),
                ("PackageFamilyName", "Contoso.SynthApp_9abcdef01234h"),
                ("ErrorCode", "0x80073CF9"),
            ],
        ));
        assert_eq!(classification.signal, StoreSignal::ProvisioningFailed);
        assert_eq!(
            classification.installer_family,
            StoreInstallerFamily::UwpProvisioned
        );
        assert!(classification.family_declared);
    }

    #[test]
    fn a_per_user_scope_declares_the_user_context_family() {
        let classification = classify_event(&event(
            603,
            &[
                ("DeploymentOperation", "Register"),
                ("DeploymentScope", "User"),
                ("PackageFamilyName", "Contoso.SynthApp_9abcdef01234h"),
            ],
        ));
        assert_eq!(classification.signal, StoreSignal::RegistrationCompleted);
        assert_eq!(
            classification.installer_family,
            StoreInstallerFamily::UwpUserContext
        );
        assert_eq!(
            classification.execution_context,
            StoreExecutionContext::User
        );
    }

    #[test]
    fn an_unknown_event_id_under_a_known_provider_is_surfaced_not_guessed() {
        let classification = classify_event(&event(
            9999,
            &[
                ("DeploymentOperation", "Register"),
                ("PackageFamilyName", "Contoso.SynthApp_9abcdef01234h"),
            ],
        ));
        assert_eq!(classification.signal, StoreSignal::Unclassified);
        assert!(classification.unknown_version);
        assert!(
            !classification.level_mismatch,
            "an unrecognized dialect is not a level contradiction"
        );
        // Identity survives so the record stays correlatable.
        assert!(!classification.identity.is_empty());
    }

    /// A *known* failure id logged at Information level is the record
    /// contradicting itself, which is a distinct degradation from an
    /// unrecognized dialect and must be flagged as such (evidence-degradation
    /// cluster, inventory row 7).
    #[test]
    fn a_known_failure_id_at_information_level_is_a_level_mismatch_not_an_unknown_version() {
        let mut contradictory = event(
            404,
            &[
                ("DeploymentOperation", "Register"),
                ("DeploymentScope", "User"),
                ("PackageFamilyName", "Contoso.SynthApp_9abcdef01234h"),
                ("ErrorCode", "0x80073CF9"),
            ],
        );
        contradictory.level = NormalizedEventLevel::Information;
        let classification = classify_event(&contradictory);
        // The stated outcome is kept; the level is never promoted into one.
        assert_eq!(classification.signal, StoreSignal::RegistrationFailed);
        assert!(classification.level_mismatch);
        assert!(
            !classification.unknown_version,
            "the dialect is fully recognized; conflating the two reasons would \
             hide which degradation happened"
        );
    }

    #[test]
    fn an_unknown_provider_yields_no_signal_at_all() {
        let mut unknown = event(603, &[("DeploymentOperation", "Register")]);
        unknown.provider = "Contoso-Synthetic-Provider".to_owned();
        let classification = classify_event(&unknown);
        assert_eq!(classification.signal, StoreSignal::Unclassified);
        assert!(!classification.unknown_version);
        assert!(
            !classification.recognized,
            "an unrecognized provider must not become Store evidence"
        );
    }

    #[test]
    fn an_ime_handoff_record_declares_the_store_win32_family() {
        let classification = classify_ime_record(
            "Store app StoreProductId=9WZSYNTH0001 is a Win32 package; handing off to the Win32 app workload",
        );
        assert_eq!(classification.signal, StoreSignal::Win32HandoffStarted);
        assert_eq!(
            classification.installer_family,
            StoreInstallerFamily::StoreWin32
        );
        assert_eq!(
            classification.identity.store_product_id.as_deref(),
            Some("9WZSYNTH0001")
        );
    }

    #[test]
    fn an_ime_record_never_claims_an_appx_terminal_outcome() {
        // The IME log does not know whether registration succeeded. A line that
        // merely says "installed" must not become a registration signal.
        let classification = classify_ime_record(
            "Store app PackageFamilyName=Contoso.SynthApp_9abcdef01234h installed",
        );
        assert_eq!(classification.signal, StoreSignal::Unclassified);
    }

    #[test]
    fn no_interactive_user_is_scoped_to_the_user_context_family() {
        let classification = classify_ime_record(
            "Skipping StoreProductId=9WZSYNTH0001: no interactive user is signed in",
        );
        assert_eq!(classification.signal, StoreSignal::NoInteractiveUser);
        assert_eq!(
            classification.installer_family,
            StoreInstallerFamily::UwpUserContext
        );
    }
}

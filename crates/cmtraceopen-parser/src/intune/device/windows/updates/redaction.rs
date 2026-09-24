//! Privacy-safe export projection.
//!
//! The default export must not carry identity, device, tenant, path, or token
//! material. What survives is the diagnostic skeleton: which record, from which
//! provider, at which phase, with which outcome and error code.
//!
//! That promise is enforced field by field, and by two different means:
//!
//! * **Values this leaf classifies** are masked wholesale -- policy values,
//!   named-value content outside the Microsoft-defined identifiers, the policy
//!   id, artifact `detail` free text, and any value in a field that expects one
//!   of a known few (`UpdateSource::Unknown`, `UpdateWorkloadOwner::Unknown`,
//!   `ServiceReportedState::Unknown`). An unrecognized value is not a validated
//!   term, so it gets the same default-deny as a named value.
//! * **Text a capture supplied** that the export keeps for diagnosis -- update
//!   titles, finding text, unknown provider names, an error token that did not
//!   read as a code -- is scrubbed through the shared Intune text grammar
//!   ([`redact_text`]) rather than trusted because of the field it sits in. A
//!   title is a product string in practice, but "in practice" is not an
//!   enforcement, and the same field can carry a UPN, a path, or a secret.
//!
//! What deliberately survives, because a finding cannot be traced without it:
//! artifact and evidence identifiers, record and line numbers, channel and
//! provider identity, policy node URIs and setting ids (policy *locations*, the
//! same reason the registry provenance survives), activity ids, Windows build
//! and edition, and error codes that read as codes.
//!
//! [`redacted_export_projection`] is the export entry point. `UpdateSnapshot`
//! itself serializes as it stands, for debugging and for the crate's own tests;
//! serializing it directly is not an export.
//!
//! The projection is a pure function of the snapshot, so the same snapshot
//! always exports the same bytes. It reuses [`UpdateSnapshot`] rather than
//! introducing an export-only type, which keeps one shape to golden-test and
//! makes "what did redaction change?" a field-by-field diff.

use crate::intune::apps::windows::common::redact_text;
use crate::intune::evidence::{
    IntuneErrorCode, IntuneNamedValue, IntuneObservationContext, IntuneSensitivity,
};

use super::models::*;

/// Placeholder written in place of any value redaction removed.
///
/// A constant rather than an empty string: "this was removed" and "this was
/// empty" are different facts, and collapsing them would make an export
/// ambiguous.
pub const REDACTED: &str = "[redacted]";

/// Project a snapshot into its redacted export form.
pub fn redacted_export_projection(snapshot: &UpdateSnapshot) -> UpdateSnapshot {
    let mut projected = snapshot.clone();

    projected.device = redact_device(&snapshot.device);

    for observation in &mut projected.policy_chain.observations {
        redact_context(&mut observation.context);
        // A policy value is the single most likely carrier of tenant data: WSUS
        // URLs, service URLs, and account names all arrive here.
        if observation.value.is_some() {
            observation.value = Some(REDACTED.to_owned());
        }
        // The policy id is the enrollment's own identifier, which is exactly the
        // kind of tenant-bearing value this projection promises not to carry.
        mask_present(&mut observation.policy_id);
        mask_unknown_source(&mut observation.source);
        // An error token that did not read as a code is text from the capture,
        // wherever it sits -- policy findings cite these too.
        mask_unreadable_error(&mut observation.error);
        observation.named_data = redact_named(&observation.named_data);
    }

    for conflict in &mut projected.policy_chain.conflicts {
        mask_all(&mut conflict.policy_ids);
    }
    mask_unknown_owner(&mut projected.policy_chain.workload_owner);
    mask_unknown_source(&mut projected.policy_chain.effective_source.expected);
    mask_unknown_source(&mut projected.policy_chain.effective_source.configured);
    mask_unknown_source(&mut projected.policy_chain.effective_source.scanned);

    for observation in &mut projected.update_chain.unkeyed_observations {
        redact_context(&mut observation.context);
        mask_unknown_source(&mut observation.source);
        scrub_text_option(&mut observation.title);
        mask_unreadable_error(&mut observation.error);
        observation.named_data = redact_named(&observation.named_data);
    }

    for transaction in &mut projected.update_chain.transactions {
        scrub_text_option(&mut transaction.title);
        mask_unreadable_error(&mut transaction.error);
        mask_unknown_service_state(&mut transaction.service_state);
    }

    // Findings are prose this crate wrote, but some of it interpolates the
    // capture: an error token, a policy node, a provider name, an artifact id.
    for finding in &mut projected.findings {
        finding.title = redact_text(&finding.title);
        finding.summary = redact_text(&finding.summary);
    }

    for coverage in &mut projected.coverage {
        // `detail` is adapter free text and can name a path or an account.
        if coverage.detail.is_some() {
            coverage.detail = Some(REDACTED.to_owned());
        }
    }

    for provider in &mut projected.input_coverage.unknown_providers {
        *provider = redact_text(provider);
    }
    scrub_text_option(&mut projected.input_coverage.extraction_profile);

    projected
}

/// Mask one value outright, leaving the field present.
fn mask_present(value: &mut Option<String>) {
    if value.is_some() {
        *value = Some(REDACTED.to_owned());
    }
}

/// Mask every entry of a list of identifiers.
fn mask_all(values: &mut [String]) {
    for value in values {
        *value = REDACTED.to_owned();
    }
}

/// Scrub text a capture supplied instead of trusting the field it arrived in.
fn scrub_text_option(value: &mut Option<String>) {
    if let Some(text) = value {
        *text = redact_text(text);
    }
}

/// Mask a vocabulary value this build did not recognize.
///
/// "Unrecognized" is a statement about this build's vocabulary, so the value is
/// not a validated term at all: it is text from the capture sitting in a field
/// that expects one of a known few. The same default-deny this leaf applies to
/// named values applies here, and the field still says a value was there.
fn mask_unknown_source(source: &mut Option<UpdateSource>) {
    if let Some(UpdateSource::Unknown(_)) = source {
        *source = Some(UpdateSource::Unknown(REDACTED.to_owned()));
    }
}

fn mask_unknown_owner(owner: &mut UpdateWorkloadOwner) {
    if let UpdateWorkloadOwner::Unknown(_) = owner {
        *owner = UpdateWorkloadOwner::Unknown(REDACTED.to_owned());
    }
}

fn mask_unknown_service_state(state: &mut Option<ServiceReportedState>) {
    if let Some(ServiceReportedState::Unknown(_)) = state {
        *state = Some(ServiceReportedState::Unknown(REDACTED.to_owned()));
    }
}

/// Mask an error token that is not the code's own rendering.
///
/// A readable code keeps its place and its value: `0x80240017` is diagnostic
/// grammar. The `raw` field is kept only when it *is* that code's rendering in
/// one of the forms this build produces. Anything else in it -- including a
/// string sitting next to a perfectly readable decimal -- is text from the
/// capture, and it is masked rather than published on the strength of the field
/// it occupies.
fn mask_unreadable_error(error: &mut Option<IntuneErrorCode>) {
    if let Some(code) = error {
        let raw = code.raw.trim();
        let renders_this_code = code
            .hex
            .as_deref()
            .is_some_and(|hex| raw.eq_ignore_ascii_case(hex))
            || code
                .decimal
                .is_some_and(|decimal| raw == decimal.to_string());
        if !renders_this_code {
            code.raw = REDACTED.to_owned();
        }
    }
}

fn redact_device(device: &UpdateDeviceFacts) -> UpdateDeviceFacts {
    let mut redacted = device.clone();
    if let Some(context) = redacted.context.as_mut() {
        redact_context(context);
    }
    // The device record carries the same two vocabulary values the policy chain
    // does. Masking them there and not here published one value twice, in one
    // form masked and in the other in the clear.
    if let Some(owner) = redacted.update_workload_owner.as_mut() {
        mask_unknown_owner(owner);
    }
    mask_unknown_source(&mut redacted.expected_update_source);
    redacted.named_data = redact_named(&device.named_data);
    redacted
}

/// Strip the parts of an observation context that can carry identity.
///
/// The evidence reference, provenance kind, record and line numbers, event
/// coordinates, and states all survive: none of them names a person, a device,
/// or a tenant, and without them a finding could not be traced back to its
/// source at all.
fn redact_context(context: &mut IntuneObservationContext) {
    context.provenance.file_path = None;
    if let Some(registry) = context.provenance.registry.as_mut() {
        // Hive, key, and value name are policy locations, not user data. Nothing
        // to remove; the *value* never lives on the provenance.
        let _ = registry;
    }
}

/// Keep every name, drop every value that is not classified public.
///
/// The names are what make an export diagnosable ("this record carried a
/// serviceGuid"); the values are what can leak.
/// Whether a name reads as a field label, and is therefore safe to export.
///
/// The name slot holds field names in a capture, so the export keeps a name that
/// looks like one. It is not a whitelist of this build's constants: the corpus
/// carries names we do not define (`Message5` and `HexInt1`, both positional forms
/// the event payload uses, and vendor fields such as `updatelist`), and masking
/// those would cost legibility for nothing.
///
/// What the rule excludes is the identity shapes — a UPN (`@`), a domain-qualified
/// account (`\`), a URI or path (`/`, `:`), a dotted display name (`.`). A name in
/// one of those shapes is a *value* someone filed in the name slot, and the value
/// check next door cannot see it because it only ever inspects the value.
fn reads_as_field_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

fn redact_named(values: &[IntuneNamedValue]) -> Vec<IntuneNamedValue> {
    values
        .iter()
        .map(|entry| IntuneNamedValue {
            name: if reads_as_field_name(&entry.name) {
                entry.name.clone()
            } else {
                REDACTED.to_owned()
            },
            value: if is_public_named_value(&entry.name, &entry.value) {
                entry.value.clone()
            } else {
                REDACTED.to_owned()
            },
        })
        .collect()
}

/// Named values whose content is a Microsoft-defined identifier rather than
/// tenant data, and which are therefore safe to export verbatim.
/// Whether a named value may be exported verbatim.
///
/// The name alone cannot decide it. These values come from the capture, so a
/// record may carry `errorCode = "jdoe@contoso.com"` under a public name, and
/// copying that because of the name publishes an identity the field was never
/// meant to hold. Each public name states a shape, and a value without it is
/// masked exactly like [`mask_unreadable_error`] masks an unreadable code.
fn is_public_named_value(name: &str, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() {
        // Nothing to publish is nothing to leak.
        return true;
    }
    if name.eq_ignore_ascii_case(super::sources::NAMED_UPDATE_GUID)
        || name.eq_ignore_ascii_case(super::sources::NAMED_SERVICE_GUID)
    {
        return reads_as_guid(value);
    }
    if name.eq_ignore_ascii_case(super::sources::NAMED_UPDATE_REVISION)
        || name.eq_ignore_ascii_case(super::sources::NAMED_UPDATE_COUNT)
    {
        return value.parse::<u32>().is_ok();
    }
    if name.eq_ignore_ascii_case(super::sources::NAMED_ERROR_CODE) {
        return reads_as_error_code(value);
    }
    false
}

/// Whether a value reads as a GUID, in either of the spellings Windows uses.
fn reads_as_guid(value: &str) -> bool {
    let trimmed = value.trim_matches(|character| character == '{' || character == '}');
    let groups: Vec<&str> = trimmed.split('-').collect();
    let widths = [8, 4, 4, 4, 12];
    groups.len() == widths.len()
        && groups.iter().zip(widths).all(|(group, width)| {
            group.len() == width && group.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Whether a value reads as an error code: a hex literal or a decimal number.
fn reads_as_error_code(value: &str) -> bool {
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => !hex.is_empty() && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        None => value.bytes().all(|byte| byte.is_ascii_digit()),
    }
}

/// Whether a context is classified as safe to export without redaction.
///
/// Exposed so a caller can assert its own inputs before handing them over.
pub fn is_public(context: &IntuneObservationContext) -> bool {
    context.sensitivity == IntuneSensitivity::Public
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_is_not_a_field_name_is_masked() {
        // The value check cannot see these: the identity is in the name slot.
        let masked = [
            "adam.admin@contoso.example.com",
            r"contoso\adam.admin",
            "adam.admin",
            "./Device/Vendor/MSFT/Policy/Config/Update/UpdateServiceUrl",
        ];
        // Names the corpus actually carries, which must survive or the export
        // stops describing the capture.
        let kept = [
            "updateGuid",
            "Message5",
            "HexInt1",
            "updatelist",
            "tenantDisplayName",
        ];

        for name in masked {
            let values = vec![IntuneNamedValue {
                name: name.to_owned(),
                value: "1".to_owned(),
            }];
            assert_eq!(
                redact_named(&values)[0].name,
                REDACTED,
                "{name} is an identity shape, not a field name"
            );
        }
        for name in kept {
            let values = vec![IntuneNamedValue {
                name: name.to_owned(),
                value: "1".to_owned(),
            }];
            assert_eq!(
                redact_named(&values)[0].name,
                name,
                "{name} is a field the capture carries"
            );
        }
    }

    use crate::intune::evidence::{
        IntuneAccessState, IntuneEvidenceRef, IntuneParseState, IntuneProvenance, IntuneSourceKind,
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
                file_path: Some("SYNTHETIC://wu/events.evtx".to_owned()),
                line_number: None,
                record_number: Some(3),
                registry: None,
                event: None,
            },
            source_timestamp: None,
            observed_at_utc: "2026-07-31T00:00:00Z".to_owned(),
            sensitivity: IntuneSensitivity::Sensitive,
            parse_state: IntuneParseState::Parsed,
            access_state: IntuneAccessState::Available,
        }
    }

    /// The reviewer's trigger: a public name is not a promise about the value.
    #[test]
    fn a_public_name_holding_a_non_conforming_value_is_masked() {
        assert!(!is_public_named_value("errorCode", "jdoe@contoso.com"));
        assert!(!is_public_named_value(
            "updateGuid",
            r"C:\Users\jdoe\AppData"
        ));
        assert!(!is_public_named_value("updateRevisionNumber", "alpha"));
    }

    /// Values that do have the shape their name states are kept.
    #[test]
    fn a_public_name_holding_a_conforming_value_is_kept() {
        assert!(is_public_named_value(
            "updateGuid",
            "aaaaaaaa-0000-0000-0000-000000000001"
        ));
        assert!(is_public_named_value(
            "updateGuid",
            "{AAAAAAAA-0000-0000-0000-000000000001}"
        ));
        assert!(is_public_named_value("errorCode", "0x80070005"));
        assert!(is_public_named_value("errorCode", "2147942405"));
        assert!(is_public_named_value("updateRevisionNumber", "1"));
        assert!(is_public_named_value("serviceGuid", ""));
    }

    #[test]
    fn a_policy_value_never_survives_the_export() {
        let mut snapshot = UpdateSnapshot::default();
        snapshot.policy_chain.observations.push(PolicyObservation {
            context: context(),
            signal: PolicySignal::Applied,
            setting_uri: Some(
                "./Device/Vendor/MSFT/Policy/Config/Update/UpdateServiceUrl".to_owned(),
            ),
            setting_id: None,
            policy_id: None,
            value: Some("http://wsus.example.invalid:8530".to_owned()),
            error: None,
            event_id: None,
            source: None,
            named_data: vec![IntuneNamedValue {
                name: "Message5".to_owned(),
                value: "http://wsus.example.invalid:8530".to_owned(),
            }],
        });

        let exported = redacted_export_projection(&snapshot);
        let observation = &exported.policy_chain.observations[0];
        assert_eq!(observation.value.as_deref(), Some(REDACTED));
        assert_eq!(observation.named_data[0].value, REDACTED);
        assert_eq!(observation.named_data[0].name, "Message5");
        assert!(observation.context.provenance.file_path.is_none());
        // Provenance that cannot identify anyone must survive, or the export
        // stops being traceable.
        assert_eq!(observation.context.provenance.record_number, Some(3));
    }

    #[test]
    fn microsoft_defined_identifiers_survive_the_export() {
        let mut snapshot = UpdateSnapshot::default();
        snapshot
            .update_chain
            .unkeyed_observations
            .push(UpdateObservation {
                context: context(),
                phase: UpdatePhase::Scan,
                outcome: UpdateOutcome::Failed,
                key: UpdateKey::default(),
                error: None,
                activity_id: None,
                event_id: Some(25),
                source: None,
                title: None,
                supplemental: None,
                named_data: vec![
                    IntuneNamedValue {
                        name: "errorCode".to_owned(),
                        value: "0x8024402C".to_owned(),
                    },
                    IntuneNamedValue {
                        name: "Message2".to_owned(),
                        value: "tenant specific".to_owned(),
                    },
                ],
            });

        let exported = redacted_export_projection(&snapshot);
        let named = &exported.update_chain.unkeyed_observations[0].named_data;
        assert_eq!(named[0].value, "0x8024402C");
        assert_eq!(named[1].value, REDACTED);
    }

    #[test]
    fn the_projection_is_deterministic() {
        let snapshot = UpdateSnapshot::default();
        let first = serde_json::to_string(&redacted_export_projection(&snapshot)).unwrap();
        let second = serde_json::to_string(&redacted_export_projection(&snapshot)).unwrap();
        assert_eq!(first, second);
    }
}

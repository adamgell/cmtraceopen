//! Privacy-safe export projection.
//!
//! The default export must not carry identity, device, tenant, path, or token
//! material. What survives is the diagnostic skeleton: which record, from which
//! provider, at which phase, with which outcome and error code.
//!
//! The projection is a pure function of the snapshot, so the same snapshot
//! always exports the same bytes. It reuses [`UpdateSnapshot`] rather than
//! introducing an export-only type, which keeps one shape to golden-test and
//! makes "what did redaction change?" a field-by-field diff.

use crate::intune::evidence::{IntuneNamedValue, IntuneObservationContext, IntuneSensitivity};

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
        observation.named_data = redact_named(&observation.named_data);
    }

    for observation in &mut projected.update_chain.unkeyed_observations {
        redact_context(&mut observation.context);
        observation.named_data = redact_named(&observation.named_data);
    }

    // Update titles are Microsoft product strings and carry no identity, so they
    // survive; they are the most useful thing in the export.
    for coverage in &mut projected.coverage {
        // `detail` is adapter free text and can name a path or an account.
        if coverage.detail.is_some() {
            coverage.detail = Some(REDACTED.to_owned());
        }
    }

    projected
}

fn redact_device(device: &UpdateDeviceFacts) -> UpdateDeviceFacts {
    let mut redacted = device.clone();
    if let Some(context) = redacted.context.as_mut() {
        redact_context(context);
    }
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
fn redact_named(values: &[IntuneNamedValue]) -> Vec<IntuneNamedValue> {
    values
        .iter()
        .map(|entry| IntuneNamedValue {
            name: entry.name.clone(),
            value: if is_public_named_value(&entry.name) {
                entry.value.clone()
            } else {
                REDACTED.to_owned()
            },
        })
        .collect()
}

/// Named values whose content is a Microsoft-defined identifier rather than
/// tenant data, and which are therefore safe to export verbatim.
fn is_public_named_value(name: &str) -> bool {
    const PUBLIC: [&str; 5] = [
        super::sources::NAMED_UPDATE_GUID,
        super::sources::NAMED_UPDATE_REVISION,
        super::sources::NAMED_ERROR_CODE,
        super::sources::NAMED_SERVICE_GUID,
        super::sources::NAMED_UPDATE_COUNT,
    ];
    PUBLIC
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
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

    #[test]
    fn a_policy_value_never_survives_the_export() {
        let mut snapshot = UpdateSnapshot::default();
        snapshot.policy_chain.observations.push(PolicyObservation {
            context: context(),
            signal: PolicySignal::Applied,
            setting_uri: Some("./Device/Vendor/MSFT/Policy/Config/Update/UpdateServiceUrl".to_owned()),
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

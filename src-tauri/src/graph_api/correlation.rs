//! Deterministic local-to-Graph device correlation for ESP diagnostics.

use cmtraceopen_parser::esp::{
    EspCorrelationConfidence, EspEvidenceRef, EspGraphDeviceMatch, EspGraphManagedDevice,
    EspIdentityEvidence,
};

use super::normalize_graph_guid;

#[derive(Clone)]
struct MatchRule {
    basis: &'static str,
    confidence: EspCorrelationConfidence,
}

/// Correlate a local ESP identity with bounded managed-device candidates.
///
/// Rules are intentionally ordered. An explicit UI selection wins, followed
/// by locally observed managed-device ID, Entra device ID, serial number, and
/// only then an exact hostname with corroborating tenant or user evidence.
/// Ambiguous matches never select a device automatically.
pub fn correlate_managed_device(
    identity: &EspIdentityEvidence,
    selected_managed_device_id: Option<&str>,
    mut candidates: Vec<EspGraphManagedDevice>,
) -> EspGraphDeviceMatch {
    candidates.sort_by(|left, right| {
        left.managed_device_id
            .to_ascii_lowercase()
            .cmp(&right.managed_device_id.to_ascii_lowercase())
            .then_with(|| left.managed_device_id.cmp(&right.managed_device_id))
    });

    if let Some(selected) = selected_managed_device_id {
        let matched: Vec<EspGraphManagedDevice> = candidates
            .iter()
            .filter(|candidate| guid_eq(&candidate.managed_device_id, selected))
            .cloned()
            .collect();
        if matched.len() == 1 {
            return EspGraphDeviceMatch {
                selected: matched.first().cloned(),
                evidence: combined_evidence(identity, &matched),
                candidates: matched,
                match_basis: Some("selectedManagedDeviceId".to_string()),
                confidence: EspCorrelationConfidence::Exact,
            };
        }

        return EspGraphDeviceMatch {
            selected: None,
            evidence: combined_evidence(identity, &candidates),
            candidates,
            match_basis: Some("selectedManagedDeviceId".to_string()),
            confidence: EspCorrelationConfidence::Uncorrelated,
        };
    }

    let rules: Vec<(MatchRule, Vec<EspGraphManagedDevice>)> = vec![
        (
            MatchRule {
                basis: "managedDeviceId",
                confidence: EspCorrelationConfidence::Exact,
            },
            identity
                .managed_device_id
                .as_deref()
                .map(|managed_id| {
                    candidates
                        .iter()
                        .filter(|candidate| guid_eq(&candidate.managed_device_id, managed_id))
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
        ),
        (
            MatchRule {
                basis: "entraDeviceId",
                confidence: EspCorrelationConfidence::Exact,
            },
            identity
                .entra_device_id
                .as_deref()
                .map(|entra_id| {
                    candidates
                        .iter()
                        .filter(|candidate| {
                            candidate
                                .entra_device_id
                                .as_deref()
                                .is_some_and(|candidate_id| guid_eq(candidate_id, entra_id))
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
        ),
        (
            MatchRule {
                basis: "serialNumber",
                confidence: EspCorrelationConfidence::Strong,
            },
            identity
                .serial_number
                .as_ref()
                .map(|serial| {
                    candidates
                        .iter()
                        .filter(|candidate| {
                            candidate
                                .serial_number
                                .as_ref()
                                .is_some_and(|candidate_serial| {
                                    text_eq(&candidate_serial.value, &serial.value)
                                })
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
        ),
        (
            MatchRule {
                basis: "hostnameWithTenantOrUser",
                confidence: EspCorrelationConfidence::Strong,
            },
            identity
                .device_name
                .as_deref()
                .map(|device_name| {
                    candidates
                        .iter()
                        .filter(|candidate| {
                            candidate
                                .device_name
                                .as_deref()
                                .is_some_and(|candidate_name| text_eq(candidate_name, device_name))
                                && corroborates_tenant_or_user(identity, candidate)
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
        ),
    ];

    for (rule, matched) in rules {
        if matched.is_empty() {
            continue;
        }

        let evidence = combined_evidence(identity, &matched);
        if matched.len() == 1 {
            return EspGraphDeviceMatch {
                selected: matched.first().cloned(),
                candidates: matched,
                match_basis: Some(rule.basis.to_string()),
                confidence: rule.confidence,
                evidence,
            };
        }

        return EspGraphDeviceMatch {
            selected: None,
            candidates: matched,
            match_basis: Some(rule.basis.to_string()),
            confidence: EspCorrelationConfidence::Uncorrelated,
            evidence,
        };
    }

    EspGraphDeviceMatch {
        selected: None,
        candidates: Vec::new(),
        match_basis: None,
        confidence: EspCorrelationConfidence::Uncorrelated,
        evidence: identity.evidence.clone(),
    }
}

fn guid_eq(left: &str, right: &str) -> bool {
    normalize_graph_guid(left)
        .is_some_and(|left| normalize_graph_guid(right).is_some_and(|right| left == right))
}

fn text_eq(left: &str, right: &str) -> bool {
    let left = left.trim();
    let right = right.trim();
    !left.is_empty() && left.eq_ignore_ascii_case(right)
}

fn corroborates_tenant_or_user(
    identity: &EspIdentityEvidence,
    candidate: &EspGraphManagedDevice,
) -> bool {
    let tenant_matches = identity.tenant_id.as_ref().is_some_and(|local| {
        candidate
            .tenant_id
            .as_ref()
            .is_some_and(|remote| text_eq(&local.value, &remote.value))
    });
    let user_matches = identity.user_principal_name.as_ref().is_some_and(|local| {
        candidate
            .user_principal_name
            .as_ref()
            .is_some_and(|remote| text_eq(&local.value, &remote.value))
    });
    tenant_matches || user_matches
}

fn combined_evidence(
    identity: &EspIdentityEvidence,
    candidates: &[EspGraphManagedDevice],
) -> Vec<EspEvidenceRef> {
    let mut evidence = identity.evidence.clone();
    for candidate in candidates {
        for item in &candidate.evidence {
            if !evidence.iter().any(|existing| existing == item) {
                evidence.push(item.clone());
            }
        }
    }
    evidence
}

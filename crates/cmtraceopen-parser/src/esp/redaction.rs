use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use regex::Regex;

use super::models::*;

const REDACTED: &str = "[redacted]";
const REMOVED_OVERSIZE: &str = "[redacted: oversized text omitted]";
const MAX_REDACTION_INPUT_BYTES: usize = 256 * 1024;

fn email_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
            .expect("email redaction pattern must compile")
    })
}

fn sid_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bS-1-(?:0x[0-9A-F]{1,12}|\d{1,10})(?:-\d{1,10}){1,15}\b")
            .expect("SID redaction pattern must compile")
    })
}

fn user_profile_path_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)(?P<prefix>(?:^|[\\/])(?:users|documents and settings)[\\/])[^\\/\r\n]+")
            .expect("user-profile path redaction pattern must compile")
    })
}

fn authorization_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<prefix>(?:--?|/)?authorization(?:\s+|\s*[=:]\s*))(?:basic\s+|bearer\s+|digest\s+|apikey\s+)?(?P<value>"[^"]*"|'[^']*'|[^\s]+)"#,
        )
        .expect("authorization redaction pattern must compile")
    })
}

fn secret_argument_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<prefix>(?:--?|/)?(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|tenant(?:id)?|entdmid|serial(?:number)?)(?:\s+|\s*[=:]\s*))(?P<value>"[^"]*"|'[^']*'|[^\s]+)"#,
        )
        .expect("secret argument redaction pattern must compile")
    })
}

fn forbidden_raw_content_pattern() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(authorization\s*:|(?:access|refresh|id)[_-]?token\s*[:=]|bearer\s+[A-Z0-9._~+/=-]{8,})",
        )
        .expect("forbidden raw-content pattern must compile")
    })
}

/// Return a safe copy/export projection without changing the local snapshot.
///
/// Typed sensitive fields are masked, secret-like command arguments are
/// redacted, SID-bearing structural IDs are consistently pseudonymized, and
/// source records that could contain credentials, raw Graph responses, or
/// hardware hashes are omitted completely.
pub fn redacted_export_projection(snapshot: &EspDiagnosticsSnapshot) -> EspDiagnosticsSnapshot {
    let mut safe = snapshot.clone();
    let sid_pseudonyms = collect_sid_pseudonyms(&safe);
    pseudonymize_sid_references(&mut safe, &sid_pseudonyms);

    redact_identity(&mut safe.identity);
    if let Some(profile) = &mut safe.profile {
        redact_profile(profile);
    }
    for enrollment in &mut safe.enrollments {
        mask_classified(&mut enrollment.tenant_id);
        mask_classified(&mut enrollment.user_principal_name);
        mask_classified(&mut enrollment.entdm_id);
    }
    for session in &mut safe.sessions {
        pseudonymize_classified_sid(&mut session.user_sid, &sid_pseudonyms);
    }
    for workload in &mut safe.workloads {
        redact_optional_text(&mut workload.display_name);
        redact_status(&mut workload.status);
    }
    for correlation in &mut safe.installer_correlations {
        correlation.reason = redact_text(&correlation.reason);
        for process in &mut correlation.process_observations {
            redact_optional_text(&mut process.sanitized_command_line);
            redact_optional_text(&mut process.referenced_log_path);
            redact_provenance(&mut process.context.provenance);
        }
    }
    for node in &mut safe.node_cache {
        if node.expected_value.is_some() {
            node.expected_value = Some(REDACTED.to_string());
        }
    }
    for registration in &mut safe.registration_events {
        registration.message = redact_text(&registration.message);
        redact_status(&mut registration.status);
        for named in &mut registration.named_data {
            named.value = redact_text(&named.value);
        }
    }
    if let Some(hardware) = &mut safe.hardware {
        mask_classified(&mut hardware.serial_number);
    }
    for activity in &mut safe.activity {
        activity.title = redact_text(&activity.title);
        redact_optional_text(&mut activity.detail);
        if let Some(status) = &mut activity.status {
            redact_status(status);
        }
    }
    for coverage in &mut safe.coverage {
        redact_optional_text(&mut coverage.detail);
    }
    safe.raw_evidence
        .retain(|record| !raw_record_must_be_removed(record));
    for record in &mut safe.raw_evidence {
        if raw_record_must_be_masked(record) {
            mask_observation_value(&mut record.raw_value);
        } else {
            redact_observation_value(&mut record.raw_value);
        }
        redact_provenance(&mut record.provenance);
    }
    if let Some(graph) = &mut safe.graph {
        redact_graph_overlay(graph);
    }

    safe
}

fn redact_identity(identity: &mut EspIdentityEvidence) {
    mask_classified(&mut identity.entdm_id);
    mask_classified(&mut identity.tenant_id);
    mask_classified(&mut identity.tenant_domain);
    mask_classified(&mut identity.user_principal_name);
    mask_classified(&mut identity.serial_number);
}

fn redact_profile(profile: &mut EspProfileEvidence) {
    redact_optional_text(&mut profile.profile_name);
    mask_classified(&mut profile.tenant_domain);
    mask_classified(&mut profile.tenant_id);
}

fn mask_classified(value: &mut Option<EspClassifiedString>) {
    if let Some(value) = value {
        value.value = REDACTED.to_string();
    }
}

fn redact_status(status: &mut EspStatus) {
    redact_raw_status(&mut status.raw);
    status.display = redact_text(&status.display);
    if let Some(detail) = &mut status.detail {
        redact_raw_status(&mut detail.raw);
        detail.display = redact_text(&detail.display);
    }
}

fn redact_raw_status(status: &mut EspRawStatus) {
    if let EspRawStatus::Text(value) = status {
        *value = redact_text(value);
    }
}

fn redact_observation_value(value: &mut EspObservationValue) {
    match value {
        EspObservationValue::Text(value) => *value = redact_text(value),
        EspObservationValue::StringList(values) => {
            for value in values {
                *value = redact_text(value);
            }
        }
        EspObservationValue::Integer(_)
        | EspObservationValue::Unsigned(_)
        | EspObservationValue::Boolean(_) => {}
    }
}

fn mask_observation_value(value: &mut EspObservationValue) {
    *value = EspObservationValue::Text(REDACTED.to_string());
}

fn collect_sid_pseudonyms(snapshot: &EspDiagnosticsSnapshot) -> BTreeMap<String, String> {
    let mut sids = BTreeSet::new();
    for session in &snapshot.sessions {
        collect_sids(&session.session_id, &mut sids);
        if let Some(user_sid) = &session.user_sid {
            collect_sids(&user_sid.value, &mut sids);
        }
        for workload_id in &session.workload_ids {
            collect_sids(workload_id, &mut sids);
        }
    }
    for workload in &snapshot.workloads {
        collect_sids(&workload.workload_id, &mut sids);
        collect_sids(&workload.session_id, &mut sids);
    }
    for correlation in &snapshot.installer_correlations {
        if let Some(workload_id) = &correlation.workload_id {
            collect_sids(workload_id, &mut sids);
        }
        for workload_id in &correlation.candidate_workload_ids {
            collect_sids(workload_id, &mut sids);
        }
    }

    sids.into_iter()
        .enumerate()
        .map(|(index, sid)| (sid, format!("[redacted-sid-{}]", index + 1)))
        .collect()
}

fn collect_sids(value: &str, sids: &mut BTreeSet<String>) {
    sids.extend(
        sid_pattern()
            .find_iter(value)
            .map(|matched| matched.as_str().to_ascii_uppercase()),
    );
}

fn pseudonymize_sid_references(
    snapshot: &mut EspDiagnosticsSnapshot,
    pseudonyms: &BTreeMap<String, String>,
) {
    for session in &mut snapshot.sessions {
        pseudonymize_sids(&mut session.session_id, pseudonyms);
        for workload_id in &mut session.workload_ids {
            pseudonymize_sids(workload_id, pseudonyms);
        }
    }
    for workload in &mut snapshot.workloads {
        pseudonymize_sids(&mut workload.workload_id, pseudonyms);
        pseudonymize_sids(&mut workload.session_id, pseudonyms);
    }
    for correlation in &mut snapshot.installer_correlations {
        if let Some(workload_id) = &mut correlation.workload_id {
            pseudonymize_sids(workload_id, pseudonyms);
        }
        for workload_id in &mut correlation.candidate_workload_ids {
            pseudonymize_sids(workload_id, pseudonyms);
        }
    }
}

fn pseudonymize_classified_sid(
    value: &mut Option<EspClassifiedString>,
    pseudonyms: &BTreeMap<String, String>,
) {
    if let Some(value) = value {
        value.value = pseudonyms
            .get(&value.value.to_ascii_uppercase())
            .cloned()
            .unwrap_or_else(|| REDACTED.to_string());
    }
}

fn pseudonymize_sids(value: &mut String, pseudonyms: &BTreeMap<String, String>) {
    *value = sid_pattern()
        .replace_all(value, |captures: &regex::Captures<'_>| {
            pseudonyms
                .get(&captures[0].to_ascii_uppercase())
                .cloned()
                .unwrap_or_else(|| REDACTED.to_string())
        })
        .into_owned();
}

fn redact_optional_text(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = redact_text(value);
    }
}

fn redact_text(value: &str) -> String {
    let bounded = bounded_text(value);
    let redacted = authorization_pattern().replace_all(bounded, "${prefix}[redacted]");
    let redacted = secret_argument_pattern().replace_all(&redacted, "${prefix}[redacted]");
    let redacted = user_profile_path_pattern().replace_all(&redacted, "${prefix}[redacted]");
    let redacted = email_pattern().replace_all(&redacted, REDACTED);
    let redacted = sid_pattern().replace_all(&redacted, REDACTED);
    if bounded.len() == value.len() {
        redacted.into_owned()
    } else {
        format!("{redacted}\n{REMOVED_OVERSIZE}")
    }
}

fn bounded_text(value: &str) -> &str {
    if value.len() <= MAX_REDACTION_INPUT_BYTES {
        return value;
    }
    let mut end = MAX_REDACTION_INPUT_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn raw_record_must_be_removed(record: &EspRawEvidenceRecord) -> bool {
    if record.provenance.source_kind == EspSourceKind::Graph {
        return true;
    }
    let mut labels = vec![
        record.record_id.as_str(),
        record.provenance.source_artifact_id.as_str(),
    ];
    if let Some(path) = record.provenance.file_path.as_deref() {
        labels.push(path);
    }
    if let Some(registry) = &record.provenance.registry {
        labels.push(registry.key.as_str());
        if let Some(value_name) = registry.value_name.as_deref() {
            labels.push(value_name);
        }
    }
    if let Some(event) = &record.provenance.event {
        labels.extend(event.named_data.iter().map(|value| value.name.as_str()));
    }
    if labels.iter().any(|label| forbidden_raw_label(label)) {
        return true;
    }
    match &record.raw_value {
        EspObservationValue::Text(value) => forbidden_raw_content(value),
        EspObservationValue::StringList(values) => {
            values.iter().any(|value| forbidden_raw_content(value))
        }
        EspObservationValue::Integer(_)
        | EspObservationValue::Unsigned(_)
        | EspObservationValue::Boolean(_) => false,
    }
}

fn raw_record_must_be_masked(record: &EspRawEvidenceRecord) -> bool {
    if matches!(
        record.sensitivity,
        EspSensitivity::Sensitive | EspSensitivity::Restricted
    ) {
        return true;
    }
    let Some(registry) = &record.provenance.registry else {
        return false;
    };
    if normalize_label(&registry.key).contains("nodecache") {
        return true;
    }
    registry
        .value_name
        .as_deref()
        .is_some_and(sensitive_value_label)
}

fn sensitive_value_label(value: &str) -> bool {
    let normalized = normalize_label(value);
    matches!(
        normalized.as_str(),
        "upn"
            | "userprincipalname"
            | "usersid"
            | "sid"
            | "aadtenantid"
            | "tenantid"
            | "tenantdomain"
            | "cloudassignedtenantid"
            | "cloudassignedtenantdomain"
            | "entdmid"
            | "serial"
            | "serialnumber"
    )
}

fn forbidden_raw_label(value: &str) -> bool {
    let normalized = normalize_label(value);
    [
        "authorization",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "hardwarehash",
        "rawgraphbody",
        "graphresponsebody",
    ]
    .iter()
    .any(|forbidden| normalized.contains(forbidden))
}

fn normalize_label(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn forbidden_raw_content(value: &str) -> bool {
    forbidden_raw_content_pattern().is_match(bounded_text(value))
}

fn redact_provenance(provenance: &mut EspEvidenceProvenance) {
    if let Some(path) = &mut provenance.file_path {
        *path = redact_text(path);
    }
    if let Some(registry) = &mut provenance.registry {
        registry.key = redact_text(&registry.key);
    }
    if let Some(event) = &mut provenance.event {
        for named in &mut event.named_data {
            named.value = if sensitive_value_label(&named.name) || forbidden_raw_label(&named.name)
            {
                REDACTED.to_string()
            } else {
                redact_text(&named.value)
            };
        }
    }
}

fn redact_graph_overlay(graph: &mut EspGraphOverlay) {
    if let Some(device_match) = &mut graph.device_match.data {
        if let Some(selected) = &mut device_match.selected {
            redact_graph_managed_device(selected);
        }
        for candidate in &mut device_match.candidates {
            redact_graph_managed_device(candidate);
        }
    }
    redact_graph_error(&mut graph.device_match.error);

    if let Some(identity) = &mut graph.autopilot_identity.data {
        mask_classified(&mut identity.serial_number);
        redact_optional_text(&mut identity.group_tag);
    }
    redact_graph_error(&mut graph.autopilot_identity.error);

    redact_graph_profile_section(&mut graph.deployment_profile);
    redact_graph_profile_section(&mut graph.intended_deployment_profile);
    redact_graph_error(&mut graph.profile_assignments.error);

    if let Some(events) = &mut graph.autopilot_events.data {
        for event in events {
            redact_status(&mut event.deployment_state);
            for detail in &mut event.policy_status_details {
                redact_optional_text(&mut detail.display_name);
                redact_status(&mut detail.status);
            }
        }
    }
    redact_graph_error(&mut graph.autopilot_events.error);

    if let Some(configuration) = &mut graph.enrollment_configuration.data {
        redact_optional_text(&mut configuration.display_name);
    }
    redact_graph_error(&mut graph.enrollment_configuration.error);

    if let Some(apps) = &mut graph.apps.data {
        for app in apps {
            redact_optional_text(&mut app.display_name);
            if let Some(status) = &mut app.status {
                redact_status(status);
            }
        }
    }
    redact_graph_error(&mut graph.apps.error);

    if let Some(policies) = &mut graph.policies.data {
        for policy in policies {
            redact_optional_text(&mut policy.display_name);
            if let Some(status) = &mut policy.status {
                redact_status(status);
            }
        }
    }
    redact_graph_error(&mut graph.policies.error);

    if let Some(scripts) = &mut graph.scripts.data {
        for script in scripts {
            redact_optional_text(&mut script.display_name);
            if let Some(status) = &mut script.status {
                redact_status(status);
            }
        }
    }
    redact_graph_error(&mut graph.scripts.error);
}

fn redact_graph_managed_device(device: &mut EspGraphManagedDevice) {
    mask_classified(&mut device.serial_number);
    mask_classified(&mut device.user_principal_name);
    mask_classified(&mut device.tenant_id);
}

fn redact_graph_profile_section(section: &mut GraphSection<EspGraphDeploymentProfile>) {
    if let Some(profile) = &mut section.data {
        redact_optional_text(&mut profile.display_name);
    }
    redact_graph_error(&mut section.error);
}

fn redact_graph_error(error: &mut Option<GraphSectionError>) {
    if let Some(error) = error {
        error.message = redact_text(&error.message);
    }
}

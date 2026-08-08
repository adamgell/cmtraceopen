//! Redaction projection for the Company Portal Windows log evidence document.
//!
//! The rule table itself lives in `esp::redaction` and is reused verbatim
//! through [`crate::esp::redact_text`]. It is evidence-agnostic — UPN/email,
//! user-profile paths, SIDs, secret-labelled values (`token`, `authorization`,
//! `tenantId`, `serialNumber`, `hardwareHash`, …), Azure storage credentials,
//! and IPv4/IPv6/MAC identifiers — and duplicating it here would let two rule
//! tables drift apart. This module only decides *which fields* of a Company
//! Portal document are free text.

use crate::esp::redact_text;

use super::models::CompanyPortalLogDocument;

/// Return a safe copy/export projection without changing the input document.
///
/// Every free-text field is run through the shared rule table; the file name,
/// activity id, app version, sequence, and timestamps are structural and are
/// left intact so records stay correlatable after redaction.
///
/// Callers normally get this for free: `parse_log_document` applies it, and
/// only `parse_log_document_preserving_local_values` skips it.
pub fn redacted_export_projection(document: &CompanyPortalLogDocument) -> CompanyPortalLogDocument {
    let mut safe = document.clone();
    safe.redacted = true;

    for record in &mut safe.records {
        record.message = redact_text(&record.message);
        record.raw_text = redact_text(&record.raw_text);
        if let Some(severity) = &mut record.severity {
            severity.raw_text = redact_text(&severity.raw_text);
        }
        redact_optional(&mut record.component);
        redact_optional(&mut record.category);
        redact_optional(&mut record.scenario);
    }

    for coverage in &mut safe.coverage {
        redact_optional(&mut coverage.detail);
    }

    safe
}

fn redact_optional(value: &mut Option<String>) {
    if let Some(value) = value {
        *value = redact_text(value);
    }
}

#[cfg(test)]
mod tests {
    use super::super::document::parse_log_document_preserving_local_values;
    use super::*;

    const PATH: &str = "C:/Users/adele.vance/AppData/Local/Packages/Microsoft.CompanyPortal_8wekyb3d8bbwe/LocalState/Log_1.log";

    fn sample_document() -> CompanyPortalLogDocument {
        let content = concat!(
            "2024-11-15T16:50:07.2850341Z  INFO  Event  None  0  ",
            "1487dc30-3bb0-46bf-98ee-76771bd9953e  12-0-0  ",
            "[SignIn] signed in adele.vance@contoso.onmicrosoft.com from 203.0.113.10\n",
        );
        parse_log_document_preserving_local_values(PATH, content)
    }

    #[test]
    fn projection_does_not_mutate_the_input_document() {
        let document = sample_document();
        let safe = redacted_export_projection(&document);

        assert!(!document.redacted);
        assert!(safe.redacted);
        assert!(document.records[0]
            .message
            .contains("adele.vance@contoso.onmicrosoft.com"));
    }

    #[test]
    fn projection_is_idempotent() {
        let document = sample_document();
        let safe = redacted_export_projection(&document);

        assert_eq!(redacted_export_projection(&safe), safe);
    }

    #[test]
    fn structural_correlation_fields_survive_redaction() {
        let safe = redacted_export_projection(&sample_document());

        assert_eq!(
            safe.records[0].activity_id.as_deref(),
            Some("1487dc30-3bb0-46bf-98ee-76771bd9953e")
        );
        assert_eq!(safe.records[0].component.as_deref(), Some("SignIn"));
        assert_eq!(safe.file.file_name, "Log_1.log");
    }
}

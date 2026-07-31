//! Deterministic redaction for Company Portal macOS log exports.
//!
//! Company Portal advanced logging adds certificate and network-response detail,
//! so redaction is on by default and covers identity/UPN/email, tenant and
//! device ids, serials, tokens and secrets, URLs (including every query value),
//! certificate subjects and thumbprints, user paths, and network addresses
//! (IPv4, IPv6, and MAC).
//!
//! Placeholders are stable and correlation-preserving: the same original value
//! always maps to the same token within an export, and a given input always
//! produces byte-identical output. Original values are never carried into the
//! export, not even in the placeholder index.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;

use super::models::*;

fn certificate_subject_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bCN=[^\r\n]+").expect("certificate subject pattern must compile")
    })
}

fn labeled_secret_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:access[_-]?token|refresh[_-]?token|id[_-]?token|bearer[_-]?token|auth[_-]?token|token|password|passwd|pwd|client[_-]?secret|secret|api[_-]?key)\s*[:=]\s*("?[^\s"',;]+"?)"#,
        )
        .expect("labeled secret pattern must compile")
    })
}

fn thumbprint_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b(?:thumbprint|fingerprint)\s*[:=]\s*([0-9A-Fa-f:]{16,})")
            .expect("thumbprint pattern must compile")
    })
}

fn serial_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:serial(?:[_-]?number)?|device[_-]?serial)\s*[:=]\s*([A-Za-z0-9-]{4,})",
        )
        .expect("serial pattern must compile")
    })
}

fn url_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r#"(?i)\bhttps?://[^\s<>"']+"#).expect("url pattern must compile")
    })
}

fn email_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
            .expect("email pattern must compile")
    })
}

fn guid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b")
            .expect("guid pattern must compile")
    })
}

/// Dotted-quad IPv4, each octet bounded to 0-255 so version strings such as
/// `5.2504.0` cannot match.
fn ipv4_address_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        )
        .expect("ipv4 address pattern must compile")
    })
}

/// Six colon- or dash-separated hex pairs. Runs before the IPv6 matcher, which
/// requires either eight groups or a `::` run and so cannot claim a MAC.
fn mac_address_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b")
            .expect("mac address pattern must compile")
    })
}

/// Fully-expanded eight-group IPv6 or any `::`-compressed form. Greedy so
/// `replace_group` never leaves a trailing fragment behind.
fn ipv6_address_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}|(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?)\b",
        )
        .expect("ipv6 address pattern must compile")
    })
}

fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)/Users/(?P<user>[^/\s]+)(?P<rest>(?:/[^\s]*)?)")
            .expect("user path pattern must compile")
    })
}

/// Issues stable placeholder tokens and tracks how often each was used.
#[derive(Debug, Default)]
struct Redactor {
    tokens: BTreeMap<(&'static str, String), String>,
    counters: BTreeMap<&'static str, u32>,
    placeholders: BTreeMap<(PortalRedactionKind, String), PortalPlaceholder>,
}

impl Redactor {
    fn token_for(&mut self, kind: PortalRedactionKind, original: &str) -> String {
        let key = (kind.tag(), original.to_string());
        let token = match self.tokens.get(&key) {
            Some(token) => token.clone(),
            None => {
                let counter = self.counters.entry(kind.tag()).or_insert(0);
                *counter += 1;
                let token = format!("[redacted:{}:{:03}]", kind.tag(), counter);
                self.tokens.insert(key, token.clone());
                token
            }
        };

        self.placeholders
            .entry((kind, token.clone()))
            .or_insert(PortalPlaceholder {
                token: token.clone(),
                kind,
                occurrences: 0,
            })
            .occurrences += 1;

        token
    }

    /// Replace capture group `group` of every match with a placeholder token.
    fn replace_group(
        &mut self,
        text: &str,
        pattern: &Regex,
        kind: PortalRedactionKind,
        group: usize,
    ) -> String {
        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        for caps in pattern.captures_iter(text) {
            let Some(target) = caps.get(group) else {
                continue;
            };
            let token = self.token_for(kind, target.as_str());
            out.push_str(&text[last..target.start()]);
            out.push_str(&token);
            last = target.end();
        }
        out.push_str(&text[last..]);
        out
    }

    fn replace_user_paths(&mut self, text: &str) -> String {
        let pattern = user_path_re();
        let mut out = String::with_capacity(text.len());
        let mut last = 0usize;
        for caps in pattern.captures_iter(text) {
            let whole = caps.get(0).expect("group 0 always matches");
            let user = caps.name("user").map(|m| m.as_str()).unwrap_or_default();
            let rest = caps.name("rest").map(|m| m.as_str()).unwrap_or_default();

            out.push_str(&text[last..whole.start()]);
            out.push_str("/Users/");
            out.push_str(&self.token_for(PortalRedactionKind::UserName, user));
            if !rest.is_empty() {
                out.push('/');
                out.push_str(&self.token_for(PortalRedactionKind::Path, rest));
            }
            last = whole.end();
        }
        out.push_str(&text[last..]);
        out
    }

    /// Apply every redaction rule, in a fixed order.
    ///
    /// Certificate subjects go first and are deliberately over-broad (`CN=` to
    /// end of line) so no RDN component survives. URLs are redacted whole, which
    /// removes every query value with them.
    ///
    /// Network addresses run after URLs so a host embedded in a URL is already
    /// gone, and in IPv4 then MAC then IPv6 order so an IPv4-mapped IPv6 address
    /// cannot leak its dotted tail and a MAC cannot be mistaken for an IPv6 run.
    fn redact(&mut self, text: &str) -> String {
        let text = self.replace_group(
            text,
            certificate_subject_re(),
            PortalRedactionKind::Certificate,
            0,
        );
        let text = self.replace_group(&text, labeled_secret_re(), PortalRedactionKind::Token, 1);
        let text = self.replace_group(&text, thumbprint_re(), PortalRedactionKind::Certificate, 1);
        let text = self.replace_group(&text, serial_re(), PortalRedactionKind::Serial, 1);
        let text = self.replace_group(&text, url_re(), PortalRedactionKind::Url, 0);
        let text = self.replace_group(&text, email_re(), PortalRedactionKind::Email, 0);
        let text = self.replace_group(&text, guid_re(), PortalRedactionKind::Guid, 0);
        let text = self.replace_group(&text, ipv4_address_re(), PortalRedactionKind::Ip, 0);
        let text = self.replace_group(&text, mac_address_re(), PortalRedactionKind::Mac, 0);
        let text = self.replace_group(&text, ipv6_address_re(), PortalRedactionKind::Ip, 0);
        self.replace_user_paths(&text)
    }

    fn into_placeholders(self) -> Vec<PortalPlaceholder> {
        self.placeholders.into_values().collect()
    }
}

/// Build the deterministic, redacted export projection of a parse.
///
/// Two runs over equal input produce byte-identical JSON: tokens are issued in a
/// fixed traversal order and the placeholder index is ordered by kind then
/// token.
pub fn redacted_export_projection(parse: &PortalLogParse) -> PortalRedactedExport {
    let mut redactor = Redactor::default();

    let file_path = redactor.redact(&parse.file_path);
    let source_artifact_id = redactor.redact(&parse.source_artifact_id);

    let records = parse
        .records
        .iter()
        .map(|record| PortalRedactedRecord {
            record_index: record.record_index,
            line_number: record.line_number,
            line_span: record.line_span,
            state: record.state,
            timestamp: record.timestamp.clone(),
            severity_letter: record.severity_letter.clone(),
            severity: record.severity,
            process: record.process.clone(),
            component: record.component.clone(),
            thread_id: record.thread_id,
            activity_id: record
                .activity_id
                .as_ref()
                .map(|activity| redactor.redact(&activity.value)),
            category: record.category,
            message: redactor.redact(&record.message.value),
            raw_text: redactor.redact(&record.raw_text.value),
            evidence_id: record.evidence_ref.evidence_id.clone(),
        })
        .collect();

    PortalRedactedExport {
        schema_version: parse.schema_version,
        source_artifact_id,
        file_path,
        encoding: parse.encoding,
        rotation: PortalRotationMember {
            file_name: parse.rotation.file_name.clone(),
            rotation_index: parse.rotation.rotation_index,
            is_current: parse.rotation.is_current,
        },
        detection: parse.detection.clone(),
        app_version: parse.app_version.clone(),
        coverage: parse.coverage.clone(),
        records,
        placeholders: redactor.into_placeholders(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact(text: &str) -> String {
        Redactor::default().redact(text)
    }

    #[test]
    fn redacts_identity_and_secrets() {
        let redacted =
            redact("user adele.vance@contoso.example accessToken=eyJhbGciOi.payload.sig");
        assert!(!redacted.contains("adele.vance@contoso.example"));
        assert!(!redacted.contains("eyJhbGciOi.payload.sig"));
        assert!(redacted.contains("[redacted:email:001]"));
        assert!(redacted.contains("[redacted:token:001]"));
    }

    #[test]
    fn redacts_urls_including_query_values() {
        let redacted =
            redact("GET https://manage.contoso.example/apps?tenantId=4b2f9d61-1c53-4c58-8f1a-b0d3e1b5aa77 returned 200");
        assert!(!redacted.contains("tenantId"));
        assert!(!redacted.contains("4b2f9d61"));
        assert!(redacted.ends_with(" returned 200"));
    }

    #[test]
    fn redacts_certificate_serial_and_paths() {
        let redacted = redact("subject CN=SC_Online_Issuing, OU=Devices");
        assert!(!redacted.contains("SC_Online_Issuing"));

        let redacted = redact("thumbprint=A1B2C3D4E5F60718293A4B5C6D7E8F9012345678");
        assert!(!redacted.contains("A1B2C3D4"));

        let redacted = redact("serialNumber=C02XK1TDJGH5 model MacBookPro18,3");
        assert!(!redacted.contains("C02XK1TDJGH5"));
        assert!(redacted.contains("model MacBookPro18,3"));

        let redacted = redact("/Users/adele/Library/Logs/CompanyPortal/report.zip");
        assert!(!redacted.contains("adele"));
        assert!(redacted.starts_with("/Users/[redacted:user:001]/"));
    }

    #[test]
    fn repeated_values_reuse_one_token() {
        let mut redactor = Redactor::default();
        let first = redactor.redact("a@b.example");
        let second = redactor.redact("a@b.example");
        assert_eq!(first, second);
        let placeholders = redactor.into_placeholders();
        assert_eq!(placeholders.len(), 1);
        assert_eq!(placeholders[0].occurrences, 2);
    }
}

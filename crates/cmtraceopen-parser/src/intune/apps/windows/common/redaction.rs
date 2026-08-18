//! Deterministic text masking shared by the Intune Windows analyzers.
//!
//! Platform scripts and remediations quote the same kinds of sensitive value --
//! UPNs, user profile paths, inline command lines and credential switches -- so
//! they mask them with one implementation rather than two that can drift apart.
//! Each analyzer still owns its own *projection*: which fields are classified
//! sensitive is a property of that analyzer's contract, not of this module.
//!
//! Masking is a pure function of the masked text, so the same input always
//! produces the same token and two records that mentioned the same user still
//! visibly mention the same user. The projection is idempotent: replacement
//! tokens cannot themselves match a rule.

const REMOVED_OVERSIZE: &str = "[redacted: oversized text omitted]";
const MAX_REDACTION_INPUT_BYTES: usize = 256 * 1024;
use std::sync::OnceLock;

use regex::Regex;

/// FNV-1a. Stable across runs and platforms, which `DefaultHasher` is not.
fn stable_token(kind: &str, value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("[{kind}:{:016x}]", hash)
}

fn upn_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
            .expect("UPN regex must compile")
    })
}

/// The profile segment of a user path, in either slash direction.
///
/// Both profile roots are covered: `Users` and the legacy
/// `Documents and Settings`, which still appears in installer logs via
/// junction-resolved paths and older tooling. The separator may be doubled.
/// These logs embed JSON payloads, and a Windows path inside one arrives
/// JSON-escaped as `C:\\Users\\Someone`; requiring a single separator let
/// every such path through unmasked.
fn user_path_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // The segment is bounded by the path separator, a quote, or the end of
        // the line -- not by whitespace. Windows permits spaces in profile
        // directory names, and bounding on `\s` masked only the first word:
        // `C:\Users\John Doe\...` leaked "Doe" into the export.
        //
        // The leading `[` exclusion is what makes the projection idempotent:
        // an already-masked `[user:...]` segment must not be masked again.
        Regex::new(
            r"(?i)(?P<prefix>[\\/]{1,2}(?:Users|Documents and Settings)[\\/]{1,2})(?P<user>[^\\/\r\n\x22\[][^\\/\r\n\x22]*)",
        )
        .expect("user path regex must compile")
    })
}

/// A command line or credential value supplied inline after a flag.
///
/// Two properties matter here and both were bugs before:
///
/// * The value must stop at a line break rather than at the end of the string.
///   A CCM record is one *logical* record and routinely contains newlines (see
///   the `multiline-ccm-record` fixture). Anchoring on `$` meant a `-Command`
///   inside a multi-line record matched nothing at all and leaked in full.
/// * The separator between flag and value may be whitespace, `:` or `=`.
///   `-Password:hunter2` and `-Token=abc` are as common as the spaced form and
///   were previously exported verbatim.
/// * The flag vocabulary covers credential-bearing switches, not just
///   `-Command`. A launch record reading `-Password hunter2` is exactly as
///   sensitive as an inline command and was previously exported verbatim.
/// * The sigil may be `-` or `/`. Installer command lines use the slash form
///   (`/Password hunter2`) as often as the dash form.
///
/// The value deliberately runs to the end of the line rather than the next
/// token: a `-Command` value is multi-token by nature, and over-masking a
/// trailing switch is safe where under-masking a second secret token is not.
fn command_line_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r"(?i)(?P<flag>[-/](?:Command|EncodedCommand|Password|Secret|ClientSecret|Token|AccessToken|ApiKey|Api[-_]?Key|Credential|Authorization)[\s:=]+)(?P<value>[^\r\n]+)",
        )
        .expect("command line regex must compile")
    })
}

/// An MSI-property-style credential: `PASSWORD=hunter2` with no sigil at all.
///
/// `msiexec` product lines pass secrets as public properties, and nothing in
/// that shape carries a `-` or `/` for the flag rule to anchor on. The property
/// name vocabulary is deliberately credential-shaped only, so an ordinary
/// property like `INSTALLDIR=` stays visible.
fn msi_property_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?P<property>\b(?i:PASSWORD|PWD|PASSPHRASE|LICENSEKEY|LICENSE_KEY|PRODUCTKEY|PRODUCT_KEY|SERIALKEY|SERIAL|APIKEY|API_KEY|APISECRET|API_SECRET|ACCESS_TOKEN|ACCESSTOKEN|TOKEN|SECRET|CLIENTSECRET|CLIENT_SECRET|CREDENTIAL|CREDENTIALS)\s*["']?\s*[:=]\s*)(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s\r\n]+)"#,
        )
        .expect("msi property regex must compile")
    })
}

/// Organization-owned identifiers and device inventory values are sensitive
/// when they occur in an explicitly labelled field. Bare GUIDs remain visible
/// because they are often correlation keys rather than tenant identity.
fn sensitive_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<field>\b(?:serial(?:number)?|device(?:id|serial(?:number)?)|hardware(?:hash|identifier|id|data)|devicehardwaredata|tenant(?:id)?|aadtenantid)\s*["']?\s*[:=]\s*)(?P<value>\[[a-z]+:[0-9a-f]{16}\]|"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;}\]<>]+)"#,
        )
        .expect("sensitive field redaction pattern must compile")
    })
}
/// JSON properties written with HTML entity delimiters.
///
/// Exported event messages sometimes pass through an HTML/XML layer before
/// reaching JSON. Restricting this rule to an explicit property name and a
/// quoted value catches those encoded records without treating `&quot;` in
/// ordinary prose as a credential boundary.
fn entity_encoded_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?is)&quot;(?P<field>RunAsUser|RunAsAccount|TargetUserName|UserName|UserPrincipalName|LoggedOnUser|Account|UserId|Upn|SubjectUserName|SubjectDomainName|ComputerName|Computer|MachineName|HostName|DeviceName|RemoteHost|Password|Pwd|Passphrase|LicenseKey|License_Key|ProductKey|Product_Key|SerialKey|Serial|ApiKey|Api_Key|ApiSecret|Api_Secret|AccessToken|Access_Token|Token|Secret|ClientSecret|Client_Secret|Credential|Credentials|Authorization)&quot;\s*:\s*&quot;(?P<value>.*?)&quot;"#,
        )
        .expect("entity-encoded field redaction pattern must compile")
    })
}

fn redact_entity_encoded_fields(value: &str) -> String {
    entity_encoded_field_re()
        .replace_all(value, |caps: &regex::Captures<'_>| {
            let prefix = format!("{}: ", &caps["field"]);
            let redacted = redact_text(&format!("{prefix}{}", &caps["value"]));
            let redacted = redacted
                .strip_prefix(&prefix)
                .unwrap_or(&caps["value"]);
            format!(
                "&quot;{}&quot;:&quot;{}&quot;",
                &caps["field"], redacted
            )
        })
        .into_owned()
}

fn is_redaction_token(value: &str) -> bool {
    let value = value.trim_matches(|character| character == '"' || character == '\'');
    let Some(body) = value.strip_prefix('[').and_then(|value| value.strip_suffix(']')) else {
        return false;
    };
    let Some((kind, hash)) = body.split_once(':') else {
        return false;
    };
    !kind.is_empty()
        && kind.chars().all(|character| character.is_ascii_lowercase())
        && hash.len() == 16
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn redact_sensitive_field(value: &str) -> String {
    let quote = value.chars().next().filter(|character| *character == '"' || *character == '\'');
    let inner = quote
        .and_then(|quote| value.strip_prefix(quote).and_then(|value| value.strip_suffix(quote)))
        .unwrap_or(value);
    if is_redaction_token(inner) {
        return value.to_owned();
    }
    let redacted = stable_token("sensitive", inner);
    quote.map_or(redacted.clone(), |quote| format!("{quote}{redacted}{quote}"))
}

/// An account named in an explicit field.
///
/// `RunAsUser = CONTOSO\jsmith` carries an identity that neither the UPN rule
/// nor the path rule matches. The value is bounded by a delimiter, a quote, or
/// the end of the line — the same shape as the path rule — never by
/// whitespace: Windows account display forms contain spaces
/// (`CONTOSO\John Doe`), and bounding on whitespace exported the second half
/// of the name verbatim.
fn account_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // The `pre` guard stops the field vocabulary matching *inside* an
        // existing replacement token: `[upn:…]` and `[account:…]` contain the
        // words `upn`/`account` followed by `:`, and without the guard a second
        // pass re-masked the token itself.
        //
        // The value's two alternatives are the leading-`[` rule: a
        // bracket-prefixed value only fires when it is token-*shaped*
        // (`[kind:hex…]`), so bracketed prose like `[not signed in]` never
        // matches and survives verbatim. A token-shaped match is then split
        // by the closure: a well-formed token is preserved (with its tail
        // masked — see `split_leading_token`), while a malformed
        // token-lookalike is masked rather than trusted.
        Regex::new(
            r#"(?i)(?P<pre>^|[^\[])(?P<field>\b(?:RunAsUser|RunAsAccount|TargetUserName|UserName|UserPrincipalName|LoggedOnUser|Account|UserId|Upn|SubjectUserName|SubjectDomainName)\s*["']?\s*[:=]\s*)(?P<value>\[[A-Za-z]+:[0-9a-fA-F]+\][^,;\r\n\x22]*|["'][^"\r\n]*["']|[^\s,;\r\n\x22\[][^,;\r\n\x22<>]*)"#,
        )
        .expect("account field regex must compile")
    })
}

/// A hostname named in an explicit field, or the server segment of a UNC path.
///
/// Free-standing hostnames are indistinguishable from ordinary words, so only
/// the anchored shapes are masked: a device-name field, and the first segment
/// after a UNC `\\` (single or JSON-escaped separators, like the path rule).
fn host_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // A value that begins with an emitted token must not be re-hashed, or
        // the stable `[host:…]` token is destroyed on the second pass; the
        // closure preserves the token and masks any non-token fragment glued
        // after it (`preserve_token_mask_tail`), while a malformed
        // token-lookalike is still masked rather than trusted.
        Regex::new(
            r#"(?i)(?P<field>\b(?:ComputerName|Computer|MachineName|HostName|DeviceName|RemoteHost)\s*["']?\s*[:=]\s*)(?P<value>"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;\r\n\x22<>]+)"#,
        )
        .expect("host field regex must compile")
    })
}

fn unc_host_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // The prefix must not follow a drive-colon: `C:\\Users` is a
        // JSON-escaped local path, not a UNC root. Start-of-text or a
        // separator character anchors a real `\\server` (or its JSON-escaped
        // `\\\\server` form).
        Regex::new(
            r#"(?P<prefix>(?:^|[\s\x22'=,;(])[\\]{2,4})(?P<host>[^\s\\/\x22'\[,;.][^\s\\/\x22',;]*)"#,
        )
        .expect("unc host regex must compile")
    })
}

/// A tenant id named in an explicit field. GUIDs in general are correlation
/// keys (app ids, deployment types) and must survive; only the field-anchored
/// tenant shape is an organization identifier.
fn tenant_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(
            r#"(?i)(?P<field>\b(?:AAD)?Tenant\s*Id\s*["']?\s*[:=]\s*)(?P<value>\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?)"#,
        )
        .expect("tenant field regex must compile")
    })
}

/// A Windows security identifier, anywhere in the text.
///
/// The `S-1-…` shape is unambiguous enough to mask without an anchor, and a
/// SID identifies a user or machine exactly as strongly as a UPN does.
///
/// Case-insensitive like every other rule in this file. Windows itself emits the
/// uppercase form, but third-party logs and JSON round-trips lowercase
/// identifiers, and a `s-1-5-21-…` exporting verbatim while the uppercase form
/// masked was an inconsistency nothing in the code or the docs intended.
fn sid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"(?i)\bS-1-\d+(?:-\d+){2,}").expect("sid regex must compile")
    })
}

/// Every Windows SID in `text`, as `(byte offset, matched text)`.
///
/// Public so anything needing to *find* SIDs — the fixture privacy scanner most
/// of all — asks this grammar instead of restating the shape. A detector that
/// re-implements what the masker matches will drift from it, and drift in a
/// safety net is invisible by construction: the check whose job is catching a
/// leak is the one place a mismatch goes unnoticed.
pub fn sid_occurrences(text: &str) -> Vec<(usize, &str)> {
    sid_re()
        .find_iter(text)
        .map(|found| (found.start(), found.as_str()))
        .collect()
}

/// Whether `kind:hash` is a well-formed token body — the one validity rule
/// [`starts_with_token`] and [`already_masked`] share.
fn is_token_body(body: &str) -> bool {
    let Some((kind, hash)) = body.split_once(':') else {
        return false;
    };
    !kind.is_empty()
        && kind.chars().all(|c| c.is_ascii_lowercase())
        && hash.len() == 16
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether a value *begins* with a well-formed replacement token.
///
/// The UPN rule runs before the field rules, so a field value routinely
/// arrives as an emitted token followed by more text. Re-hashing token-plus-
/// tail would destroy the stable token — breaking cross-record correlation —
/// so the token itself is preserved and only the tail is masked (see
/// [`split_leading_token`]). A malformed token-lookalike does not qualify and
/// is still masked rather than trusted.
fn starts_with_token(value: &str) -> bool {
    value
        .strip_prefix('[')
        .and_then(|rest| rest.find(']').map(|end| &rest[..end]))
        .is_some_and(is_token_body)
}

/// Whether a value is already a replacement token (optionally quoted), so
/// re-masking cannot hash a token and break idempotence.
fn already_masked(value: &str) -> bool {
    value
        .trim_matches(|c| c == '\x22' || c == '\'')
        .trim_end()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .is_some_and(is_token_body)
}

/// Split a value that begins with a well-formed token into the token and the
/// remainder.
///
/// The remainder is where the pre-existing trailing-identity leak lived: a
/// value like `[upn:…] (aka CONTOSO\jsmith.adm)` was returned verbatim to
/// protect the token, and the identity after it leaked. Callers preserve the
/// token and mask the non-empty remainder — deterministic over-masking of a
/// trailing fragment is safe where under-masking a second identity is not,
/// the same trade the `-Command` rule makes. A remainder that is itself a
/// token (a previous pass's tail mask) is left alone for idempotence.
fn split_leading_token(value: &str) -> Option<(&str, &str)> {
    let rest = value.strip_prefix('[')?;
    let end = rest.find(']')?;
    if !is_token_body(&rest[..end]) {
        return None;
    }
    // `end` indexes into `rest`, which starts one byte after the `[`, so the
    // closing bracket sits at `end + 1` in `value` and the split lands after it.
    Some(value.split_at(end + 2))
}

/// The preserved-token projection of a field value: keep the leading token,
/// mask a non-empty tail with `kind`, and leave an already-masked tail alone.
/// Returns `None` when the value does not begin with a well-formed token.
fn preserve_token_mask_tail(value: &str, kind: &str) -> Option<String> {
    let (token, rest) = split_leading_token(value)?;
    let rest_trimmed = rest.trim_start();
    if rest_trimmed.is_empty() || starts_with_token(rest_trimmed) || already_masked(rest_trimmed) {
        return Some(value.to_owned());
    }
    let lead = &rest[..rest.len() - rest_trimmed.len()];
    Some(format!("{token}{lead}{}", stable_token(kind, rest_trimmed)))
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
    if value.len() > MAX_REDACTION_INPUT_BYTES {
        return REMOVED_OVERSIZE.to_owned();
    }
    let masked = upn_re().replace_all(value, |caps: &regex::Captures<'_>| {
        stable_token("upn", &caps[0])
    });

    let masked = user_path_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is not part of the profile name; keeping it out
        // of the hashed value means `C:\Users\John Doe ` and `C:\Users\John Doe`
        // still resolve to the same user.
        let user = caps["user"].trim_end();
        let trailing = &caps["user"][user.len()..];
        format!(
            "{}{}{}",
            &caps["prefix"],
            stable_token("user", user),
            trailing
        )
    });

    let masked = tenant_field_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        format!("{}{}", &caps["field"], stable_token("tenant", &caps["value"]))
    });

    let masked = sensitive_field_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        format!(
            "{}{}",
            &caps["field"],
            redact_sensitive_field(&caps["value"])
        )
    });

    let masked = host_field_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let value = &caps["value"];
        let quote = value.chars().next().filter(|character| *character == '"' || *character == '\'');
        let inner = quote
            .and_then(|quote| value.strip_prefix(quote).and_then(|value| value.strip_suffix(quote)))
            .unwrap_or(value);
        if already_masked(inner) {
            return format!("{}{}", &caps["field"], value);
        }
        let projected = preserve_token_mask_tail(inner, "host")
            .unwrap_or_else(|| stable_token("host", inner));
        let projected = quote.map_or(projected.clone(), |quote| format!("{quote}{projected}{quote}"));
        format!("{}{}", &caps["field"], projected)
    });

    let masked = unc_host_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        format!("{}{}", &caps["prefix"], stable_token("host", &caps["host"]))
    });

    let masked = account_field_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is prose spacing, not part of the account name.
        let value = caps["value"].trim_end();
        let trailing = &caps["value"][value.len()..];
        if already_masked(value) {
            return format!("{}{}{}{}", &caps["pre"], &caps["field"], value, trailing);
        }
        if let Some(projected) = preserve_token_mask_tail(value, "account") {
            return format!("{}{}{}{}", &caps["pre"], &caps["field"], projected, trailing);
        }
        format!(
            "{}{}{}{}",
            &caps["pre"],
            &caps["field"],
            stable_token("account", value),
            trailing
        )
    });

    let masked = msi_property_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let value = &caps["value"];
        if already_masked(value) {
            return format!("{}{}", &caps["property"], value);
        }
        format!("{}{}", &caps["property"], stable_token("secret", value))
    });

    let masked = command_line_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let value = caps["value"].trim_end();
        // Already masked: re-masking would hash the token and break
        // idempotence.
        if already_masked(value) {
            return format!("{}{}", &caps["flag"], value);
        }
        format!("{}{}", &caps["flag"], stable_token("command", value))
    });

    let masked = sid_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            // Hashed from the uppercase form. A SID is case-insensitive, so the
            // two spellings name one identity and must reach one token; hashing
            // the text as written would hand an analyst two tokens for the same
            // account and break the correlation these tokens exist to provide.
            stable_token("sid", &caps[0].to_ascii_uppercase())
        })
        .into_owned();
    redact_entity_encoded_fields(&masked)
}
#[cfg(test)]
mod tests {
    use super::{redact_text, sid_occurrences};

    #[test]
    fn a_json_escaped_windows_path_is_masked() {
        // These logs embed JSON payloads; a path inside one is escaped.
        let redacted = redact_text(r#"{"Path":"C:\\Users\\John Doe\\AppData\\Local"}"#);
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
        assert!(redacted.contains(r"AppData"), "got {redacted:?}");
    }

    #[test]
    fn a_json_escaped_path_mask_is_idempotent() {
        let once = redact_text(r#"{"Path":"C:\\Users\\John Doe\\AppData"}"#);
        assert_eq!(once, redact_text(&once));
    }
    #[test]
    fn encoded_json_identity_and_credential_fields_are_masked_without_masking_prose() {
        let entity = redact_text(
            r#"&quot;Password&quot;:&quot;hunter2&quot; &quot;UserName&quot;:&quot;CONTOSO\John Doe&quot; &quot;Message&quot;:&quot;Password is required&quot;"#,
        );
        assert!(!entity.contains("hunter2"), "got {entity:?}");
        assert!(!entity.contains("John Doe"), "got {entity:?}");
        assert!(entity.contains("Password is required"), "got {entity:?}");

        let escaped =
            redact_text(r#"{\"Password\":\"hunter2\",\"UserName\":\"CONTOSO\\John Doe\",\"ComputerName\":\"DESKTOP-JOHN\"}"#);
        assert!(!escaped.contains("hunter2"), "got {escaped:?}");
        assert!(!escaped.contains("John Doe"), "got {escaped:?}");
        assert!(!escaped.contains("DESKTOP-JOHN"), "got {escaped:?}");
        assert_eq!(escaped, redact_text(&escaped));
    }

    #[test]
    fn credential_values_using_colon_or_equals_are_masked() {
        for text in [
            "app.exe -Password:hunter2",
            "app.exe -Password=hunter2",
            "app.exe -Token=abc123",
        ] {
            let redacted = redact_text(text);
            assert!(!redacted.contains("hunter2"), "{text} -> {redacted}");
            assert!(!redacted.contains("abc123"), "{text} -> {redacted}");
        }
    }

    #[test]
    fn a_single_separator_path_is_still_masked() {
        let redacted = redact_text(r"C:\Users\adele.vance\a.ps1");
        assert!(!redacted.contains("adele.vance"));
        assert!(redacted.ends_with(r"\a.ps1"));
    }

    #[test]
    fn a_slash_sigil_credential_flag_is_masked() {
        let redacted = redact_text("setup.exe /Password hunter2 /quiet");
        assert!(!redacted.contains("hunter2"), "got {redacted:?}");
    }

    #[test]
    fn an_msi_property_credential_without_a_sigil_is_masked() {
        for text in [
            "msiexec /i app.msi PASSWORD=hunter2 /qn",
            "msiexec /i app.msi LICENSEKEY=ABCD-1234-EFGH",
            "msiexec /i app.msi PWD=\"multi word secret\" /qn",
        ] {
            let redacted = redact_text(text);
            assert!(!redacted.contains("hunter2"), "{text} -> {redacted}");
            assert!(!redacted.contains("ABCD-1234"), "{text} -> {redacted}");
            assert!(!redacted.contains("multi word secret"), "{text} -> {redacted}");
        }
        // An ordinary property is not credential-shaped and stays visible.
        let benign = redact_text("msiexec /i app.msi INSTALLDIR=C:\\App /qn");
        assert!(benign.contains("INSTALLDIR=C:\\App"), "got {benign:?}");
    }

    #[test]
    fn an_account_field_value_containing_a_space_is_fully_masked() {
        let redacted = redact_text(r"RunAsUser = CONTOSO\John Doe, session 2");
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
        assert!(redacted.starts_with("RunAsUser = "));
        assert!(redacted.ends_with(", session 2"), "got {redacted:?}");
    }

    #[test]
    fn an_account_value_starting_with_a_token_keeps_the_token_and_masks_the_tail() {
        // The UPN rule runs first, so the account field's value begins with an
        // emitted token. Re-hashing token+tail together would destroy the
        // stable token (breaking cross-record correlation) — but returning
        // the whole value verbatim leaked whatever identity followed the
        // token. The token survives and the tail is masked.
        let once = redact_text(r"UserName: adele.vance@contoso.example (aka CONTOSO\jsmith.adm)");
        assert!(once.contains("[upn:"), "got {once:?}");
        assert!(
            !once.contains("jsmith"),
            "the trailing identity must be masked: {once:?}"
        );
        assert_eq!(once, redact_text(&once), "and it must stay idempotent");
    }

    #[test]
    fn a_bracketed_prose_account_value_is_not_hashed_whole() {
        // "[not signed in]" is prose, not a token; hashing it whole destroyed
        // an ordinary status message. The account rule must not fire on a
        // bracket-prefixed value unless it begins with a well-formed token.
        let text = "Account: [not signed in] - deferring enforcement";
        let redacted = redact_text(text);
        assert_eq!(redacted, text, "bracketed prose must survive verbatim");
        assert_eq!(redacted, redact_text(&redacted));
    }

    #[test]
    fn a_host_value_starting_with_a_token_masks_its_trailing_fragment() {
        let masked = redact_text("ComputerName: DESKTOP-AB12CD");
        let token_start = masked.find("[host:").expect("token");
        let token = &masked[token_start..token_start + "[host:0123456789abcdef]".len()];
        let with_tail = format!("{masked}.fragment");
        let redacted_tail = redact_text(&with_tail);
        assert!(
            redacted_tail.contains(token),
            "{token:?} must survive in {redacted_tail:?}"
        );
        assert!(
            !redacted_tail.contains(".fragment"),
            "the trailing fragment glued to a token is masked: {redacted_tail:?}"
        );
        assert_eq!(redacted_tail, redact_text(&redacted_tail));
    }

    #[test]
    fn a_host_value_starting_with_a_token_is_not_rehashed() {
        let masked = redact_text("ComputerName: DESKTOP-AB12CD");
        assert!(masked.contains("[host:"), "got {masked:?}");
        let twice = redact_text(&masked);
        assert_eq!(masked, twice);
        // A token with a trailing fragment must not be folded into a new hash:
        // the exact original token has to survive, tail and all.
        let token_start = masked.find("[host:").expect("token");
        let token = &masked[token_start..token_start + "[host:0123456789abcdef]".len()];
        let with_tail = format!("{masked}!");
        let redacted_tail = redact_text(&with_tail);
        assert!(
            redacted_tail.contains(token),
            "{token:?} must survive in {redacted_tail:?}"
        );
    }

    #[test]
    fn a_documents_and_settings_profile_path_is_masked() {
        let redacted = redact_text(r"C:\Documents and Settings\adele.vance\a.ps1");
        assert!(!redacted.contains("adele.vance"), "got {redacted:?}");
        assert!(redacted.ends_with(r"\a.ps1"), "got {redacted:?}");

        // The JSON-escaped form arrives with doubled separators, exactly like
        // the Users root.
        let escaped =
            redact_text(r#"{"Path":"C:\\Documents and Settings\\John Doe\\AppData"}"#);
        assert!(!escaped.contains("John"), "got {escaped:?}");
        assert!(!escaped.contains("Doe"), "got {escaped:?}");
        assert!(escaped.contains("AppData"), "got {escaped:?}");
    }

    #[test]
    fn a_lowercase_sid_masks_to_the_same_token_as_the_uppercase_form() {
        // Every other rule in this file is case-insensitive; this one was not, so a
        // lowercase identifier from a third-party log or a JSON round-trip exported
        // verbatim while the uppercase form masked.
        let upper = redact_text("owner S-1-5-21-397955417-626881126-188441444-1010 end");
        let lower = redact_text("owner s-1-5-21-397955417-626881126-188441444-1010 end");

        assert!(!lower.contains("397955417"), "got {lower:?}");
        // One identity, one token. Hashing the text as written would hand an analyst
        // two tokens for the same account.
        assert_eq!(upper, lower, "case must not change the masked result");
    }

    #[test]
    fn sid_occurrences_finds_what_the_masker_masks() {
        // The fixture privacy scanner uses this, so anything it fails to find is
        // material the masker would have hidden and the guard would have waved past.
        for text in [
            "S-1-5-21-397955417-626881126-188441444-1010",
            "s-1-5-21-397955417-626881126-188441444-1010",
            // A trailing separator: the re-implementation this replaced required the
            // candidate to end in a digit, so this passed the scan while the masker
            // masked it.
            "S-1-5-21-1-2-3-",
            "\"S-1-5-21-1-2-3\"",
        ] {
            assert!(
                !sid_occurrences(text).is_empty(),
                "the scanner must see {text:?}"
            );
            assert_ne!(redact_text(text), text, "the masker must mask {text:?}");
        }

        // Below the sub-authority threshold, both agree it identifies nobody.
        assert!(sid_occurrences("running as S-1-5-18").is_empty());
    }

    #[test]
    fn a_windows_sid_is_masked_anywhere() {
        let redacted = redact_text("Granting access to S-1-5-21-397955417-626881126-188441444-1010 done");
        assert!(!redacted.contains("397955417"), "got {redacted:?}");
        assert!(redacted.contains("done"));
        // Well-known machine SIDs with fewer sub-authorities identify nobody
        // and stay visible.
        assert!(redact_text("running as S-1-5-18").contains("S-1-5-18"));
    }

    #[test]
    fn a_device_name_field_and_a_unc_host_are_masked() {
        let field = redact_text("ComputerName: DESKTOP-AB12CD");
        assert!(!field.contains("DESKTOP-AB12CD"), "got {field:?}");

        let unc = redact_text(r"copying from \\FILESRV01\share\pkg.msi");
        assert!(!unc.contains("FILESRV01"), "got {unc:?}");
        assert!(unc.contains(r"\share\pkg.msi"), "got {unc:?}");

        let escaped = redact_text(r#"{"source":"\\\\FILESRV01\\share"}"#);
        assert!(!escaped.contains("FILESRV01"), "got {escaped:?}");
    }

    #[test]
    fn a_drive_rooted_path_is_not_mistaken_for_a_unc_host() {
        let redacted = redact_text(r#"{"Path":"C:\\ProgramData\\App"}"#);
        assert!(redacted.contains("ProgramData"), "got {redacted:?}");
    }

    #[test]
    fn a_tenant_id_field_is_masked_but_bare_guids_survive() {
        let app = "11111111-2222-4333-8444-555555555555";
        let tenant = "99999999-8888-4777-8666-555555555555";
        let redacted = redact_text(&format!(
            "TenantId: {tenant} processing app with id: {app}"
        ));
        assert!(!redacted.contains(tenant), "got {redacted:?}");
        assert!(
            redacted.contains(app),
            "correlation keys must survive: {redacted:?}"
        );
    }

    // ── Grammar tests moved from `win32::redaction` ─────────────────────────
    // That module owns only the projection; the grammar and its regression
    // pins live here with their owner so a grammar change fails in one place.

    #[test]
    fn upn_is_masked_deterministically() {
        let first = redact_text("Enforcing for adele.vance@contoso.example");
        let second = redact_text("Reported for adele.vance@contoso.example");
        assert!(!first.contains("adele.vance"));
        let token = first.split_whitespace().last().expect("token");
        assert!(second.contains(token), "same UPN must yield the same token");
    }

    #[test]
    fn different_users_get_different_tokens() {
        assert_ne!(
            redact_text("adele.vance@contoso.example"),
            redact_text("alex.wilber@contoso.example")
        );
    }

    #[test]
    fn user_profile_segment_is_masked_but_the_path_shape_survives() {
        let redacted = redact_text(r"C:\Users\adele.vance\AppData\Local\Temp\setup.log");
        assert!(!redacted.contains("adele.vance"));
        assert!(redacted.starts_with(r"C:\Users\"));
        assert!(redacted.ends_with(r"\AppData\Local\Temp\setup.log"));
    }

    #[test]
    fn a_profile_name_containing_a_space_is_fully_masked() {
        let redacted = redact_text(r"C:\Users\John Doe\AppData\Local\Temp\setup.log");
        assert!(!redacted.contains("John"), "got {redacted:?}");
        assert!(!redacted.contains("Doe"), "got {redacted:?}");
    }

    #[test]
    fn an_account_field_is_masked_even_without_an_at_sign() {
        let redacted = redact_text(r"RunAsUser = CONTOSO\jsmith");
        assert!(!redacted.contains("jsmith"), "got {redacted:?}");
        assert!(redacted.starts_with("RunAsUser = "));
    }

    #[test]
    fn inline_credential_values_are_masked_for_every_flag_shape() {
        for (flag, secret) in [
            ("-Password", "hunter2"),
            ("/Password", "hunter2"),
            ("-ApiKey", "abc123def"),
            ("-ClientSecret", "s3cr3tvalue"),
        ] {
            let redacted = redact_text(&format!("setup.exe {flag} {secret} /quiet"));
            assert!(
                !redacted.contains(secret),
                "{flag} leaked its value: {redacted:?}"
            );
        }
    }

    #[test]
    fn a_secret_inside_a_multiline_record_is_still_masked() {
        let record = "Install command line: setup.exe -Password hunter2\nAt line:1 char:1";
        let redacted = redact_text(record);
        assert!(!redacted.contains("hunter2"), "got {redacted:?}");
        assert!(redacted.contains("At line:1 char:1"));
    }

    #[test]
    fn correlation_keys_survive_redaction() {
        let app = "11111111-2222-4333-8444-555555555555";
        let redacted = redact_text(&format!(
            "Installation is done for app with id: {app}, exit code: 1603"
        ));
        assert!(redacted.contains(app), "correlation keys must not be lost");
        assert!(redacted.contains("1603"));
    }

    #[test]
    fn malformed_mask_tokens_are_not_treated_as_already_masked() {
        let redacted = redact_text("setup.exe -Command \"[command:0123456789abcdef] /quiet]\"");
        assert!(!redacted.contains("/quiet"));
        let redacted = redact_text("RunAsUser = [account:0123456789abcdef0]");
        assert!(!redacted.contains("0123456789abcdef0"));
    }

    #[test]
    fn a_malformed_token_lookalike_is_masked_not_trusted() {
        // The account regex accepts any `[Kind:hex…]` shape so the closure can
        // decide; `is_token_body` then requires a lowercase kind and exactly
        // 16 hex digits. This pins the gap between the two: a lookalike that
        // fails the validator is hashed whole, never preserved as a token.
        //
        // Wrong hash length: 17 hex digits, not 16.
        let redacted = redact_text("RunAsUser = [account:0123456789abcdef0]");
        assert!(!redacted.contains("0123456789abcdef0"), "got {redacted:?}");
        // Uppercase kind: `stable_token` never emits one.
        let redacted = redact_text("RunAsUser = [ACCOUNT:0123456789abcdef]");
        assert!(
            !redacted.contains("ACCOUNT:0123456789abcdef"),
            "got {redacted:?}"
        );
        assert_eq!(redacted, redact_text(&redacted), "and it stays idempotent");
    }

    #[test]
    fn labeled_serial_hardware_and_tenant_values_are_masked() {
        let redacted = redact_text(
            r#"serialNumber: ABC123456 hardwareHash=AA-BB-CC tenantId={99999999-8888-4777-8666-555555555555}"#,
        );
        assert!(!redacted.contains("ABC123456"), "got {redacted:?}");
        assert!(!redacted.contains("AA-BB-CC"), "got {redacted:?}");
        assert!(!redacted.contains("99999999-8888"), "got {redacted:?}");
    }

    #[test]
    fn oversized_text_is_replaced_instead_of_partially_exported() {
        let input = format!("prefix {}", "secret-user@example.com ".repeat(20_000));
        let redacted = redact_text(&input);
        assert!(redacted.contains("[redacted: oversized text omitted]"));
        assert!(!redacted.contains("secret-user@example.com"));
    }

    #[test]
    fn the_extended_projection_is_idempotent() {
        let once = redact_text(
            r"ComputerName: DESKTOP-AB12CD RunAsUser = CONTOSO\John Doe, S-1-5-21-397955417-626881126-188441444-1010 ran msiexec PASSWORD=hunter2 from \\FILESRV01\share for adele.vance@contoso.example TenantId: 99999999-8888-4777-8666-555555555555",
        );
        assert_eq!(once, redact_text(&once));
    }

    #[test]
    fn labeled_multiword_identity_fields_mask_the_entire_value() {
        let redacted = redact_text(
            r"TargetUserName=CONTOSO\Jane Doe, SubjectUserName=CONTOSO\Alice Smith, SubjectDomainName=CONTOSO",
        );
        assert!(!redacted.contains("Jane"));
        assert!(!redacted.contains("Doe"));
        assert!(!redacted.contains("Alice"));
        assert!(!redacted.contains("Smith"));
        assert!(!redacted.contains("CONTOSO"));
    }

    #[test]
    fn quoted_json_field_names_are_redacted() {
        let redacted = redact_text(
            r#"{"serialNumber":"ABC123456","tenantId":"99999999-8888-4777-8666-555555555555","TargetUserName":"CONTOSO\Jane Doe"}"#,
        );
        assert!(!redacted.contains("ABC123456"));
        assert!(!redacted.contains("99999999-8888"));
        assert!(!redacted.contains("Jane Doe"));
        assert!(!redacted.contains("CONTOSO"));
    }

    #[test]
    fn credential_labels_and_quoted_computer_values_are_redacted() {
        let redacted = redact_text(
            r#"ApiSecret=hunter2 AccessToken=abc123 Credential=topsecret {"Computer":"DESKTOP-JOHN"}"#,
        );
        assert!(!redacted.contains("hunter2"));
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("topsecret"));
        assert!(!redacted.contains("DESKTOP-JOHN"));
    }
}

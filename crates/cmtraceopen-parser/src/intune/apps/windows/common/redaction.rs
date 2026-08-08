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
            r"(?P<property>\b(?i:PASSWORD|PWD|PASSPHRASE|LICENSEKEY|LICENSE_KEY|PRODUCTKEY|PRODUCT_KEY|SERIALKEY|SERIAL|APIKEY|API_KEY|TOKEN|SECRET|CLIENTSECRET|CLIENT_SECRET)=)(?P<value>\x22[^\x22\r\n]*\x22|'[^'\r\n]*'|[^\s\r\n]+)",
        )
        .expect("msi property regex must compile")
    })
}

/// An account named in an explicit field.
///
/// `RunAsUser = CONTOSO\jsmith` carries an identity that neither the UPN rule
/// nor the path rule matches. The value is bounded by a delimiter, a quote, or
/// the end of the line — the same shape as the path rule — never by
/// whitespace: Windows account display forms contain spaces
/// (`CONTOSO\John Doe`), and bounding on whitespace exported the second half
/// of the name verbatim. The leading `[` exclusion keeps the projection
/// idempotent.
fn account_field_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        // The `pre` guard stops the field vocabulary matching *inside* an
        // existing replacement token: `[upn:…]` and `[account:…]` contain the
        // words `upn`/`account` followed by `:`, and without the guard a second
        // pass re-masked the token itself. The value's first character excludes
        // whitespace only; a value *beginning* with an emitted token — the UPN
        // rule runs first, so `UserName: [upn:…] is retrying` is routine — is
        // preserved by the `starts_with_token` guard in the closure, which
        // still lets a malformed token-lookalike be masked rather than
        // trusted.
        Regex::new(
            r"(?i)(?P<pre>^|[^\[])(?P<field>\b(?:RunAsUser|RunAsAccount|UserName|UserPrincipalName|LoggedOnUser|Account|UserId|Upn)\s*[:=]\s*)(?P<value>[^\s,;\r\n\x22][^,;\r\n\x22]*)",
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
        // A value that begins with an emitted token (with or without a
        // trailing fragment) must not be re-hashed, or the stable `[host:…]`
        // token is destroyed on the second pass; the `starts_with_token`
        // guard in the closure preserves it while a malformed token-lookalike
        // is still masked rather than trusted.
        Regex::new(
            r"(?i)(?P<field>\b(?:ComputerName|MachineName|HostName|DeviceName)\s*[:=]\s*)(?P<value>[^\s,;\r\n\x22]+)",
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
            r"(?i)(?P<field>\b(?:AAD)?Tenant\s*Id\s*[:=]\s*)(?P<value>\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?)",
        )
        .expect("tenant field regex must compile")
    })
}

/// A Windows security identifier, anywhere in the text.
///
/// The `S-1-…` shape is unambiguous enough to mask without an anchor, and a
/// SID identifies a user or machine exactly as strongly as a UPN does.
fn sid_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"\bS-1-\d+(?:-\d+){2,}").expect("sid regex must compile")
    })
}

/// Whether a value *begins* with a well-formed replacement token.
///
/// The UPN rule runs before the field rules, so a field value routinely
/// arrives as an emitted token followed by prose (`[upn:…] is retrying`).
/// Re-hashing token-plus-prose would destroy the stable token — breaking
/// cross-record correlation — and swallow the prose with it, so such values
/// are preserved whole. A malformed token-lookalike does not qualify and is
/// still masked rather than trusted.
fn starts_with_token(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('[') else {
        return false;
    };
    let Some(end) = rest.find(']') else {
        return false;
    };
    let Some((kind, hash)) = rest[..end].split_once(':') else {
        return false;
    };
    !kind.is_empty()
        && kind.chars().all(|c| c.is_ascii_lowercase())
        && hash.len() == 16
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether a value is already a replacement token (optionally quoted), so
/// re-masking cannot hash a token and break idempotence.
fn already_masked(value: &str) -> bool {
    let inner = value
        .trim_matches(|c| c == '\x22' || c == '\'')
        .trim_end();
    let Some(rest) = inner.strip_prefix('[') else {
        return false;
    };
    let Some((kind, hash)) = rest.strip_suffix(']').and_then(|body| body.split_once(':')) else {
        return false;
    };
    !kind.is_empty()
        && kind.chars().all(|c| c.is_ascii_lowercase())
        && hash.len() == 16
        && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Mask the sensitive spans inside a free-text value.
pub fn redact_text(value: &str) -> String {
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

    let masked = host_field_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        let value = &caps["value"];
        if already_masked(value) || starts_with_token(value) {
            return format!("{}{}", &caps["field"], value);
        }
        format!("{}{}", &caps["field"], stable_token("host", value))
    });

    let masked = unc_host_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        format!("{}{}", &caps["prefix"], stable_token("host", &caps["host"]))
    });

    let masked = account_field_re().replace_all(&masked, |caps: &regex::Captures<'_>| {
        // Trailing whitespace is prose spacing, not part of the account name.
        let value = caps["value"].trim_end();
        let trailing = &caps["value"][value.len()..];
        if already_masked(value) || starts_with_token(value) {
            return format!("{}{}{}{}", &caps["pre"], &caps["field"], value, trailing);
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

    sid_re()
        .replace_all(&masked, |caps: &regex::Captures<'_>| {
            stable_token("sid", &caps[0])
        })
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::redact_text;

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
    fn an_account_value_starting_with_a_token_keeps_the_token_and_the_prose() {
        // The UPN rule runs first, so the account field's value begins with an
        // emitted token followed by prose. Re-hashing token+prose together
        // would destroy the stable token (breaking cross-record correlation)
        // and swallow the prose.
        let once = redact_text("UserName: adele.vance@contoso.example is retrying");
        assert!(once.contains("[upn:"), "got {once:?}");
        assert!(once.ends_with(" is retrying"), "got {once:?}");
        assert_eq!(once, redact_text(&once), "and it must stay idempotent");
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

    #[test]
    fn the_extended_projection_is_idempotent() {
        let once = redact_text(
            r"ComputerName: DESKTOP-AB12CD RunAsUser = CONTOSO\John Doe, S-1-5-21-397955417-626881126-188441444-1010 ran msiexec PASSWORD=hunter2 from \\FILESRV01\share for adele.vance@contoso.example TenantId: 99999999-8888-4777-8666-555555555555",
        );
        assert_eq!(once, redact_text(&once));
    }
}

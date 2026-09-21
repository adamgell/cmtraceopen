//! Native acceptance for the dsregcmd shareable-bundle hand-off (issue #628).
//!
//! This drives the *real* commands on a live Windows host: `capture_dsregcmd`
//! shells out to `dsregcmd.exe /status` and stages a capture bundle, and
//! `export_dsregcmd_shareable_bundle` projects it. Nothing here is synthetic, so
//! it is excluded from the ordinary test run and invoked explicitly:
//!
//! ```text
//! cargo test --locked \
//!   -p cmtrace-open \
//!   --test dsregcmd_shareable_bundle_native_acceptance \
//!   -- --ignored --nocapture
//! ```
//!
//! It is `#[ignore]`d rather than `#[cfg]`d out because a skipped acceptance is
//! indistinguishable from a passing one. Invoked explicitly it takes a live
//! capture or fails: a host with no `dsregcmd.exe`, or a capture that does not
//! analyze, is an error rather than a silent pass.
//!
//! ## What it prints
//!
//! Counts, hashes and booleans only. The values it counts — the on-premises
//! domain, any tenant id, the device id, the thumbprint and the user identity —
//! are never printed, so the output can be attached to a pull request. Where a
//! value has to be reported it is reported as a SHA-256 prefix.
//!
//! ## Definitions
//!
//! Occurrences are counted in **decoded semantic values**, not in serialized
//! bytes: a JSON artifact is parsed and each string value counted, so an escaped
//! `\\t` or `\\u0009` cannot hide a domain from the count or inflate it. The
//! domain-qualified account occurrence is the `DOMAIN\account` pair, which is the
//! shape a real event log carries in its message text.

#![cfg(all(feature = "dsregcmd", target_os = "windows"))]

use app_lib::commands::dsregcmd::{capture_dsregcmd, export_dsregcmd_shareable_bundle};
use cmtraceopen_parser::dsregcmd::{analyze_text_with_evidence, DsregcmdBundleEvidence};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// A short, non-reversible label for a value the report may mention.
fn digest(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let finished = hasher.finalize();
    finished[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Decode an artifact the way the lane's reader does: UTF-16LE when it is
/// marked as such, UTF-8 otherwise.
fn decode(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

/// Every text artifact under `root`, as (bundle-relative path, decoded text).
fn read_artifacts(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                if let Ok(bytes) = fs::read(&path) {
                    let relative = path
                        .strip_prefix(root)
                        .map(|value| value.to_string_lossy().replace('\\', "/"))
                        .unwrap_or_default();
                    files.push((relative, decode(&bytes)));
                }
            }
        }
    }
    files.sort();
    files
}

fn is_json(relative_path: &str) -> bool {
    relative_path
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case("json"))
}

/// The values a reader of this artifact would see, with JSON decoded.
///
/// A JSON artifact that no longer parses yields its raw text and a marker, so
/// the caller can assert validity separately rather than silently counting
/// bytes.
fn decoded_values(relative_path: &str, text: &str) -> (Vec<String>, bool) {
    if !is_json(relative_path) {
        return (vec![text.to_string()], true);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return (vec![text.to_string()], false);
    };

    fn collect(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::String(text) => out.push(text.clone()),
            serde_json::Value::Array(items) => items.iter().for_each(|item| collect(item, out)),
            serde_json::Value::Object(members) => {
                members.values().for_each(|member| collect(member, out))
            }
            serde_json::Value::Number(_) | serde_json::Value::Bool(_) | serde_json::Value::Null => {
            }
        }
    }

    let mut values = Vec::new();
    collect(&value, &mut values);
    (values, true)
}

fn occurrences(haystack: &str, needle: &str) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack.matches(needle).count()
}

/// The label/value pairs a live capture reports for the identity classes this
/// hand-off masks, keeping only the ones this host actually carries.
fn captured_identity_values(status: &str) -> Vec<(String, String)> {
    const LABELS: &[&str] = &[
        "TenantId",
        "TenantName",
        "DomainName",
        "DeviceId",
        "Thumbprint",
        "User Identity",
        "MdmUrl",
        "AzureAdPrtAuthority",
    ];

    let mut found = Vec::new();
    for line in status.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let label = label.trim();
        let value = value.trim();
        if value.len() >= 4
            && LABELS.contains(&label)
            && !found.iter().any(|(seen, _)| seen == label)
        {
            found.push((label.to_string(), value.to_string()));
        }
    }
    found
}

/// The status text a bundle carries, which is what re-opening it analyzes.
fn status_text(artifacts: &[(String, String)]) -> Option<String> {
    artifacts
        .iter()
        .find(|(path, _)| path.ends_with("command-output/dsregcmd-status.txt"))
        .or_else(|| {
            artifacts
                .iter()
                .find(|(path, _)| path.ends_with("dsregcmd-status.txt"))
        })
        .map(|(_, text)| text.clone())
}

fn diagnostic_ids(text: &str) -> Vec<String> {
    analyze_text_with_evidence(text, DsregcmdBundleEvidence::default())
        .expect("the capture analyzes")
        .diagnostics
        .iter()
        .map(|issue| issue.id.clone())
        .collect()
}

#[test]
#[ignore = "requires a live Windows dsregcmd capture"]
fn dsregcmd_shareable_bundle_native_acceptance() {
    // A capture is the prerequisite. Failing here rather than returning is what
    // makes an explicitly invoked acceptance report a result.
    let capture = tauri::async_runtime::block_on(capture_dsregcmd())
        .expect("the live dsregcmd capture must succeed for this acceptance to run");
    let bundle_path = capture
        .bundle_path
        .clone()
        .expect("a successful capture stages a bundle");

    let raw_artifacts = read_artifacts(Path::new(&bundle_path));
    println!("RAW_FILE_COUNT={}", raw_artifacts.len());

    let identity = captured_identity_values(&capture.input);
    println!("HOST_IDENTITY_CLASSES_PRESENT={}", identity.len());
    for (label, value) in &identity {
        println!("HOST_CLASS {label} digest={}", digest(value));
    }

    // The on-premises domain is the class a domain-joined-only host carries and
    // the class the escaped-JSON defect reached.
    let domains: Vec<&String> = identity
        .iter()
        .filter(|(label, _)| label == "DomainName" || label == "TenantName")
        .map(|(_, value)| value)
        .collect();
    for domain in &domains {
        println!("DOMAIN digest={}", digest(domain));
    }

    // Count in decoded values on both sides, so the comparison is like for like.
    let raw_values: Vec<String> = raw_artifacts
        .iter()
        .flat_map(|(path, text)| decoded_values(path, text).0)
        .collect();
    let raw_joined = raw_values.join("\n");

    let dest = tempfile::tempdir().expect("a temporary destination");
    let projected = tauri::async_runtime::block_on(export_dsregcmd_shareable_bundle(
        bundle_path.clone(),
        dest.path().to_string_lossy().to_string(),
    ))
    .expect("the shareable export must succeed");
    println!("PROJECTED_FILE_COUNT={}", projected.artifact_count);

    let proj_artifacts = read_artifacts(Path::new(&projected.bundle_path));
    let proj_joined = proj_artifacts
        .iter()
        .flat_map(|(path, text)| decoded_values(path, text).0)
        .collect::<Vec<_>>()
        .join("\n");

    // 1. The domain itself, and the domain-qualified account form it appears in.
    let mut raw_domain_hits = 0usize;
    let mut proj_domain_hits = 0usize;
    let mut raw_pair_hits = 0usize;
    let mut proj_pair_hits = 0usize;
    for domain in &domains {
        raw_domain_hits += occurrences(&raw_joined, domain);
        proj_domain_hits += occurrences(&proj_joined, domain);
        let qualified = format!("{domain}\\");
        raw_pair_hits += occurrences(&raw_joined, &qualified);
        proj_pair_hits += occurrences(&proj_joined, &qualified);
    }
    println!("RAW_DOMAIN_OCCURRENCES={raw_domain_hits}");
    println!("PROJECTED_DOMAIN_OCCURRENCES={proj_domain_hits}");
    println!("RAW_DOMAIN_QUALIFIED_ACCOUNT_OCCURRENCES={raw_pair_hits}");
    println!("PROJECTED_DOMAIN_QUALIFIED_ACCOUNT_OCCURRENCES={proj_pair_hits}");

    // 2. The token that replaced them. Counting the token that stands where the
    // domain stood is what ties the two numbers together.
    let tenant_tokens = proj_joined.matches("[tenant:").count();
    println!("PROJECTED_TENANT_TOKENS={tenant_tokens}");
    let account_tokens = proj_joined.matches("[account:").count();
    println!("PROJECTED_ACCOUNT_TOKENS={account_tokens}");

    // The same comparison, scoped to the one artifact that carried the defect.
    // Aggregate counts cannot show that the token stands where the occurrence
    // stood, so both numbers here are read from that single file.
    let mut log_raw_domain = 0usize;
    let mut log_raw_pairs = 0usize;
    let mut log_proj_domain = 0usize;
    let mut log_tokens = 0usize;
    if let Some((path, raw_text)) = raw_artifacts
        .iter()
        .find(|(path, _)| path.ends_with("dsregcmd-events.json"))
    {
        println!("EVENT_LOG_ARTIFACT={path}");
        let raw_decoded = decoded_values(path, raw_text).0.join("\n");
        for domain in &domains {
            log_raw_domain += occurrences(&raw_decoded, domain);
            log_raw_pairs += occurrences(&raw_decoded, &format!("{domain}\\"));
        }
        if let Some((_, proj_text)) = proj_artifacts.iter().find(|(p, _)| p == path) {
            let proj_decoded = decoded_values(path, proj_text).0.join("\n");
            log_proj_domain = domains
                .iter()
                .map(|domain| occurrences(&proj_decoded, domain))
                .sum();
            log_tokens = proj_decoded.matches("[tenant:").count();
        }
        println!("EVENT_LOG_RAW_DOMAIN_OCCURRENCES={log_raw_domain}");
        println!("EVENT_LOG_RAW_DOMAIN_QUALIFIED_ACCOUNT_OCCURRENCES={log_raw_pairs}");
        println!("EVENT_LOG_PROJECTED_DOMAIN_OCCURRENCES={log_proj_domain}");
        println!("EVENT_LOG_PROJECTED_TENANT_TOKENS={log_tokens}");
    }

    // 3. Every projected JSON artifact is still valid JSON.
    let invalid_json: Vec<&String> = proj_artifacts
        .iter()
        .filter(|(path, text)| is_json(path) && !decoded_values(path, text).1)
        .map(|(path, _)| path)
        .collect();
    println!("PROJECTED_JSON_INVALID_COUNT={}", invalid_json.len());

    // 4. No artifact was dropped, and the UTF-16LE registry evidence survived.
    let raw_paths: Vec<&String> = raw_artifacts.iter().map(|(path, _)| path).collect();
    let proj_paths: Vec<&String> = proj_artifacts.iter().map(|(path, _)| path).collect();
    let missing: Vec<&&String> = raw_paths
        .iter()
        .filter(|path| !proj_paths.contains(path))
        .collect();
    println!("DROPPED_ARTIFACT_COUNT={}", missing.len());
    let registry_files = proj_artifacts
        .iter()
        .filter(|(path, _)| path.starts_with("evidence/registry/"))
        .count();
    println!("PROJECTED_REGISTRY_FILE_COUNT={registry_files}");

    // 5. The oversize marker must be absent: it is what a refused projection
    // leaves behind, and a refused projection is a silent leak.
    println!(
        "OVERSIZE_MARKER_PRESENT={}",
        proj_joined.contains("oversized text omitted")
    );

    // 6. The bundle still reopens and reaches the same verdicts.
    let raw_status = status_text(&raw_artifacts).expect("the raw bundle carries the capture");
    let proj_status =
        status_text(&proj_artifacts).expect("the projected bundle carries the capture");
    let raw_findings = diagnostic_ids(&raw_status);
    let proj_findings = diagnostic_ids(&proj_status);
    println!("RAW_FINDING_COUNT={}", raw_findings.len());
    println!("PROJECTED_FINDING_COUNT={}", proj_findings.len());
    println!("FINDINGS_IDENTICAL={}", raw_findings == proj_findings);

    // 7. The working path this run used must not travel in the projection.
    let working_root = std::env::temp_dir().to_string_lossy().to_string();
    println!(
        "PROJECTED_WORKING_PATH_OCCURRENCES={}",
        occurrences(&proj_joined, working_root.trim_end_matches(['\\', '/']))
    );

    // The acceptance baseline, asserted rather than only reported.
    if !domains.is_empty() {
        assert!(
            raw_pair_hits > 0,
            "this host carries no domain-qualified account occurrence, so the escaped-JSON \
             defect is not observable here and this acceptance proves nothing"
        );
        assert_eq!(
            proj_pair_hits, 0,
            "a domain-qualified account occurrence survived the hand-off"
        );
        assert_eq!(
            proj_domain_hits, 0,
            "the on-premises domain survived the hand-off"
        );
        assert!(
            tenant_tokens + account_tokens > 0,
            "the removed occurrences reached no token, so they were dropped rather than masked"
        );
        assert_eq!(
            log_proj_domain, 0,
            "the event-log artifact still carries the on-premises domain"
        );
        assert!(log_raw_pairs > 0, "the defect specimen left this artifact");
        assert!(
            log_tokens >= log_raw_pairs,
            "the event-log artifact lost domain-qualified occurrences without a typed token \
             standing in their place"
        );
    }
    assert!(
        invalid_json.is_empty(),
        "a projected JSON artifact is invalid"
    );
    assert!(missing.is_empty(), "the hand-off dropped an artifact");
    assert!(
        registry_files > 0,
        "the projected bundle lost its registry evidence"
    );
    assert!(
        !proj_joined.contains("oversized text omitted"),
        "the projection refused an artifact and left its content in place"
    );
    assert_eq!(
        raw_findings, proj_findings,
        "the projected bundle reaches different verdicts than the raw one"
    );
}

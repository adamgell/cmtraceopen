//! Deterministic installer/process correlation for ESP diagnostics.
//!
//! Correlation is intentionally evidence-first. Exact identifiers and canonical
//! log paths always take precedence over time, contradictory exact identifiers
//! remain ambiguous, and PID ancestry is guarded by process start time so PID
//! reuse cannot manufacture a parent chain.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};

use super::models::{
    EspCorrelationConfidence, EspDeploymentLogObservation, EspEvidenceRef, EspImeObservation,
    EspInstallerCorrelation, EspProcessObservation, EspTimestamp, EspWorkload,
};
use super::normalize::extract_guid;

const TEMPORAL_SLOP: Duration = Duration::minutes(5);
const MAX_PARENT_CHAIN_DEPTH: usize = 16;

/// Extracts an MSI-style `/L`, `/L*V`, or generic `/log` target without
/// executing or expanding the command line.
pub fn extract_installer_log_path(command_line: &str) -> Option<String> {
    let arguments = split_windows_arguments(command_line);
    let mut index = 0;
    while index < arguments.len() {
        if let Some(attached) = parse_log_switch(&arguments[index]) {
            if let Some(path) = attached {
                return nonempty_path(path);
            }
            return arguments.get(index + 1).cloned().and_then(nonempty_path);
        }
        index += 1;
    }
    None
}

/// Produces a platform-neutral canonical comparison key for a Windows log
/// path. This performs lexical normalization only and never touches the host
/// filesystem.
pub fn canonical_installer_log_path(path: &str) -> Option<String> {
    let mut value = path.trim().trim_matches(['"', '\'']).replace('/', "\\");
    if value.is_empty() || value.contains('\0') {
        return None;
    }
    if value
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        value = format!(r"\\{}", &value[8..]);
    } else if value
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\"))
    {
        value.drain(..4);
    } else if value.starts_with(r"\\.\") {
        return None;
    }

    let is_unc = value.starts_with(r"\\");
    let is_drive_absolute = value
        .as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':');
    let minimum_depth = if is_unc {
        2
    } else if is_drive_absolute {
        1
    } else {
        0
    };
    let mut parts = Vec::new();
    for component in value.split('\\') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            if parts.len() <= minimum_depth {
                return None;
            }
            parts.pop();
            continue;
        }
        let component = component.trim_end_matches([' ', '.']);
        if component.is_empty() {
            return None;
        }
        parts.push(component.to_ascii_lowercase());
    }
    if parts.is_empty() {
        return None;
    }

    let joined = parts.join("\\");
    Some(if is_unc {
        format!(r"\\{joined}")
    } else {
        joined
    })
}

/// Correlates live installer processes to ESP workloads using the fixed
/// precedence contract. The output is deterministic for identical ordered
/// input and carries every process/workload/source reference used.
pub fn correlate_installer_processes(
    workloads: &[EspWorkload],
    processes: &[EspProcessObservation],
    deployment_logs: &[EspDeploymentLogObservation],
    ime_logs: &[EspImeObservation],
) -> Vec<EspInstallerCorrelation> {
    let workload_identifiers = workloads
        .iter()
        .filter(|workload| is_installer_workload(workload))
        .map(|workload| {
            (
                workload.workload_id.as_str(),
                normalized_identifiers(&workload.raw_identifier),
            )
        })
        .collect::<Vec<_>>();

    let mut roots = processes
        .iter()
        .filter(|process| is_installer_root(process))
        .collect::<Vec<_>>();
    roots.sort_by_key(|process| process_identity_key(process));

    roots
        .into_iter()
        .map(|root| {
            correlate_one(
                root,
                workloads,
                &workload_identifiers,
                processes,
                deployment_logs,
                ime_logs,
            )
        })
        .collect()
}

fn correlate_one(
    root: &EspProcessObservation,
    workloads: &[EspWorkload],
    workload_identifiers: &[(&str, BTreeSet<String>)],
    processes: &[EspProcessObservation],
    deployment_logs: &[EspDeploymentLogObservation],
    ime_logs: &[EspImeObservation],
) -> EspInstallerCorrelation {
    let lineage = process_lineage(root, processes);
    let mut evidence = lineage
        .iter()
        .map(|process| process.context.evidence_ref.clone())
        .collect::<Vec<_>>();
    let mut signals: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    let mut exact_identifier_present = false;

    for (index, process) in lineage.iter().enumerate() {
        if let Some(app_id) = process.app_id.as_deref() {
            exact_identifier_present = true;
            add_identifier_signal(
                if index == 0 { "appId" } else { "parentAppId" },
                app_id,
                workload_identifiers,
                &mut signals,
            );
        }
        if let Some(product_code) = process.product_code.as_deref() {
            exact_identifier_present = true;
            add_identifier_signal(
                if index == 0 {
                    "productCode"
                } else {
                    "parentProductCode"
                },
                product_code,
                workload_identifiers,
                &mut signals,
            );
        }
    }

    let process_log_path = root
        .referenced_log_path
        .as_deref()
        .and_then(canonical_installer_log_path)
        .or_else(|| {
            root.sanitized_command_line
                .as_deref()
                .and_then(extract_installer_log_path)
                .as_deref()
                .and_then(canonical_installer_log_path)
        });
    if let Some(process_log_path) = process_log_path.as_deref() {
        for deployment in deployment_logs {
            let Some(deployment_path) = deployment
                .log_path
                .as_deref()
                .and_then(canonical_installer_log_path)
            else {
                continue;
            };
            if deployment_path != process_log_path {
                continue;
            }
            evidence.push(deployment.context.evidence_ref.clone());
            if let Some(product_code) = deployment.product_code.as_deref() {
                exact_identifier_present = true;
                add_identifier_signal(
                    "canonicalLogPath",
                    product_code,
                    workload_identifiers,
                    &mut signals,
                );
            }
        }
    }

    let lineage_pids = lineage
        .iter()
        .map(|process| process.pid)
        .collect::<Vec<_>>();
    for ime in ime_logs {
        let Some(app_id) = ime.app_id.as_deref() else {
            continue;
        };
        if !lineage_pids
            .iter()
            .any(|pid| message_mentions_pid(&ime.message, *pid))
        {
            continue;
        }
        exact_identifier_present = true;
        evidence.push(ime.context.evidence_ref.clone());
        add_identifier_signal(
            "imeProcessAppId",
            app_id,
            workload_identifiers,
            &mut signals,
        );
    }

    let nonempty_signal_sets = signals
        .iter()
        .filter(|(_, candidates)| !candidates.is_empty())
        .collect::<Vec<_>>();
    let exact_candidates = nonempty_signal_sets
        .iter()
        .flat_map(|(_, candidates)| candidates.iter().cloned())
        .collect::<BTreeSet<_>>();
    let signal_conflict = nonempty_signal_sets.iter().any(|(_, left)| {
        nonempty_signal_sets
            .iter()
            .any(|(_, right)| left.is_disjoint(right))
    });

    let (workload_id, confidence, reason, candidates) = if signal_conflict {
        (
            None,
            EspCorrelationConfidence::Uncorrelated,
            "contradictoryExactIdentifiers".to_string(),
            exact_candidates,
        )
    } else if exact_candidates.len() == 1 {
        let workload_id = exact_candidates.iter().next().cloned();
        let reason = signals
            .iter()
            .filter(|(_, candidates)| {
                workload_id
                    .as_ref()
                    .is_some_and(|workload_id| candidates.contains(workload_id))
            })
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join("+");
        (
            workload_id,
            EspCorrelationConfidence::Exact,
            reason,
            exact_candidates,
        )
    } else if exact_identifier_present {
        (
            None,
            EspCorrelationConfidence::Uncorrelated,
            if exact_candidates.is_empty() {
                "exactIdentifierNotTracked".to_string()
            } else {
                "ambiguousExactIdentifier".to_string()
            },
            exact_candidates,
        )
    } else {
        let temporal = workloads
            .iter()
            .filter(|workload| is_installer_workload(workload))
            .filter(|workload| workload_contains_process(workload, &root.process_start_time))
            .map(|workload| workload.workload_id.clone())
            .collect::<BTreeSet<_>>();
        match temporal.len() {
            0 => (
                None,
                EspCorrelationConfidence::Uncorrelated,
                "noEvidenceBackedCandidate".to_string(),
                temporal,
            ),
            1 => (
                temporal.iter().next().cloned(),
                EspCorrelationConfidence::Temporal,
                "singleTemporalCandidate".to_string(),
                temporal,
            ),
            _ => (
                None,
                EspCorrelationConfidence::Uncorrelated,
                "multipleTemporalCandidates".to_string(),
                temporal,
            ),
        }
    };

    for candidate in &candidates {
        if let Some(workload) = workloads
            .iter()
            .find(|workload| workload.workload_id == *candidate)
        {
            evidence.extend(workload.evidence.iter().cloned());
        }
    }
    deduplicate_evidence(&mut evidence);

    EspInstallerCorrelation {
        correlation_id: correlation_id(root),
        workload_id,
        confidence,
        reason,
        candidate_workload_ids: candidates.into_iter().collect(),
        process_observations: lineage.into_iter().cloned().collect(),
        evidence,
    }
}

fn is_installer_root(process: &EspProcessObservation) -> bool {
    let executable = process.executable_name.to_ascii_lowercase();
    matches!(executable.as_str(), "msiexec.exe" | "winget.exe")
        || process.product_code.is_some()
        || (!matches!(
            executable.as_str(),
            "intunemanagementextension.exe" | "agentexecutor.exe"
        ) && (process.referenced_log_path.is_some()
            || process
                .sanitized_command_line
                .as_deref()
                .and_then(extract_installer_log_path)
                .is_some()))
}

fn is_installer_workload(workload: &EspWorkload) -> bool {
    matches!(
        workload.kind,
        super::models::EspTrackedKind::Msi
            | super::models::EspTrackedKind::Office
            | super::models::EspTrackedKind::ModernApp
            | super::models::EspTrackedKind::Win32App
            | super::models::EspTrackedKind::DevicePreparationWorkload
    )
}

fn process_lineage<'a>(
    root: &'a EspProcessObservation,
    processes: &'a [EspProcessObservation],
) -> Vec<&'a EspProcessObservation> {
    let mut lineage = vec![root];
    let mut current = root;
    let mut visited = BTreeSet::from([process_identity_key(root)]);

    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(parent_pid) = current.parent_pid else {
            break;
        };
        let Some(child_started) = timestamp_value(&current.process_start_time) else {
            break;
        };
        let Some(parent) = processes
            .iter()
            .filter(|candidate| candidate.pid == parent_pid)
            .filter_map(|candidate| {
                let started = timestamp_value(&candidate.process_start_time)?;
                (started <= child_started).then_some((started, candidate))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(_, candidate)| candidate)
        else {
            break;
        };
        if !visited.insert(process_identity_key(parent)) {
            break;
        }
        lineage.push(parent);
        current = parent;
    }

    lineage
}

fn add_identifier_signal(
    signal: &'static str,
    value: &str,
    workload_identifiers: &[(&str, BTreeSet<String>)],
    signals: &mut BTreeMap<&'static str, BTreeSet<String>>,
) {
    let identifiers = normalized_identifiers(value);
    let matches = workload_identifiers
        .iter()
        .filter(|(_, workload_values)| !identifiers.is_disjoint(workload_values))
        .map(|(workload_id, _)| (*workload_id).to_string())
        .collect::<BTreeSet<_>>();
    signals.entry(signal).or_default().extend(matches);
}

fn normalized_identifiers(value: &str) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    let trimmed = value
        .trim()
        .trim_matches(['{', '}', '"', '\''])
        .to_ascii_lowercase();
    if !trimmed.is_empty() {
        values.insert(trimmed);
    }
    if let Some(guid) = extract_guid(value) {
        values.insert(guid.to_ascii_lowercase());
    }
    values
}

fn workload_contains_process(workload: &EspWorkload, process_time: &EspTimestamp) -> bool {
    let Some(process_time) = timestamp_value(process_time) else {
        return false;
    };
    let Some(first) = timestamp_value(&workload.timestamps.first_observed) else {
        return false;
    };
    let last = [
        workload.timestamps.started.as_ref(),
        workload.timestamps.ended.as_ref(),
        workload.timestamps.last_updated.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter_map(timestamp_value)
    .max()
    .unwrap_or(first);
    process_time >= first - TEMPORAL_SLOP && process_time <= last + TEMPORAL_SLOP
}

fn timestamp_value(timestamp: &EspTimestamp) -> Option<DateTime<Utc>> {
    timestamp
        .normalized_utc
        .as_deref()
        .or(Some(timestamp.raw_text.as_str()))
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn process_identity_key(process: &EspProcessObservation) -> (u32, String) {
    (
        process.pid,
        process
            .process_start_time
            .normalized_utc
            .clone()
            .unwrap_or_else(|| process.process_start_time.raw_text.clone()),
    )
}

fn correlation_id(process: &EspProcessObservation) -> String {
    format!(
        "installer|{}|{}|{}|{}",
        escape_component(&process.context.provenance.source_artifact_id),
        escape_component(&process.context.evidence_ref.evidence_id),
        process.pid,
        escape_component(
            process
                .process_start_time
                .normalized_utc
                .as_deref()
                .unwrap_or(&process.process_start_time.raw_text),
        )
    )
}

fn message_mentions_pid(message: &str, pid: u32) -> bool {
    let target = pid.to_string();
    message
        .split(|character: char| !character.is_ascii_digit())
        .any(|value| value == target)
}

fn deduplicate_evidence(evidence: &mut Vec<EspEvidenceRef>) {
    let mut seen = BTreeSet::new();
    evidence
        .retain(|item| seen.insert((item.source_artifact_id.clone(), item.evidence_id.clone())));
}

fn split_windows_arguments(command_line: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = command_line.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' => quoted = !quoted,
            '\\' if chars.peek() == Some(&'"') => {
                chars.next();
                current.push('"');
            }
            character if character.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    arguments.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(character),
        }
    }
    if !current.is_empty() {
        arguments.push(current);
    }
    arguments
}

fn parse_log_switch(argument: &str) -> Option<Option<String>> {
    let value = argument.strip_prefix(['/', '-'])?;
    let lower = value.to_ascii_lowercase();
    if lower == "log" {
        return Some(None);
    }
    if lower.starts_with("log=") || lower.starts_with("log:") {
        return Some(Some(value[4..].to_string()));
    }

    let separator = value.find(['=', ':']);
    let (switch, attached) = separator
        .map(|index| (&value[..index], Some(value[index + 1..].to_string())))
        .unwrap_or((value, None));
    let mut characters = switch.chars();
    if !characters
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case(&'l'))
    {
        return None;
    }
    if !characters.all(|character| {
        matches!(
            character.to_ascii_lowercase(),
            '*' | 'i' | 'w' | 'e' | 'a' | 'r' | 'u' | 'c' | 'm' | 'o' | 'p' | 'v' | 'x' | '+' | '!'
        )
    }) {
        return None;
    }
    Some(attached)
}

fn nonempty_path(value: String) -> Option<String> {
    let value = value.trim().trim_matches(['"', '\'']).to_string();
    (!value.is_empty()).then_some(value)
}

fn escape_component(value: &str) -> String {
    value.replace('%', "%25").replace('|', "%7C")
}

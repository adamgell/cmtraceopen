//! Deterministic installer/process correlation for ESP diagnostics.
//!
//! Correlation is intentionally evidence-first. Exact identifiers and canonical
//! log paths always take precedence over time, contradictory exact identifiers
//! remain ambiguous, and PID ancestry is guarded by process start time so PID
//! reuse cannot manufacture a parent chain.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, FixedOffset, NaiveDate, SecondsFormat, TimeZone, Utc};

use super::models::{
    EspCorrelationConfidence, EspDeploymentLogObservation, EspEvidenceRef, EspImeObservation,
    EspInstallerCorrelation, EspObservationContext, EspProcessObservation, EspTimestamp,
    EspTimestampKind, EspWorkload,
};
use super::normalize::extract_guid;

const TEMPORAL_SLOP: Duration = Duration::minutes(2);
const MAX_PARENT_CHAIN_DEPTH: usize = 16;

type ProcessIdentity = (u32, DateTime<Utc>);
type ProcessSamples<'a> = Vec<&'a EspProcessObservation>;

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

    let process_groups = group_process_observations(processes);

    process_groups
        .values()
        .filter(|samples| samples.iter().any(|process| is_installer_root(process)))
        .map(|root| {
            correlate_one(
                root,
                workloads,
                &workload_identifiers,
                &process_groups,
                deployment_logs,
                ime_logs,
            )
        })
        .collect()
}

fn correlate_one<'a>(
    root: &[&'a EspProcessObservation],
    workloads: &[EspWorkload],
    workload_identifiers: &[(&str, BTreeSet<String>)],
    process_groups: &BTreeMap<ProcessIdentity, ProcessSamples<'a>>,
    deployment_logs: &[EspDeploymentLogObservation],
    ime_logs: &[EspImeObservation],
) -> EspInstallerCorrelation {
    let lineage = process_lineage(root, process_groups);
    let root_representative = preferred_process(root).expect("installer root group is non-empty");
    let mut evidence = lineage
        .iter()
        .flat_map(|samples| samples.iter())
        .map(|process| process.context.evidence_ref.clone())
        .collect::<Vec<_>>();
    let process_conflict = lineage
        .iter()
        .any(|samples| process_samples_conflict(samples));
    let mut signals: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    let mut exact_signal_sets = Vec::new();
    let mut exact_identifier_present = false;

    for (index, samples) in lineage.iter().enumerate() {
        for process in samples.iter() {
            if let Some(app_id) = process.app_id.as_deref() {
                exact_identifier_present |= add_identifier_signal(
                    if index == 0 { "appId" } else { "parentAppId" },
                    app_id,
                    workload_identifiers,
                    &mut signals,
                    &mut exact_signal_sets,
                );
            }
            if let Some(product_code) = process.product_code.as_deref() {
                exact_identifier_present |= add_identifier_signal(
                    if index == 0 {
                        "productCode"
                    } else {
                        "parentProductCode"
                    },
                    product_code,
                    workload_identifiers,
                    &mut signals,
                    &mut exact_signal_sets,
                );
            }
        }
    }

    let mut process_log_paths = BTreeSet::new();
    for process in root {
        if let Some(path) = process
            .referenced_log_path
            .as_deref()
            .and_then(canonical_installer_log_path)
        {
            process_log_paths.insert(path);
        }
        if let Some(path) = process
            .sanitized_command_line
            .as_deref()
            .and_then(extract_installer_log_path)
            .as_deref()
            .and_then(canonical_installer_log_path)
        {
            process_log_paths.insert(path);
        }
    }
    if !process_log_paths.is_empty() {
        for deployment in deployment_logs {
            let Some(deployment_path) = deployment
                .log_path
                .as_deref()
                .and_then(canonical_installer_log_path)
            else {
                continue;
            };
            if !process_log_paths.contains(&deployment_path) {
                continue;
            }
            if !observation_within_process_window(root, &deployment.context) {
                continue;
            }
            evidence.push(deployment.context.evidence_ref.clone());
            if let Some(product_code) = deployment.product_code.as_deref() {
                exact_identifier_present |= add_identifier_signal(
                    "canonicalLogPath",
                    product_code,
                    workload_identifiers,
                    &mut signals,
                    &mut exact_signal_sets,
                );
            }
        }
    }

    for ime in ime_logs {
        let Some(app_id) = ime.app_id.as_deref() else {
            continue;
        };
        if !lineage.iter().any(|samples| {
            process_pid(samples).is_some_and(|pid| message_mentions_pid(&ime.message, pid))
                && observation_within_process_window(samples, &ime.context)
        }) {
            continue;
        }
        if !add_identifier_signal(
            "imeProcessAppId",
            app_id,
            workload_identifiers,
            &mut signals,
            &mut exact_signal_sets,
        ) {
            continue;
        }
        exact_identifier_present = true;
        evidence.push(ime.context.evidence_ref.clone());
    }

    let nonempty_signal_sets = signals
        .iter()
        .filter(|(_, candidates)| !candidates.is_empty())
        .collect::<Vec<_>>();
    let exact_candidates = nonempty_signal_sets
        .iter()
        .flat_map(|(_, candidates)| candidates.iter().cloned())
        .collect::<BTreeSet<_>>();
    let signal_conflict = exact_signal_sets.iter().any(|left| {
        exact_signal_sets
            .iter()
            .any(|right| left.is_disjoint(right))
    });

    let (workload_id, confidence, reason, candidates) = if process_conflict {
        (
            None,
            EspCorrelationConfidence::Uncorrelated,
            "conflictingProcessSamples".to_string(),
            exact_candidates,
        )
    } else if signal_conflict {
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
        let temporal = process_start_timestamp(root)
            .map(|process_time| {
                workloads
                    .iter()
                    .filter(|workload| is_installer_workload(workload))
                    .filter(|workload| workload_contains_process(workload, process_time))
                    .map(|workload| workload.workload_id.clone())
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
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
        correlation_id: correlation_id(root_representative),
        workload_id,
        confidence,
        reason,
        candidate_workload_ids: candidates.into_iter().collect(),
        process_observations: if process_conflict || signal_conflict {
            lineage
                .iter()
                .flat_map(|samples| samples.iter().map(|process| (*process).clone()))
                .collect()
        } else {
            lineage
                .iter()
                .filter_map(|samples| merge_process_samples(samples))
                .collect()
        },
        evidence,
    }
}

fn is_installer_root(process: &EspProcessObservation) -> bool {
    let executable = normalized_executable_name(&process.executable_name);
    if matches!(
        executable.as_str(),
        "intunemanagementextension" | "agentexecutor"
    ) {
        return false;
    }

    matches!(executable.as_str(), "msiexec" | "winget")
        || process
            .product_code
            .as_deref()
            .is_some_and(has_normalized_identifier)
        || (process
            .referenced_log_path
            .as_deref()
            .and_then(canonical_installer_log_path)
            .is_some()
            || process
                .sanitized_command_line
                .as_deref()
                .and_then(extract_installer_log_path)
                .is_some())
}

fn normalized_executable_name(executable: &str) -> String {
    let name = executable
        .trim()
        .trim_matches(['"', '\''])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).to_string()
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

fn group_process_observations(
    processes: &[EspProcessObservation],
) -> BTreeMap<ProcessIdentity, ProcessSamples<'_>> {
    let mut groups = BTreeMap::<ProcessIdentity, ProcessSamples<'_>>::new();
    for process in processes {
        let Some(identity) = process_identity_key(process) else {
            continue;
        };
        let Some(sampled) = process_sample_timestamp(process) else {
            continue;
        };
        let Some(started) = process_start_value(&process.process_start_time) else {
            continue;
        };
        if sampled < started {
            continue;
        }
        groups.entry(identity).or_default().push(process);
    }
    for samples in groups.values_mut() {
        samples.sort_by_key(|process| process_preference_key(process));
    }
    groups
}

fn process_lineage<'process>(
    root: &[&'process EspProcessObservation],
    process_groups: &BTreeMap<ProcessIdentity, ProcessSamples<'process>>,
) -> Vec<ProcessSamples<'process>> {
    let mut lineage = vec![root.to_vec()];
    let Some(root_identity) = process_group_identity(root) else {
        return lineage;
    };
    let mut visited = BTreeSet::from([root_identity]);

    for _ in 0..MAX_PARENT_CHAIN_DEPTH {
        let Some(current) = lineage.last() else {
            break;
        };
        let Some(parent_pid) = unique_parent_pid(current) else {
            break;
        };
        let Some(child_started) = process_start_timestamp(current) else {
            break;
        };
        let Some(child_sampled) = latest_process_sample_timestamp(current) else {
            break;
        };
        let Some(parent) = process_groups
            .values()
            .filter(|samples| process_pid(samples.as_slice()) == Some(parent_pid))
            .filter_map(|samples| {
                let started = process_start_timestamp(samples)?;
                if started > child_started {
                    return None;
                }
                let in_window = samples
                    .iter()
                    .copied()
                    .filter(|process| {
                        process_sample_timestamp(process).is_some_and(|sampled| {
                            sampled >= child_started && sampled <= child_sampled
                        })
                    })
                    .collect::<ProcessSamples<'process>>();
                (!in_window.is_empty()).then_some((started, in_window))
            })
            .max_by(|(left_started, left), (right_started, right)| {
                left_started
                    .cmp(right_started)
                    .then_with(|| {
                        preferred_process(left)
                            .map(process_preference_key)
                            .cmp(&preferred_process(right).map(process_preference_key))
                    })
                    .then_with(|| process_group_identity(left).cmp(&process_group_identity(right)))
            })
            .map(|(_, samples)| samples)
        else {
            break;
        };
        let Some(parent_identity) = process_group_identity(&parent) else {
            break;
        };
        if !visited.insert(parent_identity) {
            break;
        }
        lineage.push(parent);
    }

    lineage
}

fn add_identifier_signal(
    signal: &'static str,
    value: &str,
    workload_identifiers: &[(&str, BTreeSet<String>)],
    signals: &mut BTreeMap<&'static str, BTreeSet<String>>,
    exact_signal_sets: &mut Vec<BTreeSet<String>>,
) -> bool {
    let identifiers = normalized_identifiers(value);
    if identifiers.is_empty() {
        return false;
    }
    let matches = workload_identifiers
        .iter()
        .filter(|(_, workload_values)| !identifiers.is_disjoint(workload_values))
        .map(|(workload_id, _)| (*workload_id).to_string())
        .collect::<BTreeSet<_>>();
    if !matches.is_empty() {
        exact_signal_sets.push(matches.clone());
    }
    signals.entry(signal).or_default().extend(matches);
    true
}

fn has_normalized_identifier(value: &str) -> bool {
    !normalized_identifiers(value).is_empty()
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

fn workload_contains_process(workload: &EspWorkload, process_time: DateTime<Utc>) -> bool {
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
    process_time >= lower_slop_bound(first) && process_time <= upper_slop_bound(last)
}

fn timestamp_value(timestamp: &EspTimestamp) -> Option<DateTime<Utc>> {
    timestamp
        .normalized_utc
        .as_deref()
        .or(Some(timestamp.raw_text.as_str()))
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&Utc))
}

fn context_timestamp(context: &EspObservationContext) -> Option<DateTime<Utc>> {
    context
        .source_timestamp
        .as_ref()
        .and_then(timestamp_value)
        .or_else(|| {
            DateTime::parse_from_rfc3339(&context.observed_at_utc)
                .ok()
                .map(|value| value.with_timezone(&Utc))
        })
}

fn observation_within_process_window(
    samples: &[&EspProcessObservation],
    context: &EspObservationContext,
) -> bool {
    let Some(started) = process_start_timestamp(samples) else {
        return false;
    };
    let Some(observed) = context_timestamp(context) else {
        return false;
    };
    let Some(sampled) = latest_process_sample_timestamp(samples) else {
        return false;
    };

    observed >= started && observed <= sampled
}

fn lower_slop_bound(value: DateTime<Utc>) -> DateTime<Utc> {
    value.checked_sub_signed(TEMPORAL_SLOP).unwrap_or(value)
}

fn upper_slop_bound(value: DateTime<Utc>) -> DateTime<Utc> {
    value.checked_add_signed(TEMPORAL_SLOP).unwrap_or(value)
}

fn process_sample_timestamp(process: &EspProcessObservation) -> Option<DateTime<Utc>> {
    [
        DateTime::parse_from_rfc3339(&process.context.observed_at_utc)
            .ok()
            .map(|value| value.with_timezone(&Utc)),
        process
            .context
            .source_timestamp
            .as_ref()
            .and_then(timestamp_value),
    ]
    .into_iter()
    .flatten()
    .max()
}

fn process_start_timestamp(samples: &[&EspProcessObservation]) -> Option<DateTime<Utc>> {
    samples
        .iter()
        .filter_map(|process| process_start_value(&process.process_start_time))
        .max()
}

fn process_start_value(timestamp: &EspTimestamp) -> Option<DateTime<Utc>> {
    let raw = timestamp.raw_text.as_str();
    // Process identity requires the model's lossless raw representation. A
    // normalized value may already have discarded sub-second or leap carry.
    if raw.trim().is_empty() {
        return None;
    }

    match &timestamp.kind {
        EspTimestampKind::Utc if raw_uses_utc_designator(raw) => parse_rfc3339_utc(raw),
        EspTimestampKind::Offset if raw_looks_like_wmi_datetime(raw) => {
            parse_wmi_process_start(raw)
        }
        EspTimestampKind::Offset if !raw_uses_utc_designator(raw) => parse_rfc3339_utc(raw),
        EspTimestampKind::Local
        | EspTimestampKind::Invalid
        | EspTimestampKind::Unspecified
        | EspTimestampKind::Utc
        | EspTimestampKind::Offset => None,
    }
}

fn parse_rfc3339_utc(raw: &str) -> Option<DateTime<Utc>> {
    if !rfc3339_fraction_is_representable(raw) {
        return None;
    }
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn rfc3339_fraction_is_representable(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.get(19) != Some(&b'.') {
        return true;
    }

    // Chrono stores nanoseconds but accepts longer RFC 3339 fractions by
    // truncating them. Extra zeroes are exact; any other excess digit would
    // collapse a distinct process start into the same identity.
    bytes[20..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .skip(9)
        .all(|byte| *byte == b'0')
}

fn raw_uses_utc_designator(raw: &str) -> bool {
    raw.as_bytes()
        .last()
        .is_some_and(|value| matches!(value, b'Z' | b'z'))
}

fn raw_looks_like_wmi_datetime(raw: &str) -> bool {
    raw.len() == 25 && raw.as_bytes().get(14) == Some(&b'.')
}

fn parse_wmi_process_start(raw: &str) -> Option<DateTime<Utc>> {
    if !raw_looks_like_wmi_datetime(raw) || !raw.is_ascii() {
        return None;
    }
    let parse_component = |start, end| {
        let value = raw.get(start..end)?;
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| value.parse::<u32>().ok())
            .flatten()
    };
    let year = parse_component(0, 4)?.try_into().ok()?;
    let month = parse_component(4, 6)?;
    let day = parse_component(6, 8)?;
    let hour = parse_component(8, 10)?;
    let minute = parse_component(10, 12)?;
    let second = parse_component(12, 14)?;
    let microseconds = parse_component(15, 21)?;
    if second > 60 {
        return None;
    }
    // Chrono represents a leap second as second 59 plus a nanosecond carry.
    let leap_second_carry = if second == 60 { 1_000_000_000 } else { 0 };
    let nanoseconds = microseconds
        .checked_mul(1_000)?
        .checked_add(leap_second_carry)?;
    let naive = NaiveDate::from_ymd_opt(year, month, day)?.and_hms_nano_opt(
        hour,
        minute,
        second.min(59),
        nanoseconds,
    )?;
    let sign = match raw.as_bytes().get(21)? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let offset_minutes = i32::try_from(parse_component(22, 25)?)
        .ok()?
        .checked_mul(sign)?;
    let offset = FixedOffset::east_opt(offset_minutes.checked_mul(60)?)?;
    offset
        .from_local_datetime(&naive)
        .single()
        .map(|value| value.with_timezone(&Utc))
}

fn latest_process_sample_timestamp(samples: &[&EspProcessObservation]) -> Option<DateTime<Utc>> {
    let started = process_start_timestamp(samples)?;
    samples
        .iter()
        .filter_map(|process| process_sample_timestamp(process))
        .filter(|sampled| *sampled >= started)
        .max()
}

fn process_pid(samples: &[&EspProcessObservation]) -> Option<u32> {
    samples.first().map(|process| process.pid)
}

fn unique_parent_pid(samples: &[&EspProcessObservation]) -> Option<u32> {
    let parent_pids = samples
        .iter()
        .filter_map(|process| process.parent_pid)
        .collect::<BTreeSet<_>>();
    (parent_pids.len() == 1)
        .then(|| parent_pids.first().copied())
        .flatten()
}

fn preferred_process<'a>(
    samples: &[&'a EspProcessObservation],
) -> Option<&'a EspProcessObservation> {
    samples
        .iter()
        .copied()
        .max_by_key(|process| process_preference_key(process))
}

fn process_samples_conflict(samples: &[&EspProcessObservation]) -> bool {
    normalized_string_conflict(samples, |process| {
        let normalized = normalized_executable_name(&process.executable_name);
        (!normalized.is_empty()).then_some(normalized)
    }) || command_line_conflict(samples)
        || normalized_string_conflict(samples, |process| {
            process
                .referenced_log_path
                .as_deref()
                .and_then(canonical_installer_log_path)
        })
        || identifier_field_conflict(samples, |process| process.app_id.as_deref())
        || identifier_field_conflict(samples, |process| process.product_code.as_deref())
        || parent_pid_field_conflict(samples)
}

fn command_line_conflict(samples: &[&EspProcessObservation]) -> bool {
    samples
        .iter()
        .filter_map(|process| process.sanitized_command_line.as_deref())
        .filter_map(|value| match canonical_command_arguments(value) {
            Some(arguments) if arguments.is_empty() => None,
            Some(arguments) => Some(arguments),
            None => Some(vec![value.to_string()]),
        })
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

fn canonical_command_arguments(command_line: &str) -> Option<Vec<String>> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut previous = None;
    let mut chars = command_line.chars().peekable();

    while let Some(character) = chars.next() {
        match character {
            '"' => {
                // Backslash-escaped and adjacent quotes require the full CRT
                // parsing rules. Keep those representations distinct instead
                // of claiming an equivalence we cannot prove here.
                if previous == Some('\\') || chars.peek() == Some(&'"') {
                    return None;
                }
                quoted = !quoted;
                started = true;
            }
            character if matches!(character, ' ' | '\t') && !quoted => {
                if started {
                    arguments.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(character);
                started = true;
            }
        }
        previous = Some(character);
    }

    if quoted {
        return None;
    }
    if started {
        arguments.push(current);
    }
    Some(arguments)
}

fn normalized_string_conflict(
    samples: &[&EspProcessObservation],
    value: impl Fn(&EspProcessObservation) -> Option<String>,
) -> bool {
    samples
        .iter()
        .filter_map(|process| value(process))
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

fn identifier_field_conflict<'a>(
    samples: &[&'a EspProcessObservation],
    value: impl Fn(&'a EspProcessObservation) -> Option<&'a str>,
) -> bool {
    let identifiers = samples
        .iter()
        .filter_map(|process| value(process))
        .map(normalized_identifiers)
        .filter(|values| !values.is_empty())
        .collect::<Vec<_>>();
    identifier_sets_conflict(&identifiers)
}

fn parent_pid_field_conflict(samples: &[&EspProcessObservation]) -> bool {
    samples
        .iter()
        .filter_map(|process| process.parent_pid)
        .collect::<BTreeSet<_>>()
        .len()
        > 1
}

fn identifier_sets_conflict(identifiers: &[BTreeSet<String>]) -> bool {
    identifiers
        .iter()
        .any(|left| identifiers.iter().any(|right| left.is_disjoint(right)))
}

fn merge_process_samples(samples: &[&EspProcessObservation]) -> Option<EspProcessObservation> {
    let latest = samples.iter().copied().max_by(|left, right| {
        process_sample_timestamp(left)
            .cmp(&process_sample_timestamp(right))
            .then_with(|| process_preference_key(left).cmp(&process_preference_key(right)))
    })?;
    let mut merged = latest.clone();
    merged.parent_pid = unique_parent_pid(samples);
    merged.executable_name =
        merged_process_string(samples, |process| Some(process.executable_name.as_str()))
            .unwrap_or_default();
    merged.sanitized_command_line =
        merged_process_string(samples, |process| process.sanitized_command_line.as_deref());
    merged.referenced_log_path =
        merged_process_string(samples, |process| process.referenced_log_path.as_deref());
    merged.app_id = merged_process_string(samples, |process| process.app_id.as_deref());
    merged.product_code = merged_process_string(samples, |process| process.product_code.as_deref());
    if let Some(sampled) = latest_process_sample_timestamp(samples) {
        merged.context.observed_at_utc = sampled.to_rfc3339_opts(SecondsFormat::AutoSi, true);
    }
    Some(merged)
}

fn merged_process_string<'a>(
    samples: &[&'a EspProcessObservation],
    value: impl Fn(&'a EspProcessObservation) -> Option<&'a str>,
) -> Option<String> {
    samples
        .iter()
        .copied()
        .filter(|process| value(process).is_some_and(|value| !value.trim().is_empty()))
        .max_by(|left, right| {
            process_sample_timestamp(left)
                .cmp(&process_sample_timestamp(right))
                .then_with(|| {
                    value(left)
                        .map(str::to_ascii_lowercase)
                        .cmp(&value(right).map(str::to_ascii_lowercase))
                })
                .then_with(|| {
                    left.context
                        .provenance
                        .source_artifact_id
                        .cmp(&right.context.provenance.source_artifact_id)
                })
                .then_with(|| {
                    left.context
                        .evidence_ref
                        .evidence_id
                        .cmp(&right.context.evidence_ref.evidence_id)
                })
        })
        .and_then(value)
        .map(str::to_string)
}

fn process_preference_key(
    process: &EspProcessObservation,
) -> (u8, Option<DateTime<Utc>>, &str, &str) {
    let information = [
        process
            .app_id
            .as_deref()
            .is_some_and(has_normalized_identifier),
        process
            .product_code
            .as_deref()
            .is_some_and(has_normalized_identifier),
        process
            .referenced_log_path
            .as_deref()
            .and_then(canonical_installer_log_path)
            .is_some(),
        process
            .sanitized_command_line
            .as_deref()
            .is_some_and(|command_line| !command_line.trim().is_empty()),
    ]
    .into_iter()
    .filter(|meaningful| *meaningful)
    .count() as u8;
    (
        information,
        process_sample_timestamp(process),
        process.context.provenance.source_artifact_id.as_str(),
        process.context.evidence_ref.evidence_id.as_str(),
    )
}

fn process_group_identity(samples: &[&EspProcessObservation]) -> Option<ProcessIdentity> {
    samples
        .first()
        .and_then(|process| process_identity_key(process))
}

fn process_identity_key(process: &EspProcessObservation) -> Option<ProcessIdentity> {
    process_start_value(&process.process_start_time).map(|started| (process.pid, started))
}

fn correlation_id(process: &EspProcessObservation) -> String {
    let (pid, started) =
        process_identity_key(process).expect("correlated process has a validated identity");
    format!(
        "installer|{}|{}",
        pid,
        escape_component(&started.to_rfc3339_opts(SecondsFormat::AutoSi, true))
    )
}

fn message_mentions_pid(message: &str, pid: u32) -> bool {
    let target = pid.to_string();
    let tokens = message
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    tokens.windows(2).any(|window| {
        (window[0].eq_ignore_ascii_case("pid")
            || window[0].eq_ignore_ascii_case("process")
            || window[0].eq_ignore_ascii_case("processid"))
            && window[1] == target
    }) || tokens.windows(3).any(|window| {
        window[0].eq_ignore_ascii_case("process")
            && window[1].eq_ignore_ascii_case("id")
            && window[2] == target
    })
}

fn deduplicate_evidence(evidence: &mut Vec<EspEvidenceRef>) {
    evidence.sort_by(|left, right| {
        (&left.source_artifact_id, &left.evidence_id)
            .cmp(&(&right.source_artifact_id, &right.evidence_id))
    });
    evidence.dedup_by(|left, right| {
        left.source_artifact_id == right.source_artifact_id && left.evidence_id == right.evidence_id
    });
}

fn split_windows_arguments(command_line: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = command_line.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '"' => {
                quoted = !quoted;
                current.push(character);
            }
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

    let separator = value.find(['=', ':', '"', '\'']);
    let (switch, attached) = separator
        .map(|index| {
            let separator = value.as_bytes()[index];
            let path_start = if matches!(separator, b'"' | b'\'') {
                index
            } else {
                index + 1
            };
            (&value[..index], Some(value[path_start..].to_string()))
        })
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

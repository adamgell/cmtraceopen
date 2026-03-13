use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::State;

use crate::intune::models::{EvidenceBundleArtifactCounts, EvidenceBundleMetadata};
use crate::models::log_entry::ParseResult;
use crate::parser;
use crate::state::app_state::{AppState, OpenFile};

const DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS: &[&str] = &[
    "evidence/logs",
    "evidence/registry",
    "evidence/event-logs",
    "evidence/exports",
    "evidence/screenshots",
    "evidence/command-output",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LogSourceKind {
    File,
    Folder,
    Known,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnownSourcePathKind {
    File,
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PlatformKind {
    All,
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnownSourceDefaultFileSelectionBehavior {
    None,
    PreferFileName,
    PreferFileNameThenPattern,
    PreferPattern,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownSourceGroupingMetadata {
    pub family_id: String,
    pub family_label: String,
    pub group_id: String,
    pub group_label: String,
    pub group_order: u32,
    pub source_order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownSourceDefaultFileIntent {
    pub selection_behavior: KnownSourceDefaultFileSelectionBehavior,
    pub preferred_file_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum LogSource {
    File {
        path: String,
    },
    Folder {
        path: String,
    },
    Known {
        #[serde(rename = "sourceId")]
        source_id: String,
        #[serde(rename = "defaultPath")]
        default_path: String,
        #[serde(rename = "pathKind")]
        path_kind: KnownSourcePathKind,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderEntry {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub size_bytes: Option<u64>,
    pub modified_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderListingResult {
    pub source_kind: LogSourceKind,
    pub source: LogSource,
    pub entries: Vec<FolderEntry>,
    #[serde(default)]
    pub bundle_metadata: Option<EvidenceBundleMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KnownSourceMetadata {
    pub id: String,
    pub label: String,
    pub description: String,
    pub platform: PlatformKind,
    pub source_kind: LogSourceKind,
    pub source: LogSource,
    pub file_patterns: Vec<String>,
    #[serde(default)]
    pub grouping: Option<KnownSourceGroupingMetadata>,
    #[serde(default)]
    pub default_file_intent: Option<KnownSourceDefaultFileIntent>,
}

/// Open and parse a log file, auto-detecting its format.
/// Stores the backend parser selection in AppState for tail reading.
#[tauri::command]
pub fn open_log_file(path: String, state: State<'_, AppState>) -> Result<ParseResult, String> {
    let (result, parser_selection) = parser::parse_file(&path)?;

    // Store in AppState so tail parsing reuses the same backend parser selection.
    let mut open_files = state.open_files.lock().map_err(|e| e.to_string())?;
    open_files.insert(
        PathBuf::from(&path),
        OpenFile {
            path: PathBuf::from(&path),
            entries: vec![], // entries live in the frontend
            parser_selection,
            byte_offset: result.byte_offset,
        },
    );

    Ok(result)
}

fn normalize_path_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn metadata_modified_unix_ms(metadata: &fs::Metadata) -> Option<u64> {
    let duration = metadata.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(duration.as_millis()).ok()
}

fn compare_folder_entries(left: &FolderEntry, right: &FolderEntry) -> Ordering {
    match (left.is_dir, right.is_dir) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => {
            let left_lower = left.name.to_lowercase();
            let right_lower = right.name.to_lowercase();

            left_lower
                .cmp(&right_lower)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.path.cmp(&right.path))
        }
    }
}

fn bundle_entry_rank(entry: &FolderEntry) -> usize {
    match entry.name.to_ascii_lowercase().as_str() {
        "manifest.json" => 0,
        "notes.md" => 1,
        "evidence" => 2,
        _ => 3,
    }
}

fn compare_bundle_folder_entries(left: &FolderEntry, right: &FolderEntry) -> Ordering {
    bundle_entry_rank(left)
        .cmp(&bundle_entry_rank(right))
        .then_with(|| compare_folder_entries(left, right))
}

fn detect_evidence_bundle_metadata(path: &Path) -> Option<EvidenceBundleMetadata> {
    let manifest_path = path.join("manifest.json");
    if !manifest_path.is_file() {
        return None;
    }

    let manifest_content = fs::read_to_string(&manifest_path).ok()?;
    let manifest = serde_json::from_str::<Value>(&manifest_content).ok()?;

    let mut primary_entry_points = resolve_bundle_primary_entry_points(path, &manifest);
    if primary_entry_points.is_empty() {
        primary_entry_points = DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS
            .iter()
            .map(|relative| path.join(relative))
            .collect();
    }

    Some(EvidenceBundleMetadata {
        manifest_path: manifest_path.to_string_lossy().to_string(),
        notes_path: resolve_bundle_hint_path(
            path,
            json_string_at(&manifest, &["intakeHints", "notesPath"]).as_deref(),
        )
        .or_else(|| {
            let default_path = path.join("notes.md");
            default_path.is_file().then_some(default_path)
        })
        .map(|value| value.to_string_lossy().to_string()),
        evidence_root: resolve_bundle_hint_path(
            path,
            json_string_at(&manifest, &["intakeHints", "evidenceRoot"]).as_deref(),
        )
        .or_else(|| {
            let default_path = path.join("evidence");
            default_path.is_dir().then_some(default_path)
        })
        .map(|value| value.to_string_lossy().to_string()),
        primary_entry_points: primary_entry_points
            .iter()
            .map(|entry| entry.to_string_lossy().to_string())
            .collect(),
        available_primary_entry_points: primary_entry_points
            .iter()
            .filter(|entry| entry.exists())
            .map(|entry| entry.to_string_lossy().to_string())
            .collect(),
        bundle_id: json_string_at(&manifest, &["bundle", "bundleId"]),
        bundle_label: json_string_at(&manifest, &["bundle", "bundleLabel"]),
        created_utc: json_string_at(&manifest, &["bundle", "createdUtc"]),
        case_reference: json_string_at(&manifest, &["bundle", "caseReference"]),
        summary: json_string_at(&manifest, &["bundle", "summary"]),
        collector_profile: json_string_at(&manifest, &["collection", "collectorProfile"]),
        collector_version: json_string_at(&manifest, &["collection", "collectorVersion"]),
        collected_utc: json_string_at(&manifest, &["collection", "collectedUtc"]),
        device_name: json_string_at(&manifest, &["bundle", "device", "deviceName"]),
        primary_user: json_string_at(&manifest, &["bundle", "device", "primaryUser"]),
        platform: json_string_at(&manifest, &["bundle", "device", "platform"]),
        os_version: json_string_at(&manifest, &["bundle", "device", "osVersion"]),
        tenant: json_string_at(&manifest, &["bundle", "device", "tenant"]),
        artifact_counts: Some(EvidenceBundleArtifactCounts {
            collected: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "collected"],
            )?,
            missing: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "missing"],
            )?,
            failed: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "failed"],
            )?,
            skipped: json_u64_at(
                &manifest,
                &["collection", "results", "artifactCounts", "skipped"],
            )?,
        }),
    })
}

fn resolve_bundle_primary_entry_points(bundle_root: &Path, manifest: &Value) -> Vec<PathBuf> {
    let manifest_entry_points = json_string_array_at(manifest, &["intakeHints", "primaryEntryPoints"]);
    let entry_points = if manifest_entry_points.is_empty() {
        DEFAULT_BUNDLE_PRIMARY_ENTRY_POINTS
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        manifest_entry_points
    };

    entry_points
        .iter()
        .filter_map(|entry| resolve_bundle_hint_path(bundle_root, Some(entry.as_str())))
        .collect()
}

fn resolve_bundle_hint_path(bundle_root: &Path, raw_path: Option<&str>) -> Option<PathBuf> {
    let raw_path = raw_path?.trim();
    if raw_path.is_empty() {
        return None;
    }

    let path = PathBuf::from(raw_path);
    if path.is_absolute() {
        Some(path)
    } else {
        Some(bundle_root.join(path))
    }
}

fn json_value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn json_string_at(value: &Value, path: &[&str]) -> Option<String> {
    json_value_at(value, path)
        .and_then(Value::as_str)
        .map(|value| value.to_string())
}

fn json_u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    json_value_at(value, path).and_then(Value::as_u64)
}

fn json_string_array_at(value: &Value, path: &[&str]) -> Vec<String> {
    json_value_at(value, path)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|value| value.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// List top-level entries for a folder source.
#[tauri::command]
pub fn list_log_folder(path: String) -> Result<FolderListingResult, String> {
    eprintln!("event=list_log_folder_start path=\"{}\"", path);

    let requested_path = PathBuf::from(&path);

    if !requested_path.exists() {
        return Err(format!(
            "folder does not exist: {}",
            requested_path.display()
        ));
    }

    if !requested_path.is_dir() {
        return Err(format!(
            "path is not a folder: {}",
            requested_path.display()
        ));
    }

    let read_dir = fs::read_dir(&requested_path)
        .map_err(|e| format!("failed to read folder {}: {e}", requested_path.display()))?;

    let mut entries: Vec<FolderEntry> = Vec::new();

    for entry_result in read_dir {
        let entry = match entry_result {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "event=list_log_folder_skip reason=read_dir_entry_error path=\"{}\" error=\"{}\"",
                    requested_path.display(),
                    error
                );
                continue;
            }
        };

        let entry_path = entry.path();
        let metadata = match entry.metadata() {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "event=list_log_folder_skip reason=metadata_error entry_path=\"{}\" error=\"{}\"",
                    entry_path.display(),
                    error
                );
                continue;
            }
        };

        entries.push(FolderEntry {
            name: entry.file_name().to_string_lossy().to_string(),
            path: normalize_path_string(&entry_path),
            is_dir: metadata.is_dir(),
            size_bytes: if metadata.is_file() {
                Some(metadata.len())
            } else {
                None
            },
            modified_unix_ms: metadata_modified_unix_ms(&metadata),
        });
    }

    let bundle_metadata = detect_evidence_bundle_metadata(&requested_path);
    if bundle_metadata.is_some() {
        entries.sort_by(compare_bundle_folder_entries);
    } else {
        entries.sort_by(compare_folder_entries);
    }

    eprintln!(
        "event=list_log_folder_complete path=\"{}\" entry_count={}",
        requested_path.display(),
        entries.len()
    );

    Ok(FolderListingResult {
        source_kind: LogSourceKind::Folder,
        source: LogSource::Folder {
            path: normalize_path_string(&requested_path),
        },
        entries,
        bundle_metadata,
    })
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
fn windows_known_source(
    id: &str,
    label: &str,
    description: &str,
    path_kind: KnownSourcePathKind,
    default_path: &str,
    file_patterns: &[&str],
    grouping: KnownSourceGroupingMetadata,
    default_file_intent: Option<KnownSourceDefaultFileIntent>,
) -> KnownSourceMetadata {
    let id_text = id.to_string();

    KnownSourceMetadata {
        id: id_text.clone(),
        label: label.to_string(),
        description: description.to_string(),
        platform: PlatformKind::Windows,
        source_kind: LogSourceKind::Known,
        source: LogSource::Known {
            source_id: id_text,
            default_path: default_path.to_string(),
            path_kind,
        },
        file_patterns: file_patterns
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        grouping: Some(grouping),
        default_file_intent,
    }
}

#[cfg(target_os = "windows")]
fn windows_known_log_sources() -> Vec<KnownSourceMetadata> {
    vec![
        windows_known_source(
            "windows-intune-ime-logs",
            "Intune IME Logs Folder",
            "Known log source for Intune Management Extension (IME) app and script diagnostics.",
            KnownSourcePathKind::Folder,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs",
            &[
                "IntuneManagementExtension.log",
                "AppWorkload.log",
                "AppActionProcessor.log",
                "AgentExecutor.log",
                "HealthScripts.log",
                "*.log",
            ],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "IntuneManagementExtension.log".to_string(),
                    "AppWorkload.log".to_string(),
                    "AppActionProcessor.log".to_string(),
                    "AgentExecutor.log".to_string(),
                    "HealthScripts.log".to_string(),
                ],
            }),
        ),
        windows_known_source(
            "windows-intune-ime-intunemanagementextension-log",
            "Intune IME: IntuneManagementExtension.log",
            "Primary IME log for check-ins, policy processing, and app orchestration.",
            KnownSourcePathKind::File,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\IntuneManagementExtension.log",
            &["IntuneManagementExtension*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 20,
            },
            None,
        ),
        windows_known_source(
            "windows-intune-ime-appworkload-log",
            "Intune IME: AppWorkload.log",
            "Win32 and WinGet app download/staging/install diagnostics.",
            KnownSourcePathKind::File,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AppWorkload.log",
            &["AppWorkload*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 30,
            },
            None,
        ),
        windows_known_source(
            "windows-intune-ime-agentexecutor-log",
            "Intune IME: AgentExecutor.log",
            "Script execution and remediation output with exit code tracking.",
            KnownSourcePathKind::File,
            "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\AgentExecutor.log",
            &["AgentExecutor*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-ime".to_string(),
                group_label: "Intune IME".to_string(),
                group_order: 10,
                source_order: 40,
            },
            None,
        ),
        windows_known_source(
            "windows-dmclient-logs",
            "DMClient Local Logs",
            "MDM DMClient log folder used for local sync diagnostics.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\mdm",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-intune".to_string(),
                family_label: "Windows Intune".to_string(),
                group_id: "intune-mdm".to_string(),
                group_label: "MDM and Enrollment".to_string(),
                group_order: 20,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        windows_known_source(
            "windows-panther-setupact-log",
            "setupact.log (Panther)",
            "Primary Windows setup and Autopilot/OOBE action log.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Panther\\setupact.log",
            &["setupact.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-setup".to_string(),
                family_label: "Windows Setup".to_string(),
                group_id: "setup-panther".to_string(),
                group_label: "Panther".to_string(),
                group_order: 30,
                source_order: 10,
            },
            None,
        ),
        windows_known_source(
            "windows-panther-setuperr-log",
            "setuperr.log (Panther)",
            "Error-focused Windows setup and Autopilot/OOBE triage log.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Panther\\setuperr.log",
            &["setuperr.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-setup".to_string(),
                family_label: "Windows Setup".to_string(),
                group_id: "setup-panther".to_string(),
                group_label: "Panther".to_string(),
                group_order: 30,
                source_order: 20,
            },
            None,
        ),
        windows_known_source(
            "windows-cbs-log",
            "CBS.log",
            "Component-Based Servicing log for update and servicing failures.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Logs\\CBS\\CBS.log",
            &["CBS.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-servicing".to_string(),
                family_label: "Windows Servicing".to_string(),
                group_id: "servicing-core".to_string(),
                group_label: "CBS and DISM".to_string(),
                group_order: 40,
                source_order: 10,
            },
            None,
        ),
        windows_known_source(
            "windows-dism-log",
            "DISM.log",
            "Deployment Image Servicing and Management diagnostics log.",
            KnownSourcePathKind::File,
            "C:\\Windows\\Logs\\DISM\\dism.log",
            &["dism.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-servicing".to_string(),
                family_label: "Windows Servicing".to_string(),
                group_id: "servicing-core".to_string(),
                group_label: "CBS and DISM".to_string(),
                group_order: 40,
                source_order: 20,
            },
            None,
        ),
        windows_known_source(
            "windows-reporting-events-log",
            "ReportingEvents.log",
            "Windows Update transaction history in tab-delimited text.",
            KnownSourcePathKind::File,
            "C:\\Windows\\SoftwareDistribution\\ReportingEvents.log",
            &["ReportingEvents.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-servicing".to_string(),
                family_label: "Windows Servicing".to_string(),
                group_id: "servicing-update".to_string(),
                group_label: "Windows Update".to_string(),
                group_order: 40,
                source_order: 30,
            },
            None,
        ),
    ]
}

#[cfg(target_os = "windows")]
fn build_known_log_sources() -> Vec<KnownSourceMetadata> {
    windows_known_log_sources()
}

#[cfg(not(target_os = "windows"))]
fn build_known_log_sources() -> Vec<KnownSourceMetadata> {
    Vec::new()
}

/// Return known platform log source metadata.
#[tauri::command]
pub fn get_known_log_sources() -> Result<Vec<KnownSourceMetadata>, String> {
    let sources = build_known_log_sources();

    eprintln!("event=get_known_log_sources count={}", sources.len());

    Ok(sources)
}

#[cfg(test)]
mod tests {
        use super::list_log_folder;
        use std::fs;
        use std::path::PathBuf;
        use std::time::{SystemTime, UNIX_EPOCH};

        #[test]
        fn list_log_folder_marks_evidence_bundle_and_exposes_primary_entry_points() {
                let bundle_dir = create_temp_dir("file-ops-bundle");
                fs::create_dir_all(bundle_dir.join("evidence").join("logs")).expect("create logs dir");
                fs::create_dir_all(bundle_dir.join("evidence").join("registry"))
                        .expect("create registry dir");
                fs::write(bundle_dir.join("notes.md"), "notes").expect("write notes");
                fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest()).expect("write manifest");

                let result = list_log_folder(bundle_dir.to_string_lossy().to_string()).expect("list folder");
                let bundle_metadata = result.bundle_metadata.expect("bundle metadata");

                assert_eq!(bundle_metadata.bundle_id.as_deref(), Some("CMTRACE-123"));
                assert_eq!(result.entries.first().map(|entry| entry.name.as_str()), Some("manifest.json"));
                assert!(bundle_metadata
                        .available_primary_entry_points
                        .iter()
                        .any(|path| path.ends_with("evidence\\logs") || path.ends_with("evidence/logs")));
                assert!(bundle_metadata
                        .available_primary_entry_points
                        .iter()
                        .any(|path| path.ends_with("evidence\\registry") || path.ends_with("evidence/registry")));

                fs::remove_dir_all(&bundle_dir).expect("remove temp bundle dir");
        }

    #[test]
    fn list_log_folder_bundle_metadata_filters_missing_manifest_entry_points() {
        let bundle_dir = create_temp_dir("file-ops-bundle-missing");
        fs::create_dir_all(bundle_dir.join("evidence").join("logs")).expect("create logs dir");
        fs::write(bundle_dir.join("manifest.json"), sample_bundle_manifest_with_missing_entry())
            .expect("write manifest");

        let result = list_log_folder(bundle_dir.to_string_lossy().to_string()).expect("list folder");
        let bundle_metadata = result.bundle_metadata.expect("bundle metadata");

        assert_eq!(bundle_metadata.primary_entry_points.len(), 2);
        assert!(bundle_metadata
            .primary_entry_points
            .iter()
            .any(|path| path.ends_with("evidence\\logs") || path.ends_with("evidence/logs")));
        assert!(bundle_metadata
            .primary_entry_points
            .iter()
            .any(|path| path.ends_with("evidence\\missing") || path.ends_with("evidence/missing")));
        assert_eq!(bundle_metadata.available_primary_entry_points.len(), 1);
        assert!(bundle_metadata
            .available_primary_entry_points
            .iter()
            .all(|path| !path.ends_with("evidence\\missing") && !path.ends_with("evidence/missing")));

        fs::remove_dir_all(&bundle_dir).expect("remove temp bundle dir");
    }

        fn create_temp_dir(prefix: &str) -> PathBuf {
                let unique = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("system time before unix epoch")
                        .as_nanos();
                let path = std::env::temp_dir().join(format!("{}-{}", prefix, unique));
                fs::create_dir_all(&path).expect("create temp dir");
                path
        }

        fn sample_bundle_manifest() -> &'static str {
                r#"{
    "bundle": {
        "bundleId": "CMTRACE-123",
        "bundleLabel": "intune-endpoint-evidence",
        "createdUtc": "2026-03-12T16:00:54Z",
        "caseReference": "case-123",
        "summary": "Curated endpoint evidence bundle.",
        "device": {
            "deviceName": "GELL-VM-5879648",
            "primaryUser": "AzureAD\\AdamGell",
            "platform": "Windows",
            "osVersion": "Windows 11",
            "tenant": "CDWWorkspaceLab"
        }
    },
    "collection": {
        "collectorProfile": "intune-windows-endpoint-v1",
        "collectorVersion": "1.1.0",
        "collectedUtc": "2026-03-12T16:00:54Z",
        "results": {
            "artifactCounts": {
                "collected": 55,
                "missing": 7,
                "failed": 2,
                "skipped": 0
            }
        }
    },
    "intakeHints": {
        "notesPath": "notes.md",
        "evidenceRoot": "evidence",
        "primaryEntryPoints": [
            "evidence/logs",
            "evidence/registry",
            "evidence/event-logs",
            "evidence/exports",
            "evidence/screenshots",
            "evidence/command-output"
        ]
    }
}"#
        }

        fn sample_bundle_manifest_with_missing_entry() -> &'static str {
                r#"{
    "bundle": {
        "bundleId": "CMTRACE-456",
        "bundleLabel": "intune-endpoint-evidence",
        "createdUtc": "2026-03-12T16:00:54Z",
        "device": {
            "deviceName": "GELL-VM-5879648",
            "platform": "Windows"
        }
    },
    "collection": {
        "results": {
            "artifactCounts": {
                "collected": 1,
                "missing": 1,
                "failed": 0,
                "skipped": 0
            }
        }
    },
    "intakeHints": {
        "primaryEntryPoints": [
            "evidence/logs",
            "evidence/missing"
        ]
    }
}"#
        }
}

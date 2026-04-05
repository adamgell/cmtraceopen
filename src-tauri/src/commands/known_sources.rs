use serde::{Deserialize, Serialize};

use super::file_ops::{LogSource, LogSourceKind};

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

// ── Tauri Commands ──────────────────────────────────────────────────────

#[tauri::command]
pub fn get_known_log_sources() -> Result<Vec<KnownSourceMetadata>, crate::error::AppError> {
    let sources = build_known_log_sources();

    log::info!("event=get_known_log_sources count={}", sources.len());

    Ok(sources)
}

// ── Public helpers (used by menu.rs) ────────────────────────────────────

pub fn build_known_log_sources() -> Vec<KnownSourceMetadata> {
    #[cfg(target_os = "windows")]
    {
        windows_known_log_sources()
    }

    #[cfg(target_os = "macos")]
    {
        macos_known_log_sources()
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        Vec::new()
    }
}

// ── Platform-specific builders ──────────────────────────────────────────

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
        // ── ConfigMgr ──
        windows_known_source(
            "windows-configmgr-ccm-logs",
            "CCM Logs Folder",
            "ConfigMgr client operational logs (policy, inventory, software distribution).",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\CCM\\Logs",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-configmgr".to_string(),
                family_label: "ConfigMgr".to_string(),
                group_id: "configmgr-logs".to_string(),
                group_label: "ConfigMgr Logs".to_string(),
                group_order: 25,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        windows_known_source(
            "windows-configmgr-ccmsetup-logs",
            "ccmsetup Logs Folder",
            "ConfigMgr client installation and setup logs.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\ccmsetup\\Logs",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-configmgr".to_string(),
                family_label: "ConfigMgr".to_string(),
                group_id: "configmgr-logs".to_string(),
                group_label: "ConfigMgr Logs".to_string(),
                group_order: 25,
                source_order: 20,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        windows_known_source(
            "windows-configmgr-swmtr",
            "Software Metering Logs",
            "ConfigMgr software metering usage reporting data.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\System32\\SWMTRReporting",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-configmgr".to_string(),
                family_label: "ConfigMgr".to_string(),
                group_id: "configmgr-logs".to_string(),
                group_label: "ConfigMgr Logs".to_string(),
                group_order: 25,
                source_order: 30,
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
                group_order: 40,
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
                group_order: 40,
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
                group_order: 50,
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
                group_order: 50,
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
                group_order: 50,
                source_order: 30,
            },
            None,
        ),
        windows_known_source(
            "windows-iis-logs",
            "IIS Logs",
            "IIS W3C extended log folder (W3SVC*) under inetpub log files.",
            KnownSourcePathKind::Folder,
            "C:\\inetpub\\logs\\LogFiles",
            &["u_ex*.log", "*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-iis".to_string(),
                family_label: "Windows IIS".to_string(),
                group_id: "iis-w3c".to_string(),
                group_label: "W3C Logs".to_string(),
                group_order: 55,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior: KnownSourceDefaultFileSelectionBehavior::PreferPattern,
                preferred_file_names: Vec::new(),
            }),
        ),
        // ── Software Deployment ──────────────────────────────────────
        windows_known_source(
            "windows-deployment-logs-software",
            "Software Logs Folder",
            "Common deployment log output folder used by PSADT, SCCM, and custom installers.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\Logs\\Software",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-deployment".to_string(),
                family_label: "Software Deployment".to_string(),
                group_id: "deployment-logs".to_string(),
                group_label: "Deployment Logs".to_string(),
                group_order: 30,
                source_order: 10,
            },
            None,
        ),
        windows_known_source(
            "windows-deployment-ccmcache",
            "ccmcache Folder",
            "ConfigMgr client cache folder where packages and scripts are staged.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\ccmcache",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-deployment".to_string(),
                family_label: "Software Deployment".to_string(),
                group_id: "deployment-logs".to_string(),
                group_label: "Deployment Logs".to_string(),
                group_order: 30,
                source_order: 20,
            },
            None,
        ),
        windows_known_source(
            "windows-deployment-psadt",
            "PSADT Logs Folder",
            "Default PSAppDeployToolkit log output directory.",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\Logs\\Software",
            &["*_PSAppDeployToolkit*.log", "*Deploy-Application*.log", "*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-deployment".to_string(),
                family_label: "Software Deployment".to_string(),
                group_id: "deployment-psadt".to_string(),
                group_label: "PSADT".to_string(),
                group_order: 30,
                source_order: 30,
            },
            None,
        ),
        windows_known_source(
            "windows-deployment-msi-log",
            "MSI Verbose Log Folder",
            "Default location for MSI verbose install logs (%TEMP%).",
            KnownSourcePathKind::Folder,
            "C:\\Windows\\Temp",
            &["MSI*.LOG", "MSI*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-deployment".to_string(),
                family_label: "Software Deployment".to_string(),
                group_id: "deployment-msi".to_string(),
                group_label: "MSI Logs".to_string(),
                group_order: 30,
                source_order: 40,
            },
            None,
        ),
        // ── PatchMyPC ───────────────────────────────────────────────────
        windows_known_source(
            "windows-deployment-patchmypc-logs",
            "PatchMyPC Logs Folder",
            "PatchMyPC client and notification logs (CMTrace format).",
            KnownSourcePathKind::Folder,
            "C:\\ProgramData\\PatchMyPC\\Logs",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-deployment".to_string(),
                family_label: "Software Deployment".to_string(),
                group_id: "deployment-patchmypc".to_string(),
                group_label: "PatchMyPC".to_string(),
                group_order: 30,
                source_order: 50,
            },
            None,
        ),
        windows_known_source(
            "windows-deployment-patchmypc-install-logs",
            "PatchMyPC Install Logs",
            "MSI verbose and WiX/Burn bootstrapper logs from PatchMyPC-managed installations.",
            KnownSourcePathKind::Folder,
            "C:\\ProgramData\\PatchMyPCInstallLogs",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "windows-deployment".to_string(),
                family_label: "Software Deployment".to_string(),
                group_id: "deployment-patchmypc".to_string(),
                group_label: "PatchMyPC".to_string(),
                group_order: 30,
                source_order: 60,
            },
            None,
        ),
        // --- Sysmon live event log ---
        windows_known_source(
            "windows-sysmon-live-events",
            "Sysmon Live Event Log",
            "Query the live Microsoft-Windows-Sysmon/Operational event log channel for real-time Sysmon events.",
            KnownSourcePathKind::Folder,
            "live-event-log",
            &[],
            KnownSourceGroupingMetadata {
                family_id: "windows-sysmon".to_string(),
                family_label: "Windows Sysmon".to_string(),
                group_id: "sysmon-events".to_string(),
                group_label: "Sysmon Events".to_string(),
                group_order: 60,
                source_order: 10,
            },
            None,
        ),
    ]
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn macos_known_source(
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
        platform: PlatformKind::Macos,
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

#[cfg(target_os = "macos")]
fn macos_known_log_sources() -> Vec<KnownSourceMetadata> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

    vec![
        // --- macOS Intune: System-level MDM daemon logs ---
        macos_known_source(
            "macos-intune-system-logs",
            "Intune System Logs",
            "System-level MDM daemon logs for PKG/DMG installs and root script execution.",
            KnownSourcePathKind::Folder,
            "/Library/Logs/Microsoft/Intune",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-logs".to_string(),
                group_label: "Intune Logs".to_string(),
                group_order: 10,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "IntuneMDMDaemon.log".to_string(),
                ],
            }),
        ),
        // --- macOS Intune: User-level MDM agent logs ---
        macos_known_source(
            "macos-intune-user-logs",
            "Intune User Agent Logs",
            "User-level MDM agent logs for user-context scripts and policies.",
            KnownSourcePathKind::Folder,
            &format!("{}/Library/Logs/Microsoft/Intune", home),
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-logs".to_string(),
                group_label: "Intune Logs".to_string(),
                group_order: 10,
                source_order: 20,
            },
            None,
        ),
        // --- macOS Intune: Script execution logs ---
        macos_known_source(
            "macos-intune-scripts-logs",
            "Intune Script Logs",
            "Shell script execution logs from Intune script deployments.",
            KnownSourcePathKind::Folder,
            "/Library/Logs/Microsoft/IntuneScripts",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-logs".to_string(),
                group_label: "Intune Logs".to_string(),
                group_order: 10,
                source_order: 30,
            },
            None,
        ),
        // --- Company Portal ---
        macos_known_source(
            "macos-company-portal-logs",
            "Company Portal Logs",
            "Company Portal app logs for enrollment, device info, and user registration.",
            KnownSourcePathKind::Folder,
            &format!("{}/Library/Logs/CompanyPortal", home),
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-intune".to_string(),
                family_label: "macOS Intune".to_string(),
                group_id: "intune-portal".to_string(),
                group_label: "Company Portal".to_string(),
                group_order: 20,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "CompanyPortal.log".to_string(),
                ],
            }),
        ),
        // --- macOS install.log ---
        macos_known_source(
            "macos-install-log",
            "install.log",
            "macOS installer log — PKG installs from Intune and Software Update show up here.",
            KnownSourcePathKind::File,
            "/var/log/install.log",
            &["install.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 10,
            },
            None,
        ),
        // --- macOS system.log ---
        macos_known_source(
            "macos-system-log",
            "system.log",
            "macOS system log — MDM profile installs, daemon crashes, and system events.",
            KnownSourcePathKind::File,
            "/var/log/system.log",
            &["system.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 20,
            },
            None,
        ),
        // --- macOS wifi.log ---
        macos_known_source(
            "macos-wifi-log",
            "Wi-Fi Log",
            "macOS Wi-Fi diagnostic log",
            KnownSourcePathKind::File,
            "/var/log/wifi.log",
            &["wifi.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 30,
            },
            None,
        ),
        // --- macOS appfirewall.log ---
        macos_known_source(
            "macos-appfirewall-log",
            "Application Firewall Log",
            "macOS application firewall log",
            KnownSourcePathKind::File,
            "/var/log/appfirewall.log",
            &["appfirewall.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-system".to_string(),
                family_label: "macOS System".to_string(),
                group_id: "system-logs".to_string(),
                group_label: "System Logs".to_string(),
                group_order: 30,
                source_order: 40,
            },
            None,
        ),
        // --- Microsoft Defender logs ---
        macos_known_source(
            "macos-defender-logs",
            "Defender Logs",
            "Microsoft Defender for Endpoint install and error logs.",
            KnownSourcePathKind::Folder,
            "/Library/Logs/Microsoft/mdatp",
            &["*.log"],
            KnownSourceGroupingMetadata {
                family_id: "macos-defender".to_string(),
                family_label: "macOS Defender".to_string(),
                group_id: "defender-logs".to_string(),
                group_label: "Defender Logs".to_string(),
                group_order: 40,
                source_order: 10,
            },
            Some(KnownSourceDefaultFileIntent {
                selection_behavior:
                    KnownSourceDefaultFileSelectionBehavior::PreferFileNameThenPattern,
                preferred_file_names: vec![
                    "microsoft_defender_core_err.log".to_string(),
                    "install.log".to_string(),
                ],
            }),
        ),
    ]
}

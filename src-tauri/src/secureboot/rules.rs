use super::models::{
    DiagnosticFinding, DiagnosticSeverity, LogSession, LogSource, SecureBootScanState,
    SecureBootStage,
};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn finding(
    rule_id: &str,
    severity: DiagnosticSeverity,
    title: &str,
    detail: &str,
    recommendation: &str,
) -> DiagnosticFinding {
    DiagnosticFinding {
        rule_id: rule_id.to_string(),
        severity,
        title: title.to_string(),
        detail: detail.to_string(),
        recommendation: recommendation.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Evaluate all diagnostic rules and return a sorted list of findings.
///
/// Findings are sorted errors-first, then warnings, then info.
pub fn evaluate_all(
    state: &SecureBootScanState,
    stage: SecureBootStage,
    sessions: &[LogSession],
) -> Vec<DiagnosticFinding> {
    let mut findings: Vec<DiagnosticFinding> = Vec::new();

    // ---- Prerequisite rules ------------------------------------------------
    rule_secure_boot_enabled(state, &mut findings);
    rule_telemetry_level(state, &mut findings);
    rule_diagtrack_service(state, &mut findings);
    rule_tpm_present(state, &mut findings);
    rule_bitlocker_escrow(state, &mut findings);
    rule_disk_gpt(state, &mut findings);

    // ---- Stage rules -------------------------------------------------------
    rule_optin_configured(state, &mut findings);
    rule_payload_present(state, stage, &mut findings);
    rule_scheduled_task_health(state, &mut findings);
    rule_uefi_ca2023_status(state, &mut findings);
    rule_boot_manager_signing(state, &mut findings);
    rule_pending_reboot(state, stage, &mut findings);
    rule_error_code_present(state, &mut findings);
    rule_wincs_available(state, &mut findings);
    rule_fallback_timer(state, &mut findings);
    rule_stage_stall(stage, sessions, &mut findings);

    // ---- Remediation rules -------------------------------------------------
    rule_missing_cumulative_update(state, &mut findings);
    rule_reboot_needed(stage, &mut findings);
    rule_transient_staging_error(state, &mut findings);
    rule_missing_payload_with_wincs(state, &mut findings);
    rule_windows_10_eol(state, &mut findings);

    // Sort: errors first, then warnings, then info.
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

// ---------------------------------------------------------------------------
// Prerequisite rules
// ---------------------------------------------------------------------------

/// R01 — Secure Boot must be enabled.
fn rule_secure_boot_enabled(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.secure_boot_enabled == Some(false) {
        out.push(finding(
            "secure-boot-enabled",
            DiagnosticSeverity::Error,
            "Secure Boot is disabled",
            "The UEFI Secure Boot setting is turned off on this device.",
            "Enable Secure Boot in the UEFI/BIOS firmware settings. \
             Ensure the device is in UEFI mode (not legacy/CSM) and that \
             the Secure Boot option is set to Enabled.",
        ));
    }
}

/// R02 — Telemetry level must not be Security (0).
fn rule_telemetry_level(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.telemetry_level == Some(0) {
        out.push(finding(
            "telemetry-level",
            DiagnosticSeverity::Error,
            "Telemetry level is set to Security (0)",
            "The Windows diagnostic data level is configured to the minimum \
             'Security' setting (level 0), which blocks the opt-in telemetry \
             required for Secure Boot certificate management.",
            "Set the diagnostic data level to at least 'Required' (level 1) via \
             Group Policy (Computer Configuration → Administrative Templates → \
             Windows Components → Data Collection and Preview Builds → \
             'Allow Diagnostic Data') or MDM policy.",
        ));
    }
}

/// R03 — DiagTrack service should be running.
fn rule_diagtrack_service(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.diagtrack_running == Some(false) {
        out.push(finding(
            "diagtrack-service",
            DiagnosticSeverity::Warning,
            "DiagTrack (Connected User Experiences) service is not running",
            "The DiagTrack service is stopped. This service is required to \
             communicate diagnostic data and may block the opt-in flow.",
            "Ensure the DiagTrack service is set to Automatic start and is \
             running. Run: 'Set-Service -Name DiagTrack -StartupType Automatic; \
             Start-Service -Name DiagTrack' in an elevated PowerShell session.",
        ));
    }
}

/// R04 — TPM should be present.
fn rule_tpm_present(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.tpm_present == Some(false) {
        out.push(finding(
            "tpm-present",
            DiagnosticSeverity::Warning,
            "No TPM detected",
            "A Trusted Platform Module (TPM) was not found on this device. \
             TPM is required for full Secure Boot certificate management.",
            "Verify that TPM is enabled in the UEFI/BIOS firmware settings. \
             TPM 2.0 is required for Windows 11 and recommended for the \
             Secure Boot certificate update process.",
        ));
    }
}

/// R05 — BitLocker key should be escrowed to Entra ID / AAD.
fn rule_bitlocker_escrow(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.bitlocker_protection_on == Some(true) {
        let has_cloud_protector = state.bitlocker_key_protectors.iter().any(|p| {
            let pu = p.to_uppercase();
            pu.contains("ENTRA") || pu.contains("AAD") || pu.contains("AZUREAD")
        });
        if !has_cloud_protector {
            out.push(finding(
                "bitlocker-escrow",
                DiagnosticSeverity::Warning,
                "BitLocker recovery key is not escrowed to Entra ID / AAD",
                "BitLocker is active but no key protector associated with \
                 Entra ID (AzureAD) was detected. If a Secure Boot change \
                 triggers a recovery prompt, the user may be locked out.",
                "Ensure the BitLocker recovery key is backed up to Entra ID \
                 via the 'BackupToAAD-BitLockerKeyProtector' cmdlet or by \
                 confirming the MDM/Intune escrow policy is applied.",
            ));
        }
    }
}

/// R06 — Disk must use GPT partition style.
fn rule_disk_gpt(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.disk_partition_style.as_deref() == Some("MBR") {
        out.push(finding(
            "disk-gpt",
            DiagnosticSeverity::Error,
            "System disk uses MBR partition style",
            "The system disk is partitioned as MBR (Master Boot Record). \
             Secure Boot requires UEFI mode, which requires a GPT-partitioned disk.",
            "Convert the disk from MBR to GPT. On Windows 10 2004+ you can use \
             'mbr2gpt /convert /allowFullOS'. Back up all data before conversion \
             and ensure the device supports UEFI boot.",
        ));
    }
}

// ---------------------------------------------------------------------------
// Stage rules
// ---------------------------------------------------------------------------

/// R07 — Managed opt-in registry value must be 0x5944.
fn rule_optin_configured(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    match state.managed_opt_in {
        None => {
            out.push(finding(
                "optin-configured",
                DiagnosticSeverity::Error,
                "Managed opt-in registry value is missing",
                "The ManagedOptIn registry value required to begin the \
                 Secure Boot certificate update was not found.",
                "Deploy the opt-in policy via Intune, Group Policy, or a \
                 remediation script that sets \
                 HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\\
                 ManagedOptIn = 0x00005944 (REG_DWORD).",
            ));
        }
        Some(v) if v != 0x5944 => {
            out.push(finding(
                "optin-configured",
                DiagnosticSeverity::Error,
                "Managed opt-in registry value is incorrect",
                &format!(
                    "ManagedOptIn is set to 0x{v:08X} instead of the required 0x00005944.",
                ),
                "Correct the ManagedOptIn registry value to 0x00005944. \
                 Check whether a conflicting policy is overwriting it.",
            ));
        }
        _ => {} // Some(0x5944) — compliant, no finding
    }
}

/// R08 — Payload folder and binaries should be present at Stage 2–3.
fn rule_payload_present(
    state: &SecureBootScanState,
    stage: SecureBootStage,
    out: &mut Vec<DiagnosticFinding>,
) {
    let relevant = matches!(stage, SecureBootStage::Stage2 | SecureBootStage::Stage3);
    if !relevant {
        return;
    }

    match state.payload_folder_exists {
        Some(false) | None => {
            out.push(finding(
                "payload-present",
                DiagnosticSeverity::Error,
                "Secure Boot payload folder is missing",
                "The payload folder expected by the Secure Boot certificate \
                 deployment script was not found.",
                "Verify that the Windows Update KB containing the payload has \
                 been installed and that the deployment script has run at least \
                 once. Re-run the detect script to refresh status.",
            ));
            return; // bin count is moot if folder missing
        }
        Some(true) => {}
    }

    if state.payload_bin_count == Some(0) {
        out.push(finding(
            "payload-present",
            DiagnosticSeverity::Warning,
            "Payload folder exists but contains no .bin files",
            "The payload folder is present but no binary files were found \
             inside it. The update may still be downloading.",
            "Wait for Windows Update to finish staging the payload, then \
             re-run the detect script. If the issue persists, check Windows \
             Update logs for download errors.",
        ));
    }
}

/// R09 — Scheduled task should exist and last run should succeed.
fn rule_scheduled_task_health(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    match state.scheduled_task_exists {
        Some(false) | None => {
            out.push(finding(
                "scheduled-task-health",
                DiagnosticSeverity::Error,
                "Secure Boot scheduled task is missing",
                "The scheduled task responsible for driving the Secure Boot \
                 certificate update was not found.",
                "Re-deploy the remediation package via Intune or re-run the \
                 install script to recreate the scheduled task.",
            ));
        }
        Some(true) => {
            if let Some(result) = &state.scheduled_task_last_result {
                if result.contains("0x80070002") {
                    out.push(finding(
                        "scheduled-task-health",
                        DiagnosticSeverity::Warning,
                        "Scheduled task last run returned error 0x80070002 (file not found)",
                        &format!(
                            "The scheduled task completed with result: {result}. \
                             Error 0x80070002 typically indicates a missing script \
                             or payload file.",
                        ),
                        "Verify that all script files are present in the expected \
                         deployment folder. Re-deploy the remediation package if \
                         any files are missing.",
                    ));
                }
            }
        }
    }
}

/// R10 — Informational: show WindowsUEFICA2023Capable value.
fn rule_uefi_ca2023_status(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    let label = match state.uefi_ca2023_capable {
        Some(0) => "0 — Certificate not present in UEFI DB",
        Some(1) => "1 — Certificate is in DB but device has not rebooted into it yet",
        Some(2) => "2 — Device is booting with the 2023 UEFI CA (compliant)",
        Some(v) => {
            // Unknown value — still report it
            out.push(finding(
                "uefi-ca2023-status",
                DiagnosticSeverity::Info,
                "WindowsUEFICA2023Capable has an unrecognised value",
                &format!("WindowsUEFICA2023Capable = {v}"),
                "Report this value to your support team for investigation.",
            ));
            return;
        }
        None => {
            out.push(finding(
                "uefi-ca2023-status",
                DiagnosticSeverity::Info,
                "WindowsUEFICA2023Capable value is not available",
                "The registry value could not be read. This may indicate \
                 the device has not yet run the detect script.",
                "Run the detect script to populate this value.",
            ));
            return;
        }
    };

    out.push(finding(
        "uefi-ca2023-status",
        DiagnosticSeverity::Info,
        "WindowsUEFICA2023Capable status",
        label,
        "No action required — this is an informational reading.",
    ));
}

/// R11 — Certificate in DB but not booting: reboot may be pending.
fn rule_boot_manager_signing(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.uefi_ca2023_capable == Some(1) {
        out.push(finding(
            "boot-manager-signing",
            DiagnosticSeverity::Warning,
            "UEFI CA 2023 certificate is in the DB but the device has not rebooted into it",
            "WindowsUEFICA2023Capable == 1 means the certificate has been \
             written to the Secure Boot database, but the device needs to \
             reboot for the boot manager to use it.",
            "Schedule a reboot of the device at the earliest opportunity. \
             Once rebooted, the value should advance to 2 and the device \
             will be compliant.",
        ));
    }
}

/// R12 — Pending reboot at Stage 4.
fn rule_pending_reboot(
    state: &SecureBootScanState,
    stage: SecureBootStage,
    out: &mut Vec<DiagnosticFinding>,
) {
    if stage == SecureBootStage::Stage4 && !state.pending_reboot_sources.is_empty() {
        let sources = state.pending_reboot_sources.join(", ");
        out.push(finding(
            "pending-reboot",
            DiagnosticSeverity::Warning,
            "Device has a pending reboot",
            &format!("Pending reboot sources: {sources}."),
            "Reboot the device to complete the Secure Boot certificate update. \
             The reboot can be initiated by the user or scheduled via Intune.",
        ));
    }
}

/// R13 — Non-zero error code in uefi_ca2023_error.
fn rule_error_code_present(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if let Some(code) = state.uefi_ca2023_error {
        if code != 0 {
            out.push(finding(
                "error-code-present",
                DiagnosticSeverity::Error,
                "Secure Boot certificate update reported an error code",
                &format!(
                    "The UEFI CA 2023 update process returned error 0x{code:08X}.",
                ),
                &format!(
                    "Look up 0x{code:08X} in the Windows error code database. \
                     Common causes include missing payload files, insufficient \
                     permissions, or a firmware incompatibility.",
                ),
            ));
        }
    }
}

/// R14 — WinCS is available (informational positive signal).
fn rule_wincs_available(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.wincs_available == Some(true) {
        out.push(finding(
            "wincs-available",
            DiagnosticSeverity::Info,
            "Windows Certificate Services (WinCS) is available",
            "WinCS was detected as available on this device, which can \
             accelerate certificate provisioning.",
            "No action required.",
        ));
    }
}

/// R15 — Fallback timer date is set (informational).
fn rule_fallback_timer(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if let Some(date) = &state.managed_opt_in_date {
        out.push(finding(
            "fallback-timer",
            DiagnosticSeverity::Info,
            "Managed opt-in fallback date is configured",
            &format!("ManagedOptInDate is set to: {date}"),
            "No action required. The fallback date controls when the opt-in \
             is automatically applied if the managed deployment has not \
             completed.",
        ));
    }
}

/// R16 — Stage stall detection: too many consecutive Detect sessions at the same stage.
fn rule_stage_stall(
    stage: SecureBootStage,
    sessions: &[LogSession],
    out: &mut Vec<DiagnosticFinding>,
) {
    // Only meaningful during active work stages.
    if !matches!(stage, SecureBootStage::Stage2 | SecureBootStage::Stage3) {
        return;
    }

    // Count consecutive *recent* Detect sessions whose result_stage matches `stage`.
    // We walk backwards and stop as soon as the stage changes.
    let consecutive = sessions
        .iter()
        .rev()
        .filter(|s| s.source == LogSource::Detect)
        .take_while(|s| s.result_stage == Some(stage))
        .count();

    if consecutive >= 7 {
        out.push(finding(
            "stage-stall",
            DiagnosticSeverity::Error,
            &format!(
                "Device appears stuck at {} for {} consecutive detect runs",
                stage.label(),
                consecutive
            ),
            &format!(
                "{consecutive} consecutive Detect sessions all reported {}. \
                 This suggests a persistent blocker preventing progression.",
                stage.label()
            ),
            "Review recent detect and remediate logs for recurring errors. \
             Common causes: Windows Update delivery issues, payload corruption, \
             or a policy rollback. Consider re-running the full remediation \
             package.",
        ));
    } else if consecutive >= 3 {
        out.push(finding(
            "stage-stall",
            DiagnosticSeverity::Warning,
            &format!(
                "Device may be stalling at {} ({} consecutive detect runs)",
                stage.label(),
                consecutive
            ),
            &format!(
                "{consecutive} consecutive Detect sessions all reported {}.",
                stage.label()
            ),
            "Monitor the device. If it does not progress within the next \
             scheduled maintenance window, review Windows Update logs and \
             check whether the scheduled task is completing successfully.",
        ));
    }
}

// ---------------------------------------------------------------------------
// Remediation rules
// ---------------------------------------------------------------------------

/// R17 — Both payload folder AND scheduled task are missing.
fn rule_missing_cumulative_update(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    let no_payload = !state.payload_folder_exists.unwrap_or(true);
    let no_task = !state.scheduled_task_exists.unwrap_or(true);

    if no_payload && no_task {
        out.push(finding(
            "missing-cumulative-update",
            DiagnosticSeverity::Error,
            "Payload folder and scheduled task are both missing",
            "Neither the Secure Boot payload folder nor the scheduled task \
             was found. The required cumulative update may not have been \
             installed, or the deployment package was not applied.",
            "Verify that the device has received the required Windows cumulative \
             update via Windows Update or WSUS/WUfB. After the update is \
             installed, re-deploy the Intune remediation package.",
        ));
    }
}

/// R18 — Device is at Stage 4 (pending reboot) — a reboot is needed.
fn rule_reboot_needed(stage: SecureBootStage, out: &mut Vec<DiagnosticFinding>) {
    if stage == SecureBootStage::Stage4 {
        out.push(finding(
            "reboot-needed",
            DiagnosticSeverity::Warning,
            "Device is at Stage 4: a reboot is required to complete enrollment",
            "The Secure Boot certificate has been written to the UEFI database. \
             A reboot is the only remaining step to activate it.",
            "Schedule or prompt the user to reboot the device. Once rebooted, \
             the next detect run should report Stage 5 (Compliant).",
        ));
    }
}

/// R19 — Transient staging error 0x8007070E (device busy / locked).
fn rule_transient_staging_error(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if state.uefi_ca2023_error == Some(0x8007070E) {
        out.push(finding(
            "transient-staging-error",
            DiagnosticSeverity::Info,
            "Transient staging error 0x8007070E detected",
            "Error 0x8007070E (The pipe is being closed / device busy) was \
             returned during the Secure Boot certificate staging operation. \
             This is often transient.",
            "Wait for the next scheduled task execution and re-check. If the \
             error persists across multiple runs, collect full ETW logs and \
             escalate.",
        ));
    }
}

/// R20 — Payload is missing but WinCS is available (possible alternative path).
fn rule_missing_payload_with_wincs(
    state: &SecureBootScanState,
    out: &mut Vec<DiagnosticFinding>,
) {
    let no_payload = !state.payload_folder_exists.unwrap_or(true);
    let wincs = state.wincs_available == Some(true);

    if no_payload && wincs {
        out.push(finding(
            "missing-payload-with-wincs",
            DiagnosticSeverity::Info,
            "Payload is missing but Windows Certificate Services is available",
            "The payload folder was not found, however WinCS is available and \
             may be able to provision the certificate through an alternative \
             delivery path.",
            "Check whether the WinCS-based certificate delivery policy is \
             configured and whether the device is within scope. The payload \
             from Windows Update may not be required in this configuration.",
        ));
    }
}

/// R21 — Windows 10 is approaching / past end-of-life.
fn rule_windows_10_eol(state: &SecureBootScanState, out: &mut Vec<DiagnosticFinding>) {
    if let Some(caption) = &state.os_caption {
        if caption.contains("Windows 10") {
            out.push(finding(
                "windows-10-eol",
                DiagnosticSeverity::Warning,
                "Device is running Windows 10",
                &format!("OS: {caption}. Windows 10 reaches end of support in October 2025."),
                "Plan the upgrade to Windows 11 as soon as possible. \
                 Windows 10 will not receive security updates after the \
                 end-of-support date, which affects the long-term viability \
                 of this device's Secure Boot posture.",
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_state() -> SecureBootScanState {
        SecureBootScanState {
            secure_boot_enabled: Some(true),
            managed_opt_in: Some(0x5944),
            ..Default::default()
        }
    }

    #[test]
    fn secure_boot_disabled_produces_error() {
        let state = SecureBootScanState {
            secure_boot_enabled: Some(false),
            ..Default::default()
        };
        let findings = evaluate_all(&state, SecureBootStage::Stage0, &[]);
        assert!(findings.iter().any(|f| f.rule_id == "secure-boot-enabled"));
        assert!(findings
            .iter()
            .find(|f| f.rule_id == "secure-boot-enabled")
            .unwrap()
            .severity
            == DiagnosticSeverity::Error);
    }

    #[test]
    fn telemetry_level_zero_produces_error() {
        let mut state = default_state();
        state.telemetry_level = Some(0);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "telemetry-level"
                && f.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn diagtrack_stopped_produces_warning() {
        let mut state = default_state();
        state.diagtrack_running = Some(false);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "diagtrack-service"
                && f.severity == DiagnosticSeverity::Warning));
    }

    #[test]
    fn tpm_missing_produces_warning() {
        let mut state = default_state();
        state.tpm_present = Some(false);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "tpm-present" && f.severity == DiagnosticSeverity::Warning));
    }

    #[test]
    fn bitlocker_no_cloud_protector_produces_warning() {
        let mut state = default_state();
        state.bitlocker_protection_on = Some(true);
        state.bitlocker_key_protectors = vec!["TPM".to_string(), "RecoveryPassword".to_string()];
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "bitlocker-escrow"
                && f.severity == DiagnosticSeverity::Warning));
    }

    #[test]
    fn bitlocker_with_aad_protector_no_finding() {
        let mut state = default_state();
        state.bitlocker_protection_on = Some(true);
        state.bitlocker_key_protectors = vec!["AAD".to_string()];
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(!findings.iter().any(|f| f.rule_id == "bitlocker-escrow"));
    }

    #[test]
    fn mbr_disk_produces_error() {
        let mut state = default_state();
        state.disk_partition_style = Some("MBR".to_string());
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "disk-gpt" && f.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn missing_optin_produces_error() {
        let mut state = default_state();
        state.managed_opt_in = None;
        let findings = evaluate_all(&state, SecureBootStage::Stage1, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "optin-configured"
                && f.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn wrong_optin_value_produces_error() {
        let mut state = default_state();
        state.managed_opt_in = Some(0xDEAD);
        let findings = evaluate_all(&state, SecureBootStage::Stage1, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "optin-configured"
                && f.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn missing_payload_at_stage2_is_error() {
        let mut state = default_state();
        state.payload_folder_exists = Some(false);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "payload-present"
                && f.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn payload_checks_skipped_at_stage5() {
        let state = default_state(); // payload_folder_exists = None
        let findings = evaluate_all(&state, SecureBootStage::Stage5, &[]);
        assert!(!findings.iter().any(|f| f.rule_id == "payload-present"));
    }

    #[test]
    fn scheduled_task_missing_is_error() {
        let mut state = default_state();
        state.scheduled_task_exists = Some(false);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "scheduled-task-health"
                && f.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn scheduled_task_0x80070002_is_warning() {
        let mut state = default_state();
        state.scheduled_task_exists = Some(true);
        state.scheduled_task_last_result = Some("0x80070002".to_string());
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "scheduled-task-health"
                && f.severity == DiagnosticSeverity::Warning));
    }

    #[test]
    fn nonzero_error_code_produces_error() {
        let mut state = default_state();
        state.uefi_ca2023_error = Some(0x80070005);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "error-code-present"
                && f.severity == DiagnosticSeverity::Error));
    }

    #[test]
    fn zero_error_code_no_finding() {
        let mut state = default_state();
        state.uefi_ca2023_error = Some(0);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(!findings.iter().any(|f| f.rule_id == "error-code-present"));
    }

    #[test]
    fn stage4_pending_reboot_warning() {
        let mut state = default_state();
        state.pending_reboot_sources = vec!["WindowsUpdate".to_string()];
        let findings = evaluate_all(&state, SecureBootStage::Stage4, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "pending-reboot"
                && f.severity == DiagnosticSeverity::Warning));
    }

    #[test]
    fn stage_stall_warning_at_3() {
        use chrono::Utc;
        use crate::secureboot::models::{LogSession, LogSource};

        let make_session = |stage| LogSession {
            source: LogSource::Detect,
            started_at: Utc::now(),
            ended_at: None,
            result_stage: Some(stage),
            result_outcome: None,
            entries: vec![],
        };

        let sessions: Vec<LogSession> = (0..3)
            .map(|_| make_session(SecureBootStage::Stage2))
            .collect();

        let findings = evaluate_all(&default_state(), SecureBootStage::Stage2, &sessions);
        let stall = findings.iter().find(|f| f.rule_id == "stage-stall");
        assert!(stall.is_some());
        assert_eq!(stall.unwrap().severity, DiagnosticSeverity::Warning);
    }

    #[test]
    fn stage_stall_error_at_7() {
        use chrono::Utc;
        use crate::secureboot::models::{LogSession, LogSource};

        let make_session = |stage| LogSession {
            source: LogSource::Detect,
            started_at: Utc::now(),
            ended_at: None,
            result_stage: Some(stage),
            result_outcome: None,
            entries: vec![],
        };

        let sessions: Vec<LogSession> = (0..7)
            .map(|_| make_session(SecureBootStage::Stage3))
            .collect();

        let state = SecureBootScanState {
            secure_boot_enabled: Some(true),
            managed_opt_in: Some(0x5944),
            ..Default::default()
        };
        let findings = evaluate_all(&state, SecureBootStage::Stage3, &sessions);
        let stall = findings.iter().find(|f| f.rule_id == "stage-stall");
        assert!(stall.is_some());
        assert_eq!(stall.unwrap().severity, DiagnosticSeverity::Error);
    }

    #[test]
    fn findings_sorted_errors_first() {
        let mut state = default_state();
        state.secure_boot_enabled = Some(false); // Error
        state.diagtrack_running = Some(false); // Warning
        let findings = evaluate_all(&state, SecureBootStage::Stage0, &[]);
        // First finding must be Error
        assert_eq!(findings[0].severity, DiagnosticSeverity::Error);
    }

    #[test]
    fn windows_10_eol_warning() {
        let mut state = default_state();
        state.os_caption = Some("Microsoft Windows 10 Pro".to_string());
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "windows-10-eol"
                && f.severity == DiagnosticSeverity::Warning));
    }

    #[test]
    fn transient_error_0x8007070e_is_info() {
        let mut state = default_state();
        state.uefi_ca2023_error = Some(0x8007070E);
        let findings = evaluate_all(&state, SecureBootStage::Stage2, &[]);
        // error-code-present fires as Error, transient-staging-error fires as Info
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "transient-staging-error"
                && f.severity == DiagnosticSeverity::Info));
    }
}

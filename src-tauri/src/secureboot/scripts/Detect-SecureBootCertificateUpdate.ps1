<#
.SYNOPSIS
    Detects whether Windows devices have completed the Secure Boot certificate transition before June 2026 expiration.

.DESCRIPTION
    This detection script checks if devices have fully transitioned to the new Secure Boot certificates
    before the June 2026 expiration of Microsoft Corporation KEK CA 2011 and UEFI CA 2011.
    Microsoft Windows Production PCA 2011 expires in October 2026.
    
    The script uses a tiered compliance model:
    - Stage 0: Secure Boot disabled (exit 1)
    - Stage 1: MicrosoftUpdateManagedOptIn not configured (exit 1 - triggers remediation)
    - Stage 2: OptIn configured, awaiting Windows Update processing (exit 1)
    - Stage 3: Certificate updates in progress (exit 1)
    - Stage 4: CA2023 certificate in UEFI DB but not yet booting from it (exit 1)
    - Stage 5: COMPLIANT - Booting from 2023 signed boot manager (exit 0)
    
    A device is only considered compliant when WindowsUEFICA2023Capable equals 2,
    meaning the 2023 certificate is in the UEFI DB AND the device is booting from it.
    
    Fallback Timer: If a device has been opted in for more than FallbackDays days
    without reaching compliance, the detection output indicates that the fallback
    timer is active. The companion remediation script will then use the direct
    AvailableUpdates method (KB5025885) instead of waiting for Windows Update.
    
    Each detection run logs detailed diagnostic data locally including system uptime,
    TPM status, BitLocker state, Windows Update health, pending reboots, and a full
    Secure Boot registry dump. Stage-specific analysis explains WHY a device is
    non-compliant and WHAT needs to happen next.
    
    Exit codes:
    - 0: Compliant (booting from 2023 certificate chain)
    - 1: Non-compliant (requires remediation or waiting for Windows Update)

.PARAMETER FallbackDays
    Number of days to wait after managed opt-in before the remediation falls back to
    the direct AvailableUpdates method. Detection output includes fallback countdown.
    Default: 30

.PARAMETER TimestampRegPath
    Registry path where the ManagedOptInDate timestamp is stored by the remediation script.
    Default: HKLM:\SOFTWARE\Mindcore\Secureboot

.EXAMPLE
    .\Detect-SecureBootCertificateUpdate.ps1
    
    Checks the device for Secure Boot certificate update readiness and outputs tiered compliance status.

.EXAMPLE
    .\Detect-SecureBootCertificateUpdate.ps1 -FallbackDays 45 -TimestampRegPath "HKLM:\SOFTWARE\Contoso\Secureboot"
    
    Uses a 45-day fallback threshold and a custom registry path for the opt-in timestamp.

.NOTES
    Version:        4.0
    Author:         Mattias Melkersen
    Creation Date:  2026-01-15
    
    CHANGELOG
    ---------------
    2026-04-06 - v4.0 - Added SecureBootUpdates payload folder validation to diagnose task error 0x80070002 (MM)
                        Added scheduled task last-run-result inspection (Get-SecureBootTaskStatus helper)
                        Added UEFICA2023Status registry check written by WinCS
                        Added WinCsFlags.exe availability detection and /query output capture
                        Added UEFI DB firmware-level certificate verification via Get-SecureBootUEFI
                        Added Secure Boot event log harvesting (IDs 1036,1043,1044,1045,1801,1808)
                        Surfaced payload health, task result, WinCS availability in Write-Host output
    2026-04-05 - v3.1 - Buffered logging: accumulate entries in List[string], flush to disk once per run (MM)
                        Added Flush-Log function; Write-Log no longer calls Add-Content on every line
                        Moved Stage 5 compliance check before expensive diagnostic data collection
                        Compliant devices now exit immediately without querying TPM/BitLocker/WU/reboot
    2026-03-27 - v3.0 - Added configurable fallback timer with FallbackDays and TimestampRegPath parameters (MM)
                        Detection output now includes fallback countdown for non-compliant Stages 2-4
                        Added Get-FallbackStatus helper function to read ManagedOptInDate timestamp
    2026-02-19 - v2.2 - Fixed misleading "Updates:Not Configured" label when AvailableUpdates=0 (MM)
                        Suppress Updates detail from output when CA2023 cert is already in UEFI DB
    2026-02-18 - v2.1 - Enhanced local device logging with full diagnostic data for IT pro troubleshooting (MM)
                        Added: last boot time, TPM, BitLocker, WU health, pending reboot, registry dump
                        Added: stage-specific WHY/NEXT STEPS guidance in log output
    2026-02-18 - v2.0 - Tiered compliance: exit 0 only when booting from 2023 cert chain (MM)
                        Replaced Get-WmiObject with Get-CimInstance to fix Provider load failures
                        Remediation script made idempotent to avoid unnecessary registry writes
    2026-01-15 - v1.0 - Initial version for June 2026 certificate expiration preparation (MM)
    
    References:
    - https://aka.ms/getsecureboot
    - https://techcommunity.microsoft.com/blog/windows-itpro-blog/act-now-secure-boot-certificates-expire-in-june-2026/4426856
    - https://support.microsoft.com/topic/enterprise-deployment-guidance-for-cve-2023-24932-88b8f034-20b7-4a45-80cb-c6049b0f9967
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$FallbackDays = 30,

    [Parameter(Mandatory = $false)]
    [string]$TimestampRegPath = "HKLM:\SOFTWARE\Mindcore\Secureboot"
)

#region Logging Configuration
[string]$LogFile = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\SecureBootCertificateUpdate.log"
[string]$ScriptName = "DETECT"
[int]$MaxLogSizeMB = 4
$script:LogBuffer = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $script:LogBuffer.Add("$TimeStamp [$ScriptName] [$Level] $Message")
}

function Flush-Log {
    if ($script:LogBuffer.Count -eq 0) { return }
    try {
        $LogDir = Split-Path -Path $LogFile -Parent
        if (-not (Test-Path $LogDir)) {
            New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
        }
        if (Test-Path $LogFile) {
            $LogFileSizeMB = (Get-Item $LogFile).Length / 1MB
            if ($LogFileSizeMB -ge $MaxLogSizeMB) {
                $BackupLog = "$LogFile.old"
                if (Test-Path $BackupLog) {
                    Remove-Item -Path $BackupLog -Force -ErrorAction SilentlyContinue
                }
                Rename-Item -Path $LogFile -NewName $BackupLog -Force -ErrorAction SilentlyContinue
                $TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $script:LogBuffer.Insert(0, "$TimeStamp [SYSTEM] [INFO] Log rotated - Previous log archived to: $BackupLog")
            }
        }
        Add-Content -Path $LogFile -Value $script:LogBuffer.ToArray() -ErrorAction SilentlyContinue
        $script:LogBuffer.Clear()
    }
    catch {
        # Silently fail if logging doesn't work - don't break script execution
    }
}
#endregion

#region Functions
function Get-SecureBootStatus {
    try {
        $secureBootEnabled = Confirm-SecureBootUEFI
        return $secureBootEnabled
    }
    catch {
        # If Confirm-SecureBootUEFI fails, try registry method
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
            if (Test-Path $regPath) {
                $value = (Get-ItemProperty -Path $regPath -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue).UEFISecureBootEnabled
                return ($value -eq 1)
            }
        }
        catch {
            return $false
        }
    }
    return $false
}

function Get-AvailableUpdatesStatus {
    param([int]$Value)
    
    switch ($Value) {
        22852 { return "Not Started - All updates pending (0x5944)" }
        16384 { return "Complete - All certificates applied (0x4000)" }
        0     { return "No pending updates (0x0)" }
        default { return "In Progress (0x$($Value.ToString('X')))" }
    }
}

function Get-WindowsUEFICA2023Status {
    param([int]$Value)
    
    switch ($Value) {
        0 { return "Not in DB" }
        1 { return "In DB" }
        2 { return "In DB and booting from 2023 signed boot manager" }
        default { return "Unknown ($Value)" }
    }
}

function Get-FallbackStatus {
    param(
        [string]$RegPath,
        [int]$Threshold
    )
    
    $result = @{
        TimestampExists = $false
        OptInDate       = $null
        DaysElapsed     = 0
        DaysRemaining   = $Threshold
        IsActive        = $false
    }
    
    try {
        if (Test-Path $RegPath) {
            $dateStr = (Get-ItemProperty -Path $RegPath -Name "ManagedOptInDate" -ErrorAction SilentlyContinue).ManagedOptInDate
            if ($dateStr) {
                $parsed = [datetime]::Parse($dateStr)
                $elapsed = ((Get-Date) - $parsed).TotalDays
                $result.TimestampExists = $true
                $result.OptInDate = $parsed.ToString("yyyy-MM-dd HH:mm:ss")
                $result.DaysElapsed = [math]::Floor($elapsed)
                $result.DaysRemaining = [math]::Max(0, $Threshold - [math]::Floor($elapsed))
                $result.IsActive = ($elapsed -ge $Threshold)
            }
        }
    }
    catch {
        # If timestamp cannot be read, fallback is not active
    }
    
    return $result
}

function Get-SecureBootPayloadStatus {
    $payloadPath = "$env:SystemRoot\System32\SecureBootUpdates"
    $result = @{
        FolderExists  = $false
        FileCount     = 0
        Files         = @()
        HasBinFiles   = $false
        IsHealthy     = $false
    }

    try {
        if (Test-Path $payloadPath) {
            $result.FolderExists = $true
            $files = Get-ChildItem -Path $payloadPath -File -ErrorAction SilentlyContinue
            if ($files) {
                $result.FileCount = $files.Count
                $result.Files = $files | ForEach-Object { "$($_.Name) ($([math]::Round($_.Length / 1KB, 1))KB)" }
                $result.HasBinFiles = ($files | Where-Object { $_.Extension -eq '.bin' }).Count -gt 0
                $result.IsHealthy = $result.HasBinFiles
            }
        }
    }
    catch {
        # Non-critical - continue without payload info
    }

    return $result
}

function Get-SecureBootTaskStatus {
    $result = @{
        TaskExists     = $false
        LastRunTime    = $null
        LastTaskResult = $null
        NextRunTime    = $null
        ResultHex      = $null
        IsMissingFiles = $false
    }

    try {
        $task = Get-ScheduledTask -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -ErrorAction SilentlyContinue
        if ($task) {
            $result.TaskExists = $true
            $taskInfo = Get-ScheduledTaskInfo -TaskPath "\Microsoft\Windows\PI\" -TaskName "Secure-Boot-Update" -ErrorAction SilentlyContinue
            if ($taskInfo) {
                $result.LastRunTime = $taskInfo.LastRunTime
                $result.LastTaskResult = $taskInfo.LastTaskResult
                $result.ResultHex = "0x$($taskInfo.LastTaskResult.ToString('X'))"
                $result.NextRunTime = $taskInfo.NextRunTime
                # 0x80070002 = ERROR_FILE_NOT_FOUND - missing payload binaries
                $result.IsMissingFiles = ($taskInfo.LastTaskResult -eq 0x80070002)
            }
        }
    }
    catch {
        # Non-critical - continue without task info
    }

    return $result
}
#endregion

#region Main Detection Logic
try {
    Write-Log -Message "========== DETECTION STARTED ==========" -Level "INFO"
    Write-Log -Message "Script Version: 4.0" -Level "INFO"
    Write-Log -Message "Computer: $env:COMPUTERNAME | User: $env:USERNAME" -Level "INFO"
    Write-Log -Message "PowerShell: $($PSVersionTable.PSVersion) | Process: $(if ([Environment]::Is64BitProcess) {'64-bit'} else {'32-bit'})" -Level "INFO"
    
    # Check Secure Boot Status
    Write-Log -Message "Checking Secure Boot status..." -Level "INFO"
    $secureBootEnabled = Get-SecureBootStatus
    
    # -- Stage 0: Secure Boot must be enabled --
    if (-not $secureBootEnabled) {
        Write-Log -Message "Secure Boot is DISABLED - Cannot apply certificate updates" -Level "ERROR"
        Write-Log -Message "--- Stage 0 Diagnostics ---" -Level "INFO"
        $sbStatePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        if (Test-Path $sbStatePath) {
            $sbStateValue = (Get-ItemProperty -Path $sbStatePath -Name "UEFISecureBootEnabled" -ErrorAction SilentlyContinue).UEFISecureBootEnabled
            Write-Log -Message "  Firmware Mode: UEFI (SecureBoot State key exists)" -Level "INFO"
            Write-Log -Message "  UEFISecureBootEnabled: $sbStateValue" -Level "INFO"
            Write-Log -Message "  WHY: Device firmware supports Secure Boot but it is DISABLED in BIOS/UEFI settings" -Level "WARNING"
            Write-Log -Message "  NEXT STEPS: Enter BIOS/UEFI setup and enable Secure Boot under Security settings" -Level "WARNING"
        }
        else {
            Write-Log -Message "  Firmware Mode: Likely Legacy BIOS (SecureBoot State key does not exist)" -Level "WARNING"
            Write-Log -Message "  WHY: Legacy BIOS firmware does not support Secure Boot" -Level "ERROR"
            Write-Log -Message "  NEXT STEPS: Convert disk to GPT and switch firmware mode from Legacy to UEFI" -Level "ERROR"
            Write-Log -Message "  Reference: https://learn.microsoft.com/en-us/windows/deployment/mbr-to-gpt" -Level "INFO"
        }
        try {
            $osDisk = Get-Disk -Number 0 -ErrorAction SilentlyContinue
            if ($osDisk) {
                Write-Log -Message "  OS Disk Partition Style: $($osDisk.PartitionStyle)" -Level "INFO"
                if ($osDisk.PartitionStyle -eq "MBR") {
                    Write-Log -Message "  MBR disk detected - MBR2GPT conversion required before enabling UEFI mode" -Level "WARNING"
                }
            }
        }
        catch {
            Write-Log -Message "  OS Disk: Unable to determine partition style" -Level "WARNING"
        }
        try {
            $biosInfo = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
            if ($biosInfo) {
                Write-Log -Message "  BIOS Manufacturer: $($biosInfo.Manufacturer)" -Level "INFO"
                Write-Log -Message "  BIOS Version: $($biosInfo.SMBIOSBIOSVersion)" -Level "INFO"
                Write-Log -Message "  BIOS Release Date: $($biosInfo.ReleaseDate)" -Level "INFO"
            }
        }
        catch {}
        Write-Log -Message "--- End Stage 0 Diagnostics ---" -Level "INFO"
        Write-Host "SECURE_BOOT_DISABLED | Action: Enable Secure Boot in BIOS/UEFI"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 0 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        Flush-Log
        exit 1
    }
    Write-Log -Message "Secure Boot is ENABLED" -Level "SUCCESS"
    
    # -- Stage 1: MicrosoftUpdateManagedOptIn must be set --
    Write-Log -Message "Checking MicrosoftUpdateManagedOptIn registry key..." -Level "INFO"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    $regName = "MicrosoftUpdateManagedOptIn"
    
    $optInValue = $null
    if (Test-Path $regPath) {
        $optInValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
    }
    
    if ($null -eq $optInValue -or $optInValue -eq 0) {
        Write-Log -Message "MicrosoftUpdateManagedOptIn is NOT SET or 0 - Remediation required" -Level "WARNING"
        Write-Log -Message "--- Stage 1 Analysis ---" -Level "INFO"
        Write-Log -Message "  Registry Path: $regPath" -Level "INFO"
        Write-Log -Message "  Registry Path Exists: $(Test-Path $regPath)" -Level "INFO"
        Write-Log -Message "  Current Value: $(if ($null -eq $optInValue) {'<does not exist>'} else {"$optInValue (0x$($optInValue.ToString('X')))"})" -Level "INFO"
        Write-Log -Message "  Expected Value: 0x5944 (22852)" -Level "INFO"
        Write-Log -Message "  WHY: The registry key that enables Secure Boot certificate updates via Windows Update is not configured" -Level "INFO"
        Write-Log -Message "  NEXT STEPS: The remediation script will automatically set this value. No manual action required." -Level "INFO"
        Write-Log -Message "--- End Stage 1 Analysis ---" -Level "INFO"
        Write-Host "OPTIN_NOT_SET | Action: Remediation will configure registry"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 1 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        Flush-Log
        exit 1
    }
    Write-Log -Message "MicrosoftUpdateManagedOptIn is SET to 0x$($optInValue.ToString('X')) ($optInValue)" -Level "SUCCESS"
    
    # Check fallback timer status
    $fallback = Get-FallbackStatus -RegPath $TimestampRegPath -Threshold $FallbackDays
    if ($fallback.TimestampExists) {
        Write-Log -Message "Fallback Timer: OptIn date=$($fallback.OptInDate) | Elapsed=$($fallback.DaysElapsed)d | Threshold=$($FallbackDays)d | Remaining=$($fallback.DaysRemaining)d | Active=$($fallback.IsActive)" -Level "INFO"
    }
    else {
        Write-Log -Message "Fallback Timer: No ManagedOptInDate timestamp found (will be set by remediation script)" -Level "INFO"
    }
    
    # Check certificate deployment status
    Write-Log -Message "Checking certificate update deployment status..." -Level "INFO"
    $availableUpdates = (Get-ItemProperty -Path $regPath -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
    $servicingPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    $ca2023Capable = (Get-ItemProperty -Path $servicingPath -Name "WindowsUEFICA2023Capable" -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
    
    if ($null -ne $availableUpdates) {
        $updateStatus = Get-AvailableUpdatesStatus -Value $availableUpdates
        Write-Log -Message "AvailableUpdates: $updateStatus (0x$($availableUpdates.ToString('X')))" -Level "INFO"
    }
    else {
        Write-Log -Message "AvailableUpdates: Key not present (normal before Windows Update detection)" -Level "INFO"
    }
    
    if ($null -ne $ca2023Capable) {
        $ca2023Status = Get-WindowsUEFICA2023Status -Value $ca2023Capable
        Write-Log -Message "WindowsUEFICA2023Capable: $ca2023Status ($ca2023Capable)" -Level "INFO"
    }
    else {
        Write-Log -Message "WindowsUEFICA2023Capable: Key not present (normal before Windows Update processes)" -Level "INFO"
    }
    
    # Check UEFICA2023Status (written by WinCS when complete)
    $uefiCA2023Status = (Get-ItemProperty -Path $servicingPath -Name "UEFICA2023Status" -ErrorAction SilentlyContinue).UEFICA2023Status
    if ($null -ne $uefiCA2023Status) {
        Write-Log -Message "UEFICA2023Status: $uefiCA2023Status" -Level "INFO"
    }
    else {
        Write-Log -Message "UEFICA2023Status: Key not present (set by WinCS when cert update completes)" -Level "INFO"
    }
    
    # Build detail string for output (lightweight - no diagnostics needed)
    $detailParts = @("OptIn:0x$($optInValue.ToString('X'))")
    if ($null -ne $availableUpdates) {
        $updateStatus = Get-AvailableUpdatesStatus -Value $availableUpdates
        # Only include Updates detail if cert is not yet in DB (avoids confusion at Stage 4/5)
        if ($null -eq $ca2023Capable -or $ca2023Capable -lt 1) {
            $detailParts += "Updates:$updateStatus"
        }
    }
    if ($null -ne $ca2023Capable) {
        $ca2023Status = Get-WindowsUEFICA2023Status -Value $ca2023Capable
        $detailParts += "CA2023:$ca2023Status"
    }
    $details = $detailParts -join " | "
    
    # -- Stage 5: COMPLIANT - Booting from 2023 cert chain --
    # Check early to skip expensive diagnostic collection on compliant devices
    if ($ca2023Capable -eq 2) {
        Write-Log -Message "--- Stage 5: COMPLIANT ---" -Level "SUCCESS"
        Write-Log -Message "  Device is booting from the 2023-signed boot manager" -Level "SUCCESS"
        Write-Log -Message "  The Secure Boot certificate transition is complete for this device" -Level "SUCCESS"
        Write-Host "COMPLIANT | $details"
        Write-Log -Message "Detection Result: COMPLIANT - Stage 5 (exit 0)" -Level "SUCCESS"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        Flush-Log
        exit 0
    }
    
    # Check device attributes
    $deviceAttribPath = "$servicingPath\DeviceAttributes"
    if (Test-Path $deviceAttribPath) {
        $manufacturer = (Get-ItemProperty -Path $deviceAttribPath -Name "OEMManufacturerName" -ErrorAction SilentlyContinue).OEMManufacturerName
        $model = (Get-ItemProperty -Path $deviceAttribPath -Name "OEMModelNumber" -ErrorAction SilentlyContinue).OEMModelNumber
        $firmwareVersion = (Get-ItemProperty -Path $deviceAttribPath -Name "FirmwareVersion" -ErrorAction SilentlyContinue).FirmwareVersion
        $firmwareDate = (Get-ItemProperty -Path $deviceAttribPath -Name "FirmwareReleaseDate" -ErrorAction SilentlyContinue).FirmwareReleaseDate
        
        if ($manufacturer) { Write-Log -Message "Device Manufacturer: $manufacturer" -Level "INFO" }
        if ($model) { Write-Log -Message "Device Model: $model" -Level "INFO" }
        if ($firmwareVersion) { Write-Log -Message "Firmware Version: $firmwareVersion" -Level "INFO" }
        if ($firmwareDate) { Write-Log -Message "Firmware Release Date: $firmwareDate" -Level "INFO" }
    }
    
    # ===== DIAGNOSTIC DATA COLLECTION =====
    Write-Log -Message "---------- DIAGNOSTIC DATA ----------" -Level "INFO"
    
    # Secure Boot payload folder validation (diagnoses task error 0x80070002)
    Write-Log -Message "--- SecureBootUpdates Payload Check ---" -Level "INFO"
    $payload = Get-SecureBootPayloadStatus
    if ($payload.FolderExists) {
        Write-Log -Message "  Payload Folder: EXISTS ($env:SystemRoot\System32\SecureBootUpdates)" -Level "INFO"
        Write-Log -Message "  File Count: $($payload.FileCount)" -Level "INFO"
        if ($payload.FileCount -gt 0) {
            foreach ($f in $payload.Files) {
                Write-Log -Message "  File: $f" -Level "INFO"
            }
            if ($payload.HasBinFiles) {
                Write-Log -Message "  Payload Health: HEALTHY - .bin payload files present" -Level "SUCCESS"
            }
            else {
                Write-Log -Message "  Payload Health: WARNING - folder has files but no .bin payloads" -Level "WARNING"
            }
        }
        else {
            Write-Log -Message "  Payload Health: EMPTY - no files in payload folder" -Level "WARNING"
            Write-Log -Message "  This will cause the Secure-Boot-Update task to fail with 0x80070002" -Level "WARNING"
            Write-Log -Message "  FIX: Install the latest cumulative update, or use WinCsFlags.exe if available" -Level "WARNING"
        }
    }
    else {
        Write-Log -Message "  Payload Folder: MISSING ($env:SystemRoot\System32\SecureBootUpdates)" -Level "WARNING"
        Write-Log -Message "  This will cause the Secure-Boot-Update task to fail with 0x80070002" -Level "WARNING"
        Write-Log -Message "  FIX: Install the latest cumulative update, or use WinCsFlags.exe if available" -Level "WARNING"
    }
    Write-Log -Message "--- End Payload Check ---" -Level "INFO"
    
    # Scheduled task last-run-result inspection
    Write-Log -Message "--- Secure-Boot-Update Task Status ---" -Level "INFO"
    $taskStatus = Get-SecureBootTaskStatus
    if ($taskStatus.TaskExists) {
        Write-Log -Message "  Task: Found" -Level "INFO"
        if ($null -ne $taskStatus.LastRunTime -and $taskStatus.LastRunTime.Year -gt 2000) {
            Write-Log -Message "  Last Run: $($taskStatus.LastRunTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "INFO"
        }
        else {
            Write-Log -Message "  Last Run: Never" -Level "INFO"
        }
        Write-Log -Message "  Last Result: $($taskStatus.ResultHex) ($($taskStatus.LastTaskResult))" -Level "INFO"
        if ($taskStatus.IsMissingFiles) {
            Write-Log -Message "  ALERT: Task failed with 0x80070002 (ERROR_FILE_NOT_FOUND)" -Level "ERROR"
            Write-Log -Message "  ROOT CAUSE: Missing certificate payload files in SecureBootUpdates folder" -Level "ERROR"
            Write-Log -Message "  FIX: Install the latest cumulative update to restore payload files, or use WinCsFlags.exe" -Level "ERROR"
        }
        elseif ($taskStatus.LastTaskResult -ne 0) {
            Write-Log -Message "  WARNING: Task exited with non-zero result $($taskStatus.ResultHex)" -Level "WARNING"
        }
        else {
            Write-Log -Message "  Task result: Success (0x0)" -Level "SUCCESS"
        }
        if ($null -ne $taskStatus.NextRunTime -and $taskStatus.NextRunTime.Year -gt 2000) {
            Write-Log -Message "  Next Run: $($taskStatus.NextRunTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "INFO"
        }
    }
    else {
        Write-Log -Message "  Task: NOT FOUND (requires July 2024+ cumulative update)" -Level "WARNING"
    }
    Write-Log -Message "--- End Task Status ---" -Level "INFO"
    
    # WinCS (WinCsFlags.exe) availability check
    Write-Log -Message "--- WinCS Availability ---" -Level "INFO"
    $winCsPath = "$env:SystemRoot\System32\WinCsFlags.exe"
    $winCsAvailable = Test-Path $winCsPath
    if ($winCsAvailable) {
        Write-Log -Message "  WinCsFlags.exe: AVAILABLE ($winCsPath)" -Level "SUCCESS"
        try {
            $winCsOutput = & $winCsPath /query --key F33E0C8E002 2>&1
            $winCsOutputStr = ($winCsOutput | Out-String).Trim()
            foreach ($line in ($winCsOutputStr -split "`n")) {
                $trimmed = $line.Trim()
                if ($trimmed) {
                    Write-Log -Message "  WinCS: $trimmed" -Level "INFO"
                }
            }
        }
        catch {
            Write-Log -Message "  WinCS query failed: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    else {
        Write-Log -Message "  WinCsFlags.exe: NOT AVAILABLE (requires Oct/Nov 2025+ cumulative update)" -Level "INFO"
    }
    Write-Log -Message "--- End WinCS Availability ---" -Level "INFO"
    
    # UEFI DB firmware-level certificate verification
    Write-Log -Message "--- UEFI DB Certificate Verification ---" -Level "INFO"
    try {
        $dbBytes = (Get-SecureBootUEFI db -ErrorAction Stop).bytes
        $dbContent = [System.Text.Encoding]::ASCII.GetString($dbBytes)
        $hasCA2023InDB = $dbContent -match 'Windows UEFI CA 2023'
        if ($hasCA2023InDB) {
            Write-Log -Message "  UEFI DB: Windows UEFI CA 2023 certificate FOUND in firmware DB" -Level "SUCCESS"
        }
        else {
            Write-Log -Message "  UEFI DB: Windows UEFI CA 2023 certificate NOT FOUND in firmware DB" -Level "INFO"
        }
    }
    catch {
        Write-Log -Message "  UEFI DB: Unable to query firmware - $($_.Exception.Message)" -Level "WARNING"
    }
    Write-Log -Message "--- End UEFI DB Verification ---" -Level "INFO"
    
    # OS version and last boot time
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = $osInfo.Caption
    $osBuild = $osInfo.BuildNumber
    Write-Log -Message "OS: $osVersion (Build $osBuild)" -Level "INFO"
    
    if ($osVersion -like "*Windows 10*") {
        Write-Log -Message "WARNING: Windows 10 support ended October 2025. Consider upgrading to Windows 11 or ESU." -Level "WARNING"
    }
    
    $lastBoot = $osInfo.LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    Write-Log -Message "Last Boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss')) | Uptime: $([math]::Floor($uptime.TotalDays))d $($uptime.Hours)h $($uptime.Minutes)m" -Level "INFO"
    
    # TPM status
    try {
        $tpm = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
        if ($tpm) {
            Write-Log -Message "TPM: Present | Enabled: $($tpm.IsEnabled_InitialValue) | Activated: $($tpm.IsActivated_InitialValue) | Spec: $($tpm.SpecVersion)" -Level "INFO"
        }
        else {
            Write-Log -Message "TPM: Not found" -Level "WARNING"
        }
    }
    catch {
        Write-Log -Message "TPM: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # BitLocker status on OS drive
    try {
        $blVolume = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop
        if ($blVolume) {
            $blProtection = switch ($blVolume.ProtectionStatus) { 0 { "OFF" } 1 { "ON" } 2 { "UNKNOWN" } default { "Unknown ($($blVolume.ProtectionStatus))" } }
            $blConversion = switch ($blVolume.ConversionStatus) { 0 { "FullyDecrypted" } 1 { "FullyEncrypted" } 2 { "EncryptionInProgress" } 3 { "DecryptionInProgress" } 4 { "EncryptionPaused" } 5 { "DecryptionPaused" } default { "Unknown ($($blVolume.ConversionStatus))" } }
            Write-Log -Message "BitLocker ($env:SystemDrive): Protection=$blProtection | Status=$blConversion" -Level "INFO"
            if ($blProtection -eq "ON") {
                Write-Log -Message "BitLocker NOTE: Secure Boot cert changes may trigger BitLocker recovery key prompt on next reboot" -Level "WARNING"
            }
        }
        else {
            Write-Log -Message "BitLocker ($env:SystemDrive): Not encrypted or not available" -Level "INFO"
        }
    }
    catch {
        Write-Log -Message "BitLocker: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Windows Update service health
    try {
        $wuService = Get-Service -Name wuauserv -ErrorAction Stop
        Write-Log -Message "Windows Update Service: Status=$($wuService.Status) | StartType=$($wuService.StartType)" -Level "INFO"
        if ($wuService.Status -ne 'Running' -and $wuService.Status -ne 'Stopped') {
            Write-Log -Message "WU Service WARNING: Service is in unexpected state '$($wuService.Status)'" -Level "WARNING"
        }
    }
    catch {
        Write-Log -Message "Windows Update Service: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Last Windows Update scan and install times
    try {
        $autoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate -ErrorAction Stop
        $lastSearch = $autoUpdate.Results.LastSearchSuccessDate
        if ($lastSearch -and $lastSearch.Year -gt 2000) {
            $searchAge = (Get-Date) - $lastSearch
            Write-Log -Message "Last WU Scan: $($lastSearch.ToString('yyyy-MM-dd HH:mm:ss')) ($([math]::Floor($searchAge.TotalHours))h ago)" -Level "INFO"
            if ($searchAge.TotalDays -gt 7) {
                Write-Log -Message "WU Scan WARNING: Last successful scan was over 7 days ago" -Level "WARNING"
            }
        }
        else {
            Write-Log -Message "Last WU Scan: No successful scan on record" -Level "WARNING"
        }
        $lastInstall = $autoUpdate.Results.LastInstallationSuccessDate
        if ($lastInstall -and $lastInstall.Year -gt 2000) {
            Write-Log -Message "Last WU Install: $($lastInstall.ToString('yyyy-MM-dd HH:mm:ss'))" -Level "INFO"
        }
    }
    catch {
        Write-Log -Message "Windows Update COM: Unable to query - $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Pending reboot indicators
    $pendingRebootReasons = @()
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $pendingRebootReasons += "CBS-RebootPending"
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $pendingRebootReasons += "WU-RebootRequired"
    }
    $pfro = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue).PendingFileRenameOperations
    if ($pfro) {
        $pendingRebootReasons += "PendingFileRename"
    }
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting") {
        $pendingRebootReasons += "WU-PostRebootReporting"
    }
    if ($pendingRebootReasons.Count -gt 0) {
        Write-Log -Message "Pending Reboot: YES - Sources: $($pendingRebootReasons -join ', ')" -Level "WARNING"
    }
    else {
        Write-Log -Message "Pending Reboot: No pending reboot detected" -Level "INFO"
    }
    
    # Full Secure Boot registry dump
    Write-Log -Message "--- Secure Boot Registry Dump ---" -Level "INFO"
    $sbDumpPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Secureboot"
    if (Test-Path $sbDumpPath) {
        $sbDumpProps = Get-ItemProperty -Path $sbDumpPath -ErrorAction SilentlyContinue
        $sbDumpProps.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            if ($_.Value -is [int]) {
                Write-Log -Message "  Secureboot\$($_.Name) = $($_.Value) (0x$($_.Value.ToString('X')))" -Level "INFO"
            }
            elseif ($_.Value -is [byte[]]) {
                Write-Log -Message "  Secureboot\$($_.Name) = [byte[]] Length=$($_.Value.Length)" -Level "INFO"
            }
            else {
                Write-Log -Message "  Secureboot\$($_.Name) = $($_.Value)" -Level "INFO"
            }
        }
    }
    else {
        Write-Log -Message "  Secureboot key not found at $sbDumpPath" -Level "WARNING"
    }
    $sbServicingDump = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
    if (Test-Path $sbServicingDump) {
        $svcDumpProps = Get-ItemProperty -Path $sbServicingDump -ErrorAction SilentlyContinue
        $svcDumpProps.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
            if ($_.Value -is [int]) {
                Write-Log -Message "  Servicing\$($_.Name) = $($_.Value) (0x$($_.Value.ToString('X')))" -Level "INFO"
            }
            elseif ($_.Value -is [byte[]]) {
                Write-Log -Message "  Servicing\$($_.Name) = [byte[]] Length=$($_.Value.Length)" -Level "INFO"
            }
            else {
                Write-Log -Message "  Servicing\$($_.Name) = $($_.Value)" -Level "INFO"
            }
        }
    }
    else {
        Write-Log -Message "  SecureBoot\Servicing key does not exist (normal before WU processes cert updates)" -Level "INFO"
    }
    Write-Log -Message "--- End Registry Dump ---" -Level "INFO"
    
    # Secure Boot event log harvesting
    Write-Log -Message "--- Secure Boot Event Log ---" -Level "INFO"
    $sbEventIds = @(1036, 1043, 1044, 1045, 1801, 1808)
    try {
        $sbEvents = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Kernel-Boot/Operational', 'System'
            Id      = $sbEventIds
        } -MaxEvents 20 -ErrorAction SilentlyContinue
        if ($sbEvents -and $sbEvents.Count -gt 0) {
            $grouped = $sbEvents | Group-Object -Property Id
            foreach ($group in $grouped) {
                $latest = $group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
                $msgPreview = ($latest.Message -split "`n")[0]
                if ($msgPreview.Length -gt 120) { $msgPreview = $msgPreview.Substring(0, 120) + "..." }
                Write-Log -Message "  Event $($group.Name): Last=$($latest.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) Count=$($group.Count) [$msgPreview]" -Level "INFO"
            }
        }
        else {
            Write-Log -Message "  No Secure Boot events (IDs: $($sbEventIds -join ',')) found in recent logs" -Level "INFO"
        }
    }
    catch {
        Write-Log -Message "  Event Log query failed: $($_.Exception.Message)" -Level "WARNING"
    }
    Write-Log -Message "--- End Event Log ---" -Level "INFO"
    
    Write-Log -Message "---------- END DIAGNOSTIC DATA ----------" -Level "INFO"
    
    # -- Stages 2-4: Configured but not yet fully transitioned (all exit 1) --
    # The remediation script will see OptIn is already set and may trigger direct fallback.
    # Add payload, task, WinCS and fallback timer info to detail string for non-compliant stages
    if (-not $payload.IsHealthy) {
        $details += " | Payload:MISSING"
    }
    if ($taskStatus.TaskExists -and $taskStatus.IsMissingFiles) {
        $details += " | Task:0x80070002"
    }
    elseif ($taskStatus.TaskExists -and $taskStatus.LastTaskResult -eq 0) {
        $details += " | Task:OK"
    }
    if ($winCsAvailable) {
        $details += " | WinCS:Available"
    }
    if ($fallback.TimestampExists) {
        if ($fallback.IsActive) {
            $details += " | Fallback:ACTIVE($($fallback.DaysElapsed)d)"
        }
        else {
            $details += " | Fallback:$($fallback.DaysRemaining)d remaining"
        }
    }
    
    # Stage 4: CA2023 cert is in UEFI DB but device hasn't rebooted to use it yet
    if ($ca2023Capable -eq 1) {
        Write-Log -Message "--- Stage 4 Analysis ---" -Level "INFO"
        Write-Log -Message "  WHY: The Windows UEFI CA 2023 certificate has been written to the UEFI Secure Boot DB" -Level "INFO"
        Write-Log -Message "  WHY: but the device has not yet rebooted to load the new 2023-signed boot manager" -Level "INFO"
        Write-Log -Message "  Last Boot: $($lastBoot.ToString('yyyy-MM-dd HH:mm:ss')) ($([math]::Floor($uptime.TotalDays)) days, $($uptime.Hours)h ago)" -Level "INFO"
        if ($pendingRebootReasons.Count -gt 0) {
            Write-Log -Message "  Pending Reboot Detected: $($pendingRebootReasons -join ', ')" -Level "WARNING"
        }
        else {
            Write-Log -Message "  Pending Reboot: No reboot indicators found - a reboot is still required to activate the new boot manager" -Level "INFO"
        }
        Write-Log -Message "  NEXT STEPS: Reboot the device. After reboot, the boot manager will use the 2023 certificate chain." -Level "WARNING"
        Write-Log -Message "  NEXT STEPS: If the device has been rebooted recently and is still at Stage 4, check BitLocker recovery key availability." -Level "WARNING"
        if ($fallback.TimestampExists -and $fallback.IsActive) {
            Write-Log -Message "  FALLBACK: Timer exceeded ($($fallback.DaysElapsed)d > $($FallbackDays)d) - remediation will use direct method on next run" -Level "WARNING"
        }
        elseif ($fallback.TimestampExists) {
            Write-Log -Message "  FALLBACK: $($fallback.DaysRemaining) days until direct method fallback activates" -Level "INFO"
        }
        Write-Log -Message "--- End Stage 4 Analysis ---" -Level "INFO"
        Write-Host "CONFIGURED_CA2023_IN_DB | $details | Action: Reboot to complete transition"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 4 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        Flush-Log
        exit 1
    }
    
    # Stage 3: Certificate updates are actively being applied by Windows Update
    if ($null -ne $availableUpdates -and $availableUpdates -ne 0 -and $availableUpdates -ne 22852) {
        Write-Log -Message "--- Stage 3 Analysis ---" -Level "INFO"
        Write-Log -Message "  WHY: Windows Update is actively processing Secure Boot certificate updates" -Level "INFO"
        Write-Log -Message "  WHY: AvailableUpdates = 0x$($availableUpdates.ToString('X')) ($availableUpdates) indicates partial certificate deployment" -Level "INFO"
        Write-Log -Message "  WHY: Target value is 0x4000 (16384) = all certificates applied" -Level "INFO"
        if ($pendingRebootReasons.Count -gt 0) {
            Write-Log -Message "  Pending Reboot: $($pendingRebootReasons -join ', ') - a reboot may be required to continue WU processing" -Level "WARNING"
        }
        Write-Log -Message "  NEXT STEPS: Allow Windows Update to complete. This typically resolves after 1-2 quality update cycles." -Level "INFO"
        Write-Log -Message "  NEXT STEPS: If stuck here for >30 days, check Windows Update health and run 'usoclient StartScan'" -Level "WARNING"
        if ($fallback.TimestampExists -and $fallback.IsActive) {
            Write-Log -Message "  FALLBACK: Timer exceeded ($($fallback.DaysElapsed)d > $($FallbackDays)d) - remediation will use direct method on next run" -Level "WARNING"
        }
        elseif ($fallback.TimestampExists) {
            Write-Log -Message "  FALLBACK: $($fallback.DaysRemaining) days until direct method fallback activates" -Level "INFO"
        }
        Write-Log -Message "--- End Stage 3 Analysis ---" -Level "INFO"
        Write-Host "CONFIGURED_UPDATE_IN_PROGRESS | $details | Action: Waiting for Windows Update"
        Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 3 (exit 1)" -Level "WARNING"
        Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
        Flush-Log
        exit 1
    }
    
    # Stage 2: OptIn is set but Windows Update hasn't started processing yet
    Write-Log -Message "--- Stage 2 Analysis ---" -Level "INFO"
    Write-Log -Message "  WHY: MicrosoftUpdateManagedOptIn is set (0x$($optInValue.ToString('X'))) but Windows Update has not yet started certificate deployment" -Level "INFO"
    if ($null -eq $availableUpdates) {
        Write-Log -Message "  WHY: AvailableUpdates key does not exist yet - Windows Update has not scanned for Secure Boot cert updates" -Level "INFO"
    }
    else {
        Write-Log -Message "  WHY: AvailableUpdates = 0x$($availableUpdates.ToString('X')) ($availableUpdates) - waiting for WU to begin processing" -Level "INFO"
    }
    if ($null -eq $ca2023Capable) {
        Write-Log -Message "  WHY: WindowsUEFICA2023Capable key does not exist yet - normal before Windows Update processes" -Level "INFO"
    }
    else {
        Write-Log -Message "  WHY: WindowsUEFICA2023Capable = $ca2023Capable (0 = Not in DB)" -Level "INFO"
    }
    Write-Log -Message "  NEXT STEPS: Ensure device is connected to the internet and Windows Update service is running" -Level "INFO"
    Write-Log -Message "  NEXT STEPS: Certificate updates are delivered through cumulative quality updates" -Level "INFO"
    Write-Log -Message "  NEXT STEPS: If stuck here for >14 days, run 'usoclient StartScan' or check WU policy/WSUS configuration" -Level "WARNING"
    if ($fallback.TimestampExists -and $fallback.IsActive) {
        Write-Log -Message "  FALLBACK: Timer exceeded ($($fallback.DaysElapsed)d > $($FallbackDays)d) - remediation will use direct method on next run" -Level "WARNING"
    }
    elseif ($fallback.TimestampExists) {
        Write-Log -Message "  FALLBACK: $($fallback.DaysRemaining) days until direct method fallback activates" -Level "INFO"
    }
    Write-Log -Message "--- End Stage 2 Analysis ---" -Level "INFO"
    Write-Host "CONFIGURED_AWAITING_UPDATE | $details | Action: Waiting for Windows Update scan"
    Write-Log -Message "Detection Result: NON-COMPLIANT - Stage 2 (exit 1)" -Level "WARNING"
    Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
    Flush-Log
    exit 1
}
catch {
    Write-Log -Message "Unexpected error during detection: $($_.Exception.Message)" -Level "ERROR"
    Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-Host "ERROR: $($_.Exception.Message)"
    Write-Log -Message "Detection Result: ERROR (exit 1)" -Level "ERROR"
    Write-Log -Message "========== DETECTION COMPLETED ==========" -Level "INFO"
    Flush-Log
    exit 1
}
#endregion

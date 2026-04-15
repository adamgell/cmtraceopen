# Detection: WDAC CIP Files and Managed Installer Rules
# Deploy via Intune Proactive Remediation (Detection Script)
# Log: .cmtlog format via CmtLog module (CMTrace Open compatible)
#
# Detection surfaces (per Microsoft documentation):
#   - File system: CIP files, SiPolicy.p7b, ManagedInstaller.AppLocker (best MI indicator)
#   - CiTool.exe: policy enumeration (Win11 22H2+, most reliable)
#   - Registry: SrpV2\ManagedInstaller
#   - AppLocker cmdlets: supplementary only (unreliable for MDM/CSP-deployed policies)
#   - Service state: AppIdSvc (informational — must be running for MI to function)
#   - Smart App Control: exclusion check (informational — SAC masquerades as active WDAC)
#
# NOTE: Get-AppLockerPolicy only returns policies deployed via Group Policy or
#       Set-AppLockerPolicy -Merge. MDM/CSP-deployed policies are invisible to it.
#       Intune deploys MI via a hidden Proactive Remediation (ID: d78c1822-e082-491a-b3a7-4a701836481e),
#       not the AppLocker CSP. The Intune MI binary is MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE
#       (Rule GUID: 55932f09-04b8-44ec-8e2d-3fc736500c56, consistent across all tenants).

# Import CmtLog module from same directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Import-Module (Join-Path $scriptDir 'CmtLog.psm1') -Force

# Initialize log file
$logFile = Start-CmtLog -ScriptName 'Detect-WDACManagedInstaller.ps1' -Version '2.0.0' -FileName 'Detect-WDACManagedInstaller.cmtlog' -OutputPath (Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs')

$needsRemediation = $false
$reasons = [System.Collections.Generic.List[string]]::new()

# ============================================================================
# 1. Check for WDAC CIP files (multiple policy format)
# ============================================================================
Write-LogSection -Name 'CIP Files'
$ciPath = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'
Write-LogEntry -Value "Checking for WDAC CIP files in $ciPath" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles'
try {
    if (Test-Path -Path $ciPath) {
        $cipFiles = Get-ChildItem -Path $ciPath -Filter '*.cip' -ErrorAction SilentlyContinue
        if ($cipFiles) {
            $needsRemediation = $true
            $fileNames = ($cipFiles | ForEach-Object { $_.Name }) -join ', '
            $msg = "NEEDS REMEDIATION: Found $($cipFiles.Count) CIP file(s) in $ciPath [$fileNames]"
            Write-LogEntry -Value $msg -Severity 2 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:needs-remediation'
            $reasons.Add($msg)
        }
        else {
            $msg = "CLEAN: No CIP files found in $ciPath - directory exists but is empty"
            Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:clean'
            $reasons.Add($msg)
        }
    }
    else {
        $msg = "CLEAN: CIP policy directory does not exist ($ciPath) - no multiple-policy format in use"
        Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:clean'
        $reasons.Add($msg)
    }
}
catch {
    $msg = "ERROR: Unable to access $ciPath - $($_.Exception.Message)"
    Write-LogEntry -Value $msg -Severity 3 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:error'
    $reasons.Add($msg)
}

# ============================================================================
# 2. Check for legacy single-policy SiPolicy.p7b
# ============================================================================
Write-LogSection -Name 'SiPolicy'
$siPolicyPath = 'C:\Windows\System32\CodeIntegrity\SiPolicy.p7b'
Write-LogEntry -Value "Checking for legacy single-policy file at $siPolicyPath" -Severity 1 -Component 'SiPolicy' -Section 'SiPolicy'
try {
    if (Test-Path -Path $siPolicyPath) {
        $needsRemediation = $true
        $fileInfo = Get-Item -Path $siPolicyPath -ErrorAction SilentlyContinue
        $msg = "NEEDS REMEDIATION: Found legacy SiPolicy.p7b (Size: $($fileInfo.Length) bytes, Modified: $($fileInfo.LastWriteTime))"
        Write-LogEntry -Value $msg -Severity 2 -Component 'SiPolicy' -Section 'SiPolicy' -Tag 'result:needs-remediation'
        $reasons.Add($msg)
    }
    else {
        $msg = "CLEAN: No legacy SiPolicy.p7b found at $siPolicyPath"
        Write-LogEntry -Value $msg -Severity 1 -Component 'SiPolicy' -Section 'SiPolicy' -Tag 'result:clean'
        $reasons.Add($msg)
    }
}
catch {
    $msg = "ERROR: Unable to check $siPolicyPath - $($_.Exception.Message)"
    Write-LogEntry -Value $msg -Severity 3 -Component 'SiPolicy' -Section 'SiPolicy' -Tag 'result:error'
    $reasons.Add($msg)
}

# ============================================================================
# 3. Check for ManagedInstaller.AppLocker file (best MI indicator)
#    This file is created by AppIdSvc when MI rules are active — its presence
#    is the single most authoritative indicator that Managed Installer is configured.
# ============================================================================
Write-LogSection -Name 'ManagedInstaller.AppLocker'
$miAppLockerPath = "$env:windir\System32\AppLocker\ManagedInstaller.AppLocker"
Write-LogEntry -Value "Checking for ManagedInstaller.AppLocker at $miAppLockerPath" -Severity 1 -Component 'MIAppLocker' -Section 'MIAppLocker'
try {
    if (Test-Path -Path $miAppLockerPath) {
        $needsRemediation = $true
        $fileInfo = Get-Item -Path $miAppLockerPath -ErrorAction SilentlyContinue
        $msg = "NEEDS REMEDIATION: ManagedInstaller.AppLocker found (Size: $($fileInfo.Length) bytes, Modified: $($fileInfo.LastWriteTime)) - Managed Installer is actively configured"
        Write-LogEntry -Value $msg -Severity 2 -Component 'MIAppLocker' -Section 'MIAppLocker' -Tag 'result:needs-remediation'
        $reasons.Add($msg)
    }
    else {
        $msg = "CLEAN: ManagedInstaller.AppLocker not found at $miAppLockerPath - Managed Installer is not configured"
        Write-LogEntry -Value $msg -Severity 1 -Component 'MIAppLocker' -Section 'MIAppLocker' -Tag 'result:clean'
        $reasons.Add($msg)
    }
}
catch {
    $msg = "ERROR: Unable to check $miAppLockerPath - $($_.Exception.Message)"
    Write-LogEntry -Value $msg -Severity 3 -Component 'MIAppLocker' -Section 'MIAppLocker' -Tag 'result:error'
    $reasons.Add($msg)
}

# ============================================================================
# 4. CiTool policy enumeration (Win11 22H2+ — most reliable detection method)
#    Enumerates all active CI policies. Filters to user-deployed (non-platform)
#    policies that are currently enforced/loaded.
# ============================================================================
Write-LogSection -Name 'CiTool Enumeration'
Write-LogEntry -Value "Checking for CiTool.exe to enumerate active CI policies" -Severity 1 -Component 'CiTool' -Section 'CiTool'
if (Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue) {
    try {
        $ciToolJson = CiTool.exe -lp -json 2>&1
        $ciPolicies = ($ciToolJson | ConvertFrom-Json).Policies
        # Filter to user-deployed policies (PlatformPolicy=False means not a Microsoft system policy)
        $userPolicies = @($ciPolicies | Where-Object { $_.IsEnforced -eq 'True' -and $_.PlatformPolicy -eq 'False' })
        if ($userPolicies.Count -gt 0) {
            $needsRemediation = $true
            $policyList = ($userPolicies | ForEach-Object { "$($_.FriendlyName) [$($_.PolicyID)]" }) -join ', '
            $msg = "NEEDS REMEDIATION: $($userPolicies.Count) user-deployed CI policy(ies) active via CiTool: $policyList"
            Write-LogEntry -Value $msg -Severity 2 -Component 'CiTool' -Section 'CiTool' -Tag 'result:needs-remediation'
            $reasons.Add($msg)
        }
        else {
            $platformCount = @($ciPolicies | Where-Object { $_.PlatformPolicy -eq 'True' }).Count
            $msg = "CLEAN: No user-deployed CI policies active ($platformCount platform policy(ies) present)"
            Write-LogEntry -Value $msg -Severity 1 -Component 'CiTool' -Section 'CiTool' -Tag 'result:clean'
            $reasons.Add($msg)
        }
    }
    catch {
        $msg = "ERROR: CiTool enumeration failed - $($_.Exception.Message)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'CiTool' -Section 'CiTool' -Tag 'result:error'
        $reasons.Add($msg)
    }
}
else {
    $msg = "INFO: CiTool.exe not available (requires Win11 22H2+) - skipping CI policy enumeration"
    Write-LogEntry -Value $msg -Severity 1 -Component 'CiTool' -Section 'CiTool' -Tag 'result:skipped'
    $reasons.Add($msg)
}

# ============================================================================
# 5. AppLocker supplementary check for Managed Installer rules
#    WARNING: Get-AppLockerPolicy is unreliable for MDM/CSP-deployed policies.
#    It only returns policies deployed via Group Policy or Set-AppLockerPolicy -Merge.
#    Kept as supplementary confirmation; do not rely on this as sole detection.
#    Intune MI binary: MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE
#    (not IntuneMdmAgent.exe — that name was incorrect)
# ============================================================================
Write-LogSection -Name 'AppLocker Policy'
Write-LogEntry -Value "Querying AppLocker for MI rules (supplementary - unreliable for MDM-deployed policies)" -Severity 1 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy'
try {
    $effectivePolicyXml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
    $miRuleCollection = $effectivePolicyXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'ManagedInstaller' }
    if ($miRuleCollection) {
        $needsRemediation = $true
        # Check for Intune's specific MI binary (correct name per Microsoft documentation)
        $intuneAgent = $miRuleCollection.FilePublisherRule.Conditions.FilePublisherCondition |
        Where-Object { $_.BinaryName -eq 'MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE' }
        if ($intuneAgent) {
            $msg = "NEEDS REMEDIATION: Intune MI binary (MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE) found in AppLocker ManagedInstaller rules"
        }
        else {
            $ruleCount = @($miRuleCollection.FilePublisherRule).Count
            $binaryNames = @($miRuleCollection.FilePublisherRule.Conditions.FilePublisherCondition | ForEach-Object { $_.BinaryName }) -join ', '
            $msg = "NEEDS REMEDIATION: ManagedInstaller rule collection found ($ruleCount rule(s), binaries: [$binaryNames]) - may be custom/SCCM MI configuration"
        }
        Write-LogEntry -Value $msg -Severity 2 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy' -Tag 'result:needs-remediation'
        $reasons.Add($msg)
    }
    else {
        $msg = "CLEAN: No ManagedInstaller rule collection in effective AppLocker (note: MDM-deployed policies may not appear here)"
        Write-LogEntry -Value $msg -Severity 1 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy' -Tag 'result:clean'
        $reasons.Add($msg)
    }
}
catch {
    $msg = "ERROR: Unable to query AppLocker policy - $($_.Exception.Message)"
    Write-LogEntry -Value $msg -Severity 3 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy' -Tag 'result:error'
    $reasons.Add($msg)
}

# ============================================================================
# 6. Check for Managed Installer configuration in AppLocker SrpV2 registry
# ============================================================================
Write-LogSection -Name 'MI Registry'
$miRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\ManagedInstaller'
Write-LogEntry -Value "Checking Managed Installer registry configuration at $miRegPath" -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry'
try {
    if (Test-Path -Path $miRegPath) {
        $miRegKeys = Get-ChildItem -Path $miRegPath -ErrorAction SilentlyContinue
        if ($miRegKeys) {
            $needsRemediation = $true
            $keyNames = ($miRegKeys | ForEach-Object { $_.PSChildName }) -join ', '
            $msg = "NEEDS REMEDIATION: Managed Installer registry rules found at $miRegPath - $($miRegKeys.Count) rule(s): [$keyNames]"
            Write-LogEntry -Value $msg -Severity 2 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:needs-remediation'
            $reasons.Add($msg)
        }
        else {
            $msg = "CLEAN: Managed Installer registry path exists but contains no rule subkeys at $miRegPath"
            Write-LogEntry -Value $msg -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:clean'
            $reasons.Add($msg)
        }
    }
    else {
        $msg = "CLEAN: Managed Installer registry path does not exist ($miRegPath) - no MI registry configuration present"
        Write-LogEntry -Value $msg -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:clean'
        $reasons.Add($msg)
    }
}
catch {
    $msg = "ERROR: Unable to check Managed Installer registry - $($_.Exception.Message)"
    Write-LogEntry -Value $msg -Severity 3 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:error'
    $reasons.Add($msg)
}

# ============================================================================
# 7. AppIdSvc service state (informational — does not trigger remediation)
#    AppIdSvc + AppLockerFltr must both be running for MI to function.
#    If MI artifacts are present but AppIdSvc is stopped, MI is broken.
# ============================================================================
Write-LogSection -Name 'AppIdSvc Service'
Write-LogEntry -Value "Checking AppIdSvc (Application Identity) service state" -Severity 1 -Component 'AppIdSvc' -Section 'AppIdSvc'
try {
    $appIdSvc = Get-Service -Name AppIDSvc -ErrorAction Stop
    $msg = "INFO: AppIdSvc service: Status=$($appIdSvc.Status), StartType=$($appIdSvc.StartType) - must be Running for MI to function"
    if ($appIdSvc.Status -eq 'Running') {
        Write-LogEntry -Value $msg -Severity 1 -Component 'AppIdSvc' -Section 'AppIdSvc' -Tag 'status:running'
    }
    else {
        Write-LogEntry -Value $msg -Severity 2 -Component 'AppIdSvc' -Section 'AppIdSvc' -Tag 'status:stopped'
    }
    $reasons.Add($msg)
}
catch {
    $msg = "INFO: AppIdSvc service not found or inaccessible - $($_.Exception.Message)"
    Write-LogEntry -Value $msg -Severity 1 -Component 'AppIdSvc' -Section 'AppIdSvc'
    $reasons.Add($msg)
}

# ============================================================================
# 8. Smart App Control state (informational — does not trigger remediation)
#    SAC is itself a WDAC policy and will appear in CiTool/WMI as an active
#    enforced policy. Checking its state avoids false-positive cleanup triggers.
#    Values: 0=Off, 1=Enforce, 2=Evaluation
# ============================================================================
Write-LogSection -Name 'Smart App Control'
Write-LogEntry -Value "Checking Smart App Control state (avoid false WDAC positives)" -Severity 1 -Component 'SmartAppControl' -Section 'SmartAppControl'
try {
    $sacReg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name 'VerifiedAndReputablePolicyState' -ErrorAction Stop
    $sacState = $sacReg.VerifiedAndReputablePolicyState
    switch ($sacState) {
        0 { $sacDesc = 'Off' }
        1 { $sacDesc = 'Enforce' }
        2 { $sacDesc = 'Evaluation' }
        default { $sacDesc = "Unknown ($sacState)" }
    }
    $msg = "INFO: Smart App Control: $sacDesc (state=$sacState) - if active, some CI indicators may reflect SAC rather than custom WDAC"
    Write-LogEntry -Value $msg -Severity 1 -Component 'SmartAppControl' -Section 'SmartAppControl' -Tag "sac:$sacDesc"
    $reasons.Add($msg)
}
catch {
    $msg = "INFO: Smart App Control registry key not found - SAC not configured or not available on this OS version"
    Write-LogEntry -Value $msg -Severity 1 -Component 'SmartAppControl' -Section 'SmartAppControl'
    $reasons.Add($msg)
}

# ============================================================================
# Summary — log full detail, truncate Write-Output for Intune's 2048 char limit
# ============================================================================
Write-LogSection -Name 'Summary'
$fullDetail = $reasons -join '; '
Write-LogEntry -Value "Detection complete: $fullDetail" -Severity 1 -Component 'Detect-WDAC' -Section 'Summary'

if ($needsRemediation) {
    $summary = "CI cleanup required: $fullDetail"
    if ($summary.Length -gt 2000) {
        $summary = $summary.Substring(0, 1997) + '...'
    }
    Write-LogEntry -Value $summary -Severity 2 -Component 'Detect-WDAC' -Section 'Summary' -Tag 'result:needs-remediation'
    Write-Output $summary
    exit 1
}
else {
    $summary = "CI is clean: $fullDetail"
    if ($summary.Length -gt 2000) {
        $summary = $summary.Substring(0, 1997) + '...'
    }
    Write-LogEntry -Value $summary -Severity 1 -Component 'Detect-WDAC' -Section 'Summary' -Tag 'result:clean'
    Write-Output $summary
    exit 0
}

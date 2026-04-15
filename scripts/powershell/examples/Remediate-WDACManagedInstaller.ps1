# Remediation: WDAC CIP Files and Managed Installer Rules
# Deploy via Intune Proactive Remediation (Remediation Script)
#
# Usage:
#   .\Remediate-WDACManagedInstaller.ps1              # Execute remediation
#   .\Remediate-WDACManagedInstaller.ps1 -WhatIf      # Dry-run — no changes made
#   .\Remediate-WDACManagedInstaller.ps1 -Confirm      # Prompt before each action
#   .\Remediate-WDACManagedInstaller.ps1 -SkipCIPRemoval  # Skip CIP file deletion
#
# WhatIf also engages when $WhatIfPreference = $true in the calling scope.
# Log: .cmtlog format via CmtLog module (CMTrace Open compatible)
#
# Remediation surfaces (aligned with detection):
#   1. CIP files — backup to C:\Windows\Temp\CIPBackup then remove
#   2. SiPolicy.p7b — remove legacy single-policy file
#   3. ManagedInstaller.AppLocker — backup and remove (best MI indicator)
#   4. AppLocker local policy — remove MI rules via Set-AppLockerPolicy
#   5. SrpV2 registry — remove MI configuration
#   6. Post-remediation verification — CiTool, AppLocker, file-system checks
#   7. CiTool refresh — force Code Integrity to reload policies
#
# NOTE: GPO/MDM-delivered MI policies cannot be removed locally. Those are
#       flagged as warnings in the verification step.

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$SkipCIPRemoval
)

# Import CmtLog module from same directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Import-Module (Join-Path $scriptDir 'CmtLog.psm1') -Force

# Initialize log file
$logFile = Start-CmtLog -ScriptName 'Remediate-WDACManagedInstaller.ps1' -Version '2.0.0' -FileName 'Remediate-WDACManagedInstaller.cmtlog' -OutputPath (Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs')

function Invoke-CiToolWithTimeout {
    # Runs CiTool.exe with a timeout to prevent hangs. Returns a hashtable
    # with ExitCode (-1 = timeout/error), Output, and TimedOut boolean.
    param (
        [parameter(Mandatory = $true)]
        [string]$Arguments,
        [int]$TimeoutSeconds = 30
    )
    $result = @{ ExitCode = -1; Output = ''; TimedOut = $false }
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = 'CiTool.exe'
        $psi.Arguments = $Arguments
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        # Read streams asynchronously so ReadToEnd() can't block before timeout
        $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
        $stderrTask = $proc.StandardError.ReadToEndAsync()
        $exited = $proc.WaitForExit($TimeoutSeconds * 1000)
        if (-not $exited) {
            try { $proc.Kill() } catch { }
            $result.TimedOut = $true
            $partial = if ($stdoutTask.IsCompleted) { $stdoutTask.Result } else { '' }
            $result.Output = "TIMEOUT after ${TimeoutSeconds}s. Partial stdout: $partial"
        }
        else {
            $result.ExitCode = $proc.ExitCode
            $stdout = $stdoutTask.Result
            $stderr = $stderrTask.Result
            $combined = ($stdout, $stderr | Where-Object { $_ }) -join ' '
            $result.Output = $combined.Trim()
        }
    }
    catch {
        $result.Output = "Process error: $($_.Exception.Message)"
    }
    return $result
}

function Invoke-WDACRemediation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$SkipCIPRemoval
    )

    $actions = [System.Collections.Generic.List[string]]::new()
    $modeLabel = if ($WhatIfPreference) { '[WhatIf] ' } else { '' }
    $changesApplied = $false  # Track whether any remediation actions were taken

    Write-LogEntry -Value "${modeLabel}=== Starting WDAC + Managed Installer remediation ===" -Severity 1 -Component 'Remediate-WDAC' -Tag 'phase:start'

    # ========================================================================
    # Pre-flight: Verify execution context and permissions
    #   CIP files are owned by TrustedInstaller — even elevated local admins
    #   cannot delete them without taking ownership first. The script will use
    #   CiTool --remove-policy (preferred) or takeown/icacls as a fallback.
    # ========================================================================
    Write-LogSection -Name 'Pre-flight'
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $currentIdentity.IsSystem
    $isAdmin = ([Security.Principal.WindowsPrincipal]$currentIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $hasCiTool = [bool](Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue)
    Write-LogEntry -Value "Execution context: User=$($currentIdentity.Name), IsSystem=$isSystem, IsAdmin=$isAdmin, CiTool=$hasCiTool" -Severity 1 -Component 'Preflight' -Section 'Preflight'

    if (-not $isAdmin) {
        $msg = "ERROR: Script requires at minimum Administrator privileges. Current user: $($currentIdentity.Name)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'Preflight' -Section 'Preflight' -Tag 'result:error'
        Write-Output $msg
        return
    }

    if (-not $isSystem -and -not $hasCiTool) {
        $msg = "WARNING: Running as $($currentIdentity.Name) (not SYSTEM) without CiTool. CIP files are owned by TrustedInstaller and will require takeown/icacls to remove."
        Write-LogEntry -Value $msg -Severity 2 -Component 'Preflight' -Section 'Preflight' -Tag 'result:warning'
        $actions.Add($msg)
    }

    # Track CiTool health — if any call times out, skip all subsequent CiTool calls
    $ciToolBroken = $false

    # ========================================================================
    # 1. Backup and remove all WDAC CIP files (multiple policy format)
    #    Strategy: CiTool --remove-policy (preferred, Win11 22H2+)
    #              then verify files are gone and fall back to takeown+delete
    #              for any remaining files.
    #    CIP files are owned by TrustedInstaller — Remove-Item alone will fail
    #    even for elevated admins. takeown + icacls grants delete permission.
    # ========================================================================
    Write-LogSection -Name 'CIP Files'
    $ciPath = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'
    $backupPath = 'C:\Windows\Temp\CIPBackup'
    if ($SkipCIPRemoval) {
        $msg = "SKIP: CIP file removal skipped (-SkipCIPRemoval flag set)"
        Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:skip'
        $actions.Add($msg)
    }
    else {
        Write-LogEntry -Value "${modeLabel}Checking for WDAC CIP files in $ciPath (backup destination: $backupPath)" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles'
        try {
            if (Test-Path -Path $ciPath) {
                $cipFiles = Get-ChildItem -Path $ciPath -Filter '*.cip' -ErrorAction SilentlyContinue
                if ($cipFiles) {
                    $fileNames = ($cipFiles | ForEach-Object { $_.Name }) -join ', '
                    Write-LogEntry -Value "${modeLabel}Found $($cipFiles.Count) CIP file(s) to process: [$fileNames]" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles'

                    # Create backup directory
                    if ($PSCmdlet.ShouldProcess($backupPath, 'Create CIP backup directory')) {
                        if (-not (Test-Path -Path $backupPath)) {
                            New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
                            Write-LogEntry -Value "Created backup directory: $backupPath" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles'
                        }
                    }

                    # Backup all CIP files first (read access works for admins)
                    $cipIndex = 0
                    foreach ($file in $cipFiles) {
                        $cipIndex++
                        Write-LogIteration -Name 'CIP backup' -Current $cipIndex -Total $cipFiles.Count
                        if ($PSCmdlet.ShouldProcess($file.FullName, 'Backup CIP file')) {
                            Copy-Item -Path $file.FullName -Destination $backupPath -Force -ErrorAction Stop
                            Write-LogEntry -Value "Backed up $($file.Name) to $backupPath" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Iteration "$cipIndex/$($cipFiles.Count)"
                        }
                    }

                    # Phase 1: Try CiTool --remove-policy for each policy (proper API)
                    if ($hasCiTool -and -not $ciToolBroken) {
                        $cipIndex = 0
                        foreach ($file in $cipFiles) {
                            $cipIndex++
                            if ($ciToolBroken) {
                                Write-LogEntry -Value "Skipping CiTool for $($file.BaseName) - CiTool marked broken after previous timeout" -Severity 2 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:skip'
                                break
                            }
                            # CIP filename = {PolicyGUID}.cip
                            $policyGuid = $file.BaseName
                            Write-LogIteration -Name 'CiTool remove' -Current $cipIndex -Total $cipFiles.Count
                            if ($PSCmdlet.ShouldProcess("Policy $policyGuid", 'Remove via CiTool --remove-policy')) {
                                Write-LogEntry -Value "Removing policy $policyGuid via CiTool --remove-policy (30s timeout)" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Iteration "$cipIndex/$($cipFiles.Count)"
                                $ciResult = Invoke-CiToolWithTimeout -Arguments "--remove-policy $policyGuid" -TimeoutSeconds 30
                                if ($ciResult.TimedOut) {
                                    $ciToolBroken = $true
                                    Write-LogEntry -Value "CiTool TIMED OUT for $policyGuid - $($ciResult.Output) - marking CiTool broken, skipping remaining CiTool calls" -Severity 2 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:timeout'
                                    $actions.Add("WARNING: CiTool timed out for $policyGuid - all subsequent CiTool calls skipped")
                                }
                                elseif ($ciResult.ExitCode -eq 0) {
                                    $msg = "SUCCESS: Removed policy $policyGuid via CiTool - $($ciResult.Output)"
                                    Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:ok'
                                    $actions.Add($msg)
                                    $changesApplied = $true
                                }
                                else {
                                    Write-LogEntry -Value "CiTool failed for $policyGuid (exit $($ciResult.ExitCode): $($ciResult.Output)) - will try file-level removal" -Severity 2 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:fallback'
                                }
                            }
                            else {
                                $msg = "${modeLabel}Would remove policy $policyGuid via CiTool --remove-policy"
                                Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -WhatIfEntry
                                $actions.Add($msg)
                            }
                        }
                    }

                    # Phase 2: Remove any remaining CIP files via takeown + icacls + delete
                    $remainingFiles = Get-ChildItem -Path $ciPath -Filter '*.cip' -ErrorAction SilentlyContinue
                    if ($remainingFiles -and -not $WhatIfPreference) {
                        Write-LogEntry -Value "$($remainingFiles.Count) CIP file(s) remain after CiTool pass - attempting takeown/icacls removal" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles'
                        $remIndex = 0
                        foreach ($file in $remainingFiles) {
                            $remIndex++
                            Write-LogIteration -Name 'takeown removal' -Current $remIndex -Total $remainingFiles.Count
                            if ($PSCmdlet.ShouldProcess($file.FullName, 'Take ownership and remove CIP file')) {
                                try {
                                    # Take ownership from TrustedInstaller
                                    $takeownOut = & takeown.exe /F $file.FullName 2>&1
                                    Write-LogEntry -Value "takeown $($file.Name): $takeownOut" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Iteration "$remIndex/$($remainingFiles.Count)"
                                    # Grant Administrators full control
                                    $icaclsOut = & icacls.exe $file.FullName /grant 'Administrators:F' 2>&1
                                    Write-LogEntry -Value "icacls $($file.Name): $icaclsOut" -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Iteration "$remIndex/$($remainingFiles.Count)"
                                    # Now delete
                                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                                    $msg = "SUCCESS: Removed $($file.Name) via takeown/icacls/delete"
                                    Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:ok'
                                    $actions.Add($msg)
                                    $changesApplied = $true
                                }
                                catch {
                                    $msg = "ERROR: Failed to remove $($file.Name) even with takeown/icacls - $($_.Exception.Message)"
                                    Write-LogEntry -Value $msg -Severity 3 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:error'
                                    $actions.Add($msg)
                                }
                            }
                        }
                    }
                    elseif ($WhatIfPreference -and -not $hasCiTool) {
                        foreach ($file in $cipFiles) {
                            $msg = "${modeLabel}Would takeown/icacls/delete $($file.Name) from $ciPath"
                            Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -WhatIfEntry
                            $actions.Add($msg)
                        }
                    }
                }
                else {
                    $msg = "${modeLabel}SKIP: No CIP files found in $ciPath - directory exists but is empty"
                    Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:skip'
                    $actions.Add($msg)
                }
            }
            else {
                $msg = "${modeLabel}SKIP: CIP policy directory does not exist ($ciPath) - no multiple-policy format in use"
                Write-LogEntry -Value $msg -Severity 1 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:skip'
                $actions.Add($msg)
            }
        }
        catch {
            $msg = "ERROR: Failed to process CIP files - $($_.Exception.Message)"
            Write-LogEntry -Value $msg -Severity 3 -Component 'CIPFiles' -Section 'CIPFiles' -Tag 'result:error'
            $actions.Add($msg)
        }
    } # end else (not SkipCIPRemoval)

    # ========================================================================
    # 2. Remove legacy SiPolicy.p7b if present
    # ========================================================================
    Write-LogSection -Name 'SiPolicy'
    $siPolicyPath = 'C:\Windows\System32\CodeIntegrity\SiPolicy.p7b'
    Write-LogEntry -Value "${modeLabel}Checking for legacy single-policy file at $siPolicyPath" -Severity 1 -Component 'SiPolicy' -Section 'SiPolicy'
    try {
        if (Test-Path -Path $siPolicyPath) {
            $fileInfo = Get-Item -Path $siPolicyPath -ErrorAction SilentlyContinue
            Write-LogEntry -Value "${modeLabel}Found legacy SiPolicy.p7b (Size: $($fileInfo.Length) bytes, Modified: $($fileInfo.LastWriteTime))" -Severity 1 -Component 'SiPolicy' -Section 'SiPolicy'
            if ($PSCmdlet.ShouldProcess($siPolicyPath, 'Remove legacy SiPolicy.p7b')) {
                Remove-Item -Path $siPolicyPath -Force -ErrorAction Stop
                $msg = "SUCCESS: Removed legacy SiPolicy.p7b from $siPolicyPath"
                Write-LogEntry -Value $msg -Severity 1 -Component 'SiPolicy' -Section 'SiPolicy' -Tag 'result:ok'
                $actions.Add($msg)
                $changesApplied = $true
            }
            else {
                $msg = "${modeLabel}Would remove legacy SiPolicy.p7b from $siPolicyPath"
                Write-LogEntry -Value $msg -Severity 1 -Component 'SiPolicy' -Section 'SiPolicy' -WhatIfEntry
                $actions.Add($msg)
            }
        }
        else {
            $msg = "${modeLabel}SKIP: No legacy SiPolicy.p7b found at $siPolicyPath"
            Write-LogEntry -Value $msg -Severity 1 -Component 'SiPolicy' -Section 'SiPolicy' -Tag 'result:skip'
            $actions.Add($msg)
        }
    }
    catch {
        $msg = "ERROR: Failed to remove SiPolicy.p7b - $($_.Exception.Message)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'SiPolicy' -Section 'SiPolicy' -Tag 'result:error'
        $actions.Add($msg)
    }

    # ========================================================================
    # 3. Backup and remove ManagedInstaller.AppLocker file
    #    This file is created by AppIdSvc when MI rules are active — its presence
    #    is the single most authoritative indicator that MI is configured.
    #    After removing AppLocker MI rules (step 4), this file should not regenerate.
    # ========================================================================
    Write-LogSection -Name 'ManagedInstaller.AppLocker'
    $miAppLockerPath = "$env:windir\System32\AppLocker\ManagedInstaller.AppLocker"
    $miAppLockerBackup = 'C:\Windows\Temp\CIPBackup'
    Write-LogEntry -Value "${modeLabel}Checking for ManagedInstaller.AppLocker at $miAppLockerPath" -Severity 1 -Component 'MIAppLocker' -Section 'MIAppLocker'
    try {
        if (Test-Path -Path $miAppLockerPath) {
            $fileInfo = Get-Item -Path $miAppLockerPath -ErrorAction SilentlyContinue
            Write-LogEntry -Value "${modeLabel}Found ManagedInstaller.AppLocker (Size: $($fileInfo.Length) bytes, Modified: $($fileInfo.LastWriteTime))" -Severity 1 -Component 'MIAppLocker' -Section 'MIAppLocker'
            if ($PSCmdlet.ShouldProcess($miAppLockerPath, 'Backup and remove ManagedInstaller.AppLocker')) {
                if (-not (Test-Path -Path $miAppLockerBackup)) {
                    New-Item -Path $miAppLockerBackup -ItemType Directory -Force | Out-Null
                }
                Copy-Item -Path $miAppLockerPath -Destination $miAppLockerBackup -Force -ErrorAction Stop
                Remove-Item -Path $miAppLockerPath -Force -ErrorAction Stop
                $msg = "SUCCESS: Backed up ManagedInstaller.AppLocker to $miAppLockerBackup and removed from $miAppLockerPath"
                Write-LogEntry -Value $msg -Severity 1 -Component 'MIAppLocker' -Section 'MIAppLocker' -Tag 'result:ok'
                $actions.Add($msg)
                $changesApplied = $true
            }
            else {
                $msg = "${modeLabel}Would backup ManagedInstaller.AppLocker to $miAppLockerBackup and remove from $miAppLockerPath"
                Write-LogEntry -Value $msg -Severity 1 -Component 'MIAppLocker' -Section 'MIAppLocker' -WhatIfEntry
                $actions.Add($msg)
            }
        }
        else {
            $msg = "${modeLabel}SKIP: ManagedInstaller.AppLocker not found at $miAppLockerPath - MI is not configured"
            Write-LogEntry -Value $msg -Severity 1 -Component 'MIAppLocker' -Section 'MIAppLocker' -Tag 'result:skip'
            $actions.Add($msg)
        }
    }
    catch {
        $msg = "ERROR: Failed to process ManagedInstaller.AppLocker - $($_.Exception.Message)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'MIAppLocker' -Section 'MIAppLocker' -Tag 'result:error'
        $actions.Add($msg)
    }

    # ========================================================================
    # 4. Remove Managed Installer rules from local AppLocker policy
    #    NOTE: Get-AppLockerPolicy -Local only sees policies set via Group Policy
    #    or Set-AppLockerPolicy. GPO/MDM-delivered policies cannot be removed locally.
    # ========================================================================
    Write-LogSection -Name 'AppLocker Policy'
    Write-LogEntry -Value "${modeLabel}Querying local AppLocker policy for Managed Installer rule collections" -Severity 1 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy'
    try {
        $localPolicy = Get-AppLockerPolicy -Local -ErrorAction Stop
        $miCollection = $localPolicy.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'ManagedInstaller' }
        if ($miCollection) {
            Write-LogEntry -Value "${modeLabel}Found Managed Installer rule collection in local AppLocker policy" -Severity 1 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy'
            if ($PSCmdlet.ShouldProcess('Local AppLocker policy', 'Remove Managed Installer rules')) {
                $localPolicy.RuleCollections.Remove($miCollection) | Out-Null
                Set-AppLockerPolicy -PolicyObject $localPolicy
                $msg = "SUCCESS: Managed Installer rules removed from local AppLocker policy"
                Write-LogEntry -Value $msg -Severity 1 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy' -Tag 'result:ok'
                $actions.Add($msg)
                $changesApplied = $true
            }
            else {
                $msg = "${modeLabel}Would remove Managed Installer rules from local AppLocker policy"
                Write-LogEntry -Value $msg -Severity 1 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy' -WhatIfEntry
                $actions.Add($msg)
            }
        }
        else {
            $msg = "${modeLabel}SKIP: No Managed Installer rules found in local AppLocker policy"
            Write-LogEntry -Value $msg -Severity 1 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy' -Tag 'result:skip'
            $actions.Add($msg)
        }
    }
    catch {
        $msg = "ERROR: Managed Installer AppLocker cleanup failed - $($_.Exception.Message)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'AppLockerPolicy' -Section 'AppLockerPolicy' -Tag 'result:error'
        $actions.Add($msg)
    }

    # ========================================================================
    # 5. Remove Managed Installer configuration from AppLocker SrpV2 registry
    # ========================================================================
    Write-LogSection -Name 'MI Registry'
    $miRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\ManagedInstaller'
    Write-LogEntry -Value "${modeLabel}Checking Managed Installer registry configuration at $miRegPath" -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry'
    try {
        if (Test-Path -Path $miRegPath) {
            $miRegKeys = Get-ChildItem -Path $miRegPath -ErrorAction SilentlyContinue
            if ($miRegKeys) {
                $keyNames = ($miRegKeys | ForEach-Object { $_.PSChildName }) -join ', '
                Write-LogEntry -Value "${modeLabel}Found $($miRegKeys.Count) Managed Installer registry rule(s): [$keyNames]" -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry'
                if ($PSCmdlet.ShouldProcess($miRegPath, 'Remove Managed Installer registry rules')) {
                    Remove-Item -Path $miRegPath -Recurse -Force -ErrorAction Stop
                    $msg = "SUCCESS: Removed Managed Installer registry configuration at $miRegPath ($($miRegKeys.Count) rule(s) removed)"
                    Write-LogEntry -Value $msg -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:ok'
                    $actions.Add($msg)
                    $changesApplied = $true
                }
                else {
                    $msg = "${modeLabel}Would remove Managed Installer registry configuration at $miRegPath ($($miRegKeys.Count) rule(s): [$keyNames])"
                    Write-LogEntry -Value $msg -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry' -WhatIfEntry
                    $actions.Add($msg)
                }
            }
            else {
                $msg = "${modeLabel}SKIP: Managed Installer registry path exists but contains no rule subkeys at $miRegPath"
                Write-LogEntry -Value $msg -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:skip'
                $actions.Add($msg)
            }
        }
        else {
            $msg = "${modeLabel}SKIP: Managed Installer registry path does not exist ($miRegPath) - no MI registry configuration present"
            Write-LogEntry -Value $msg -Severity 1 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:skip'
            $actions.Add($msg)
        }
    }
    catch {
        $msg = "ERROR: Failed to remove Managed Installer registry configuration - $($_.Exception.Message)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'MIRegistry' -Section 'MIRegistry' -Tag 'result:error'
        $actions.Add($msg)
    }

    # ========================================================================
    # 6. Post-remediation verification
    #    Checks remaining artifacts to confirm cleanup worked or warn about
    #    GPO/MDM-delivered policies that cannot be removed locally.
    # ========================================================================
    Write-LogSection -Name 'Verification'
    Write-LogEntry -Value "Running post-remediation verification checks" -Severity 1 -Component 'Verification' -Section 'Verification'

    # 6a. Verify ManagedInstaller.AppLocker is gone
    if (Test-Path -Path $miAppLockerPath) {
        $msg = "WARNING: ManagedInstaller.AppLocker still exists after remediation - MI may be redelivered by GPO/MDM"
        Write-LogEntry -Value $msg -Severity 2 -Component 'Verification' -Section 'Verification' -Tag 'result:warning'
        $actions.Add($msg)
    }
    else {
        $msg = "VERIFIED: ManagedInstaller.AppLocker not present"
        Write-LogEntry -Value $msg -Severity 1 -Component 'Verification' -Section 'Verification' -Tag 'result:clean'
        $actions.Add($msg)
    }

    # 6b. Verify effective AppLocker policy (supplementary — unreliable for MDM)
    try {
        $effectivePolicyXml = [xml](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop)
        $miRuleCollection = $effectivePolicyXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq 'ManagedInstaller' }
        if ($miRuleCollection) {
            $intuneAgent = $miRuleCollection.FilePublisherRule.Conditions.FilePublisherCondition |
            Where-Object { $_.BinaryName -eq 'MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE' }
            if ($intuneAgent) {
                $msg = "WARNING: Intune MI binary (MICROSOFT.MANAGEMENT.SERVICES.INTUNEWINDOWSAGENT.EXE) still in effective AppLocker - delivered via GPO/MDM, cannot remove locally"
            }
            else {
                $ruleCount = @($miRuleCollection.FilePublisherRule).Count
                $msg = "WARNING: ManagedInstaller rules still in effective AppLocker ($ruleCount rule(s)) - delivered via GPO/MDM, cannot remove locally"
            }
            Write-LogEntry -Value $msg -Severity 2 -Component 'Verification' -Section 'Verification' -Tag 'result:warning'
            $actions.Add($msg)
        }
        else {
            $msg = "VERIFIED: No Managed Installer rules in effective AppLocker policy"
            Write-LogEntry -Value $msg -Severity 1 -Component 'Verification' -Section 'Verification' -Tag 'result:clean'
            $actions.Add($msg)
        }
    }
    catch {
        $msg = "ERROR: Unable to verify effective AppLocker policy - $($_.Exception.Message)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'Verification' -Section 'Verification' -Tag 'result:error'
        $actions.Add($msg)
    }

    # 6c. CiTool verification (Win11 22H2+) — read-only query, try even if ciToolBroken
    if (Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue) {
        try {
            $ciResult = Invoke-CiToolWithTimeout -Arguments '-lp -json' -TimeoutSeconds 30
            if ($ciResult.TimedOut) {
                $ciToolBroken = $true
                $msg = "WARNING: CiTool -lp -json timed out during verification - $($ciResult.Output)"
                Write-LogEntry -Value $msg -Severity 2 -Component 'Verification' -Section 'Verification' -Tag 'result:timeout'
                $actions.Add($msg)
            }
            else {
                $ciPolicies = ($ciResult.Output | ConvertFrom-Json).Policies
                $userPolicies = @($ciPolicies | Where-Object { $_.IsEnforced -eq 'True' -and $_.PlatformPolicy -eq 'False' })
                if ($userPolicies.Count -gt 0) {
                    $policyList = ($userPolicies | ForEach-Object { "$($_.FriendlyName) [$($_.PolicyID)]" }) -join ', '
                    $msg = "WARNING: $($userPolicies.Count) user-deployed CI policy(ies) still active after remediation: $policyList"
                    Write-LogEntry -Value $msg -Severity 2 -Component 'Verification' -Section 'Verification' -Tag 'result:warning'
                    $actions.Add($msg)
                }
                else {
                    $msg = "VERIFIED: No user-deployed CI policies active via CiTool"
                    Write-LogEntry -Value $msg -Severity 1 -Component 'Verification' -Section 'Verification' -Tag 'result:clean'
                    $actions.Add($msg)
                }
            }
        }
        catch {
            $msg = "ERROR: CiTool verification failed - $($_.Exception.Message)"
            Write-LogEntry -Value $msg -Severity 3 -Component 'Verification' -Section 'Verification' -Tag 'result:error'
            $actions.Add($msg)
        }
    }

    # ========================================================================
    # 7. Refresh CI policy or flag reboot requirement
    # ========================================================================
    Write-LogSection -Name 'CI Refresh'
    Write-LogEntry -Value "${modeLabel}Checking for CiTool.exe to refresh Code Integrity policy" -Severity 1 -Component 'CIRefresh' -Section 'CIRefresh'
    if (-not $changesApplied) {
        $msg = "SKIP: No changes were made - CI policy refresh not needed"
        Write-LogEntry -Value $msg -Severity 1 -Component 'CIRefresh' -Section 'CIRefresh' -Tag 'result:skip'
        $actions.Add($msg)
    }
    elseif ($ciToolBroken) {
        $msg = "WARNING: Skipping CiTool --refresh because CiTool is unresponsive. A reboot is required to apply changes."
        Write-LogEntry -Value $msg -Severity 2 -Component 'CIRefresh' -Section 'CIRefresh' -Tag 'result:warning'
        $actions.Add($msg)
    }
    elseif (Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess('Code Integrity policy', 'Refresh via CiTool')) {
            $ciResult = Invoke-CiToolWithTimeout -Arguments '--refresh' -TimeoutSeconds 60
            if ($ciResult.TimedOut) {
                $msg = "WARNING: CiTool --refresh timed out after 60s - $($ciResult.Output). Reboot may be required."
                Write-LogEntry -Value $msg -Severity 2 -Component 'CIRefresh' -Section 'CIRefresh' -Tag 'result:timeout'
                $actions.Add($msg)
            }
            else {
                $msg = "SUCCESS: CI policy refreshed via CiTool (exit $($ciResult.ExitCode)) - $($ciResult.Output)"
                Write-LogEntry -Value $msg -Severity 1 -Component 'CIRefresh' -Section 'CIRefresh' -Tag 'result:ok'
                $actions.Add($msg)
            }
        }
        else {
            $msg = "${modeLabel}Would refresh CI policy via CiTool.exe --refresh"
            Write-LogEntry -Value $msg -Severity 1 -Component 'CIRefresh' -Section 'CIRefresh' -WhatIfEntry
            $actions.Add($msg)
        }
    }
    else {
        $msg = "WARNING: CiTool.exe not available on this system - reboot required to complete policy cleanup"
        Write-LogEntry -Value $msg -Severity 2 -Component 'CIRefresh' -Section 'CIRefresh' -Tag 'result:warning'
        $actions.Add($msg)
    }

    # ========================================================================
    # Summary — log full detail, truncate Write-Output for Intune's 2048 char limit
    # ========================================================================
    $fullDetail = $actions -join '; '
    $summary = "${modeLabel}WDAC + Managed Installer cleanup complete: $fullDetail"
    Write-LogEntry -Value $summary -Severity 1 -Component 'Remediate-WDAC' -Tag 'phase:complete'
    if ($summary.Length -gt 2000) {
        $summary = $summary.Substring(0, 1997) + '...'
    }
    Write-Output $summary
}

# Invoke the function, forwarding -WhatIf / -Confirm from the script's bound parameters
Invoke-WDACRemediation @PSBoundParameters
exit 0

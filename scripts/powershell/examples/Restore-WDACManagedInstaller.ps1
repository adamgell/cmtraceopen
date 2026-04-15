# Restore: WDAC CIP Files from Backup
# Copies backed-up CIP files from C:\Windows\Temp\CIPBackup back to the active
# CiPolicies directory, then refreshes Code Integrity policy via CiTool.
#
# Usage:
#   .\Restore-WDACManagedInstaller.ps1              # Execute restore
#   .\Restore-WDACManagedInstaller.ps1 -WhatIf      # Dry-run — no changes made
#   .\Restore-WDACManagedInstaller.ps1 -Confirm      # Prompt before each action
#
# Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Restore-WDACManagedInstaller.log (CMTrace format)

[CmdletBinding(SupportsShouldProcess)]
param()

$LogFileName = 'Restore-WDACManagedInstaller.log'

function Write-LogEntry {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("1", "2", "3")]
        [string]$Severity,
        [parameter(Mandatory = $false)]
        [string]$Component = 'Restore-WDAC',
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName = $LogFileName
    )
    $LogFilePath = Join-Path -Path "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs" -ChildPath $FileName
    $Bias = (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias)
    $Time = (Get-Date -Format "HH:mm:ss.fff") + "{0:+0;-0;+0}" -f $Bias
    $Date = (Get-Date -Format "MM-dd-yyyy")
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($Component)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
    try {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop -WhatIf:$false
        if ($Severity -eq 1) {
            Write-Verbose -Message $Value
        }
        elseif ($Severity -eq 3) {
            Write-Warning -Message $Value
        }
    }
    catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to $LogFileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

function Invoke-CiToolWithTimeout {
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

function Invoke-WDACRestore {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $actions = [System.Collections.Generic.List[string]]::new()
    $modeLabel = if ($WhatIfPreference) { '[WhatIf] ' } else { '' }

    Write-LogEntry -Value "${modeLabel}=== Starting WDAC CIP file restore ===" -Severity 1 -Component 'Restore-WDAC'

    # Pre-flight: admin check
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = ([Security.Principal.WindowsPrincipal]$currentIdentity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-LogEntry -Value "Execution context: User=$($currentIdentity.Name), IsAdmin=$isAdmin" -Severity 1 -Component 'Preflight'

    if (-not $isAdmin) {
        $msg = "ERROR: Script requires Administrator privileges. Current user: $($currentIdentity.Name)"
        Write-LogEntry -Value $msg -Severity 3 -Component 'Preflight'
        Write-Output $msg
        return
    }

    $backupPath = 'C:\Windows\Temp\CIPBackup'
    $activePath = 'C:\Windows\System32\CodeIntegrity\CiPolicies\Active'

    # ========================================================================
    # 1. Validate backup exists
    # ========================================================================
    if (-not (Test-Path -Path $backupPath)) {
        $msg = "ERROR: Backup directory not found at $backupPath - nothing to restore"
        Write-LogEntry -Value $msg -Severity 3 -Component 'Validate'
        $actions.Add($msg)
        $output = "WDAC CIP restore failed: " + ($actions -join '; ')
        if ($output.Length -gt 2000) { $output = $output.Substring(0, 2000) + '...[TRUNCATED]' }
        Write-Output $output
        exit 1
    }

    $cipFiles = Get-ChildItem -Path $backupPath -Filter '*.cip' -ErrorAction SilentlyContinue
    if (-not $cipFiles -or $cipFiles.Count -eq 0) {
        $msg = "ERROR: No .cip files found in $backupPath - nothing to restore"
        Write-LogEntry -Value $msg -Severity 3 -Component 'Validate'
        $actions.Add($msg)
        $output = "WDAC CIP restore failed: " + ($actions -join '; ')
        if ($output.Length -gt 2000) { $output = $output.Substring(0, 2000) + '...[TRUNCATED]' }
        Write-Output $output
        exit 1
    }

    $fileNames = ($cipFiles | ForEach-Object { $_.Name }) -join ', '
    Write-LogEntry -Value "Found $($cipFiles.Count) CIP file(s) in backup: [$fileNames]" -Severity 1 -Component 'Validate'

    # ========================================================================
    # 2. Ensure active directory exists
    # ========================================================================
    if (-not (Test-Path -Path $activePath)) {
        if ($PSCmdlet.ShouldProcess($activePath, 'Create CiPolicies\Active directory')) {
            New-Item -Path $activePath -ItemType Directory -Force | Out-Null
            Write-LogEntry -Value "Created directory: $activePath" -Severity 1 -Component 'Restore'
        }
    }

    # ========================================================================
    # 3. Copy CIP files back to active directory
    # ========================================================================
    $restoredCount = 0
    foreach ($file in $cipFiles) {
        $destFile = Join-Path -Path $activePath -ChildPath $file.Name
        if ($PSCmdlet.ShouldProcess($file.Name, 'Restore CIP file to active directory')) {
            try {
                Copy-Item -Path $file.FullName -Destination $destFile -Force -ErrorAction Stop
                $msg = "SUCCESS: Restored $($file.Name) to $activePath"
                Write-LogEntry -Value $msg -Severity 1 -Component 'Restore'
                $actions.Add($msg)
                $restoredCount++
            }
            catch {
                $msg = "ERROR: Failed to restore $($file.Name) - $($_.Exception.Message)"
                Write-LogEntry -Value $msg -Severity 3 -Component 'Restore'
                $actions.Add($msg)
            }
        }
        else {
            $msg = "${modeLabel}Would restore $($file.Name) to $activePath"
            Write-LogEntry -Value $msg -Severity 1 -Component 'Restore'
            $actions.Add($msg)
        }
    }

    # ========================================================================
    # 4. Verify restored files
    # ========================================================================
    Write-LogEntry -Value "Running post-restore verification" -Severity 1 -Component 'Verification'
    $restoredFiles = Get-ChildItem -Path $activePath -Filter '*.cip' -ErrorAction SilentlyContinue
    if ($restoredFiles -and $restoredFiles.Count -eq $cipFiles.Count) {
        $msg = "VERIFIED: All $($restoredFiles.Count) CIP file(s) restored to $activePath"
        Write-LogEntry -Value $msg -Severity 1 -Component 'Verification'
        $actions.Add($msg)
    }
    elseif ($restoredFiles) {
        $msg = "WARNING: Only $($restoredFiles.Count) of $($cipFiles.Count) CIP file(s) present in $activePath after restore"
        Write-LogEntry -Value $msg -Severity 2 -Component 'Verification'
        $actions.Add($msg)
    }
    else {
        $msg = "ERROR: No CIP files found in $activePath after restore"
        Write-LogEntry -Value $msg -Severity 3 -Component 'Verification'
        $actions.Add($msg)
    }

    # ========================================================================
    # 5. Refresh CI policy so restored policies take effect
    # ========================================================================
    if ($restoredCount -gt 0) {
        $hasCiTool = [bool](Get-Command -Name 'CiTool.exe' -ErrorAction SilentlyContinue)
        if ($hasCiTool) {
            if ($PSCmdlet.ShouldProcess('Code Integrity policy', 'Refresh via CiTool')) {
                Write-LogEntry -Value "Refreshing CI policy via CiTool --refresh (60s timeout)" -Severity 1 -Component 'CIRefresh'
                $ciResult = Invoke-CiToolWithTimeout -Arguments '--refresh' -TimeoutSeconds 60
                if ($ciResult.TimedOut) {
                    $msg = "WARNING: CiTool --refresh timed out after 60s - $($ciResult.Output). Reboot may be required."
                    Write-LogEntry -Value $msg -Severity 2 -Component 'CIRefresh'
                    $actions.Add($msg)
                }
                else {
                    $msg = "SUCCESS: CI policy refreshed via CiTool (exit $($ciResult.ExitCode)) - $($ciResult.Output)"
                    Write-LogEntry -Value $msg -Severity 1 -Component 'CIRefresh'
                    $actions.Add($msg)
                }
            }
        }
        else {
            $msg = "WARNING: CiTool.exe not available - reboot required for restored policies to take effect"
            Write-LogEntry -Value $msg -Severity 2 -Component 'CIRefresh'
            $actions.Add($msg)
        }
    }
    else {
        $msg = "SKIP: No files were restored - CI policy refresh not needed"
        Write-LogEntry -Value $msg -Severity 1 -Component 'CIRefresh'
        $actions.Add($msg)
    }

    # ========================================================================
    # Output summary
    # ========================================================================
    Write-LogEntry -Value "${modeLabel}=== WDAC CIP restore complete ===" -Severity 1 -Component 'Restore-WDAC'
    $output = "WDAC CIP restore complete: " + ($actions -join '; ')
    Write-LogEntry -Value $output -Severity 1 -Component 'Restore-WDAC'
    if ($output.Length -gt 2000) { $output = $output.Substring(0, 2000) + '...[TRUNCATED]' }
    Write-Output $output
}

# Main execution
Invoke-WDACRestore @PSBoundParameters

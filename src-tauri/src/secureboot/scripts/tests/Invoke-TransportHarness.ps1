# Exercise the production launcher's argument serialization without requesting
# elevation. The child is a harmless output/exit-code fixture, never Secure Boot.
param(
    [Parameter(Mandatory = $true)][string]$WrapperPath,
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [Parameter(Mandatory = $true)][string]$StdoutPath,
    [Parameter(Mandatory = $true)][string]$StderrPath,
    [Parameter(Mandatory = $true)][string]$ExitCodePath
)

$ErrorActionPreference = 'Stop'

function Start-Process {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$Verb,
        [string]$WindowStyle,
        [switch]$Wait
    )

    if ($FilePath -ne 'powershell.exe' -or $Verb -ne 'RunAs' -or
        $WindowStyle -ne 'Hidden' -or -not $Wait) {
        throw 'The production elevation contract changed.'
    }

    # Keep Start-Process's real ArgumentList handling. Only the executable and
    # UAC-specific options change, so this test cannot request elevation.
    $hostPath = (Get-Process -Id $PID).Path
    $child = Microsoft.PowerShell.Management\Start-Process -FilePath $hostPath `
        -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow
    if ($child.ExitCode -ne 0) {
        throw "The capture wrapper failed with exit code $($child.ExitCode)."
    }
}

& $env:CMTRACE_TEST_LAUNCHER @PSBoundParameters

if ((Get-Content -LiteralPath $StdoutPath -Raw) -notmatch 'stdout preserved') {
    throw 'The target stdout did not reach the requested capture file.'
}
if ((Get-Content -LiteralPath $StderrPath -Raw) -notmatch 'stderr preserved') {
    throw 'The target stderr did not reach the requested capture file.'
}
if ((Get-Content -LiteralPath $ExitCodePath -Raw) -ne '23') {
    throw 'The target exit code did not reach the requested capture file.'
}
Write-Output 'transport verified'

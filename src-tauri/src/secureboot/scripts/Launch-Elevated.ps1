# Launches the capture wrapper elevated and waits for it.
#
# The paths are passed straight through as an argument array. PowerShell builds
# the child command line from the array, so an element is never re-parsed as
# syntax and needs no quoting of its own - which is the whole reason this is a
# separate script rather than a -Command string built by the caller.
param(
    [Parameter(Mandatory = $true)][string]$WrapperPath,
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [Parameter(Mandatory = $true)][string]$StdoutPath,
    [Parameter(Mandatory = $true)][string]$StderrPath,
    [Parameter(Mandatory = $true)][string]$ExitCodePath
)

$ErrorActionPreference = 'Stop'

Start-Process -FilePath 'powershell.exe' -ArgumentList @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $WrapperPath,
    '-ScriptPath', $ScriptPath,
    '-StdoutPath', $StdoutPath,
    '-StderrPath', $StderrPath,
    '-ExitCodePath', $ExitCodePath
) -Verb RunAs -WindowStyle Hidden -Wait

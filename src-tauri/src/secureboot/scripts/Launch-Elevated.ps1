# Launches the capture wrapper elevated and waits for it.
#
# Start-Process joins ArgumentList elements with spaces; it does not preserve
# argv boundaries. Quote each value for the native command line, while keeping
# paths out of PowerShell source by using -File and script parameters.
param(
    [Parameter(Mandatory = $true)][string]$WrapperPath,
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [Parameter(Mandatory = $true)][string]$StdoutPath,
    [Parameter(Mandatory = $true)][string]$StderrPath,
    [Parameter(Mandatory = $true)][string]$ExitCodePath
)

$ErrorActionPreference = 'Stop'

$childArguments = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $WrapperPath,
    '-ScriptPath', $ScriptPath,
    '-StdoutPath', $StdoutPath,
    '-StderrPath', $StderrPath,
    '-ExitCodePath', $ExitCodePath
) | ForEach-Object { '"{0}"' -f $_ }

# These are app-created file paths: Windows filenames cannot contain a double
# quote, and each path ends in a filename rather than a trailing backslash.
Start-Process -FilePath 'powershell.exe' -ArgumentList ($childArguments -join ' ') `
    -Verb RunAs -WindowStyle Hidden -Wait

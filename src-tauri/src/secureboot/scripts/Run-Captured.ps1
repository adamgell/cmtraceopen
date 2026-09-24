# Runs the requested script and captures its streams and exit code to files.
#
# Every path arrives as a parameter. `Start-Process -Verb RunAs` cannot use
# -RedirectStandardOutput, so the elevated child writes these files itself.
#
# Nothing here is interpolated from a value: a path is passed as an argument
# and read from the parameter, so a path containing a quote character cannot
# become PowerShell syntax.
param(
    [Parameter(Mandatory = $true)][string]$ScriptPath,
    [Parameter(Mandatory = $true)][string]$StdoutPath,
    [Parameter(Mandatory = $true)][string]$StderrPath,
    [Parameter(Mandatory = $true)][string]$ExitCodePath
)

$ErrorActionPreference = 'Stop'

& $ScriptPath *> $StdoutPath 2> $StderrPath
$LASTEXITCODE | Out-File -FilePath $ExitCodePath -Encoding ascii -NoNewline

[CmdletBinding()]
param(
    [string]$HandoffRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

if ([string]::IsNullOrWhiteSpace($HandoffRoot)) {
    $HandoffRoot = Get-CMTraceHandoffRoot
}

[void](Assert-CMTraceHandoffIntegrity -HandoffRoot $HandoffRoot)
Write-Output 'HANDOFF_INTEGRITY_OK'

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

[void](Assert-CMTraceHandoffIntegrity)
Assert-CMTraceWindows11Arm64
$resolvedEvidence = Assert-CMTraceFixedLocalNtfsPath -Path $EvidenceRoot -Label 'EvidenceRoot' -ForbiddenRoots @((Get-CMTraceHandoffRoot))
$rawArtifactRoot = Join-Path $resolvedEvidence 'raw-artifacts'
if (-not (Test-Path -LiteralPath $rawArtifactRoot -PathType Container)) {
    throw 'EvidenceRoot must already contain raw-artifacts from the automatic runner.'
}
[void](Assert-CMTraceFixedLocalNtfsPath -Path $rawArtifactRoot -Label 'Raw artifact root' -ForbiddenRoots @((Get-CMTraceHandoffRoot)))
$fixtureRoot = Join-Path $rawArtifactRoot 'private-source-fixtures'
[void](Assert-CMTraceFixedLocalNtfsPath -Path $fixtureRoot -Label 'Private source fixture root' -ForbiddenRoots @((Get-CMTraceHandoffRoot)) -MustNotExist)
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null

$folderFixture = Join-Path $fixtureRoot 'folder-child-errors'
$junctionTarget = Join-Path $fixtureRoot 'junction-target'
New-Item -ItemType Directory -Path $folderFixture, $junctionTarget | Out-Null
foreach ($index in 1..5) {
    $junction = Join-Path $folderFixture ('blocked-{0}.evtx' -f $index)
    New-Item -ItemType Junction -Path $junction -Target $junctionTarget -ErrorAction Stop | Out-Null
}

$unsafeZip = Join-Path $fixtureRoot 'unsafe-duplicate.zip'
$file = [IO.File]::Create($unsafeZip)
$zip = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    foreach ($name in @('../escape.bin', 'Dup.bin', 'dup.bin')) {
        $entry = $zip.CreateEntry($name)
        $stream = $entry.Open()
        try { $stream.WriteByte(0) } finally { $stream.Dispose() }
    }
}
finally {
    $zip.Dispose()
    $file.Dispose()
}

$memberLimitZip = Join-Path $fixtureRoot 'member-limit-513.zip'
$file = [IO.File]::Create($memberLimitZip)
$zip = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Create, $false)
try {
    foreach ($index in 0..512) {
        $entry = $zip.CreateEntry(('member-{0:D3}.bin' -f $index))
        $stream = $entry.Open()
        try { $stream.WriteByte(0) } finally { $stream.Dispose() }
    }
}
finally {
    $zip.Dispose()
    $file.Dispose()
}

$manifest = [ordered]@{
    schemaVersion = 1
    sourceCommit = $script:CMTraceExpectedSourceCommit
    folderRejectedChildCount = 5
    folderDisplayExpectedCount = 3
    folderHiddenExpectedCount = 2
    unsafeArchiveSha256 = Get-CMTraceSha256 -Path $unsafeZip
    unsafeArchiveMembers = 3
    memberLimitArchiveSha256 = Get-CMTraceSha256 -Path $memberLimitZip
    memberLimitArchiveMembers = 513
    privacy = 'Structural-only target-local fixtures. Never include archives, paths, or junctions in the return bundle.'
}
Write-CMTraceJson -Value $manifest -Path (Join-Path $fixtureRoot 'fixture-manifest.json')

Write-Output 'PRIVATE_SOURCE_FIXTURES_READY'

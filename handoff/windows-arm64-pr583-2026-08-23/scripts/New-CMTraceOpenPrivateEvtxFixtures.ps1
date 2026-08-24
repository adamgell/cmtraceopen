[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CleanEvtxPath,

    [Parameter(Mandatory = $true)]
    [string]$EvidenceRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'CMTraceOpenArm64Handoff.Common.ps1')

[void](Assert-CMTraceHandoffIntegrity)
Assert-CMTraceWindows11Arm64

$resolvedEvidence = Assert-CMTraceFixedLocalNtfsPath -Path $EvidenceRoot -Label 'EvidenceRoot' -ForbiddenRoots @((Get-CMTraceHandoffRoot))
$privateEvtxRoot = Join-Path $resolvedEvidence 'raw-artifacts\private-evtx'
if (-not (Test-Path -LiteralPath $privateEvtxRoot -PathType Container)) {
    throw 'EvidenceRoot must already contain raw-artifacts\private-evtx.'
}
[void](Assert-CMTraceFixedLocalNtfsPath -Path $privateEvtxRoot -Label 'Private EVTX root' -ForbiddenRoots @((Get-CMTraceHandoffRoot)))

$source = Get-Item -LiteralPath $CleanEvtxPath -Force
if ($source.PSIsContainer -or $source.Extension -ne '.evtx') {
    throw 'CleanEvtxPath must name an .evtx file.'
}
if (($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'CleanEvtxPath cannot be a symlink, junction, or reparse point.'
}
[void](Assert-CMTraceFixedLocalNtfsPath -Path $source.FullName -Label 'Clean EVTX source' -ForbiddenRoots @((Get-CMTraceHandoffRoot)))
$privatePrefix = $privateEvtxRoot.TrimEnd([char]'\') + [IO.Path]::DirectorySeparatorChar
if (-not $source.FullName.StartsWith($privatePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'CleanEvtxPath must remain beneath EvidenceRoot\raw-artifacts\private-evtx.'
}

$headerBytes = 4096
$chunkBytes = 65536
$chunkRecordOffset = 512
$minimumRecordBytes = 28
$recordSignature = [uint32]0x00002A2A
$maximumBytes = 67108864L
$minimumBytes = $headerBytes + (3 * $chunkBytes)
$sourceStream = [IO.File]::Open($source.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
try {
    if ($sourceStream.Length -gt $maximumBytes) {
        throw "The clean EVTX must not exceed the $maximumBytes-byte private fixture limit."
    }
    $sourceBytes = [byte[]]::new([int]$sourceStream.Length)
    $sourceStream.ReadExactly($sourceBytes, 0, $sourceBytes.Length)
}
finally {
    $sourceStream.Dispose()
}
$sourceHashBefore = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($sourceBytes)).ToLowerInvariant()
if ($sourceBytes.Length -gt $maximumBytes) {
    throw "The clean EVTX must not exceed the $maximumBytes-byte private fixture limit."
}
if ($sourceBytes.Length -lt $minimumBytes) {
    throw "The clean EVTX must be at least $minimumBytes bytes so an internal gap can retain later readable data."
}
if (($sourceBytes.Length - $headerBytes) % $chunkBytes -ne 0) {
    throw 'The clean EVTX length does not contain an integral number of 65536-byte chunks.'
}
if ([Text.Encoding]::ASCII.GetString($sourceBytes, 0, 8) -ne "ElfFile$([char]0)") {
    throw 'CleanEvtxPath does not contain the expected EVTX file signature.'
}
$chunkCount = [int](($sourceBytes.Length - $headerBytes) / $chunkBytes)
$usedChunkIndices = @()
foreach ($chunkIndex in 0..($chunkCount - 1)) {
    $chunkOffset = $headerBytes + ($chunkIndex * $chunkBytes)
    if ([Text.Encoding]::ASCII.GetString($sourceBytes, $chunkOffset, 8) -ne "ElfChnk$([char]0)") {
        throw "CleanEvtxPath has a missing chunk signature at chunk index $chunkIndex."
    }

    $candidateRecordOffset = $chunkOffset + $chunkRecordOffset
    if ([BitConverter]::ToUInt32($sourceBytes, $candidateRecordOffset) -ne $recordSignature) {
        continue
    }

    $candidateRecordBytes = [BitConverter]::ToUInt32($sourceBytes, $candidateRecordOffset + 4)
    if ($candidateRecordBytes -lt $minimumRecordBytes -or $candidateRecordBytes -gt ($chunkBytes - $chunkRecordOffset)) {
        throw "CleanEvtxPath has an invalid first-record size in used chunk index $chunkIndex."
    }
    $usedChunkIndices += $chunkIndex
}
if ($usedChunkIndices.Count -lt 3) {
    throw 'The clean EVTX must contain at least three used chunks with canonical first records so an internal gap can retain later readable data.'
}

$firstUsedChunkIndex = [int]$usedChunkIndices[0]
$internalUsedChunkIndex = [int]$usedChunkIndices[[int][Math]::Floor($usedChunkIndices.Count / 2)]
$lastUsedChunkIndex = [int]$usedChunkIndices[-1]
$firstUsedChunkOffset = $headerBytes + ($firstUsedChunkIndex * $chunkBytes)
$internalUsedChunkOffset = $headerBytes + ($internalUsedChunkIndex * $chunkBytes)
$lastUsedChunkOffset = $headerBytes + ($lastUsedChunkIndex * $chunkBytes)
$firstRecordOffset = $firstUsedChunkOffset + $chunkRecordOffset
$malformedBinXmlOffset = $firstRecordOffset + 24
$originalBinXmlToken = [byte]$sourceBytes[$malformedBinXmlOffset]
[byte]$malformedBinXmlToken = if ($originalBinXmlToken -eq 0xFF) { 0xFE } else { 0xFF }

$fullOutput = Join-Path $privateEvtxRoot 'recovery-copies'
[void](Assert-CMTraceFixedLocalNtfsPath -Path $fullOutput -Label 'Private recovery output' -ForbiddenRoots @((Get-CMTraceHandoffRoot)) -MustNotExist)
New-Item -ItemType Directory -Path $fullOutput | Out-Null

$fixtureSpecs = @(
    [ordered]@{ file = 'clean.evtx'; damage = 'none' },
    [ordered]@{ file = 'tail-truncated.evtx'; damage = "last used chunk record area removed after byte offset $($lastUsedChunkOffset + $chunkRecordOffset) in a copy" },
    [ordered]@{ file = 'internal-missing-chunk.evtx'; damage = "used chunk index $internalUsedChunkIndex at byte offset $internalUsedChunkOffset zeroed in a copy" },
    [ordered]@{ file = 'malformed-file-header.evtx'; damage = 'eight-byte EVTX file signature zeroed in a copy' },
    [ordered]@{ file = 'malformed-chunk-header.evtx'; damage = "eight-byte used chunk signature at byte offset $firstUsedChunkOffset zeroed in a copy" },
    [ordered]@{ file = 'malformed-record-size.evtx'; damage = "used-chunk record size at byte offset $($firstRecordOffset + 4) changed to 2147483647 in a copy" },
    [ordered]@{ file = 'malformed-binxml.evtx'; damage = "used-chunk record BinXML token at byte offset $malformedBinXmlOffset changed from $originalBinXmlToken to $malformedBinXmlToken in a copy" }
)
foreach ($fixture in $fixtureSpecs) {
    $fixturePath = Join-Path $fullOutput $fixture.file
    $fixtureStream = [IO.File]::Open($fixturePath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $fixtureStream.Write($sourceBytes, 0, $sourceBytes.Length)
        $fixtureStream.Flush($true)
    }
    finally {
        $fixtureStream.Dispose()
    }
}

$tailPath = Join-Path $fullOutput 'tail-truncated.evtx'
$tailStream = [IO.File]::Open($tailPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
try {
    $tailStream.SetLength($lastUsedChunkOffset + $chunkRecordOffset)
}
finally {
    $tailStream.Dispose()
}

function Write-PrivateFixtureByteRange {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int64]$Offset,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Position = $Offset
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

Write-PrivateFixtureByteRange -Path (Join-Path $fullOutput 'internal-missing-chunk.evtx') -Offset $internalUsedChunkOffset -Bytes ([byte[]]::new($chunkBytes))
Write-PrivateFixtureByteRange -Path (Join-Path $fullOutput 'malformed-file-header.evtx') -Offset 0 -Bytes ([byte[]]::new(8))
Write-PrivateFixtureByteRange -Path (Join-Path $fullOutput 'malformed-chunk-header.evtx') -Offset $firstUsedChunkOffset -Bytes ([byte[]]::new(8))
Write-PrivateFixtureByteRange -Path (Join-Path $fullOutput 'malformed-record-size.evtx') -Offset ($firstRecordOffset + 4) -Bytes ([BitConverter]::GetBytes([uint32]0x7FFFFFFF))
Write-PrivateFixtureByteRange -Path (Join-Path $fullOutput 'malformed-binxml.evtx') -Offset $malformedBinXmlOffset -Bytes ([byte[]]@($malformedBinXmlToken))

if ((Get-CMTraceSha256 -Path $source.FullName) -ne $sourceHashBefore) {
    throw 'The source EVTX changed during fixture generation.'
}

$fixtureHashes = @{}
foreach ($fixture in $fixtureSpecs) {
    $fixtureHash = Get-CMTraceSha256 -Path (Join-Path $fullOutput $fixture.file)
    $fixtureHashes[$fixture.file] = $fixtureHash
    if ($fixture.file -ceq 'clean.evtx') {
        if ($fixtureHash -cne $sourceHashBefore) {
            throw 'The clean EVTX fixture does not match its source.'
        }
    }
    elseif ($fixtureHash -ceq $sourceHashBefore) {
        throw "Damaged EVTX fixture is byte-identical to its source: $($fixture.file)"
    }
}
if (@($fixtureHashes.Values | Sort-Object -Unique).Count -ne $fixtureSpecs.Count) {
    throw 'Every EVTX recovery fixture must have unique bytes.'
}

$manifestFixtures = @($fixtureSpecs | ForEach-Object {
    $fixturePath = Join-Path $fullOutput $_.file
    [ordered]@{
        file = $_.file
        damage = $_.damage
        bytes = (Get-Item -LiteralPath $fixturePath).Length
        sha256 = $fixtureHashes[$_.file]
    }
})
$manifest = [ordered]@{
    schemaVersion = 2
    createdAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    privacy = 'Target-local lab EVTX material. Never include these files in the return bundle.'
    sourceSha256 = $sourceHashBefore
    fixtures = $manifestFixtures
}
Write-CMTraceJson -Value $manifest -Path (Join-Path $fullOutput 'recovery-fixtures.json')

Write-Output "PRIVATE_EVTX_FIXTURES_READY usedChunks=$($usedChunkIndices.Count)"

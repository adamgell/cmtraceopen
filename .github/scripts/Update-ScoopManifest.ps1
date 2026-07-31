<#
.SYNOPSIS
    Points the checked-in Scoop manifests in bucket/ at a CMTrace Open release.

.DESCRIPTION
    Rewrites the 'version' value and every architecture 'url'/'hash' pair using
    the manifest's own 'autoupdate' URL templates, so the self-hosted bucket and
    Scoop's Excavator bot always derive asset locations from the same source. If
    a release ever renames an asset, only the autoupdate template has to change.

    Hashes come from the GitHub release asset digest when the API reports one and
    from downloading the asset otherwise, which mirrors what Scoop itself does
    for github.com release URLs.

    The JSON text is edited in place rather than round-tripped through
    ConvertTo-Json: PowerShell reindents to two spaces, reorders nothing but
    reformats everything, and mangles the single-element nested array used by
    'shortcuts'. Scoop buckets require four-space indentation, and a whole-file
    diff on every release makes the bucket history useless.

.PARAMETER Version
    Release version, with or without a leading 'v' (for example '1.5.0').

.PARAMETER ManifestPath
    Manifests to update. Defaults to every '*.json' in the repo's bucket/
    directory, so a new manifest is picked up without touching the workflow.

.PARAMETER Repository
    GitHub 'owner/name' whose release holds the assets.

.PARAMETER Tag
    Release tag. Defaults to 'v<Version>'.

.EXAMPLE
    ./.github/scripts/Update-ScoopManifest.ps1 -Version 1.5.0
#>
[CmdletBinding()]
param(
    # Version is the only positional parameter. Giving it an explicit position
    # makes every other parameter name-only, so a stray extra argument is a
    # binding error instead of silently landing in Repository.
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Version,

    [string[]]$ManifestPath = @(),

    [string]$Repository = 'adamgell/cmtraceopen',

    [string]$Tag
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Version = $Version -replace '^[vV]', ''
if ($Version -notmatch '^\d+\.\d+\.\d+') {
    throw "Version '$Version' does not look like a release version (expected something like 1.5.0)."
}
if (-not $Tag) { $Tag = "v$Version" }

if ($ManifestPath.Count -eq 0) {
    $bucket = Join-Path $PSScriptRoot '../../bucket'
    if (-not (Test-Path -LiteralPath $bucket)) { throw "Bucket directory not found: $bucket" }
    $ManifestPath = @(Get-ChildItem -LiteralPath $bucket -Filter '*.json' -File |
        Sort-Object Name | ForEach-Object { $_.FullName })
    if ($ManifestPath.Count -eq 0) { throw "No manifests found in $bucket" }
}

function Get-ReleaseAssets {
    <#
        Returns a map of asset name to sha256 (lowercase hex, or $null when the
        API reports no digest for that asset). Doubles as the check that every
        URL the manifests build actually exists in the release.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Tag
    )

    $headers = @{
        'Accept'               = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent'           = 'cmtraceopen-scoop-updater'
    }
    if ($env:GITHUB_TOKEN) { $headers['Authorization'] = "Bearer $env:GITHUB_TOKEN" }

    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repository/releases/tags/$Tag" -Headers $headers
    $assets = @{}
    foreach ($asset in $release.assets) {
        $digest = $null
        if (($asset.PSObject.Properties.Name -contains 'digest') -and
            ($asset.digest -match '^sha256:([0-9a-fA-F]{64})$')) {
            $digest = $Matches[1].ToLowerInvariant()
        }
        $assets[$asset.name] = $digest
    }

    if ($assets.Count -eq 0) { throw "Release $Tag of $Repository has no assets." }
    return $assets
}

function Get-AssetHash {
    <#
        Falls back to downloading when the release predates GitHub's asset
        digests, so the script never writes a hash it did not verify.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$AssetName,
        [Parameter(Mandatory = $true)][hashtable]$ReleaseAssets
    )

    if (-not $ReleaseAssets.ContainsKey($AssetName)) {
        throw "Release asset '$AssetName' not found. Available: $(($ReleaseAssets.Keys | Sort-Object) -join ', ')"
    }

    if ($ReleaseAssets[$AssetName]) {
        Write-Host "  $AssetName -> $($ReleaseAssets[$AssetName]) (release digest)"
        return $ReleaseAssets[$AssetName]
    }

    $temp = Join-Path ([System.IO.Path]::GetTempPath()) "cmtraceopen-scoop-$([guid]::NewGuid().ToString('n')).bin"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $temp -UseBasicParsing
        $hash = (Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant()
    } finally {
        Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
    }

    Write-Host "  $AssetName -> $hash (downloaded)"
    return $hash
}

function Set-CapturedValue {
    <#
        Splices $Value between capture groups 1 and 2 of the single match of
        $Pattern. Refuses to guess when the pattern matches zero or many times,
        which is what turns an unexpected manifest shape into a build failure
        instead of a silently wrong manifest.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$What
    )

    $matched = [regex]::Matches($Text, $Pattern)
    if ($matched.Count -ne 1) {
        throw "Expected exactly 1 match for $What, found $($matched.Count)."
    }

    $m = $matched[0]
    return $Text.Substring(0, $m.Index) +
        $m.Groups[1].Value + $Value + $m.Groups[2].Value +
        $Text.Substring($m.Index + $m.Length)
}

$releaseAssets = Get-ReleaseAssets -Repository $Repository -Tag $Tag

foreach ($path in $ManifestPath) {
    if (-not (Test-Path -LiteralPath $path)) { throw "Manifest not found: $path" }
    $file = (Resolve-Path -LiteralPath $path).Path
    $name = [System.IO.Path]::GetFileNameWithoutExtension($file)
    Write-Host "$name -> $Version"

    $text = Get-Content -LiteralPath $file -Raw
    $manifest = $text | ConvertFrom-Json

    $text = Set-CapturedValue -Text $text -Value $Version -What "the version of $name" `
        -Pattern '(?m)^(\s*"version"\s*:\s*")[^"]*(")'

    $expected = @{}
    foreach ($architecture in $manifest.autoupdate.architecture.PSObject.Properties) {
        $arch = $architecture.Name
        $url = $architecture.Value.url.Replace('$version', $Version)
        if ($url.Contains('$')) {
            throw "Unresolved template variable in the $arch autoupdate URL of $name`: $url"
        }

        # Scoop's '#/name.exe' fragment renames the download; the asset name is
        # everything before it.
        $assetName = [System.IO.Path]::GetFileName(($url -split '#/')[0])
        $hash = Get-AssetHash -Url $url -AssetName $assetName -ReleaseAssets $releaseAssets

        # '[^"]*' cannot cross a quote and the autoupdate blocks carry no 'hash',
        # so this only ever matches the real architecture block.
        $text = Set-CapturedValue -Text $text -Value $url -What "the $arch URL of $name" `
            -Pattern ('("' + [regex]::Escape($arch) + '"\s*:\s*\{\s*"url"\s*:\s*")[^"]*("\s*,\s*"hash")')
        $text = Set-CapturedValue -Text $text -Value $hash -What "the $arch hash of $name" `
            -Pattern ('("' + [regex]::Escape($arch) + '"\s*:\s*\{\s*"url"\s*:\s*"[^"]*"\s*,\s*"hash"\s*:\s*")[0-9a-fA-F]*(")')

        $expected[$arch] = @{ Url = $url; Hash = $hash }
    }

    if ($expected.Count -eq 0) { throw "$name has no autoupdate architectures to update." }

    # Re-parse rather than trust the splices.
    $updated = $text | ConvertFrom-Json
    if ($updated.version -ne $Version) {
        throw "$name still reports version '$($updated.version)' after the update."
    }
    foreach ($arch in $expected.Keys) {
        $actual = $updated.architecture.$arch
        if ($actual.url -ne $expected[$arch].Url) {
            throw "$name $arch URL is '$($actual.url)', expected '$($expected[$arch].Url)'."
        }
        if ($actual.hash -ne $expected[$arch].Hash) {
            throw "$name $arch hash is '$($actual.hash)', expected '$($expected[$arch].Hash)'."
        }
    }

    [System.IO.File]::WriteAllText($file, $text, (New-Object System.Text.UTF8Encoding($false)))
}

Write-Host "Updated $($ManifestPath.Count) manifest(s) to $Version."

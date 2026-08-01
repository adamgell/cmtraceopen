<#
.SYNOPSIS
    Applies repo-owned defaultLocale metadata to komac-generated winget manifests.

.DESCRIPTION
    'komac update' carries PackageUrl, ShortDescription, Description, Moniker and
    Tags forward from the previously published manifest and offers no CLI flags to
    change them, so a stale value stays stale for every future release. This script
    splices the keys from .github/winget/locale-metadata.yaml into the generated
    defaultLocale manifest, between 'komac update --dry-run --output-directory' and
    'komac submit'.

    Keys already present in the generated manifest are replaced in place, which
    preserves schema key order. Keys komac omitted entirely are inserted at their
    correct schema position. Line endings of the generated manifest are preserved
    (winget-pkgs manifests are CRLF; rewriting them as LF produces a whole-file
    diff and fails validation).

.PARAMETER ManifestDirectory
    Directory holding the komac-generated manifests. Searched recursively for
    '*.locale.en-US.yaml'.

.PARAMETER MetadataPath
    Path to the metadata YAML whose top-level keys should be applied.

.EXAMPLE
    ./.github/scripts/Set-WingetLocaleMetadata.ps1 -ManifestDirectory "$env:RUNNER_TEMP\winget-out" -MetadataPath ./.github/winget/locale-metadata.yaml
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ManifestDirectory,

    [Parameter(Mandatory = $true)]
    [string]$MetadataPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Key order from the defaultLocale manifest schema. Only used to position keys
# that the generated manifest does not already contain.
$schemaOrder = @(
    'PackageIdentifier', 'PackageVersion', 'PackageLocale', 'Publisher',
    'PublisherUrl', 'PublisherSupportUrl', 'PrivacyUrl', 'Author', 'PackageName',
    'PackageUrl', 'License', 'LicenseUrl', 'Copyright', 'CopyrightUrl',
    'ShortDescription', 'Description', 'Moniker', 'Tags', 'Agreements',
    'ReleaseNotes', 'ReleaseNotesUrl', 'PurchaseUrl', 'InstallationNotes',
    'Documentations', 'Icons', 'ManifestType', 'ManifestVersion'
)

function Get-YamlSegments {
    <#
        Splits flat YAML text into ordered segments, one per top-level key. Each
        segment owns its continuation lines (block scalar bodies, sequence items),
        so replacing a segment replaces the whole value.
    #>
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][AllowEmptyString()][string[]]$Lines)

    $preamble = [System.Collections.Generic.List[string]]::new()
    $segments = [System.Collections.Generic.List[object]]::new()

    foreach ($line in $Lines) {
        if ($line -match '^([A-Za-z][A-Za-z0-9_]*):') {
            $segment = [pscustomobject]@{
                Key   = $Matches[1]
                Lines = [System.Collections.Generic.List[string]]::new()
            }
            $segment.Lines.Add($line)
            $segments.Add($segment)
        }
        elseif ($segments.Count -gt 0) {
            $segments[$segments.Count - 1].Lines.Add($line)
        }
        else {
            $preamble.Add($line)
        }
    }

    return [pscustomobject]@{ Preamble = $preamble; Segments = $segments }
}

function Assert-MetadataLimits {
    <#
        Fails the build on values winget would reject, so a bad edit to the
        metadata file surfaces here rather than as a rejected pull request.
    #>
    param([Parameter(Mandatory = $true)][object[]]$Segments)

    foreach ($segment in $Segments) {
        switch ($segment.Key) {
            'ShortDescription' {
                $value = ($segment.Lines[0] -replace '^ShortDescription:\s*', '')
                if ($value.Length -gt 256) {
                    throw "ShortDescription is $($value.Length) characters; winget allows 256."
                }
            }
            'Tags' {
                $tags = @($segment.Lines | Where-Object { $_ -match '^-\s+' })
                if ($tags.Count -gt 16) {
                    throw "Tags has $($tags.Count) entries; winget allows 16."
                }
                foreach ($tag in $tags) {
                    $name = ($tag -replace '^-\s+', '')
                    if ($name.Length -gt 40) {
                        throw "Tag '$name' is $($name.Length) characters; winget allows 40."
                    }
                }
            }
        }
    }
}

if (-not (Test-Path -LiteralPath $MetadataPath)) {
    throw "Metadata file not found: $MetadataPath"
}

# Comments are only stripped ahead of the first key, so a '#' inside a block
# scalar (a Description mentioning a hash) is left alone.
$metadataRaw = Get-Content -LiteralPath $MetadataPath -Raw
$metadataLines = @($metadataRaw -split '\r?\n')
$firstKeyIndex = 0
for ($i = 0; $i -lt $metadataLines.Count; $i++) {
    if ($metadataLines[$i] -match '^[A-Za-z][A-Za-z0-9_]*:') { $firstKeyIndex = $i; break }
}
$metadata = Get-YamlSegments -Lines @($metadataLines[$firstKeyIndex..($metadataLines.Count - 1)])

if ($metadata.Segments.Count -eq 0) {
    throw "No top-level keys found in $MetadataPath"
}

# The metadata file's trailing newline would otherwise attach an empty line to its
# last segment, injecting a blank line mid-manifest when that key is replaced in
# place rather than appended at the end.
foreach ($segment in $metadata.Segments) {
    while ($segment.Lines.Count -gt 1 -and $segment.Lines[$segment.Lines.Count - 1] -eq '') {
        $segment.Lines.RemoveAt($segment.Lines.Count - 1)
    }
}

Assert-MetadataLimits -Segments $metadata.Segments

$manifests = @(Get-ChildItem -LiteralPath $ManifestDirectory -Recurse -Filter '*.locale.en-US.yaml' -File)
if ($manifests.Count -eq 0) {
    throw "No '*.locale.en-US.yaml' manifest found under $ManifestDirectory"
}

foreach ($manifest in $manifests) {
    $raw = Get-Content -LiteralPath $manifest.FullName -Raw
    $newline = if ($raw -match '\r\n') { "`r`n" } else { "`n" }
    $hadTrailingNewline = $raw.EndsWith("`n")

    $target = Get-YamlSegments -Lines @($raw -split '\r?\n')
    $segments = $target.Segments

    foreach ($incoming in $metadata.Segments) {
        $existing = $segments | Where-Object { $_.Key -eq $incoming.Key } | Select-Object -First 1

        if ($null -ne $existing) {
            $existing.Lines.Clear()
            foreach ($line in $incoming.Lines) { $existing.Lines.Add($line) }
            Write-Host "  replaced $($incoming.Key)"
            continue
        }

        # Not emitted by komac: insert at the schema position by walking back to
        # the nearest preceding key that the manifest does contain.
        $schemaIndex = $schemaOrder.IndexOf($incoming.Key)
        if ($schemaIndex -lt 0) {
            throw "Key '$($incoming.Key)' is not part of the defaultLocale schema order."
        }

        $insertAt = 0
        for ($i = $schemaIndex - 1; $i -ge 0; $i--) {
            $anchorKey = $schemaOrder[$i]
            $anchorIndex = -1
            for ($j = 0; $j -lt $segments.Count; $j++) {
                if ($segments[$j].Key -eq $anchorKey) { $anchorIndex = $j; break }
            }
            if ($anchorIndex -ge 0) { $insertAt = $anchorIndex + 1; break }
        }

        $segments.Insert($insertAt, $incoming)
        Write-Host "  inserted $($incoming.Key)"
    }

    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($line in $target.Preamble) { $out.Add($line) }
    foreach ($segment in $segments) {
        foreach ($line in $segment.Lines) { $out.Add($line) }
    }

    # A trailing empty element from the original split would double the final
    # newline once re-joined, so drop it and restore the newline explicitly.
    while ($out.Count -gt 0 -and $out[$out.Count - 1] -eq '') { $out.RemoveAt($out.Count - 1) }

    $text = [string]::Join($newline, $out)
    if ($hadTrailingNewline) { $text += $newline }

    # No BOM: winget-pkgs manifests are plain UTF-8.
    [System.IO.File]::WriteAllText($manifest.FullName, $text, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Applied locale metadata to $($manifest.Name) ($(if ($newline -eq "`r`n") { 'CRLF' } else { 'LF' }) preserved)"
}

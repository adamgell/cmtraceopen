param(
  [Parameter(Mandatory)][string]$Tag,
  [Parameter(Mandatory)][string]$ReleaseMetadataPath,
  [Parameter(Mandatory)][string]$InstallerPath,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [string]$TemplateRoot = (Join-Path $PSScriptRoot '../packaging/chocolatey/cmtraceopen')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Tag -cnotmatch '^v\d+\.\d+\.\d+$') { throw 'Expected a stable vMAJOR.MINOR.PATCH tag' }
$version = $Tag.Substring(1)
$release = Get-Content $ReleaseMetadataPath -Raw | ConvertFrom-Json
if ($release.tag_name -cne $Tag -or $release.draft -ne $false -or $release.prerelease -ne $false) {
  throw 'Expected the selected published stable release'
}
$assetName = "CMTrace-Open_${version}_x64.msi"
$url = "https://github.com/adamgell/cmtraceopen/releases/download/$Tag/$assetName"
$assets = @($release.assets | Where-Object { $_.name -ceq $assetName })
if ($assets.Count -ne 1 -or $assets[0].browser_download_url -cne $url -or
    $assets[0].digest -cnotmatch '^sha256:[0-9a-f]{64}$') { throw 'Expected one product MSI with a SHA256 release digest' }
$checksum = $assets[0].digest.Substring(7)

$nuspecText = Get-Content (Join-Path $TemplateRoot 'cmtraceopen.nuspec') -Raw
$templateVersion = [string]([xml]$nuspecText).package.metadata.version
if ($templateVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Invalid template version' }
$source = Get-Content (Join-Path $TemplateRoot 'tools/chocolateyinstall.ps1') -Raw
$checksums = [regex]::Matches($source, "checksum\s*=\s*'([0-9a-f]{64})'")
if ($checksums.Count -ne 1) { throw 'Expected one template checksum' }
$templateUrl = "https://github.com/adamgell/cmtraceopen/releases/download/v$templateVersion/CMTrace-Open_${templateVersion}_x64.msi"
$source = $source.Replace($templateUrl, $url).Replace($checksums[0].Groups[1].Value, $checksum)
$replacements = @(
  @{From="<version>$templateVersion</version>"; To="<version>$version</version>"},
  @{From="<tags>cmtraceopen $templateVersion "; To="<tags>cmtraceopen $version "},
  @{From="<iconUrl>https://cdn.jsdelivr.net/gh/adamgell/cmtraceopen@v$templateVersion/logo.png</iconUrl>"; To="<iconUrl>https://cdn.jsdelivr.net/gh/adamgell/cmtraceopen@$Tag/logo.png</iconUrl>"}
)
foreach ($replacement in $replacements) {
  if ([regex]::Matches($nuspecText, [regex]::Escape($replacement.From)).Count -ne 1) { throw 'Missing or ambiguous package metadata template fragment' }
}
foreach ($replacement in $replacements) { $nuspecText = $nuspecText.Replace($replacement.From, $replacement.To) }
if (Test-Path $OutputDirectory) { throw 'Output directory must not already exist' }
New-Item -ItemType Directory -Path (Join-Path $OutputDirectory 'tools') | Out-Null
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'cmtraceopen.nuspec'), $nuspecText)
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'tools/chocolateyinstall.ps1'), $source)
& (Join-Path $PSScriptRoot 'validate-chocolatey-package.ps1') -PackageRoot $OutputDirectory -ReleaseMetadataPath $ReleaseMetadataPath -InstallerPath $InstallerPath

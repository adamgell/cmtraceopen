param(
  [Parameter(Mandatory)][string]$PackageRoot,
  [Parameter(Mandatory)][string]$ReleaseMetadataPath,
  [Parameter(Mandatory)][string]$InstallerPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

[xml]$nuspec = Get-Content (Join-Path $PackageRoot 'cmtraceopen.nuspec') -Raw
$version = [string]$nuspec.package.metadata.version
if ($nuspec.package.metadata.id -cne 'cmtraceopen' -or $version -notmatch '^\d+\.\d+\.\d+$') {
  throw 'Expected cmtraceopen with a stable three-part version'
}
$assetName = "CMTrace-Open_${version}_x64.msi"
$expectedUrl = "https://github.com/adamgell/cmtraceopen/releases/download/v$version/$assetName"
$release = Get-Content $ReleaseMetadataPath -Raw | ConvertFrom-Json
if ($release.draft -ne $false -or $release.prerelease -ne $false -or $release.tag_name -cne "v$version") {
  throw 'Package version must match a published stable release'
}
$assets = @($release.assets | Where-Object { $_.name -ceq $assetName })
if ($assets.Count -ne 1 -or $assets[0].browser_download_url -cne $expectedUrl) {
  throw 'Expected exactly one matching release asset from the product repository'
}

$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  (Join-Path $PackageRoot 'tools/chocolateyinstall.ps1'), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Install script has PowerShell syntax errors' }
$statements = @($ast.EndBlock.Statements)
if ($ast.ParamBlock -or $ast.BeginBlock -or $ast.ProcessBlock -or $ast.CleanBlock -or $ast.DynamicParamBlock -or
    $ast.UsingStatements -or $ast.EndBlock.Traps -or $statements.Count -ne 5) {
  throw 'Installer must retain the existing five-statement structure'
}
$expectedAssignments = @('$ErrorActionPreference', '$toolsDir', '$url', '$packageArgs')
for ($i = 0; $i -lt $expectedAssignments.Count; $i++) {
  if ($statements[$i] -isnot [System.Management.Automation.Language.AssignmentStatementAst] -or
      $statements[$i].Left.Extent.Text -cne $expectedAssignments[$i] -or
      $statements[$i].Operator -ne 'Equals') { throw 'Unexpected installer assignment' }
}
if ($statements[0].Right.Expression.SafeGetValue() -cne 'Stop' -or
    $statements[1].Right.Extent.Text -cne '"$(Split-Path -parent $MyInvocation.MyCommand.Definition)"' -or
    $statements[4].Extent.Text.Trim() -cne 'Install-ChocolateyPackage @packageArgs') {
  throw 'Existing installer setup or invocation changed'
}
$assignments = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)
$urlAssignments = @($assignments | Where-Object { $_.Left.Extent.Text -ceq '$url' })
$argumentAssignments = @($assignments | Where-Object { $_.Left.Extent.Text -ceq '$packageArgs' })
if ($urlAssignments.Count -ne 1 -or $argumentAssignments.Count -ne 1) { throw 'Ambiguous installer arguments' }
if ($urlAssignments[0].Right.Expression.SafeGetValue() -cne $expectedUrl) { throw 'Installer URL does not match release version' }
$table = $argumentAssignments[0].Right.Expression
if ($table -isnot [System.Management.Automation.Language.HashtableAst]) { throw 'Expected literal package arguments' }
$arguments = @{}
foreach ($pair in $table.KeyValuePairs) {
  $name = $pair.Item1.SafeGetValue()
  if ($arguments.ContainsKey($name)) { throw 'Duplicate package argument' }
  $arguments[$name] = $pair.Item2
}
$allowedArguments = @('packageName', 'unzipLocation', 'fileType', 'url', 'softwareName', 'checksum', 'checksumType', 'validExitCodes', 'silentArgs')
if ($arguments.Count -ne $allowedArguments.Count -or
    @($arguments.Keys | Where-Object { $_ -cnotin $allowedArguments }).Count -ne 0) {
  throw 'Unexpected package argument set'
}
foreach ($entry in @{fileType='msi'; softwareName='CMTrace Open'; checksumType='sha256'; silentArgs='/qn'}.GetEnumerator()) {
  if ($arguments[$entry.Key].SafeGetValue() -cne $entry.Value) { throw "Unexpected $($entry.Key)" }
}
if ($arguments.url.Extent.Text.Trim() -cne '$url' -or
    $arguments.packageName.Extent.Text.Trim() -cne '$env:ChocolateyPackageName' -or
    $arguments.unzipLocation.Extent.Text.Trim() -cne '$toolsDir') { throw 'Unexpected package argument binding' }
$exitCodes = @($arguments.validExitCodes.SafeGetValue())
if ($exitCodes.Count -ne 1 -or $exitCodes[0] -ne 0) { throw 'Existing installer exit-code policy changed' }
$commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
if (@($commands | Where-Object { $_.GetCommandName() -notin @('Split-Path', 'Install-ChocolateyPackage') }).Count -ne 0 -or
    @($commands | Where-Object { $_.Extent.Text.Trim() -ceq 'Install-ChocolateyPackage @packageArgs' }).Count -ne 1) {
  throw 'Unexpected install command'
}
$checksum = [string]$arguments.checksum.SafeGetValue()
if ($checksum -cnotmatch '^[0-9a-f]{64}$' -or $assets[0].digest -cne "sha256:$checksum") { throw 'Release digest differs from package checksum' }
$actual = (Get-FileHash $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -cne $checksum -or (Get-Item $InstallerPath).Length -ne $assets[0].size) { throw 'Downloaded installer differs from release asset' }

[pscustomobject]@{Version=$version; Sha256=$checksum; AssetName=$assetName}

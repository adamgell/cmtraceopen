[CmdletBinding()]
param(
    [string]$SdkBinRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
)

$pathCommand = Get-Command mt.exe -ErrorAction SilentlyContinue
if ($null -ne $pathCommand -and -not [string]::IsNullOrWhiteSpace($pathCommand.Source)) {
    $pathCommand.Source
    exit 0
}

if (-not (Test-Path -LiteralPath $SdkBinRoot -PathType Container)) {
    throw "Windows SDK bin directory was not found: $SdkBinRoot"
}

$candidate = Get-ChildItem -LiteralPath $SdkBinRoot -Directory | ForEach-Object {
    try {
        $sdkVersion = [version]$_.Name
    }
    catch {
        return
    }
    $toolPath = Join-Path $_.FullName 'x64\mt.exe'
    if (Test-Path -LiteralPath $toolPath -PathType Leaf) {
        [pscustomobject]@{
            Version = $sdkVersion
            Path = $toolPath
        }
    }
} | Sort-Object Version -Descending | Select-Object -First 1

if ($null -eq $candidate) {
    throw "Windows SDK x64 mt.exe was not found under: $SdkBinRoot"
}

$candidate.Path

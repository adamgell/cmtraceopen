Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-True {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Condition,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Equal {
    param(
        [AllowNull()]
        $Actual,
        [AllowNull()]
        $Expected,
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw ('{0} (expected: {1}; actual: {2})' -f $Message, $Expected, $Actual)
    }
}

function Import-CollectorFunctions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string[]]$FunctionNames
    )

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath,
        [ref]$tokens,
        [ref]$errors
    )

    Assert-Equal -Actual $errors.Count -Expected 0 -Message 'Collector script should parse without PowerShell syntax errors'

    $definitions = $ast.FindAll(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        },
        $true
    )

    $functionDefinitions = New-Object System.Collections.Generic.List[string]
    foreach ($functionName in $FunctionNames) {
        $definition = $definitions |
            Where-Object { $_.Name -eq $functionName } |
            Select-Object -First 1
        Assert-True -Condition ($null -ne $definition) -Message ("Collector function '{0}' should exist" -f $functionName)
        $functionDefinitions.Add($definition.Extent.Text)
    }

    $moduleSource = [string]::Join([System.Environment]::NewLine + [System.Environment]::NewLine, $functionDefinitions)
    $moduleSource = $moduleSource + [System.Environment]::NewLine + [System.Environment]::NewLine +
        ("Export-ModuleMember -Function {0}" -f (($FunctionNames | ForEach-Object { "'{0}'" -f $_ }) -join ', '))

    return New-Module -Name 'CmtraceCollectorFunctionImport' -ScriptBlock ([scriptblock]::Create($moduleSource))
}

$collectorScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-CmtraceEvidenceCollection.ps1'
$collectorModule = Import-CollectorFunctions -ScriptPath $collectorScriptPath -FunctionNames @(
    'Expand-EnvironmentPath',
    'Get-ResolvedLogMatches'
)
Import-Module $collectorModule -Scope Local -Force

$teamsMsixRelativeLogPath = 'Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs'

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("cmtrace-collector-path-tests-{0}" -f ([System.Guid]::NewGuid().ToString('N')))
$driveName = 'T'
$driveRoot = Join-Path $tempRoot 'drive-root'

try {
    New-Item -Path $driveRoot -ItemType Directory -Force | Out-Null
    $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $driveRoot -Scope Script

    $aliceLogDir = '{0}:\Users\Alice\AppData\Local\{1}' -f $driveName, $teamsMsixRelativeLogPath
    $bobLogDir = '{0}:\Users\Bob\AppData\Local\{1}' -f $driveName, $teamsMsixRelativeLogPath
    New-Item -Path $aliceLogDir -ItemType Directory -Force | Out-Null
    New-Item -Path $bobLogDir -ItemType Directory -Force | Out-Null

    $aliceLogPath = Join-Path $aliceLogDir 'teams-alice.log'
    $bobLogPath = Join-Path $bobLogDir 'teams-bob.log'
    Set-Content -LiteralPath $aliceLogPath -Value 'alice log'
    Set-Content -LiteralPath $bobLogPath -Value 'bob log'
    $resolvedAliceLogPath = (Resolve-Path -LiteralPath $aliceLogPath).ProviderPath
    $resolvedBobLogPath = (Resolve-Path -LiteralPath $bobLogPath).ProviderPath

    $env:LOCALAPPDATA = '{0}:\Users\Alice\AppData\Local' -f $driveName

    $expandedMatches = @(Get-ResolvedLogMatches -SourcePattern ('%LOCALAPPDATA%\{0}\*' -f $teamsMsixRelativeLogPath))
    Assert-Equal -Actual $expandedMatches.Count -Expected 1 -Message 'Expanded %LOCALAPPDATA% pattern should match the current user Teams MSIX logs'
    Assert-Equal -Actual $expandedMatches[0].FullName -Expected $resolvedAliceLogPath -Message 'Expanded %LOCALAPPDATA% pattern should resolve to the current user log file'

    $allUserMatches = @(Get-ResolvedLogMatches -SourcePattern ('{0}:\Users\*\AppData\Local\{1}\*' -f $driveName, $teamsMsixRelativeLogPath))
    Assert-Equal -Actual $allUserMatches.Count -Expected 2 -Message 'Wildcard user-profile pattern should match Teams MSIX logs across user profiles'
    Assert-True -Condition ($allUserMatches.FullName -contains $resolvedAliceLogPath) -Message 'Wildcard user-profile pattern should include the Alice log'
    Assert-True -Condition ($allUserMatches.FullName -contains $resolvedBobLogPath) -Message 'Wildcard user-profile pattern should include the Bob log'
}
finally {
    Get-Module -Name 'CmtraceCollectorFunctionImport' -ErrorAction SilentlyContinue | Remove-Module -Force -ErrorAction SilentlyContinue
    Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue | Remove-PSDrive -Scope Script -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

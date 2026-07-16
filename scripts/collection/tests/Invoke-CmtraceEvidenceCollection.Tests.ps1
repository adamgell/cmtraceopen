BeforeAll {
    $collectorPath = Join-Path $PSScriptRoot '..' 'Invoke-CmtraceEvidenceCollection.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $collectorPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    $parseErrors | Should -BeNullOrEmpty

    $functionNames = @(
        'Get-ObjectPropertyValue',
        'Test-ArrayValue',
        'Assert-ProfileRequiredString',
        'Assert-ProfileRequiredArray',
        'Assert-CollectorProfileShape'
    )
    foreach ($functionName in $functionNames) {
        $definition = $ast.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $functionName
            },
            $true
        ) | Select-Object -First 1
        $definition | Should -Not -BeNullOrEmpty
        Invoke-Expression $definition.Extent.Text
    }

    function New-TestCollectorProfile {
        param(
            [string]$LogId = 'logs-primary',
            [string]$CommandId = 'commands-primary'
        )

        return [pscustomobject]@{
            profileName    = 'test-profile'
            profileVersion = '1.0.0'
            logs           = @(
                [pscustomobject]@{
                    id                = $LogId
                    family            = 'logs'
                    sourcePattern     = 'C:\Logs\*.log'
                    destinationFolder = 'logs'
                    parseHints        = @()
                }
            )
            registry       = @()
            eventLogs      = @()
            exports        = @()
            commands       = @(
                [pscustomobject]@{
                    id         = $CommandId
                    family     = 'commands'
                    command    = 'whoami.exe'
                    fileName   = 'whoami.txt'
                    arguments  = @()
                    parseHints = @()
                }
            )
        }
    }
}

Describe 'Assert-CollectorProfileShape' {
    It 'accepts unique artifact IDs across all sections' {
        $profile = New-TestCollectorProfile

        { Assert-CollectorProfileShape -CollectorProfile $profile -Path 'profile.json' } |
            Should -Not -Throw
    }

    It 'rejects case-insensitive duplicate artifact IDs across sections' {
        $profile = New-TestCollectorProfile -LogId 'shared-artifact' -CommandId 'SHARED-ARTIFACT'

        { Assert-CollectorProfileShape -CollectorProfile $profile -Path 'profile.json' } |
            Should -Throw -ExpectedMessage '*duplicate artifact id*shared-artifact*first declared at logs*repeated at commands*'
    }
}

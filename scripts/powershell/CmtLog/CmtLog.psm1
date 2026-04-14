#Requires -Version 5.1
<#
.SYNOPSIS
    CmtLog PowerShell module - write .cmtlog files from scripts.

.DESCRIPTION
    Provides functions to create and write files in the CMTrace Open .cmtlog
    format, which extends the standard CCM <![LOG[...]LOG]!> line format with
    reserved component names (__HEADER__, __SECTION__, __ITERATION__) and
    optional extended attributes (section, tag, whatif, iteration, color).

.NOTES
    Format reference: https://github.com/adamgell/cmtraceopen
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-scoped default file path set by Start-CmtLog
$script:CmtLogFilePath = $null

# UTF-8 without BOM encoder - PS 5.1's -Encoding UTF8 adds a BOM on every
# Add-Content call, corrupting log lines for parsers that don't expect
# embedded BOMs.
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

#region Private helpers

function Add-CmtLogLine {
    <#
    .SYNOPSIS
        Appends a line to a file using UTF-8 without BOM.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Line
    )
    [System.IO.File]::AppendAllText($Path, $Line + [Environment]::NewLine, $script:Utf8NoBom)
}

function Get-CmtLogTimestamp {
    <#
    .SYNOPSIS
        Returns a hashtable with Time and Date keys formatted for .cmtlog lines.

    .OUTPUTS
        Hashtable with keys: Time (HH:mm:ss.fff+bias), Date (MM-dd-yyyy)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $now = [datetime]::Now

    # Resolve UTC offset from Win32_TimeZone (avoids the deprecated Get-WmiObject)
    $bias = 0
    try {
        $tz = Get-CimInstance -ClassName Win32_TimeZone -ErrorAction SilentlyContinue
        if ($null -ne $tz) {
            $bias = [int]$tz.Bias
        }
    }
    catch {
        # Fall back to zero bias - non-critical
        $bias = 0
    }

    # CMTrace time format: HH:mm:ss.fff+bias  (bias is positive = west of UTC,
    # matching the historical CMTrace convention)
    # Use positive/negative/zero format sections so the sign is always correct
    $timeStr = '{0:HH:mm:ss.fff}{1:+000;-000;+000}' -f $now, $bias
    $dateStr = '{0:MM-dd-yyyy}' -f $now

    return @{
        Time = $timeStr
        Date = $dateStr
    }
}

function New-CmtLogRunId {
    <#
    .SYNOPSIS
        Generates a random 8-character hex run identifier.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $bytes = [byte[]]::new(4)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLower()
}

function Get-CmtLogContext {
    <#
    .SYNOPSIS
        Returns the current Windows identity as a string, or empty string on
        platforms where it is unavailable.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        return ''
    }
}

function Get-CmtLogMode {
    <#
    .SYNOPSIS
        Returns "WhatIf" when $WhatIfPreference is active, otherwise "Normal".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    # $WhatIfPreference is a preference variable in the caller's scope.
    # We reach it via the call stack.
    $callerWhatIf = $false
    try {
        $callerWhatIf = (Get-Variable -Name WhatIfPreference -Scope 1 -ValueOnly -ErrorAction SilentlyContinue) -eq $true
    }
    catch {
        $callerWhatIf = $false
    }

    if ($callerWhatIf) { return 'WhatIf' } else { return 'Normal' }
}

function Get-PsVersionString {
    <#
    .SYNOPSIS
        Returns a string representation of the current PowerShell version.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $v = $PSVersionTable.PSVersion
    return '{0}.{1}.{2}' -f $v.Major, $v.Minor, $v.Build
}

function Resolve-CmtLogFile {
    <#
    .SYNOPSIS
        Resolves the target file path: returns $FileName if non-null/empty,
        otherwise returns $script:CmtLogFilePath.

    .OUTPUTS
        String file path.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$FileName
    )

    if (-not [string]::IsNullOrWhiteSpace($FileName)) {
        return $FileName
    }

    if ([string]::IsNullOrWhiteSpace($script:CmtLogFilePath)) {
        throw 'No log file path specified and Start-CmtLog has not been called. Provide -FileName or call Start-CmtLog first.'
    }

    return $script:CmtLogFilePath
}

#endregion

#region Public functions

function Start-CmtLog {
    <#
    .SYNOPSIS
        Creates a new .cmtlog file with a header entry and returns the file path.

    .DESCRIPTION
        Generates a safe filename based on ScriptName and the current timestamp,
        creates the output directory if needed, writes the __HEADER__ line via
        Write-LogHeader, stores the path in $script:CmtLogFilePath, and returns
        the full path.

    .PARAMETER ScriptName
        Name of the script being logged (mandatory).

    .PARAMETER Version
        Script version string (default: "1.0.0").

    .PARAMETER OutputPath
        Directory in which to create the log file.
        Defaults to $env:ProgramData\CMTraceOpen\Logs.

    .PARAMETER FileName
        Exact file name (not path) for the log file, e.g. 'MyScript.cmtlog'.
        When provided, the timestamp suffix is omitted.

    .PARAMETER Mode
        Execution mode to embed in the header ("Normal" or "WhatIf").
        Auto-detected from $WhatIfPreference when omitted.

    .OUTPUTS
        String - full path to the created .cmtlog file.

    .EXAMPLE
        $log = Start-CmtLog -ScriptName 'Detect-WDAC.ps1' -Version '2.1.0'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptName,

        [Parameter()]
        [string]$Version = '1.0.0',

        [Parameter()]
        [string]$OutputPath = '',

        [Parameter()]
        [string]$FileName = '',

        [Parameter()]
        [ValidateSet('Normal', 'WhatIf')]
        [string]$Mode = ''
    )

    # Resolve output directory
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $env:ProgramData 'CMTraceOpen\Logs'
    }

    # Create directory if it does not exist
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        $null = New-Item -ItemType Directory -Path $OutputPath -Force
    }

    # Build safe file name: {ScriptName}_{yyyyMMdd-HHmmss}.cmtlog or use -FileName
    if (-not [string]::IsNullOrWhiteSpace($FileName)) {
        $fileName = $FileName
    }
    else {
        # Strip any path separators or characters unsafe for file names
        $safeName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptName) -replace '[\\/:*?"<>|]', '_'
        $timestamp = [datetime]::Now.ToString('yyyyMMdd-HHmmss')
        $fileName = '{0}_{1}.cmtlog' -f $safeName, $timestamp
    }
    $filePath = Join-Path $OutputPath $fileName

    # Resolve mode
    if ([string]::IsNullOrWhiteSpace($Mode)) {
        $Mode = if ($WhatIfPreference) { 'WhatIf' } else { 'Normal' }
    }

    # Store for module-wide use
    $script:CmtLogFilePath = $filePath

    # Create the file and write the header
    $null = New-Item -ItemType File -Path $filePath -Force
    Write-LogHeader -ScriptName $ScriptName -Version $Version -Mode $Mode -FileName $filePath

    return $filePath
}

function Write-LogHeader {
    <#
    .SYNOPSIS
        Emits a __HEADER__ line to the log file.

    .DESCRIPTION
        Writes the first structured line of a .cmtlog file recording the script
        name, version, execution mode, PS version, and a random run identifier.

    .PARAMETER ScriptName
        Name of the script being logged (mandatory).

    .PARAMETER Version
        Script version string.

    .PARAMETER Mode
        Execution mode ("Normal" or "WhatIf"). Auto-detected from
        $WhatIfPreference when omitted.

    .PARAMETER FileName
        Path to the log file. Falls back to $script:CmtLogFilePath.

    .EXAMPLE
        Write-LogHeader -ScriptName 'Deploy-App.ps1' -Version '3.0.0'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ScriptName,

        [Parameter()]
        [string]$Version = '1.0.0',

        [Parameter()]
        [ValidateSet('Normal', 'WhatIf')]
        [string]$Mode = '',

        [Parameter()]
        [string]$FileName = ''
    )

    $resolvedFile = Resolve-CmtLogFile -FileName $FileName

    # Resolve mode
    if ([string]::IsNullOrWhiteSpace($Mode)) {
        $Mode = if ($WhatIfPreference) { 'WhatIf' } else { 'Normal' }
    }

    $ts = Get-CmtLogTimestamp
    $runId = New-CmtLogRunId
    $psVer = Get-PsVersionString

    $line = '<![LOG[Script started: {0} v{1}]LOG]!><time="{2}" date="{3}" component="__HEADER__" context="" type="1" thread="0" file="" script="{0}" version="{1}" runid="{4}" mode="{5}" ps_version="{6}">' -f `
        $ScriptName, $Version, $ts.Time, $ts.Date, $runId, $Mode, $psVer

    Add-CmtLogLine -Path $resolvedFile -Line $line
}

function Write-LogEntry {
    <#
    .SYNOPSIS
        Emits a standard log line to the .cmtlog file.

    .DESCRIPTION
        Writes a CCM-format log line with optional CmtLog extended attributes
        (section, tag, whatif, iteration) appended before the closing >.

    .PARAMETER Value
        Log message text (mandatory).

    .PARAMETER Severity
        Log severity: "1" (Information), "2" (Warning), or "3" (Error) (mandatory).

    .PARAMETER Component
        Component name. Defaults to "Script".

    .PARAMETER Section
        Section label to associate with this entry.

    .PARAMETER Tag
        One or more tags. Multiple values are joined with commas.

    .PARAMETER WhatIfEntry
        When present, sets whatif="1" on the entry.

    .PARAMETER Iteration
        Iteration identifier (e.g. "1/3") to associate with this entry.

    .PARAMETER FileName
        Path to the log file. Falls back to $script:CmtLogFilePath.

    .EXAMPLE
        Write-LogEntry -Value 'Policy file found' -Severity '1' -Section 'detection' -Tag 'phase:scan','result:ok'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [Parameter(Mandatory)]
        [ValidateSet('1', '2', '3')]
        [string]$Severity,

        [Parameter()]
        [string]$Component = 'Script',

        [Parameter()]
        [string]$Section = '',

        [Parameter()]
        [string[]]$Tag = @(),

        [Parameter()]
        [switch]$WhatIfEntry,

        [Parameter()]
        [string]$Iteration = '',

        [Parameter()]
        [string]$FileName = ''
    )

    $resolvedFile = Resolve-CmtLogFile -FileName $FileName
    $ts = Get-CmtLogTimestamp
    $context = Get-CmtLogContext
    $thread = $PID

    # Build base line (no closing > yet)
    $base = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="{3}" context="{4}" type="{5}" thread="{6}" file=""' -f `
        $Value, $ts.Time, $ts.Date, $Component, $context, $Severity, $thread

    # Append optional extended attributes
    $extended = [System.Text.StringBuilder]::new($base)

    if (-not [string]::IsNullOrWhiteSpace($Section)) {
        $null = $extended.Append(' section="{0}"' -f $Section)
    }

    if ($Tag.Count -gt 0) {
        $tagValue = ($Tag | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join ','
        if (-not [string]::IsNullOrWhiteSpace($tagValue)) {
            $null = $extended.Append(' tag="{0}"' -f $tagValue)
        }
    }

    if ($WhatIfEntry.IsPresent) {
        $null = $extended.Append(' whatif="1"')
    }

    if (-not [string]::IsNullOrWhiteSpace($Iteration)) {
        $null = $extended.Append(' iteration="{0}"' -f $Iteration)
    }

    $null = $extended.Append('>')
    $line = $extended.ToString()

    Add-CmtLogLine -Path $resolvedFile -Line $line
}

function Write-LogSection {
    <#
    .SYNOPSIS
        Emits a __SECTION__ marker line to the .cmtlog file.

    .DESCRIPTION
        Writes a section boundary that CMTrace Open renders as a visual divider.
        The color attribute is only included when -Color is provided.

    .PARAMETER Name
        Section name to display (mandatory).

    .PARAMETER Color
        Optional hex color string (e.g. "#5b9aff"). Omitted from output when
        not specified.

    .PARAMETER FileName
        Path to the log file. Falls back to $script:CmtLogFilePath.

    .EXAMPLE
        Write-LogSection -Name 'Detection Phase' -Color '#5b9aff'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [string]$Color = '',

        [Parameter()]
        [string]$FileName = ''
    )

    $resolvedFile = Resolve-CmtLogFile -FileName $FileName
    $ts = Get-CmtLogTimestamp

    $base = '<![LOG[{0}]LOG]!><time="{1}" date="{2}" component="__SECTION__" context="" type="1" thread="0" file=""' -f `
        $Name, $ts.Time, $ts.Date

    if (-not [string]::IsNullOrWhiteSpace($Color)) {
        $line = '{0} color="{1}">' -f $base, $Color
    }
    else {
        $line = '{0}>' -f $base
    }

    Add-CmtLogLine -Path $resolvedFile -Line $line
}

function Write-LogIteration {
    <#
    .SYNOPSIS
        Emits an __ITERATION__ marker line to the .cmtlog file.

    .DESCRIPTION
        Writes a loop iteration boundary. CMTrace Open renders this as a
        progress indicator within the current section.

    .PARAMETER Name
        Descriptive name for the iteration target (mandatory).

    .PARAMETER Current
        Current iteration index, 1-based (mandatory).

    .PARAMETER Total
        Total number of iterations (mandatory).

    .PARAMETER Color
        Optional hex color string. Omitted from output when not specified.

    .PARAMETER FileName
        Path to the log file. Falls back to $script:CmtLogFilePath.

    .EXAMPLE
        Write-LogIteration -Name 'WDAC policies' -Current 1 -Total 3 -Color '#a78bfa'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Current,

        [Parameter(Mandatory)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Total,

        [Parameter()]
        [string]$Color = '',

        [Parameter()]
        [string]$FileName = ''
    )

    $resolvedFile = Resolve-CmtLogFile -FileName $FileName
    $ts = Get-CmtLogTimestamp
    $iterationFrac = '{0}/{1}' -f $Current, $Total

    $base = '<![LOG[Loop Iteration {0} - {1}]LOG]!><time="{2}" date="{3}" component="__ITERATION__" context="" type="1" thread="0" file="" iteration="{0}"' -f `
        $iterationFrac, $Name, $ts.Time, $ts.Date

    if (-not [string]::IsNullOrWhiteSpace($Color)) {
        $line = '{0} color="{1}">' -f $base, $Color
    }
    else {
        $line = '{0}>' -f $base
    }

    Add-CmtLogLine -Path $resolvedFile -Line $line
}

#endregion

Export-ModuleMember -Function Start-CmtLog, Write-LogEntry, Write-LogSection, Write-LogIteration, Write-LogHeader

#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery shared library. Dot-source from every collector.
  Windows PowerShell 5.1 and PowerShell 7 compatible (no ternary, no ??, no -Parallel).

  Evidence model
    Add-CEREvidence  -Control 'IAM-04' -Flag Attention|OK|Info|Unknown -Evidence '<one or two sentences with numbers>' [-Data <object>]
    Set-CERCoverage  -Collector Entra -Section ConditionalAccess -Status Collected|Partial|Failed|Skipped|NotLicensed|NoAccess -Note '...'
  Every collector writes  <run>/evidence/<collector>.evidence.json  and  <run>/coverage/<collector>.coverage.json
  New-CEREvidencePack merges everything found under the run folder, so on-prem and cloud collectors
  can run on different machines and be copied together afterwards.
#>
Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$script:CER = $null
$script:CERSectionOverride = $null

function Initialize-CERRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Client,
        [string]$OutputRoot,
        [string]$Collector = 'run',
        [string]$RunId
    )
    if (-not $OutputRoot) { $OutputRoot = Join-Path (Get-Location).Path 'output' }
    if (-not $RunId) { $RunId = Get-Date -Format 'yyyyMMdd-HHmm' }
    $runDir = Join-Path (Join-Path $OutputRoot $Client) $RunId
    foreach ($sub in @('', 'raw', 'evidence', 'coverage', 'logs', 'hosts')) {
        $d = if ($sub) { Join-Path $runDir $sub } else { $runDir }
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
    $script:CER = [ordered]@{
        Client    = $Client
        RunId     = $RunId
        RunDir    = $runDir
        Collector = $Collector
        Evidence  = New-Object System.Collections.ArrayList
        Coverage  = New-Object System.Collections.ArrayList
        LogFile   = Join-Path (Join-Path $runDir 'logs') ("{0}.log" -f $Collector)
        Started   = Get-Date
        Host      = $env:COMPUTERNAME
        User      = $env:USERNAME
        ToolVersion = '1.0'
    }
    Write-CERLog ("Run initialised  client={0}  run={1}  collector={2}  dir={3}" -f $Client, $RunId, $Collector, $runDir)
    return $script:CER
}

function Get-CERRun { return $script:CER }

function Write-CERLog {
    param([Parameter(Mandatory)][string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'DEBUG' { Write-Verbose $line }
        default { Write-Host $line }
    }
    if ($script:CER -and $script:CER.LogFile) { try { Add-Content -LiteralPath $script:CER.LogFile -Value $line -Encoding UTF8 } catch { } }
}

function Add-CEREvidence {
    <# One evidence line for one control. Keep Evidence factual and numeric; the reviewer scores it. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][ValidateSet('OK', 'Attention', 'Info', 'Unknown')][string]$Flag,
        [Parameter(Mandatory)][string]$Evidence,
        [string]$Source,
        [object]$Data
    )
    if (-not $script:CER) { throw 'Call Initialize-CERRun first.' }
    $e = [ordered]@{
        Control   = $Control
        Flag      = $Flag
        Evidence  = $Evidence
        Source    = if ($Source) { $Source } else { $script:CER.Collector }
        Collector = $script:CER.Collector
        Timestamp = (Get-Date).ToString('s')
    }
    if ($null -ne $Data) { $e['Data'] = $Data }
    $null = $script:CER.Evidence.Add([pscustomobject]$e)
}

function Set-CERCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Collector,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][ValidateSet('Collected', 'Partial', 'Failed', 'Skipped', 'NotLicensed', 'NoAccess', 'NotInstalled')][string]$Status,
        [string]$Note
    )
    if (-not $script:CER) { throw 'Call Initialize-CERRun first.' }
    # replace an existing entry for the same collector/section
    $existing = @($script:CER.Coverage | Where-Object { $_.Collector -eq $Collector -and $_.Section -eq $Section })
    foreach ($x in $existing) { $script:CER.Coverage.Remove($x) }
    $null = $script:CER.Coverage.Add([pscustomobject][ordered]@{
        Collector = $Collector; Section = $Section; Status = $Status; Note = $Note; Timestamp = (Get-Date).ToString('s'); Host = $env:COMPUTERNAME
    })
}

function Set-CERSectionResult {
    <# Call inside an Invoke-CERSection block to downgrade the automatic 'Collected' (e.g. to Partial). #>
    param([Parameter(Mandatory)][ValidateSet('Collected', 'Partial', 'Skipped', 'NotLicensed', 'NoAccess', 'NotInstalled')][string]$Status, [string]$Note)
    $script:CERSectionOverride = @{ Status = $Status; Note = $Note }
}

function Invoke-CERSection {
    <# Runs a block; records coverage; never throws. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Collector, [Parameter(Mandatory)][string]$Section, [Parameter(Mandatory)][scriptblock]$Script)
    Write-CERLog ("[{0}] {1} ..." -f $Collector, $Section)
    $script:CERSectionOverride = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $null = & $Script
        if ($script:CERSectionOverride) {
            Set-CERCoverage -Collector $Collector -Section $Section -Status $script:CERSectionOverride.Status -Note $script:CERSectionOverride.Note
        } else {
            Set-CERCoverage -Collector $Collector -Section $Section -Status 'Collected' -Note ("{0:n1}s" -f $sw.Elapsed.TotalSeconds)
        }
    } catch {
        $m = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $m = $m + ' | ' + $_.ErrorDetails.Message }
        $status = 'Failed'
        if ($m -match 'Authorization_RequestDenied|Insufficient privileges|Forbidden|\(403\)|does not have (the )?required|AccessDenied|UnauthorizedAccess|not authorized') { $status = 'NoAccess' }
        elseif ($m -match 'licen[cs]e|premium|AADSTS|B2C|not enabled for|requires an active|PremiumLicenseRequired|Tenant is not licensed') { $status = 'NotLicensed' }
        elseif ($m -match 'is not recognized as|could not be loaded|not installed|The term .* is not recognized') { $status = 'NotInstalled' }
        Set-CERCoverage -Collector $Collector -Section $Section -Status $status -Note ($m -replace '\s+', ' ').Substring(0, [Math]::Min(400, ($m -replace '\s+', ' ').Length))
        Write-CERLog ("[{0}] {1} {2}: {3}" -f $Collector, $Section, $status, $m) 'WARN'
    }
}

function Save-CERRaw {
    <# Saves an object as <run>/raw/<collector>.<name>.json. Returns the path. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][AllowNull()][object]$Object, [int]$Depth = 8, [string]$Collector)
    if (-not $Collector) { $Collector = $script:CER.Collector }
    $path = Join-Path (Join-Path $script:CER.RunDir 'raw') ("{0}.{1}.json" -f $Collector.ToLower(), $Name)
    try {
        if ($null -eq $Object) { '[]' | Set-Content -LiteralPath $path -Encoding UTF8 }
        else { ConvertTo-Json -InputObject $Object -Depth $Depth | Set-Content -LiteralPath $path -Encoding UTF8 }   # -InputObject keeps one-element arrays as arrays
    } catch { Write-CERLog ("Save-CERRaw {0} failed: {1}" -f $Name, $_.Exception.Message) 'WARN' }
    return $path
}

function Get-CERRaw {
    <# Loads a previously saved raw file from the same run (any collector). Returns $null if absent. #>
    param([Parameter(Mandatory)][string]$Collector, [Parameter(Mandatory)][string]$Name)
    $path = Join-Path (Join-Path $script:CER.RunDir 'raw') ("{0}.{1}.json" -f $Collector.ToLower(), $Name)
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    try { return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

function Complete-CERCollector {
    <# Flushes evidence and coverage for this collector to disk. #>
    param([string]$Collector)
    if (-not $Collector) { $Collector = $script:CER.Collector }
    $ev = Join-Path (Join-Path $script:CER.RunDir 'evidence') ("{0}.evidence.json" -f $Collector.ToLower())
    $cv = Join-Path (Join-Path $script:CER.RunDir 'coverage') ("{0}.coverage.json" -f $Collector.ToLower())
    $evidence = @($script:CER.Evidence | Where-Object { $_.Collector -eq $Collector })
    $coverage = @($script:CER.Coverage | Where-Object { $_.Collector -eq $Collector })
    if ($evidence.Count -eq 0) { '[]' | Set-Content -LiteralPath $ev -Encoding UTF8 } else { ConvertTo-Json -InputObject $evidence -Depth 8 | Set-Content -LiteralPath $ev -Encoding UTF8 }
    if ($coverage.Count -eq 0) { '[]' | Set-Content -LiteralPath $cv -Encoding UTF8 } else { ConvertTo-Json -InputObject $coverage -Depth 4 | Set-Content -LiteralPath $cv -Encoding UTF8 }
    $info = [ordered]@{
        Client = $script:CER.Client; RunId = $script:CER.RunId; Collector = $Collector; Host = $env:COMPUTERNAME; User = $env:USERNAME
        Started = $script:CER.Started.ToString('s'); Finished = (Get-Date).ToString('s'); PSVersion = $PSVersionTable.PSVersion.ToString()
        EvidenceRows = $evidence.Count; Sections = $coverage.Count
        Failed = @($coverage | Where-Object { $_.Status -in 'Failed', 'NoAccess', 'NotLicensed', 'NotInstalled' }).Count
    }
    $info | ConvertTo-Json | Set-Content -LiteralPath (Join-Path (Join-Path $script:CER.RunDir 'logs') ("{0}.runinfo.json" -f $Collector.ToLower())) -Encoding UTF8
    Write-CERLog ("[{0}] done: {1} evidence rows, {2} sections ({3} not collected). Files: {4}" -f $Collector, $evidence.Count, $coverage.Count, $info.Failed, $ev)
}

# ---------------------------------------------------------------- Graph helper
function Get-CERGraph {
    <# GET with paging. Returns array of .value items (or the object itself when there is no .value). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri, [switch]$Beta, [switch]$All, [int]$MaxPages = 60, [hashtable]$Headers)
    $base = if ($Beta) { 'https://graph.microsoft.com/beta/' } else { 'https://graph.microsoft.com/v1.0/' }
    $u = if ($Uri -match '^https://') { $Uri } else { $base + $Uri.TrimStart('/') }
    $items = New-Object System.Collections.ArrayList
    $pages = 0
    do {
        $params = @{ Method = 'GET'; Uri = $u; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($Headers) { $params['Headers'] = $Headers }
        $resp = Invoke-MgGraphRequest @params
        $pages++
        $hasValue = $false
        if ($null -ne $resp -and ($resp.PSObject.Properties.Name -contains 'value')) { $hasValue = $true }
        if ($hasValue) {
            foreach ($v in @($resp.value)) { $null = $items.Add($v) }
            $u = $null
            if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $u = $resp.'@odata.nextLink' }
        } else {
            return $resp
        }
    } while ($All -and $u -and $pages -lt $MaxPages)
    return , $items.ToArray()
}

function Test-CERModule {
    <# Returns $true if a module is available; logs and records coverage otherwise. #>
    param([Parameter(Mandatory)][string]$Name, [string]$Collector, [string]$Section = 'Module')
    $m = Get-Module -ListAvailable -Name $Name | Select-Object -First 1
    if ($m) { return $true }
    if ($Collector) { Set-CERCoverage -Collector $Collector -Section $Section -Status 'NotInstalled' -Note ("PowerShell module '{0}' not installed. Install-Module {0} -Scope CurrentUser" -f $Name) }
    Write-CERLog ("Module {0} not installed" -f $Name) 'WARN'
    return $false
}

# ---------------------------------------------------------------- small helpers
function ConvertTo-CERPct { param([double]$Part, [double]$Whole) if ($Whole -le 0) { return 'n/a' } return ('{0:n0}%' -f (100 * $Part / $Whole)) }
function Get-CERAgeDays { param($Date) if (-not $Date) { return $null } try { return [int]((Get-Date) - [datetime]$Date).TotalDays } catch { return $null } }
function Join-CERList { param($Items, [int]$Max = 8) $a = @($Items | Where-Object { $_ }) ; if ($a.Count -eq 0) { return '-' } ; $s = ($a | Select-Object -First $Max) -join ', ' ; if ($a.Count -gt $Max) { $s += (' (+{0} more)' -f ($a.Count - $Max)) } ; return $s }
function Get-CERProp { param($Object, [string]$Name, $Default = $null) if ($null -eq $Object) { return $Default } ; $p = $Object.PSObject.Properties[$Name] ; if ($p -and $null -ne $p.Value) { return $p.Value } ; return $Default }

# Windows build -> support status (verified 05/09/2026 against Microsoft Lifecycle; keep this table current)
function Get-CERWindowsSupport {
    param([string]$Caption, [string]$Version, [int]$ProductType = 1, [string]$EditionId)
    $build = 0
    if ($Version -match '(\d+)\.(\d+)\.(\d+)') { $build = [int]$Matches[3] } elseif ($Version -match '^\d+') { $build = 0 }
    $major = if ($Version -match '^(\d+)\.(\d+)') { "$($Matches[1]).$($Matches[2])" } else { '' }
    $r = [ordered]@{ Family = ''; Supported = $true; EndOfSupport = ''; Note = '' }
    if ($ProductType -eq 1) {
        if ($major -eq '10.0' -and $build -ge 22000) { $r.Family = 'Windows 11'; $r.Note = 'Check feature-update currency (each release ~24-36 months)' }
        elseif ($major -eq '10.0') {
            if ($EditionId -match 'EnterpriseS') { $r.Family = 'Windows 10 LTSC'; $r.Note = 'LTSC 2019 supported to 9 Jan 2029; LTSC 2021 to 13 Jan 2032' }
            else { $r.Family = 'Windows 10'; $r.Supported = $false; $r.EndOfSupport = '14 Oct 2025'; $r.Note = 'Out of support unless enrolled in ESU' }
        }
        elseif ($major -eq '6.3') { $r.Family = 'Windows 8.1'; $r.Supported = $false; $r.EndOfSupport = '10 Jan 2023' }
        elseif ($major -eq '6.1') { $r.Family = 'Windows 7'; $r.Supported = $false; $r.EndOfSupport = '14 Jan 2020' }
        else { $r.Family = $Caption }
    } else {
        if ($major -eq '10.0' -and $build -ge 26100) { $r.Family = 'Windows Server 2025' }
        elseif ($major -eq '10.0' -and $build -ge 20348) { $r.Family = 'Windows Server 2022'; $r.Note = 'Mainstream ends 13 Oct 2026; extended to 14 Oct 2031' }
        elseif ($major -eq '10.0' -and $build -ge 17763) { $r.Family = 'Windows Server 2019'; $r.Note = 'Extended support to 9 Jan 2029' }
        elseif ($major -eq '10.0' -and $build -ge 14393) { $r.Family = 'Windows Server 2016'; $r.EndOfSupport = '12 Jan 2027'; $r.Note = 'Plan migration now' }
        elseif ($major -eq '6.3') { $r.Family = 'Windows Server 2012 R2'; $r.Supported = $false; $r.EndOfSupport = '10 Oct 2023 (ESU year 3 ends 13 Oct 2026)' }
        elseif ($major -eq '6.2') { $r.Family = 'Windows Server 2012'; $r.Supported = $false; $r.EndOfSupport = '10 Oct 2023 (ESU year 3 ends 13 Oct 2026)' }
        elseif ($major -eq '6.1') { $r.Family = 'Windows Server 2008 R2'; $r.Supported = $false; $r.EndOfSupport = '14 Jan 2020' }
        elseif ($major -eq '6.0') { $r.Family = 'Windows Server 2008'; $r.Supported = $false; $r.EndOfSupport = '14 Jan 2020' }
        else { $r.Family = $Caption }
    }
    return [pscustomobject]$r
}

function Get-CERSqlSupport {
    param([string]$Version)
    $maj = 0; if ($Version -match '^(\d+)\.') { $maj = [int]$Matches[1] }
    switch ($maj) {
        16 { return @{ Name = 'SQL Server 2022'; Supported = $true; Note = 'Mainstream to 11 Jan 2028' } }
        15 { return @{ Name = 'SQL Server 2019'; Supported = $true; Note = 'Extended support to 8 Jan 2030' } }
        14 { return @{ Name = 'SQL Server 2017'; Supported = $true; Note = 'Extended support to 12 Oct 2027' } }
        13 { return @{ Name = 'SQL Server 2016'; Supported = $false; Note = 'Out of support since 14 Jul 2026 (ESU available)' } }
        12 { return @{ Name = 'SQL Server 2014'; Supported = $false; Note = 'Out of support since 9 Jul 2024 (ESU available)' } }
        11 { return @{ Name = 'SQL Server 2012'; Supported = $false; Note = 'Out of support since 12 Jul 2022' } }
        default { return @{ Name = "SQL Server (version $Version)"; Supported = $true; Note = 'Verify against Microsoft Lifecycle' } }
    }
}

# Defender ASR rule GUID -> short name (Microsoft Learn, ASR rules reference)
$script:CERAsrRules = @{
    'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block Office apps from creating child processes'
    '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office apps from creating executable content'
    '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office apps from injecting code into other processes'
    '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
    '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
    '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication apps from creating child processes'
    'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
    '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
    'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from LSASS'
    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
    'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
    'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
    '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files unless they meet prevalence/age/trusted criteria'
    'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
    '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
    'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 'Block Webshell creation for Servers'
    '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode (preview)'
    'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools (preview)'
}
function Get-CERAsrRuleName { param([string]$Id) $n = $script:CERAsrRules[$Id.ToLower()]; if ($n) { return $n } return $Id }

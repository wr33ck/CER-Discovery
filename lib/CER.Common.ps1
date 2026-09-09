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
# Toolkit root = the folder holding lib/, collectors/, build/. Resolved from this file, never from the
# caller's working directory - a collector started from any prompt must land in the same output tree.
$script:CERToolkitRoot = Split-Path $PSScriptRoot -Parent

function Resolve-CERRunTarget {
    <#
      Decides the OutputRoot and RunId for a collector run, and says out loud which it picked.
      A run folder is only useful if every collector for the review writes into the SAME one -
      New-CEREvidencePack merges one folder and nothing else. Two traps used to make that silently fail:
        * OutputRoot defaulted to the caller's working directory, so the same command from a different
          prompt wrote a different tree;
        * an omitted -RunId minted a fresh timestamp, so a collector run on its own forked a new folder.
      Precedence - OutputRoot: -OutputRoot > $env:CER_OUTPUT_ROOT > <toolkit root>\output
                   RunId:      -RunId > newest run folder for this client younger than $ReuseWithinHours
                               (unless -NewRun) > new timestamp
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Client,
        [string]$OutputRoot,
        [string]$RunId,
        [switch]$NewRun,
        [int]$ReuseWithinHours = 12
    )
    if (-not $OutputRoot) { $OutputRoot = $env:CER_OUTPUT_ROOT }
    if (-not $OutputRoot) { $OutputRoot = Join-Path $script:CERToolkitRoot 'output' }
    if ($env:CER_RUN_REUSE_HOURS -and ($env:CER_RUN_REUSE_HOURS -as [int])) { $ReuseWithinHours = [int]$env:CER_RUN_REUSE_HOURS }
    $clientDir = Join-Path $OutputRoot $Client
    $note = ''
    if ($RunId) {
        $note = 'run id supplied'
    } else {
        $existing = @()
        if (Test-Path -LiteralPath $clientDir) {
            $existing = @(Get-ChildItem -LiteralPath $clientDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d{8}-\d{4}$' } | Sort-Object Name -Descending)
        }
        $newest = $existing | Select-Object -First 1
        $ageH = if ($newest) { ((Get-Date) - $newest.CreationTime).TotalHours } else { [double]::MaxValue }
        if ($newest -and -not $NewRun -and $ageH -le $ReuseWithinHours) {
            $RunId = $newest.Name
            $note = ("reusing the newest run for {0} ({1:n1} h old) so this collector joins the same pack - use -NewRun for a fresh run id, or -RunId to target another" -f $Client, $ageH)
        } else {
            $RunId = Get-Date -Format 'yyyyMMdd-HHmm'
            if ($newest -and $NewRun) { $note = ("new run id forced (-NewRun); newest existing run is {0}" -f $newest.Name) }
            elseif ($newest) { $note = ("new run id; newest existing run {0} is {1:n1} h old (older than the {2} h reuse window)" -f $newest.Name, $ageH, $ReuseWithinHours) }
            else { $note = 'first run for this client' }
        }
    }
    return [pscustomobject]@{ OutputRoot = $OutputRoot; RunId = $RunId; RunDir = (Join-Path $clientDir $RunId); Note = $note }
}

function Initialize-CERRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Client,
        [string]$OutputRoot,
        [string]$Collector = 'run',
        [string]$RunId,
        [switch]$NewRun
    )
    $target = Resolve-CERRunTarget -Client $Client -OutputRoot $OutputRoot -RunId $RunId -NewRun:$NewRun
    $OutputRoot = $target.OutputRoot
    $RunId = $target.RunId
    $runDir = $target.RunDir
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
        ToolVersion = '1.1'
    }
    Write-CERLog ("Run initialised  client={0}  run={1}  collector={2}" -f $Client, $RunId, $Collector)
    Write-CERLog ("Writing to: {0}" -f $runDir)
    if ($target.Note) { Write-CERLog ("Run id: {0}" -f $target.Note) }
    Write-CERLog 'Every collector for this review must write into that same folder - the evidence pack merges one folder only.'
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
    <#
      One evidence line for one control.

      -Evidence stays strictly factual and numeric: what was seen, with counts and names. It never argues.
      -Action is the separate, optional half: the recommended next step for THIS finding, written against
      what actually tripped the threshold rather than against the control in general. "KRBTGT last set 412
      days ago" earns "rotate it twice, 24 h apart", not a paragraph about AD hardening.

      The justification ("why it matters") and the baseline ("target state") are NOT written here - they
      are per-control and come from the review workbook via mapping/controls-map.json, so there is one
      source of truth for them and it is the workbook. The reviewer still decides the score.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][ValidateSet('OK', 'Attention', 'Info', 'Unknown')][string]$Flag,
        [Parameter(Mandatory)][string]$Evidence,
        [string]$Action,
        [string]$Source,
        [object]$Data
    )
    if (-not $script:CER) { throw 'Call Initialize-CERRun first.' }
    $e = [ordered]@{
        Control   = $Control
        Flag      = $Flag
        Evidence  = $Evidence
        Action    = $Action
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

# Exchange build -> family, support status, and the latest serviced build.
# Verified 08/09/2026 against Microsoft Learn "Exchange Server build numbers and release dates"
# (https://learn.microsoft.com/exchange/new-features/build-numbers-and-release-dates). KEEP THIS CURRENT -
# a stale table under-reports missing security updates, which is the whole point of the check.
$script:CERExchangeBuildsVerified = '08/09/2026'
$script:CERExchangeLatest = @{
    # family = @{ CU build = @{ Rev = latest revision; Name = release name; Date = release date } }
    'Exchange Server SE' = @{ 2562 = @{ Rev = 46; Name = 'SE RTM Aug26SU'; Date = '11 Aug 2026' } }
    'Exchange 2019'      = @{ 1748 = @{ Rev = 49; Name = 'CU15 Aug26SU'; Date = '11 Aug 2026' }
                              1544 = @{ Rev = 44; Name = 'CU14 Aug26SU'; Date = '11 Aug 2026' } }
    'Exchange 2016'      = @{ 2507 = @{ Rev = 72; Name = 'CU23 Aug26SU'; Date = '11 Aug 2026' } }
}
function Get-CERExchangeSupport {
    <#
      Accepts any Exchange version string - 'Version 15.2 (Build 1748.10)' from Get-ExchangeServer,
      '15.02.1748.037' from ExSetup.exe, or the serialNumber on the AD msExchExchangeServer object.
      ExSetup gives the true build including SUs/HUs; AdminDisplayVersion shows the CU only, so a server
      can look current on AdminDisplayVersion while missing every security update since. Callers should
      pass the ExSetup build where they can get it and set -CuOnly when they cannot.
    #>
    param([string]$Version, [switch]$CuOnly)
    $r = [ordered]@{ Family = $Version; Supported = $true; EndOfSupport = ''; Build = ''; Cu = 0; Rev = 0
        LatestKnown = ''; LatestName = ''; UpToDate = $null; RevisionsBehind = $null; Note = '' }
    $nums = @([regex]::Matches("$Version", '\d+') | ForEach-Object { [int]$_.Value })
    # Supported stays $null for anything we cannot place - never default an unreadable version to "supported",
    # that turns a gap in the evidence into a clean bill of health.
    if ($nums.Count -lt 3) { $r.Supported = $null; $r.Family = 'Exchange (version not recognised)'; $r.Note = ("Version string '{0}' not recognised - read the build from ExSetup.exe on the server." -f $Version); return [pscustomobject]$r }
    $maj = $nums[0]; $min = $nums[1]; $cu = $nums[2]; $rev = if ($nums.Count -ge 4) { $nums[3] } else { 0 }
    $r.Cu = $cu; $r.Rev = $rev; $r.Build = ('{0}.{1}.{2}.{3}' -f $maj, $min, $cu, $rev)
    if ($maj -eq 15 -and $min -eq 2 -and $cu -ge 2562) { $r.Family = 'Exchange Server SE' }
    elseif ($maj -eq 15 -and $min -eq 2) { $r.Family = 'Exchange 2019'; $r.Supported = $false; $r.EndOfSupport = '14 Oct 2025'
        $r.Note = 'Out of support. Security updates from Dec 2025 only under the paid Extended Security Update (ESU) programme; otherwise migrate to Exchange Server SE.' }
    elseif ($maj -eq 15 -and $min -eq 1) { $r.Family = 'Exchange 2016'; $r.Supported = $false; $r.EndOfSupport = '14 Oct 2025'
        $r.Note = 'Out of support. Security updates from Dec 2025 only under the paid ESU programme; otherwise migrate to Exchange Server SE.' }
    elseif ($maj -eq 15 -and $min -eq 0) { $r.Family = 'Exchange 2013'; $r.Supported = $false; $r.EndOfSupport = '11 Apr 2023'; $r.Note = 'Out of support, no ESU. Remove or migrate.' }
    elseif ($maj -eq 14) { $r.Family = 'Exchange 2010'; $r.Supported = $false; $r.EndOfSupport = '13 Oct 2020'; $r.Note = 'Out of support, no ESU. Remove or migrate.' }
    elseif ($maj -eq 8) { $r.Family = 'Exchange 2007'; $r.Supported = $false; $r.EndOfSupport = '11 Apr 2017'; $r.Note = 'Out of support, no ESU. Remove or migrate.' }
    else { $r.Family = "Exchange (build $($r.Build))"; $r.Supported = $null; $r.Note = 'Unknown Exchange family - verify against Microsoft Lifecycle.' }
    $fam = $script:CERExchangeLatest[$r.Family]
    if ($fam) {
        if ($fam.ContainsKey($cu)) {
            $l = $fam[$cu]
            $r.LatestKnown = ('{0}.{1}.{2}.{3}' -f $maj, $min, $cu, $l.Rev); $r.LatestName = ('{0} ({1})' -f $l.Name, $l.Date)
            if ($CuOnly) { $r.Note = (('{0} Build read from the CU only - SU/HU level unknown; run "Get-Command ExSetup.exe | %{{$_.FileVersionInfo}}" on the server.' -f $r.Note)).Trim() }
            else { $r.UpToDate = ($rev -ge $l.Rev); $r.RevisionsBehind = [math]::Max(0, $l.Rev - $rev) }
        } else {
            $newest = ($fam.Keys | Sort-Object -Descending | Select-Object -First 1)
            $r.LatestKnown = ('{0}.{1}.{2}.{3}' -f $maj, $min, $newest, $fam[$newest].Rev); $r.LatestName = ('{0} ({1})' -f $fam[$newest].Name, $fam[$newest].Date)
            $r.UpToDate = $false
            $r.Note = (('{0} Cumulative update {1} is not one of the serviced builds - no security updates are published for it.' -f $r.Note, $cu)).Trim()
        }
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

# ---------------------------------------------------------------- published-app / VDI platform lifecycle
# Three vendor tables behind SRV-14. Same contract as Get-CERExchangeSupport: anything that cannot be
# placed returns Supported = $null, never $true - an unreadable version is a gap in the evidence, not a
# clean bill of health. Refresh each from the cited source when the currency finding matters.

# Parallels RAS. Verified 08/09/2026 against "Lifecycle announcement for Parallels Remote Application
# Server" (kb.parallels.com/en/123002, last reviewed 27/02/2026). LTS = 30 months maintenance + 6 months
# support; non-LTS = 18 + 6. That article states plainly that every version not in its table has already
# reached both EOM and EOS, so an unlisted major below the lowest known one is out of support, not unknown.
$script:CERRasBuildsVerified = '08/09/2026'
$script:CERRasLifecycle = @{
    21 = @{ Name = 'Parallels RAS 21 (LTS)'; Released = '11 Nov 2025'; Eom = '11 May 2028'; Eos = '11 Nov 2028' }
    20 = @{ Name = 'Parallels RAS 20 (LTS)'; Released = '30 Oct 2024'; Eom = '30 Mar 2027'; Eos = '30 Oct 2027' }
    19 = @{ Name = 'Parallels RAS 19 (LTS)'; Released = '28 Jul 2022'; Eom = '28 Feb 2025'; Eos = '28 Jul 2025' }
    18 = @{ Name = 'Parallels RAS 18 (LTS)'; Released = '16 Dec 2020'; Eom = '16 Jun 2023'; Eos = '16 Dec 2023' }
}
function Get-CERRasSupport {
    <# Accepts any RAS version string - '20.4 (29192)', '19.4.28840', 'Parallels RAS 21'. Only the major matters. #>
    param([string]$Version)
    $r = [ordered]@{ Family = $Version; Major = 0; Supported = $null; InMaintenance = $null
        EndOfMaintenance = ''; EndOfSupport = ''; Released = ''; Note = '' }
    $m = [regex]::Match("$Version", '\d+')
    if (-not $m.Success) {
        $r.Family = 'Parallels RAS (version not recognised)'
        $r.Note = ("Version string '{0}' not recognised - read it from Get-RASVersion on the connection broker." -f $Version)
        return [pscustomobject]$r
    }
    $maj = [int]$m.Value
    $r.Major = $maj
    $known = $script:CERRasLifecycle[$maj]
    if ($known) {
        $r.Family = $known.Name; $r.Released = $known.Released
        $r.EndOfMaintenance = $known.Eom; $r.EndOfSupport = $known.Eos
        $now = Get-Date
        try { $r.Supported = ((Get-Date $known.Eos) -ge $now) } catch { $r.Supported = $null }
        try { $r.InMaintenance = ((Get-Date $known.Eom) -ge $now) } catch { $r.InMaintenance = $null }
        if ($r.Supported -eq $false) { $r.Note = ('Past end of support ({0}) - no technical support and no fixes. Upgrade to RAS 21 (LTS).' -f $known.Eos) }
        elseif ($r.InMaintenance -eq $false) { $r.Note = ('In the support-only window: maintenance ended {0}, support ends {1}. No further development iterations, so plan the upgrade inside that window.' -f $known.Eom, $known.Eos) }
    } elseif ($maj -lt 18) {
        $r.Family = ("Parallels RAS {0}" -f $maj); $r.Supported = $false
        $r.EndOfSupport = 'before 16 Dec 2023'
        $r.Note = 'Older than RAS 18 - past end of maintenance and end of support per the Parallels lifecycle article. Upgrade.'
    } else {
        $r.Family = ("Parallels RAS {0}" -f $maj)
        $r.Note = 'Newer than the versions in this table - refresh it from kb.parallels.com/en/123002.'
    }
    return [pscustomobject]$r
}

# Citrix Virtual Apps and Desktops (on-prem). Verified 08/09/2026 against the Citrix product matrix and
# endoflife.date/citrix-vad (updated 06/09/2026). CR = end of active support 6 months after release, end of
# security support at 18 months. LTSR = 5 years active+security, then up to 5 more years of PAID extended
# support - extended support is a purchase, so it is reported as a note and never as "supported".
$script:CERCitrixBuildsVerified = '08/09/2026'
$script:CERCitrixLifecycle = @{
    '2607' = @{ Ltsr = $true;  Released = '18 Aug 2026'; Eos = '17 Aug 2029'; Extended = '' }
    '2603' = @{ Ltsr = $false; Released = '30 Apr 2026'; Eos = '30 Oct 2027'; ActiveEnd = '30 Oct 2026'; Extended = '' }
    '2511' = @{ Ltsr = $false; Released = '29 Dec 2025'; Eos = '29 Jun 2027'; ActiveEnd = '29 Jun 2026'; Extended = '' }
    '2507' = @{ Ltsr = $true;  Released = '19 Aug 2025'; Eos = '18 Aug 2028'; Extended = '18 Aug 2033' }
    '2503' = @{ Ltsr = $false; Released = '29 Apr 2025'; Eos = '29 Oct 2026'; ActiveEnd = '29 Oct 2025'; Extended = '' }
    '2411' = @{ Ltsr = $false; Released = '03 Dec 2024'; Eos = '03 Jun 2026'; ActiveEnd = '03 Jun 2025'; Extended = '' }
    '2407' = @{ Ltsr = $false; Released = '30 Jul 2024'; Eos = '31 Dec 2025'; ActiveEnd = '31 Dec 2024'; Extended = '' }
    '2402' = @{ Ltsr = $true;  Released = '14 Apr 2024'; Eos = '15 Apr 2029'; Extended = '15 Apr 2034' }
    '2203' = @{ Ltsr = $true;  Released = '23 Mar 2022'; Eos = '23 Mar 2027'; Extended = '23 Mar 2032' }
    '1912' = @{ Ltsr = $true;  Released = '18 Dec 2019'; Eos = '18 Dec 2024'; Extended = '18 Dec 2029' }
    '7.15' = @{ Ltsr = $true;  Released = '15 Aug 2017'; Eos = '15 Aug 2022'; Extended = '15 Aug 2027' }
}
# File-based licensing for on-premises Citrix reached end of life on 15 Apr 2026; the License Activation
# Service is the only remaining activation path. Minimum LAS-capable NetScaler builds: 14.1-51.x / 13.1-60.x.
$script:CERCitrixLasCutover = '15 Apr 2026'
function Get-CERCitrixSupport {
    <#
      Accepts a CVAD version as reported by Get-BrokerSite / Get-BrokerController - '2402', '2402.0.0.37',
      '7.2203', '7.15.4000.653' - and places it on the release table.
    #>
    param([string]$Version)
    $r = [ordered]@{ Family = $Version; Release = ''; Ltsr = $null; Supported = $null; ActiveSupport = $null
        EndOfSupport = ''; ExtendedSupport = ''; Released = ''; Note = '' }
    $v = "$Version"
    $rel = ''
    $ym = [regex]::Match($v, '(?<![\d.])(1[89]|2[0-9])(0[1-9]|1[0-2])(?![\d])')     # a YYMM release like 2402
    if ($ym.Success) { $rel = $ym.Value }
    elseif ($v -match '(?<![\d])7[._ ]15(?![\d])') { $rel = '7.15' }
    if (-not $rel) {
        $r.Family = 'Citrix Virtual Apps and Desktops (version not recognised)'
        $r.Note = ("Version string '{0}' not recognised - read it from (Get-BrokerSite).ControllerVersion on a Delivery Controller and check the Citrix product matrix." -f $Version)
        return [pscustomobject]$r
    }
    $r.Release = $rel
    $known = $script:CERCitrixLifecycle[$rel]
    if (-not $known) {
        $r.Family = ("CVAD {0}" -f $rel)
        $r.Note = 'Release not in this table - refresh it from the Citrix product matrix (citrix.com/support/product-lifecycle).'
        return [pscustomobject]$r
    }
    $r.Ltsr = $known.Ltsr
    $r.Released = $known.Released
    $r.EndOfSupport = $known.Eos
    $r.ExtendedSupport = $known.Extended
    if ($rel -eq '7.15') { $r.Family = 'XenApp/XenDesktop 7.15 LTSR' }
    else { $r.Family = ("CVAD {0}{1}" -f $rel, $(if ($known.Ltsr) { ' LTSR' } else { ' CR' })) }
    $now = Get-Date
    try { $r.Supported = ((Get-Date $known.Eos) -ge $now) } catch { $r.Supported = $null }
    if ($known.ContainsKey('ActiveEnd') -and $known.ActiveEnd) {
        try { $r.ActiveSupport = ((Get-Date $known.ActiveEnd) -ge $now) } catch { $r.ActiveSupport = $null }
    } elseif ($known.Ltsr) { $r.ActiveSupport = $r.Supported }
    $notes = @()
    if ($r.Supported -eq $false) {
        if ($known.Extended) { $notes += ('Past end of active and security support ({0}). Only the PAID extended support programme covers it, to {1} - confirm the client actually holds it, otherwise this is unsupported software.' -f $known.Eos, $known.Extended) }
        else { $notes += ('Past end of security support ({0}) with no extended-support option. Upgrade to a current LTSR.' -f $known.Eos) }
    } elseif (-not $known.Ltsr) {
        $notes += ('Current Release, not an LTSR: security support ends {0}, which is 18 months from release. A CR in a managed estate means an upgrade every 18 months - if that is not the intent, move to the nearest LTSR.' -f $known.Eos)
        if ($r.ActiveSupport -eq $false) { $notes += ('Active support already ended {0}, so no new fixes - only security updates until {1}.' -f $known.ActiveEnd, $known.Eos) }
    }
    $r.Note = ($notes -join ' ')
    return [pscustomobject]$r
}

# NetScaler (Citrix ADC) firmware. Verified 08/09/2026 against the NetScaler ADC firmware release cycle
# (support.citrix.com CTX241500) and the Citrix product matrix. From 14.1 the cycle is 7 years.
$script:CERNetScalerBuildsVerified = '08/09/2026'
$script:CERNetScalerLifecycle = @{
    '14.1' = @{ Eom = ''; Eos = '08 Aug 2030'; LasMinBuild = 51 }
    '13.1' = @{ Eom = '15 Sep 2026'; Eos = '15 Sep 2027'; LasMinBuild = 60 }
}
function Get-CERNetScalerSupport {
    <# Accepts 'NS14.1: Build 34.42.nc' or '13.1-49.15' - anything carrying major.minor and a build number. #>
    param([string]$Version)
    $r = [ordered]@{ Family = $Version; Branch = ''; Build = $null; Supported = $null; InMaintenance = $null
        EndOfMaintenance = ''; EndOfSupport = ''; LasCapable = $null; Note = '' }
    $b = [regex]::Match("$Version", '(\d+)\.(\d+)')
    if (-not $b.Success) {
        $r.Family = 'NetScaler (version not recognised)'
        $r.Note = ("Version string '{0}' not recognised - read it from 'show ns version' or NITRO config/nsversion." -f $Version)
        return [pscustomobject]$r
    }
    $branch = ('{0}.{1}' -f $b.Groups[1].Value, $b.Groups[2].Value)
    $r.Branch = $branch
    $r.Family = ('NetScaler ' + $branch)
    # build number is the first number AFTER the branch, e.g. 'NS14.1: Build 34.42' -> 34
    $after = "$Version".Substring($b.Index + $b.Length)
    $bm = [regex]::Match($after, '\d+')
    if ($bm.Success) { $r.Build = [int]$bm.Value }
    $known = $script:CERNetScalerLifecycle[$branch]
    if ($known) {
        $r.EndOfMaintenance = $known.Eom; $r.EndOfSupport = $known.Eos
        $now = Get-Date
        try { $r.Supported = ((Get-Date $known.Eos) -ge $now) } catch { $r.Supported = $null }
        if ($known.Eom) { try { $r.InMaintenance = ((Get-Date $known.Eom) -ge $now) } catch { $r.InMaintenance = $null } } else { $r.InMaintenance = $r.Supported }
        if ($null -ne $r.Build -and $known.LasMinBuild) { $r.LasCapable = ($r.Build -ge $known.LasMinBuild) }
        $notes = @()
        if ($r.Supported -eq $false) { $notes += ('Past end of life ({0}) - no firmware fixes, including for PSIRT advisories. Upgrade to 14.1.' -f $known.Eos) }
        elseif ($r.InMaintenance -eq $false) { $notes += ('Past end of maintenance ({0}); technical support only until end of life {1}. No new builds means unpatched CVEs on an internet-facing appliance.' -f $known.Eom, $known.Eos) }
        if ($r.LasCapable -eq $false) { $notes += ('Build {0} is below the minimum LAS-capable build for this branch ({1}-{2}.x). File-based licensing reached end of life on {3}, so this appliance cannot be re-licensed until it is upgraded.' -f $r.Build, $branch, $known.LasMinBuild, $script:CERCitrixLasCutover) }
        $r.Note = ($notes -join ' ')
    } else {
        $maj = [int]$b.Groups[1].Value; $min = [int]$b.Groups[2].Value
        if ($maj -lt 13 -or ($maj -eq 13 -and $min -lt 1)) {
            $r.Supported = $false
            $r.Note = 'Branch 13.0 and earlier are past end of life - confirm the exact date on the Citrix product matrix, then upgrade to 14.1. An end-of-life ADC on the internet edge is the highest-value target in the estate.'
        } else {
            $r.Note = 'Branch not in this table - refresh it from the NetScaler firmware release cycle article (CTX241500).'
        }
    }
    return [pscustomobject]$r
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

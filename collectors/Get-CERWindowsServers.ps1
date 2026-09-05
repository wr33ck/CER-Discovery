#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: Windows servers over WinRM (run from a domain-joined jump host / DC as a domain admin).
  Pushes the host-state function from agent\Invoke-CERLocalHostCheck.ps1 to each server and aggregates the results.
.EXAMPLE
  # servers discovered by the AD collector in the same run (raw\ad.servers.json)
  .\Get-CERWindowsServers.ps1 -Client C-003 -OutputRoot D:\CER\output -RunId 20260905-0900
  # explicit list
  .\Get-CERWindowsServers.ps1 -Client C-003 -RunId 20260905-0900 -ComputerName SRV01,SRV02 -IncludeWindowsUpdateSearch
  # only re-aggregate JSON already in <run>\hosts (e.g. RMM drops)
  .\Get-CERWindowsServers.ps1 -Client C-003 -RunId 20260905-0900 -ImportOnly
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string[]]$ComputerName,
    [string]$ComputerListFile,
    [switch]$IncludeDomainControllers,
    [int]$MaxServers = 250,
    [int]$ThrottleLimit = 16,
    [pscredential]$Credential,
    [switch]$IncludeWindowsUpdateSearch,
    [switch]$ImportOnly
)
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib/CER.Common.ps1')
. (Join-Path $root 'lib/CER.HostEvidence.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Servers' -RunId $RunId
$C = 'Servers'
$run = Get-CERRun
$hostDir = Join-Path $run.RunDir 'hosts'

if (-not $ImportOnly) {
    # ----- target list
    $targets = @()
    if ($ComputerName) { $targets = @($ComputerName | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ }) }
    elseif ($ComputerListFile -and (Test-Path $ComputerListFile)) { $targets = @(Get-Content $ComputerListFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { $_.Trim() }) }
    else {
        $ad = Get-CERRaw -Collector 'ad' -Name 'servers'
        if ($ad) { $targets = @($ad | ForEach-Object { if ($_.DNSHostName) { $_.DNSHostName } else { $_.Name } }) }
        if ($IncludeDomainControllers) { $dcs = Get-CERRaw -Collector 'ad' -Name 'dcs'; if ($dcs) { $targets += @($dcs | ForEach-Object { $_.Name }) } }
    }
    $targets = @($targets | Where-Object { $_ } | Select-Object -Unique)
    if ($targets.Count -eq 0) { Set-CERCoverage -Collector $C -Section 'Targets' -Status Skipped -Note 'No servers given (-ComputerName / -ComputerListFile) and no raw\ad.servers.json from the AD collector in this run.'; Complete-CERCollector; return }
    if ($targets.Count -gt $MaxServers) { Write-CERLog ("{0} targets, capping at {1} (raise -MaxServers)" -f $targets.Count, $MaxServers) 'WARN'; $targets = $targets[0..($MaxServers - 1)] }
    Set-CERCoverage -Collector $C -Section 'Targets' -Status Collected -Note ("{0} targets" -f $targets.Count)

    # ----- remote scriptblock = HOSTSTATE region of the agent + a call
    $agent = Get-Content -Raw (Join-Path $root 'agent/Invoke-CERLocalHostCheck.ps1')
    if ($agent -notmatch '(?s)#region HOSTSTATE(.*?)#endregion HOSTSTATE') { throw 'HOSTSTATE region not found in agent script' }
    $body = $Matches[1] + "`nGet-CERHostState -IncludeWindowsUpdateSearch:`$" + ([string]$IncludeWindowsUpdateSearch.IsPresent) + "`n"
    $sb = [scriptblock]::Create($body)

    Invoke-CERSection -Collector $C -Section 'RemoteCollection' -Script {
        $icm = @{ ComputerName = $targets; ScriptBlock = $sb; ThrottleLimit = $ThrottleLimit; ErrorAction = 'SilentlyContinue'; ErrorVariable = 'icmErr' }
        if ($Credential) { $icm['Credential'] = $Credential }
        $results = @(Invoke-Command @icm)
        $reached = @{}
        foreach ($r in $results) {
            if ($r -and $r.Meta) {
                $name = $r.Meta.Hostname; $reached[$name.ToLower()] = $true
                $r | Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName | ConvertTo-Json -Depth 9 | Set-Content -LiteralPath (Join-Path $hostDir ("{0}.cer-host.json" -f $name)) -Encoding UTF8
            }
        }
        $unreach = @()
        foreach ($t in $targets) { $short = ($t -split '\.')[0].ToLower(); if (-not $reached[$short]) { $unreach += $t } }
        $errSummary = @($icmErr | ForEach-Object { "{0}: {1}" -f $_.TargetObject, ($_.Exception.Message -split "`n")[0] } | Select-Object -First 15)
        Save-CERRaw -Name 'remote.errors' -Object $errSummary
        Save-CERRaw -Name 'unreachable' -Object $unreach
        Set-CERSectionResult -Status $(if ($unreach.Count -eq 0) { 'Collected' } else { 'Partial' }) -Note ("{0}/{1} hosts returned data; unreachable: {2}" -f $results.Count, $targets.Count, (Join-CERList $unreach 10))
    }
}

# ----- aggregate everything in <run>\hosts
Invoke-CERSection -Collector $C -Section 'Aggregate' -Script {
    $files = @(Get-ChildItem -LiteralPath $hostDir -Filter '*.cer-host.json' -ErrorAction SilentlyContinue)
    $hosts = @(); foreach ($f in $files) { try { $hosts += (Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { Write-CERLog ("bad host file {0}: {1}" -f $f.Name, $_.Exception.Message) 'WARN' } }
    $unreach = @(); $u = Get-CERRaw -Collector 'servers' -Name 'unreachable'; if ($u) { $unreach = @($u) }
    ConvertTo-CERHostEvidence -Hosts $hosts -Unreachable $unreach -SourceLabel 'Servers'
    Set-CERSectionResult -Status $(if ($hosts.Count) { 'Collected' } else { 'Skipped' }) -Note ("{0} host files aggregated" -f $hosts.Count)
}
Complete-CERCollector

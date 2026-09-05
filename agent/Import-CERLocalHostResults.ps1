#Requires -Version 5.1
<#
.SYNOPSIS
  Aggregates JSON produced by Invoke-CERLocalHostCheck.ps1 (dropped by N-central / NinjaOne / a share) into CER evidence.
.EXAMPLE
  .\Import-CERLocalHostResults.ps1 -Client C-003 -OutputRoot D:\CER\output -RunId 20260905-0900 -Path \\FILESERVER\CER$
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [Parameter(Mandatory)][string]$Path,
    [switch]$Recurse
)
$root = Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'lib/CER.Common.ps1')
. (Join-Path $root 'lib/CER.HostEvidence.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Endpoints' -RunId $RunId
$C = 'Endpoints'
$hostDir = Join-Path (Get-CERRun).RunDir 'hosts'
Invoke-CERSection -Collector $C -Section 'Import' -Script {
    $gci = @{ Path = $Path; Filter = '*.cer-host.json'; ErrorAction = 'Stop' }; if ($Recurse) { $gci['Recurse'] = $true }
    $files = @(Get-ChildItem @gci)
    $hosts = @(); $bad = 0
    foreach ($f in $files) {
        try { $obj = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json; if ($obj.Meta) { $hosts += $obj; Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $hostDir $f.Name) -Force } else { $bad++ } } catch { $bad++ }
    }
    $stale = @($hosts | Where-Object { (Get-CERAgeDays $_.Meta.CollectedAt) -gt 14 })
    Set-CERSectionResult -Status $(if ($hosts.Count) { 'Collected' } else { 'Skipped' }) -Note ("{0} host files imported, {1} unreadable, {2} older than 14 days" -f $hosts.Count, $bad, $stale.Count)
    $script:imported = $hosts
}
Invoke-CERSection -Collector $C -Section 'Aggregate' -Script {
    if (-not $script:imported -or $script:imported.Count -eq 0) { Set-CERSectionResult -Status Skipped -Note 'nothing to aggregate'; return }
    ConvertTo-CERHostEvidence -Hosts $script:imported -SourceLabel 'Endpoints'
}
Complete-CERCollector

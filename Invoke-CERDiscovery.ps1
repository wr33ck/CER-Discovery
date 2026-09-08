#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery orchestrator - runs the selected collectors for one client into one run folder, then builds the evidence pack.

.DESCRIPTION
  Scopes:  Entra, Intune, Exchange, DNS, Teams, Azure   (cloud - run from your laptop, PowerShell 7 recommended)
                                                        NB 'Exchange' is Exchange ONLINE; on-prem is 'ExchangeOnPrem'
           AD, ExchangeOnPrem, Servers, Endpoints       (on-prem - run on a domain-joined jump host / DC as domain admin, PS 5.1 ok;
                                                         ExchangeOnPrem needs the Exchange Management Shell or -ExchangeServer)
           vSphere, Veeam, FortiGate                    (optional - need module / API access)
           Cloud = Entra,Intune,Exchange,DNS,Teams,Azure   OnPrem = AD,ExchangeOnPrem,Servers   All = everything you supplied parameters for
  Same -Client and -RunId across machines -> copy the on-prem run folder into the laptop's output\<client>\<runid>\ and rebuild.
  Omit -RunId and a run started within the last 12 h is reused, so a second pass joins the same pack; -NewRun forces a fresh one.

.EXAMPLE
  # cloud pass from the laptop (named admin over GDAP)
  .\Invoke-CERDiscovery.ps1 -Client C-003 -Scope Cloud -TenantId 11111111-2222-3333-4444-555555555555 `
      -UserPrincipalName admin.b.shrestha@blueapache.com -DelegatedOrganization contoso.onmicrosoft.com -AzureTenantId <bA tenant for Lighthouse>
  # on-prem pass on the jump host, same run id
  .\Invoke-CERDiscovery.ps1 -Client C-003 -Scope OnPrem -RunId 20260905-0900 -OutputRoot D:\CER\output -IncludeDomainControllers
  # add RMM host-check results and rebuild
  .\Invoke-CERDiscovery.ps1 -Client C-003 -Scope Endpoints -RunId 20260905-0900 -LocalCheckPath \\FS01\CER$
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string[]]$Scope = @('Cloud'),
    # cloud
    [string]$TenantId, [string]$UserPrincipalName, [string]$DelegatedOrganization, [switch]$UseDeviceCode, [switch]$CheckInboxRules, [string[]]$Domains,
    [string]$AzureTenantId, [string[]]$SubscriptionId, [switch]$SkipCost,
    # on-prem
    [string[]]$ComputerName, [string]$ComputerListFile, [switch]$IncludeDomainControllers, [switch]$IncludeWindowsUpdateSearch, [int]$MaxServers = 250, [string]$LocalCheckPath,
    [string]$ExchangeServer, [pscredential]$ExchangeCredential, [switch]$SkipExchangeIisChecks,
    # optional
    [string]$VCenter, [pscredential]$VCenterCredential, [string]$VbrServer, [string]$FortiGate, [int]$FortiPort = 443, [securestring]$FortiApiToken, [switch]$FortiSkipCertificateCheck,
    [switch]$NewRun, [switch]$NoBuild
)
$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
. (Join-Path $here 'lib/CER.Common.ps1')
# Same resolution the collectors use, so an orchestrated pass and a standalone collector land in one folder.
$target = Resolve-CERRunTarget -Client $Client -OutputRoot $OutputRoot -RunId $RunId -NewRun:$NewRun
$OutputRoot = $target.OutputRoot; $RunId = $target.RunId
$valid = 'Entra', 'Intune', 'Exchange', 'ExchangeOnPrem', 'DNS', 'Teams', 'Azure', 'AD', 'Servers', 'Endpoints', 'vSphere', 'Veeam', 'FortiGate', 'Cloud', 'OnPrem', 'All'
$Scope = @($Scope | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ })
foreach ($s in $Scope) { if ($valid -notcontains $s) { throw "Unknown scope '$s'. Valid: $($valid -join ', ')" } }
$want = New-Object System.Collections.Generic.List[string]
foreach ($s in $Scope) {
    switch ($s) {
        'Cloud' { 'Entra', 'Intune', 'Exchange', 'DNS', 'Teams', 'Azure' | ForEach-Object { $want.Add($_) } }
        'OnPrem' { 'AD', 'ExchangeOnPrem', 'Servers' | ForEach-Object { $want.Add($_) } }
        'All' { 'Entra', 'Intune', 'Exchange', 'DNS', 'Teams', 'Azure', 'AD', 'ExchangeOnPrem', 'Servers', 'Endpoints', 'vSphere', 'Veeam', 'FortiGate' | ForEach-Object { $want.Add($_) } }
        default { $want.Add($s) }
    }
}
$order = 'Entra', 'Intune', 'Exchange', 'DNS', 'Teams', 'Azure', 'AD', 'ExchangeOnPrem', 'Servers', 'Endpoints', 'vSphere', 'Veeam', 'FortiGate'
$run = @($order | Where-Object { $want -contains $_ })
Write-Host ("CER-Discovery  client={0}  run={1}  collectors={2}" -f $Client, $RunId, ($run -join ',')) -ForegroundColor Cyan
Write-Host ("Output: {0}" -f (Join-Path (Join-Path $OutputRoot $Client) $RunId)) -ForegroundColor Cyan
if ($target.Note) { Write-Host ("Run id: {0}" -f $target.Note) -ForegroundColor Cyan }
$common = @{ Client = $Client; OutputRoot = $OutputRoot; RunId = $RunId }
$results = @()
function Invoke-Step { param([string]$Name, [string]$Script, [hashtable]$Params, [scriptblock]$Precheck)
    $skip = $null; if ($Precheck) { $skip = & $Precheck }
    if ($skip) { Write-Host ("[{0}] skipped: {1}" -f $Name, $skip) -ForegroundColor Yellow; $script:results += [pscustomobject]@{ Collector = $Name; Result = "skipped: $skip" }; return }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $clean = @{}; foreach ($k in $Params.Keys) { $v = $Params[$k]; if ($null -eq $v) { continue }; if ($v -is [System.Management.Automation.SwitchParameter] -and -not $v.IsPresent) { continue }; if (($v -is [string]) -and $v -eq '') { continue }; $clean[$k] = $v }
    try { & (Join-Path $here $Script) @common @clean; $script:results += [pscustomobject]@{ Collector = $Name; Result = ("ok {0:n0}s" -f $sw.Elapsed.TotalSeconds) } }
    catch { Write-Host ("[{0}] FAILED: {1}" -f $Name, $_.Exception.Message) -ForegroundColor Red; $script:results += [pscustomobject]@{ Collector = $Name; Result = "failed: $($_.Exception.Message)" } }
}
foreach ($c in $run) {
    switch ($c) {
        'Entra' { Invoke-Step 'Entra' 'collectors/Get-CEREntra.ps1' @{ TenantId = $TenantId; UseDeviceCode = $UseDeviceCode } { if (-not $TenantId) { 'needs -TenantId' } } }
        'Intune' { Invoke-Step 'Intune' 'collectors/Get-CERIntune.ps1' @{ TenantId = $TenantId; UseDeviceCode = $UseDeviceCode } { if (-not $TenantId) { 'needs -TenantId' } } }
        'Exchange' { Invoke-Step 'Exchange' 'collectors/Get-CERExchangeOnline.ps1' @{ UserPrincipalName = $UserPrincipalName; DelegatedOrganization = $DelegatedOrganization; CheckInboxRules = $CheckInboxRules } { if (-not $UserPrincipalName) { 'needs -UserPrincipalName (and -DelegatedOrganization for GDAP)' } } }
        'DNS' { Invoke-Step 'DNS' 'collectors/Get-CERDns.ps1' @{ Domains = $Domains } }
        'Teams' { Invoke-Step 'Teams' 'collectors/Get-CERTeams.ps1' @{ TenantId = $TenantId; UseDeviceCode = $UseDeviceCode } { if (-not $TenantId) { 'needs -TenantId' } elseif (-not (Get-Module -ListAvailable MicrosoftTeams)) { 'MicrosoftTeams module not installed (optional)' } } }
        'Azure' { Invoke-Step 'Azure' 'collectors/Get-CERAzure.ps1' @{ AzureTenantId = $AzureTenantId; SubscriptionId = $SubscriptionId; UseDeviceCode = $UseDeviceCode; SkipCost = $SkipCost } { if (-not (Get-Module -ListAvailable Az.ResourceGraph)) { 'Az.ResourceGraph not installed' } } }
        'AD' { Invoke-Step 'AD' 'collectors/Get-CERActiveDirectory.ps1' @{} { if (-not (Get-Module -ListAvailable ActiveDirectory)) { 'ActiveDirectory module (RSAT) not installed - run on a DC/jump host' } } }
        'ExchangeOnPrem' { Invoke-Step 'ExchangeOnPrem' 'collectors/Get-CERExchangeHybrid.ps1' @{ Server = $ExchangeServer; Credential = $ExchangeCredential; SkipIisChecks = $SkipExchangeIisChecks } { if (-not (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) -and -not $ExchangeServer) { 'no Exchange Management Shell on this host and no -ExchangeServer given (skip if the client has no on-prem Exchange)' } } }
        'Servers' { Invoke-Step 'Servers' 'collectors/Get-CERWindowsServers.ps1' @{ ComputerName = $ComputerName; ComputerListFile = $ComputerListFile; IncludeDomainControllers = $IncludeDomainControllers; IncludeWindowsUpdateSearch = $IncludeWindowsUpdateSearch; MaxServers = $MaxServers } }
        'Endpoints' { Invoke-Step 'Endpoints' 'agent/Import-CERLocalHostResults.ps1' @{ Path = $LocalCheckPath; Recurse = $true } { if (-not $LocalCheckPath) { 'needs -LocalCheckPath (folder/share with *.cer-host.json from the RMM job)' } } }
        'vSphere' { Invoke-Step 'vSphere' 'collectors/Get-CERvSphere.ps1' @{ VCenter = $VCenter; Credential = $VCenterCredential } { if (-not $VCenter) { 'needs -VCenter (optional)' } } }
        'Veeam' { Invoke-Step 'Veeam' 'collectors/Get-CERVeeam.ps1' @{ VbrServer = $(if ($VbrServer) { $VbrServer } else { 'localhost' }) } { if (-not (Get-Module -ListAvailable Veeam.Backup.PowerShell)) { 'Veeam.Backup.PowerShell not installed - run on the VBR server (optional)' } } }
        'FortiGate' { Invoke-Step 'FortiGate' 'collectors/Get-CERFortiGate.ps1' @{ FortiGate = $FortiGate; Port = $FortiPort; ApiToken = $FortiApiToken; SkipCertificateCheck = $FortiSkipCertificateCheck } { if (-not $FortiGate -or -not $FortiApiToken) { 'needs -FortiGate and -FortiApiToken (optional)' } } }
    }
}
$results | Format-Table -AutoSize | Out-String | Write-Host
if (-not $NoBuild) { & (Join-Path $here 'build/New-CEREvidencePack.ps1') -RunDir (Join-Path (Join-Path $OutputRoot $Client) $RunId) }

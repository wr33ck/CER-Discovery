#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (optional): VMware vSphere via PowerCLI. Feeds SRV-06, SRV-07, SRV-02 (guest OS), BDR-06 (snapshots).
.EXAMPLE
  .\Get-CERvSphere.ps1 -Client C-003 -RunId 20260905-0900 -VCenter vcsa.client.local -Credential (Get-Credential)
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Client, [string]$OutputRoot, [string]$RunId, [Parameter(Mandatory)][string]$VCenter, [pscredential]$Credential, [int]$SnapshotAgeHours = 72)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'vSphere' -RunId $RunId
$C = 'vSphere'
if (-not (Test-CERModule -Name VMware.VimAutomation.Core -Collector $C)) { Complete-CERCollector; return }
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
try { Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -ParticipateInCEIP $false -Scope Session -Confirm:$false | Out-Null } catch { }
Invoke-CERSection -Collector $C -Section 'Connect' -Script { $p = @{ Server = $VCenter; ErrorAction = 'Stop' }; if ($Credential) { $p['Credential'] = $Credential }; Connect-VIServer @p | Out-Null }
Invoke-CERSection -Collector $C -Section 'Platform' -Script {
    $vc = $global:DefaultVIServer
    $hosts = @(Get-VMHost | Select-Object Name, Version, Build, ConnectionState, PowerState, Manufacturer, Model, NumCpu, MemoryTotalGB, MemoryUsageGB, CpuUsageMhz, CpuTotalMhz, @{ n = 'BootTime'; e = { $_.ExtensionData.Runtime.BootTime } }, @{ n = 'NtpServers'; e = { (Get-VMHostNtpServer -VMHost $_) -join ',' } }, @{ n = 'SshRunning'; e = { (Get-VMHostService -VMHost $_ | Where-Object { $_.Key -eq 'TSM-SSH' }).Running } }, @{ n = 'LockdownMode'; e = { $_.ExtensionData.Config.LockdownMode } })
    $clusters = @(Get-Cluster | Select-Object Name, HAEnabled, HAFailoverLevel, HAAdmissionControlEnabled, DrsEnabled, DrsAutomationLevel, EVCMode, @{ n = 'Hosts'; e = { @($_ | Get-VMHost).Count } })
    $ds = @(Get-Datastore | Select-Object Name, Type, CapacityGB, FreeSpaceGB, @{ n = 'FreePct'; e = { [math]::Round(100 * $_.FreeSpaceGB / [math]::Max(1, $_.CapacityGB), 1) } })
    $vms = @(Get-VM | Select-Object Name, PowerState, NumCpu, MemoryGB, HardwareVersion, @{ n = 'GuestOS'; e = { $_.Guest.OSFullName } }, @{ n = 'ToolsStatus'; e = { $_.ExtensionData.Guest.ToolsVersionStatus2 } }, @{ n = 'ToolsRunning'; e = { $_.ExtensionData.Guest.ToolsRunningStatus } }, @{ n = 'Folder'; e = { $_.Folder.Name } }, UsedSpaceGB, ProvisionedSpaceGB)
    $snaps = @(Get-VM | Get-Snapshot | Select-Object VM, Name, Created, SizeGB, @{ n = 'AgeHours'; e = { [math]::Round(((Get-Date) - $_.Created).TotalHours) } })
    $lic = @(); try { $lm = Get-View LicenseManager; $lic = @($lm.Licenses | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Total = $_.Total; Used = $_.Used; Expires = ($_.Properties | Where-Object { $_.Key -eq 'expirationDate' } | Select-Object -ExpandProperty Value) } }) } catch { }
    Save-CERRaw -Name 'platform' -Object ([ordered]@{ vCenter = @{ Name = $vc.Name; Version = $vc.Version; Build = $vc.Build }; Hosts = $hosts; Clusters = $clusters; Datastores = $ds; VMs = $vms; Snapshots = $snaps; Licenses = $lic })
    $ver = "$($vc.Version)"; $major = if ($ver -match '^(\d+)') { [int]$Matches[1] } else { 0 }
    $verNote = if ($major -le 6) { 'vSphere 6.x - out of support' } elseif ($major -eq 7) { 'vSphere 7 - end of general support 2 Oct 2025 (technical guidance to 2 Apr 2027)' } elseif ($major -eq 8) { 'vSphere 8 - supported' } else { "vSphere $ver" }
    $oldSnaps = @($snaps | Where-Object { $_.AgeHours -gt $SnapshotAgeHours })
    $lowDs = @($ds | Where-Object { $_.FreePct -lt 20 })
    $noHa = @($clusters | Where-Object { -not $_.HAEnabled })
    $oldTools = @($vms | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.ToolsStatus -in 'guestToolsNeedUpgrade', 'guestToolsBlacklisted', 'guestToolsTooOld', 'guestToolsNotInstalled' })
    $flag = if ($major -le 7 -or $oldSnaps.Count -or $lowDs.Count -or $noHa.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'SRV-06' -Flag $flag -Action 'Check vCenter and ESXi against Broadcom''s support matrix - vSphere 7 reached end of general support on 2 Oct 2025. Turn SSH off on the hosts unless it is actively in use and enable lockdown mode; ESXi is a favoured ransomware target precisely because encrypting a datastore takes every VM on it at once.' -Evidence ("vCenter {0} build {1} ({2}); hosts {3} (versions {4}; SSH running on {5}; lockdown on {6}); clusters {7} ({8} without HA, {9} without DRS; failover level {10}); datastores {11} - below 20% free: {12} ({13}); VMs {14} ({15} powered on); snapshots older than {16} h: {17} ({18}); VM tools needing upgrade/missing: {19}; licences: {20}." -f $ver, $vc.Build, $verNote, $hosts.Count, (Join-CERList ($hosts | Group-Object Version | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 3), @($hosts | Where-Object SshRunning).Count, @($hosts | Where-Object { $_.LockdownMode -ne 'lockdownDisabled' }).Count, $clusters.Count, $noHa.Count, @($clusters | Where-Object { -not $_.DrsEnabled }).Count, (Join-CERList ($clusters | ForEach-Object { "{0}:{1}" -f $_.Name, $_.HAFailoverLevel }) 3), $ds.Count, $lowDs.Count, (Join-CERList ($lowDs | ForEach-Object { "{0} {1}%" -f $_.Name, $_.FreePct }) 5), $vms.Count, @($vms | Where-Object { $_.PowerState -eq 'PoweredOn' }).Count, $SnapshotAgeHours, $oldSnaps.Count, (Join-CERList ($oldSnaps | ForEach-Object { "{0} ({1}h, {2:n0}GB)" -f $_.VM, $_.AgeHours, $_.SizeGB }) 5), $oldTools.Count, (Join-CERList ($lic | ForEach-Object { "{0} {1}/{2} exp {3}" -f $_.Name, $_.Used, $_.Total, $(if ($_.Expires) { $_.Expires } else { 'never' }) }) 4))
    $cpuPct = if ($hosts.Count) { 100 * (($hosts | Measure-Object CpuUsageMhz -Sum).Sum / [math]::Max(1, ($hosts | Measure-Object CpuTotalMhz -Sum).Sum)) } else { 0 }
    $memPct = if ($hosts.Count) { 100 * (($hosts | Measure-Object MemoryUsageGB -Sum).Sum / [math]::Max(1, ($hosts | Measure-Object MemoryTotalGB -Sum).Sum)) } else { 0 }
    $over = @($vms | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.NumCpu -ge 8 })
    Add-CEREvidence -Control 'SRV-07' -Flag $(if ($cpuPct -gt 75 -or $memPct -gt 85 -or $lowDs.Count) { 'Attention' } else { 'OK' }) -Action 'Address the clusters or datastores running low on headroom. A datastore filling up stops every VM on it simultaneously, and it is one of the most predictable outages there is - confirm each has a monitor in Orion with enough runway to act on, and build the 12-month growth trend into the capacity conversation.' -Evidence ("Cluster utilisation now: CPU {0:n0}%, memory {1:n0}% across {2} hosts; total datastore free {3:n0}/{4:n0} GB; VMs with >= 8 vCPU (right-sizing candidates): {5}; hosts with N+1 headroom must be checked against HA failover level {6}. 90-day trends come from Orion/vCenter performance charts." -f $cpuPct, $memPct, $hosts.Count, ($ds | Measure-Object FreeSpaceGB -Sum).Sum, ($ds | Measure-Object CapacityGB -Sum).Sum, $over.Count, (Join-CERList ($clusters | ForEach-Object { $_.HAFailoverLevel }) 3))
    $guest = @($vms | Where-Object { $_.PowerState -eq 'PoweredOn' } | Group-Object GuestOS | Sort-Object Count -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $legacy = @($vms | Where-Object { $_.PowerState -eq 'PoweredOn' -and $_.GuestOS -match '2003|2008|2012|Windows 7|Windows XP|CentOS 6|CentOS 7|Ubuntu 1[4-8]|Red Hat.*6|Debian [7-9]' })
    Add-CEREvidence -Control 'SRV-02' -Flag $(if ($legacy.Count) { 'Attention' } else { 'Info' }) -Action 'Cross-check these guest OS versions against the AD and host-check inventories - VMs that appear here but not there are unmanaged, which usually means unpatched and unmonitored as well. Legacy guests need either a migration plan or a documented exception with compensating controls.' -Evidence ("Guest OS mix (powered-on VMs per VMware Tools): {0}. Legacy guests: {1} ({2})." -f (Join-CERList $guest 6), $legacy.Count, (Join-CERList ($legacy | ForEach-Object { "{0} [{1}]" -f $_.Name, $_.GuestOS }) 6))
    if ($oldSnaps.Count) { Add-CEREvidence -Control 'BDR-06' -Flag Attention -Action 'Delete the long-lived snapshots. A snapshot is not a backup: it grows until it fills the datastore, degrades performance while it exists, and consolidating a large one is itself a risky operation that gets riskier the longer it is left. Anything older than a few days needs a reason and a removal date.' -Evidence ("Long-lived snapshots are not backups and will hurt performance/consolidation: {0}" -f (Join-CERList ($oldSnaps | ForEach-Object { "{0} '{1}' {2}d" -f $_.VM, $_.Name, [math]::Round($_.AgeHours / 24) }) 6)) }
}
try { Disconnect-VIServer -Server * -Confirm:$false -ErrorAction SilentlyContinue } catch { }
Complete-CERCollector

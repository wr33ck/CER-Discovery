#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (optional): Veeam Backup & Replication v11/v12 via Veeam.Backup.PowerShell (run on the VBR server
  or a machine with the Veeam console installed). Feeds BDR-01/02/04/05/06/09, SRV-09 (app-aware), M365-09 (if VB365 present).
.EXAMPLE
  .\Get-CERVeeam.ps1 -Client C-003 -RunId 20260905-0900 -VbrServer vbr01.client.local
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Client, [string]$OutputRoot, [string]$RunId, [string]$VbrServer = 'localhost', [pscredential]$Credential, [int]$Days = 30)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Veeam' -RunId $RunId
$C = 'Veeam'
if (-not (Test-CERModule -Name Veeam.Backup.PowerShell -Collector $C)) { Complete-CERCollector; return }
Import-Module Veeam.Backup.PowerShell -ErrorAction Stop -WarningAction SilentlyContinue
$now = Get-Date
Invoke-CERSection -Collector $C -Section 'Connect' -Script { try { Disconnect-VBRServer -ErrorAction SilentlyContinue } catch { }; $p = @{ Server = $VbrServer; ErrorAction = 'Stop' }; if ($Credential) { $p['Credential'] = $Credential }; Connect-VBRServer @p }
Invoke-CERSection -Collector $C -Section 'ServerLicence' -Script {
    $info = $null; try { $info = Get-VBRBackupServerInfo } catch { }
    $lic = $null; try { $lic = Get-VBRInstalledLicense } catch { }
    $ver = if ($info) { "$($info.Build)" } else { try { (Get-Item "${env:ProgramFiles}\Veeam\Backup and Replication\Backup\Veeam.Backup.Manager.exe").VersionInfo.ProductVersion } catch { 'unknown' } }
    Save-CERRaw -Name 'server' -Object ([ordered]@{ Server = $VbrServer; Build = $ver; Licence = $(if ($lic) { $lic | Select-Object Edition, Status, Type, ExpirationDate, SupportExpirationDate, LicensedTo } else { $null }) })
    $major = if ("$ver" -match '^(\d+)\.') { [int]$Matches[1] } else { 0 }
    $exp = if ($lic -and $lic.ExpirationDate) { Get-CERAgeDays $lic.ExpirationDate } else { $null }
    Add-CEREvidence -Control 'BDR-09' -Flag $(if ($major -lt 12 -or ($exp -ne $null -and $exp -gt -60)) { 'Attention' } else { 'OK' }) -Evidence ("Veeam B&R {0} on {1} ({2}); licence: {3} {4}, status {5}, expires {6}, support expires {7}." -f $ver, $VbrServer, $(if ($major -ge 12) { 'v12 supported' } elseif ($major -eq 11) { 'v11 - end of support, upgrade' } else { 'check support status' }), $(if ($lic) { $lic.Edition } else { 'n/a' }), $(if ($lic) { $lic.Type } else { '' }), $(if ($lic) { $lic.Status } else { '' }), $(if ($lic) { $lic.ExpirationDate } else { '' }), $(if ($lic) { $lic.SupportExpirationDate } else { '' }))
}
Invoke-CERSection -Collector $C -Section 'JobsSessions' -Script {
    $jobs = @(Get-VBRJob -WarningAction SilentlyContinue | Select-Object Name, JobType, IsScheduleEnabled, @{ n = 'LastResult'; e = { "$($_.GetLastResult())" } }, @{ n = 'LastState'; e = { "$($_.GetLastState())" } }, @{ n = 'Objects'; e = { @($_.GetObjectsInJob()).Count } }, @{ n = 'AppAware'; e = { try { $_.VssOptions.Enabled } catch { $null } } }, @{ n = 'Retention'; e = { try { "$($_.BackupStorageOptions.RetainCycles) pts / $($_.BackupStorageOptions.RetainDaysToKeep) days" } catch { '' } } }, @{ n = 'Repo'; e = { try { $_.GetTargetRepository().Name } catch { '' } } })
    $agentJobs = @(); try { $agentJobs = @(Get-VBRComputerBackupJob | Select-Object Name, Type, JobEnabled) } catch { }
    $since = $now.AddDays(-$Days)
    $sess = @(Get-VBRBackupSession -WarningAction SilentlyContinue | Where-Object { $_.CreationTime -ge $since } | Select-Object JobName, JobType, Result, State, CreationTime, EndTime)
    $byResult = @($sess | Group-Object Result | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $failedJobs = @($sess | Where-Object { "$($_.Result)" -eq 'Failed' } | Group-Object JobName | Sort-Object Count -Descending)
    $warnJobs = @($sess | Where-Object { "$($_.Result)" -eq 'Warning' } | Group-Object JobName | Sort-Object Count -Descending)
    $success = @($sess | Where-Object { "$($_.Result)" -eq 'Success' }).Count
    $sure = @(); try { $sure = @(Get-VBRSureBackupJob | Select-Object Name, IsEnabled, @{ n = 'LastResult'; e = { "$($_.LastResult)" } }, @{ n = 'LastRun'; e = { $_.LastRun } }) } catch { }
    $copy = @($jobs | Where-Object { "$($_.JobType)" -match 'BackupCopy|BackupSync' })
    Save-CERRaw -Name 'jobs' -Object ([ordered]@{ Jobs = $jobs; AgentJobs = $agentJobs; Sessions = $sess; SureBackup = $sure })
    $rate = if ($sess.Count) { 100 * $success / $sess.Count } else { 0 }
    Add-CEREvidence -Control 'BDR-02' -Flag $(if ($rate -ge 98 -and $failedJobs.Count -eq 0) { 'OK' } else { 'Attention' }) -Evidence ("Veeam sessions last {0} days: {1} ({2}); success rate {3:n1}%. Jobs with failures: {4} ({5}); jobs with warnings: {6} ({7}). Jobs: {8} ({9} disabled schedule); backup copy jobs: {10}." -f $Days, $sess.Count, (Join-CERList $byResult 4), $rate, $failedJobs.Count, (Join-CERList ($failedJobs | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) 5), $warnJobs.Count, (Join-CERList ($warnJobs | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) 5), $jobs.Count, @($jobs | Where-Object { -not $_.IsScheduleEnabled }).Count, $copy.Count)
    Add-CEREvidence -Control 'BDR-05' -Flag $(if (@($sure | Where-Object IsEnabled).Count) { 'OK' } else { 'Attention' }) -Evidence ("SureBackup jobs: {0} ({1} enabled): {2}. Manual restore-test evidence still needs a ticket/LOG entry." -f $sure.Count, @($sure | Where-Object IsEnabled).Count, (Join-CERList ($sure | ForEach-Object { "{0} last {1} on {2:yyyy-MM-dd}" -f $_.Name, $_.LastResult, $_.LastRun }) 3))
    $noVss = @($jobs | Where-Object { "$($_.JobType)" -eq 'Backup' -and $_.AppAware -eq $false })
    Add-CEREvidence -Control 'BDR-06' -Flag $(if ($noVss.Count) { 'Attention' } else { 'OK' }) -Evidence ("Application-aware processing disabled on {0} backup jobs: {1}. Retention per job: {2}." -f $noVss.Count, (Join-CERList ($noVss | ForEach-Object { $_.Name }) 5), (Join-CERList ($jobs | Where-Object { "$($_.JobType)" -eq 'Backup' } | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Retention }) 5))
    Add-CEREvidence -Control 'BDR-03' -Flag Info -Evidence ("Configured retention by job: {0}. Compare with the agreed RPO/RTO/retention table." -f (Join-CERList ($jobs | ForEach-Object { "{0} [{1}] {2}" -f $_.Name, $_.JobType, $_.Retention }) 8))
}
Invoke-CERSection -Collector $C -Section 'Repositories' -Script {
    $repos = @(Get-VBRBackupRepository -WarningAction SilentlyContinue | ForEach-Object { $r = $_; $imm = @($r.PSObject.Properties | Where-Object { $_.Name -match 'mmutab' } | ForEach-Object { "{0}={1}" -f $_.Name, $_.Value }); $free = $null; $total = $null; try { $c = $r.GetContainer(); $free = [math]::Round($c.CachedFreeSpace.InGigabytes); $total = [math]::Round($c.CachedTotalSpace.InGigabytes) } catch { }; [pscustomobject]@{ Name = $r.Name; Type = "$($r.Type)"; Host = $(try { $r.GetHost().Name } catch { '' }); FreeGB = $free; TotalGB = $total; FreePct = $(if ($total) { [math]::Round(100 * $free / $total, 1) } else { $null }); Immutability = ($imm -join '; '); Path = $r.FriendlyPath } })
    $obj = @(); try { $obj = @(Get-VBRObjectStorageRepository | ForEach-Object { $r = $_; $imm = @($r.PSObject.Properties | Where-Object { $_.Name -match 'mmutab' } | ForEach-Object { "{0}={1}" -f $_.Name, $_.Value }); [pscustomobject]@{ Name = $r.Name; Type = "$($r.Type)"; Immutability = ($imm -join '; ') } }) } catch { }
    $sobr = @(); try { $sobr = @(Get-VBRBackupRepository -ScaleOut | Select-Object Name, @{ n = 'Extents'; e = { @($_.Extent).Count } }, @{ n = 'Capacity'; e = { $_.CapacityExtent.Repository.Name } }, @{ n = 'Archive'; e = { $_.ArchiveExtent.Repository.Name } }) } catch { }
    $roles = @(); try { $roles = @(Get-VBRUserRoleAssignment | Select-Object Name, Role) } catch { }
    $mfaCmd = Get-Command -Module Veeam.Backup.PowerShell -Name '*MFA*' -ErrorAction SilentlyContinue | Select-Object -First 1
    $mfa = if ($mfaCmd) { try { (& $mfaCmd.Name | Out-String).Trim() } catch { 'n/a' } } else { 'no MFA cmdlet in this version - check Users and Roles in console' }
    $domainJoined = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    Save-CERRaw -Name 'repositories' -Object ([ordered]@{ Repositories = $repos; ObjectStorage = $obj; ScaleOut = $sobr; Roles = $roles; MFA = $mfa; BackupServerDomainJoined = $domainJoined })
    $immRepos = @($repos + $obj | Where-Object { $_.Immutability -match 'True|Enabled|=\d+' -and $_.Immutability -notmatch 'False' })
    $hardened = @($repos | Where-Object { $_.Type -match 'LinuxHardened' })
    $low = @($repos | Where-Object { $_.FreePct -ne $null -and $_.FreePct -lt 15 })
    Add-CEREvidence -Control 'BDR-04' -Flag $(if ($immRepos.Count -eq 0 -or $domainJoined) { 'Attention' } else { 'OK' }) -Evidence ("Repositories: {0} ({1}) + object storage {2}; hardened Linux repos: {3}; repositories reporting immutability: {4} ({5}); scale-out repos: {6}. Backup server domain-joined: {7} (should be isolated). Console role assignments: {8}; MFA: {9}." -f $repos.Count, (Join-CERList ($repos | ForEach-Object { "{0} [{1}] {2}% free" -f $_.Name, $_.Type, $_.FreePct }) 5), $obj.Count, $hardened.Count, $immRepos.Count, (Join-CERList ($immRepos | ForEach-Object { "{0}: {1}" -f $_.Name, $_.Immutability }) 3), $sobr.Count, $domainJoined, (Join-CERList ($roles | ForEach-Object { "{0}={1}" -f $_.Name, $_.Role }) 5), ($mfa -replace '\s+', ' '))
    Add-CEREvidence -Control 'BDR-09' -Flag $(if ($low.Count) { 'Attention' } else { 'OK' }) -Evidence ("Repository capacity: {0}. Below 15% free: {1}." -f (Join-CERList ($repos | Where-Object { $_.TotalGB } | ForEach-Object { "{0} {1}/{2} GB free" -f $_.Name, $_.FreeGB, $_.TotalGB }) 5), (Join-CERList ($low | ForEach-Object { $_.Name }) 5))
}
Invoke-CERSection -Collector $C -Section 'Coverage' -Script {
    $rp = @(Get-VBRRestorePoint -WarningAction SilentlyContinue | Where-Object { $_.CreationTime -ge $now.AddDays(-7) } | Select-Object -ExpandProperty VmName -Unique)
    $ents = @(); try { $ents = @(Find-VBRViEntity -VMsAndTemplates -WarningAction SilentlyContinue | Where-Object { -not $_.IsTemplate -and $_.PowerState -eq 'PoweredOn' } | Select-Object -ExpandProperty Name -Unique) } catch { }
    $hv = @(); try { $hv = @(Find-VBRHvEntity -VMsAndTemplates -WarningAction SilentlyContinue | Where-Object { $_.PowerState -eq 'PoweredOn' } | Select-Object -ExpandProperty Name -Unique) } catch { }
    $all = @($ents + $hv | Select-Object -Unique)
    $unprot = @($all | Where-Object { $rp -notcontains $_ })
    Save-CERRaw -Name 'coverage' -Object ([ordered]@{ RestorePointVMs7d = $rp; InventoryVMs = $all; Unprotected = $unprot })
    if ($all.Count) { Add-CEREvidence -Control 'BDR-01' -Flag $(if ($unprot.Count) { 'Attention' } else { 'OK' }) -Evidence ("Veeam coverage: {0} powered-on VMs in registered hypervisors; {1} have a restore point in the last 7 days; without: {2} ({3}). Physical/agent-protected servers and SaaS are not in this comparison." -f $all.Count, @($all | Where-Object { $rp -contains $_ }).Count, $unprot.Count, (Join-CERList $unprot 10)) }
    else { Add-CEREvidence -Control 'BDR-01' -Flag Info -Evidence ("Veeam: {0} VMs with restore points in the last 7 days; no hypervisor inventory registered in VBR to compare against (agent-only environment?)." -f $rp.Count) }
}
try { Disconnect-VBRServer -ErrorAction SilentlyContinue } catch { }
Complete-CERCollector

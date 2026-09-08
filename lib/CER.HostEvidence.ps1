#Requires -Version 5.1
<#
  Turns a set of host-state objects (from Invoke-CERLocalHostCheck / the Servers collector) into fleet-level evidence.
  Dot-source after CER.Common.ps1. PS 5.1 compatible.
#>
function ConvertTo-CERHostEvidence {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Hosts, [string[]]$Unreachable = @(), [string]$SourceLabel = 'HostCheck')

    $All = @($Hosts | Where-Object { $_ -and $_.System })
    if ($All.Count -eq 0) { Add-CEREvidence -Control 'END-01' -Flag Unknown -Action 'Deploy agent\Invoke-CERLocalHostCheck.ps1 through N-central or NinjaOne to every workstation and server, then import the resulting *.cer-host.json with -Scope Endpoints -LocalCheckPath. Without host evidence roughly a third of the review is unevidenced - endpoint hardening, encryption, local admin, patching and agent coverage all depend on it, and none of them can be scored from the cloud side alone.' -Evidence ("No host results to analyse ({0} unreachable)." -f $Unreachable.Count); return }
    $W = @($All | Where-Object { $_.System.ProductType -eq 1 })
    $S = @($All | Where-Object { $_.System.ProductType -ne 1 })
    $DC = @($All | Where-Object { $_.System.ProductType -eq 2 })
    function _names { param($set, [int]$max = 8) Join-CERList ($set | ForEach-Object { $_.Meta.Hostname }) $max }
    function _pct { param($part, $whole) ConvertTo-CERPct $part $whole }
    function _has { param($o, $path) $cur = $o; foreach ($p in $path.Split('.')) { if ($null -eq $cur) { return $null }; $cur = Get-CERProp $cur $p }; return $cur }
    function _hasEdr { param($h) $edr = @(_has $h 'Agents.EDR'); if ($edr.Count -gt 0) { return $true }; $d = _has $h 'Defender'; if ($d -and $d.Present -and $d.RealTimeProtectionEnabled -and ("$($d.AMRunningMode)" -match 'Normal|EDR Block')) { return $true }; return $false }

    # ---------- summary CSV
    $rows = foreach ($h in $All) {
        [pscustomobject]@{
            Host = $h.Meta.Hostname; Type = @{1 = 'Workstation'; 2 = 'DC'; 3 = 'Server' }[[int]$h.System.ProductType]; OS = $h.System.Support.Family; Build = $h.System.Build; Supported = $h.System.Support.Supported; Virtual = $h.System.IsVirtual; Laptop = $h.System.IsLaptop
            UptimeDays = $h.System.UptimeDays; LastPatchDays = (_has $h 'Patching.LastHotfixAgeDays'); PendingReboot = (_has $h 'Patching.PendingReboot.Any'); PendingUpdates = (_has $h 'Patching.PendingUpdates')
            EDR = (@(_has $h 'Agents.EDR') -join '/'); DefenderMode = (_has $h 'Defender.AMRunningMode'); Tamper = (_has $h 'Defender.IsTamperProtected'); MDR = (@(_has $h 'Agents.MDR') -join '/'); RMM = (@(_has $h 'Agents.RMM') -join '/'); AppControlAgent = (@(_has $h 'Agents.AppControl') -join '/')
            BitLockerOS = (_has $h 'Encryption.OSVolumeProtected'); LAPS = (_has $h 'Hardening.LAPS.Configured'); NonStdLocalAdmins = (_has $h 'LocalAccounts.NonStandardAdminCount'); BuiltinAdminEnabled = (_has $h 'LocalAccounts.BuiltinAdminEnabled')
            SMB1 = (_has $h 'Hardening.SMB1Enabled'); TLS10 = (_has $h 'Hardening.TLS10Server'); RDPNLA = (_has $h 'Hardening.RDPNLARequired'); FirewallAllOn = (_has $h 'Hardening.FirewallAllProfilesOn'); PSv2 = (_has $h 'Hardening.PowerShellV2'); PSLogging = (_has $h 'Hardening.PSLogging.ScriptBlock')
            AppLocker = $(if ((_has $h 'AppControl.AppLocker.Present')) { ((_has $h 'AppControl.AppLocker.Collections').PSObject.Properties | ForEach-Object { "$($_.Name):$($_.Value.Enforcement)" }) -join ';' } else { '' }); WDAC = (_has $h 'AppControl.WDAC.Meaning'); MacroPolicy = (_has $h 'Office.MacroPolicyPresent'); ASRBlock = (_has $h 'Defender.ASRBlockCount')
            RemoteTools = (@(@(_has $h 'Agents.RemoteTools') + @(_has $h 'Software.RemoteTools')) | Select-Object -Unique) -join '/'; BroadWriteShares = (@(_has $h 'Storage.BroadWriteShares') -join '/'); SQL = (@(_has $h 'Roles.SqlInstances') | ForEach-Object { "$($_.Instance)=$($_.Product)" }) -join '/'
            TimeSource = (_has $h 'Network.TimeSource'); Errors = @(_has $h 'Errors').Count
        }
    }
    try { $rows | Export-Csv -LiteralPath (Join-Path (Get-CERRun).RunDir 'hosts.csv') -NoTypeInformation -Encoding UTF8 } catch { }
    Save-CERRaw -Name 'hosts.summary' -Object $rows

    # ---------- inventory
    Add-CEREvidence -Control 'END-01' -Flag Info -Action 'Reconcile this count against Intune, Entra devices, the RMM and the EDR console. The number that matters is not how many devices each tool reports but how many appear in one and not the others - a device missing from any of them is unmanaged in that dimension, and nobody notices until it is the one that gets hit.' -Evidence ("Host check results: {0} hosts ({1} workstations, {2} servers incl. {3} DCs); {4} unreachable ({5}). Compare with Intune/Entra/RMM/EDR device counts." -f $All.Count, $W.Count, $S.Count, $DC.Count, $Unreachable.Count, (Join-CERList $Unreachable 6))
    if ($Unreachable.Count -gt 0) { Add-CEREvidence -Control 'COV-02' -Flag Attention -Action ("Establish why each of the {0} unreachable host(s) could not be contacted - powered off, decommissioned but still in AD, firewalled, or WinRM disabled - and resolve each. Anything genuinely retired should be removed from AD and the CMDB; anything live needs WinRM so it can be patched and audited. An unreachable host is unevidenced, not compliant, so it must not be scored as covered." -f $Unreachable.Count) -Evidence ("{0} in-scope hosts unreachable over WinRM (off, firewalled, or WinRM disabled): {1}. Unreachable is itself a monitoring/management finding." -f $Unreachable.Count, (Join-CERList $Unreachable 10)) }

    # ---------- hardware age (physical hosts, BIOS release date as proxy)
    $phys = @($All | Where-Object { -not $_.System.IsVirtual })
    if ($phys.Count) {
        $old = @($phys | Where-Object { (_has $_ 'System.HardwareAgeYearsApprox') -gt 5 }); $veryOld = @($phys | Where-Object { (_has $_ 'System.HardwareAgeYearsApprox') -gt 7 })
        $models = @($phys | Group-Object { "{0} {1}" -f $_.System.Manufacturer, $_.System.Model } | Sort-Object Count -Descending | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count })
        $ctl = if (@($phys | Where-Object { $_.System.ProductType -eq 1 }).Count -gt 0) { 'END-16' } else { 'LIC-01' }
        $actHw = if ($veryOld.Count) { "Run the serials in hosts.csv through the Dell/HP warranty lookups and build a refresh list, starting with the $($veryOld.Count) unit(s) over seven years old - $(_names $veryOld 6). Past warranty, a failure is a rebuild rather than a repair, and the device is probably also the one blocking Windows 11. Get the numbers to the SDM and CAM in time for the client's budget cycle." }
        elseif ($old.Count) { "Warranty-check the $($old.Count) unit(s) over five years old and start a rolling refresh plan, so replacement is a budgeted line rather than an emergency purchase after a failure." } else { '' }
        Add-CEREvidence -Control 'END-16' -Flag $(if ($veryOld.Count) { 'Attention' } elseif ($old.Count) { 'Info' } else { 'OK' }) -Action $actHw -Evidence ("Physical hosts: {0} ({1}); BIOS release date older than 5 years (age proxy) on {2}, older than 7 years on {3} ({4}). Serials are in hosts.csv for warranty lookups." -f $phys.Count, (Join-CERList $models 5), $old.Count, $veryOld.Count, (_names $veryOld 6))
        Add-CEREvidence -Control 'LIC-01' -Flag Info -Action 'Load the manufacturer, model and serial from hosts.csv into the hardware lifecycle register, add warranty end dates from the vendor lookup, and give the register an owner and a review date. BIOS date is only a proxy for age - the warranty record is the number the client will be asked to fund against.' -Evidence ("Hardware register inputs from host check: {0} physical hosts with manufacturer/model/serial captured; {1} appear older than 5 years by BIOS date." -f $phys.Count, $old.Count)
    }

    # ---------- OS currency
    foreach ($grp in @(@{ Set = $W; Ctl = 'END-02'; Label = 'workstations' }, @{ Set = $S; Ctl = 'SRV-02'; Label = 'servers' })) {
        $set = $grp.Set; if ($set.Count -eq 0) { continue }
        $fam = $set | Group-Object { $_.System.Support.Family } | Sort-Object Count -Descending
        $unsup = @($set | Where-Object { -not $_.System.Support.Supported }); $soon = @($set | Where-Object { $_.System.Support.Supported -and $_.System.Support.EndOfSupport })
        $flag = if ($unsup.Count) { 'Attention' } elseif ($soon.Count) { 'Attention' } else { 'OK' }
        $actOs = if ($unsup.Count) { "Upgrade or replace the $($unsup.Count) out-of-support $($grp.Label) - $(_names $unsup 6). These receive no security updates, so every vulnerability published from their end-of-support date onward stays open permanently. Where an application pins the version, log it as an accepted risk with a compensating control and a review date rather than leaving it silent." }
        elseif ($soon.Count) { "Schedule the $($soon.Count) $($grp.Label) whose support ends within 12 months - $(_names $soon 6). Getting this into the client's roadmap while it is still a plan is a very different conversation from raising it once the date has passed." } else { '' }
        Add-CEREvidence -Control $grp.Ctl -Flag $flag -Action $actOs -Evidence ("{0} {1} checked: {2}. Unsupported OS: {3} ({4}). Support ending within 12 months: {5} ({6})." -f $set.Count, $grp.Label, (Join-CERList ($fam | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })), $unsup.Count, (_names $unsup), $soon.Count, (_names $soon))
    }

    # ---------- patching
    foreach ($grp in @(@{ Set = $W; Ctl = 'END-03'; Label = 'workstations' }, @{ Set = $S; Ctl = 'SRV-03'; Label = 'servers' })) {
        $set = $grp.Set; if ($set.Count -eq 0) { continue }
        $ages = @($set | ForEach-Object { _has $_ 'Patching.LastHotfixAgeDays' } | Where-Object { $null -ne $_ })
        $within30 = @($ages | Where-Object { $_ -le 30 }).Count; $over60 = @($set | Where-Object { (_has $_ 'Patching.LastHotfixAgeDays') -gt 60 })
        $reboot = @($set | Where-Object { (_has $_ 'Patching.PendingReboot.Any') })
        $pend = @($set | Where-Object { $null -ne (_has $_ 'Patching.PendingUpdates') })
        $pendTxt = if ($pend.Count) { (" Live WU scan on {0} hosts: {1} with pending updates, max {2} outstanding." -f $pend.Count, @($pend | Where-Object { (_has $_ 'Patching.PendingUpdates') -gt 0 }).Count, (($pend | ForEach-Object { _has $_ 'Patching.PendingUpdates' } | Measure-Object -Maximum).Maximum)) } else { '' }
        $managed = $set | Group-Object { _has $_ 'Patching.ManagedBy' } | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
        $flag = if ($ages.Count -and ($within30 / $ages.Count) -ge 0.95 -and $over60.Count -eq 0) { 'OK' } else { 'Attention' }
        $fp = @()
        if ($over60.Count) { $fp += "Investigate the $($over60.Count) $($grp.Label) more than 60 days behind - $(_names $over60 6). Check each is actually in an N-central patch policy and reporting, rather than assumed covered; the usual causes are a missing agent, a device that never stays on long enough, or a policy scoped to the wrong group" }
        if ($ages.Count -and ($within30 / $ages.Count) -lt 0.95) { $fp += "Bring patch compliance up to the Essential Eight ML1 baseline of monthly patching - currently $(_pct $within30 $ages.Count) of $($grp.Label) are within 30 days against a 95% target" }
        if ($reboot.Count) { $fp += "$($reboot.Count) host(s) are holding a pending reboot, so their patches are installed but not in effect - agree a reboot window with the client rather than waiting for them to happen" }
        $actPatch = if ($fp.Count) { (($fp -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control $grp.Ctl -Flag $flag -Action $actPatch -Evidence ("{0}: last cumulative update within 30 days on {1}/{2} ({3}); {4} hosts > 60 days ({5}); pending reboot on {6}; long uptime > 60 days on {7}. Update source: {8}.{9}" -f $grp.Label, $within30, $ages.Count, (_pct $within30 $ages.Count), $over60.Count, (_names $over60), $reboot.Count, @($set | Where-Object { $_.System.UptimeDays -gt 60 }).Count, (Join-CERList $managed 4), $pendTxt)
    }

    # ---------- EDR / MDR / RMM coverage
    foreach ($grp in @(@{ Set = $W; Ctl = 'END-06'; Label = 'workstations' }, @{ Set = $S; Ctl = 'SRV-04'; Label = 'servers' })) {
        $set = $grp.Set; if ($set.Count -eq 0) { continue }
        $withEdr = @($set | Where-Object { _hasEdr $_ }); $noEdr = @($set | Where-Object { -not (_hasEdr $_) })
        $products = $set | ForEach-Object { @(_has $_ 'Agents.EDR') } | Group-Object | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
        $def = @($set | Where-Object { (_has $_ 'Defender.Present') -and ("$(_has $_ 'Defender.AMRunningMode')" -match 'Normal|EDR Block') })
        $tamperOff = @($def | Where-Object { -not (_has $_ 'Defender.IsTamperProtected') }); $sigOld = @($def | Where-Object { (_has $_ 'Defender.SignatureAgeDays') -gt 7 })
        $flag = if ($noEdr.Count -eq 0 -and $tamperOff.Count -eq 0) { 'OK' } else { 'Attention' }
        $fe = @()
        if ($noEdr.Count) { $fe += "Deploy EDR to the $($noEdr.Count) $($grp.Label) with no endpoint protection detected - $(_names $noEdr 6). An unprotected host is where an intrusion starts and the one place nobody will see it happen" }
        if ($tamperOff.Count) { $fe += "Turn tamper protection on for the $($tamperOff.Count) Defender host(s) without it - $(_names $tamperOff 5). Without it, the first thing ransomware does is disable the AV, and it succeeds" }
        if ($sigOld.Count) { $fe += "$($sigOld.Count) host(s) have signatures more than 7 days old, which usually means the host is not checking in rather than that updates are broken - confirm each is still live and reporting to the console" }
        $actEdr = if ($fe.Count) { (($fe -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control $grp.Ctl -Flag $flag -Action $actEdr -Evidence ("{0}: EDR/AV present on {1}/{2} ({3}) - {4}; NO endpoint protection detected on {5} ({6}). Defender active on {7}: tamper protection off on {8} ({9}), signatures > 7 days on {10}." -f $grp.Label, $withEdr.Count, $set.Count, (_pct $withEdr.Count $set.Count), (Join-CERList $products 5), $noEdr.Count, (_names $noEdr), $def.Count, $tamperOff.Count, (_names $tamperOff 5), $sigOld.Count)
    }
    $mdr = @($All | Where-Object { @(_has $_ 'Agents.MDR').Count -gt 0 }); $noMdr = @($All | Where-Object { @(_has $_ 'Agents.MDR').Count -eq 0 })
    $mdrProducts = $All | ForEach-Object { @(_has $_ 'Agents.MDR') } | Group-Object | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
    $actMdr = if ($mdr.Count -eq 0) { 'No MDR agent was found on any host. EDR alerts nobody is watching outside business hours are not detection - confirm whether MDR is in the contract (BAMS scope) and, if it is, why nothing is deployed. If it is not, this is the single highest-value gap to put to the SDM.' }
    elseif ($noMdr.Count) { "Deploy the MDR agent to the $($noMdr.Count) host(s) missing it - $(_names $noMdr 8). Partial MDR coverage gives the client the impression of monitoring while leaving named machines outside it; reconcile deployed agents against licensed seats while you are there." } else { '' }
    Add-CEREvidence -Control 'SEC-02' -Flag $(if ($noMdr.Count -eq 0) { 'OK' } elseif ($mdr.Count -eq 0) { 'Attention' } else { 'Attention' }) -Action $actMdr -Evidence ("MDR agents (Huntress / Rapid7 Insight / other) present on {0}/{1} hosts ({2}); missing on {3}: {4}." -f $mdr.Count, $All.Count, (Join-CERList $mdrProducts 4), $noMdr.Count, (_names $noMdr 10))
    $rmm = @($All | Where-Object { @(_has $_ 'Agents.RMM').Count -gt 0 }); $noRmm = @($All | Where-Object { @(_has $_ 'Agents.RMM').Count -eq 0 })
    $rmmProducts = $All | ForEach-Object { @(_has $_ 'Agents.RMM') } | Group-Object | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }
    Add-CEREvidence -Control 'COV-04' -Flag $(if ($noRmm.Count -eq 0) { 'OK' } else { 'Attention' }) -Action $(if ($noRmm.Count) { "Install the RMM agent on the $($noRmm.Count) host(s) without one - $(_names $noRmm 8). A host outside the RMM cannot be in a patch policy, cannot be monitored and does not appear in the reporting the client is shown, so it is invisible in exactly the way that matters." } else { '' }) -Evidence ("RMM/management agents present on {0}/{1} hosts ({2}); none detected on {3}: {4} - these cannot be in a patch policy." -f $rmm.Count, $All.Count, (Join-CERList $rmmProducts 5), $noRmm.Count, (_names $noRmm 10))
    $noEdrAll = @($All | Where-Object { -not (_hasEdr $_) }); $appCtl = @($All | Where-Object { @(_has $_ 'Agents.AppControl').Count -gt 0 })
    Add-CEREvidence -Control 'COV-05' -Flag $(if ($noEdrAll.Count -or $noMdr.Count -or $noRmm.Count) { 'Attention' } else { 'OK' }) -Action $(if ($noEdrAll.Count -or $noMdr.Count -or $noRmm.Count) { "Reconcile deployed agents against the seat counts in the contract - EDR missing on $($noEdrAll.Count), MDR on $($noMdr.Count), RMM on $($noRmm.Count). Two different findings hide here: devices the client is paying to protect and is not, and devices being protected beyond what is billed. Both need raising, the first as risk and the second to the CAM." } else { '' }) -Evidence ("Agent coverage across {0} hosts: EDR/AV {1}, MDR {2}, RMM {3}, application-control agent {4}. Hosts missing EDR: {5}; missing MDR: {6}; missing RMM: {7}. Compare with licensed seat counts." -f $All.Count, (_pct ($All.Count - $noEdrAll.Count) $All.Count), (_pct $mdr.Count $All.Count), (_pct $rmm.Count $All.Count), (_pct $appCtl.Count $All.Count), $noEdrAll.Count, $noMdr.Count, $noRmm.Count)

    # ---------- encryption (workstations)
    if ($W.Count) {
        $bl = @($W | Where-Object { (_has $_ 'Encryption.OSVolumeProtected') -eq $true }); $unenc = @($W | Where-Object { (_has $_ 'Encryption.OSVolumeProtected') -ne $true })
        $laptopsUnenc = @($unenc | Where-Object { $_.System.IsLaptop })
        $noRecovery = @($bl | Where-Object { (_has $_ 'Encryption.OSVolumeHasRecoveryPassword') -eq $false })
        $fb = @()
        if ($laptopsUnenc.Count) { $fb += "Encrypt the $($laptopsUnenc.Count) unencrypted laptop(s) first - $(_names $laptopsUnenc 6). A lost unencrypted laptop is a notifiable data breach under the Privacy Act; an encrypted one is a hardware loss" }
        if ($unenc.Count -gt $laptopsUnenc.Count) { $fb += "Then the remaining $($unenc.Count - $laptopsUnenc.Count) unencrypted desktop(s) - enforce by Intune compliance policy or GPO rather than per device" }
        if ($noRecovery.Count) { $fb += "$($noRecovery.Count) encrypted host(s) have no recovery-password protector, so there is no key to escrow and no way back in if TPM state changes after a firmware update - add one and confirm it escrows to Entra or AD" }
        $actBl = if ($fb.Count) { (($fb -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control 'END-07' -Flag $(if ($W.Count -and ($bl.Count / $W.Count) -ge 0.98) { 'OK' } else { 'Attention' }) -Action $actBl -Evidence ("BitLocker OS volume protected on {0}/{1} workstations ({2}); unprotected: {3} incl. {4} laptops ({5}); protected without a recovery-password protector: {6}. Key escrow is checked from Entra/AD, not locally." -f $bl.Count, $W.Count, (_pct $bl.Count $W.Count), $unenc.Count, $laptopsUnenc.Count, (_names $laptopsUnenc 6), $noRecovery.Count)
    }

    # ---------- local admins / LAPS
    foreach ($grp in @(@{ Set = $W; Ctl = 'END-08'; Label = 'workstations' }, @{ Set = $S; Ctl = 'SRV-05'; Label = 'servers' })) {
        $set = $grp.Set; if ($set.Count -eq 0) { continue }
        $withExtra = @($set | Where-Object { (_has $_ 'LocalAccounts.NonStandardAdminCount') -gt 0 })
        $topMembers = $withExtra | ForEach-Object { @(_has $_ 'LocalAccounts.NonStandardAdmins') } | Group-Object | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object { "{0} (x{1})" -f $_.Name, $_.Count }
        $laps = @($set | Where-Object { (_has $_ 'Hardening.LAPS.Configured') }); $bAdmin = @($set | Where-Object { (_has $_ 'LocalAccounts.BuiltinAdminEnabled') -eq $true })
        $oldPw = @($set | Where-Object { (_has $_ 'LocalAccounts.BuiltinAdminPasswordAgeDays') -gt 180 })
        $flag = if ($withExtra.Count -eq 0 -and ($laps.Count / [math]::Max(1, $set.Count)) -ge 0.95) { 'OK' } else { 'Attention' }
        $fl = @()
        if ($withExtra.Count) { $fl += "Remove the non-standard local administrators from $($withExtra.Count) $($grp.Label) - most common: $(Join-CERList $topMembers 4). Standard users holding local admin is what turns a phishing click into a compromised device; where elevation is genuinely needed, use an endpoint privilege management flow or a documented temporary grant rather than a permanent group membership" }
        if (($laps.Count / [math]::Max(1, $set.Count)) -lt 0.95) { $fl += "Extend LAPS to the remaining $($set.Count - $laps.Count) $($grp.Label) (configured on $(_pct $laps.Count $set.Count) today)" }
        if ($bAdmin.Count) { $fl += "The built-in Administrator account is enabled on $($bAdmin.Count) host(s)$(if ($oldPw.Count) { ", and $($oldPw.Count) of those have a password older than 180 days" }) - disable it where nothing depends on it, and put the rest under LAPS so the password is unique per machine and rotates" }
        $actLa = if ($fl.Count) { (($fl -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control $grp.Ctl -Flag $flag -Action $actLa -Evidence ("{0}: non-standard members in local Administrators on {1}/{2} hosts ({3}) - most common: {4}; LAPS policy configured on {5} ({6}); built-in Administrator enabled on {7}, with password age > 180 days on {8}." -f $grp.Label, $withExtra.Count, $set.Count, (_names $withExtra 6), (Join-CERList $topMembers 6), $laps.Count, (_pct $laps.Count $set.Count), $bAdmin.Count, $oldPw.Count)
    }

    # ---------- application control
    foreach ($grp in @(@{ Set = $W; Ctl = 'END-09'; Label = 'workstations' }, @{ Set = $S; Ctl = 'SRV-04'; Label = 'servers' })) {
        $set = $grp.Set; if ($set.Count -eq 0) { continue }
        $alEnf = @($set | Where-Object { $c = _has $_ 'AppControl.AppLocker.Collections'; $c -and @($c.PSObject.Properties | Where-Object { $_.Value.Enforcement -eq 'Enabled' }).Count -gt 0 })
        $alAudit = @($set | Where-Object { $c = _has $_ 'AppControl.AppLocker.Collections'; $c -and @($c.PSObject.Properties | Where-Object { $_.Value.Enforcement -eq 'AuditOnly' }).Count -gt 0 -and $alEnf -notcontains $_ })
        $wdEnf = @($set | Where-Object { (_has $_ 'AppControl.WDAC.UsermodeCodeIntegrityPolicyEnforcementStatus') -eq 2 }); $wdAudit = @($set | Where-Object { (_has $_ 'AppControl.WDAC.UsermodeCodeIntegrityPolicyEnforcementStatus') -eq 1 })
        $third = @($set | Where-Object { @(_has $_ 'Agents.AppControl').Count -gt 0 })
        $covered = @($set | Where-Object { ($alEnf -contains $_) -or ($wdEnf -contains $_) -or ($third -contains $_) })
        $flag = if ($set.Count -and ($covered.Count / $set.Count) -ge 0.95) { 'OK' } else { 'Attention' }
        $actAc = if ($covered.Count -eq 0 -and ($alAudit.Count + $wdAudit.Count) -eq 0) { "No application control is enforced or auditing on any of the $($set.Count) $($grp.Label). Application control is Essential Eight's most effective single mitigation and the hardest to retrofit, so start in audit mode (AppLocker or WDAC) to build the picture of what actually runs before enforcing anything. If Airlock is in the contract, check why it is not deployed." }
        elseif (($alAudit.Count + $wdAudit.Count) -gt 0 -and $covered.Count -lt $set.Count) { "Move the $($alAudit.Count + $wdAudit.Count) host(s) sitting in audit-only mode to enforcement. Audit mode collects evidence and blocks nothing - it counts as progress only if there is a date on moving past it; agree one with the client." }
        elseif ($covered.Count -lt $set.Count) { "Extend application control to the remaining $($set.Count - $covered.Count) $($grp.Label) - enforced on $(_pct $covered.Count $set.Count) today. Cover the user-writable paths (profile and temp), which is where the E8 requirement actually bites." } else { '' }
        Add-CEREvidence -Control $grp.Ctl -Flag $flag -Action $actAc -Evidence ("{0} application control: enforced on {1}/{2} ({3}) [AppLocker enforce {4}, WDAC enforce {5}, Airlock/ThreatLocker agent {6}]; audit-only: AppLocker {7}, WDAC {8}; none: {9}." -f $grp.Label, $covered.Count, $set.Count, (_pct $covered.Count $set.Count), $alEnf.Count, $wdEnf.Count, $third.Count, $alAudit.Count, $wdAudit.Count, ($set.Count - $covered.Count - @($set | Where-Object { ($alAudit -contains $_) -or ($wdAudit -contains $_) } | Where-Object { $covered -notcontains $_ }).Count))
    }

    # ---------- Office macros (workstations + RDS hosts)
    $macroSet = @($W + @($S | Where-Object { (_has $_ 'Roles.IsRdsHost') }))
    if ($macroSet.Count) {
        function _macroOk { param($h, $app, $field, $minVal)
            $mp = _has $h 'Office.MachinePolicy'; $v = $null
            if ($mp) { $a = Get-CERProp $mp $app; if ($a) { $v = Get-CERProp $a $field } }
            if ($null -eq $v) { foreach ($u in @(_has $h 'Office.UserPolicies')) { $a = Get-CERProp $u.Policy $app; if ($a) { $x = Get-CERProp $a $field; if ($null -ne $x) { $v = $x; break } } } }
            if ($null -eq $v) { return $false }; return ([int]$v -ge $minVal)
        }
        $withPolicy = @($macroSet | Where-Object { (_has $_ 'Office.MacroPolicyPresent') })
        $blockInternet = @($macroSet | Where-Object { (_macroOk $_ 'word' 'BlockContentExecutionFromInternet' 1) -and (_macroOk $_ 'excel' 'BlockContentExecutionFromInternet' 1) })
        $disabled = @($macroSet | Where-Object { (_macroOk $_ 'word' 'VBAWarnings' 3) -and (_macroOk $_ 'excel' 'VBAWarnings' 3) -and (_macroOk $_ 'powerpoint' 'VBAWarnings' 3) })
        $scan = @($macroSet | Where-Object { $m = _has $_ 'Office.MachinePolicy'; ($m -and (Get-CERProp $m '_MacroRuntimeScanScope') -eq 2) })
        $win32 = @($macroSet | Where-Object { @(_has $_ 'Defender.ASR') | Where-Object { $_.Id -eq '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' -and $_.Action -eq 1 } })
        $officeHosts = @($macroSet | Where-Object { (_has $_ 'Office.Installed') })
        $flag = if ($officeHosts.Count -and ($blockInternet.Count / $officeHosts.Count) -ge 0.95 -and ($disabled.Count / $officeHosts.Count) -ge 0.95) { 'OK' } else { 'Attention' }
        $fm = @()
        if ($officeHosts.Count -and ($blockInternet.Count / $officeHosts.Count) -lt 0.95) { $fm += "Set 'Block macros from running in Office files from the Internet' for Word, Excel and PowerPoint by GPO or Intune ADMX - currently on $(_pct $blockInternet.Count $officeHosts.Count) of Office hosts. This is Essential Eight ML1 and the single most effective macro control; it blocks the delivery path rather than trying to judge the macro" }
        if ($officeHosts.Count -and ($disabled.Count / $officeHosts.Count) -lt 0.95) { $fm += "Set VBAWarnings to 'disable all except digitally signed' (value 3) across Word, Excel and PowerPoint - currently $(_pct $disabled.Count $officeHosts.Count). Identify the users with a genuine macro need first and scope an exception group for them" }
        if ($scan.Count -lt $officeHosts.Count) { $fm += "Enable the AMSI macro runtime scan for all documents (MacroRuntimeScanScope = 2) on the remaining $($officeHosts.Count - $scan.Count) host(s)" }
        if ($win32.Count -lt $officeHosts.Count) { $fm += "Put the ASR rule 'Block Win32 API calls from Office macros' into block mode for E8 ML2 - block on $($win32.Count) of $($officeHosts.Count) today" }
        $actMac = if ($fm.Count) { (($fm -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control 'END-10' -Flag $flag -Action $actMac -Evidence ("Office installed on {0}/{1} hosts. Macro policy present on {2}; macros from the internet blocked (Word+Excel) on {3} ({4}); macros disabled/signed-only (VBAWarnings>=3, Word/Excel/PowerPoint) on {5} ({6}); AMSI macro runtime scan = all on {7}; ASR 'Block Win32 API calls from Office macros' in block mode on {8} (E8 ML2)." -f $officeHosts.Count, $macroSet.Count, $withPolicy.Count, $blockInternet.Count, (_pct $blockInternet.Count $officeHosts.Count), $disabled.Count, (_pct $disabled.Count $officeHosts.Count), $scan.Count, $win32.Count)
    }

    # ---------- user application hardening (workstations + RDS)
    if ($macroSet.Count) {
        $keyRules = @('d4f940ab-401b-4efc-aadc-ad5f3c50688a', '3b576869-a4ec-4529-8536-b80a7769e899', '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'd1e49aac-8f56-4280-b9ba-993a6d77406c', '5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550')
        $ruleSummary = foreach ($r in $keyRules) { $b = @($macroSet | Where-Object { @(_has $_ 'Defender.ASR') | Where-Object { $_.Id -eq $r -and $_.Action -eq 1 } }).Count; $a = @($macroSet | Where-Object { @(_has $_ 'Defender.ASR') | Where-Object { $_.Id -eq $r -and $_.Action -eq 2 } }).Count; "{0}: block {1}/audit {2}" -f (Get-CERAsrRuleName $r), $b, $a }
        $allBlock = @($macroSet | Where-Object { $h = $_; $ok = $true; foreach ($r in $keyRules[0..3]) { if (-not (@(_has $h 'Defender.ASR') | Where-Object { $_.Id -eq $r -and $_.Action -eq 1 })) { $ok = $false } }; $ok })
        $ie = @($macroSet | Where-Object { (_has $_ 'Hardening.IE11Feature') -eq 'Enabled' }); $ps2 = @($macroSet | Where-Object { (_has $_ 'Hardening.PowerShellV2') -eq 'Enabled' })
        $psLog = @($macroSet | Where-Object { (_has $_ 'Hardening.PSLogging.ScriptBlock') }); $cmd = @($macroSet | Where-Object { (_has $_ 'Hardening.CmdLineAuditing') }); $llmnr = @($macroSet | Where-Object { (_has $_ 'Hardening.LLMNRDisabled') })
        $java = @($macroSet | Where-Object { @(_has $_ 'Browsers.JavaRuntimes').Count -gt 0 })
        $ext = @($macroSet | Where-Object { @(_has $_ 'Browsers.Edge.ForceInstalledExtensions').Count -gt 0 -or @(_has $_ 'Browsers.Chrome.ForceInstalledExtensions').Count -gt 0 })
        $edgePol = @($macroSet | Where-Object { (_has $_ 'Browsers.Edge.PolicyCount') -gt 0 }); $chromePol = @($macroSet | Where-Object { (_has $_ 'Browsers.Chrome.Installed') -and (_has $_ 'Browsers.Chrome.PolicyCount') -gt 0 }); $chrome = @($macroSet | Where-Object { (_has $_ 'Browsers.Chrome.Installed') })
        $flag = if (($allBlock.Count / $macroSet.Count) -ge 0.95 -and $ie.Count -eq 0 -and $ps2.Count -eq 0 -and ($psLog.Count / $macroSet.Count) -ge 0.95) { 'OK' } else { 'Attention' }
        $fu = @()
        if (($allBlock.Count / $macroSet.Count) -lt 0.95) { $fu += "Put the core Office and PDF ASR rules into block mode across the fleet - all four are in block mode on only $(_pct $allBlock.Count $macroSet.Count) of hosts. Deploy in audit for a fortnight, review what would have been blocked, then flip to block" }
        if ($ps2.Count) { $fu += "Remove the PowerShell 2.0 engine feature from $($ps2.Count) host(s) - it bypasses script-block logging and AMSI entirely, which is exactly why attackers invoke it" }
        if ($ie.Count) { $fu += "Remove the Internet Explorer 11 feature from $($ie.Count) host(s); it is out of support and still reachable as a rendering engine" }
        if ($java.Count) { $fu += "Review the Java runtime found on $($java.Count) host(s) - remove it where no line-of-business application needs it, and where one does, record which and keep it patched" }
        if (($psLog.Count / $macroSet.Count) -lt 0.95) { $fu += "Enable PowerShell script-block logging fleet-wide ($(_pct $psLog.Count $macroSet.Count) today) - without it there is no record of what a script did during an incident" }
        $actUah = if ($fu.Count) { (($fu -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control 'END-11' -Flag $flag -Action $actUah -Evidence ("Of {0} user-facing hosts: core Office/PDF ASR rules all in block mode on {1} ({2}); IE11 feature enabled on {3}; PowerShell 2.0 enabled on {4}; script-block logging on {5} ({6}); command-line process auditing on {7}; LLMNR disabled on {8}; Java runtime present on {9}; Edge policies present on {10}, Chrome installed on {11} with policies on {12}; browser extensions force-installed (ad/script blocking?) on {13}. ASR detail: {14}." -f $macroSet.Count, $allBlock.Count, (_pct $allBlock.Count $macroSet.Count), $ie.Count, $ps2.Count, $psLog.Count, (_pct $psLog.Count $macroSet.Count), $cmd.Count, $llmnr.Count, $java.Count, $edgePol.Count, $chrome.Count, $chromePol.Count, $ext.Count, ($ruleSummary -join '; '))
        Add-CEREvidence -Control 'SEC-03' -Flag $(if (($psLog.Count / $macroSet.Count) -ge 0.95 -and ($cmd.Count / $macroSet.Count) -ge 0.95) { 'OK' } else { 'Attention' }) -Action ("Turn on PowerShell script-block logging and command-line process auditing (event 4688) fleet-wide - currently {0} and {1}. These are the two settings that decide whether an incident can be reconstructed at all; both are free, both are a GPO or Intune setting, and neither can be applied retrospectively to an event that has already happened. Then confirm the logs actually reach the SIEM - collection on the host is only half the control." -f (_pct $psLog.Count $macroSet.Count), (_pct $cmd.Count $macroSet.Count)) -Evidence ("Logging prerequisites on user-facing hosts: PowerShell script-block logging {0}, module logging {1}, command-line in 4688 {2} (of {3}). Central collection is checked in the SIEM, not here." -f (_pct $psLog.Count $macroSet.Count), (_pct @($macroSet | Where-Object { (_has $_ 'Hardening.PSLogging.Module') }).Count $macroSet.Count), (_pct $cmd.Count $macroSet.Count), $macroSet.Count)
    }

    # ---------- peripheral / host controls (workstations)
    if ($W.Count) {
        $fw = @($W | Where-Object { (_has $_ 'Hardening.FirewallAllProfilesOn') }); $autologon = @($W | Where-Object { (_has $_ 'Hardening.AutoLogonConfigured') })
        $lock = @($W | Where-Object { $t = _has $_ 'Hardening.ScreenLock.MachineInactivityTimeoutSecs'; ($t -and $t -le 900) -or (@(_has $_ 'Hardening.ScreenLock.UserPolicies') | Where-Object { $_.ScreenSaveTimeOut -and [int]$_.ScreenSaveTimeOut -le 900 -and $_.ScreenSaverIsSecure -eq 1 }).Count -gt 0 })
        $usb = @($W | Where-Object { (_has $_ 'Hardening.USBStorage.DenyAllRemovable') -eq 1 -or (_has $_ 'Hardening.USBStorage.USBSTORStart') -eq 4 -or (_has $_ 'Hardening.USBStorage.RemovableDiskDenyWrite') -eq 1 })
        $pnp = @($W | Where-Object { (_has $_ 'Hardening.PointAndPrint.RestrictDriverInstallationToAdministrators') -eq 1 })
        $flag = if (($fw.Count / $W.Count) -ge 0.95 -and ($lock.Count / $W.Count) -ge 0.9 -and $autologon.Count -eq 0) { 'OK' } else { 'Attention' }
        $fpz = @()
        if ($autologon.Count) { $fpz += "Remove the stored AutoLogon credential from $(_names $autologon 4) - the password sits in the registry in clear text, readable by any local user" }
        if (($fw.Count / $W.Count) -lt 0.95) { $fpz += "Enforce the Windows Firewall on all three profiles by policy - on for all profiles on $(_pct $fw.Count $W.Count) of workstations today" }
        if (($lock.Count / $W.Count) -lt 0.9) { $fpz += "Enforce a screen lock at 15 minutes or less with a password on resume ($(_pct $lock.Count $W.Count) today)" }
        if (($usb.Count / $W.Count) -lt 0.5) { $fpz += "Decide the removable-storage position with the client and enforce it - restricted on only $(_pct $usb.Count $W.Count) of workstations, so today it is a default rather than a decision" }
        if (($pnp.Count / $W.Count) -lt 0.95) { $fpz += "Set Point and Print driver installation to administrators only ($(_pct $pnp.Count $W.Count) today) - the PrintNightmare class of local privilege escalation" }
        $actPz = if ($fpz.Count) { (($fpz -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control 'END-15' -Flag $flag -Action $actPz -Evidence ("Workstations ({0}): Windows Firewall on for all profiles {1}; screen lock <= 15 min enforced {2}; removable storage restricted {3}; Point and Print restricted to admins {4}; AutoLogon configured on {5} ({6})." -f $W.Count, (_pct $fw.Count $W.Count), (_pct $lock.Count $W.Count), (_pct $usb.Count $W.Count), (_pct $pnp.Count $W.Count), $autologon.Count, (_names $autologon 4))
    }

    # ---------- server hardening
    if ($S.Count) {
        $smb1 = @($S | Where-Object { (_has $_ 'Hardening.SMB1Enabled') -eq $true -or (_has $_ 'Hardening.SMB1FeatureState') -eq 'Enabled' })
        $tls = @($S | Where-Object { (_has $_ 'Hardening.TLS10Server') -eq 'Enabled' -or (_has $_ 'Hardening.TLS11Server') -eq 'Enabled' -or ((_has $_ 'Hardening.TLS10Server') -eq 'OS default' -and $_.System.Version -match '^(6\.|10\.0\.1[4-9]|10\.0\.20348)') })
        $nla = @($S | Where-Object { (_has $_ 'Hardening.RDPEnabled') -and -not (_has $_ 'Hardening.RDPNLARequired') })
        $fwOff = @($S | Where-Object { (_has $_ 'Hardening.FirewallAllProfilesOn') -eq $false }); $wdigest = @($S | Where-Object { (_has $_ 'Hardening.WDigestUseLogonCredential') -eq 1 })
        $lm = @($S | Where-Object { $v = _has $_ 'Hardening.LmCompatibilityLevel'; ($null -ne $v -and $v -lt 5) }); $uac = @($S | Where-Object { (_has $_ 'Hardening.UAC.EnableLUA') -eq 0 })
        $spool = @($S | Where-Object { (_has $_ 'Roles.SpoolerRunning') -and (_has $_ 'Roles.SharedPrinters') -eq 0 -and -not (_has $_ 'Roles.IsRdsHost') })
        $dcSpool = @($DC | Where-Object { (_has $_ 'Roles.SpoolerRunning') })
        $flag = if ($smb1.Count -or $nla.Count -or $fwOff.Count -or $wdigest.Count -or $dcSpool.Count) { 'Attention' } else { 'OK' }
        $fs = @()
        if ($smb1.Count) { $fs += "Remove the SMBv1 feature from $(_names $smb1 5) - check for legacy scanners and NAS first, then remove; SMBv1 has no meaningful defence against relay or the WannaCry class of worm" }
        if ($nla.Count) { $fs += "Require Network Level Authentication for RDP on $(_names $nla 5); without NLA the logon screen is reachable before authentication, which is both a brute-force target and a pre-auth attack surface" }
        if ($wdigest.Count) { $fs += "Set WDigest UseLogonCredential to 0 on $($wdigest.Count) server(s) - it caches passwords in memory in clear text, which is exactly what credential dumpers look for first" }
        if ($fwOff.Count) { $fs += "Turn the Windows Firewall back on for all profiles on $(_names $fwOff 5) - the host firewall is what stops lateral movement once something is already inside" }
        if ($dcSpool.Count) { $fs += "Stop and disable the Print Spooler on $($dcSpool.Count) domain controller(s)" }
        if ($tls.Count) { $fs += "Disable TLS 1.0 and 1.1 server-side on $($tls.Count) server(s), explicitly in the registry rather than relying on the OS default" }
        if ($spool.Count) { $fs += "Disable the spooler on the $($spool.Count) non-print, non-RDS server(s) still running it" }
        if ($uac.Count) { $fs += "Re-enable UAC on $($uac.Count) server(s)" }
        $actSh = if ($fs.Count) { (($fs -join '. ') + ' Bundle these into one hardening RFC per server group rather than raising each separately.') } else { '' }
        Add-CEREvidence -Control 'SRV-04' -Flag $flag -Action $actSh -Evidence ("Servers ({0}): SMBv1 enabled on {1} ({2}); TLS 1.0/1.1 server-side enabled or OS-default-on on {3}; RDP without NLA on {4} ({5}); firewall profile(s) off on {6} ({7}); WDigest cleartext caching on {8}; LmCompatibilityLevel < 5 on {9}; UAC disabled on {10}; Print Spooler running on {11} non-print servers incl. {12} DCs." -f $S.Count, $smb1.Count, (_names $smb1 6), $tls.Count, $nla.Count, (_names $nla 6), $fwOff.Count, (_names $fwOff 6), $wdigest.Count, $lm.Count, $uac.Count, $spool.Count, $dcSpool.Count)
        $risky = $S | ForEach-Object { $h = $_; @(_has $h 'Network.RiskyListeners') | ForEach-Object { "{0}:{1}" -f $h.Meta.Hostname, $_.Port } }
        Add-CEREvidence -Control 'NET-04' -Flag Info -Action 'Cross-check these listening ports against the firewall NAT and policy table (FortiGate collector, NET-02/03). This is an internal view only - it shows what is listening, not what is reachable from outside. Anything on this list that is also published to the internet, particularly RDP or SMB, needs closing or moving behind the VPN/ZTNA today.' -Evidence ("Listening services on servers (internal view; confirm none are NAT'd to the internet): {0}." -f (Join-CERList ($S | ForEach-Object { $h = $_; @(_has $h 'Network.RiskyListeners') | ForEach-Object { $_.Port } } | Group-Object | Sort-Object Count -Descending | ForEach-Object { "tcp/{0} on {1} hosts" -f $_.Name, $_.Count }) 10))
        $shares = $S | ForEach-Object { $h = $_; @(_has $h 'Storage.BroadWriteShares') | ForEach-Object { "\\{0}\{1}" -f $h.Meta.Hostname, $_ } }
        $fileHosts = @($S | Where-Object { @(_has $_ 'Storage.Shares').Count -gt 0 })
        Add-CEREvidence -Control 'SRV-08' -Flag $(if (@($shares).Count) { 'Attention' } else { 'OK' }) -Action $(if (@($shares).Count) { "Review the $(@($shares).Count) share(s) granting Change or Full to Everyone, Authenticated Users or Domain Users and replace the share permission with a named security group. Note the tool did not evaluate NTFS ACLs, so the effective access may be tighter than the share permission suggests - but a broad share permission is what ransomware enumerates, and tightening it is a low-risk change. Start with the shares holding finance, HR or client data." } else { '' }) -Evidence ("{0} servers publish non-admin SMB shares ({1} shares); shares granting Change/Full to Everyone, Authenticated Users or Domain Users: {2} - {3}. NTFS ACLs are not evaluated; review these first." -f $fileHosts.Count, ($fileHosts | ForEach-Object { @(_has $_ 'Storage.Shares').Count } | Measure-Object -Sum).Sum, @($shares).Count, (Join-CERList $shares 10))
        $sql = $S | ForEach-Object { $h = $_; @(_has $h 'Roles.SqlInstances') | ForEach-Object { [pscustomobject]@{ Host = $h.Meta.Hostname; Instance = $_.Instance; Product = $_.Product; Supported = $_.Supported; Note = $_.Note; Edition = $_.Edition; Patch = $_.PatchLevel } } }
        if (@($sql).Count) { $bad = @($sql | Where-Object { -not $_.Supported }); Add-CEREvidence -Control 'SRV-09' -Flag $(if ($bad.Count) { 'Attention' } else { 'OK' }) -Action $(if ($bad.Count) { "Plan the upgrade for the $($bad.Count) out-of-support SQL instance(s) - $(Join-CERList ($bad | ForEach-Object { '{0}\{1} {2}' -f $_.Host, $_.Instance, $_.Product }) 5). The blocker is usually the application vendor rather than SQL itself, so the first action is to get the vendor's supported-version statement in writing. Confirm the backup covers these with application-aware processing and log truncation, and check the licensing position before moving anything - SQL is licensed per core on the host it runs on." } else { 'Confirm these instances are covered by application-aware backups with log truncation, and that the SQL licensing position matches what the client is actually running (per-core on the VM host is where this usually goes wrong).' }) -Evidence ("SQL Server instances found: {0} on {1} hosts - {2}. Out of support: {3} ({4})." -f @($sql).Count, @($sql | Select-Object -ExpandProperty Host -Unique).Count, (Join-CERList ($sql | ForEach-Object { "{0}\{1}={2} {3}" -f $_.Host, $_.Instance, $_.Product, $_.Edition }) 8), $bad.Count, (Join-CERList ($bad | ForEach-Object { "{0}\{1} {2}" -f $_.Host, $_.Instance, $_.Product }) 6)) }
        $certs = $S | ForEach-Object { $h = $_; @(_has $h 'Certificates.ExpiringOrExpired') | ForEach-Object { [pscustomobject]@{ Host = $h.Meta.Hostname; Subject = $_.Subject; DaysLeft = $_.DaysLeft; SelfSigned = $_.SelfSigned } } }
        $realCerts = @($certs | Where-Object { -not $_.SelfSigned })
        Add-CEREvidence -Control 'SRV-10' -Flag $(if (@($realCerts | Where-Object { $_.DaysLeft -lt 30 }).Count) { 'Attention' } else { 'OK' }) -Action $(if ($realCerts.Count) { "Renew the certificates expiring inside 30 days first, then put every entry into a certificate register with an owner and a renewal date. Public TLS lifetimes are already down to 200 days and drop to 100 in March 2027 and 47 in March 2029, so manual renewal stops being viable - this is the year to plan automated issuance (ACME or an internal CA with auto-enrolment) rather than diarising renewals." } else { '' }) -Evidence ("Server certificates (LocalMachine\My, private key) expiring within 60 days or expired: {0} CA-issued ({1}); {2} self-signed ignored. {3}" -f $realCerts.Count, (Join-CERList ($realCerts | Sort-Object DaysLeft | ForEach-Object { "{0}: {1} ({2}d)" -f $_.Host, ($_.Subject -replace '^CN=', '' -split ',')[0], $_.DaysLeft }) 8), (@($certs).Count - $realCerts.Count), '')
        $localClock = @($S | Where-Object { (_has $_ 'Network.TimeSourceIsLocalClock') -and -not (_has $_ 'Roles.IsDomainController') })
        $dcClock = @($DC | ForEach-Object { "{0}={1}" -f $_.Meta.Hostname, (_has $_ 'Network.TimeSource') })
        Add-CEREvidence -Control 'SRV-11' -Flag $(if ($localClock.Count) { 'Attention' } else { 'OK' }) -Action $(if ($localClock.Count) { "Point $(_names $localClock 6) back at the domain time hierarchy (w32tm /config /syncfromflags:DOMHIER /update) and stop the hypervisor overwriting the guest clock. A member server on its own clock will drift past the five-minute Kerberos tolerance and then fail authentication intermittently - which gets diagnosed as anything except time." } else { '' }) -Evidence ("Time: DC sources {0}; member servers on local clock/free-running: {1} ({2})." -f (Join-CERList $dcClock 4), $localClock.Count, (_names $localClock 6))
        $print = @($S | Where-Object { (_has $_ 'Roles.SharedPrinters') -gt 0 }); $printUnrestricted = @($print | Where-Object { (_has $_ 'Hardening.PointAndPrint.RestrictDriverInstallationToAdministrators') -ne 1 })
        $rds = @($S | Where-Object { (_has $_ 'Roles.IsRdsHost') }); $oldNet = @($S | Where-Object { $r = _has $_ 'Software.DotNetRelease'; ($r -and $r -lt 528040) })
        $f12 = @()
        if ($printUnrestricted.Count) { $f12 += "Set RestrictDriverInstallationToAdministrators on $(_names $printUnrestricted 5) - unrestricted Point and Print lets a standard user install a driver as SYSTEM" }
        if ($oldNet.Count) { $f12 += "Upgrade .NET Framework to 4.8 or later on $(_names $oldNet 5); earlier 4.x versions are out of support and are a common dependency for line-of-business apps nobody has revisited" }
        Add-CEREvidence -Control 'SRV-12' -Flag $(if ($printUnrestricted.Count -or $oldNet.Count) { 'Attention' } else { 'Info' }) -Action $(if ($f12.Count) { (($f12 -join '. ') + '.') } else { '' }) -Evidence ("Print servers (shared queues): {0} - Point and Print not restricted on {1} ({2}); RDS session hosts: {3} ({4}); IIS on {5}; .NET Framework below 4.8 on {6} ({7})." -f $print.Count, $printUnrestricted.Count, (_names $printUnrestricted 5), $rds.Count, (_names $rds 5), @($S | Where-Object { (_has $_ 'Roles.HasIIS') }).Count, $oldNet.Count, (_names $oldNet 5))
        $low = $S | ForEach-Object { $h = $_; @(_has $h 'Storage.LowSpaceVolumes') | ForEach-Object { "{0} {1}" -f $h.Meta.Hostname, $_ } }
        Add-CEREvidence -Control 'SRV-07' -Flag $(if (@($low).Count) { 'Attention' } else { 'OK' }) -Action $(if (@($low).Count) { "Reclaim or extend the $(@($low).Count) volume(s) below 15% free - $(Join-CERList $low 6). Confirm each has a disk-space monitor in Orion with a threshold that fires with enough runway to act on; a full volume on a DC or a database server is an outage, and it is the most predictable outage there is." } else { '' }) -Evidence ("Volumes below 15% free on servers: {0} - {1}. Virtual: {2}/{3}; uptime > 90 days: {4}." -f @($low).Count, (Join-CERList $low 8), @($S | Where-Object { $_.System.IsVirtual }).Count, $S.Count, @($S | Where-Object { $_.System.UptimeDays -gt 90 }).Count)
        $exch = @($S | Where-Object { (_has $_ 'Roles.HasExchange') }); if ($exch.Count) { Add-CEREvidence -Control 'M365-05' -Flag Info -Action ("Run the ExchangeOnPrem collector on {0} for the true security-update level, hybrid state, virtual directory exposure and Extended Protection. The build seen here comes from the installed binaries and does not tell you which security updates are applied." -f (_names $exch 3)) -Evidence ("Exchange binaries on: {0}" -f (Join-CERList ($exch | ForEach-Object { "{0} (15.{1})" -f $_.Meta.Hostname, ((_has $_ 'Roles.ExchangeBuild') -replace '^15\.', '') }))) }
        $adsync = @($S | Where-Object { (_has $_ 'Roles.HasADSync') }); if ($adsync.Count) { Add-CEREvidence -Control 'IAM-01' -Flag Info -Action ("Record {0} in STACK.md as the identity sync server, confirm the Entra Connect version is still supported (Microsoft force-upgrades or blocks old builds), and check whether a staging-mode server exists. If this host is lost with no staging server, sync stops and password hash sync with it - that is a single point of failure worth naming to the client." -f (_names $adsync 3)) -Evidence ("Entra Connect (ADSync service) runs on: {0}" -f (_names $adsync)) }
        $veeam = @($S | Where-Object { (_has $_ 'Roles.HasVeeamBackupServer') }); if ($veeam.Count) { Add-CEREvidence -Control 'BDR-09' -Flag Info -Action ("Run the Veeam collector on {0} to get jobs, repositories and immutability. While there, confirm the backup server is not domain-joined to the same domain it protects - if it is, a domain compromise takes the backups with it, which is how most ransomware recoveries fail." -f (_names $veeam 2)) -Evidence ("Veeam Backup & Replication server(s): {0}; OS: {1}. Run the Veeam collector there for jobs/repositories." -f (_names $veeam), (Join-CERList ($veeam | ForEach-Object { $_.System.Support.Family }))) }
        $ca = @($S | Where-Object { (_has $_ 'Roles.HasCertSvc') }); if ($ca.Count) { Add-CEREvidence -Control 'SRV-10' -Flag Info -Action ("Run pkiview.msc on {0} and confirm CRL and AIA publishing is healthy, then review the certificate templates for the ESC1-class misconfigurations (templates allowing requester-supplied subject names with client authentication EKU, enrollable by broad groups). A CA is tier-0 infrastructure: whoever can issue certificates can impersonate anyone." -f (_names $ca 3)) -Evidence ("Certificate Services running on: {0} (OS: {1})" -f (_names $ca), (Join-CERList ($ca | ForEach-Object { $_.System.Support.Family }))) }
    }

    # ---------- DC protocol settings from host check
    if ($DC.Count) {
        $ldap = @($DC | Where-Object { (_has $_ 'Hardening.DC.LDAPServerIntegrity') -ne 2 }); $cbt = @($DC | Where-Object { (_has $_ 'Hardening.DC.LdapEnforceChannelBinding') -ne 2 }); $smb1dc = @($DC | Where-Object { (_has $_ 'Hardening.SMB1Enabled') -eq $true })
        Add-CEREvidence -Control 'IAM-10' -Flag $(if ($ldap.Count -or $cbt.Count -or $smb1dc.Count) { 'Attention' } else { 'OK' }) -Action $(if ($ldap.Count -or $cbt.Count -or $smb1dc.Count) { "Enforce LDAP signing (LDAPServerIntegrity = 2) and LDAP channel binding (LdapEnforceChannelBinding = 2) on the DCs, and remove SMBv1 where present. Audit first using event 2889 to find clients still binding without signing - printers, scanners and old appliances are the usual holdouts - then enforce by GPO. Together these close the LDAP relay path that turns any authenticated foothold into domain compromise." } else { '' }) -Evidence ("DCs via host check ({0}): LDAP signing not required on {1}, channel binding not enforced on {2}, SMBv1 on {3}." -f $DC.Count, $ldap.Count, $cbt.Count, $smb1dc.Count)
    }

    # ---------- software watchlist, remote tools, sync clients
    $watch = $All | ForEach-Object { $h = $_; @(_has $h 'Software.Watchlist') | Where-Object { $_.Flag -eq 'Attention' } | ForEach-Object { [pscustomobject]@{ Host = $h.Meta.Hostname; Name = $_.Name; Version = $_.Version; Note = $_.Note } } }
    $byApp = @($watch | Group-Object Name | Sort-Object Count -Descending | ForEach-Object { "{0} (x{1}; {2})" -f $_.Name, $_.Count, $_.Group[0].Note })
    $browsers = $All | ForEach-Object { @(_has $_ 'Software.Browsers') } | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }
    Add-CEREvidence -Control 'END-04' -Flag $(if (@($watch).Count) { 'Attention' } else { 'OK' }) -Action $(if (@($watch).Count) { "Remove or update the end-of-life and known-vulnerable software found - $(Join-CERList $byApp 5). Third-party applications are where most exploited vulnerabilities actually live, and they are usually outside the OS patch policy entirely; confirm the RMM's third-party patching covers each of these titles, and where it cannot, decide whether the application is still needed at all." } else { '' }) -Evidence ("Software watchlist hits (EoL or known-vulnerable versions) across {0} hosts: {1} - {2}. Browser versions seen: {3}. Patch-tool compliance % comes from N-Central/NinjaOne reports." -f $All.Count, @($watch).Count, (Join-CERList $byApp 8), (Join-CERList $browsers 6))
    $remote = $All | ForEach-Object { $h = $_; @(@(_has $h 'Agents.RemoteTools') + @(_has $h 'Software.RemoteTools')) | Select-Object -Unique | ForEach-Object { [pscustomobject]@{ Host = $h.Meta.Hostname; Tool = $_ } } }
    $byTool = @($remote | Group-Object Tool | Sort-Object Count -Descending | ForEach-Object { "{0} (x{1}: {2})" -f $_.Name, $_.Count, (Join-CERList ($_.Group | ForEach-Object { $_.Host }) 4) })
    Add-CEREvidence -Control 'SEC-12' -Flag $(if (@($remote).Count) { 'Attention' } else { 'OK' }) -Action $(if (@($remote).Count) { "Account for every remote-access tool found - $(Join-CERList ($remote | Group-Object Tool | ForEach-Object { $_.Name }) 6) - and confirm each is a sanctioned blueAPACHE or named-vendor path with a known owner. Remove the rest and block them with application control. Unsanctioned remote-access software is both a standing third-party route into the estate and the most common way an attacker keeps access after the original hole is closed." } else { '' }) -Evidence ("Remote-access tools installed/running: {0} occurrences on {1} hosts - {2}. Confirm each is the sanctioned bA/vendor path; block the rest with application control." -f @($remote).Count, @($remote | Select-Object -ExpandProperty Host -Unique).Count, (Join-CERList $byTool 8))
    $sync = $All | ForEach-Object { $h = $_; @(_has $h 'Software.Watchlist') | Where-Object { $_.Note -like '*sync client*' } | ForEach-Object { "{0}:{1}" -f $h.Meta.Hostname, $_.Name } }
    if (@($sync).Count) { Add-CEREvidence -Control 'BDR-07' -Flag Info -Action 'Find out what business data is going through these sync clients. Anything syncing to a personal Dropbox or Google account is corporate data leaving the tenant with no retention, no legal hold and no visibility - and it will not be in any backup. Enforce OneDrive Known Folder Move so user data has a managed destination, then block the alternatives with application control.' -Evidence ("Third-party sync clients found (data outside OneDrive?): {0}" -f (Join-CERList $sync 8)) }

    # ---------- events
    $cleared = @($All | Where-Object { (_has $_ 'Events.SecurityLogCleared90d') -gt 0 }); $smallLog = @($S | Where-Object { $m = _has $_ 'Hardening.SecurityLogMaxMB'; ($m -and $m -lt 196) })
    $bruteforce = @($All | Where-Object { (_has $_ 'Events.FailedLogons24h') -ge 200 })
    $fev = @()
    if ($cleared.Count) { $fev += "Investigate why the Security log was cleared on $(_names $cleared 5) in the last 90 days. Event 1102 has legitimate causes, but clearing the Security log is also the standard way to destroy evidence, so each instance needs an explanation rather than an assumption" }
    if ($bruteforce.Count) { $fev += "Look into the hosts seeing 200+ failed logons in 24 hours - $(_names $bruteforce 5). It is usually a service account with a stale password, but password spraying looks identical from a single host's perspective, so confirm which" }
    if ($smallLog.Count) { $fev += "Raise the Security log maximum size above 196 MB on $($smallLog.Count) server(s) - a small log on a busy server wraps within hours, so the evidence is gone before anyone asks for it" }
    Add-CEREvidence -Control 'SEC-03' -Flag $(if ($cleared.Count) { 'Attention' } else { 'Info' }) -Action $(if ($fev.Count) { (($fev -join '. ') + '.') } else { '' }) -Evidence ("Security event log cleared (1102) in last 90 days on {0} hosts ({1}); Security log max size < 196 MB on {2} servers; >= 200 failed logons (4625) in 24 h on {3} ({4})." -f $cleared.Count, (_names $cleared 5), $smallLog.Count, $bruteforce.Count, (_names $bruteforce 5))
    $errs = @($All | Where-Object { @(_has $_ 'Errors').Count -gt 0 })
    if ($errs.Count) { Add-CEREvidence -Control 'END-01' -Flag Info -Action ("Re-run the host check on {0} with full local administrator rights, or accept that the sections that errored are unevidenced on those hosts. Partial results should not be scored as compliant - see the Errors array in the per-host JSON for what failed." -f (_names $errs 5)) -Evidence ("Host check ran with partial errors on {0} hosts (usually non-admin or missing cmdlets): {1}" -f $errs.Count, (_names $errs 6)) }
}

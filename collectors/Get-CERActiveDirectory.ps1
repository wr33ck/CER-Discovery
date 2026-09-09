#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: on-premises Active Directory (run on a DC or a domain-joined jump host with RSAT).
  Feeds IAM-01/05/09/10/11, SRV-02/05/09/10/11/12, END-02, M365-05, BDR-06, SEC-08, DOC-06.
.EXAMPLE
  .\Get-CERActiveDirectory.ps1 -Client C-003 -OutputRoot D:\CER\output -RunId 20260905-0900
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string]$Server,
    [int]$StaleDays = 90,
    [int]$MaxGpoReports = 300,
    [switch]$SkipDcRemote
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'AD' -RunId $RunId
$C = 'AD'
if (-not (Test-CERModule -Name ActiveDirectory -Collector $C -Section 'Module')) { Complete-CERCollector; return }
Import-Module ActiveDirectory -ErrorAction Stop
$srvArg = @{}; if ($Server) { $srvArg['Server'] = $Server }
$now = Get-Date

# ---------------- Forest / domain / DCs
$forest = $null; $domain = $null; $dcs = @()
Invoke-CERSection -Collector $C -Section 'ForestDomain' -Script {
    $script:forest = Get-ADForest @srvArg
    $script:domain = Get-ADDomain @srvArg
    $trusts = @(Get-ADTrust -Filter * @srvArg | Select-Object Name, Direction, TrustType, ForestTransitive, SelectiveAuthentication, SIDFilteringForestAware)
    Save-CERRaw -Name 'forest' -Object ([ordered]@{ Forest = ($script:forest | Select-Object Name, ForestMode, DomainNamingMaster, SchemaMaster, Domains, GlobalCatalogs, Sites, UPNSuffixes); Domain = ($script:domain | Select-Object DNSRoot, NetBIOSName, DomainMode, PDCEmulator, RIDMaster, InfrastructureMaster, DistinguishedName, ReplicaDirectoryServers, ReadOnlyReplicaDirectoryServers); Trusts = $trusts })
    Add-CEREvidence -Control 'IAM-10' -Flag Info -Action ('Record the FSMO role placement and the trust list in STACK.md - both are things nobody looks up until an outage. Review each trust against whether the relationship is still live, and confirm SID filtering and selective authentication are on for any external trust; a forgotten trust to a decommissioned partner is a standing route into the domain.') -Evidence ("Forest {0} (mode {1}), domain {2} (mode {3}); FSMO: schema={4}, naming={5}, PDC={6}, RID={7}, infra={8}; trusts: {9}." -f $script:forest.Name, $script:forest.ForestMode, $script:domain.DNSRoot, $script:domain.DomainMode, $script:forest.SchemaMaster, $script:forest.DomainNamingMaster, $script:domain.PDCEmulator, $script:domain.RIDMaster, $script:domain.InfrastructureMaster, (Join-CERList ($trusts | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Direction })))
}
Invoke-CERSection -Collector $C -Section 'DomainControllers' -Script {
    $script:dcs = @(Get-ADDomainController -Filter * @srvArg | Select-Object Name, HostName, IPv4Address, OperatingSystem, OperatingSystemVersion, Site, IsGlobalCatalog, IsReadOnly, Enabled)
    $rows = foreach ($d in $script:dcs) { $s = Get-CERWindowsSupport -Caption $d.OperatingSystem -Version $d.OperatingSystemVersion -ProductType 2; [pscustomobject]@{ Name = $d.Name; OS = $d.OperatingSystem; Family = $s.Family; Supported = $s.Supported; EndOfSupport = $s.EndOfSupport; Site = $d.Site; GC = $d.IsGlobalCatalog; RODC = $d.IsReadOnly; IP = $d.IPv4Address } }
    Save-CERRaw -Name 'dcs' -Object $rows
    $unsup = @($rows | Where-Object { -not $_.Supported })
    $soon = @($rows | Where-Object { $_.Supported -and $_.EndOfSupport })
    $flag = if ($unsup.Count) { 'Attention' } elseif ($soon.Count) { 'Attention' } else { 'OK' }
    $act = ''
    if ($unsup.Count) { $act = "Replace the out-of-support domain controller(s) - $(Join-CERList ($unsup | ForEach-Object { $_.Name })). Build a supported DC alongside, transfer FSMO roles, demote the old one, then raise the functional levels once the last legacy DC is gone. A DC holds every credential in the domain and is receiving no security updates." }
    elseif ($soon.Count) { $act = "Schedule the DC refresh for $(Join-CERList ($soon | ForEach-Object { '{0} (support ends {1})' -f $_.Name, $_.EndOfSupport })). A DC replacement needs a window, FSMO moves and a rollback plan - book it a quarter ahead of the date, not the month before." }
    if ($rows.Count -eq 1) { $act = ($act + ' Only one domain controller exists: a single DC is a single point of failure for authentication, DNS and Group Policy, and a failed restore means a forest rebuild. Add a second DC in a separate failure domain.').Trim() }
    Add-CEREvidence -Control 'IAM-10' -Flag $flag -Action $act -Evidence ("{0} DCs ({1} RODC): {2}. Unsupported OS: {3}. Ending soon: {4}." -f $rows.Count, @($rows | Where-Object RODC).Count, (Join-CERList ($rows | ForEach-Object { "{0} [{1}]" -f $_.Name, $_.Family })), (Join-CERList ($unsup | ForEach-Object { $_.Name })), (Join-CERList ($soon | ForEach-Object { "{0} ({1})" -f $_.Name, $_.EndOfSupport })))
    Add-CEREvidence -Control 'SRV-02' -Flag $flag -Action $act -Evidence ("Domain controllers: {0}" -f (Join-CERList ($rows | ForEach-Object { "{0}={1}" -f $_.Name, $_.Family })))
}
Invoke-CERSection -Collector $C -Section 'Replication' -Script {
    $partners = @(Get-ADReplicationPartnerMetadata -Target $script:domain.DNSRoot -Scope Domain -ErrorAction Stop | Select-Object Server, Partner, LastReplicationSuccess, LastReplicationAttempt, ConsecutiveReplicationFailures, LastReplicationResult)
    $fail = @(Get-ADReplicationFailure -Target $script:domain.DNSRoot -Scope Domain -ErrorAction SilentlyContinue | Select-Object Server, Partner, FailureCount, FirstFailureTime, LastError)
    $rep = $null; try { $rep = repadmin /replsummary 2>&1 | Out-String } catch { }
    Save-CERRaw -Name 'replication' -Object ([ordered]@{ Partners = $partners; Failures = $fail; ReplSummary = $rep })
    $stale = @($partners | Where-Object { $_.LastReplicationSuccess -and ((Get-CERAgeDays $_.LastReplicationSuccess) -gt 1) })
    $flag = if ($fail.Count -or $stale.Count) { 'Attention' } else { 'OK' }
    $act = ''
    if ($fail.Count -or $stale.Count) {
        $act = "Fix replication before anything else in AD - run 'repadmin /replsummary' and 'dcdiag /v' on $(Join-CERList (@($fail + $stale | ForEach-Object { $_.Server }) | Select-Object -Unique) 4), and work the specific error (LastError on the failing link). Replication that has been broken longer than the tombstone lifetime cannot be repaired by waiting: the lagging DC must be demoted and rebuilt, so treat the clock as running."
    }
    Add-CEREvidence -Control 'IAM-10' -Flag $flag -Action $act -Evidence ("Replication: {0} partner links, {1} with failures, {2} with last success > 24 h; consecutive failures max {3}." -f $partners.Count, $fail.Count, $stale.Count, (($partners | Measure-Object ConsecutiveReplicationFailures -Maximum).Maximum))
}
Invoke-CERSection -Collector $C -Section 'ADHealthFlags' -Script {
    $dn = $script:domain.DistinguishedName
    $rb = Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' @srvArg
    $rbOn = (@($rb.EnabledScopes).Count -gt 0)
    $krb = Get-ADUser krbtgt -Properties PasswordLastSet @srvArg
    $krbAge = Get-CERAgeDays $krb.PasswordLastSet
    $dfsr = Get-ADObject -Filter 'name -eq "DFSR-GlobalSettings"' -SearchBase "CN=System,$dn" @srvArg -ErrorAction SilentlyContinue
    $sysvol = if ($dfsr) { 'DFSR' } else { 'FRS (legacy - must migrate)' }
    $ts = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$($script:forest.PartitionsContainer -replace '^CN=Partitions,','')" -Properties tombstoneLifetime @srvArg -ErrorAction SilentlyContinue).tombstoneLifetime
    $backup = $null; try { $backup = repadmin /showbackup 2>&1 | Out-String } catch { }
    Save-CERRaw -Name 'health' -Object ([ordered]@{ RecycleBin = $rbOn; KrbtgtPasswordLastSet = $krb.PasswordLastSet; KrbtgtAgeDays = $krbAge; Sysvol = $sysvol; TombstoneLifetime = $ts; ShowBackup = $backup })
    $flag = if (-not $rbOn -or $krbAge -gt 180 -or $sysvol -like 'FRS*') { 'Attention' } else { 'OK' }
    $fix = @()
    if (-not $rbOn) { $fix += "Enable the AD Recycle Bin (Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target '$($script:forest.Name)'). It is a one-way switch and free; without it, restoring a deleted OU or group means an authoritative restore from backup" }
    if ($krbAge -gt 180) { $fix += "Rotate the KRBTGT password twice, at least 24 h apart (one rotation, wait a full replication cycle plus 10 h, then rotate again) - it was last set $krbAge days ago. A stale KRBTGT means any golden ticket forged since then still works" }
    if ($sysvol -like 'FRS*') { $fix += 'Migrate SYSVOL from FRS to DFSR (dfsrmig /setglobalstate) - FRS is removed from Windows Server 2016 and later, so the domain cannot be upgraded past 2012 R2 until this is done' }
    $act = if ($fix.Count) { (($fix -join '. ') + '.') } else { '' }
    Add-CEREvidence -Control 'IAM-10' -Flag $flag -Action $act -Evidence ("AD Recycle Bin: {0}; KRBTGT password age: {1} days (target < 180, rotate twice); SYSVOL replication: {2}; tombstone lifetime: {3}." -f $(if ($rbOn) { 'enabled' } else { 'NOT enabled' }), $krbAge, $sysvol, $ts)
    if ($backup) {
        # repadmin /showbackup prints the dSASignature attribute per partition - raw, that is a wall of GUIDs.
        # Only the dates carry meaning here, so report the newest and its age and leave the rest in raw/.
        $dates = @([regex]::Matches($backup, '\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}') | ForEach-Object { $_.Value } | Select-Object -Unique | Sort-Object -Descending)
        if ($dates.Count) {
            $age = Get-CERAgeDays $dates[0]
            $act = if ($null -ne $age -and $age -gt 7) { "Get a working system-state backup of at least one DC. The newest AD backup is $age days old; a backup older than the tombstone lifetime ($ts days) is useless for forest recovery because the restored DC can no longer replicate. Confirm the Veeam job covering the DC has application-aware processing enabled, not just a crash-consistent VM image." } else { '' }
            Add-CEREvidence -Control 'BDR-06' -Flag $(if ($null -ne $age -and $age -gt 7) { 'Attention' } else { 'Info' }) -Action $act -Evidence ("Last AD system-state backup (repadmin /showbackup): {0}{1}; {2} partition entries reported. A backup older than the tombstone lifetime cannot be used to restore the forest - full output in raw\ad.health.json." -f $dates[0], $(if ($null -ne $age) { " ($age days ago)" } else { '' }), $dates.Count)
        } else {
            Add-CEREvidence -Control 'BDR-06' -Flag Unknown -Action 'Confirm a DC is covered by an application-aware backup job and that a system-state restore has actually been tested. repadmin /showbackup reporting no dates usually means no Exchange/AD-aware backup has ever run against a DC - a crash-consistent VM snapshot is not a supported AD restore.' -Evidence 'repadmin /showbackup returned no backup dates - no AD system-state backup recorded, or the command could not read them. Confirm against the backup platform (Veeam collector, BDR-06).'
        }
    }
}

# ---------------- Privileged accounts
Invoke-CERSection -Collector $C -Section 'PrivilegedGroups' -Script {
    $groups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners'
    $rows = @(); $allPriv = @{}
    foreach ($g in $groups) {
        try {
            $m = @(Get-ADGroupMember -Identity $g -Recursive @srvArg -ErrorAction Stop)
            $rows += [pscustomobject]@{ Group = $g; Count = $m.Count; Members = @($m | ForEach-Object { $_.SamAccountName }) }
            foreach ($x in $m) { if ($x.objectClass -eq 'user') { $allPriv[$x.SamAccountName] = $g } }
        } catch { }
    }
    $privUsers = @()
    foreach ($sam in $allPriv.Keys) {
        $u = Get-ADUser -Identity $sam -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, Enabled, mail, proxyAddresses, adminCount, MemberOf, whenCreated @srvArg -ErrorAction SilentlyContinue
        if ($u) {
            $privUsers += [pscustomobject]@{ Sam = $u.SamAccountName; Enabled = $u.Enabled; LastLogonDays = (Get-CERAgeDays $u.LastLogonDate); PasswordAgeDays = (Get-CERAgeDays $u.PasswordLastSet); PasswordNeverExpires = $u.PasswordNeverExpires; HasMailbox = [bool]($u.mail -or ($u.proxyAddresses | Where-Object { $_ -like 'SMTP:*' })); InProtectedUsers = ([bool]($u.MemberOf | Where-Object { $_ -like 'CN=Protected Users,*' })); ViaGroup = $allPriv[$u.SamAccountName] }
        }
    }
    $adminCountUsers = @(Get-ADUser -Filter 'adminCount -eq 1 -and Enabled -eq $true' @srvArg | Measure-Object).Count
    $protected = @(); try { $protected = @(Get-ADGroupMember 'Protected Users' @srvArg -ErrorAction Stop | ForEach-Object { $_.SamAccountName }) } catch { }
    Save-CERRaw -Name 'privileged' -Object ([ordered]@{ Groups = $rows; Users = $privUsers; AdminCountEnabled = $adminCountUsers; ProtectedUsers = $protected })
    $da = ($rows | Where-Object Group -eq 'Domain Admins').Count
    $ea = ($rows | Where-Object Group -eq 'Enterprise Admins').Count
    $withMail = @($privUsers | Where-Object { $_.HasMailbox -and $_.Enabled })
    $stalePriv = @($privUsers | Where-Object { $_.Enabled -and ($_.LastLogonDays -gt 45 -or $null -eq $_.LastLogonDays) })
    $pne = @($privUsers | Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
    $flag = if ($da -gt 5 -or $withMail.Count -gt 0 -or $stalePriv.Count -gt 0) { 'Attention' } else { 'OK' }
    $f1 = @()
    if ($da -gt 5) { $f1 += "Trim Domain Admins from $da to the smallest set that can actually be justified (target 5 or fewer) - every extra member is another credential worth stealing, and most day-to-day work does not need DA" }
    if (-not $protected.Count -and $privUsers.Count) { $f1 += 'Add the privileged accounts to the Protected Users group, which blocks NTLM, unconstrained delegation and credential caching for those members (test first - it breaks anything relying on NTLM)' }
    if ($ea -gt 1) { $f1 += "Reduce Enterprise Admins to zero standing members ($ea today) and add on demand for schema or forest-wide changes only" }
    $act1 = if ($f1.Count) { (($f1 -join '. ') + '.') } else { '' }
    $f2 = @()
    if ($withMail.Count) { $f2 += "Separate the admin accounts that carry a mailbox - $(Join-CERList ($withMail | ForEach-Object { $_.Sam }) 5). A privileged account that reads email is one phishing click away from domain compromise; give each admin a dedicated, mailbox-less admin account and leave the mailbox on their standard user account" }
    if ($stalePriv.Count) { $f2 += "Disable the $($stalePriv.Count) privileged account(s) not used in 45 days - $(Join-CERList ($stalePriv | ForEach-Object { $_.Sam }) 5). Essential Eight ML2 requires privileged access to be disabled after 45 days of inactivity" }
    if ($pne.Count) { $f2 += "Clear password-never-expires on $(Join-CERList ($pne | ForEach-Object { $_.Sam }) 5), or move those accounts to a gMSA if they are service accounts" }
    $act2 = if ($f2.Count) { (($f2 -join '. ') + '.') } else { '' }
    Add-CEREvidence -Control 'SRV-05' -Flag $flag -Action $act1 -Evidence ("Domain Admins: {0} (target <= 5), Enterprise Admins: {1}, Schema Admins: {2}, Account Operators: {3}, Backup Operators: {4}; Protected Users group: {5} members; enabled adminCount=1 users: {6}." -f $da, $ea, ($rows | Where-Object Group -eq 'Schema Admins').Count, ($rows | Where-Object Group -eq 'Account Operators').Count, ($rows | Where-Object Group -eq 'Backup Operators').Count, $protected.Count, $adminCountUsers)
    Add-CEREvidence -Control 'SEC-08' -Flag $flag -Action $act2 -Evidence ("Privileged AD accounts: {0} total; {1} with a mailbox (not dedicated admin accounts): {2}; {3} not logged on for > 45 days (E8 ML2 disable): {4}; {5} with password never expires: {6}." -f $privUsers.Count, $withMail.Count, (Join-CERList ($withMail | ForEach-Object { $_.Sam })), $stalePriv.Count, (Join-CERList ($stalePriv | ForEach-Object { $_.Sam })), $pne.Count, (Join-CERList ($pne | ForEach-Object { $_.Sam })))
    Add-CEREvidence -Control 'IAM-05' -Flag Info -Action 'Compare this list against Entra Global Administrators. A synced account holding both on-prem Domain Admin and Entra Global Admin collapses the tiering boundary - compromise of the on-prem account takes the tenant with it. Cloud admin roles should sit on cloud-only accounts.' -Evidence ("On-prem Domain Admins ({0}): {1}. Cross-check against Entra Global Administrators (synced admins should not hold both)." -f $da, (Join-CERList (($rows | Where-Object Group -eq 'Domain Admins').Members)))
}

# ---------------- Users, computers, service accounts, LAPS
Invoke-CERSection -Collector $C -Section 'UsersComputers' -Script {
    $cut = $now.AddDays(-$StaleDays)
    $users = @(Get-ADUser -Filter * -Properties Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires, PasswordNotRequired, whenCreated, ServicePrincipalName, DoesNotRequirePreAuth, UseDESKeyOnly, SIDHistory, Description, TrustedForDelegation, msDS-SupportedEncryptionTypes @srvArg)
    $enabled = @($users | Where-Object Enabled)
    $stale = @($enabled | Where-Object { ($_.LastLogonDate -and $_.LastLogonDate -lt $cut) -or (-not $_.LastLogonDate -and $_.whenCreated -lt $cut) })
    $pne = @($enabled | Where-Object PasswordNeverExpires)
    $pnr = @($enabled | Where-Object PasswordNotRequired)
    $oldPw = @($enabled | Where-Object { $_.PasswordLastSet -and $_.PasswordLastSet -lt $now.AddYears(-1) })
    $spn = @($enabled | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' })
    $asrep = @($enabled | Where-Object DoesNotRequirePreAuth)
    $des = @($enabled | Where-Object UseDESKeyOnly)
    $sidh = @($enabled | Where-Object { $_.SIDHistory })
    $unconstrained = @($enabled | Where-Object TrustedForDelegation)
    $msol = @($users | Where-Object { $_.SamAccountName -like 'MSOL_*' -or $_.SamAccountName -like 'AAD_*' })
    $svcLike = @($enabled | Where-Object { $_.SamAccountName -match '^(svc|sa|srv|service)[_\-\.]' -or $_.ServicePrincipalName })
    $gmsa = @(); try { $gmsa = @(Get-ADServiceAccount -Filter * @srvArg) } catch { }
    $computers = @(Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion, whenCreated, DNSHostName, IPv4Address, TrustedForDelegation, 'msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime', Description @srvArg)
    $compEnabled = @($computers | Where-Object Enabled)
    $compStale = @($compEnabled | Where-Object { ($_.LastLogonDate -and $_.LastLogonDate -lt $cut) -or (-not $_.LastLogonDate -and $_.whenCreated -lt $cut) })
    $compActive = @($compEnabled | Where-Object { $_.LastLogonDate -and $_.LastLogonDate -ge $now.AddDays(-60) })
    $osRows = @($compActive | Group-Object OperatingSystem | Sort-Object Count -Descending | ForEach-Object { $x = $_.Group[0]; $pt = if ($x.OperatingSystem -match 'Server') { 3 } else { 1 }; $s = Get-CERWindowsSupport -Caption $x.OperatingSystem -Version $x.OperatingSystemVersion -ProductType $pt; [pscustomobject]@{ OS = $_.Name; Count = $_.Count; Family = $s.Family; Supported = $s.Supported; EndOfSupport = $s.EndOfSupport } })
    $servers = @($compActive | Where-Object { $_.OperatingSystem -match 'Server' } | Select-Object Name, DNSHostName, IPv4Address, OperatingSystem, OperatingSystemVersion, LastLogonDate, Description)
    $workstations = @($compActive | Where-Object { $_.OperatingSystem -notmatch 'Server' -and $_.OperatingSystem -match 'Windows' })
    $winLapsSchema = [bool](Get-ADObject -SearchBase (Get-ADRootDSE @srvArg).schemaNamingContext -Filter 'name -eq "ms-LAPS-Password"' @srvArg -ErrorAction SilentlyContinue)
    $legacyLapsSchema = [bool](Get-ADObject -SearchBase (Get-ADRootDSE @srvArg).schemaNamingContext -Filter 'name -eq "ms-Mcs-AdmPwd"' @srvArg -ErrorAction SilentlyContinue)
    $lapsWs = @($workstations | Where-Object { $_.'msLAPS-PasswordExpirationTime' -or $_.'ms-Mcs-AdmPwdExpirationTime' })
    $lapsSrv = @($servers | ForEach-Object { $n = $_.Name; $compActive | Where-Object { $_.Name -eq $n -and ($_.'msLAPS-PasswordExpirationTime' -or $_.'ms-Mcs-AdmPwdExpirationTime') } })
    $unconstrainedComp = @($compEnabled | Where-Object { $_.TrustedForDelegation -and $_.OperatingSystem -notmatch 'Domain Controller' -and ($script:dcs.Name -notcontains $_.Name) })
    Save-CERRaw -Name 'servers' -Object $servers
    Save-CERRaw -Name 'users.summary' -Object ([ordered]@{ Total = $users.Count; Enabled = $enabled.Count; Stale = @($stale | ForEach-Object { $_.SamAccountName }); PasswordNeverExpires = @($pne | ForEach-Object { $_.SamAccountName }); PasswordNotRequired = @($pnr | ForEach-Object { $_.SamAccountName }); Kerberoastable = @($spn | ForEach-Object { $_.SamAccountName }); ASREPRoastable = @($asrep | ForEach-Object { $_.SamAccountName }); DESOnly = @($des | ForEach-Object { $_.SamAccountName }); SIDHistory = @($sidh | ForEach-Object { $_.SamAccountName }); UnconstrainedDelegationUsers = @($unconstrained | ForEach-Object { $_.SamAccountName }); MSOL = @($msol | ForEach-Object { [ordered]@{ Sam = $_.SamAccountName; Description = $_.Description } }); ServiceAccountLike = @($svcLike | ForEach-Object { $_.SamAccountName }); gMSA = @($gmsa | ForEach-Object { $_.Name }) })
    Save-CERRaw -Name 'computers.summary' -Object ([ordered]@{ Total = $computers.Count; Enabled = $compEnabled.Count; ActiveLast60d = $compActive.Count; Stale = $compStale.Count; OS = $osRows; WinLapsSchema = $winLapsSchema; LegacyLapsSchema = $legacyLapsSchema; LapsWorkstations = $lapsWs.Count; Workstations = $workstations.Count; LapsServers = $lapsSrv.Count; Servers = $servers.Count; UnconstrainedDelegation = @($unconstrainedComp | ForEach-Object { $_.Name }) })
    $flagStale = if ($enabled.Count -and ($stale.Count / [math]::Max(1, $enabled.Count)) -gt 0.02) { 'Attention' } else { 'OK' }
    $f3 = @()
    if ($stale.Count) { $f3 += "Disable the $($stale.Count) enabled account(s) with no logon in $StaleDays days, then delete after a retention period. Agree a joiner-mover-leaver process with the client so this does not rebuild - a dormant enabled account is a credential nobody is watching" }
    if ($pnr.Count) { $f3 += "Clear password-not-required on $($pnr.Count) account(s) immediately - that flag lets the account be set to a blank password" }
    if ($pne.Count) { $f3 += "Review the $($pne.Count) password-never-expires account(s); genuine service accounts should become group managed service accounts (gMSA), which rotate their own passwords" }
    if ($svcLike.Count -and -not $gmsa.Count) { $f3 += "$($svcLike.Count) service-account-like objects exist with no gMSA in the domain - convert the ones whose services support it, so passwords rotate automatically and nobody needs to know them" }
    $actStale = if ($f3.Count) { (($f3 -join '. ') + '.') } else { '' }
    Add-CEREvidence -Control 'IAM-09' -Flag $flagStale -Action $actStale -Evidence ("AD users: {0} total, {1} enabled; {2} enabled users stale > {3} days ({4}); {5} enabled computers stale (of {6}); password-never-expires: {7}; password-not-required: {8}; password older than 1 year: {9}; service-account-like accounts: {10}; gMSA: {11}." -f $users.Count, $enabled.Count, $stale.Count, $StaleDays, (ConvertTo-CERPct $stale.Count $enabled.Count), $compStale.Count, $compEnabled.Count, $pne.Count, $pnr.Count, $oldPw.Count, $svcLike.Count, $gmsa.Count)
    $flagKerb = if ($spn.Count -or $asrep.Count -or $des.Count -or $unconstrainedComp.Count) { 'Attention' } else { 'OK' }
    $f4 = @()
    if ($spn.Count) { $f4 += "Give the $($spn.Count) SPN-bearing user account(s) a long random password (25+ characters) or convert them to gMSA - $(Join-CERList ($spn | ForEach-Object { $_.SamAccountName }) 4). Any domain user can request a service ticket for these and crack it offline (Kerberoasting), so password length is the only real control" }
    if ($asrep.Count) { $f4 += "Turn Kerberos pre-authentication back on for $(Join-CERList ($asrep | ForEach-Object { $_.SamAccountName }) 4) - without it an attacker can request an AS-REP and crack it offline with no credentials at all" }
    if ($des.Count) { $f4 += "Clear the DES-only encryption flag on $($des.Count) account(s); DES is broken and forces the whole ticket exchange down to it" }
    if ($unconstrainedComp.Count) { $f4 += "Remove unconstrained delegation from $(Join-CERList ($unconstrainedComp | ForEach-Object { $_.Name }) 4) and use constrained or resource-based constrained delegation instead. A compromised host with unconstrained delegation captures the TGT of every user who connects to it, including Domain Admins" }
    $actKerb = if ($f4.Count) { (($f4 -join '. ') + '.') } else { '' }
    Add-CEREvidence -Control 'IAM-10' -Flag $flagKerb -Action $actKerb -Evidence ("Kerberos hygiene: {0} user accounts with SPNs (kerberoastable): {1}; {2} without pre-auth (AS-REP roastable): {3}; {4} DES-only; {5} with SIDHistory; unconstrained delegation on {6} non-DC computers: {7}." -f $spn.Count, (Join-CERList ($spn | ForEach-Object { $_.SamAccountName }) 6), $asrep.Count, (Join-CERList ($asrep | ForEach-Object { $_.SamAccountName }) 6), $des.Count, $sidh.Count, $unconstrainedComp.Count, (Join-CERList ($unconstrainedComp | ForEach-Object { $_.Name }) 6))
    $lapsFlag = if ($workstations.Count -and ($lapsWs.Count / $workstations.Count) -ge 0.95) { 'OK' } elseif ($winLapsSchema -or $legacyLapsSchema) { 'Attention' } else { 'Attention' }
    $actLaps = if ($lapsFlag -eq 'OK') { '' }
    elseif (-not $winLapsSchema -and -not $legacyLapsSchema) { 'Deploy Windows LAPS - extend the schema (Update-LapsADSchema), delegate password read to the right group, and push the policy by GPO or Intune. With no LAPS at all, the local administrator password is almost certainly identical across the fleet, which turns one compromised workstation into all of them.' }
    else { "Finish the LAPS rollout: $($lapsWs.Count) of $($workstations.Count) workstations and $($lapsSrv.Count) of $($servers.Count) member servers currently store a managed password. The schema is already in place, so the gap is policy scope - check the GPO/Intune assignment covers every OU, then confirm the machines have checked in." }
    Add-CEREvidence -Control 'IAM-11' -Flag $lapsFlag -Action $actLaps -Evidence ("LAPS (AD-backed): schema Windows LAPS={0}, legacy LAPS={1}; workstations with a LAPS password attribute: {2}/{3} ({4}); member servers: {5}/{6}. (Entra-backed LAPS is reported by the Entra collector.)" -f $winLapsSchema, $legacyLapsSchema, $lapsWs.Count, $workstations.Count, (ConvertTo-CERPct $lapsWs.Count $workstations.Count), $lapsSrv.Count, $servers.Count)
    Add-CEREvidence -Control 'END-08' -Flag $lapsFlag -Action $actLaps -Evidence ("AD LAPS coverage on active workstations: {0}/{1} ({2})." -f $lapsWs.Count, $workstations.Count, (ConvertTo-CERPct $lapsWs.Count $workstations.Count))
    $unsupWs = @($osRows | Where-Object { -not $_.Supported -and $_.OS -notmatch 'Server' }); $unsupSrv = @($osRows | Where-Object { -not $_.Supported -and $_.OS -match 'Server' }); $soonSrv = @($osRows | Where-Object { $_.Supported -and $_.EndOfSupport -and $_.OS -match 'Server' })
    $actWs = if ($unsupWs.Count) { "Replace or upgrade the $((($unsupWs | Measure-Object Count -Sum).Sum)) out-of-support workstation(s) - $(Join-CERList ($unsupWs | ForEach-Object { '{0} x{1}' -f $_.Family, $_.Count }) 4). Windows 10 left support on 14 Oct 2025; unless the client has bought ESU, these receive no security updates at all. Where hardware blocks Windows 11, that is a budget conversation to raise with the SDM now, not at renewal." } else { '' }
    Add-CEREvidence -Control 'END-02' -Flag $(if ($unsupWs.Count) { 'Attention' } else { 'OK' }) -Action $actWs -Evidence ("AD computer objects active in last 60 days: {0} workstations. OS mix: {1}. Unsupported: {2}." -f $workstations.Count, (Join-CERList (($osRows | Where-Object { $_.OS -notmatch 'Server' }) | ForEach-Object { "{0}={1}" -f $_.Family, $_.Count })), (Join-CERList ($unsupWs | ForEach-Object { "{0}={1}" -f $_.OS, $_.Count })))
    $actSrv = if ($unsupSrv.Count) { "Get the out-of-support server(s) off unsupported Windows - $(Join-CERList ($unsupSrv | ForEach-Object { '{0} x{1}' -f $_.Family, $_.Count }) 4). Where an application pins the OS version, record it as an accepted risk with a compensating control (segmentation, no internet egress) rather than leaving it undocumented." }
    elseif ($soonSrv.Count) { "Build the server refresh into the roadmap now - $(Join-CERList ($soonSrv | ForEach-Object { '{0} x{1} (ends {2})' -f $_.Family, $_.Count, $_.EndOfSupport }) 4). Server 2016 ends 12 Jan 2027; a migration of that size needs to be in the client's budget cycle a year out." } else { '' }
    Add-CEREvidence -Control 'SRV-02' -Flag $(if ($unsupSrv.Count) { 'Attention' } elseif ($soonSrv.Count) { 'Attention' } else { 'OK' }) -Action $actSrv -Evidence ("AD server objects active in last 60 days: {0}. OS mix: {1}. Unsupported: {2}. Ending within 12 months: {3}." -f $servers.Count, (Join-CERList (($osRows | Where-Object { $_.OS -match 'Server' }) | ForEach-Object { "{0}={1}" -f $_.Family, $_.Count })), (Join-CERList ($unsupSrv | ForEach-Object { "{0}={1}" -f $_.OS, $_.Count })), (Join-CERList ($soonSrv | ForEach-Object { "{0}={1} ({2})" -f $_.Family, $_.Count, $_.EndOfSupport })))
    if ($msol.Count) { Add-CEREvidence -Control 'IAM-01' -Flag Info -Action 'Identify which sync server each of these accounts belongs to and record it in STACK.md - the description field usually names the host. Retire any MSOL_/AAD_ account whose sync server no longer exists: it holds directory replication rights (the ability to read every password hash in the domain) and is a favourite persistence mechanism precisely because it looks like it belongs.' -Evidence ("Entra Connect service accounts in AD: {0}" -f (Join-CERList ($msol | ForEach-Object { "{0} [{1}]" -f $_.SamAccountName, $_.Description }) 3)) }
}

# ---------------- Password policy
Invoke-CERSection -Collector $C -Section 'PasswordPolicy' -Script {
    $pp = Get-ADDefaultDomainPasswordPolicy @srvArg
    $fg = @(Get-ADFineGrainedPasswordPolicy -Filter * @srvArg | Select-Object Name, Precedence, MinPasswordLength, ComplexityEnabled, LockoutThreshold, MaxPasswordAge, AppliesTo)
    Save-CERRaw -Name 'passwordpolicy' -Object ([ordered]@{ Default = ($pp | Select-Object MinPasswordLength, ComplexityEnabled, LockoutThreshold, LockoutDuration, LockoutObservationWindow, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled); FineGrained = $fg })
    $flag = if ($pp.MinPasswordLength -lt 12 -or -not $pp.ComplexityEnabled -or $pp.LockoutThreshold -eq 0 -or $pp.ReversibleEncryptionEnabled) { 'Attention' } else { 'OK' }
    $f5 = @()
    if ($pp.MinPasswordLength -lt 12) { $f5 += "Raise the minimum password length from $($pp.MinPasswordLength) to at least 14 and drop forced expiry, which is the modern guidance (ACSC and NIST both moved away from rotation)" }
    if (-not $pp.ComplexityEnabled) { $f5 += 'Turn complexity back on, or replace it with Entra Password Protection on-prem, which blocks the weak passwords complexity rules let through' }
    if ($pp.LockoutThreshold -eq 0) { $f5 += 'Set an account lockout threshold (10 attempts, 15-minute window is a workable balance) - with no threshold, on-prem accounts can be brute-forced indefinitely' }
    if ($pp.ReversibleEncryptionEnabled) { $f5 += 'Disable reversible encryption immediately - it stores passwords in a recoverable form, which is functionally plaintext' }
    if (-not $fg.Count) { $f5 += 'Consider a fine-grained password policy applying a longer minimum to the privileged accounts than to standard users' }
    $act = if ($f5.Count) { (($f5 -join '. ') + '.') } else { '' }
    Add-CEREvidence -Control 'IAM-11' -Flag $flag -Action $act -Evidence ("Default domain password policy: min length {0}, complexity {1}, history {2}, max age {3} days, lockout threshold {4}, reversible encryption {5}; fine-grained policies: {6} ({7})." -f $pp.MinPasswordLength, $pp.ComplexityEnabled, $pp.PasswordHistoryCount, $pp.MaxPasswordAge.Days, $pp.LockoutThreshold, $pp.ReversibleEncryptionEnabled, $fg.Count, (Join-CERList ($fg | ForEach-Object { "{0} (min {1})" -f $_.Name, $_.MinPasswordLength })))
}

# ---------------- GPOs
Invoke-CERSection -Collector $C -Section 'GroupPolicy' -Script {
    if (-not (Get-Module -ListAvailable GroupPolicy)) { Set-CERSectionResult -Status NotInstalled -Note 'GroupPolicy module (RSAT) not installed'; return }
    Import-Module GroupPolicy
    $gpos = @(Get-GPO -All @srvArg)
    $unlinked = @(); $keywords = @{}
    $kw = 'LAPS', 'AppLocker', 'Applocker', 'WDAC', 'Macro', 'Office', 'SMB', 'PowerShell', 'Logging', 'Audit', 'BitLocker', 'Firewall', 'RDP', 'Remote Desktop', 'Defender', 'ASR', 'Attack Surface', 'Edge', 'Chrome', 'Java', 'LLMNR', 'NTLM', 'Print', 'USB', 'Removable', 'Screen', 'Lock', 'Password', 'Tier', 'Protected Users', 'Credential Guard', 'WSUS', 'Update'
    if ($gpos.Count -le $MaxGpoReports) {
        foreach ($g in $gpos) {
            try { [xml]$x = Get-GPOReport -Guid $g.Id -ReportType Xml @srvArg; if (-not $x.GPO.LinksTo) { $unlinked += $g.DisplayName } } catch { }
        }
    }
    foreach ($k in $kw) { $hits = @($gpos | Where-Object { $_.DisplayName -match [regex]::Escape($k) } | ForEach-Object { $_.DisplayName }); if ($hits.Count) { $keywords[$k] = $hits } }
    Save-CERRaw -Name 'gpos' -Object ([ordered]@{ Count = $gpos.Count; Names = @($gpos | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime); Unlinked = $unlinked; KeywordHits = $keywords })
    $actGpo = if ($unlinked.Count) { "Review and remove the $($unlinked.Count) unlinked GPO(s) - $(Join-CERList $unlinked 5). Unlinked policies are dead weight that still confuse the next engineer reading the estate, and occasionally get relinked by accident. Record the GPO inventory and intent in the client's documentation set (DOC-06)." } else { 'Record the GPO inventory and what each policy is for in the client documentation - a list of names is not a design.' }
    Add-CEREvidence -Control 'DOC-06' -Flag Info -Action $actGpo -Evidence ("GPOs: {0} total, {1} unlinked ({2}). Hardening-related GPO names: {3}." -f $gpos.Count, $unlinked.Count, (Join-CERList $unlinked 5), (Join-CERList ($keywords.Keys | ForEach-Object { "{0}: {1}" -f $_, ($keywords[$_] -join '/') }) 12))
    foreach ($pair in @(@('LAPS', 'END-08'), @('AppLocker', 'END-09'), @('Macro', 'END-10'), @('PowerShell', 'END-11'), @('Attack Surface', 'END-11'), @('ASR', 'END-11'), @('Removable', 'END-15'), @('Print', 'END-15'), @('BitLocker', 'END-07'))) {
        if ($keywords[$pair[0]]) { Add-CEREvidence -Control $pair[1] -Flag Info -Action ("A GPO is named for this control, which is not the same as the setting being applied. Confirm the link scope and the effective setting on a real device (gpresult, or the endpoint host-check evidence on this control) before scoring it - a policy named '{0}' that is unlinked or scoped to an empty OU reads as coverage and provides none." -f $pair[0]) -Evidence ("GPO(s) named for '{0}': {1} (verify scope/link and effective settings with the host check)." -f $pair[0], ($keywords[$pair[0]] -join '; ')) }
    }
}

# ---------------- DNS / time
# DHCP moved out to collectors\Get-CERDhcp.ps1 in v1.2 - it now covers options, the DNS registration
# credential, audit logging and the database backup as well as scope utilisation and failover, which is
# more than belongs inside the AD collector. Run -Scope DHCP (it is part of OnPrem) for the other half
# of SRV-11; this section no longer reports on DHCP at all.
Invoke-CERSection -Collector $C -Section 'DnsTime' -Script {
    $pdc = $script:domain.PDCEmulator
    $dnsOk = Get-Module -ListAvailable DnsServer
    $dns = [ordered]@{}
    if ($dnsOk) {
        Import-Module DnsServer
        $sc = Get-DnsServerScavenging -ComputerName $pdc -ErrorAction SilentlyContinue
        $fw = Get-DnsServerForwarder -ComputerName $pdc -ErrorAction SilentlyContinue
        $zones = @(Get-DnsServerZone -ComputerName $pdc -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone })
        $aging = @(); foreach ($z in $zones) { $a = Get-DnsServerZoneAging -Name $z.ZoneName -ComputerName $pdc -ErrorAction SilentlyContinue; if ($a) { $aging += [pscustomobject]@{ Zone = $z.ZoneName; AgingEnabled = $a.AgingEnabled; ScavengeServers = @($a.ScavengeServers) } } }
        $dns = [ordered]@{ ScavengingState = $sc.ScavengingState; ScavengingInterval = "$($sc.ScavengingInterval)"; LastScavengeTime = $sc.LastScavengeTime; Forwarders = @($fw.IPAddress | ForEach-Object { "$_" }); UseRootHint = $fw.UseRootHint; Zones = $aging }
        $publicFwd = @($dns.Forwarders | Where-Object { $_ -match '^(8\.8\.|1\.1\.1\.|9\.9\.9\.|208\.67\.)' })
        $flag = if (-not $sc.ScavengingState) { 'Attention' } else { 'OK' }
        $f6 = @()
        if (-not $sc.ScavengingState) { $f6 += 'Enable DNS scavenging on the zone and on the server (7-day no-refresh, 7-day refresh is the usual pair), then let it run a full cycle. Without it, stale A records accumulate for years and eventually point at a reissued address - which shows up as intermittent connections to the wrong host' }
        $noAging = @($aging | Where-Object { -not $_.AgingEnabled })
        if ($noAging.Count) { $f6 += "Enable aging on the $($noAging.Count) primary zone(s) without it - $(Join-CERList ($noAging | ForEach-Object { $_.Zone }) 4) - or scavenging will not touch those records" }
        if ($publicFwd.Count) { $f6 += "Point the forwarders at a filtering resolver the client controls rather than the public ones in use ($(Join-CERList $publicFwd 3)). Public resolvers give no DNS-layer blocking, no logging you can query during an incident, and no way to prove what a host looked up" }
        $act = if ($f6.Count) { (($f6 -join '. ') + '.') } else { '' }
        Add-CEREvidence -Control 'SRV-11' -Flag $flag -Action $act -Evidence ("DNS ({0}): scavenging {1} (interval {2}, last {3}); aging enabled on {4}/{5} primary zones; forwarders: {6}{7}." -f $pdc, $(if ($sc.ScavengingState) { 'enabled' } else { 'DISABLED' }), $dns.ScavengingInterval, $sc.LastScavengeTime, @($aging | Where-Object AgingEnabled).Count, $aging.Count, (Join-CERList $dns.Forwarders), $(if ($publicFwd.Count) { ' (public resolvers - consider ISP/DNS-filtering design)' } else { '' }))
    } else { Add-CEREvidence -Control 'SRV-11' -Flag Unknown -Action 'Re-run this collector on a DC, or install the RSAT DNS Server Tools feature on the jump host, so DNS scavenging, aging and forwarders can be read. Until then SRV-11 is unevidenced rather than compliant.' -Evidence 'DnsServer module not available on this host - run on a DC or install RSAT DNS tools.' }
    $time = $null
    try { $time = Invoke-Command -ComputerName $pdc -ScriptBlock { [ordered]@{ Source = (w32tm /query /source); Status = (w32tm /query /status | Out-String); Type = ((w32tm /query /configuration | Select-String '^\s*Type:\s*(\S+)').Matches.Groups[1].Value) } } -ErrorAction Stop }
    catch { try { if ($env:COMPUTERNAME -ieq ($pdc -split '\.')[0]) { $time = [ordered]@{ Source = (w32tm /query /source); Status = (w32tm /query /status | Out-String); Type = ((w32tm /query /configuration | Select-String '^\s*Type:\s*(\S+)').Matches.Groups[1].Value) } } } catch { } }
    if ($time) {
        $flag = if ($time.Source -match 'Local CMOS|Free-running|VM IC') { 'Attention' } else { 'OK' }
        $act = if ($flag -eq 'Attention') { "Point the PDC emulator ($pdc) at an external NTP source and stop the hypervisor syncing its clock (w32tm /config /manualpeerlist:'<ntp> 0x8' /syncfromflags:MANUAL /reliable:YES /update, then disable time sync in the VM's integration services). It is currently taking time from '$($time.Source)', so the whole domain's clock drifts with one virtual machine. Kerberos rejects tickets more than five minutes out, so this surfaces as sporadic, unexplained authentication failures." } else { '' }
        Add-CEREvidence -Control 'SRV-11' -Flag $flag -Action $act -Evidence ("PDC emulator {0} time source: {1} (type {2}). Target: external NTP stratum on the PDC, domain hierarchy elsewhere; VM hosts must not overwrite." -f $pdc, $time.Source, $time.Type)
    } else { Add-CEREvidence -Control 'SRV-11' -Flag Unknown -Action ("Run 'w32tm /query /source' and 'w32tm /query /status' on {0} by hand, or open WinRM from the jump host, and record the result. Time is a silent dependency for Kerberos - it is worth confirming rather than assuming." -f $pdc) -Evidence ("Could not query time source on PDC {0} (WinRM). Run 'w32tm /query /source' there." -f $pdc) }
    Save-CERRaw -Name 'dnstime' -Object ([ordered]@{ Dns = $dns; Time = $time })
    # Say out loud that the DHCP half of SRV-11 comes from somewhere else now, so a standalone AD run does not
    # read as "DHCP is fine" when it simply was not looked at.
    if (-not (Get-CERRaw -Collector 'Dhcp' -Name 'scopes')) {
        Add-CEREvidence -Control 'SRV-11' -Flag Info -Action 'Run the DHCP collector (-Scope DHCP, or it comes with -Scope OnPrem) to cover scope utilisation, failover, option hygiene, the DNS registration credential, audit logging and the database backup. Without it the DHCP half of this control is unevidenced.' -Evidence 'DHCP evidence comes from the Dhcp collector, which has not run into this run folder. The AD collector covers DNS and time only.'
    }
}

# ---------------- Discovery from AD: Exchange, CAs, SQL (SPN), print servers, sites
Invoke-CERSection -Collector $C -Section 'ServiceDiscovery' -Script {
    $cfg = (Get-ADRootDSE @srvArg).configurationNamingContext
    $exch = @(Get-ADObject -SearchBase "CN=Microsoft Exchange,CN=Services,$cfg" -LDAPFilter '(objectClass=msExchExchangeServer)' -Properties serialNumber, msExchCurrentServerRoles, whenCreated @srvArg -ErrorAction SilentlyContinue | ForEach-Object {
        $ver = "$($_.serialNumber)"
        $sup = Get-CERExchangeSupport -Version $ver -CuOnly   # AD holds the CU version only, never the SU level
        [pscustomobject]@{ Name = $_.Name; Version = $ver; Family = $sup.Family; Supported = $sup.Supported; EndOfSupport = $sup.EndOfSupport; Roles = $_.msExchCurrentServerRoles; Created = $_.whenCreated } })
    $cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates @srvArg -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ CA = $_.Name; Host = $_.dNSHostName; Templates = @($_.certificateTemplates).Count } })
    $sqlHosts = @(Get-ADObject -LDAPFilter '(servicePrincipalName=MSSQLSvc/*)' -Properties servicePrincipalName @srvArg -ErrorAction SilentlyContinue | ForEach-Object { $_.servicePrincipalName | Where-Object { $_ -like 'MSSQLSvc/*' } | ForEach-Object { ($_ -replace '^MSSQLSvc/', '') -replace ':.*$', '' } } | Select-Object -Unique)
    $printServers = @(Get-ADObject -LDAPFilter '(objectClass=printQueue)' -Properties serverName @srvArg -ErrorAction SilentlyContinue | ForEach-Object { $_.serverName } | Select-Object -Unique)
    $sites = @(Get-ADReplicationSite -Filter * @srvArg | Select-Object -ExpandProperty Name); $subnets = @(Get-ADReplicationSubnet -Filter * @srvArg | Select-Object -ExpandProperty Name)
    Save-CERRaw -Name 'discovery' -Object ([ordered]@{ Exchange = $exch; CAs = $cas; SqlHosts = $sqlHosts; PrintServers = $printServers; Sites = $sites; Subnets = $subnets })
    if ($exch.Count) {
        $unsup = @($exch | Where-Object { $_.Supported -eq $false })
        $actEx = if ($unsup.Count) { "Run the ExchangeOnPrem collector against $(Join-CERList ($unsup | ForEach-Object { $_.Name }) 3) to get the true patch level, hybrid state and internet exposure before deciding anything - AD only shows the cumulative update, not the security updates. Then take the decision the client has been deferring: migrate to Exchange Server SE, or remove the server entirely if the only remaining job is recipient management." } else { 'Confirm with the ExchangeOnPrem collector whether this server still holds mailboxes or exists only for recipient management - the decommission path is completely different for each.' }
        Add-CEREvidence -Control 'M365-05' -Flag $(if ($unsup.Count) { 'Attention' } else { 'OK' }) -Action $actEx -Evidence ("On-prem Exchange servers in the AD configuration partition: {0}. Past end of support: {1}. AD holds the cumulative-update version only - run the ExchangeOnPrem collector on the server for the true build (security-update level), hybrid state, connectors, virtual directory exposure and Extended Protection." -f (Join-CERList ($exch | ForEach-Object { "{0} [{1}]" -f $_.Name, $_.Family })), (Join-CERList ($unsup | ForEach-Object { "{0} ({1}, EoS {2})" -f $_.Name, $_.Family, $_.EndOfSupport })))
    } else { Add-CEREvidence -Control 'M365-05' -Flag OK -Evidence 'No Exchange server objects in the AD configuration partition (no on-prem Exchange, or fully decommissioned).' }
    $actCa = if ($cas.Count) { "Run pkiview.msc on $(Join-CERList ($cas | ForEach-Object { $_.Host }) 3) and confirm every CRL and AIA location resolves and is current. An expired CRL fails authentication everywhere certificates are checked, all at once, and the cause is rarely obvious from the client side. Also check the CA host's own OS support status and that the CA certificate itself has more life left than the certificates it issues." } else { 'No enterprise CA is published in AD. If certificates are in use they come from a public CA or a standalone one - record which, and where the renewal calendar lives (SRV-10 needs an owner either way).' }
    Add-CEREvidence -Control 'SRV-10' -Flag Info -Action $actCa -Evidence ("Enterprise CAs published in AD: {0} ({1}). Check CRL/AIA validity with pkiview.msc / certutil -URL on the CA host." -f $cas.Count, (Join-CERList ($cas | ForEach-Object { "{0}@{1}" -f $_.CA, $_.Host })))
    Add-CEREvidence -Control 'SRV-09' -Flag Info -Action ('Cross-check these SQL hosts against the Servers collector for engine version and support status, and against the backup platform for application-aware SQL processing with log truncation. SQL 2014 and SQL 2016 are both out of support (9 Jul 2024 and 14 Jul 2026), so any instance found on those needs a migration plan or a documented ESU.') -Evidence ("Hosts advertising SQL SPNs (MSSQLSvc): {0} - {1}. Engine versions come from the Servers/host check (Roles.SqlInstances)." -f $sqlHosts.Count, (Join-CERList $sqlHosts 10))
    if ($printServers.Count) { Add-CEREvidence -Control 'SRV-12' -Flag Info -Action 'Confirm Point and Print restrictions are enforced by GPO on these print servers and their clients (RestrictDriverInstallationToAdministrators = 1). Unrestricted Point and Print lets a standard user install a driver as SYSTEM, which is the PrintNightmare class of issue and still the easiest local privilege escalation in most estates.' -Evidence ("Print servers with AD-published queues: {0}." -f (Join-CERList $printServers)) }
    Add-CEREvidence -Control 'NET-01' -Flag Info -Action ("Compare these {0} AD site(s) and {1} subnet(s) against the current network diagram and Netbox. Subnets missing from AD Sites and Services send clients to the wrong DC for authentication and Group Policy, which reads to the user as a slow logon at one office and nothing at all at the others." -f $sites.Count, $subnets.Count) -Evidence ("AD sites: {0} ({1}); subnets defined: {2}. Compare with the network diagram / Netbox." -f $sites.Count, (Join-CERList $sites 6), $subnets.Count)
}

# ---------------- DC legacy protocol settings (WinRM to each DC)
if (-not $SkipDcRemote) {
    Invoke-CERSection -Collector $C -Section 'DcProtocolSettings' -Script {
        $results = @(); $unreach = @()
        foreach ($d in $script:dcs) {
            try {
                $r = Invoke-Command -ComputerName $d.HostName -ErrorAction Stop -ScriptBlock {
                    function _r { param($p, $n) try { (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n } catch { $null } }
                    [ordered]@{ Name = $env:COMPUTERNAME; SMB1 = (Get-SmbServerConfiguration).EnableSMB1Protocol; SMBSigning = (Get-SmbServerConfiguration).RequireSecuritySignature; LDAPServerIntegrity = (_r 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LDAPServerIntegrity'); LdapEnforceChannelBinding = (_r 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' 'LdapEnforceChannelBinding'); LmCompatibilityLevel = (_r 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'); ADSyncService = [bool](Get-Service ADSync -ErrorAction SilentlyContinue); PrintSpooler = (Get-Service Spooler).Status.ToString(); TLS10Server = (_r 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' 'Enabled') }
                }
                $results += [pscustomobject]$r
            } catch { $unreach += $d.Name }
        }
        Save-CERRaw -Name 'dcsettings' -Object ([ordered]@{ Results = $results; Unreachable = $unreach })
        $smb1 = @($results | Where-Object { $_.SMB1 }); $ldapWeak = @($results | Where-Object { $_.LDAPServerIntegrity -ne 2 }); $cbtWeak = @($results | Where-Object { $_.LdapEnforceChannelBinding -ne 2 }); $ntlmWeak = @($results | Where-Object { $null -eq $_.LmCompatibilityLevel -or $_.LmCompatibilityLevel -lt 5 }); $spooler = @($results | Where-Object { $_.PrintSpooler -eq 'Running' })
        $flag = if ($smb1.Count -or $ldapWeak.Count -or $cbtWeak.Count -or $ntlmWeak.Count -or $spooler.Count) { 'Attention' } else { 'OK' }
        $f8 = @()
        if ($smb1.Count) { $f8 += "Remove the SMBv1 feature from $(Join-CERList ($smb1 | ForEach-Object { $_.Name }) 4) (Disable-WindowsOptionalFeature -FeatureName SMB1Protocol). Check for legacy scanners and NAS devices first, but SMBv1 on a DC is indefensible" }
        if ($ldapWeak.Count) { $f8 += "Require LDAP signing on $(Join-CERList ($ldapWeak | ForEach-Object { $_.Name }) 4) (LDAPServerIntegrity = 2, by GPO). Audit first with event 2889 to find the clients still binding without signing, then enforce" }
        if ($cbtWeak.Count) { $f8 += "Enforce LDAP channel binding (LdapEnforceChannelBinding = 2) on $(Join-CERList ($cbtWeak | ForEach-Object { $_.Name }) 4) - together with signing this closes the LDAP relay path that turns any authenticated foothold into domain compromise" }
        if ($ntlmWeak.Count) { $f8 += "Set LmCompatibilityLevel to 5 on $(Join-CERList ($ntlmWeak | ForEach-Object { $_.Name }) 4) so the DC refuses LM and NTLMv1" }
        if ($spooler.Count) { $f8 += "Stop and disable the Print Spooler on the domain controller(s) - $(Join-CERList ($spooler | ForEach-Object { $_.Name }) 4). A DC has no business printing, and the spooler is a recurring remote code execution surface" }
        $act = if ($f8.Count) { (($f8 -join '. ') + ' Each of these is a standard change - raise them as one RFC with a maintenance window and a documented rollback.') } else { '' }
        Add-CEREvidence -Control 'IAM-10' -Flag $flag -Action $act -Evidence ("DC protocol settings ({0}/{1} DCs reached): SMBv1 enabled on {2}; LDAP signing not required on {3}; LDAP channel binding not enforced on {4}; LmCompatibilityLevel < 5 on {5}; Print Spooler running on {6} ({7}). Unreachable: {8}." -f $results.Count, $script:dcs.Count, $smb1.Count, $ldapWeak.Count, $cbtWeak.Count, $ntlmWeak.Count, $spooler.Count, (Join-CERList ($spooler | ForEach-Object { $_.Name })), (Join-CERList $unreach))
        $adsync = @($results | Where-Object ADSyncService); if ($adsync.Count) { Add-CEREvidence -Control 'IAM-01' -Flag Info -Action ("Move Entra Connect off the domain controller onto a dedicated member server. On a DC it cannot be patched or rebooted independently of authentication, and the sync service account's rights sit on a tier-0 host. Plan it as a staging-mode migration so the cutover is a switch rather than a rebuild. Affected: {0}." -f (Join-CERList ($adsync | ForEach-Object { $_.Name }))) -Evidence ("ADSync (Entra Connect) service found on DC(s): {0} - running Entra Connect on a DC is not recommended." -f (Join-CERList ($adsync | ForEach-Object { $_.Name }))) }
    }
}

Complete-CERCollector

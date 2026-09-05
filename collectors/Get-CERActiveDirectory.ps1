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
    Add-CEREvidence -Control 'IAM-10' -Flag Info -Evidence ("Forest {0} (mode {1}), domain {2} (mode {3}); FSMO: schema={4}, naming={5}, PDC={6}, RID={7}, infra={8}; trusts: {9}." -f $script:forest.Name, $script:forest.ForestMode, $script:domain.DNSRoot, $script:domain.DomainMode, $script:forest.SchemaMaster, $script:forest.DomainNamingMaster, $script:domain.PDCEmulator, $script:domain.RIDMaster, $script:domain.InfrastructureMaster, (Join-CERList ($trusts | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Direction })))
}
Invoke-CERSection -Collector $C -Section 'DomainControllers' -Script {
    $script:dcs = @(Get-ADDomainController -Filter * @srvArg | Select-Object Name, HostName, IPv4Address, OperatingSystem, OperatingSystemVersion, Site, IsGlobalCatalog, IsReadOnly, Enabled)
    $rows = foreach ($d in $script:dcs) { $s = Get-CERWindowsSupport -Caption $d.OperatingSystem -Version $d.OperatingSystemVersion -ProductType 2; [pscustomobject]@{ Name = $d.Name; OS = $d.OperatingSystem; Family = $s.Family; Supported = $s.Supported; EndOfSupport = $s.EndOfSupport; Site = $d.Site; GC = $d.IsGlobalCatalog; RODC = $d.IsReadOnly; IP = $d.IPv4Address } }
    Save-CERRaw -Name 'dcs' -Object $rows
    $unsup = @($rows | Where-Object { -not $_.Supported })
    $soon = @($rows | Where-Object { $_.Supported -and $_.EndOfSupport })
    $flag = if ($unsup.Count) { 'Attention' } elseif ($soon.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-10' -Flag $flag -Evidence ("{0} DCs ({1} RODC): {2}. Unsupported OS: {3}. Ending soon: {4}." -f $rows.Count, @($rows | Where-Object RODC).Count, (Join-CERList ($rows | ForEach-Object { "{0} [{1}]" -f $_.Name, $_.Family })), (Join-CERList ($unsup | ForEach-Object { $_.Name })), (Join-CERList ($soon | ForEach-Object { "{0} ({1})" -f $_.Name, $_.EndOfSupport })))
    Add-CEREvidence -Control 'SRV-02' -Flag $flag -Evidence ("Domain controllers: {0}" -f (Join-CERList ($rows | ForEach-Object { "{0}={1}" -f $_.Name, $_.Family })))
}
Invoke-CERSection -Collector $C -Section 'Replication' -Script {
    $partners = @(Get-ADReplicationPartnerMetadata -Target $script:domain.DNSRoot -Scope Domain -ErrorAction Stop | Select-Object Server, Partner, LastReplicationSuccess, LastReplicationAttempt, ConsecutiveReplicationFailures, LastReplicationResult)
    $fail = @(Get-ADReplicationFailure -Target $script:domain.DNSRoot -Scope Domain -ErrorAction SilentlyContinue | Select-Object Server, Partner, FailureCount, FirstFailureTime, LastError)
    $rep = $null; try { $rep = repadmin /replsummary 2>&1 | Out-String } catch { }
    Save-CERRaw -Name 'replication' -Object ([ordered]@{ Partners = $partners; Failures = $fail; ReplSummary = $rep })
    $stale = @($partners | Where-Object { $_.LastReplicationSuccess -and ((Get-CERAgeDays $_.LastReplicationSuccess) -gt 1) })
    $flag = if ($fail.Count -or $stale.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-10' -Flag $flag -Evidence ("Replication: {0} partner links, {1} with failures, {2} with last success > 24 h; consecutive failures max {3}." -f $partners.Count, $fail.Count, $stale.Count, (($partners | Measure-Object ConsecutiveReplicationFailures -Maximum).Maximum))
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
    Add-CEREvidence -Control 'IAM-10' -Flag $flag -Evidence ("AD Recycle Bin: {0}; KRBTGT password age: {1} days (target < 180, rotate twice); SYSVOL replication: {2}; tombstone lifetime: {3}." -f $(if ($rbOn) { 'enabled' } else { 'NOT enabled' }), $krbAge, $sysvol, $ts)
    if ($backup) {
        $lines = @($backup -split "`r?`n" | Where-Object { $_ -match '\d{4}-\d{2}-\d{2}' })
        Add-CEREvidence -Control 'BDR-06' -Flag Info -Evidence ("repadmin /showbackup (last AD system-state backup per partition): {0}" -f (Join-CERList ($lines | ForEach-Object { $_.Trim() }) 4))
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
    Add-CEREvidence -Control 'SRV-05' -Flag $flag -Evidence ("Domain Admins: {0} (target <= 5), Enterprise Admins: {1}, Schema Admins: {2}, Account Operators: {3}, Backup Operators: {4}; Protected Users group: {5} members; enabled adminCount=1 users: {6}." -f $da, $ea, ($rows | Where-Object Group -eq 'Schema Admins').Count, ($rows | Where-Object Group -eq 'Account Operators').Count, ($rows | Where-Object Group -eq 'Backup Operators').Count, $protected.Count, $adminCountUsers)
    Add-CEREvidence -Control 'SEC-08' -Flag $flag -Evidence ("Privileged AD accounts: {0} total; {1} with a mailbox (not dedicated admin accounts): {2}; {3} not logged on for > 45 days (E8 ML2 disable): {4}; {5} with password never expires: {6}." -f $privUsers.Count, $withMail.Count, (Join-CERList ($withMail | ForEach-Object { $_.Sam })), $stalePriv.Count, (Join-CERList ($stalePriv | ForEach-Object { $_.Sam })), $pne.Count, (Join-CERList ($pne | ForEach-Object { $_.Sam })))
    Add-CEREvidence -Control 'IAM-05' -Flag Info -Evidence ("On-prem Domain Admins ({0}): {1}. Cross-check against Entra Global Administrators (synced admins should not hold both)." -f $da, (Join-CERList (($rows | Where-Object Group -eq 'Domain Admins').Members)))
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
    Add-CEREvidence -Control 'IAM-09' -Flag $flagStale -Evidence ("AD users: {0} total, {1} enabled; {2} enabled users stale > {3} days ({4}); {5} enabled computers stale (of {6}); password-never-expires: {7}; password-not-required: {8}; password older than 1 year: {9}; service-account-like accounts: {10}; gMSA: {11}." -f $users.Count, $enabled.Count, $stale.Count, $StaleDays, (ConvertTo-CERPct $stale.Count $enabled.Count), $compStale.Count, $compEnabled.Count, $pne.Count, $pnr.Count, $oldPw.Count, $svcLike.Count, $gmsa.Count)
    $flagKerb = if ($spn.Count -or $asrep.Count -or $des.Count -or $unconstrainedComp.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-10' -Flag $flagKerb -Evidence ("Kerberos hygiene: {0} user accounts with SPNs (kerberoastable): {1}; {2} without pre-auth (AS-REP roastable): {3}; {4} DES-only; {5} with SIDHistory; unconstrained delegation on {6} non-DC computers: {7}." -f $spn.Count, (Join-CERList ($spn | ForEach-Object { $_.SamAccountName }) 6), $asrep.Count, (Join-CERList ($asrep | ForEach-Object { $_.SamAccountName }) 6), $des.Count, $sidh.Count, $unconstrainedComp.Count, (Join-CERList ($unconstrainedComp | ForEach-Object { $_.Name }) 6))
    $lapsFlag = if ($workstations.Count -and ($lapsWs.Count / $workstations.Count) -ge 0.95) { 'OK' } elseif ($winLapsSchema -or $legacyLapsSchema) { 'Attention' } else { 'Attention' }
    Add-CEREvidence -Control 'IAM-11' -Flag $lapsFlag -Evidence ("LAPS (AD-backed): schema Windows LAPS={0}, legacy LAPS={1}; workstations with a LAPS password attribute: {2}/{3} ({4}); member servers: {5}/{6}. (Entra-backed LAPS is reported by the Entra collector.)" -f $winLapsSchema, $legacyLapsSchema, $lapsWs.Count, $workstations.Count, (ConvertTo-CERPct $lapsWs.Count $workstations.Count), $lapsSrv.Count, $servers.Count)
    Add-CEREvidence -Control 'END-08' -Flag $lapsFlag -Evidence ("AD LAPS coverage on active workstations: {0}/{1} ({2})." -f $lapsWs.Count, $workstations.Count, (ConvertTo-CERPct $lapsWs.Count $workstations.Count))
    $unsupWs = @($osRows | Where-Object { -not $_.Supported -and $_.OS -notmatch 'Server' }); $unsupSrv = @($osRows | Where-Object { -not $_.Supported -and $_.OS -match 'Server' }); $soonSrv = @($osRows | Where-Object { $_.Supported -and $_.EndOfSupport -and $_.OS -match 'Server' })
    Add-CEREvidence -Control 'END-02' -Flag $(if ($unsupWs.Count) { 'Attention' } else { 'OK' }) -Evidence ("AD computer objects active in last 60 days: {0} workstations. OS mix: {1}. Unsupported: {2}." -f $workstations.Count, (Join-CERList (($osRows | Where-Object { $_.OS -notmatch 'Server' }) | ForEach-Object { "{0}={1}" -f $_.Family, $_.Count })), (Join-CERList ($unsupWs | ForEach-Object { "{0}={1}" -f $_.OS, $_.Count })))
    Add-CEREvidence -Control 'SRV-02' -Flag $(if ($unsupSrv.Count) { 'Attention' } elseif ($soonSrv.Count) { 'Attention' } else { 'OK' }) -Evidence ("AD server objects active in last 60 days: {0}. OS mix: {1}. Unsupported: {2}. Ending within 12 months: {3}." -f $servers.Count, (Join-CERList (($osRows | Where-Object { $_.OS -match 'Server' }) | ForEach-Object { "{0}={1}" -f $_.Family, $_.Count })), (Join-CERList ($unsupSrv | ForEach-Object { "{0}={1}" -f $_.OS, $_.Count })), (Join-CERList ($soonSrv | ForEach-Object { "{0}={1} ({2})" -f $_.Family, $_.Count, $_.EndOfSupport })))
    if ($msol.Count) { Add-CEREvidence -Control 'IAM-01' -Flag Info -Evidence ("Entra Connect service accounts in AD: {0}" -f (Join-CERList ($msol | ForEach-Object { "{0} [{1}]" -f $_.SamAccountName, $_.Description }) 3)) }
}

# ---------------- Password policy
Invoke-CERSection -Collector $C -Section 'PasswordPolicy' -Script {
    $pp = Get-ADDefaultDomainPasswordPolicy @srvArg
    $fg = @(Get-ADFineGrainedPasswordPolicy -Filter * @srvArg | Select-Object Name, Precedence, MinPasswordLength, ComplexityEnabled, LockoutThreshold, MaxPasswordAge, AppliesTo)
    Save-CERRaw -Name 'passwordpolicy' -Object ([ordered]@{ Default = ($pp | Select-Object MinPasswordLength, ComplexityEnabled, LockoutThreshold, LockoutDuration, LockoutObservationWindow, MaxPasswordAge, MinPasswordAge, PasswordHistoryCount, ReversibleEncryptionEnabled); FineGrained = $fg })
    $flag = if ($pp.MinPasswordLength -lt 12 -or -not $pp.ComplexityEnabled -or $pp.LockoutThreshold -eq 0 -or $pp.ReversibleEncryptionEnabled) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-11' -Flag $flag -Evidence ("Default domain password policy: min length {0}, complexity {1}, history {2}, max age {3} days, lockout threshold {4}, reversible encryption {5}; fine-grained policies: {6} ({7})." -f $pp.MinPasswordLength, $pp.ComplexityEnabled, $pp.PasswordHistoryCount, $pp.MaxPasswordAge.Days, $pp.LockoutThreshold, $pp.ReversibleEncryptionEnabled, $fg.Count, (Join-CERList ($fg | ForEach-Object { "{0} (min {1})" -f $_.Name, $_.MinPasswordLength })))
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
    Add-CEREvidence -Control 'DOC-06' -Flag Info -Evidence ("GPOs: {0} total, {1} unlinked ({2}). Hardening-related GPO names: {3}." -f $gpos.Count, $unlinked.Count, (Join-CERList $unlinked 5), (Join-CERList ($keywords.Keys | ForEach-Object { "{0}: {1}" -f $_, ($keywords[$_] -join '/') }) 12))
    foreach ($pair in @(@('LAPS', 'END-08'), @('AppLocker', 'END-09'), @('Macro', 'END-10'), @('PowerShell', 'END-11'), @('Attack Surface', 'END-11'), @('ASR', 'END-11'), @('Removable', 'END-15'), @('Print', 'END-15'), @('BitLocker', 'END-07'))) {
        if ($keywords[$pair[0]]) { Add-CEREvidence -Control $pair[1] -Flag Info -Evidence ("GPO(s) named for '{0}': {1} (verify scope/link and effective settings with the host check)." -f $pair[0], ($keywords[$pair[0]] -join '; ')) }
    }
}

# ---------------- DNS / DHCP / time
Invoke-CERSection -Collector $C -Section 'DnsDhcpTime' -Script {
    $pdc = $script:domain.PDCEmulator
    $dnsOk = Get-Module -ListAvailable DnsServer
    $dhcpOk = Get-Module -ListAvailable DhcpServer
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
        Add-CEREvidence -Control 'SRV-11' -Flag $flag -Evidence ("DNS ({0}): scavenging {1} (interval {2}, last {3}); aging enabled on {4}/{5} primary zones; forwarders: {6}{7}." -f $pdc, $(if ($sc.ScavengingState) { 'enabled' } else { 'DISABLED' }), $dns.ScavengingInterval, $sc.LastScavengeTime, @($aging | Where-Object AgingEnabled).Count, $aging.Count, (Join-CERList $dns.Forwarders), $(if ($publicFwd.Count) { ' (public resolvers - consider ISP/DNS-filtering design)' } else { '' }))
    } else { Add-CEREvidence -Control 'SRV-11' -Flag Unknown -Evidence 'DnsServer module not available on this host - run on a DC or install RSAT DNS tools.' }
    $dhcp = @()
    if ($dhcpOk) {
        Import-Module DhcpServer
        $servers = @(Get-DhcpServerInDC -ErrorAction SilentlyContinue)
        foreach ($s in $servers) {
            try {
                $scopes = @(Get-DhcpServerv4Scope -ComputerName $s.DnsName -ErrorAction Stop)
                $stats = @(Get-DhcpServerv4ScopeStatistics -ComputerName $s.DnsName -ErrorAction SilentlyContinue)
                $fo = @(Get-DhcpServerv4Failover -ComputerName $s.DnsName -ErrorAction SilentlyContinue)
                foreach ($sc2 in $scopes) { $st = $stats | Where-Object { $_.ScopeId -eq $sc2.ScopeId }; $dhcp += [pscustomobject]@{ Server = $s.DnsName; Scope = "$($sc2.ScopeId)"; Name = $sc2.Name; State = "$($sc2.State)"; PercentInUse = $(if ($st) { [math]::Round($st.PercentageInUse, 1) } else { $null }); Failover = [bool]($fo | Where-Object { $_.ScopeId -contains $sc2.ScopeId }); LeaseDuration = "$($sc2.LeaseDuration)" } }
            } catch { $dhcp += [pscustomobject]@{ Server = $s.DnsName; Scope = 'n/a'; Name = "unreachable: $($_.Exception.Message)"; State = ''; PercentInUse = $null; Failover = $null; LeaseDuration = '' } }
        }
        $hot = @($dhcp | Where-Object { $_.PercentInUse -ge 80 }); $noFo = @($dhcp | Where-Object { $_.State -eq 'Active' -and -not $_.Failover })
        Add-CEREvidence -Control 'SRV-11' -Flag $(if ($hot.Count -or ($noFo.Count -and $dhcp.Count)) { 'Attention' } else { 'OK' }) -Evidence ("DHCP: {0} authorised servers, {1} scopes; {2} scopes >= 80% used ({3}); {4} active scopes without failover." -f $servers.Count, $dhcp.Count, $hot.Count, (Join-CERList ($hot | ForEach-Object { "{0} {1}%" -f $_.Scope, $_.PercentInUse })), $noFo.Count)
    }
    $time = $null
    try { $time = Invoke-Command -ComputerName $pdc -ScriptBlock { [ordered]@{ Source = (w32tm /query /source); Status = (w32tm /query /status | Out-String); Type = ((w32tm /query /configuration | Select-String '^\s*Type:\s*(\S+)').Matches.Groups[1].Value) } } -ErrorAction Stop }
    catch { try { if ($env:COMPUTERNAME -ieq ($pdc -split '\.')[0]) { $time = [ordered]@{ Source = (w32tm /query /source); Status = (w32tm /query /status | Out-String); Type = ((w32tm /query /configuration | Select-String '^\s*Type:\s*(\S+)').Matches.Groups[1].Value) } } } catch { } }
    if ($time) {
        $flag = if ($time.Source -match 'Local CMOS|Free-running|VM IC') { 'Attention' } else { 'OK' }
        Add-CEREvidence -Control 'SRV-11' -Flag $flag -Evidence ("PDC emulator {0} time source: {1} (type {2}). Target: external NTP stratum on the PDC, domain hierarchy elsewhere; VM hosts must not overwrite." -f $pdc, $time.Source, $time.Type)
    } else { Add-CEREvidence -Control 'SRV-11' -Flag Unknown -Evidence ("Could not query time source on PDC {0} (WinRM). Run 'w32tm /query /source' there." -f $pdc) }
    Save-CERRaw -Name 'dnsdhcptime' -Object ([ordered]@{ Dns = $dns; Dhcp = $dhcp; Time = $time })
}

# ---------------- Discovery from AD: Exchange, CAs, SQL (SPN), print servers, sites
Invoke-CERSection -Collector $C -Section 'ServiceDiscovery' -Script {
    $cfg = (Get-ADRootDSE @srvArg).configurationNamingContext
    $exch = @(Get-ADObject -SearchBase "CN=Microsoft Exchange,CN=Services,$cfg" -LDAPFilter '(objectClass=msExchExchangeServer)' -Properties serialNumber, msExchCurrentServerRoles, whenCreated @srvArg -ErrorAction SilentlyContinue | ForEach-Object {
        $ver = "$($_.serialNumber)"; $fam = if ($ver -match 'Version 15\.2 \(Build (\d+)') { if ([int]$Matches[1] -ge 2562) { 'Exchange Server SE' } else { 'Exchange 2019' } } elseif ($ver -match 'Version 15\.1') { 'Exchange 2016' } elseif ($ver -match 'Version 15\.0') { 'Exchange 2013' } elseif ($ver -match 'Version 14') { 'Exchange 2010' } else { $ver }
        [pscustomobject]@{ Name = $_.Name; Version = $ver; Family = $fam; Roles = $_.msExchCurrentServerRoles; Created = $_.whenCreated } })
    $cas = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$cfg" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties dNSHostName, certificateTemplates @srvArg -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ CA = $_.Name; Host = $_.dNSHostName; Templates = @($_.certificateTemplates).Count } })
    $sqlHosts = @(Get-ADObject -LDAPFilter '(servicePrincipalName=MSSQLSvc/*)' -Properties servicePrincipalName @srvArg -ErrorAction SilentlyContinue | ForEach-Object { $_.servicePrincipalName | Where-Object { $_ -like 'MSSQLSvc/*' } | ForEach-Object { ($_ -replace '^MSSQLSvc/', '') -replace ':.*$', '' } } | Select-Object -Unique)
    $printServers = @(Get-ADObject -LDAPFilter '(objectClass=printQueue)' -Properties serverName @srvArg -ErrorAction SilentlyContinue | ForEach-Object { $_.serverName } | Select-Object -Unique)
    $sites = @(Get-ADReplicationSite -Filter * @srvArg | Select-Object -ExpandProperty Name); $subnets = @(Get-ADReplicationSubnet -Filter * @srvArg | Select-Object -ExpandProperty Name)
    Save-CERRaw -Name 'discovery' -Object ([ordered]@{ Exchange = $exch; CAs = $cas; SqlHosts = $sqlHosts; PrintServers = $printServers; Sites = $sites; Subnets = $subnets })
    if ($exch.Count) {
        $unsup = @($exch | Where-Object { $_.Family -in 'Exchange 2010', 'Exchange 2013', 'Exchange 2016', 'Exchange 2019' })
        Add-CEREvidence -Control 'M365-05' -Flag $(if ($unsup.Count) { 'Attention' } else { 'OK' }) -Evidence ("On-prem Exchange servers in AD: {0}. Unsupported (2016/2019 EoS 14 Oct 2025): {1}." -f (Join-CERList ($exch | ForEach-Object { "{0} [{1}]" -f $_.Name, $_.Family })), (Join-CERList ($unsup | ForEach-Object { $_.Name })))
    } else { Add-CEREvidence -Control 'M365-05' -Flag OK -Evidence 'No Exchange server objects in the AD configuration partition (no on-prem Exchange, or fully decommissioned).' }
    Add-CEREvidence -Control 'SRV-10' -Flag Info -Evidence ("Enterprise CAs published in AD: {0} ({1}). Check CRL/AIA validity with pkiview.msc / certutil -URL on the CA host." -f $cas.Count, (Join-CERList ($cas | ForEach-Object { "{0}@{1}" -f $_.CA, $_.Host })))
    Add-CEREvidence -Control 'SRV-09' -Flag Info -Evidence ("Hosts advertising SQL SPNs (MSSQLSvc): {0} - {1}. Engine versions come from the Servers/host check (Roles.SqlInstances)." -f $sqlHosts.Count, (Join-CERList $sqlHosts 10))
    Add-CEREvidence -Control 'SRV-12' -Flag Info -Evidence ("Print servers with AD-published queues: {0}." -f (Join-CERList $printServers))
    Add-CEREvidence -Control 'NET-01' -Flag Info -Evidence ("AD sites: {0} ({1}); subnets defined: {2}. Compare with the network diagram / Netbox." -f $sites.Count, (Join-CERList $sites 6), $subnets.Count)
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
        Add-CEREvidence -Control 'IAM-10' -Flag $flag -Evidence ("DC protocol settings ({0}/{1} DCs reached): SMBv1 enabled on {2}; LDAP signing not required on {3}; LDAP channel binding not enforced on {4}; LmCompatibilityLevel < 5 on {5}; Print Spooler running on {6} ({7}). Unreachable: {8}." -f $results.Count, $script:dcs.Count, $smb1.Count, $ldapWeak.Count, $cbtWeak.Count, $ntlmWeak.Count, $spooler.Count, (Join-CERList ($spooler | ForEach-Object { $_.Name })), (Join-CERList $unreach))
        $adsync = @($results | Where-Object ADSyncService); if ($adsync.Count) { Add-CEREvidence -Control 'IAM-01' -Flag Info -Evidence ("ADSync (Entra Connect) service found on DC(s): {0} - running Entra Connect on a DC is not recommended." -f (Join-CERList ($adsync | ForEach-Object { $_.Name }))) }
    }
}

Complete-CERCollector

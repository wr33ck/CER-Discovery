#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: Windows DHCP - authorised servers, scope utilisation and failover, option hygiene,
  dynamic DNS registration, audit logging and database backup. Feeds SRV-11 and NET-01.

.DESCRIPTION
  Run on a domain-joined jump host or a DC with the RSAT DhcpServer module. Every server authorised in AD is
  queried over the module's own CIM/WinRM path; unreachable servers are reported as a finding, not an error.

  Read-only: Get-Dhcp* only. Nothing is written to any DHCP server.

  Before v1.2 a single DHCP evidence line lived inside the AD collector (scope utilisation and failover only).
  That line now lives here, with the option, DNS-registration, audit and database checks it was missing. The AD
  collector keeps DNS and time and points at this collector for DHCP.

.EXAMPLE
  .\Get-CERDhcp.ps1 -Client C-003 -RunId 20260905-0900
  .\Get-CERDhcp.ps1 -Client C-003 -RunId 20260905-0900 -ComputerName dhcp01.contoso.local,dhcp02.contoso.local
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string[]]$ComputerName,
    [int]$UtilisationThreshold = 80,
    [int]$MaxScopes = 500
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Dhcp' -RunId $RunId
$C = 'Dhcp'
if (-not (Test-CERModule -Name DhcpServer -Collector $C)) {
    Add-CEREvidence -Control 'SRV-11' -Flag Unknown -Action 'Re-run this collector on a DC or a jump host with the RSAT DHCP Server Tools feature installed (Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0). Until then the DHCP half of SRV-11 is unevidenced rather than compliant.' -Evidence 'DhcpServer module not available on this host - run on a DC or install the RSAT DHCP tools.'
    Complete-CERCollector; return
}
Import-Module DhcpServer -ErrorAction Stop -WarningAction SilentlyContinue

# ---------------- which servers
$script:servers = @()
Invoke-CERSection -Collector $C -Section 'Servers' -Script {
    $inDc = @()
    try { $inDc = @(Get-DhcpServerInDC -ErrorAction Stop) } catch { Write-CERLog ("Get-DhcpServerInDC failed: {0}" -f $_.Exception.Message) 'WARN' }
    $names = @()
    if ($ComputerName) { $names = @($ComputerName) } else { $names = @($inDc | ForEach-Object { $_.DnsName }) }
    $names = @($names | Where-Object { $_ } | Select-Object -Unique)
    $rows = @()
    foreach ($n in $names) {
        $row = [ordered]@{ Server = $n; Reachable = $false; Version = ''; IsDomainController = $null; Error = '' }
        try {
            $v = Get-DhcpServerVersion -ComputerName $n -ErrorAction Stop
            $row.Reachable = $true
            $row.Version = ("{0}.{1}" -f $v.MajorVersion, $v.MinorVersion)
        } catch { $row.Error = ($_.Exception.Message -replace '\s+', ' ') }
        # A DHCP server that is also a DC is the setup that makes the DNS-registration credential mandatory.
        try {
            $short = ($n -split '\.')[0]
            $dc = Get-ADDomainController -Identity $short -ErrorAction Stop
            if ($dc) { $row.IsDomainController = $true }
        } catch { if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) { $row.IsDomainController = $false } }
        $rows += [pscustomobject]$row
    }
    $script:servers = @($rows | Where-Object { $_.Reachable })
    Save-CERRaw -Name 'servers' -Object ([ordered]@{ AuthorisedInDC = $inDc; Queried = $rows })
    $unreach = @($rows | Where-Object { -not $_.Reachable })
    $unauth = @()
    if ($ComputerName -and $inDc.Count) { $unauth = @($ComputerName | Where-Object { $n = $_; -not ($inDc | Where-Object { $_.DnsName -eq $n }) }) }
    if ($rows.Count -eq 0) {
        Set-CERSectionResult -Status 'Partial' -Note 'No DHCP servers authorised in AD and none supplied'
        Add-CEREvidence -Control 'SRV-11' -Flag Info -Action 'Confirm where DHCP actually lives. No authorised Windows DHCP server usually means the firewall, a router or an appliance is serving addresses - record which, and who owns its scopes, because that is where scope exhaustion and DNS-registration problems will be diagnosed from.' -Evidence 'No DHCP servers authorised in Active Directory and none supplied with -ComputerName. DHCP is served by something other than Windows (firewall/router/appliance) or not in use.'
    } else {
        $act = @()
        if ($unreach.Count) { $act += ("Get WinRM/RPC access to the {0} unreachable server(s) - {1} - and re-run. An authorised DHCP server nobody can query is also one nobody is monitoring" -f $unreach.Count, (Join-CERList ($unreach | ForEach-Object { $_.Server }) 4)) }
        if ($unauth.Count) { $act += ("Authorise {0} in AD, or confirm it is a deliberate standalone. An unauthorised Windows DHCP server will not serve leases at all, which presents as one site with no addresses" -f (Join-CERList $unauth 3)) }
        Add-CEREvidence -Control 'SRV-11' -Flag $(if ($unreach.Count -or $unauth.Count) { 'Attention' } else { 'Info' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'Record the DHCP server names, their roles and the failover relationship in the client documentation - DHCP is the service nobody documents until the day it stops.' }) -Evidence ("DHCP servers authorised in AD: {0} ({1}); queried {2}, reachable {3}, unreachable {4} ({5}). Also a domain controller: {6}." -f $inDc.Count, (Join-CERList ($inDc | ForEach-Object { $_.DnsName }) 6), $rows.Count, $script:servers.Count, $unreach.Count, (Join-CERList ($unreach | ForEach-Object { $_.Server }) 4), (Join-CERList ($rows | Where-Object { $_.IsDomainController } | ForEach-Object { $_.Server }) 4))
    }
}

# ---------------- scopes, utilisation, failover
$script:scopes = @()
Invoke-CERSection -Collector $C -Section 'Scopes' -Script {
    if (-not $script:servers.Count) { Set-CERSectionResult -Status 'Skipped' -Note 'no reachable DHCP server'; return }
    $rows = @(); $failovers = @(); $superscopes = @()
    foreach ($s in $script:servers) {
        $n = $s.Server
        $fo = @(); try { $fo = @(Get-DhcpServerv4Failover -ComputerName $n -ErrorAction SilentlyContinue) } catch { }
        foreach ($f in $fo) { $failovers += [pscustomobject]@{ Server = $n; Name = $f.Name; Mode = "$($f.Mode)"; Partner = $f.PartnerServer; State = "$($f.State)"; ScopeCount = @($f.ScopeId).Count; LoadBalancePercent = $f.LoadBalancePercent; MaxClientLeadTime = "$($f.MaxClientLeadTime)"; AutoStateTransition = $f.AutoStateTransition; SharedSecretSet = [bool]$f.SharedSecret } }
        try { $superscopes += @(Get-DhcpServerv4Superscope -ComputerName $n -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Server = $n; Name = $_.SuperscopeName; Scopes = @($_.ScopeId).Count } }) } catch { }
        $sc = @(); try { $sc = @(Get-DhcpServerv4Scope -ComputerName $n -ErrorAction Stop | Select-Object -First $MaxScopes) } catch { Write-CERLog ("Scopes on {0}: {1}" -f $n, $_.Exception.Message) 'WARN'; continue }
        $stats = @(); try { $stats = @(Get-DhcpServerv4ScopeStatistics -ComputerName $n -ErrorAction SilentlyContinue) } catch { }
        foreach ($x in $sc) {
            $st = $stats | Where-Object { "$($_.ScopeId)" -eq "$($x.ScopeId)" } | Select-Object -First 1
            $inFo = @($fo | Where-Object { @($_.ScopeId | ForEach-Object { "$_" }) -contains "$($x.ScopeId)" })
            $rsv = $null; try { $rsv = @(Get-DhcpServerv4Reservation -ComputerName $n -ScopeId $x.ScopeId -ErrorAction SilentlyContinue).Count } catch { }
            $rows += [pscustomobject]@{
                Server = $n; ScopeId = "$($x.ScopeId)"; Name = $x.Name; State = "$($x.State)"
                StartRange = "$($x.StartRange)"; EndRange = "$($x.EndRange)"; SubnetMask = "$($x.SubnetMask)"
                LeaseDuration = "$($x.LeaseDuration)"; LeaseHours = $(if ($x.LeaseDuration) { [math]::Round(([timespan]$x.LeaseDuration).TotalHours, 1) } else { $null })
                PercentInUse = $(if ($st) { [math]::Round($st.PercentageInUse, 1) } else { $null })
                Free = $(if ($st) { $st.Free } else { $null }); InUse = $(if ($st) { $st.InUse } else { $null })
                Reservations = $rsv
                Failover = [bool]$inFo.Count; FailoverName = (@($inFo | ForEach-Object { $_.Name }) -join ',')
            }
        }
    }
    $script:scopes = $rows
    Save-CERRaw -Name 'scopes' -Object ([ordered]@{ Scopes = $rows; Failover = $failovers; Superscopes = $superscopes })
    $active = @($rows | Where-Object { $_.State -eq 'Active' })
    $hot = @($active | Where-Object { $null -ne $_.PercentInUse -and $_.PercentInUse -ge $UtilisationThreshold })
    $noFo = @($active | Where-Object { -not $_.Failover })
    $badFo = @($failovers | Where-Object { "$($_.State)" -and "$($_.State)" -notmatch 'Normal' })
    $longLease = @($active | Where-Object { $null -ne $_.LeaseHours -and $_.LeaseHours -gt 192 })
    $act = @()
    if ($hot.Count) { $act += ("Extend or re-scope the {0} range(s) at or above {1}% - {2}. Scope exhaustion presents as random devices failing to get an address, always on the busiest morning" -f $hot.Count, $UtilisationThreshold, (Join-CERList ($hot | ForEach-Object { '{0} at {1}%' -f $_.ScopeId, $_.PercentInUse }) 4)) }
    if ($noFo.Count -and $script:servers.Count -gt 1) { $act += ("Add the {0} active scope(s) without failover to a load-balance relationship between the two DHCP servers - {1}. There are already two servers, so this is configuration rather than procurement" -f $noFo.Count, (Join-CERList ($noFo | ForEach-Object { $_.ScopeId }) 4)) }
    elseif ($noFo.Count) { $act += ("Stand up a second DHCP server and configure failover in load-balance mode for the {0} active scope(s). A single DHCP server is a site-wide outage waiting for a reboot, and the reboot is usually a patch window nobody associated with DHCP" -f $noFo.Count) }
    if ($badFo.Count) { $act += ("Investigate the failover relationship(s) not in Normal state - {0}. A relationship stuck in Communication Interrupted or Partner Down is silently serving from one side and will run the partner's pool down" -f (Join-CERList ($badFo | ForEach-Object { "{0} on {1} = {2}" -f $_.Name, $_.Server, $_.State }) 3)) }
    if ($longLease.Count) { $act += ("Review the {0} scope(s) with a lease longer than 8 days - {1}. Long leases on a mobile-heavy or guest network hold addresses for devices that left days ago, which reads as exhaustion in a range that is mostly idle" -f $longLease.Count, (Join-CERList ($longLease | ForEach-Object { '{0} at {1} h' -f $_.ScopeId, $_.LeaseHours }) 4)) }
    Add-CEREvidence -Control 'SRV-11' -Flag $(if ($hot.Count -or $badFo.Count -or ($noFo.Count -and $active.Count)) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on scope health. Confirm the failover relationships are in the monitoring platform so a partner-down state raises a ticket rather than waiting for the next review.' }) -Evidence ("DHCP scopes: {0} total across {1} server(s), {2} active, {3} inactive. At or above {4}% used: {5} ({6}). Active scopes without failover: {7} ({8}). Failover relationships: {9} ({10}); not in Normal state: {11}. Superscopes: {12}. Lease durations over 8 days: {13}." -f $rows.Count, $script:servers.Count, $active.Count, @($rows | Where-Object { $_.State -ne 'Active' }).Count, $UtilisationThreshold, $hot.Count, (Join-CERList ($hot | ForEach-Object { "{0} {1}%" -f $_.ScopeId, $_.PercentInUse }) 6), $noFo.Count, (Join-CERList ($noFo | ForEach-Object { $_.ScopeId }) 6), $failovers.Count, (Join-CERList ($failovers | ForEach-Object { "{0} [{1}] with {2}, {3}" -f $_.Name, $_.Mode, $_.Partner, $_.State }) 4), $badFo.Count, $superscopes.Count, $longLease.Count)

    # the scope table is the closest thing to documented evidence of the client's IP schema
    Add-CEREvidence -Control 'NET-01' -Flag Info -Action 'Reconcile these ranges against the VLAN/IP schema in Netbox and the L3 diagram. Scopes that exist for a VLAN missing from the documentation, or documented subnets with no scope, are both signs the diagram has drifted from the network - and the DHCP server is the more reliable of the two.' -Evidence ("DHCP-served subnets ({0} active scopes): {1}. Reservations defined: {2}. Compare with the VLAN/IP schema in Netbox and the L3 diagram." -f $active.Count, (Join-CERList ($active | ForEach-Object { "{0} {1} ({2}-{3})" -f $_.ScopeId, $_.Name, $_.StartRange, $_.EndRange }) 12), (@($rows | ForEach-Object { $_.Reservations }) | Measure-Object -Sum).Sum)
}

# ---------------- option hygiene (DNS, gateway, domain name, NTP)
Invoke-CERSection -Collector $C -Section 'Options' -Script {
    if (-not $script:servers.Count) { Set-CERSectionResult -Status 'Skipped' -Note 'no reachable DHCP server'; return }
    $serverOpts = @(); $scopeOpts = @()
    foreach ($s in $script:servers) {
        $n = $s.Server
        try { $serverOpts += @(Get-DhcpServerv4OptionValue -ComputerName $n -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Server = $n; OptionId = $_.OptionId; Name = $_.Name; Value = (@($_.Value) -join ', ') } }) } catch { }
    }
    foreach ($x in $script:scopes) {
        try {
            $o = @(Get-DhcpServerv4OptionValue -ComputerName $x.Server -ScopeId $x.ScopeId -ErrorAction SilentlyContinue)
            $scopeOpts += [pscustomobject]@{
                Server = $x.Server; ScopeId = $x.ScopeId; State = $x.State
                Dns = (@(($o | Where-Object { $_.OptionId -eq 6 }).Value) -join ', ')
                Router = (@(($o | Where-Object { $_.OptionId -eq 3 }).Value) -join ', ')
                DomainName = (@(($o | Where-Object { $_.OptionId -eq 15 }).Value) -join ', ')
                Ntp = (@(($o | Where-Object { $_.OptionId -eq 42 }).Value) -join ', ')
                OptionCount = $o.Count
            }
        } catch { }
    }
    Save-CERRaw -Name 'options' -Object ([ordered]@{ ServerLevel = $serverOpts; ScopeLevel = $scopeOpts })
    $srvDns = (@(($serverOpts | Where-Object { $_.OptionId -eq 6 }).Value) -join ', ')
    $active = @($scopeOpts | Where-Object { $_.State -eq 'Active' })
    $noDns = @($active | Where-Object { -not $_.Dns -and -not $srvDns })
    $noRouter = @($active | Where-Object { -not $_.Router })
    $publicDns = @($active | Where-Object { $_.Dns -match '(^|[ ,])(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|208\.67\.(222|220)\.)' })
    if ($srvDns -match '(^|[ ,])(8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|208\.67\.(222|220)\.)') { $publicDns += [pscustomobject]@{ ScopeId = 'server-level option 006'; Dns = $srvDns } }
    $act = @()
    if ($noDns.Count) { $act += ("Set option 006 (DNS servers) on the {0} active scope(s) without it and without a server-level default - {1}. Clients on those ranges get no resolver from DHCP, which breaks domain join and every name lookup" -f $noDns.Count, (Join-CERList ($noDns | ForEach-Object { $_.ScopeId }) 4)) }
    if ($noRouter.Count) { $act += ("Set option 003 (router) on the {0} active scope(s) missing it - {1}, unless the range is deliberately isolated" -f $noRouter.Count, (Join-CERList ($noRouter | ForEach-Object { $_.ScopeId }) 4)) }
    if ($publicDns.Count) { $act += ("Point the {0} scope(s) handing out public resolvers - {1} - at the internal DNS servers. Domain-joined clients using a public resolver cannot find the domain's SRV records, so they authenticate slowly or not at all, and no DNS-layer filtering or query logging applies to them" -f $publicDns.Count, (Join-CERList ($publicDns | ForEach-Object { "{0} -> {1}" -f $_.ScopeId, $_.Dns }) 4)) }
    Add-CEREvidence -Control 'SRV-11' -Flag $(if ($noDns.Count -or $publicDns.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on option hygiene. Worth confirming option 042 (NTP) is either set deliberately or deliberately absent - domain members should take time from the domain hierarchy, not from DHCP.' }) -Evidence ("DHCP options: server-level DNS (006) = {0}; active scopes with no DNS option and no server default: {1}; with no router option (003): {2}; handing out public resolvers: {3} ({4}). Scopes setting a domain name (015): {5}; setting NTP (042): {6}." -f $(if ($srvDns) { $srvDns } else { 'not set' }), $noDns.Count, $noRouter.Count, $publicDns.Count, (Join-CERList ($publicDns | ForEach-Object { $_.ScopeId }) 4), @($active | Where-Object { $_.DomainName }).Count, @($active | Where-Object { $_.Ntp }).Count)
}

# ---------------- dynamic DNS registration, name protection, credential
Invoke-CERSection -Collector $C -Section 'DnsRegistration' -Script {
    if (-not $script:servers.Count) { Set-CERSectionResult -Status 'Skipped' -Note 'no reachable DHCP server'; return }
    $rows = @()
    foreach ($s in $script:servers) {
        $n = $s.Server
        $dns = $null; try { $dns = Get-DhcpServerv4DnsSetting -ComputerName $n -ErrorAction SilentlyContinue } catch { }
        $cred = $null; $credSet = $false
        try { $cred = Get-DhcpServerDnsCredential -ComputerName $n -ErrorAction SilentlyContinue; if ($cred -and $cred.UserName) { $credSet = $true } } catch { }
        $rows += [pscustomobject]@{
            Server = $n; IsDomainController = $s.IsDomainController
            DynamicUpdates = "$($dns.DynamicUpdates)"; UpdateDnsRRForOlderClients = $dns.UpdateDnsRRForOlderClients
            DeleteDnsRROnLeaseExpiry = $dns.DeleteDnsRROnLeaseExpiry; NameProtection = $dns.NameProtection
            DisableDnsPtrRRUpdate = $dns.DisableDnsPtrRRUpdate
            # the account only - never a credential, and Get-DhcpServerDnsCredential returns no password anyway
            DnsCredentialUser = $(if ($credSet) { ("{0}\{1}" -f $cred.DomainName, $cred.UserName) } else { '' })
            DnsCredentialSet = $credSet
        }
    }
    Save-CERRaw -Name 'dnsregistration' -Object $rows
    $noCred = @($rows | Where-Object { -not $_.DnsCredentialSet })
    $noCredOnDc = @($noCred | Where-Object { $_.IsDomainController })
    $noProtection = @($rows | Where-Object { $_.NameProtection -eq $false })
    $noDelete = @($rows | Where-Object { $_.DeleteDnsRROnLeaseExpiry -eq $false })
    $act = @()
    if ($noCred.Count) {
        $extra = ''
        if ($noCredOnDc.Count) { $extra = (" On {0} the DHCP server is also a domain controller, which is the case where this matters most: without a credential the records are owned by the computer account of a DC, and members of DnsUpdateProxy (if the service account was added there) leave records with no ownership at all - anyone on the network can overwrite them." -f (Join-CERList ($noCredOnDc | ForEach-Object { $_.Server }) 3)) }
        $act += ("Configure the DHCP DNS registration credential on {0} (a plain, non-privileged domain user, set with Set-DhcpServerDnsCredential).{1} Without it, DHCP registers DNS records as itself and cannot later delete or update records it did not create, which is how stale A records that resolve to the wrong host accumulate" -f (Join-CERList ($noCred | ForEach-Object { $_.Server }) 4), $extra)
    }
    if ($noProtection.Count) { $act += ("Consider enabling name protection on {0} so a rogue or misconfigured host cannot take over an existing name registration (DHCID record)" -f (Join-CERList ($noProtection | ForEach-Object { $_.Server }) 4)) }
    if ($noDelete.Count) { $act += ("Enable 'discard A and PTR records when lease is deleted' on {0} - without it, expired leases leave their DNS records behind and the address gets reissued to a different host under the old name" -f (Join-CERList ($noDelete | ForEach-Object { $_.Server }) 4)) }
    Add-CEREvidence -Control 'SRV-11' -Flag $(if ($noCred.Count -or $noDelete.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { '' }) -Evidence ("DHCP dynamic DNS: {0}. Registration credential configured on {1}/{2} server(s){3}. Name protection off on {4}; discard-on-expiry off on {5}." -f (Join-CERList ($rows | ForEach-Object { "{0}: updates {1}, name protection {2}" -f $_.Server, $_.DynamicUpdates, $_.NameProtection }) 4), @($rows | Where-Object { $_.DnsCredentialSet }).Count, $rows.Count, $(if ($noCredOnDc.Count) { (' - and {0} of the servers without one is a domain controller' -f $noCredOnDc.Count) } else { '' }), $noProtection.Count, $noDelete.Count)
}

# ---------------- audit logging, database backup, conflict detection, policies
Invoke-CERSection -Collector $C -Section 'AuditAndDatabase' -Script {
    if (-not $script:servers.Count) { Set-CERSectionResult -Status 'Skipped' -Note 'no reachable DHCP server'; return }
    $rows = @()
    foreach ($s in $script:servers) {
        $n = $s.Server
        $audit = $null; try { $audit = Get-DhcpServerAuditLog -ComputerName $n -ErrorAction SilentlyContinue } catch { }
        $db = $null; try { $db = Get-DhcpServerDatabase -ComputerName $n -ErrorAction SilentlyContinue } catch { }
        $set = $null; try { $set = Get-DhcpServerSetting -ComputerName $n -ErrorAction SilentlyContinue } catch { }
        $pol = 0; try { $pol = @(Get-DhcpServerv4Policy -ComputerName $n -ErrorAction SilentlyContinue).Count } catch { }
        $filters = @(); try { $filters = @(Get-DhcpServerv4Filter -ComputerName $n -ErrorAction SilentlyContinue) } catch { }
        $rows += [pscustomobject]@{
            Server = $n
            AuditEnabled = $(if ($audit) { $audit.Enable } else { $null }); AuditPath = $(if ($audit) { $audit.Path } else { '' })
            AuditMaxSizeMB = $(if ($audit) { $audit.MaxMBFileSize } else { $null })
            DbBackupPath = $(if ($db) { $db.BackupPath } else { '' }); DbBackupIntervalMin = $(if ($db) { $db.BackupInterval } else { $null })
            DbCleanupIntervalMin = $(if ($db) { $db.CleanupInterval } else { $null })
            ConflictDetectionAttempts = $(if ($set) { $set.ConflictDetectionAttempts } else { $null })
            IsAuthorized = $(if ($set) { $set.IsAuthorized } else { $null })
            NpsUnreachableAction = $(if ($set) { "$($set.NpsUnreachableAction)" } else { '' })
            Policies = $pol
            FilterAllow = @($filters | Where-Object { "$($_.List)" -eq 'Allow' }).Count
            FilterDeny = @($filters | Where-Object { "$($_.List)" -eq 'Deny' }).Count
        }
    }
    Save-CERRaw -Name 'auditdatabase' -Object $rows
    $noAudit = @($rows | Where-Object { $_.AuditEnabled -eq $false })
    $localBackup = @($rows | Where-Object { $_.DbBackupPath -and $_.DbBackupPath -notmatch '^\\\\' })
    $noConflict = @($rows | Where-Object { $null -ne $_.ConflictDetectionAttempts -and $_.ConflictDetectionAttempts -eq 0 })
    $act = @()
    if ($noAudit.Count) { $act += ("Turn DHCP audit logging back on for {0}. It is on by default, so off means someone turned it off - and without it there is no record of which MAC held which address, which is the first question asked in any incident that starts with an IP address" -f (Join-CERList ($noAudit | ForEach-Object { $_.Server }) 4)) }
    if ($localBackup.Count) { $act += ("Confirm the DHCP database backup on {0} is picked up by the server backup - the backup path is local, so it only helps if the whole server is being backed up. Losing the DHCP database loses every reservation, which is a long manual rebuild" -f (Join-CERList ($localBackup | ForEach-Object { "{0} ({1})" -f $_.Server, $_.DbBackupPath }) 3)) }
    if ($noConflict.Count) { $act += ("Set conflict detection to 1 or 2 attempts on {0} where static addressing and DHCP share a range. It costs a ping before each offer and prevents the duplicate-address faults that get diagnosed as a network problem for days" -f (Join-CERList ($noConflict | ForEach-Object { $_.Server }) 3)) }
    Add-CEREvidence -Control 'SRV-11' -Flag $(if ($noAudit.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action. Confirm the DHCP database backup is inside the server backup job and that a restore of it has actually been tested (BDR-05).' }) -Evidence ("DHCP audit logging enabled on {0}/{1} server(s){2}. Database backup: {3}. Conflict detection attempts: {4}. DHCP policies defined: {5}; MAC filters: {6} allow / {7} deny." -f @($rows | Where-Object { $_.AuditEnabled }).Count, $rows.Count, $(if ($noAudit.Count) { (' - off on ' + (Join-CERList ($noAudit | ForEach-Object { $_.Server }) 3)) } else { '' }), (Join-CERList ($rows | ForEach-Object { "{0} -> {1} every {2} min" -f $_.Server, $_.DbBackupPath, $_.DbBackupIntervalMin }) 3), (Join-CERList ($rows | ForEach-Object { "{0}={1}" -f $_.Server, $_.ConflictDetectionAttempts }) 4), (@($rows | ForEach-Object { $_.Policies }) | Measure-Object -Sum).Sum, (@($rows | ForEach-Object { $_.FilterAllow }) | Measure-Object -Sum).Sum, (@($rows | ForEach-Object { $_.FilterDeny }) | Measure-Object -Sum).Sum)
}

Complete-CERCollector

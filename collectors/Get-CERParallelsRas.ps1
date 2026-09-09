#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (optional): Parallels Remote Application Server (RAS) - farm and site layout, version
  support status, RD session hosts, publishing agent and gateway redundancy, SSL/TLS, MFA, licensing and
  published resources. Feeds SRV-14, SRV-02, NET-05, LIC-02 and LIC-03.

.DESCRIPTION
  Uses the RASAdmin PowerShell module, which ships with the RAS console. Run it on the Parallels RAS connection
  broker (publishing agent) or on any machine with the console installed, pointing at the farm with -Server.

  Read-only: Get-RAS* only, plus New-RASSession to connect and Remove-RASSession to disconnect. Nothing is
  applied - no Invoke-RASApply is ever called, so nothing this collector does can change the farm.

  Cmdlet coverage varies between RAS 18, 19, 20 and 21. Every call beyond the core three is guarded by
  Get-Command and degrades to a recorded coverage gap rather than an error, the same way the Veeam collector
  handles properties that move between versions.

.EXAMPLE
  .\Get-CERParallelsRas.ps1 -Client C-003 -RunId 20260905-0900                        # on the broker itself
  .\Get-CERParallelsRas.ps1 -Client C-003 -RunId 20260905-0900 -Server ras01.contoso.local -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string]$Server,
    [pscredential]$Credential
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'ParallelsRas' -RunId $RunId
$C = 'ParallelsRas'

function Invoke-Ras {
    <#
      Calls a Get-RAS* cmdlet if this RAS version has it. Returns @() when the cmdlet does not exist or the call
      fails, and says which in the log - a missing cmdlet is a coverage gap to report, never a terminating error.
    #>
    param([Parameter(Mandatory)][string]$Name, [hashtable]$Params = @{})
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-CERLog ("{0} not present in this RAS version - skipped" -f $Name) 'DEBUG'
        return @()
    }
    try { return @(& $Name @Params -ErrorAction Stop) }
    catch { Write-CERLog ("{0} failed: {1}" -f $Name, ($_.Exception.Message -replace '\s+', ' ')) 'WARN'; return @() }
}

if (-not (Test-CERModule -Name RASAdmin -Collector $C)) {
    Add-CEREvidence -Control 'SRV-14' -Flag Unknown -Action 'Run this collector on the Parallels RAS connection broker, or install the RAS console on the jump host (it brings the RASAdmin module with it) and re-run with -Server. If the client does not use Parallels RAS, score SRV-14 against whichever published-application platform they do run - Citrix, plain RDS, or none.' -Evidence 'RASAdmin module not available on this host - run on the RAS broker or a machine with the Parallels RAS console installed.'
    Complete-CERCollector; return
}
Import-Module RASAdmin -ErrorAction Stop -WarningAction SilentlyContinue

# ---------------- connect
$script:connected = $false
Invoke-CERSection -Collector $C -Section 'Connect' -Script {
    $p = @{ ErrorAction = 'Stop' }
    if ($Server) { $p['Server'] = $Server }
    if ($Credential) { $p['Credential'] = $Credential }
    $null = New-RASSession @p
    $script:connected = $true
    Write-CERLog ("Connected to Parallels RAS farm{0}" -f $(if ($Server) { " on $Server" } else { ' (local broker)' }))
}

# ---------------- farm, sites, version, licence
Invoke-CERSection -Collector $C -Section 'FarmAndLicence' -Script {
    if (-not $script:connected) { Set-CERSectionResult -Status 'NoAccess' -Note 'no RAS session'; return }
    $ver = Invoke-Ras 'Get-RASVersion'
    $sites = Invoke-Ras 'Get-RASSite'
    $lic = Invoke-Ras 'Get-RASLicenseDetails'
    $vstr = ''
    if ($ver) {
        foreach ($p in 'Version', 'ProductVersion', 'RASVersion') { $v = Get-CERProp $ver[0] $p; if ($v) { $vstr = "$v"; break } }
        if (-not $vstr) { $vstr = ("$($ver[0])").Trim() }
    }
    $sup = Get-CERRasSupport -Version $vstr
    Save-CERRaw -Name 'farm' -Object ([ordered]@{ Version = $ver; DetectedVersion = $vstr; Support = $sup; Sites = $sites; Licence = $lic })
    $act = @()
    if ($sup.Note) { $act += $sup.Note }
    if ($sites.Count -gt 1) { $act += ("This is a multi-site farm ({0} sites). Confirm each site has its own local publishing agent and gateway redundancy - a secondary site that depends on the primary site's broker fails with it, which defeats the point of having it" -f $sites.Count) }
    $flag = 'OK'
    if ($sup.Supported -eq $false) { $flag = 'Attention' } elseif ($null -eq $sup.Supported) { $flag = 'Unknown' } elseif ($sup.InMaintenance -eq $false) { $flag = 'Attention' }
    Add-CEREvidence -Control 'SRV-14' -Flag $flag -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on version currency. Keep the RAS version on the renewals and lifecycle register - Parallels ships a major release yearly and support is 36 months from release for an LTS, so the upgrade window arrives sooner than most people expect.' }) -Evidence ("Parallels RAS {0} ({1}), support status {2}{3}{4}. Sites in farm: {5} ({6})." -f $(if ($vstr) { $vstr } else { 'version not readable' }), $sup.Family, $(if ($null -eq $sup.Supported) { 'unknown' } elseif ($sup.Supported) { 'in support' } else { 'OUT OF SUPPORT' }), $(if ($sup.EndOfSupport) { (' to ' + $sup.EndOfSupport) } else { '' }), $(if ($sup.EndOfMaintenance) { (', maintenance to ' + $sup.EndOfMaintenance) } else { '' }), $sites.Count, (Join-CERList ($sites | ForEach-Object { "{0} [{1}]" -f (Get-CERProp $_ 'Name'), (Get-CERProp $_ 'Server') }) 5))

    Add-CEREvidence -Control 'LIC-02' -Flag $(if ($sup.Supported -eq $false) { 'Attention' } else { 'Info' }) -Action 'Add Parallels RAS to the software lifecycle register with its end-of-maintenance and end-of-support dates. RAS keeps working long after support ends, so it needs a date in the register rather than a reminder from the product.' -Evidence ("Parallels RAS {0}: {1}, end of maintenance {2}, end of support {3}." -f $vstr, $sup.Family, $(if ($sup.EndOfMaintenance) { $sup.EndOfMaintenance } else { 'unknown' }), $(if ($sup.EndOfSupport) { $sup.EndOfSupport } else { 'unknown' }))

    if ($lic) {
        $l = $lic[0]
        $expiry = $null; foreach ($p in 'ExpiryDate', 'ExpirationDate', 'SupportExpiryDate') { $v = Get-CERProp $l $p; if ($v) { $expiry = $v; break } }
        $days = Get-CERAgeDays $expiry
        $used = Get-CERProp $l 'UsedConcurrentUsers'; if ($null -eq $used) { $used = Get-CERProp $l 'ConcurrentUsers' }
        $total = Get-CERProp $l 'LicenseUsers'; if ($null -eq $total) { $total = Get-CERProp $l 'MaxConcurrentUsers' }
        $pct = $null; if ($total -and [double]$total -gt 0 -and $null -ne $used) { $pct = [math]::Round(100 * [double]$used / [double]$total, 1) }
        $soon = ($null -ne $days -and $days -gt -90)
        Add-CEREvidence -Control 'LIC-03' -Flag $(if ($soon -or ($null -ne $pct -and $pct -ge 90)) { 'Attention' } else { 'OK' }) -Action $(if ($soon) { 'Put the Parallels RAS subscription renewal in the renewals calendar with the FortiCare, Veeam, Citrix and M365 anniversaries. RAS is subscription-licensed, so an expiry stops new connections rather than just ending support - it is an outage, not a warning.' } elseif ($null -ne $pct -and $pct -ge 90) { 'Concurrent user licence usage is at or above 90% of what is owned. The next hire or the next busy day is a user who cannot connect. Size the next licence purchase now rather than during the incident.' } else { 'Record the licence count and renewal date in the renewals calendar and reconcile the concurrent-user entitlement against actual peak usage at the next review.' }) -Evidence ("Parallels RAS licence: type {0}, status {1}, expires {2}{3}; concurrent users {4} of {5}{6}." -f (Get-CERProp $l 'LicenseType'), (Get-CERProp $l 'LicenseStatus'), $(if ($expiry) { $expiry } else { 'not reported' }), $(if ($null -ne $days) { (' ({0} days)' -f (-1 * $days)) } else { '' }), $used, $total, $(if ($null -ne $pct) { (" - {0}% used" -f $pct) } else { '' }))
    } else {
        Add-CEREvidence -Control 'LIC-03' -Flag Info -Action 'Read the licence type, concurrent-user entitlement and renewal date from the RAS console (Licensing) and put them in the renewals calendar. Get-RASLicenseDetails returned nothing from here.' -Evidence 'Parallels RAS licence details not readable from this host - read them from the RAS console under Licensing.'
    }
}

# ---------------- infrastructure redundancy: publishing agents, gateways, HALB
Invoke-CERSection -Collector $C -Section 'Infrastructure' -Script {
    if (-not $script:connected) { Set-CERSectionResult -Status 'NoAccess' -Note 'no RAS session'; return }
    $pa = Invoke-Ras 'Get-RASPA'
    if (-not $pa.Count) { $pa = Invoke-Ras 'Get-RASBroker' }
    if (-not $pa.Count) { $pa = Invoke-Ras 'Get-RASConnectionBroker' }
    $gw = Invoke-Ras 'Get-RASGateway'
    $gwStatus = Invoke-Ras 'Get-RASGatewayStatus'
    $halb = Invoke-Ras 'Get-RASHALB'
    $cert = Invoke-Ras 'Get-RASCertificate'
    Save-CERRaw -Name 'infrastructure' -Object ([ordered]@{ PublishingAgents = $pa; Gateways = $gw; GatewayStatus = $gwStatus; HALB = $halb; Certificates = $cert })
    $paEnabled = @($pa | Where-Object { $v = Get-CERProp $_ 'Enabled'; $null -eq $v -or $v })
    $gwEnabled = @($gw | Where-Object { $v = Get-CERProp $_ 'Enabled'; $null -eq $v -or $v })
    $gwDown = @($gwStatus | Where-Object { "$(Get-CERProp $_ 'AgentState')" -inotmatch 'OK|Ready|Verified' -and "$(Get-CERProp $_ 'ServerState')" -inotmatch 'OK|Ready' })
    $act = @()
    if ($paEnabled.Count -lt 2) { $act += 'There is a single publishing agent (connection broker). It is the component that brokers every session, so while it is down nobody can start a new session at all - existing sessions survive, which is what makes this fail quietly until the first person tries to reconnect. Add a secondary publishing agent; it is a supported, licence-free addition' }
    if ($gwEnabled.Count -lt 2) { $act += 'There is a single RAS Secure Gateway. Every external connection passes through it, so it is a single point of failure for remote access. Add a second gateway and put HALB or an external load balancer in front' }
    elseif (-not $halb.Count) { $act += ("There are {0} gateways but no HALB appliance is configured. Two gateways without a load balancer in front only helps if clients are configured with both, which in practice they are not - confirm how clients are directed to the second gateway" -f $gwEnabled.Count) }
    if ($gwDown.Count) { $act += ("Investigate the {0} gateway(s) not reporting a healthy state - {1}" -f $gwDown.Count, (Join-CERList ($gwDown | ForEach-Object { "{0}: {1}" -f (Get-CERProp $_ 'Server'), (Get-CERProp $_ 'AgentState') }) 3)) }
    Add-CEREvidence -Control 'SRV-14' -Flag $(if ($paEnabled.Count -lt 2 -or $gwEnabled.Count -lt 2 -or $gwDown.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on redundancy. Confirm the second publishing agent and gateway are on different hosts and ideally different hypervisor nodes - two brokers on the same ESXi host is one host failure away from being no brokers.' }) -Evidence ("Parallels RAS infrastructure: publishing agents {0} ({1} enabled) - {2}; secure gateways {3} ({4} enabled) - {5}; HALB virtual servers {6}. Gateways not reporting healthy: {7}." -f $pa.Count, $paEnabled.Count, (Join-CERList ($pa | ForEach-Object { "{0}" -f (Get-CERProp $_ 'Server') }) 4), $gw.Count, $gwEnabled.Count, (Join-CERList ($gw | ForEach-Object { "{0}" -f (Get-CERProp $_ 'Server') }) 4), $halb.Count, $gwDown.Count)

    if ($cert.Count) {
        $expiring = @($cert | Where-Object { $e = Get-CERProp $_ 'ExpirationDate'; $e -and (Get-CERAgeDays $e) -gt -60 })
        Add-CEREvidence -Control 'SRV-10' -Flag $(if ($expiring.Count) { 'Attention' } else { 'OK' }) -Action $(if ($expiring.Count) { 'Renew and rebind the expiring gateway certificate(s). An expired certificate on the RAS gateway stops every external connection, and the client-side error points at the client rather than the server, so it burns service-desk time before anyone checks the certificate.' } else { 'Add the RAS gateway certificates to the certificate expiry register with a named owner so they are tracked with the rest of the estate rather than only inside the RAS console.' }) -Evidence ("Parallels RAS certificates: {0} - {1}. Expiring within 60 days: {2}." -f $cert.Count, (Join-CERList ($cert | ForEach-Object { "{0} expires {1}" -f (Get-CERProp $_ 'Name'), (Get-CERProp $_ 'ExpirationDate') }) 5), $expiring.Count)
    }
}

# ---------------- RD session hosts and host pools
Invoke-CERSection -Collector $C -Section 'SessionHosts' -Script {
    if (-not $script:connected) { Set-CERSectionResult -Status 'NoAccess' -Note 'no RAS session'; return }
    $rds = Invoke-Ras 'Get-RASRDS'
    $rdsStatus = Invoke-Ras 'Get-RASRDSStatus'
    $pools = Invoke-Ras 'Get-RASRDSHostPool'
    $vdi = Invoke-Ras 'Get-RASVDIHost'
    if (-not $vdi.Count) { $vdi = Invoke-Ras 'Get-RASProvider' }
    Save-CERRaw -Name 'sessionhosts' -Object ([ordered]@{ RDSHosts = $rds; RDSStatus = $rdsStatus; HostPools = $pools; VDIProviders = $vdi })
    $enabled = @($rds | Where-Object { $v = Get-CERProp $_ 'Enabled'; $null -eq $v -or $v })
    $bad = @($rdsStatus | Where-Object { "$(Get-CERProp $_ 'AgentState')" -inotmatch 'OK|Ready|Verified' })
    $needsUpdate = @($rdsStatus | Where-Object { "$(Get-CERProp $_ 'AgentState')" -imatch 'NeedsUpdate|NotVerified|Update' })
    $act = @()
    if ($bad.Count) { $act += ("Bring the {0} session host(s) with an unhealthy RAS agent back into service - {1}. A host whose agent is not in an OK state is capacity the farm cannot place users on, and it does not announce itself" -f $bad.Count, (Join-CERList ($bad | ForEach-Object { "{0}: {1}" -f (Get-CERProp $_ 'Server'), (Get-CERProp $_ 'AgentState') }) 4)) }
    if ($needsUpdate.Count) { $act += ("Push the RAS agent update to {0} host(s) reporting NeedsUpdate. A mismatched agent version between the broker and its session hosts is the usual cause of intermittent, host-specific session failures that look random from the service desk" -f $needsUpdate.Count) }
    if ($enabled.Count -lt 2) { $act += 'There is a single enabled RD session host. Every published application and desktop depends on it, so a reboot for patching is a full outage. Add a second host to the pool and confirm the applications are published from the pool rather than pinned to the one server' }
    Add-CEREvidence -Control 'SRV-14' -Flag $(if ($bad.Count -or $enabled.Count -lt 2) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on the session hosts. Confirm the drain/maintenance process for patching is documented - taking a host out of the pool cleanly is what stops a patch window becoming a set of disconnected users.' }) -Evidence ("Parallels RAS session hosts: {0} ({1} enabled) - {2}. Host pools: {3}. VDI providers: {4}. Agents not in a healthy state: {5} ({6}); reporting NeedsUpdate: {7}." -f $rds.Count, $enabled.Count, (Join-CERList ($rds | ForEach-Object { "{0}" -f (Get-CERProp $_ 'Server') }) 6), $pools.Count, $vdi.Count, $bad.Count, (Join-CERList ($bad | ForEach-Object { "{0}={1}" -f (Get-CERProp $_ 'Server'), (Get-CERProp $_ 'AgentState') }) 4), $needsUpdate.Count)

    Add-CEREvidence -Control 'SRV-02' -Flag Info -Action 'Cross-check these session host names against the Servers collector and the host check for Windows build and support status. Session hosts carry every user on the farm, so an out-of-support build here has the widest blast radius in the estate - and they are the servers people are most reluctant to reboot.' -Evidence ("Parallels RAS session hosts to reconcile with the Servers collector for Windows build and support status: {0}." -f (Join-CERList ($rds | ForEach-Object { "{0}" -f (Get-CERProp $_ 'Server') }) 12))
}

# ---------------- MFA, SSL and how users authenticate
Invoke-CERSection -Collector $C -Section 'AuthenticationAndMfa' -Script {
    if (-not $script:connected) { Set-CERSectionResult -Status 'NoAccess' -Note 'no RAS session'; return }
    $mfa = Invoke-Ras 'Get-RASMFA'
    $mfaDefault = Invoke-Ras 'Get-RASMFADefaultSettings'
    $mfaCriteria = Invoke-Ras 'Get-RASMFACriteria'
    $auth = Invoke-Ras 'Get-RASAuthSettings'
    $saml = Invoke-Ras 'Get-RASSAMLIDP'
    Save-CERRaw -Name 'authentication' -Object ([ordered]@{ MFA = $mfa; MFADefaults = $mfaDefault; MFACriteria = $mfaCriteria; AuthSettings = $auth; SamlIdp = $saml })
    $mfaOn = @($mfa | Where-Object { $v = Get-CERProp $_ 'Enabled'; $v -eq $true })
    if (-not $mfaOn.Count -and $mfaDefault) { $mfaOn = @($mfaDefault | Where-Object { $v = Get-CERProp $_ 'Enabled'; $v -eq $true }) }
    $samlOn = @($saml | Where-Object { $v = Get-CERProp $_ 'Enabled'; $null -eq $v -or $v })
    $providers = @($mfa | ForEach-Object { "$(Get-CERProp $_ 'Type')$(Get-CERProp $_ 'Provider')" } | Where-Object { $_ })
    $act = @()
    if (-not $mfaOn.Count -and -not $samlOn.Count) { $act += 'No multi-factor authentication is enabled on the RAS farm. If the gateway is published to the internet, remote access is username and password against Active Directory - which is the single finding most likely to matter in this whole review. Either enable the built-in MFA against an existing provider, or federate to Entra with SAML so Conditional Access applies and brings device compliance and sign-in risk with it' }
    elseif ($samlOn.Count) { $act += ("SAML is configured ({0}). Confirm the identity provider is Entra and that the Conditional Access policy behind it genuinely requires MFA - federating the logon without a CA policy that enforces a second factor moves where the password is checked without adding a factor" -f (Join-CERList ($saml | ForEach-Object { "$(Get-CERProp $_ 'Name')" }) 3)) }
    elseif ($mfaOn.Count) { $act += ("MFA is enabled ({0}). Confirm the criteria actually cover external connections rather than exempting them - an MFA rule scoped to an internal subnet leaves the published gateway, which is the part on the internet, unprotected" -f (Join-CERList $providers 3)) }
    Add-CEREvidence -Control 'NET-05' -Flag $(if (-not $mfaOn.Count -and -not $samlOn.Count) { 'Attention' } else { 'OK' }) -Action (($act -join '. ') + '.') -Evidence ("Parallels RAS authentication: MFA providers configured {0} ({1} enabled) - {2}; MFA criteria/exclusion rules {3}; SAML identity providers {4} ({5} enabled) - {6}." -f $mfa.Count, $mfaOn.Count, (Join-CERList $providers 4), $mfaCriteria.Count, $saml.Count, $samlOn.Count, (Join-CERList ($saml | ForEach-Object { "$(Get-CERProp $_ 'Name')" }) 3))
}

# ---------------- published resources
Invoke-CERSection -Collector $C -Section 'PublishedResources' -Script {
    if (-not $script:connected) { Set-CERSectionResult -Status 'NoAccess' -Note 'no RAS session'; return }
    $pub = Invoke-Ras 'Get-RASPubItem'
    $sessions = Invoke-Ras 'Get-RASSession'
    Save-CERRaw -Name 'published' -Object ([ordered]@{ PublishedItems = $pub; Sessions = $sessions })
    $byType = @($pub | Group-Object { "$(Get-CERProp $_ 'Type')" } | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $desktops = @($pub | Where-Object { "$(Get-CERProp $_ 'Type')" -imatch 'Desktop' })
    $disabled = @($pub | Where-Object { (Get-CERProp $_ 'Enabled') -eq $false })
    Add-CEREvidence -Control 'SRV-14' -Flag Info -Action $(if ($desktops.Count) { 'Review who the published desktops are assigned to. A published full desktop gives the user a Windows session on a shared server, so the server hardening baseline, application control and macro settings all apply to it exactly as they would to a workstation - and it is usually excluded from the endpoint tooling because it is filed as a server. Confirm the session hosts are in the EDR, patching and application-control coverage counts (COV-04, COV-05, END-09).' } else { 'Confirm the published application list still matches what the business uses. Published items outlive the projects that justified them, and each one is an entry point onto a shared session host.' }) -Evidence ("Published resources: {0} item(s) - {1}; published full desktops {2}; disabled items {3}. Sessions at time of collection: {4}." -f $pub.Count, (Join-CERList $byType 6), $desktops.Count, $disabled.Count, $sessions.Count)
}

# ---------------- disconnect
try { if ($script:connected -and (Get-Command Remove-RASSession -ErrorAction SilentlyContinue)) { Remove-RASSession -ErrorAction SilentlyContinue; Write-CERLog 'RAS session closed.' } } catch { }

Complete-CERCollector

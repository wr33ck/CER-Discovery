#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: on-premises / hybrid Exchange, via the Exchange Management Shell.
  Feeds M365-02/03/04/05, IAM-01/04, SRV-02/03/04/09/10, BDR-06, LIC-02.

.DESCRIPTION
  Read-only. Every call is a Get-* cmdlet, a WinRM Invoke-Command running Get-* / registry reads, or an
  IIS configuration read. Nothing is created, changed or removed anywhere in the Exchange organisation.

  Where to run it
    * On the Exchange server itself, from the Exchange Management Shell (simplest, and the only way to get
      the true build number including security updates from ExSetup.exe), OR
    * from any domain-joined host with -Server <exchange fqdn>, which opens an implicit remoting session to
      http://<server>/PowerShell/ with Kerberos. The account needs a remote-PowerShell-enabled mailbox and
      the View-Only Organization Management role group (or Organization Management).

  BETA - like the FortiGate collector. Cmdlets and properties are verified against Microsoft Learn
  (08/09/2026) but this has not yet been run against a live hybrid estate; treat the first run's output as
  something to check rather than something to quote. Property names differ across versions, so sections are
  written defensively and a section that fails is recorded in coverage, never thrown.

.EXAMPLE
  # On the Exchange server, in the Exchange Management Shell
  .\Get-CERExchangeHybrid.ps1 -Client C-003 -RunId 20260905-0900 -OutputRoot D:\CER\output

.EXAMPLE
  # From a jump host, over implicit remoting
  .\Get-CERExchangeHybrid.ps1 -Client C-003 -RunId 20260905-0900 -Server exch01.contoso.local
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string]$Server,
    [pscredential]$Credential,
    [int]$CertExpiryWarnDays = 90,
    [int]$MaxMailboxes = 5000,
    [switch]$SkipIisChecks,
    [switch]$SkipServerRemote
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'ExchangeOnPrem' -RunId $RunId
$C = 'ExchangeOnPrem'
$now = Get-Date
$script:exSession = $null
$script:servers = @()
$script:acceptedDomains = @()

# ---------------- Connect
Invoke-CERSection -Collector $C -Section 'Connect' -Script {
    if (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue) {
        Write-CERLog 'Exchange cmdlets already present (running in the Exchange Management Shell).'
        return
    }
    if (-not $Server) {
        Set-CERSectionResult -Status Skipped -Note 'No Exchange Management Shell on this host and no -Server given. Run on the Exchange server from EMS, or pass -Server <exchange fqdn>. If the client has no on-prem Exchange, skipping this collector is the right answer - the AD collector confirms absence from the configuration partition.'
        return
    }
    $p = @{ ConfigurationName = 'Microsoft.Exchange'; ConnectionUri = ("http://{0}/PowerShell/" -f $Server); Authentication = 'Kerberos'; ErrorAction = 'Stop' }
    if ($Credential) { $p['Credential'] = $Credential }
    $script:exSession = New-PSSession @p
    $null = Import-PSSession -Session $script:exSession -DisableNameChecking -AllowClobber -CommandName 'Get-*' -ErrorAction Stop
    Write-CERLog ("Connected to on-prem Exchange via {0} (read-only: Get-* cmdlets only)." -f $Server)
}
if (-not (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)) {
    Write-CERLog 'No Exchange cmdlets available - nothing further to collect.' 'WARN'
    Complete-CERCollector
    return
}

# ---------------- Servers, builds and security-update currency
Invoke-CERSection -Collector $C -Section 'Servers' -Script {
    $raw = @(Get-ExchangeServer -ErrorAction Stop)
    $rows = foreach ($s in $raw) {
        $adv = "$($s.AdminDisplayVersion)"
        $exsetup = $null
        if (-not $SkipServerRemote) {
            try { $exsetup = Invoke-Command -ComputerName $s.Name -ErrorAction Stop -ScriptBlock { (Get-Command ExSetup.exe -ErrorAction Stop | ForEach-Object { $_.FileVersionInfo } | Select-Object -First 1).ProductVersion } } catch { }
        }
        $sup = if ($exsetup) { Get-CERExchangeSupport -Version $exsetup } else { Get-CERExchangeSupport -Version $adv -CuOnly }
        [pscustomobject]@{
            Name = $s.Name; Fqdn = "$($s.Fqdn)"; Edition = "$($s.Edition)"; Roles = "$($s.ServerRole)"; Site = "$($s.Site)"
            AdminDisplayVersion = $adv; ExSetupBuild = $exsetup; Family = $sup.Family; Supported = $sup.Supported
            EndOfSupport = $sup.EndOfSupport; LatestKnown = $sup.LatestKnown; LatestName = $sup.LatestName
            UpToDate = $sup.UpToDate; RevisionsBehind = $sup.RevisionsBehind; Note = $sup.Note
        }
    }
    $script:servers = @($rows)
    Save-CERRaw -Name 'servers' -Object $rows
    $eos = @($rows | Where-Object { $_.Supported -eq $false })
    $unknownFam = @($rows | Where-Object { $null -eq $_.Supported })   # version unreadable - not the same as "supported"
    $behind = @($rows | Where-Object { $_.UpToDate -eq $false })
    $unknownSu = @($rows | Where-Object { $null -eq $_.UpToDate })
    $edge = @($rows | Where-Object { $_.Roles -match 'Edge' })
    $flag = if ($eos.Count -or $behind.Count) { 'Attention' } elseif ($unknownFam.Count -or $unknownSu.Count) { 'Unknown' } else { 'OK' }
    Add-CEREvidence -Control 'M365-05' -Flag $flag -Action 'Take the decision the client has probably been deferring. If mailboxes still live here, the migration is unfinished and the version and exposure findings are live operational risk. If the server exists only for recipient management, the supported options are Exchange Server SE or the management-tools-only path - an out-of-support server kept to edit attributes is a large attack surface for a small job.' -Evidence ("On-prem Exchange servers: {0} - {1}. Past end of support: {2} ({3}). Behind the latest security update: {4} ({5}). Build table verified {6}; confirm at aka.ms/exchangebuildnumbers." -f $rows.Count, (Join-CERList ($rows | ForEach-Object { "{0} [{1} {2}]" -f $_.Name, $_.Family, $(if ($_.ExSetupBuild) { $_.ExSetupBuild } else { $_.AdminDisplayVersion }) })), $eos.Count, (Join-CERList ($eos | ForEach-Object { "{0} ({1}, EoS {2})" -f $_.Name, $_.Family, $_.EndOfSupport })), $behind.Count, (Join-CERList ($behind | ForEach-Object { "{0} is {1} revision(s) behind {2}" -f $_.Name, $_.RevisionsBehind, $_.LatestName })), $script:CERExchangeBuildsVerified)
    Add-CEREvidence -Control 'SRV-03' -Flag $flag -Action 'Apply the outstanding security updates. Exchange SUs are cumulative and Exchange is the most reliably exploited on-prem Microsoft product there is - a server behind on SUs and reachable from the internet should be treated as urgent rather than scheduled. Confirm the build afterwards with ExSetup.exe rather than Get-ExchangeServer, which shows the CU only.' -Evidence ("Exchange security-update currency: {0}/{1} servers on the latest known build. Behind: {2}. Build read from ExSetup.exe (true SU level) on {3}/{4} servers; the rest report the cumulative update only, which hides missing SUs: {5}." -f @($rows | Where-Object { $_.UpToDate -eq $true }).Count, $rows.Count, (Join-CERList ($behind | ForEach-Object { "{0} {1} -> latest {2}" -f $_.Name, $_.ExSetupBuild, $_.LatestKnown })), @($rows | Where-Object { $_.ExSetupBuild }).Count, $rows.Count, (Join-CERList ($unknownSu | ForEach-Object { $_.Name })))
    Add-CEREvidence -Control 'SRV-02' -Flag Info -Action 'Record the Exchange server roles, editions and sites in STACK.md. Note any Edge Transport server separately - it sits in the perimeter, is not domain-joined, and is routinely missed by both the patching policy and the AD-based collectors.' -Evidence ("Exchange server roles and sites: {0}. Edge Transport servers (perimeter, not domain-joined): {1}. Windows OS support for these hosts comes from the Servers collector." -f (Join-CERList ($rows | ForEach-Object { "{0}={1}@{2}" -f $_.Name, $_.Roles, $_.Site })), $(if ($edge.Count) { (Join-CERList ($edge | ForEach-Object { $_.Name })) } else { 'none' }))
    if ($unknownFam.Count) { Add-CEREvidence -Control 'M365-05' -Flag Unknown -Action 'Read the build directly on the affected server with Get-Command ExSetup.exe piped to FileVersionInfo. An unreadable version must not be scored as supported - it is unevidenced, which is a different finding.' -Evidence ("Version not readable on {0} server(s): {1}. Support status unknown - not assumed supported. Read the build with 'Get-Command ExSetup.exe | %{{$_.FileVersionInfo}}' on each." -f $unknownFam.Count, (Join-CERList ($unknownFam | ForEach-Object { "{0} ('{1}')" -f $_.Name, $_.AdminDisplayVersion }))) }
    Add-CEREvidence -Control 'LIC-02' -Flag $(if ($eos.Count) { 'Attention' } else { 'Info' }) -Action 'Add these Exchange versions and their end-of-support dates to the lifecycle register with the rest of the estate. Exchange 2016 and 2019 both ended support on 14 Oct 2025, so anything still on them needs either a funded ESU subscription or a migration date - and ESU is a bridge, not a destination.' -Evidence ("Lifecycle register - Exchange: {0}. Exchange 2016 and 2019 both reached end of support 14 Oct 2025; security updates after Dec 2025 require the paid Extended Security Update programme. Exchange Server SE is the only version in mainstream support." -f (Join-CERList ($rows | ForEach-Object { "{0}: {1}{2}" -f $_.Name, $_.Family, $(if ($_.EndOfSupport) { " (EoS $($_.EndOfSupport))" } else { '' }) })))
}

# ---------------- Hybrid configuration, federation and OAuth
Invoke-CERSection -Collector $C -Section 'Hybrid' -Script {
    $hc = $null; try { $hc = Get-HybridConfiguration -ErrorAction Stop } catch { }
    $orgRel = @(); try { $orgRel = @(Get-OrganizationRelationship -ErrorAction Stop | Select-Object Name, DomainNames, Enabled, FreeBusyAccessEnabled, FreeBusyAccessLevel, MailboxMoveEnabled, TargetApplicationUri, TargetAutodiscoverEpr) } catch { }
    $ioc = @(); try { $ioc = @(Get-IntraOrganizationConnector -ErrorAction Stop | Select-Object Name, TargetAddressDomains, DiscoveryEndpoint, Enabled) } catch { }
    $fed = $null; try { $fed = Get-FederationTrust -ErrorAction Stop | Select-Object Name, ApplicationUri, TokenIssuerUri, OrgCertificate, OrgPrivCertificate, OrgNextCertificate | Select-Object -First 1 } catch { }
    $migEnd = @(); try { $migEnd = @(Get-MigrationEndpoint -ErrorAction Stop | Select-Object Identity, EndpointType, RemoteServer, MaxConcurrentMigrations) } catch { }
    $authCfg = $null; $authCur = $null; $authNext = $null
    try {
        $authCfg = Get-AuthConfig -ErrorAction Stop
        if ($authCfg.CurrentCertificateThumbprint) { $authCur = Get-ExchangeCertificate -Thumbprint $authCfg.CurrentCertificateThumbprint -ErrorAction SilentlyContinue | Select-Object Subject, Thumbprint, NotBefore, NotAfter, Status | Select-Object -First 1 }
        if ($authCfg.NextCertificateThumbprint) { $authNext = Get-ExchangeCertificate -Thumbprint $authCfg.NextCertificateThumbprint -ErrorAction SilentlyContinue | Select-Object Subject, Thumbprint, NotBefore, NotAfter | Select-Object -First 1 }
    } catch { }
    $authServers = @(); try { $authServers = @(Get-AuthServer -ErrorAction Stop | Select-Object Name, Type, IssuerIdentifier, Enabled, TokenIssuingEndpoint) } catch { }
    Save-CERRaw -Name 'hybrid' -Object ([ordered]@{ HybridConfiguration = ($hc | Select-Object Domains, Features, ExternalIPAddresses, OnPremisesSmartHost, TlsCertificateName, SecureMailCertificateThumbprint, ClientAccessServers, TransportServers, SendingTransportServers, ReceivingTransportServers, ServiceInstance); OrganizationRelationships = $orgRel; IntraOrgConnectors = $ioc; FederationTrust = $fed; MigrationEndpoints = $migEnd; AuthConfig = ($authCfg | Select-Object CurrentCertificateThumbprint, NextCertificateThumbprint, NewCertificateThumbprint, NewCertificateEffectiveDate, ServiceName, Realm, IsValid); AuthCurrentCertificate = $authCur; AuthNextCertificate = $authNext; AuthServers = $authServers })

    $isHybrid = [bool]($hc -or $ioc.Count -or @($orgRel | Where-Object { "$($_.DomainNames)" -match 'outlook\.com|office365|onmicrosoft' }).Count)
    Add-CEREvidence -Control 'M365-05' -Flag $(if ($isHybrid) { 'Info' } else { 'Info' }) -Action 'Confirm the hybrid configuration still reflects reality. A HybridConfiguration object left in place after a completed migration keeps stale connectors and organisation relationships alive; one missing where hybrid is in use means the HCW has not been re-run after a change and free/busy or mail flow will fail in ways that look intermittent.' -Evidence ("Hybrid configuration on-prem: {0}. HCW features: {1}. Hybrid domains: {2}. Organisation relationships: {3}. Intra-organisation connectors: {4} ({5}). Migration endpoints: {6}." -f $(if ($isHybrid) { 'present' } else { 'no HybridConfiguration object - either never configured, or removed after decommission' }), $(if ($hc) { (Join-CERList @($hc.Features)) } else { '-' }), $(if ($hc) { (Join-CERList @($hc.Domains)) } else { '-' }), (Join-CERList ($orgRel | ForEach-Object { "{0} (enabled={1}, free/busy={2}, moves={3})" -f $_.Name, $_.Enabled, $_.FreeBusyAccessEnabled, $_.MailboxMoveEnabled }) 3), $ioc.Count, (Join-CERList ($ioc | ForEach-Object { "{0} (enabled={1})" -f $_.Name, $_.Enabled }) 3), (Join-CERList ($migEnd | ForEach-Object { "{0}={1}" -f $_.Identity, $_.EndpointType }) 3))
    Add-CEREvidence -Control 'IAM-01' -Flag Info -Action 'Record the federation trust and OAuth server configuration in STACK.md and cross-check the sync side against the Entra collector. This is the plumbing that makes free/busy, mailbox moves and cross-premises delegation work; nobody documents it until it breaks, and it breaks silently.' -Evidence ("Hybrid identity plumbing on-prem: federation trust {0}; OAuth auth servers configured: {1} ({2}). Cross-check the Entra collector for the sync side (Entra Connect / Cloud Sync)." -f $(if ($fed) { "'$($fed.Name)' (app uri $($fed.ApplicationUri))" } else { 'none (modern hybrid / OAuth-only, or never configured)' }), $authServers.Count, (Join-CERList ($authServers | ForEach-Object { "{0} [{1}, enabled={2}]" -f $_.Name, $_.Type, $_.Enabled }) 4))

    # The OAuth (Auth) certificate is the one that silently breaks hybrid free/busy, OWA and ECP sign-in when it expires.
    if ($authCfg) {
        $days = if ($authCur) { Get-CERAgeDays $authCur.NotAfter } else { $null }
        $daysLeft = if ($null -ne $days) { - $days } else { $null }
        $flag = if (-not $authCur) { 'Attention' } elseif ($daysLeft -lt 0) { 'Attention' } elseif ($daysLeft -lt $CertExpiryWarnDays) { 'Attention' } else { 'OK' }
        Add-CEREvidence -Control 'SRV-10' -Flag $flag -Action 'Rotate the Exchange OAuth certificate before it expires, staging the new one at least 48 hours ahead with Set-AuthConfig so it replicates to every server. When this certificate expires, hybrid free/busy stops and Outlook on the web and ECP sign-in fail - with no warning and no obvious link back to a certificate.' -Evidence ("Exchange OAuth (Auth) certificate: {0}. IsValid={1}. Next certificate staged: {2}. An expired Auth certificate breaks hybrid free/busy and Outlook on the web / ECP sign-in with no other warning - rotate at least 48 h before expiry (Set-AuthConfig -NewCertificateThumbprint ... -NewCertificateEffectiveDate)." -f $(if ($authCur) { "thumbprint {0}, expires {1:yyyy-MM-dd} ({2} days)" -f $authCur.Thumbprint, $authCur.NotAfter, $daysLeft } else { "thumbprint $($authCfg.CurrentCertificateThumbprint) is configured but the certificate was NOT found on this server" }), $authCfg.IsValid, $(if ($authNext) { "{0}, effective {1}" -f $authNext.Thumbprint, $authCfg.NewCertificateEffectiveDate } else { 'none' }))
    }
}

# ---------------- Mail flow: connectors, relay, transport rules, domains
Invoke-CERSection -Collector $C -Section 'MailFlow' -Script {
    $send = @(Get-SendConnector -ErrorAction SilentlyContinue | Select-Object Name, Enabled, AddressSpaces, SmartHosts, DNSRoutingEnabled, TlsAuthLevel, RequireTLS, TlsCertificateName, SourceTransportServers, FrontendProxyEnabled)
    $recv = @(Get-ReceiveConnector -ErrorAction SilentlyContinue | Select-Object Identity, Server, Name, Enabled, Bindings, RemoteIPRanges, PermissionGroups, AuthMechanism, TransportRole, RequireTLS, TlsDomainCapabilities, MaxMessageSize)
    $tc = $null; try { $tc = Get-TransportConfig -ErrorAction Stop | Select-Object InternalSMTPServers, MaxReceiveSize, MaxSendSize, TLSReceiveDomainSecureList, TLSSendDomainSecureList } catch { }
    $script:acceptedDomains = @(Get-AcceptedDomain -ErrorAction SilentlyContinue | Select-Object DomainName, DomainType, Default, AddressBookEnabled)
    $remote = @(Get-RemoteDomain -ErrorAction SilentlyContinue | Select-Object DomainName, AutoForwardEnabled, AutoReplyEnabled, TNEFEnabled)
    $rules = @(Get-TransportRule -ErrorAction SilentlyContinue | Select-Object Name, State, Priority, Mode, RedirectMessageTo, BlindCopyTo, CopyTo, SetSCL, FromScope, SentToScope, WhenChanged)
    $eap = @(Get-EmailAddressPolicy -ErrorAction SilentlyContinue | Select-Object Name, Priority, EnabledEmailAddressTemplates, RecipientFilter)

    # Anonymous relay is granted two ways (Microsoft Learn, "Allow anonymous relay on Exchange servers"):
    #   1. PermissionGroups AnonymousUsers + ms-Exch-SMTP-Accept-Any-Recipient granted to NT AUTHORITY\ANONYMOUS LOGON
    #   2. AuthMechanism ExternalAuthoritative + PermissionGroups ExchangeServers (externally secured)
    $relay = @()
    foreach ($rc in $recv) {
        $anonAny = $false
        try { $anonAny = [bool](@(Get-ADPermission -Identity $rc.Identity -ErrorAction Stop | Where-Object { "$($_.User)" -match 'ANONYMOUS LOGON' -and "$($_.ExtendedRights)" -match 'ms-Exch-SMTP-Accept-Any-Recipient' })).Count } catch { }
        $extSecured = ("$($rc.AuthMechanism)" -match 'ExternalAuthoritative' -and "$($rc.PermissionGroups)" -match 'ExchangeServers')
        if ($anonAny -or $extSecured) {
            $ranges = @($rc.RemoteIPRanges | ForEach-Object { "$_" })
            $wide = @($ranges | Where-Object { $_ -match '^0\.0\.0\.0' -or $_ -match '^::-' -or $_ -eq '0.0.0.0-255.255.255.255' })
            $relay += [pscustomobject]@{ Connector = "$($rc.Identity)"; Server = "$($rc.Server)"; Method = $(if ($anonAny) { 'anonymous + accept-any-recipient' } else { 'externally secured' }); Enabled = $rc.Enabled; Ranges = $ranges.Count; Unrestricted = [bool]$wide.Count; Sample = (Join-CERList $ranges 4) }
        }
    }
    Save-CERRaw -Name 'mailflow' -Object ([ordered]@{ SendConnectors = $send; ReceiveConnectors = $recv; RelayConnectors = $relay; TransportConfig = $tc; AcceptedDomains = $script:acceptedDomains; RemoteDomains = $remote; TransportRules = $rules; EmailAddressPolicies = $eap })

    $openRelay = @($relay | Where-Object { $_.Enabled -and $_.Unrestricted })
    $flag = if ($openRelay.Count) { 'Attention' } elseif ($relay.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'M365-03' -Flag $flag -Action 'Scope every anonymous relay connector to named device IP addresses and review whether each still needs to exist. An unrestricted relay connector accepting from 0.0.0.0-255.255.255.255 is an open relay: anything that can reach port 25 can send mail as the client''s domain, which damages the domain reputation the SPF and DMARC work is meant to protect.' -Evidence ("On-prem receive connectors: {0} ({1} enabled). Connectors permitting anonymous relay: {2} - {3}. Of those, {4} accept from ANY source address (0.0.0.0-255.255.255.255), which is an open relay reachable by anything that can route to port 25. Every relay connector should be scoped to named device IPs and reviewed against what still needs it." -f $recv.Count, @($recv | Where-Object Enabled).Count, $relay.Count, (Join-CERList ($relay | ForEach-Object { "{0} on {1} [{2}, {3} range(s): {4}]" -f $_.Connector, $_.Server, $_.Method, $_.Ranges, $_.Sample }) 6), $openRelay.Count)
    $noTls = @($send | Where-Object { $_.Enabled -and -not $_.RequireTLS -and "$($_.AddressSpaces)" -notmatch '^\s*$' })
    Add-CEREvidence -Control 'M365-03' -Flag Info -Action 'Confirm the send connectors require TLS and route where they are supposed to. A connector not requiring TLS sends mail in clear text across the internet; one with an unexpected smart host is worth investigating rather than assuming, because it is also how mail gets quietly copied elsewhere.' -Evidence ("On-prem send connectors: {0} - {1}. Smart-host routing (a gateway or Exchange Online in front): {2}. Connectors not requiring TLS: {3}." -f $send.Count, (Join-CERList ($send | ForEach-Object { "{0} -> {1}" -f $_.Name, $(if ("$($_.SmartHosts)") { "$($_.SmartHosts)" } else { 'DNS/MX' }) }) 5), @($send | Where-Object { "$($_.SmartHosts)" }).Count, (Join-CERList ($noTls | ForEach-Object { $_.Name }) 5))
    Add-CEREvidence -Control 'M365-02' -Flag Info -Action 'Cross-check these accepted domains against the SPF records in the DNS collector. Anything sending from these domains through this server must be authorised in SPF, or it will be quarantined - and this server is exactly the sender that gets forgotten when SPF is written for the cloud tenant.' -Evidence ("On-prem accepted domains: {0} ({1} authoritative, {2} internal relay): {3}. Anything sending from these domains through this server must be covered by the SPF record - see the DNS collector. Email address policies: {4}." -f $script:acceptedDomains.Count, @($script:acceptedDomains | Where-Object { $_.DomainType -eq 'Authoritative' }).Count, @($script:acceptedDomains | Where-Object { $_.DomainType -eq 'InternalRelay' }).Count, (Join-CERList ($script:acceptedDomains | ForEach-Object { "{0} [{1}]" -f $_.DomainName, $_.DomainType }) 6), $eap.Count)
    $fwdRules = @($rules | Where-Object { $_.State -eq 'Enabled' -and ($_.RedirectMessageTo -or $_.BlindCopyTo -or $_.CopyTo) })
    $rdOpen = @($remote | Where-Object { $_.AutoForwardEnabled })
    Add-CEREvidence -Control 'M365-04' -Flag $(if ($fwdRules.Count -or $rdOpen.Count) { 'Attention' } else { 'OK' }) -Action 'Review the on-prem transport rules alongside the Exchange Online ones. In hybrid both rule sets apply depending on the route a message takes, so a rule that exists in one and not the other produces behaviour that looks random and is very hard to diagnose from the user''s description.' -Evidence ("On-prem transport rules: {0} ({1} enabled); rules that redirect/BCC/copy mail: {2} ({3}); remote domains allowing auto-forward: {4} ({5}). These are separate from the Exchange Online rules the Exchange collector reports - in hybrid both sets apply depending on the route." -f $rules.Count, @($rules | Where-Object { $_.State -eq 'Enabled' }).Count, $fwdRules.Count, (Join-CERList ($fwdRules | ForEach-Object { $_.Name }) 4), $rdOpen.Count, (Join-CERList ($rdOpen | ForEach-Object { $_.DomainName }) 4))
}

# ---------------- Client access: what is published, and how it authenticates
Invoke-CERSection -Collector $C -Section 'ClientAccess' -Script {
    function _vdir { param([string]$Cmd, [string]$Label)
        $out = @()
        try {
            foreach ($v in @(& $Cmd -ErrorAction Stop)) {
                $out += [pscustomobject]@{ Type = $Label; Server = "$($v.Server)"; Name = "$($v.Name)"
                    InternalUrl = "$($v.InternalUrl)"; ExternalUrl = "$($v.ExternalUrl)"
                    InternalAuth = (@($v.InternalAuthenticationMethods) -join '/'); ExternalAuth = (@($v.ExternalAuthenticationMethods) -join '/')
                    BasicAuth = $(if ($null -ne $v.BasicAuthentication) { [bool]$v.BasicAuthentication } else { $null })
                    WindowsAuth = $(if ($null -ne $v.WindowsAuthentication) { [bool]$v.WindowsAuthentication } else { $null }) }
            }
        } catch { }
        return $out
    }
    $vdirs = @()
    $vdirs += _vdir 'Get-OwaVirtualDirectory' 'OWA'
    $vdirs += _vdir 'Get-EcpVirtualDirectory' 'ECP'
    $vdirs += _vdir 'Get-WebServicesVirtualDirectory' 'EWS'
    $vdirs += _vdir 'Get-MapiVirtualDirectory' 'MAPI'
    $vdirs += _vdir 'Get-ActiveSyncVirtualDirectory' 'ActiveSync'
    $vdirs += _vdir 'Get-OabVirtualDirectory' 'OAB'
    $vdirs += _vdir 'Get-AutodiscoverVirtualDirectory' 'Autodiscover'
    $oa = @(); try { $oa = @(Get-OutlookAnywhere -ErrorAction Stop | Select-Object Server, ExternalHostname, InternalHostname, ExternalClientAuthenticationMethod, InternalClientAuthenticationMethod, IISAuthenticationMethods, ExternalClientsRequireSsl, SSLOffloading) } catch { }
    $pop = @(); try { $pop = @(Get-PopSettings -ErrorAction Stop | Select-Object Server, LoginType, ProtocolLogEnabled, UnencryptedOrTLSBindings) } catch { }
    $imap = @(); try { $imap = @(Get-ImapSettings -ErrorAction Stop | Select-Object Server, LoginType, ProtocolLogEnabled, UnencryptedOrTLSBindings) } catch { }
    Save-CERRaw -Name 'clientaccess' -Object ([ordered]@{ VirtualDirectories = $vdirs; OutlookAnywhere = $oa; Pop = $pop; Imap = $imap })

    $published = @($vdirs | Where-Object { $_.ExternalUrl -and $_.ExternalUrl -ne '' })
    $extHosts = @($published | ForEach-Object { try { ([uri]$_.ExternalUrl).Host } catch { $null } } | Where-Object { $_ } | Select-Object -Unique)
    Add-CEREvidence -Control 'SRV-04' -Flag $(if ($published.Count) { 'Attention' } else { 'OK' }) -Action 'Establish what is genuinely reachable from the internet - firewall policy and NAT, not just the published URL - and reduce it to what the client actually needs. An internet-facing Exchange server on an unsupported build is the highest-value target in the estate; where hybrid only needs mail flow and free/busy, the Hybrid Agent removes the inbound requirement entirely.' -Evidence ("Exchange virtual directories with an external URL (published to the internet unless a gateway or the Hybrid Agent fronts them): {0}/{1} - {2}. External host names: {3}. An internet-facing Exchange server on an unsupported build is the single highest-value target in the estate; confirm what actually reaches it from outside (firewall policy, WAF, Hybrid Agent) rather than assuming the URL means exposure." -f $published.Count, $vdirs.Count, (Join-CERList (($published | Group-Object Type | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })) 8), (Join-CERList $extHosts 5))
    $basic = @($vdirs | Where-Object { $_.BasicAuth -eq $true -or $_.ExternalAuth -match 'Basic' })
    $oaBasic = @($oa | Where-Object { "$($_.ExternalClientAuthenticationMethod)" -match 'Basic' -or "$($_.IISAuthenticationMethods)" -match 'Basic' })
    $popOn = @($pop | Where-Object { "$($_.LoginType)" -ne 'SecureLogin' -or $_.UnencryptedOrTLSBindings })
    Add-CEREvidence -Control 'IAM-04' -Flag $(if ($basic.Count -or $oaBasic.Count) { 'Attention' } else { 'OK' }) -Action 'Disable Basic authentication on the virtual directories and Outlook Anywhere, and turn off POP and IMAP where nothing depends on them. On-prem Exchange has no Conditional Access, so blocking legacy authentication in Entra does not cover these paths - they remain a live credential-stuffing surface with no MFA in front of them.' -Evidence ("Legacy authentication on-prem: virtual directories offering Basic auth: {0} ({1}); Outlook Anywhere with Basic: {2} ({3}); POP settings: {4}; IMAP settings: {5}. On-prem Exchange has no Conditional Access - blocking legacy auth in Entra does not cover these paths, so Basic here is a live credential-stuffing surface." -f $basic.Count, (Join-CERList ($basic | ForEach-Object { "{0}@{1}" -f $_.Type, $_.Server }) 6), $oaBasic.Count, (Join-CERList ($oaBasic | ForEach-Object { $_.Server }) 3), (Join-CERList ($pop | ForEach-Object { "{0}={1}" -f $_.Server, $_.LoginType }) 3), (Join-CERList ($imap | ForEach-Object { "{0}={1}" -f $_.Server, $_.LoginType }) 3))
    $offload = @($oa | Where-Object { $_.SSLOffloading })
    if ($offload.Count) { Add-CEREvidence -Control 'SRV-04' -Flag Attention -Action 'Disable SSL offloading for Outlook Anywhere (Set-OutlookAnywhere -SSLOffloading $false) before enabling Extended Protection. Any TLS termination in front of Exchange is treated as a man-in-the-middle by the channel-binding check, so leaving offloading on means Extended Protection breaks clients rather than protecting them.' -Evidence ("Outlook Anywhere SSL offloading is enabled on {0} server(s): {1}. SSL offloading must be off before Extended Protection can work - any TLS termination in front of Exchange is treated as a man-in-the-middle and fails the channel-binding check." -f $offload.Count, (Join-CERList ($offload | ForEach-Object { $_.Server }))) }
}

# ---------------- Certificates, Extended Protection, TLS
Invoke-CERSection -Collector $C -Section 'SecurityPosture' -Script {
    $certs = @()
    try { $certs = @(Get-ExchangeCertificate -ErrorAction Stop | Select-Object @{n = 'Server'; e = { "$($_.Identity)".Split('\')[0] } }, Thumbprint, Subject, @{n = 'Names'; e = { (@($_.CertificateDomains) -join ';') } }, @{n = 'Svc'; e = { "$($_.Services)" } }, NotBefore, NotAfter, IsSelfSigned, Status) } catch { }
    $expired = @($certs | Where-Object { $_.NotAfter -and $_.NotAfter -lt $now })
    $soon = @($certs | Where-Object { $_.NotAfter -and $_.NotAfter -ge $now -and $_.NotAfter -lt $now.AddDays($CertExpiryWarnDays) })
    $selfSignedInUse = @($certs | Where-Object { $_.IsSelfSigned -and "$($_.Svc)" -match 'IIS' })

    # Extended Protection lives in IIS, not in an Exchange cmdlet. Recommended values per Microsoft Learn
    # ("Configure Windows Extended Protection in Exchange Server"): Default Web Site - API/ECP/MAPI/OWA
    # Required, EWS/ActiveSync/OAB Allow, AutoDiscover None. Enabled by default from Exchange 2019 CU14.
    $ep = @(); $epUnreachable = @()
    if (-not $SkipIisChecks -and -not $SkipServerRemote) {
        $targets = @($script:servers | Where-Object { $_.Roles -notmatch 'Edge' } | ForEach-Object { $_.Name })
        foreach ($n in $targets) {
            try {
                $r = Invoke-Command -ComputerName $n -ErrorAction Stop -ScriptBlock {
                    Import-Module WebAdministration -ErrorAction Stop
                    $out = @()
                    foreach ($site in 'Default Web Site', 'Exchange Back End') {
                        foreach ($v in 'API', 'Autodiscover', 'ecp', 'EWS', 'mapi', 'Microsoft-Server-ActiveSync', 'OAB', 'owa', 'PowerShell', 'RPC') {
                            $f = "IIS:\Sites\$site\$v"
                            if (-not (Test-Path $f)) { continue }
                            $val = $null; $ssl = $null
                            try { $val = (Get-WebConfigurationProperty -Filter 'system.webServer/security/authentication/windowsAuthentication' -Location "$site/$v" -Name 'extendedProtection.tokenChecking' -ErrorAction Stop).Value } catch { }
                            try { $ssl = (Get-WebConfigurationProperty -Filter 'system.webServer/security/access' -Location "$site/$v" -Name 'sslFlags' -ErrorAction Stop).Value } catch { }
                            $out += [pscustomobject]@{ Server = $env:COMPUTERNAME; Site = $site; VDir = $v; TokenChecking = "$val"; SslFlags = "$ssl" }
                        }
                    }
                    $out
                }
                $ep += @($r)
            } catch { $epUnreachable += $n }
        }
    }
    $tls = @(); $tlsUnreachable = @()
    if (-not $SkipServerRemote) {
        foreach ($n in @($script:servers | ForEach-Object { $_.Name })) {
            try {
                $tls += Invoke-Command -ComputerName $n -ErrorAction Stop -ScriptBlock {
                    function _r { param($p, $n2) try { (Get-ItemProperty -Path $p -Name $n2 -ErrorAction Stop).$n2 } catch { $null } }
                    $b = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
                    [ordered]@{ Server = $env:COMPUTERNAME
                        TLS10Server = (_r "$b\TLS 1.0\Server" 'Enabled'); TLS11Server = (_r "$b\TLS 1.1\Server" 'Enabled'); TLS12Server = (_r "$b\TLS 1.2\Server" 'Enabled')
                        NetStrongCrypto = (_r 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto')
                        LmCompatibilityLevel = (_r 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel') }
                }
            } catch { $tlsUnreachable += $n }
        }
    }
    $overrides = @(); try { $overrides = @(Get-SettingOverride -ErrorAction Stop | Select-Object Name, ComponentName, SectionName, Parameters, Server, Status, Reason) } catch { }
    Save-CERRaw -Name 'security' -Object ([ordered]@{ Certificates = $certs; ExtendedProtection = $ep; ExtendedProtectionUnreachable = $epUnreachable; Tls = $tls; TlsUnreachable = $tlsUnreachable; SettingOverrides = $overrides })

    $certFlag = if ($expired.Count -or $selfSignedInUse.Count) { 'Attention' } elseif ($soon.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'SRV-10' -Flag $certFlag -Action 'Renew the expired and near-expiry certificates, and replace any self-signed certificate bound to IIS with one from a trusted CA. A self-signed certificate on a client-facing service trains users to click through certificate warnings, which is the habit that makes interception attacks work.' -Evidence ("Exchange certificates: {0} across {1} server(s). Expired: {2} ({3}). Expiring within {4} days: {5} ({6}). Self-signed but bound to IIS (clients will see a name/trust error): {7} ({8})." -f $certs.Count, @($certs | ForEach-Object { $_.Server } | Select-Object -Unique).Count, $expired.Count, (Join-CERList ($expired | ForEach-Object { "{0} on {1} ({2:yyyy-MM-dd})" -f $_.Subject, $_.Server, $_.NotAfter }) 4), $CertExpiryWarnDays, $soon.Count, (Join-CERList ($soon | ForEach-Object { "{0} on {1} ({2:yyyy-MM-dd}, services {3})" -f $_.Subject, $_.Server, $_.NotAfter, $_.Svc }) 4), $selfSignedInUse.Count, (Join-CERList ($selfSignedInUse | ForEach-Object { "{0} on {1}" -f $_.Subject, $_.Server }) 3))

    if ($ep.Count) {
        $want = @{ 'API' = 'Require'; 'ecp' = 'Require'; 'mapi' = 'Require'; 'owa' = 'Require'; 'EWS' = 'Allow'; 'Microsoft-Server-ActiveSync' = 'Allow'; 'OAB' = 'Allow'; 'Autodiscover' = 'None' }
        $front = @($ep | Where-Object { $_.Site -eq 'Default Web Site' -and $want.ContainsKey($_.VDir) })
        $off = @($front | Where-Object { $want[$_.VDir] -ne 'None' -and ($_.TokenChecking -eq 'None' -or -not $_.TokenChecking) })
        $wrong = @($front | Where-Object { $want[$_.VDir] -ne 'None' -and $_.TokenChecking -and $_.TokenChecking -ne 'None' -and $_.TokenChecking -ne $want[$_.VDir] })
        Add-CEREvidence -Control 'SRV-04' -Flag $(if ($off.Count) { 'Attention' } else { 'OK' }) -Action 'Enable Extended Protection using the Microsoft script (aka.ms/ExchangeEPScript) rather than by hand - it validates the prerequisites and applies consistent values across every server. Extended Protection is the mitigation for the authentication-relay attacks that Exchange has been repeatedly exploited through, and it is on by default from Exchange 2019 CU14, so a value of None needs a documented reason.' -Evidence ("Windows Extended Protection on the front-end virtual directories: {0}/{1} at the value Microsoft recommends; {2} still set to None ({3}); {4} set to a different value than recommended ({5}). Extended Protection is the mitigation for authentication-relay attacks against Exchange and is on by default from Exchange 2019 CU14 - anything at None on OWA, ECP, MAPI or API needs a reason. Configure with aka.ms/ExchangeEPScript, not by hand. Servers unreachable over WinRM: {6}." -f ($front.Count - $off.Count - $wrong.Count), $front.Count, $off.Count, (Join-CERList ($off | ForEach-Object { "{0}@{1}" -f $_.VDir, $_.Server }) 6), $wrong.Count, (Join-CERList ($wrong | ForEach-Object { "{0}@{1}={2} (want {3})" -f $_.VDir, $_.Server, $_.TokenChecking, $want[$_.VDir] }) 4), (Join-CERList $epUnreachable))
    } else {
        Add-CEREvidence -Control 'SRV-04' -Flag Unknown -Action 'Run the Exchange Health Checker (aka.ms/ExchangeHealthChecker) on each server, or re-run this collector with WinRM reachable and the WebAdministration module present. Extended Protection is an IIS setting rather than an Exchange one, so it cannot be read from the Exchange cmdlets - and unread must not be scored as configured.' -Evidence ("Extended Protection state not read{0}. It is an IIS setting, not an Exchange one - run aka.ms/ExchangeHealthChecker on each server, or re-run this collector with WinRM reachable and the WebAdministration module present." -f $(if ($SkipIisChecks) { ' (-SkipIisChecks)' } elseif ($epUnreachable.Count) { (' - unreachable: ' + (Join-CERList $epUnreachable)) } else { '' }))
    }

    if ($tls.Count) {
        $t10 = @($tls | Where-Object { $_.TLS10Server -ne 0 }); $t11 = @($tls | Where-Object { $_.TLS11Server -ne 0 }); $t12off = @($tls | Where-Object { $_.TLS12Server -eq 0 })
        $ntlm = @($tls | Where-Object { $null -eq $_.LmCompatibilityLevel -or $_.LmCompatibilityLevel -lt 3 })
        $mixed = (@($tls | ForEach-Object { "{0}/{1}/{2}" -f $_.TLS10Server, $_.TLS11Server, $_.TLS12Server } | Select-Object -Unique).Count -gt 1)
        Add-CEREvidence -Control 'SRV-04' -Flag $(if ($t10.Count -or $t11.Count -or $t12off.Count -or $mixed -or $ntlm.Count) { 'Attention' } else { 'OK' }) -Action 'Make the TLS configuration identical across every Exchange server before enabling Extended Protection - an inconsistent configuration breaks client connections once EP is on, which is the most common cause of a rollback. Disable TLS 1.0 and 1.1 explicitly rather than relying on OS defaults, and set LmCompatibilityLevel to at least 3.' -Evidence ("Exchange server TLS/NTLM: TLS 1.0 not explicitly disabled on {0} server(s) ({1}); TLS 1.1 on {2}; TLS 1.2 explicitly disabled on {3}; LmCompatibilityLevel below 3 on {4}. TLS settings identical across all Exchange servers: {5} - an inconsistent TLS configuration breaks client connections once Extended Protection is enabled, so it must be fixed first. Unreachable: {6}." -f $t10.Count, (Join-CERList ($t10 | ForEach-Object { $_.Server }) 4), $t11.Count, $t12off.Count, $ntlm.Count, $(if ($mixed) { 'NO' } else { 'yes' }), (Join-CERList $tlsUnreachable))
    }
    if ($overrides.Count) { Add-CEREvidence -Control 'SRV-04' -Flag Info -Action 'Document why each setting override exists and whether it is still needed. Overrides alter shipped behaviour, sometimes including security mitigations added by a security update, and they persist silently through CU installs long after the problem they worked around was fixed.' -Evidence ("Exchange setting overrides in place: {0}. Overrides disable or alter shipped behaviour (including some security mitigations) and are easy to forget - each one needs a documented reason: {1}." -f $overrides.Count, (Join-CERList ($overrides | ForEach-Object { "{0} [{1}/{2}]" -f $_.Name, $_.ComponentName, $_.SectionName }) 6)) }
}

# ---------------- Recipients, databases and what is actually still hosted here
Invoke-CERSection -Collector $C -Section 'RecipientsAndDatabases' -Script {
    $mbx = @(); $mbxCapped = $false
    try {
        $mbx = @(Get-Mailbox -ResultSize $MaxMailboxes -ErrorAction Stop | Select-Object Name, PrimarySmtpAddress, RecipientTypeDetails, Database, WhenCreated, HiddenFromAddressListsEnabled, ForwardingAddress, ForwardingSmtpAddress, AuditEnabled, LitigationHoldEnabled)
        $mbxCapped = ($mbx.Count -ge $MaxMailboxes)
    } catch { }
    $arb = @(); try { $arb = @(Get-Mailbox -Arbitration -ErrorAction Stop | Select-Object Name, Database, PrimarySmtpAddress) } catch { }
    $remoteMbx = 0; try { $remoteMbx = @(Get-RemoteMailbox -ResultSize Unlimited -ErrorAction Stop).Count } catch { }
    $pfMbx = @(); try { $pfMbx = @(Get-Mailbox -PublicFolder -ErrorAction Stop | Select-Object Name, Database) } catch { }
    $pfCount = $null; try { $pfCount = @(Get-PublicFolder -Recurse -ResultSize 2000 -ErrorAction Stop).Count } catch { }
    $dbs = @(); try { $dbs = @(Get-MailboxDatabase -Status -ErrorAction Stop | Select-Object Name, Server, CircularLoggingEnabled, LastFullBackup, LastIncrementalBackup, DatabaseSize, AvailableNewMailboxSpace, Mounted, MasterServerOrAvailabilityGroup, RetainDeletedItemsUntilBackup) } catch { }
    $dag = @(); try { $dag = @(Get-DatabaseAvailabilityGroup -Status -ErrorAction Stop | Select-Object Name, Servers, WitnessServer, WitnessDirectory, ReplicationPort, PrimaryActiveManager) } catch { }
    $copies = @(); try { $copies = @(Get-MailboxDatabaseCopyStatus -Server '*' -ErrorAction Stop | Select-Object Name, Status, CopyQueueLength, ReplayQueueLength, ContentIndexState) } catch { }
    Save-CERRaw -Name 'recipients' -Object ([ordered]@{ MailboxSummary = @($mbx | Group-Object RecipientTypeDetails | ForEach-Object { [ordered]@{ Type = $_.Name; Count = $_.Count } }); MailboxesCapped = $mbxCapped; Arbitration = $arb; RemoteMailboxCount = $remoteMbx; PublicFolderMailboxes = $pfMbx; PublicFolderCount = $pfCount; Databases = $dbs; DAGs = $dag; Copies = $copies })

    $userMbx = @($mbx | Where-Object { $_.RecipientTypeDetails -in 'UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox' })
    $onlyArb = ($userMbx.Count -eq 0 -and $arb.Count -gt 0)
    Add-CEREvidence -Control 'M365-05' -Flag $(if ($userMbx.Count) { 'Attention' } else { 'Info' }) -Action 'Use this to decide the decommission path. Mailboxes still hosted here means the migration is incomplete and everything else in this section is live risk. No user mailboxes but arbitration mailboxes present means this is the last Exchange server kept for recipient management, which is a supported position only on Exchange Server SE or the management tools.' -Evidence ("Mailboxes still hosted on-prem: {0}{1} ({2}). Arbitration/system mailboxes: {3}. Mail-enabled users pointing at Exchange Online (RemoteMailbox): {4}. Public folder mailboxes: {5}, public folders: {6}. Position: {7}" -f $userMbx.Count, $(if ($mbxCapped) { " (capped at -MaxMailboxes $MaxMailboxes)" } else { '' }), (Join-CERList (@($mbx | Group-Object RecipientTypeDetails | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })) 6), $arb.Count, $remoteMbx, $pfMbx.Count, $(if ($null -ne $pfCount) { $pfCount } else { 'not read' }), $(if ($onlyArb) { 'management-only - no user mailboxes left, so this is a last-Exchange-server-for-recipient-management case. Exchange Server SE (or the management tools where supported) is the supported way to keep it; an out-of-support server kept only to edit recipient attributes is a large attack surface for a small job.' } elseif ($userMbx.Count) { 'still hosting production mailboxes - migration to Exchange Online is not complete, so version currency and internet exposure are live operational risks, not just tidy-up.' } else { 'no mailboxes and no arbitration mailboxes found - check the collector reached the right organisation.' }))

    if ($dbs.Count) {
        $noBackup = @($dbs | Where-Object { -not $_.LastFullBackup })
        $staleBackup = @($dbs | Where-Object { $_.LastFullBackup -and (Get-CERAgeDays $_.LastFullBackup) -gt 7 })
        $circ = @($dbs | Where-Object { $_.CircularLoggingEnabled })
        Add-CEREvidence -Control 'BDR-06' -Flag $(if ($noBackup.Count -or $staleBackup.Count) { 'Attention' } else { 'OK' }) -Action 'Get an Exchange-aware backup running against any database with no LastFullBackup, and turn off circular logging where point-in-time recovery matters. No LastFullBackup means no backup has ever truncated the logs - the transaction logs will grow until the volume fills, and there is no supported restore path in the meantime. Cross-check against the Veeam collector''s application-aware processing.' -Evidence ("Exchange mailbox databases: {0}. Never backed up (no LastFullBackup - so no Exchange-aware backup has ever truncated the logs): {1} ({2}). Last full backup older than 7 days: {3} ({4}). Circular logging enabled on {5} ({6}) - circular logging discards the transaction logs, so point-in-time recovery between backups is not possible. Cross-check against the Veeam collector's application-aware processing." -f $dbs.Count, $noBackup.Count, (Join-CERList ($noBackup | ForEach-Object { $_.Name }) 5), $staleBackup.Count, (Join-CERList ($staleBackup | ForEach-Object { "{0} ({1:yyyy-MM-dd})" -f $_.Name, $_.LastFullBackup }) 5), $circ.Count, (Join-CERList ($circ | ForEach-Object { $_.Name }) 5))
        $unmounted = @($dbs | Where-Object { $_.Mounted -eq $false })
        $badCopies = @($copies | Where-Object { "$($_.Status)" -notin 'Healthy', 'Mounted' -or "$($_.ContentIndexState)" -notin 'Healthy', 'HealthyAndUpgrading', '' })
        Add-CEREvidence -Control 'SRV-09' -Flag $(if ($unmounted.Count -or $badCopies.Count) { 'Attention' } else { 'Info' }) -Action 'Investigate any unmounted database or unhealthy copy. A failed content index makes search silently return nothing rather than erroring, which users report as missing email; a copy queue that is growing means the DAG is not actually providing the resilience it appears to.' -Evidence ("Exchange databases: {0} ({1} unmounted: {2}). Database availability groups: {3} ({4}). Copies not healthy: {5} ({6})." -f (Join-CERList ($dbs | ForEach-Object { "{0}@{1}" -f $_.Name, $_.Server }) 8), $unmounted.Count, (Join-CERList ($unmounted | ForEach-Object { $_.Name }) 4), $dag.Count, (Join-CERList ($dag | ForEach-Object { "{0} (witness {1})" -f $_.Name, $_.WitnessServer }) 3), $badCopies.Count, (Join-CERList ($badCopies | ForEach-Object { "{0}={1}/index {2}" -f $_.Name, $_.Status, $_.ContentIndexState }) 5))
    }
    $fwd = @($mbx | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })
    $auditOff = @($mbx | Where-Object { $_.AuditEnabled -eq $false })
    if ($mbx.Count) { Add-CEREvidence -Control 'M365-04' -Flag $(if ($fwd.Count) { 'Attention' } else { 'OK' }) -Action 'Review mailbox forwarding on the remaining on-prem mailboxes and turn on mailbox auditing where it is off. These mailboxes are outside the Exchange Online auditing and Defender policies entirely, so whatever is configured in the tenant does not apply to them.' -Evidence ("On-prem mailbox hygiene: {0} mailboxes with forwarding set ({1}); mailbox auditing off on {2}/{3}; litigation hold on {4}." -f $fwd.Count, (Join-CERList ($fwd | ForEach-Object { "{0} -> {1}" -f $_.PrimarySmtpAddress, $(if ($_.ForwardingSmtpAddress) { $_.ForwardingSmtpAddress } else { $_.ForwardingAddress }) }) 5), $auditOff.Count, $mbx.Count, @($mbx | Where-Object LitigationHoldEnabled).Count) }
}

if ($script:exSession) { try { Remove-PSSession -Session $script:exSession -ErrorAction SilentlyContinue } catch { } }
Complete-CERCollector

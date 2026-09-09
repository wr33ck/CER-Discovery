#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (optional, BETA): NetScaler (Citrix ADC) / Citrix Gateway via the NITRO REST API with a
  read-only account. Feeds NET-02, NET-04, NET-05, SRV-10, SRV-14, LIC-02 and LIC-03.

.DESCRIPTION
  NITRO config objects mirror the CLI tree: 'show ns version' -> config/nsversion, 'show ha node' -> config/hanode.
  Confirmed from Citrix developer documentation: the /nitro/v1/config/ base, the login object for session auth,
  and config/lbvserver, config/sslvserver, config/sslcertkey, config/vpnvserver. Other paths are derived from the
  CLI tree and may differ between firmware branches - anything the appliance does not expose is reported as a
  coverage gap, not an error. Same beta caveat as the FortiGate collector, and for the same reason.

  Read-only: GET only, plus the POST that opens the login session and the one that closes it. Nothing is saved
  to the appliance (no 'save ns config'), so nothing here survives an appliance reboot.

  Use a read-only NetScaler account (command policy 'read-only'), not nsroot.

.EXAMPLE
  $c = Get-Credential                              # a read-only NetScaler account
  .\Get-CERNetScaler.ps1 -Client C-003 -RunId 20260905-0900 -NetScaler 10.0.0.5 -Credential $c -SkipCertificateCheck
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [Parameter(Mandatory)][string]$NetScaler,
    [int]$Port = 443,
    [Parameter(Mandatory)][pscredential]$Credential,
    [switch]$UseHttp,
    [switch]$SkipCertificateCheck,
    [int]$CertExpiryWarningDays = 60
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'NetScaler' -RunId $RunId
$C = 'NetScaler'
$scheme = 'https'; if ($UseHttp) { $scheme = 'http' }
$base = ("{0}://{1}:{2}/nitro/v1/" -f $scheme, $NetScaler, $Port)
if ($PSVersionTable.PSVersion.Major -lt 6) {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol } catch { }
    if ($SkipCertificateCheck) { try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch { } }
}
$script:sessionId = $null

function Invoke-NS {
    param([string]$Path, [string]$Method = 'GET', $Body, [switch]$Config)
    $seg = 'config/'; if (-not $Config -and $Path -match '^stat/') { $seg = '' }
    $u = $base + $(if ($Path -match '^(config|stat)/') { $Path } else { $seg + $Path })
    $h = @{}
    if ($script:sessionId) { $h['Cookie'] = ("NITRO_AUTH_TOKEN={0}" -f $script:sessionId) }
    $p = @{ Uri = $u; Method = $Method; Headers = $h; ErrorAction = 'Stop'; TimeoutSec = 40; ContentType = 'application/json' }
    if ($Body) { $p['Body'] = ($Body | ConvertTo-Json -Depth 6 -Compress) }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $p['SkipCertificateCheck'] = $true }
    return Invoke-RestMethod @p
}
function Get-NS {
    <# GET one config object; returns the array under its own key, or @() when the firmware does not expose it. #>
    param([string]$Object, [string]$Key)
    $r = Invoke-NS -Path $Object
    $k = $Key; if (-not $k) { $k = ($Object -split '\?')[0] -replace '^.*/', '' }
    if ($r -and $r.PSObject.Properties[$k]) { return @($r.$k) }
    return @()
}

# ---------------- log in
Invoke-CERSection -Collector $C -Section 'Logon' -Script {
    $u = $Credential.UserName
    $pw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
    $r = Invoke-NS -Path 'login' -Method 'POST' -Body @{ login = @{ username = $u; password = $pw; timeout = 900 } }
    $pw = $null
    if ($r -and $r.PSObject.Properties['sessionid']) { $script:sessionId = $r.sessionid }
    if (-not $script:sessionId) { throw 'NITRO login returned no session id - check the account, its command policy, and that the NITRO API is reachable on this interface.' }
    Write-CERLog ("NITRO session opened to {0} as {1}" -f $NetScaler, $u)
}

# ---------------- platform, firmware, HA, licence
$script:version = ''
Invoke-CERSection -Collector $C -Section 'System' -Script {
    if (-not $script:sessionId) { Set-CERSectionResult -Status 'NoAccess' -Note 'no NITRO session'; return }
    $ver = @(); try { $ver = Get-NS 'nsversion' } catch { }
    $hw = @(); try { $hw = Get-NS 'nshardware' } catch { }
    $ha = @(); try { $ha = Get-NS 'hanode' } catch { }
    $lic = @(); try { $lic = Get-NS 'nslicense' } catch { }
    $feat = @(); try { $feat = Get-NS 'nsfeature' } catch { }
    $ips = @(); try { $ips = Get-NS 'nsip' } catch { }
    $users = @(); try { $users = Get-NS 'systemuser' } catch { }
    $sysparam = @(); try { $sysparam = Get-NS 'systemparameter' } catch { }
    $ntp = @(); try { $ntp = Get-NS 'ntpserver' } catch { }
    $syslog = @(); try { $syslog = Get-NS 'auditsyslogaction' } catch { }
    $vstr = ''
    if ($ver.Count) { $vstr = "$($ver[0].version)" }
    $script:version = $vstr
    $sup = Get-CERNetScalerSupport -Version $vstr
    Save-CERRaw -Name 'system' -Object ([ordered]@{
            Version = $ver; Support = $sup; Hardware = $hw
            HA = @($ha | Select-Object id, ipaddress, state, hastatus, hasync, masterstate, enaifaces, routemonitor)
            Licence = @($lic | Select-Object f_sslvpn_users, f_ns_type, modelid, licensingmode, isstandardlic, isenterpriselic, isplatinumlic)
            Features = $feat
            IPs = @($ips | Select-Object ipaddress, netmask, type, mgmtaccess, gui, ssh, snmp, telnet, restrictaccess)
            SystemUsers = @($users | Select-Object username, timeout, logging, externalauth)      # no password material is returned by NITRO
            SystemParameter = $sysparam; Ntp = $ntp; Syslog = @($syslog | Select-Object name, serverip, loglevel)
        })
    $haPrimary = @($ha | Where-Object { "$($_.state)" -imatch 'Primary' })
    $haOk = @($ha | Where-Object { "$($_.hastatus)" -imatch 'UP' -and "$($_.hasync)" -imatch 'ENABLED|SUCCESS' })
    $standalone = ($ha.Count -le 1)
    $mgmtOpen = @($ips | Where-Object { "$($_.type)" -imatch 'NSIP|SNIP' -and ("$($_.gui)" -imatch 'ENABLED' -or "$($_.ssh)" -imatch 'ENABLED' -or "$($_.telnet)" -imatch 'ENABLED') -and "$($_.restrictaccess)" -inotmatch 'ENABLED' })
    $telnet = @($ips | Where-Object { "$($_.telnet)" -imatch 'ENABLED' })
    $nsroot = @($users | Where-Object { "$($_.username)" -ieq 'nsroot' })
    $localUsers = @($users | Where-Object { "$($_.externalauth)" -imatch 'DISABLED' })
    $act = @()
    if ($sup.Note) { $act += $sup.Note }
    if ($standalone) { $act += 'This appliance is standalone. A NetScaler in front of a published-application farm is a single point of failure for every remote user at once - price an HA pair, and if the client declines, record the accepted risk against the RTO they have agreed' }
    elseif (-not $haOk.Count) { $act += ("HA is configured but not healthy - {0}. An HA pair that is not synchronising will fail over to a stale configuration, which is worse than not failing over at all" -f (Join-CERList ($ha | ForEach-Object { "{0}: state {1}, status {2}, sync {3}" -f $_.ipaddress, $_.state, $_.hastatus, $_.hasync }) 3)) }
    if ($telnet.Count) { $act += 'Disable Telnet on the management IP - it is cleartext, and on an appliance that terminates remote access it exposes an administrative credential to anyone on the management network' }
    if ($mgmtOpen.Count) { $act += ("Restrict management access on {0} (set the restrictaccess flag and put the management interface on a dedicated VLAN). NetScaler management interfaces have been the entry point in several actively exploited advisories, so reachability is the control that matters most here" -f (Join-CERList ($mgmtOpen | ForEach-Object { $_.ipaddress }) 4)) }
    if ($nsroot.Count) { $act += 'Confirm the nsroot password has been changed from the default and is in CyberArk, and move administrative logon to external authentication with MFA so nsroot is a break-glass account rather than the account everyone uses' }
    $flag = 'OK'
    if ($sup.Supported -eq $false -or $telnet.Count -or $mgmtOpen.Count) { $flag = 'Attention' }
    elseif ($standalone -or $sup.InMaintenance -eq $false -or $sup.LasCapable -eq $false) { $flag = 'Attention' }
    elseif ($null -eq $sup.Supported) { $flag = 'Unknown' }
    Add-CEREvidence -Control 'NET-02' -Flag $flag -Action (($act -join '. ') + '.') -Evidence ("NetScaler {0}: firmware {1} ({2}), support status {3}{4}. HA: {5} node(s), {6}. Management: {7} IP(s) with GUI/SSH/Telnet enabled and no access restriction ({8}); Telnet enabled on {9}. Local system users: {10} ({11} local-only); nsroot present: {12}. NTP servers: {13}; syslog targets: {14}." -f $NetScaler, $(if ($vstr) { $vstr } else { 'not readable' }), $sup.Family, $(if ($null -eq $sup.Supported) { 'unknown' } elseif ($sup.Supported) { 'in support' } else { 'PAST END OF LIFE' }), $(if ($sup.EndOfSupport) { (' to ' + $sup.EndOfSupport) } else { '' }), $ha.Count, $(if ($standalone) { 'standalone' } else { (Join-CERList ($ha | ForEach-Object { "{0}={1}/{2}/sync {3}" -f $_.ipaddress, $_.state, $_.hastatus, $_.hasync }) 3) }), $mgmtOpen.Count, (Join-CERList ($mgmtOpen | ForEach-Object { $_.ipaddress }) 3), $telnet.Count, $users.Count, $localUsers.Count, [bool]$nsroot.Count, (Join-CERList ($ntp | ForEach-Object { $_.serverip }) 3), (Join-CERList ($syslog | ForEach-Object { $_.serverip }) 3))

    Add-CEREvidence -Control 'LIC-02' -Flag $(if ($sup.Supported -eq $false) { 'Attention' } else { 'Info' }) -Action $(if ($sup.LasCapable -eq $false) { ("This build predates the License Activation Service minimum for its branch, and file-based licensing reached end of life on {0}. Plan the firmware upgrade before any hardware change, RMA or licence re-host - after that cutover the appliance cannot be re-licensed on the old model, so a failure becomes an outage with no quick licensing path out of it." -f $script:CERCitrixLasCutover) } else { 'Add the NetScaler model, firmware branch and its end-of-life date to the software lifecycle register alongside FortiOS and the hypervisor. Branch end-of-maintenance is the date that matters operationally - after it there are no new builds, so a new CVE has no fix.' }) -Evidence ("NetScaler {0} firmware {1}: branch {2}, build {3}, end of maintenance {4}, end of life {5}. LAS-capable build: {6}. Licence: {7}." -f $NetScaler, $vstr, $sup.Branch, $sup.Build, $(if ($sup.EndOfMaintenance) { $sup.EndOfMaintenance } else { 'n/a' }), $(if ($sup.EndOfSupport) { $sup.EndOfSupport } else { 'unknown' }), $(if ($null -eq $sup.LasCapable) { 'unknown' } else { $sup.LasCapable }), (Join-CERList ($lic | ForEach-Object { "model {0}, mode {1}, SSL VPN users {2}" -f $_.modelid, $_.licensingmode, $_.f_sslvpn_users }) 2))
}

# ---------------- Gateway / AAA vServers and how they authenticate
Invoke-CERSection -Collector $C -Section 'GatewayAndAuth' -Script {
    if (-not $script:sessionId) { Set-CERSectionResult -Status 'NoAccess' -Note 'no NITRO session'; return }
    $vpn = @(); try { $vpn = Get-NS 'vpnvserver' } catch { }
    $aaa = @(); try { $aaa = Get-NS 'authenticationvserver' } catch { }
    $lb = @(); try { $lb = Get-NS 'lbvserver' } catch { }
    $cs = @(); try { $cs = Get-NS 'csvserver' } catch { }
    $saml = @(); try { $saml = Get-NS 'authenticationsamlaction' } catch { }
    $radius = @(); try { $radius = Get-NS 'authenticationradiusaction' } catch { }
    $ldap = @(); try { $ldap = Get-NS 'authenticationldapaction' } catch { }
    $advPol = @(); try { $advPol = Get-NS 'authenticationpolicy' } catch { }
    $bindings = @()
    foreach ($v in $vpn) {
        $n = "$($v.name)"
        foreach ($obj in 'vpnvserver_authenticationsamlpolicy_binding', 'vpnvserver_authenticationldappolicy_binding', 'vpnvserver_authenticationradiuspolicy_binding', 'vpnvserver_authenticationpolicy_binding') {
            try {
                $r = Invoke-NS -Path ("{0}/{1}" -f $obj, [uri]::EscapeDataString($n))
                $k = $obj
                if ($r -and $r.PSObject.Properties[$k]) { foreach ($b in @($r.$k)) { $bindings += [pscustomobject]@{ VServer = $n; Type = ($obj -replace '^vpnvserver_authentication', '' -replace '_binding$', ''); Policy = "$($b.policy)$($b.policyname)" } } }
            } catch { }
        }
    }
    Save-CERRaw -Name 'gateway' -Object ([ordered]@{
            VpnVServers = @($vpn | Select-Object name, ipv46, port, state, vservertype, dtls, icaonly, doublehop, loginonce, authentication, certkeynames, tcpprofilename
            ); AaaVServers = @($aaa | Select-Object name, ipv46, port, state, authenticationdomain)
            LbVServers = @($lb | Select-Object name, ipv46, port, servicetype, state, effectivestate)
            CsVServers = @($cs | Select-Object name, ipv46, port, servicetype, state)
            SamlActions = @($saml | Select-Object name, samlidpcertname, samlredirecturl, samlissuername, signaturealg, digestmethod)
            RadiusActions = @($radius | Select-Object name, serverip, serverport, authtimeout, radnasip)     # no shared secret is returned by NITRO
            LdapActions = @($ldap | Select-Object name, serverip, serverport, sectype, ldaploginname, searchfilter)
            AdvancedPolicies = @($advPol | Select-Object name, rule, action)
            Bindings = $bindings
        })
    $up = @($vpn | Where-Object { "$($_.state)" -imatch 'UP' })
    $samlGw = @($bindings | Where-Object { $_.Type -imatch 'saml' } | Select-Object -ExpandProperty VServer -Unique)
    $ldapOnlyGw = @($up | Where-Object { $n = "$($_.name)"; ($samlGw -notcontains $n) -and -not (@($bindings | Where-Object { $_.VServer -eq $n -and $_.Type -imatch 'radius' }).Count) })
    $radiusGw = @($bindings | Where-Object { $_.Type -imatch 'radius' } | Select-Object -ExpandProperty VServer -Unique)
    $icaOnly = @($up | Where-Object { "$($_.icaonly)" -imatch 'ON' })
    $act = @()
    if ($ldapOnlyGw.Count) { $act += ("The Gateway vServer(s) {0} authenticate with LDAP alone - username and password against Active Directory, published on the internet, with no second factor. Bind a SAML policy to Entra so Conditional Access applies (device compliance, risk and MFA all come with it), or at minimum add RADIUS to an MFA provider. A Citrix Gateway without MFA is the single highest-value target the client publishes" -f (Join-CERList ($ldapOnlyGw | ForEach-Object { $_.name }) 4)) }
    if ($samlGw.Count) { $act += ("SAML authentication is bound on {0} - confirm the identity provider is Entra and that the Conditional Access policy behind it actually requires MFA and a compliant device, rather than just federating the logon" -f (Join-CERList $samlGw 3)) }
    if ($radiusGw.Count -and -not $samlGw.Count) { $act += 'RADIUS is bound for the second factor. Confirm what sits behind it - if it is NPS with the Entra MFA extension that is acceptable, but SAML to Entra is the better position because it brings device compliance and sign-in risk with it' }
    Add-CEREvidence -Control 'NET-05' -Flag $(if ($ldapOnlyGw.Count) { 'Attention' } elseif ($up.Count) { 'OK' } else { 'Info' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No Gateway vServer is up. If remote access to published applications is expected, confirm where it terminates.' }) -Evidence ("Citrix Gateway vServers: {0} ({1} up) - {2}. Authentication bound: SAML on {3} ({4}), RADIUS on {5} ({6}), LDAP-only on {7} ({8}). AAA vServers: {9}. SAML identity providers configured: {10}. RADIUS targets: {11}. LDAP targets: {12} ({13} using SSL/TLS)." -f $vpn.Count, $up.Count, (Join-CERList ($vpn | ForEach-Object { "{0} {1}:{2} [{3}]" -f $_.name, $_.ipv46, $_.port, $_.state }) 5), $samlGw.Count, (Join-CERList $samlGw 3), $radiusGw.Count, (Join-CERList $radiusGw 3), $ldapOnlyGw.Count, (Join-CERList ($ldapOnlyGw | ForEach-Object { $_.name }) 4), $aaa.Count, (Join-CERList ($saml | ForEach-Object { $_.name }) 3), (Join-CERList ($radius | ForEach-Object { $_.serverip }) 3), $ldap.Count, @($ldap | Where-Object { "$($_.sectype)" -imatch 'SSL|TLS' }).Count)

    Add-CEREvidence -Control 'SRV-14' -Flag $(if ($ldapOnlyGw.Count) { 'Attention' } else { 'Info' }) -Action 'Confirm which published-application farm sits behind these Gateway vServers and that ICA-only mode matches the intent - ICA-only means no VPN tunnel and no SSL VPN licence consumption, which is the right setting for a pure published-application deployment and the wrong one if full VPN access is expected. Check the STA (Secure Ticket Authority) servers still point at live controllers; a Gateway pointing at a decommissioned STA fails launches while the logon page keeps working, which is the classic "Citrix is broken but I can log in" ticket.' -Evidence ("Citrix Gateway front end for the published-application farm: {0} vServer(s), {1} in ICA-only mode ({2}). Load-balanced vServers: {3}; content-switching vServers: {4}." -f $vpn.Count, $icaOnly.Count, (Join-CERList ($icaOnly | ForEach-Object { $_.name }) 3), $lb.Count, $cs.Count)

    $downLb = @($lb | Where-Object { "$($_.state)" -imatch 'UP' -and "$($_.effectivestate)" -imatch 'DOWN' })
    if ($downLb.Count) {
        Add-CEREvidence -Control 'NET-04' -Flag Attention -Action 'Investigate the load-balanced vServers that are administratively up but effectively down - every service behind them has failed its monitor. This is usually a monitor pointing at a decommissioned backend, and it means the published service is offline while the appliance still answers on its VIP.' -Evidence ("Load-balanced vServers up administratively but DOWN effectively: {0} - {1}." -f $downLb.Count, (Join-CERList ($downLb | ForEach-Object { "{0} {1}:{2}" -f $_.name, $_.ipv46, $_.port }) 5))
    }
}

# ---------------- SSL/TLS posture and certificate expiry
Invoke-CERSection -Collector $C -Section 'SslAndCertificates' -Script {
    if (-not $script:sessionId) { Set-CERSectionResult -Status 'NoAccess' -Note 'no NITRO session'; return }
    $sslv = @(); try { $sslv = Get-NS 'sslvserver' } catch { }
    $certs = @(); try { $certs = Get-NS 'sslcertkey' } catch { }
    $sslparam = @(); try { $sslparam = Get-NS 'sslparameter' } catch { }
    Save-CERRaw -Name 'ssl' -Object ([ordered]@{
            SslVServers = @($sslv | Select-Object vservername, ssl2, ssl3, tls1, tls11, tls12, tls13, dh, ersa, sessreuse, snienable, hsts, maxage
            ); Certificates = @($certs | Select-Object certkey, cert, status, daystoexpiration, clientcertnotbefore, clientcertnotafter, issuer, subject, serial, signaturealg)
            SslParameter = $sslparam
        })
    $legacy = @($sslv | Where-Object { "$($_.ssl3)" -imatch 'ENABLED' -or "$($_.tls1)" -imatch 'ENABLED' -or "$($_.tls11)" -imatch 'ENABLED' -or "$($_.ssl2)" -imatch 'ENABLED' })
    $noTls13 = @($sslv | Where-Object { "$($_.tls13)" -inotmatch 'ENABLED' })
    $noHsts = @($sslv | Where-Object { "$($_.hsts)" -inotmatch 'ENABLED' })
    $expiring = @($certs | Where-Object { $null -ne $_.daystoexpiration -and [int]$_.daystoexpiration -le $CertExpiryWarningDays })
    $expired = @($certs | Where-Object { $null -ne $_.daystoexpiration -and [int]$_.daystoexpiration -le 0 })
    $sha1 = @($certs | Where-Object { "$($_.signaturealg)" -imatch 'sha1' })
    $act = @()
    if ($legacy.Count) { $act += ("Disable SSLv3, TLS 1.0 and TLS 1.1 on {0} - {1}. They are failed protocols; leaving them enabled is also a straightforward finding in any external scan or insurance questionnaire the client fills in" -f $legacy.Count, (Join-CERList ($legacy | ForEach-Object { $_.vservername }) 4)) }
    if ($expired.Count) { $act += ("Replace the {0} EXPIRED certificate(s) now - {1}. An expired certificate on a Gateway vServer stops every remote user, and it always expires on a weekend" -f $expired.Count, (Join-CERList ($expired | ForEach-Object { $_.certkey }) 4)) }
    elseif ($expiring.Count) { $act += ("Renew the {0} certificate(s) expiring within {1} days - {2} - and put the renewal dates in the calendar with an owner rather than relying on the appliance's own expiry alert, which usually emails a mailbox nobody reads" -f $expiring.Count, $CertExpiryWarningDays, (Join-CERList ($expiring | ForEach-Object { "{0} in {1} d" -f $_.certkey, $_.daystoexpiration }) 4)) }
    if ($sha1.Count) { $act += ("Replace the {0} SHA-1 signed certificate(s) - modern browsers and clients reject them outright" -f $sha1.Count) }
    Add-CEREvidence -Control 'NET-04' -Flag $(if ($legacy.Count -or $expired.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on the TLS posture. Worth confirming the published Gateway URL scores acceptably on an external SSL test, since the appliance view and the internet view differ when a WAF or CDN sits in front.' }) -Evidence ("SSL vServers: {0}. With SSLv2/SSLv3/TLS 1.0/TLS 1.1 still enabled: {1} ({2}). Without TLS 1.3: {3}. Without HSTS: {4}." -f $sslv.Count, $legacy.Count, (Join-CERList ($legacy | ForEach-Object { $_.vservername }) 5), $noTls13.Count, $noHsts.Count)

    Add-CEREvidence -Control 'SRV-10' -Flag $(if ($expired.Count) { 'Attention' } elseif ($expiring.Count) { 'Attention' } else { 'OK' }) -Action $(if ($expired.Count -or $expiring.Count) { 'Renew and rebind these certificates, then add them to the certificate expiry register with a named owner. Rebinding is the step that gets missed - the new certificate is uploaded but the vServer keeps serving the old one until someone binds it.' } else { 'Add these certificates and their expiry dates to the certificate register alongside the internal CA-issued ones so there is one list rather than one per appliance.' }) -Evidence ("NetScaler certificates: {0} total; expired {1} ({2}); expiring within {3} days {4} ({5}); SHA-1 signed {6}. Detail: {7}." -f $certs.Count, $expired.Count, (Join-CERList ($expired | ForEach-Object { $_.certkey }) 4), $CertExpiryWarningDays, @($expiring | Where-Object { [int]$_.daystoexpiration -gt 0 }).Count, (Join-CERList ($expiring | Where-Object { [int]$_.daystoexpiration -gt 0 } | ForEach-Object { "{0} in {1} d" -f $_.certkey, $_.daystoexpiration }) 4), $sha1.Count, (Join-CERList ($certs | ForEach-Object { "{0} expires in {1} d" -f $_.certkey, $_.daystoexpiration }) 6))
}

# ---------------- log out (the only other write, and it only ends our own session)
try {
    if ($script:sessionId) { $null = Invoke-NS -Path 'logout' -Method 'POST' -Body @{ logout = @{} }; Write-CERLog 'NITRO session closed.' }
} catch { Write-CERLog ("NITRO logout failed (session will time out on its own): {0}" -f $_.Exception.Message) 'WARN' }

Complete-CERCollector

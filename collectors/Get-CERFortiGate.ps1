#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (optional, BETA): FortiGate via REST API with a read-only API user token. Feeds NET-02..05, NET-08, NET-09.
  CMDB paths mirror the CLI config tree (config system ha -> cmdb/system/ha). Verified in docs: monitor/system/status,
  cmdb/firewall/policy, monitor/firewall/policy (hit_count), access_token auth. Others are derived - unknown endpoints are
  reported as coverage gaps, not errors.
.EXAMPLE
  .\Get-CERFortiGate.ps1 -Client C-003 -RunId 20260905-0900 -FortiGate 10.0.0.1 -Port 443 -ApiToken (Read-Host -AsSecureString)
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Client, [string]$OutputRoot, [string]$RunId, [Parameter(Mandatory)][string]$FortiGate, [int]$Port = 443, [Parameter(Mandatory)][securestring]$ApiToken, [string]$Vdom = 'root', [switch]$SkipCertificateCheck)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'FortiGate' -RunId $RunId
$C = 'FortiGate'
$token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiToken))
$base = "https://${FortiGate}:${Port}/api/v2/"
if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -lt 6) { try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } } catch { } }
function Get-FGT { param([string]$Path, [switch]$Global)
    $u = $base + $Path + $(if ($Path -match '\?') { '&' } else { '?' }) + $(if ($Global) { 'scope=global' } else { "vdom=$Vdom" })
    $p = @{ Uri = $u; Headers = @{ Authorization = "Bearer $token" }; Method = 'GET'; ErrorAction = 'Stop'; TimeoutSec = 30 }
    if ($SkipCertificateCheck -and $PSVersionTable.PSVersion.Major -ge 6) { $p['SkipCertificateCheck'] = $true }
    $r = Invoke-RestMethod @p
    if ($r.PSObject.Properties['results']) { return $r.results } else { return $r }
}
$status = $null
Invoke-CERSection -Collector $C -Section 'System' -Script {
    $script:status = Get-FGT 'monitor/system/status' -Global
    $ha = $null; try { $ha = Get-FGT 'cmdb/system/ha' -Global } catch { }
    $haPeer = @(); try { $haPeer = @(Get-FGT 'monitor/system/ha-peer' -Global) } catch { }
    $lic = $null; try { $lic = Get-FGT 'monitor/license/status' -Global } catch { }
    $fw = $null; try { $fw = Get-FGT 'monitor/system/firmware' -Global } catch { }
    $glob = $null; try { $glob = Get-FGT 'cmdb/system/global' -Global } catch { }
    $admins = @(); try { $admins = @(Get-FGT 'cmdb/system/admin' -Global) } catch { }
    $ifaces = @(); try { $ifaces = @(Get-FGT 'cmdb/system/interface' -Global) } catch { }
    $ntp = $null; try { $ntp = Get-FGT 'cmdb/system/ntp' -Global } catch { }
    $fazCfg = $null; try { $fazCfg = Get-FGT 'cmdb/log.fortianalyzer/setting' -Global } catch { }
    $syslog = $null; try { $syslog = Get-FGT 'cmdb/log.syslogd/setting' -Global } catch { }
    Save-CERRaw -Name 'system' -Object ([ordered]@{ Status = $script:status; HA = $ha; HAPeers = $haPeer; Licence = $lic; Firmware = $fw; Global = ($glob | Select-Object admin-sport, admin-port, admintimeout, strong-crypto, admin-https-ssl-versions, gui-certificates, ssh-kex-algo); Admins = @($admins | Select-Object name, accprofile, trusthost1, trusthost2, trusthost3, 'two-factor', 'two-factor-authentication', remote-auth); Interfaces = @($ifaces | Select-Object name, ip, role, allowaccess, status, type); Ntp = $ntp; FortiAnalyzer = ($fazCfg | Select-Object status, server, 'upload-option'); Syslog = ($syslog | Select-Object status, server, mode) })
    $s = $script:status
    $ver = "$($s.version)"; $verNum = if ($ver -match 'v?(\d+)\.(\d+)\.(\d+)') { [version]("{0}.{1}.{2}" -f $Matches[1], $Matches[2], $Matches[3]) } else { $null }
    $haMode = if ($ha) { "$($ha.mode)" } else { 'unknown' }
    $wanMgmt = @($ifaces | Where-Object { ($_.role -eq 'wan' -or $_.name -match 'wan') -and "$($_.allowaccess)" -match 'https|ssh|http|telnet' })
    $noTrust = @($admins | Where-Object { -not $_.trusthost1 -or "$($_.trusthost1)" -eq '0.0.0.0 0.0.0.0' })
    $no2fa = @($admins | Where-Object { "$($_.'two-factor')" -in 'disable', '' -and -not $_.'remote-auth' })
    $newerAvail = if ($fw -and $fw.available) { @($fw.available | Where-Object { $_.'major' -eq $verNum.Major -and $_.'minor' -eq $verNum.Minor -and [int]$_.patch -gt $verNum.Build }).Count } else { 'n/a' }
    $licExp = ''; if ($lic) { foreach ($k in 'forticare', 'antivirus', 'ips', 'web_filtering') { $x = Get-CERProp $lic $k; if ($x) { $licExp += ("{0}={1} " -f $k, $(if ($x.PSObject.Properties['expires']) { ([datetimeoffset]::FromUnixTimeSeconds([long]$x.expires)).ToString('yyyy-MM-dd') } else { "$($x.status)" })) } } }
    $flag = if ($haMode -eq 'standalone' -or $wanMgmt.Count -or $noTrust.Count -or $no2fa.Count) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'NET-02' -Flag $flag -Action 'Move FortiOS onto a mature release in a recommended branch and keep it in the PSIRT advisory loop - Fortinet SSL-VPN and management-plane vulnerabilities are actively exploited within days of disclosure. Confirm the HA pair is genuinely synchronised and that the configuration is backed up to FortiManager.' -Evidence ("FortiGate {0} ({1}) serial {2}: FortiOS {3} (newer patch releases available in same branch: {4}); HA mode {5} ({6} peers); admins {7} - without trusted hosts {8} ({9}), without 2FA/remote auth {10} ({11}); management (https/ssh) allowed on WAN-role interfaces: {12} ({13}); admin HTTPS port {14}, idle timeout {15} min; FortiAnalyzer logging {16} -> {17}; syslog {18}; licences: {19}." -f $s.hostname, $s.model, $s.serial, $ver, $newerAvail, $haMode, $haPeer.Count, $admins.Count, $noTrust.Count, (Join-CERList ($noTrust | ForEach-Object { $_.name }) 4), $no2fa.Count, (Join-CERList ($no2fa | ForEach-Object { $_.name }) 4), $wanMgmt.Count, (Join-CERList ($wanMgmt | ForEach-Object { "{0}:{1}" -f $_.name, $_.allowaccess }) 3), $(if ($glob) { $glob.'admin-sport' } else { '' }), $(if ($glob) { $glob.admintimeout } else { '' }), $(if ($fazCfg) { $fazCfg.status } else { 'n/a' }), $(if ($fazCfg) { $fazCfg.server } else { '' }), $(if ($syslog) { $syslog.status } else { 'n/a' }), $licExp)
    Add-CEREvidence -Control 'NET-08' -Flag $(if ($fazCfg -and $fazCfg.status -eq 'enable') { 'OK' } else { 'Attention' }) -Action 'Ship firewall logs to FortiAnalyzer or the SIEM and confirm NTP is set. Firewall logs are the only record of what crossed the perimeter, they are the first thing asked for in an incident, and they are worthless if the timestamps do not line up with the rest of the estate.' -Evidence ("FortiGate log shipping: FortiAnalyzer {0} ({1}), syslog {2} ({3}). NTP: {4}." -f $(if ($fazCfg) { $fazCfg.status } else { 'n/a' }), $(if ($fazCfg) { $fazCfg.server } else { '' }), $(if ($syslog) { $syslog.status } else { 'n/a' }), $(if ($syslog) { $syslog.server } else { '' }), $(if ($ntp) { "$($ntp.ntpsync) / $($ntp.type)" } else { 'n/a' }))
}
Invoke-CERSection -Collector $C -Section 'Policies' -Script {
    $pol = @(Get-FGT 'cmdb/firewall/policy')
    $hits = @{}; try { foreach ($h in @(Get-FGT 'monitor/firewall/policy')) { $hits[[string]$h.policyid] = $h } } catch { }
    $rows = @($pol | ForEach-Object { $h = $hits[[string]$_.policyid]; [pscustomobject]@{ Id = $_.policyid; Name = $_.name; Status = $_.status; Action = $_.action; Src = (@($_.srcintf | ForEach-Object { $_.name }) -join ','); Dst = (@($_.dstintf | ForEach-Object { $_.name }) -join ','); SrcAddr = (@($_.srcaddr | ForEach-Object { $_.name }) -join ','); DstAddr = (@($_.dstaddr | ForEach-Object { $_.name }) -join ','); Service = (@($_.service | ForEach-Object { $_.name }) -join ','); Log = $_.logtraffic; UTM = $_.'utm-status'; Profiles = @(@($_.'av-profile', $_.'webfilter-profile', $_.'ips-sensor', $_.'application-list', $_.'dnsfilter-profile', $_.'ssl-ssh-profile') | Where-Object { $_ }) -join '/'; Hits = $(if ($h) { $h.hit_count } else { $null }); LastUsed = $(if ($h -and $h.last_used) { ([datetimeoffset]::FromUnixTimeSeconds([long]$h.last_used)).ToString('yyyy-MM-dd') } else { '' }); Nat = $_.nat; Geo = ($_.srcaddr.name -match 'geo|country') } })
    Save-CERRaw -Name 'policies' -Object $rows
    $en = @($rows | Where-Object { $_.Status -eq 'enable' })
    $anyAny = @($en | Where-Object { $_.Action -eq 'accept' -and $_.SrcAddr -eq 'all' -and $_.DstAddr -eq 'all' -and $_.Service -eq 'ALL' })
    $noLog = @($en | Where-Object { $_.Log -eq 'disable' })
    $internet = @($en | Where-Object { $_.Action -eq 'accept' -and $_.Dst -match 'wan|internet|ppp' })
    $noUtm = @($internet | Where-Object { $_.UTM -ne 'enable' -or -not $_.Profiles })
    $unused = @($en | Where-Object { $null -ne $_.Hits -and [long]$_.Hits -eq 0 })
    $inbound = @($en | Where-Object { $_.Action -eq 'accept' -and $_.Src -match 'wan|internet|ppp' })
    $riskyIn = @($inbound | Where-Object { $_.Service -match 'RDP|SMB|MS-SQL|MYSQL|TELNET|FTP|ALL|VNC|SSH|WINRM' })
    $flag = if ($anyAny.Count -or $noUtm.Count -or $riskyIn.Count) { 'Attention' } elseif ($noLog.Count -or $unused.Count -gt 5) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'NET-03' -Flag $flag -Action 'Remove or scope the any/any/ALL accept policies and turn on logging for every policy. An any/any rule usually started as a temporary test; unlogged traffic is traffic that cannot be investigated afterwards. Then apply security profiles - IPS, AV, web filter, application control, DNS filter - to the internet-facing policies rather than leaving them as plain accepts.' -Evidence ("Firewall policies: {0} ({1} enabled). any/any/ALL accept: {2} ({3}); logging disabled: {4}; internet-bound accept policies {5}, of which without UTM profiles: {6} ({7}); zero-hit policies: {8} ({9}); geo-based sources used on {10}." -f $rows.Count, $en.Count, $anyAny.Count, (Join-CERList ($anyAny | ForEach-Object { "#{0} {1}" -f $_.Id, $_.Name }) 4), $noLog.Count, $internet.Count, $noUtm.Count, (Join-CERList ($noUtm | ForEach-Object { "#{0} {1}" -f $_.Id, $_.Name }) 5), $unused.Count, (Join-CERList ($unused | ForEach-Object { "#{0} {1}" -f $_.Id, $_.Name }) 6), @($en | Where-Object Geo).Count)
    Add-CEREvidence -Control 'NET-04' -Flag $(if ($riskyIn.Count) { 'Attention' } else { 'Info' }) -Action 'Review every inbound WAN-sourced accept policy and remove the published services that do not need to be there. RDP, SMB, SQL, Telnet and FTP published to the internet are found by internet-wide scanning within hours - move them behind the VPN or ZTNA rather than restricting by source IP, which does not survive the first change request.' -Evidence ("Inbound (WAN-sourced) accept policies: {0} - {1}. Risky services published (RDP/SMB/SQL/Telnet/FTP/ALL/VNC/SSH/WinRM): {2} ({3}). Confirm each against the external scan." -f $inbound.Count, (Join-CERList ($inbound | ForEach-Object { "#{0} {1} -> {2} [{3}]" -f $_.Id, $_.Name, $_.DstAddr, $_.Service }) 6), $riskyIn.Count, (Join-CERList ($riskyIn | ForEach-Object { "#{0} {1}" -f $_.Id, $_.Service }) 5))
    Add-CEREvidence -Control 'NET-06' -Flag Info -Action 'Check whether the inter-VLAN policies actually implement the segmentation the network diagram claims. Segmentation that exists as VLANs but permits everything between them is documentation, not a control - and it is the difference between one compromised workstation and the whole estate.' -Evidence ("Interfaces referenced by enabled policies: {0}. Inter-VLAN policies (non-WAN to non-WAN): {1}. Review against the VLAN plan for default-deny between zones." -f (Join-CERList (@($en | ForEach-Object { $_.Src }) + @($en | ForEach-Object { $_.Dst }) | ForEach-Object { $_ -split ',' } | Select-Object -Unique) 10), @($en | Where-Object { $_.Src -notmatch 'wan|ppp' -and $_.Dst -notmatch 'wan|ppp' -and $_.Action -eq 'accept' }).Count)
}
Invoke-CERSection -Collector $C -Section 'Vpn' -Script {
    $ssl = $null; try { $ssl = Get-FGT 'cmdb/vpn.ssl/settings' } catch { }
    $ipsec = @(); try { $ipsec = @(Get-FGT 'cmdb/vpn.ipsec/phase1-interface') } catch { }
    $local = @(); try { $local = @(Get-FGT 'cmdb/user/local') } catch { }
    $saml = @(); try { $saml = @(Get-FGT 'cmdb/user/saml') } catch { }
    $ldap = @(); try { $ldap = @(Get-FGT 'cmdb/user/ldap') } catch { }
    $radius = @(); try { $radius = @(Get-FGT 'cmdb/user/radius') } catch { }
    Save-CERRaw -Name 'vpn' -Object ([ordered]@{ SslVpn = ($ssl | Select-Object status, port, 'source-interface', 'auth-timeout', 'idle-timeout', 'tunnel-ip-pools', 'authentication-rule'); IpsecPhase1 = @($ipsec | Select-Object name, type, 'remote-gw', 'peertype', 'authmethod', 'eap', 'xauthtype', proposal, dhgrp); LocalUsers = @($local | Select-Object name, status, type, 'two-factor'); Saml = @($saml | Select-Object name, 'idp-entity-id'); Ldap = @($ldap | Select-Object name, server, secure); Radius = @($radius | Select-Object name, server) })
    $sslOn = ($ssl -and "$($ssl.status)" -eq 'enable')
    $dialup = @($ipsec | Where-Object { "$($_.type)" -eq 'dynamic' })
    $localOn = @($local | Where-Object { "$($_.status)" -eq 'enable' })
    $local2fa = @($localOn | Where-Object { "$($_.'two-factor')" -ne 'disable' -and $_.'two-factor' })
    $flag = if ($sslOn -or ($localOn.Count -gt 2 -and $local2fa.Count -lt $localOn.Count)) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'NET-05' -Flag $flag -Action 'Plan the move off SSL-VPN tunnel mode - it is removed in FortiOS 7.6.3, so this is a deadline rather than a recommendation. Whatever replaces it (IPsec or ZTNA) must require MFA through SAML to Entra and check device posture; remote access without both is a password away from being inside the network.' -Evidence ("Remote access: SSL-VPN {0} (port {1}) - tunnel mode removed in FortiOS 7.6.3, plan IPsec/ZTNA; IPsec dial-up phase1s: {2} ({3}); site-to-site phase1s: {4}; authentication sources: SAML {5} ({6}), LDAP {7} ({8} secure), RADIUS {9}; local firewall users: {10} enabled, {11} with FortiToken 2FA." -f $(if ($sslOn) { 'ENABLED' } else { 'disabled' }), $(if ($ssl) { $ssl.port } else { '' }), $dialup.Count, (Join-CERList ($dialup | ForEach-Object { "{0} ({1}, eap {2})" -f $_.name, $_.authmethod, $_.eap }) 3), ($ipsec.Count - $dialup.Count), $saml.Count, (Join-CERList ($saml | ForEach-Object { $_.name }) 3), $ldap.Count, @($ldap | Where-Object { "$($_.secure)" -ne 'disable' }).Count, $radius.Count, $localOn.Count, $local2fa.Count)
    Add-CEREvidence -Control 'NET-09' -Flag Info -Action 'Document the site-to-site tunnels with their purpose, the remote party and an owner, and confirm the WAN resilience position. A tunnel to a partner nobody can account for is a standing route into the network from an organisation whose security posture is unknown.' -Evidence ("Site-to-site IPsec tunnels defined: {0} ({1}). SD-WAN/dual-WAN state: cmdb/system/sdwan not collected in v1 - check FortiGate GUI > Network > SD-WAN." -f ($ipsec.Count - $dialup.Count), (Join-CERList ($ipsec | Where-Object { "$($_.type)" -ne 'dynamic' } | ForEach-Object { "{0} -> {1}" -f $_.name, $_.'remote-gw' }) 5))
}
Complete-CERCollector

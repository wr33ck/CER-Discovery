#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (beta): Network Policy Server (RADIUS) - clients, connection request policies,
  network policies and the authentication methods they actually allow, accounting, and the Entra MFA
  extension. Feeds NET-05, NET-07, NET-11, SEC-12 and SRV-11.

.DESCRIPTION
  NPS has no useful Get-* surface: the Nps module exposes Export-NpsConfiguration and Import-NpsConfiguration
  and nothing else, so reading the policy set means reading the exported XML.

  SHARED SECRETS. Microsoft documents that the exported XML contains the RADIUS shared secrets of every client
  and every remote RADIUS server group IN CLEAR TEXT. This collector therefore:
    * runs the export and the parse ON the NPS server (locally, or inside one Invoke-Command), so the file with
      the secrets in it never crosses the network and never touches the reviewer's machine;
    * writes the export to the server's own temp folder, never into the run folder;
    * returns only parsed, redacted objects - a secret is reported as present/absent and by length, never by
      value - with a final regex sweep over everything before it is returned;
    * deletes the export in a finally block, overwriting it first, whether or not the parse succeeded.
  Nothing under output\ should ever contain a RADIUS secret. If you extend this collector, keep that true.

  Read-only against NPS: the export does not change configuration. Nothing is imported, ever.

  BETA. The exported schema is walked by element and property NAME rather than by a fixed path, because the
  layout differs between Windows Server versions. Treat the first run's output as something to check.

.EXAMPLE
  .\Get-CERNps.ps1 -Client C-003 -RunId 20260905-0900                       # on the NPS server itself
  .\Get-CERNps.ps1 -Client C-003 -RunId 20260905-0900 -ComputerName nps01,nps02
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string[]]$ComputerName,
    [pscredential]$Credential
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Nps' -RunId $RunId
$C = 'Nps'

# ------------------------------------------------------------------ the bit that runs on the NPS server
# Self-contained: no CER library functions exist on the far side of Invoke-Command.
$npsProbe = {
    $out = [ordered]@{
        Host = $env:COMPUTERNAME; ServiceInstalled = $false; ServiceState = ''; IsDomainController = $false
        Clients = @(); ConnectionRequestPolicies = @(); NetworkPolicies = @(); RemoteRadiusGroups = @()
        Accounting = [ordered]@{}; MfaExtension = [ordered]@{ Installed = $false; TenantId = '' }
        ExportOk = $false; Error = ''
    }
    $svc = Get-Service -Name IAS -ErrorAction SilentlyContinue
    if ($svc) { $out.ServiceInstalled = $true; $out.ServiceState = "$($svc.Status)" }
    try { $out.IsDomainController = ((Get-CimInstance Win32_ComputerSystem).DomainRole -in 4, 5) } catch { }

    # Entra (Azure) MFA NPS extension - the supported way to put MFA in front of RADIUS
    foreach ($p in 'HKLM:\SOFTWARE\Microsoft\AzureMfa', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\AzureMfa') {
        try {
            $k = Get-ItemProperty -Path $p -ErrorAction Stop
            if ($k) {
                $out.MfaExtension.Installed = $true
                foreach ($nm in 'AZURE_MFA_TENANT_ID', 'TenantId', 'AZURE_MFA_HOSTNAME') {
                    $v = $null; try { $v = $k.$nm } catch { }
                    if ($v -and -not $out.MfaExtension.TenantId) { $out.MfaExtension.TenantId = "$v" }
                }
            }
        } catch { }
    }
    if (-not $out.MfaExtension.Installed) {
        try { if (Test-Path "$env:SystemRoot\System32\AzureMfaAuthenticationExtension.dll") { $out.MfaExtension.Installed = $true } } catch { }
    }

    if (-not $out.ServiceInstalled) { return [pscustomobject]$out }

    $tmp = Join-Path $env:TEMP ("cer-nps-{0}.xml" -f ([guid]::NewGuid().ToString('N')))
    try {
        try { Export-NpsConfiguration -Path $tmp -ErrorAction Stop }
        catch { $null = & netsh nps export filename="$tmp" exportPSK=YES 2>&1 }
        if (-not (Test-Path -LiteralPath $tmp)) { $out.Error = 'NPS configuration export produced no file'; return [pscustomobject]$out }
        $xml = New-Object System.Xml.XmlDocument
        $xml.Load($tmp)
        $out.ExportOk = $true

        # --- generic helpers over the exported tree (layout varies by OS version) -------------------
        $secretNames = 'shared_secret|sharedsecret|secret|password|psk'
        function Get-Prop {
            param($Node, [string]$Name)
            if ($null -eq $Node) { return $null }
            foreach ($p in $Node.SelectNodes('.//*')) {
                if ($p.LocalName -and ($p.LocalName -replace '[^A-Za-z0-9]', '') -ieq ($Name -replace '[^A-Za-z0-9]', '')) {
                    if ($p.InnerText) { return $p.InnerText }
                    $a = $p.GetAttribute('value'); if ($a) { return $a }
                }
            }
            return $null
        }
        function Get-Container {
            param([string]$Pattern)
            foreach ($n in $xml.SelectNodes('//*')) { if ($n.LocalName -imatch $Pattern) { return $n } }
            return $null
        }
        function Get-Kids { param($Node) if ($null -eq $Node) { return @() }; $c = $Node.SelectSingleNode('./Children'); if ($c) { return @($c.ChildNodes) }; return @($Node.ChildNodes) }

        # --- RADIUS clients -------------------------------------------------------------------------
        $cc = Get-Container 'RADIUS_?Clients$|^Clients$'
        foreach ($k in (Get-Kids $cc)) {
            if ($k.NodeType -ne 'Element') { continue }
            $sec = Get-Prop $k 'Shared_Secret'
            $out.Clients += [pscustomobject]@{
                Name = $(if ($k.GetAttribute('name')) { $k.GetAttribute('name') } else { $k.LocalName })
                Address = "$(Get-Prop $k 'IP_Address')"
                Vendor = "$(Get-Prop $k 'Manufacturer_ID')"
                Enabled = "$(Get-Prop $k 'Enabled')"
                RequireMessageAuthenticator = "$(Get-Prop $k 'Require_Signature')"
                NapCapable = "$(Get-Prop $k 'NAP_Capable')"
                SharedSecretPresent = [bool]$sec          # never the value
                SharedSecretLength = $(if ($sec) { "$sec".Length } else { 0 })
            }
        }

        # --- policies ---------------------------------------------------------------------------------
        function Read-Policies {
            param($Container)
            $rows = @()
            foreach ($k in (Get-Kids $Container)) {
                if ($k.NodeType -ne 'Element') { continue }
                $conds = @(); $auth = @()
                foreach ($p in $k.SelectNodes('.//*')) {
                    if ($p.LocalName -imatch 'Conditions?$' -and $p.InnerText) { $conds += ($p.InnerText -replace '\s+', ' ').Trim() }
                    if ($p.LocalName -imatch 'Authentication_?Type|EAP|Allowed_?EAP' -and $p.InnerText) { $auth += ($p.InnerText -replace '\s+', ' ').Trim() }
                }
                $rows += [pscustomobject]@{
                    Name = $(if ($k.GetAttribute('name')) { $k.GetAttribute('name') } else { $k.LocalName })
                    Enabled = "$(Get-Prop $k 'Enabled')"
                    Order = "$(Get-Prop $k 'Processing_Order')"
                    Action = "$(Get-Prop $k 'Policy_Enabled')"
                    AccessPermission = "$(Get-Prop $k 'AccessType')"
                    ConditionText = (($conds | Select-Object -Unique) -join ' | ')
                    AuthMethods = (($auth | Select-Object -Unique) -join ', ')
                    Raw = (($k.OuterXml -replace '\s+', ' ')).Substring(0, [Math]::Min(1200, ($k.OuterXml -replace '\s+', ' ').Length))
                }
            }
            return $rows
        }
        $out.NetworkPolicies = @(Read-Policies (Get-Container '^NetworkPolicy$|Network_?Policies?$'))
        $out.ConnectionRequestPolicies = @(Read-Policies (Get-Container 'Connection_?Request_?Polic'))

        $rg = Get-Container 'Remote_?RADIUS_?Server|RadiusServerGroup'
        foreach ($k in (Get-Kids $rg)) {
            if ($k.NodeType -ne 'Element') { continue }
            $out.RemoteRadiusGroups += [pscustomobject]@{ Name = $(if ($k.GetAttribute('name')) { $k.GetAttribute('name') } else { $k.LocalName }); Servers = @($k.SelectNodes('.//*') | Where-Object { $_.LocalName -imatch 'Server|Address' -and $_.InnerText }).Count }
        }

        $acc = Get-Container 'Accounting'
        if ($acc) {
            $out.Accounting = [ordered]@{
                LogAccounting = "$(Get-Prop $acc 'Log_Accounting')"
                LogAuth = "$(Get-Prop $acc 'Log_Accounting_Interim')"
                SqlConfigured = [bool](Get-Prop $acc 'SQL')
                LogFileDirectory = "$(Get-Prop $acc 'Log_File_Directory')"
                Present = $true
            }
        }
    } catch {
        $out.Error = ($_.Exception.Message -replace '\s+', ' ')
    } finally {
        if (Test-Path -LiteralPath $tmp) {
            try { $len = (Get-Item -LiteralPath $tmp).Length; Set-Content -LiteralPath $tmp -Value ([string]('0' * [Math]::Min(4096, [int]$len))) -Force -ErrorAction SilentlyContinue } catch { }
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    # Belt and braces: nothing that looks like a secret leaves this machine, whatever the schema did.
    $scrub = {
        param($o)
        if ($null -eq $o) { return $null }
        if ($o -is [string]) { return ([regex]::Replace($o, '(?i)(<[^>]*(shared_?secret|password|psk)[^>]*>)([^<]*)(</)', '$1<REDACTED>$4')) }
        return $o
    }
    foreach ($p in @($out.NetworkPolicies) + @($out.ConnectionRequestPolicies)) {
        if ($p -and $p.Raw) { $p.Raw = (& $scrub $p.Raw) }
    }
    return [pscustomobject]$out
}

# ------------------------------------------------------------------ run it, locally or remotely
$script:results = @()
Invoke-CERSection -Collector $C -Section 'Collect' -Script {
    $targets = @()
    if ($ComputerName) { $targets = @($ComputerName) } else { $targets = @($env:COMPUTERNAME) }
    $rows = @(); $failed = @()
    foreach ($t in $targets) {
        $isLocal = ($t -ieq $env:COMPUTERNAME -or $t -ieq 'localhost' -or $t -ieq '.')
        try {
            if ($isLocal) { $rows += (& $npsProbe) }
            else {
                $p = @{ ComputerName = $t; ScriptBlock = $npsProbe; ErrorAction = 'Stop' }
                if ($Credential) { $p['Credential'] = $Credential }
                $rows += (Invoke-Command @p)
            }
        } catch { $failed += [pscustomobject]@{ Server = $t; Error = ($_.Exception.Message -replace '\s+', ' ') } }
    }
    $script:results = @($rows | Where-Object { $_ })
    Save-CERRaw -Name 'servers' -Object ([ordered]@{ Results = $script:results; Unreachable = $failed })
    $withNps = @($script:results | Where-Object { $_.ServiceInstalled })
    if (-not $withNps.Count) {
        Set-CERSectionResult -Status 'Skipped' -Note 'NPS role not present on any target'
        Add-CEREvidence -Control 'NET-05' -Flag Info -Action 'If the client uses 802.1X or RADIUS-backed VPN, find where that RADIUS service actually runs (another NPS, a FortiAuthenticator, a cloud RADIUS) and re-run this collector against it with -ComputerName. If nothing does RADIUS, the wireless is on a pre-shared key and the VPN is authenticating some other way - both are worth recording explicitly rather than leaving blank.' -Evidence ("No Network Policy Server role found on {0} ({1}). RADIUS is served elsewhere or not in use." -f (Join-CERList $targets 4), $(if ($failed.Count) { ("{0} unreachable" -f $failed.Count) } else { 'all reachable' }))
        return
    }
    if ($failed.Count) { Set-CERSectionResult -Status 'Partial' -Note ("{0} target(s) unreachable" -f $failed.Count) }
    $errs = @($withNps | Where-Object { $_.Error })
    Add-CEREvidence -Control 'SRV-11' -Flag $(if ($errs.Count -or @($withNps | Where-Object { $_.ServiceState -ne 'Running' }).Count) { 'Attention' } else { 'OK' }) -Action $(if ($withNps.Count -lt 2) { 'Only one NPS server was found. RADIUS is a single point of failure for wireless and VPN authentication at the same time - if this one reboots, nobody gets on the network from anywhere. Stand up a second NPS and add it to the network device configuration as a secondary RADIUS server.' } else { 'Confirm both NPS servers carry the same policy set - a second NPS with a stale or empty policy set fails open or closed unpredictably at the worst moment. Export from the primary and import to the secondary as the documented refresh process.' }) -Evidence ("NPS servers: {0} of {1} target(s) have the role. Service state: {2}. Also a domain controller: {3}. Configuration export succeeded on {4}/{5}{6}." -f $withNps.Count, $script:results.Count + $failed.Count, (Join-CERList ($withNps | ForEach-Object { "{0}={1}" -f $_.Host, $_.ServiceState }) 4), (Join-CERList ($withNps | Where-Object { $_.IsDomainController } | ForEach-Object { $_.Host }) 4), @($withNps | Where-Object { $_.ExportOk }).Count, $withNps.Count, $(if ($errs.Count) { (' - errors: ' + (Join-CERList ($errs | ForEach-Object { "{0}: {1}" -f $_.Host, $_.Error }) 2)) } else { '' }))
}

# ---------------- RADIUS clients (who is allowed to ask NPS a question)
Invoke-CERSection -Collector $C -Section 'RadiusClients' -Script {
    $withNps = @($script:results | Where-Object { $_.ServiceInstalled -and $_.ExportOk })
    if (-not $withNps.Count) { Set-CERSectionResult -Status 'Skipped' -Note 'no NPS configuration read'; return }
    $clients = @()
    foreach ($r in $withNps) { foreach ($c2 in @($r.Clients)) { $clients += [pscustomobject]@{ Server = $r.Host; Name = $c2.Name; Address = $c2.Address; Vendor = $c2.Vendor; Enabled = $c2.Enabled; RequireMessageAuthenticator = $c2.RequireMessageAuthenticator; SecretPresent = $c2.SharedSecretPresent; SecretLength = $c2.SharedSecretLength } }
    }
    Save-CERRaw -Name 'radiusclients' -Object $clients
    $noMsgAuth = @($clients | Where-Object { "$($_.RequireMessageAuthenticator)" -imatch '^(0|false|no)$' })
    $shortSecret = @($clients | Where-Object { $_.SecretPresent -and $_.SecretLength -gt 0 -and $_.SecretLength -lt 22 })
    $disabled = @($clients | Where-Object { "$($_.Enabled)" -imatch '^(0|false|no)$' })
    $act = @()
    if ($noMsgAuth.Count) { $act += ("Tick 'Access-Request messages must contain the Message-Authenticator attribute' on the {0} client(s) without it - {1} - after confirming each network device supports it. RADIUS/UDP without that attribute is what the Blast-RADIUS class of attack forges; the setting is free and the risk is an authentication bypass" -f $noMsgAuth.Count, (Join-CERList ($noMsgAuth | ForEach-Object { $_.Name }) 5)) }
    if ($shortSecret.Count) { $act += ("Rotate the shared secret on {0} to a long random string (22+ characters). RADIUS shared secrets protect a protocol that still relies on MD5, and a short secret is offline-crackable from captured traffic. Rotate on the network device and NPS together in a change window, and store the new value in CyberArk" -f (Join-CERList ($shortSecret | ForEach-Object { "{0} ({1} chars)" -f $_.Name, $_.SecretLength }) 4)) }
    if ($disabled.Count) { $act += ("Remove the {0} disabled RADIUS client(s) - {1} - if the device is gone. A disabled client entry still holds a shared secret and hides what is genuinely in use" -f $disabled.Count, (Join-CERList ($disabled | ForEach-Object { $_.Name }) 4)) }
    Add-CEREvidence -Control 'NET-11' -Flag $(if ($noMsgAuth.Count -or $shortSecret.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on the client list itself. Confirm every entry still matches a device that exists, and that the shared secrets are in CyberArk rather than in a build document.' }) -Evidence ("RADIUS clients defined: {0} across {1} NPS server(s) - {2}. Without Message-Authenticator required: {3}. Shared secret shorter than 22 characters: {4}. Disabled entries: {5}. (Secret values are never read or stored by this collector - only presence and length.)" -f $clients.Count, $withNps.Count, (Join-CERList ($clients | ForEach-Object { "{0} [{1}]" -f $_.Name, $_.Address }) 8), $noMsgAuth.Count, $shortSecret.Count, $disabled.Count)

    $thirdParty = @($clients | Where-Object { "$($_.Vendor)" -and "$($_.Vendor)" -notmatch '^(0|RADIUS Standard)$' })
    Add-CEREvidence -Control 'SEC-12' -Flag Info -Action 'Cross-check this client list against the vendor access register. Every RADIUS client is a device that can ask NPS to authenticate a user, so an entry nobody recognises is either a decommissioned appliance whose secret is still valid, or third-party kit that was never recorded as having an authentication path into the estate.' -Evidence ("RADIUS clients by device: {0}. Non-standard vendor entries (appliance-specific dictionaries): {1}." -f (Join-CERList ($clients | ForEach-Object { "{0} at {1}" -f $_.Name, $_.Address }) 10), (Join-CERList ($thirdParty | ForEach-Object { "{0} ({1})" -f $_.Name, $_.Vendor }) 4))
}

# ---------------- network policies: what authentication is actually allowed
Invoke-CERSection -Collector $C -Section 'NetworkPolicies' -Script {
    $withNps = @($script:results | Where-Object { $_.ServiceInstalled -and $_.ExportOk })
    if (-not $withNps.Count) { Set-CERSectionResult -Status 'Skipped' -Note 'no NPS configuration read'; return }
    $pol = @(); $crp = @()
    foreach ($r in $withNps) {
        foreach ($p in @($r.NetworkPolicies)) { $pol += [pscustomobject]@{ Server = $r.Host; Name = $p.Name; Enabled = $p.Enabled; Order = $p.Order; Conditions = $p.ConditionText; Auth = $p.AuthMethods; Raw = $p.Raw } }
        foreach ($p in @($r.ConnectionRequestPolicies)) { $crp += [pscustomobject]@{ Server = $r.Host; Name = $p.Name; Enabled = $p.Enabled; Order = $p.Order; Conditions = $p.ConditionText; Auth = $p.AuthMethods } }
    }
    Save-CERRaw -Name 'policies' -Object ([ordered]@{ NetworkPolicies = $pol; ConnectionRequestPolicies = $crp; RemoteRadiusGroups = @($withNps | ForEach-Object { $_.RemoteRadiusGroups }) })
    $enabled = @($pol | Where-Object { "$($_.Enabled)" -inotmatch '^(0|false|no)$' })
    # Authentication strength, read from whatever the export exposed plus the raw policy XML as a fallback.
    $blob = (($pol | ForEach-Object { "$($_.Auth) $($_.Raw)" }) -join ' ')
    $hasEapTls = ($blob -imatch 'EAP[-_ ]?TLS|Smart ?Card or other certificate|13')
    $hasPeap = ($blob -imatch 'PEAP')
    $hasMschap = ($blob -imatch 'MS-?CHAP')
    $hasPapChap = ($blob -imatch '(?<!MS-)\bPAP\b|Unencrypted authentication|\bCHAP\b(?!v2)')
    $wireless = @($enabled | Where-Object { "$($_.Conditions)" -imatch 'Wireless|IEEE ?802\.11' })
    $wired = @($enabled | Where-Object { "$($_.Conditions)" -imatch 'Ethernet|IEEE ?802\.3|Wired' })
    $vpn = @($enabled | Where-Object { "$($_.Conditions)" -imatch 'VPN|Virtual|Async|Sync' })
    $anyUser = @($enabled | Where-Object { -not ("$($_.Conditions)" -imatch 'Group|Windows-Groups|Machine-Groups|User-Groups') })
    $act = @()
    if ($hasPapChap) { $act += 'Turn off PAP/CHAP (the "unencrypted authentication" tick) on any policy that still allows it. PAP sends the password recoverable from the RADIUS exchange - the only legitimate use is MAC Authentication Bypass, and if that is what this is, scope that policy to the MAB device group alone so no user account can ever authenticate through it' }
    if ($hasMschap -and -not $hasEapTls) { $act += 'Plan the move from PEAP-MSCHAPv2 to EAP-TLS with client certificates. MSCHAPv2 is credential-based, so a rogue access point can relay the exchange and crack it offline, and the only thing standing in the way is whether every client validates the NPS server certificate - which is a client-side setting the server cannot prove. Certificate authentication removes the password from the exchange entirely' }
    if ($anyUser.Count) { $act += ("Scope the {0} enabled policy/policies with no group condition - {1} - to a specific security group. A policy that grants network access without a group condition grants it to every account that matches the connection method, including service and disabled-but-not-removed accounts" -f $anyUser.Count, (Join-CERList ($anyUser | ForEach-Object { $_.Name }) 4)) }
    Add-CEREvidence -Control 'NET-11' -Flag $(if ($hasPapChap -or $anyUser.Count) { 'Attention' } elseif ($enabled.Count) { 'OK' } else { 'Info' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action from the policy set. Confirm on the switch side which ports actually enforce 802.1X - NPS proves a policy exists, not that any port requires it.' }) -Evidence ("NPS network policies: {0} ({1} enabled). By connection type: wireless {2}, wired/Ethernet {3}, VPN {4}. Authentication methods seen across the policy set: EAP-TLS {5}, PEAP {6}, MS-CHAPv2 {7}, PAP/CHAP {8}. Enabled policies with no group condition: {9} ({10}). Connection request policies: {11}. Policy names: {12}." -f $pol.Count, $enabled.Count, $wireless.Count, $wired.Count, $vpn.Count, $hasEapTls, $hasPeap, $hasMschap, $hasPapChap, $anyUser.Count, (Join-CERList ($anyUser | ForEach-Object { $_.Name }) 4), $crp.Count, (Join-CERList ($enabled | ForEach-Object { "{0} (#{1})" -f $_.Name, $_.Order }) 8))

    # NET-07: whether corporate wireless is 802.1X at all, rather than a shared PSK
    Add-CEREvidence -Control 'NET-07' -Flag $(if ($wireless.Count) { 'OK' } else { 'Info' }) -Action $(if ($wireless.Count) { 'Corporate wireless is authenticating against RADIUS rather than a shared key, which is the target state. Confirm on the wireless controller that the corporate SSID is the one bound to these policies and that no parallel PSK SSID exists for the same network - the PSK one is usually the one that was never decommissioned after the 802.1X migration.' } else { 'No wireless network policy exists on NPS, so corporate Wi-Fi is either on a pre-shared key or authenticating against something else. A corporate PSK cannot be revoked per user or per device - when someone leaves, the key leaves with them, and rotating it means touching every device. Confirm on the wireless controller and price the move to WPA2/3-Enterprise with 802.1X against this NPS.' }) -Evidence ("Wireless (IEEE 802.11) network policies on NPS: {0}{1}. This evidences 802.1X for corporate Wi-Fi; the SSID-to-policy binding and any parallel PSK SSID still need confirming on the wireless controller." -f $wireless.Count, $(if ($wireless.Count) { (' - ' + (Join-CERList ($wireless | ForEach-Object { $_.Name }) 5)) } else { '' }))

    # NET-05: RADIUS as the VPN authentication backend, and whether MFA sits in front of it
    $mfa = @($withNps | Where-Object { $_.MfaExtension.Installed })
    Add-CEREvidence -Control 'NET-05' -Flag $(if ($vpn.Count -and -not $mfa.Count) { 'Attention' } elseif ($mfa.Count) { 'OK' } else { 'Info' }) -Action $(if ($vpn.Count -and -not $mfa.Count) { 'VPN authentication terminates on NPS with no MFA extension installed, so remote access is username and password against Active Directory. Either install the Entra MFA NPS extension on every NPS server that serves the VPN, or move the VPN to SAML against Entra so Conditional Access applies - the second is preferable because it brings device compliance and risk signals with it. Installing the extension on only one of a pair of NPS servers is the common half-finished state, and it fails open on the server without it.' } elseif ($mfa.Count) { 'The Entra MFA NPS extension is installed. Confirm it is on EVERY NPS server serving remote access, not just this one, and check the extension is in a supported version - a half-deployed extension means a fallback to password-only whenever the second server answers.' } else { 'No VPN-shaped network policy found on NPS. Confirm where remote access authenticates - if it is SAML to Entra, that is the better position and NET-05 is evidenced by the firewall collector instead.' }) -Evidence ("VPN-shaped network policies on NPS: {0} ({1}). Entra MFA NPS extension installed on {2}/{3} NPS server(s){4}. Remote RADIUS server groups (proxy/forwarding): {5}." -f $vpn.Count, (Join-CERList ($vpn | ForEach-Object { $_.Name }) 4), $mfa.Count, $withNps.Count, $(if ($mfa.Count -and $mfa.Count -lt $withNps.Count) { ' - NOT on all of them' } else { '' }), (@($withNps | ForEach-Object { @($_.RemoteRadiusGroups).Count }) | Measure-Object -Sum).Sum)
}

# ---------------- accounting / logging
Invoke-CERSection -Collector $C -Section 'Accounting' -Script {
    $withNps = @($script:results | Where-Object { $_.ServiceInstalled -and $_.ExportOk })
    if (-not $withNps.Count) { Set-CERSectionResult -Status 'Skipped' -Note 'no NPS configuration read'; return }
    $rows = @($withNps | ForEach-Object { [pscustomobject]@{ Server = $_.Host; Present = $_.Accounting.Present; LogAccounting = $_.Accounting.LogAccounting; SqlConfigured = $_.Accounting.SqlConfigured; LogFileDirectory = $_.Accounting.LogFileDirectory } })
    Save-CERRaw -Name 'accounting' -Object $rows
    $noLog = @($rows | Where-Object { -not $_.Present -or "$($_.LogAccounting)" -imatch '^(0|false|no)$' })
    Add-CEREvidence -Control 'SEC-12' -Flag $(if ($noLog.Count) { 'Attention' } else { 'OK' }) -Action $(if ($noLog.Count) { ("Turn on NPS accounting on {0} and ship the logs somewhere they are actually read (Rapid7/Sentinel). Without accounting there is no record of which account authenticated onto the network from which device and when - so a compromised credential used over Wi-Fi or VPN leaves no trail on the authentication side at all, and the investigation has to be reconstructed from switch and firewall logs instead." -f (Join-CERList ($noLog | ForEach-Object { $_.Server }) 4)) } else { 'Accounting is on. Confirm the logs are forwarded to the central logging platform and retained for the agreed period rather than rotating locally on the NPS server, which is where they are least useful during an incident.' }) -Evidence ("NPS accounting: {0}. Servers with accounting off or unreadable: {1}." -f (Join-CERList ($rows | ForEach-Object { "{0}: logging={1}, SQL={2}, dir={3}" -f $_.Server, $_.LogAccounting, $_.SqlConfigured, $_.LogFileDirectory }) 4), $noLog.Count)
}

Complete-CERCollector

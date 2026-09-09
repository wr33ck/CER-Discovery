#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector (optional, beta): Citrix Virtual Apps and Desktops (CVAD) on-premises - site and
  controller version currency, machine catalogs and delivery groups, VDA registration and version spread,
  licensing model and licence server. Feeds SRV-14, SRV-02, LIC-02 and LIC-03.

.DESCRIPTION
  Run on a Delivery Controller, or on a machine with the CVAD PowerShell SDK installed using -AdminAddress.

  RUN IT IN WINDOWS POWERSHELL 5.1, not PowerShell 7. The CVAD SDK still ships as PSSnapins on most versions,
  and Add-PSSnapin does not exist in PowerShell 7. Where the newer Citrix.*.Commands modules are present this
  collector uses those instead and either host works, but 5.1 on the DDC is the reliable path.

  Read-only: Get-* only.

  Citrix DaaS (Citrix Cloud) is NOT covered - the control plane is cloud-hosted and needs a Citrix Cloud API
  client against a different API. Where the client is on DaaS, this collector reports that it found no local
  site and the control stays manual.

  BETA. Property names vary across CVAD releases, so anything beyond the core broker cmdlets is read through
  Get-Command guards and property discovery. Treat the first run's output as something to check.

.EXAMPLE
  .\Get-CERCitrix.ps1 -Client C-003 -RunId 20260905-0900
  .\Get-CERCitrix.ps1 -Client C-003 -RunId 20260905-0900 -AdminAddress ddc01.contoso.local
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string]$AdminAddress,
    [int]$MaxMachines = 2000
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Citrix' -RunId $RunId
$C = 'Citrix'
$script:aa = @{}
if ($AdminAddress) { $script:aa = @{ AdminAddress = $AdminAddress } }

# ---------------- load the SDK
$script:sdkOk = $false
Invoke-CERSection -Collector $C -Section 'Sdk' -Script {
    $loaded = @()
    foreach ($m in 'Citrix.Broker.Commands', 'Citrix.Configuration.Commands', 'Citrix.Host.Commands', 'Citrix.Licensing.Commands') {
        if (Get-Module -ListAvailable -Name $m -ErrorAction SilentlyContinue) {
            try { Import-Module $m -ErrorAction Stop -WarningAction SilentlyContinue; $loaded += $m } catch { }
        }
    }
    if (-not (Get-Command Get-BrokerSite -ErrorAction SilentlyContinue)) {
        if (Get-Command Add-PSSnapin -ErrorAction SilentlyContinue) {
            foreach ($s in 'Citrix.Broker.Admin.V2', 'Citrix.Configuration.Admin.V2', 'Citrix.Host.Admin.V2', 'Citrix.Licensing.Admin.V1') {
                try { Add-PSSnapin -Name $s -ErrorAction Stop; $loaded += $s } catch { }
            }
        } else {
            Write-CERLog 'Add-PSSnapin is not available - this is PowerShell 7. The CVAD SDK ships as snapins on most versions; run this collector in Windows PowerShell 5.1 on the Delivery Controller.' 'WARN'
        }
    }
    if (-not (Get-Command Get-BrokerSite -ErrorAction SilentlyContinue)) {
        Set-CERSectionResult -Status 'NotInstalled' -Note 'CVAD PowerShell SDK (Citrix.Broker) not available on this host'
        Add-CEREvidence -Control 'SRV-14' -Flag Unknown -Action 'Run this collector on a Citrix Delivery Controller in Windows PowerShell 5.1, or install the CVAD PowerShell SDK on the jump host and pass -AdminAddress. If the client has no on-premises Citrix - because they are on Citrix DaaS, or on Parallels RAS, or on plain RDS - record that instead and score SRV-14 against whichever platform they actually run.' -Evidence 'Citrix broker SDK not present on this host - no on-premises CVAD site could be read from here.'
        return
    }
    $script:sdkOk = $true
    Write-CERLog ("Citrix SDK loaded: {0}" -f (Join-CERList $loaded 6))
}

# ---------------- site, version, licensing
$script:site = $null
Invoke-CERSection -Collector $C -Section 'Site' -Script {
    if (-not $script:sdkOk) { Set-CERSectionResult -Status 'Skipped' -Note 'SDK not loaded'; return }
    $site = Get-BrokerSite @script:aa -ErrorAction Stop
    $script:site = $site
    $ctrls = @()
    try { $ctrls = @(Get-BrokerController @script:aa -ErrorAction SilentlyContinue) } catch { }
    # The site's own version property has moved around between releases - take the first one that answers.
    $ver = ''
    foreach ($p in 'ControllerVersion', 'BrokerServiceGroupVersion', 'DdcVersion', 'Version') {
        $v = Get-CERProp $site $p; if ($v) { $ver = "$v"; break }
    }
    if (-not $ver -and $ctrls.Count) { $ver = "$(Get-CERProp $ctrls[0] 'ControllerVersion')" }
    $sup = Get-CERCitrixSupport -Version $ver
    $licServer = "$(Get-CERProp $site 'LicenseServerName')"
    $licEdition = "$(Get-CERProp $site 'LicenseEdition')"
    $licModel = "$(Get-CERProp $site 'LicensingModel')"
    $licGrace = Get-CERProp $site 'LicenseGraceSessionsRemaining'
    $peak = Get-CERProp $site 'PeakConcurrentLicenseUsers'
    $active = Get-CERProp $site 'LicensedSessionsActive'
    $lic = $null
    if (Get-Command Get-LicInventory -ErrorAction SilentlyContinue) {
        try { $lic = @(Get-LicInventory -AdminAddress $(if ($licServer) { $licServer } else { $AdminAddress }) -ErrorAction SilentlyContinue | Select-Object LicenseProductName, LicenseEdition, LicenseType, LicensesAvailable, LicensesInUse, LicenseExpirationDate, LicenseSubscriptionAdvantageDate) } catch { }
    }
    Save-CERRaw -Name 'site' -Object ([ordered]@{
            Site = ($site | Select-Object Name, LicenseServerName, LicenseServerPort, LicenseEdition, LicensingModel, LicensedSessionsActive, PeakConcurrentLicenseUsers, LicenseGraceSessionsRemaining, ConnectionLeasingEnabled, LocalHostCacheEnabled, TrustRequestsSentToTheXmlServicePort)
            DetectedVersion = $ver; Support = $sup; Controllers = @($ctrls | Select-Object DNSName, ControllerVersion, State, LastActivityTime, DesktopsRegistered, ActiveSiteServices)
            LicenceInventory = $lic
        })
    $flag = 'OK'
    if ($sup.Supported -eq $false) { $flag = 'Attention' } elseif ($sup.Supported -eq $null) { $flag = 'Unknown' } elseif ($sup.Ltsr -eq $false) { $flag = 'Attention' }
    $act = @()
    if ($sup.Note) { $act += $sup.Note }
    $act += ("Confirm the licensing model. File-based licensing for on-premises Citrix reached end of life on {0} and the License Activation Service is now the only way to activate or re-license - a site still holding file-based licences cannot be re-licensed after a hardware change or a licence server rebuild until it is moved to LAS. Check the Subscription Advantage / Customer Success Services renewal date at the same time, because upgrading to a newer CVAD release requires it to be current on the date that release shipped" -f $script:CERCitrixLasCutover)
    Add-CEREvidence -Control 'SRV-14' -Flag $flag -Action (($act -join '. ') + '.') -Evidence ("Citrix CVAD site '{0}': version {1} ({2}), support status {3}{4}. Delivery Controllers: {5} ({6}). Local Host Cache: {7}. Licence server {8}, edition {9}, model {10}; sessions licensed now {11}, peak concurrent {12}, grace sessions remaining {13}." -f (Get-CERProp $site 'Name'), $(if ($ver) { $ver } else { 'not readable' }), $sup.Family, $(if ($null -eq $sup.Supported) { 'unknown' } elseif ($sup.Supported) { 'in support' } else { 'OUT OF SUPPORT' }), $(if ($sup.EndOfSupport) { (' to ' + $sup.EndOfSupport) } else { '' }), $ctrls.Count, (Join-CERList ($ctrls | ForEach-Object { "{0} [{1}] {2}" -f $_.DNSName, $_.ControllerVersion, $_.State }) 5), (Get-CERProp $site 'LocalHostCacheEnabled'), $(if ($licServer) { $licServer } else { 'not set' }), $licEdition, $licModel, $active, $peak, $licGrace)

    Add-CEREvidence -Control 'LIC-02' -Flag $(if ($sup.Supported -eq $false) { 'Attention' } else { 'Info' }) -Action 'Add the CVAD release, its end-of-support date and the licence edition to the software lifecycle register alongside Windows, SQL and the hypervisor. Citrix LTSR dates are the ones most often missed because the platform keeps working long after support ends, and the extended-support option is a purchase rather than a right.' -Evidence ("CVAD {0} - {1}, end of support {2}{3}. Licence edition {4}, model {5}." -f $sup.Release, $sup.Family, $(if ($sup.EndOfSupport) { $sup.EndOfSupport } else { 'unknown' }), $(if ($sup.ExtendedSupport) { (', paid extended support available to ' + $sup.ExtendedSupport) } else { '' }), $licEdition, $licModel)

    if ($lic) {
        $expSoon = @($lic | Where-Object { $_.LicenseExpirationDate -and (Get-CERAgeDays $_.LicenseExpirationDate) -gt -90 })
        Add-CEREvidence -Control 'LIC-03' -Flag $(if ($expSoon.Count) { 'Attention' } else { 'OK' }) -Action 'Put the Citrix licence and Customer Success Services dates in the renewals calendar with the FortiCare, Veeam and M365 anniversaries. CSS lapsing does not stop the farm, which is exactly why it goes unnoticed until an upgrade is blocked by it.' -Evidence ("Citrix licences on {0}: {1}. Expiring or expired within 90 days: {2}." -f $licServer, (Join-CERList ($lic | ForEach-Object { "{0} {1}: {2} in use of {3}, expires {4}, SA date {5}" -f $_.LicenseProductName, $_.LicenseEdition, $_.LicensesInUse, $_.LicensesAvailable, $_.LicenseExpirationDate, $_.LicenseSubscriptionAdvantageDate }) 6), $expSoon.Count)
    } else {
        Add-CEREvidence -Control 'LIC-03' -Flag Info -Action 'Open the Citrix Licensing console on the licence server and record the licence counts, expiry and Customer Success Services renewal date into the renewals calendar. The licensing SDK was not reachable from here, so this is a manual read.' -Evidence ("Citrix licence inventory not readable from this host (licensing SDK absent or licence server {0} unreachable). Site reports edition {1}, model {2}, peak concurrent {3}." -f $licServer, $licEdition, $licModel, $peak)
    }
}

# ---------------- catalogs and delivery groups
Invoke-CERSection -Collector $C -Section 'CatalogsAndGroups' -Script {
    if (-not $script:sdkOk -or -not $script:site) { Set-CERSectionResult -Status 'Skipped' -Note 'no site'; return }
    $cats = @(); $dgs = @()
    try { $cats = @(Get-BrokerCatalog @script:aa -ErrorAction SilentlyContinue | Select-Object Name, AllocationType, ProvisioningType, SessionSupport, PersistUserChanges, AssignedCount, UnassignedCount, UsedCount, MinimumFunctionalLevel) } catch { }
    try { $dgs = @(Get-BrokerDesktopGroup @script:aa -ErrorAction SilentlyContinue | Select-Object Name, Enabled, InMaintenanceMode, DeliveryType, SessionSupport, TotalDesktops, DesktopsAvailable, DesktopsUnregistered, DesktopsInUse, MinimumFunctionalLevel) } catch { }
    $apps = 0; try { $apps = @(Get-BrokerApplication @script:aa -ErrorAction SilentlyContinue).Count } catch { }
    Save-CERRaw -Name 'catalogs' -Object ([ordered]@{ Catalogs = $cats; DeliveryGroups = $dgs; PublishedApplicationCount = $apps })
    $maint = @($dgs | Where-Object { $_.InMaintenanceMode })
    $disabled = @($dgs | Where-Object { -not $_.Enabled })
    $unreg = @($dgs | Where-Object { $_.DesktopsUnregistered -gt 0 })
    $empty = @($cats | Where-Object { ($_.AssignedCount + $_.UnassignedCount) -eq 0 })
    $act = @()
    if ($maint.Count) { $act += ("Take the {0} delivery group(s) out of maintenance mode, or record why they are in it - {1}. A delivery group left in maintenance after a change window silently stops accepting new sessions while every dashboard still shows it as healthy" -f $maint.Count, (Join-CERList ($maint | ForEach-Object { $_.Name }) 4)) }
    if ($unreg.Count) { $act += ("Investigate the unregistered VDAs in {0}. Unregistered machines are capacity the users have already paid for and cannot reach, and the usual causes are time skew, a firewall rule, or the controller list on the VDA pointing at a decommissioned DDC" -f (Join-CERList ($unreg | ForEach-Object { "{0} ({1} unregistered)" -f $_.Name, $_.DesktopsUnregistered }) 4)) }
    if ($empty.Count) { $act += ("Remove or repopulate the {0} empty machine catalog(s) - {1}. Empty catalogs are usually the residue of a migration that was never tidied up, and they confuse capacity reporting" -f $empty.Count, (Join-CERList ($empty | ForEach-Object { $_.Name }) 4)) }
    Add-CEREvidence -Control 'SRV-14' -Flag $(if ($unreg.Count -or $maint.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action on the farm layout. Confirm the delivery group to user-group mapping still matches who is supposed to have access - published desktops outlive the projects that justified them.' }) -Evidence ("Machine catalogs: {0} ({1}). Delivery groups: {2} - {3} enabled, {4} in maintenance mode ({5}), {6} with unregistered machines. Published applications: {7}. Group detail: {8}." -f $cats.Count, (Join-CERList ($cats | ForEach-Object { "{0} [{1}/{2}] {3} machines" -f $_.Name, $_.AllocationType, $_.ProvisioningType, ($_.AssignedCount + $_.UnassignedCount) }) 5), $dgs.Count, @($dgs | Where-Object { $_.Enabled }).Count, $maint.Count, (Join-CERList ($maint | ForEach-Object { $_.Name }) 3), $unreg.Count, $apps, (Join-CERList ($dgs | ForEach-Object { "{0} [{1}] {2} total / {3} available / {4} unregistered" -f $_.Name, $_.DeliveryType, $_.TotalDesktops, $_.DesktopsAvailable, $_.DesktopsUnregistered }) 6))
}

# ---------------- VDAs: registration and version spread
Invoke-CERSection -Collector $C -Section 'Machines' -Script {
    if (-not $script:sdkOk -or -not $script:site) { Set-CERSectionResult -Status 'Skipped' -Note 'no site'; return }
    $m = @()
    try { $m = @(Get-BrokerMachine @script:aa -MaxRecordCount $MaxMachines -ErrorAction SilentlyContinue | Select-Object DNSName, MachineName, RegistrationState, AgentVersion, OSType, PowerState, InMaintenanceMode, SessionCount, CatalogName, DesktopGroupName, LastDeregistrationReason) } catch { }
    if (-not $m.Count) { Set-CERSectionResult -Status 'Partial' -Note 'no machines returned'; }
    Save-CERRaw -Name 'machines' -Object $m
    $unreg = @($m | Where-Object { "$($_.RegistrationState)" -ne 'Registered' -and "$($_.PowerState)" -ne 'Off' })
    $maint = @($m | Where-Object { $_.InMaintenanceMode })
    $byVer = @($m | Where-Object { $_.AgentVersion } | Group-Object AgentVersion | Sort-Object Count -Descending)
    $siteVer = ''
    if ($script:site) { foreach ($p in 'ControllerVersion', 'BrokerServiceGroupVersion', 'DdcVersion') { $v = Get-CERProp $script:site $p; if ($v) { $siteVer = "$v"; break } } }
    # A VDA older than the controller is supported; newer than the controller is not, and old VDAs cap features.
    $vdaOld = @($byVer | Where-Object { $_.Name -match '^7\.(\d|1[0-4])\D' -or $_.Name -match '^(19|20)(0[0-9]|1[0-2])' })
    $deregReasons = @($m | Where-Object { $_.LastDeregistrationReason } | Group-Object LastDeregistrationReason | Sort-Object Count -Descending)
    $act = @()
    if ($unreg.Count) { $act += ("Work the {0} powered-on VDA(s) that are not registered. The most common last-deregistration reasons here are {1} - time skew, a blocked port 80/443 to the controller, or a stale ListOfDDCs registry value after a controller was replaced" -f $unreg.Count, (Join-CERList ($deregReasons | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) 3)) }
    if ($byVer.Count -gt 3) { $act += ("Consolidate the VDA estate onto fewer versions - {0} distinct VDA versions are in use. A spread this wide means image builds have diverged, and the oldest VDA silently caps which features the whole delivery group can use" -f $byVer.Count) }
    if ($maint.Count) { $act += ("Confirm the {0} machine(s) in maintenance mode are deliberate. Machines left in maintenance are paid-for capacity nobody can log on to" -f $maint.Count) }
    Add-CEREvidence -Control 'SRV-14' -Flag $(if ($unreg.Count) { 'Attention' } else { 'OK' }) -Action $(if ($act.Count) { (($act -join '. ') + '.') } else { 'No action. Confirm the VDA version is being patched on the same cadence as the underlying OS - Citrix ships VDA security fixes separately from Windows Update, so a fully patched Windows box can still carry a vulnerable VDA.' }) -Evidence ("VDAs: {0} machines, {1} registered, {2} powered-on but unregistered, {3} in maintenance mode, {4} with active sessions. VDA versions in use ({5} distinct): {6}. Site/controller version: {7}. Deregistration reasons seen: {8}." -f $m.Count, @($m | Where-Object { "$($_.RegistrationState)" -eq 'Registered' }).Count, $unreg.Count, $maint.Count, @($m | Where-Object { $_.SessionCount -gt 0 }).Count, $byVer.Count, (Join-CERList ($byVer | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) 6), $(if ($siteVer) { $siteVer } else { 'unknown' }), (Join-CERList ($deregReasons | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) 4))

    Add-CEREvidence -Control 'SRV-02' -Flag Info -Action 'Cross-check these VDA hostnames against the Servers collector and the host check for Windows build and support status. A session host running an out-of-support Windows Server build carries every user session on the farm, so it is the highest-impact OS in the estate and usually the last one anybody reboots.' -Evidence ("Citrix session hosts and VDIs by OS type: {0}. Hostnames are in raw\citrix.machines.json - match them to the Servers collector for Windows build and support status." -f (Join-CERList (@($m | Group-Object OSType | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count })) 5))
}

# ---------------- sessions and database
Invoke-CERSection -Collector $C -Section 'SessionsAndDatabase' -Script {
    if (-not $script:sdkOk -or -not $script:site) { Set-CERSectionResult -Status 'Skipped' -Note 'no site'; return }
    $sess = @()
    try { $sess = @(Get-BrokerSession @script:aa -MaxRecordCount $MaxMachines -ErrorAction SilentlyContinue | Select-Object SessionState, Protocol, ClientVersion, DesktopGroupName, StartTime) } catch { }
    $db = @()
    if (Get-Command Get-BrokerDBConnection -ErrorAction SilentlyContinue) {
        try {
            $raw = "$(Get-BrokerDBConnection @script:aa -ErrorAction SilentlyContinue)"
            # connection strings can carry SQL credentials - keep the shape, drop any secret
            $safe = [regex]::Replace($raw, '(?i)(password|pwd)\s*=\s*[^;]*', '$1=<REDACTED>')
            $db += [pscustomobject]@{ Service = 'Broker'; ConnectionString = $safe; IntegratedSecurity = ($raw -imatch 'Integrated Security\s*=\s*(SSPI|true)') }
        } catch { }
    }
    Save-CERRaw -Name 'sessions' -Object ([ordered]@{ SessionSummary = @($sess | Group-Object SessionState | ForEach-Object { [pscustomobject]@{ State = $_.Name; Count = $_.Count } }); Protocols = @($sess | Group-Object Protocol | ForEach-Object { [pscustomobject]@{ Protocol = $_.Name; Count = $_.Count } }); ClientVersions = @($sess | Group-Object ClientVersion | ForEach-Object { [pscustomobject]@{ Version = $_.Name; Count = $_.Count } }); Database = $db })
    $disc = @($sess | Where-Object { "$($_.SessionState)" -imatch 'Disconnect' })
    $sqlAuth = @($db | Where-Object { -not $_.IntegratedSecurity })
    $act = @()
    if ($disc.Count -and $sess.Count -and (100 * $disc.Count / $sess.Count) -gt 40) { $act += ("{0} of {1} sessions are disconnected rather than logged off. Confirm the delivery group's disconnect and logoff timers are set - disconnected sessions hold their full memory and licence allocation, so a farm sized on concurrent users runs out of resource well before it runs out of users" -f $disc.Count, $sess.Count) }
    if ($sqlAuth.Count) { $act += 'The site database connection is not using integrated security. SQL authentication means a password in a connection string on every controller - move to Windows authentication with the controller computer accounts, which is the supported and credential-free arrangement' }
    $act += 'Confirm the site database is on a SQL instance with an HA arrangement that matches the farm''s importance (Always On availability group or a failover cluster), and that it is in the backup job with application-aware processing. The CVAD site database is a single point of failure for every session in the farm, and Local Host Cache only carries brokering for a limited window'
    Add-CEREvidence -Control 'SRV-14' -Flag Info -Action (($act -join '. ') + '.') -Evidence ("Sessions at time of collection: {0} ({1}). Protocols: {2}. Receiver/Workspace app versions in use: {3}. Site database: {4}." -f $sess.Count, (Join-CERList (@($sess | Group-Object SessionState | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })) 4), (Join-CERList (@($sess | Group-Object Protocol | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })) 4), (Join-CERList (@($sess | Group-Object ClientVersion | Sort-Object Count -Descending | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count })) 5), $(if ($db.Count) { (Join-CERList ($db | ForEach-Object { "{0}: {1}" -f $_.Service, $_.ConnectionString }) 2) } else { 'not readable from here - check Studio > Configuration' }))
}

Complete-CERCollector

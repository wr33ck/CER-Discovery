#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: Entra ID / tenant-wide Microsoft 365 settings via Microsoft Graph (delegated, GDAP-friendly).
  Feeds IAM-01..14, M365-01/06/10/11/12, END-01/07/08, AZ-02, SEC-11, LIC-04.
.NOTES
  Requires Microsoft.Graph.Authentication only (Invoke-MgGraphRequest). First run in a tenant prompts for consent of
  "Microsoft Graph Command Line Tools" - tick "Consent on behalf of your organization" (GDAP Global Admin / Cloud App Admin)
  or pre-consent it. Roles that make everything readable: Global Reader + Security Reader (GDAP).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [Parameter(Mandatory)][string]$TenantId,
    [switch]$UseDeviceCode,
    [switch]$NoConnect,
    [int]$SignInDays = 7,
    [int]$MaxSignIns = 5000,
    [int]$StaleDays = 90
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Entra' -RunId $RunId
$C = 'Entra'
if (-not (Test-CERModule -Name Microsoft.Graph.Authentication -Collector $C)) { Complete-CERCollector; return }
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
$now = Get-Date

$scopes = @('Directory.Read.All', 'Policy.Read.All', 'AuditLog.Read.All', 'Reports.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All',
    'SecurityEvents.Read.All', 'SecurityAlert.Read.All', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All', 'DeviceLocalCredential.ReadBasic.All', 'BitLockerKey.ReadBasic.All',
    'SharePointTenantSettings.Read.All', 'ServiceMessage.Read.All', 'UserAuthenticationMethod.Read.All',
    'DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementApps.Read.All', 'DeviceManagementServiceConfig.Read.All')

Invoke-CERSection -Collector $C -Section 'Connect' -Script {
    $ctx = Get-MgContext
    if ($NoConnect -and $ctx -and ($ctx.TenantId -eq $TenantId)) { Write-CERLog ("Reusing Graph session {0} in {1}" -f $ctx.Account, $ctx.TenantId); return }
    $p = @{ TenantId = $TenantId; Scopes = $scopes; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($UseDeviceCode) { $p['UseDeviceCode'] = $true }
    Connect-MgGraph @p
    $ctx = Get-MgContext
    Write-CERLog ("Connected to Graph as {0} tenant {1} ({2} scopes granted)" -f $ctx.Account, $ctx.TenantId, @($ctx.Scopes).Count)
    Save-CERRaw -Name 'context' -Object ([ordered]@{ Account = $ctx.Account; TenantId = $ctx.TenantId; Scopes = $ctx.Scopes; Environment = $ctx.Environment })
}
if (-not (Get-MgContext)) { Complete-CERCollector; return }

# ---------------- Organisation, domains, sync
$org = $null; $domains = @(); $tier = @{ P1 = $false; P2 = $false; Intune = $false; DefenderO365 = $false; MDE = $false; Purview = $false }
Invoke-CERSection -Collector $C -Section 'Organization' -Script {
    $script:org = (Get-CERGraph 'organization?$select=id,displayName,verifiedDomains,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime,createdDateTime,technicalNotificationMails,securityComplianceNotificationMails,privacyProfile,tenantType')[0]
    $script:domains = @(Get-CERGraph 'domains' -All)
    $sync = $null; try { $sync = Get-CERGraph 'directory/onPremisesSynchronization' } catch { }
    Save-CERRaw -Name 'organization' -Object ([ordered]@{ Org = $script:org; Domains = $script:domains; OnPremSync = $sync })
    $fed = @($script:domains | Where-Object { $_.authenticationType -eq 'Federated' } | ForEach-Object { $_.id })
    $unver = @($script:domains | Where-Object { -not $_.isVerified } | ForEach-Object { $_.id })
    $syncAge = Get-CERAgeDays $script:org.onPremisesLastSyncDateTime
    $syncTxt = if ($script:org.onPremisesSyncEnabled) { "hybrid - last directory sync {0} ({1:n1} h ago), last password hash sync {2}" -f $script:org.onPremisesLastSyncDateTime, ((($now.ToUniversalTime()) - [datetime]$script:org.onPremisesLastSyncDateTime).TotalHours), $script:org.onPremisesLastPasswordSyncDateTime } else { 'cloud-only (onPremisesSyncEnabled not set)' }
    $feat = if ($sync -and $sync.features) { ($sync.features.PSObject.Properties | Where-Object { $_.Value -eq $true } | ForEach-Object { $_.Name }) -join ', ' } else { 'n/a' }
    $flag = if ($script:org.onPremisesSyncEnabled -and $syncAge -ne $null -and ((($now.ToUniversalTime()) - [datetime]$script:org.onPremisesLastSyncDateTime).TotalHours -gt 3)) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-01' -Flag $flag -Action 'Record the identity posture in STACK.md - cloud-only or hybrid, which sync tool, and which domains are federated. A federated domain means authentication happens somewhere other than Entra, so any control assessed here does not apply to it; identify what that identity provider is and who runs it.' -Evidence ("Tenant '{0}' ({1}): identity posture {2}. Sync features enabled: {3}. Domains: {4} verified ({5} federated: {6}; {7} unverified). Technical notification mail: {8}." -f $script:org.displayName, $script:org.id, $syncTxt, $feat, @($script:domains | Where-Object isVerified).Count, $fed.Count, (Join-CERList $fed 3), $unver.Count, (($script:org.technicalNotificationMails) -join ', '))
    Add-CEREvidence -Control 'M365-12' -Flag Info -Action 'Point the tenant technical and security notification addresses at a monitored shared mailbox or the bA service desk, never a named individual. These are the addresses Microsoft uses for breach and service notifications, and they are routinely still set to someone who left.' -Evidence ("Tenant technical notification address(es): {0}; security & compliance notification: {1}. Confirm these are monitored role mailboxes, not ex-staff." -f (($script:org.technicalNotificationMails) -join ', '), (($script:org.securityComplianceNotificationMails) -join ', '))
}

# ---------------- Licensing / tier detection
Invoke-CERSection -Collector $C -Section 'Licensing' -Script {
    $skus = @(Get-CERGraph 'subscribedSkus' -All)
    $rows = @($skus | ForEach-Object { [pscustomobject]@{ Sku = $_.skuPartNumber; Enabled = $_.prepaidUnits.enabled; Warning = $_.prepaidUnits.warning; Suspended = $_.prepaidUnits.suspended; Consumed = $_.consumedUnits; Unassigned = ($_.prepaidUnits.enabled - $_.consumedUnits); Status = $_.capabilityStatus; Plans = @($_.servicePlans | Where-Object { $_.provisioningStatus -eq 'Success' } | ForEach-Object { $_.servicePlanName }) } })
    $plans = @($rows | ForEach-Object { $_.Plans }) | Select-Object -Unique
    $script:tier.P1 = [bool]($plans | Where-Object { $_ -eq 'AAD_PREMIUM' -or $_ -eq 'AAD_PREMIUM_P2' }); $script:tier.P2 = [bool]($plans | Where-Object { $_ -eq 'AAD_PREMIUM_P2' })
    $script:tier.Intune = [bool]($plans | Where-Object { $_ -like 'INTUNE_A*' -or $_ -eq 'INTUNE_O365' }); $script:tier.DefenderO365 = [bool]($plans | Where-Object { $_ -like 'ATP_ENTERPRISE*' -or $_ -eq 'THREAT_INTELLIGENCE' })
    $script:tier.MDE = [bool]($plans | Where-Object { $_ -like 'WINDEFATP*' -or $_ -like 'MDE_*' -or $_ -eq 'DEFENDER_ENDPOINT_P1' }); $script:tier.Purview = [bool]($plans | Where-Object { $_ -like 'MIP_S_CLP*' -or $_ -like 'RMS_S_*' })
    Save-CERRaw -Name 'licensing' -Object ([ordered]@{ Skus = $rows; Tier = $script:tier })
    $paid = @($rows | Where-Object { $_.Enabled -gt 0 -and $_.Sku -notmatch 'FREE|TRIAL|FLOW_FREE|POWER_BI_STANDARD|TEAMS_EXPLORATORY|STREAM|POWERAPPS_VIRAL|WINDOWS_STORE|RIGHTSMANAGEMENT_ADHOC|MCOPSTNC' })
    $unassigned = ($paid | Measure-Object Unassigned -Sum).Sum
    $flag = if ($paid.Count -and (($paid | Measure-Object Enabled -Sum).Sum) -gt 0 -and ($unassigned / (($paid | Measure-Object Enabled -Sum).Sum)) -gt 0.05) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'M365-10' -Flag $flag -Action 'Reclaim the unassigned paid seats or reduce the subscription at the next NCE anniversary. Also check the entitlements the client already owns but is not using - a licensed but undeployed P1, Intune or Defender feature is a security control they have already paid for, which is the easiest improvement to fund.' -Evidence ("Licences: {0}. Unassigned paid seats: {1}. Entitlements detected: Entra P1={2}, P2={3}, Intune={4}, Defender for Office={5}, Defender for Endpoint={6}, Purview IP={7}." -f (Join-CERList ($paid | Sort-Object Enabled -Descending | ForEach-Object { "{0} {1}/{2}" -f $_.Sku, $_.Consumed, $_.Enabled }) 8), $unassigned, $script:tier.P1, $script:tier.P2, $script:tier.Intune, $script:tier.DefenderO365, $script:tier.MDE, $script:tier.Purview)
    Add-CEREvidence -Control 'LIC-04' -Flag $flag -Action 'Take the unassigned seat count and the assigned-versus-active gap to the CAM ahead of the NCE anniversary date. Seats can only be reduced at that anniversary, so raising it a month late costs the client a full term.' -Evidence ("M365 assigned vs purchased: {0} unassigned paid seats across {1} SKUs ({2}). Active-usage comparison needs the usage reports (manual)." -f $unassigned, $paid.Count, (Join-CERList ($paid | Where-Object { $_.Unassigned -gt 0 } | ForEach-Object { "{0} +{1}" -f $_.Sku, $_.Unassigned }) 6))
}

# ---------------- Users
$users = @()
Invoke-CERSection -Collector $C -Section 'Users' -Script {
    $sel = 'id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,onPremisesSyncEnabled,assignedLicenses,signInActivity,mail'
    try { $script:users = @(Get-CERGraph ("users?`$select={0}&`$top=999" -f $sel) -All -MaxPages 200) }
    catch { Write-CERLog "signInActivity not available (needs Entra P1) - retrying without" 'WARN'; $script:users = @(Get-CERGraph ("users?`$select={0}&`$top=999" -f ($sel -replace ',signInActivity', '')) -All -MaxPages 200); Set-CERSectionResult -Status Partial -Note 'No signInActivity (Entra P1 required) - stale detection uses createdDateTime only' }
    $u = $script:users
    $members = @($u | Where-Object { $_.userType -ne 'Guest' }); $guests = @($u | Where-Object { $_.userType -eq 'Guest' })
    $enabled = @($members | Where-Object accountEnabled); $licensed = @($enabled | Where-Object { @($_.assignedLicenses).Count -gt 0 })
    $cut = $now.AddDays(-$StaleDays)
    function _last { param($x) $sa = Get-CERProp $x 'signInActivity'; if (-not $sa) { return $null }; $d = @($sa.lastSignInDateTime, $sa.lastNonInteractiveSignInDateTime) | Where-Object { $_ } | ForEach-Object { [datetime]$_ } | Sort-Object -Descending | Select-Object -First 1; return $d }
    $stale = @($enabled | Where-Object { $l = _last $_; ($l -and $l -lt $cut) -or (-not $l -and [datetime]$_.createdDateTime -lt $cut) })
    $staleLicensed = @($stale | Where-Object { @($_.assignedLicenses).Count -gt 0 })
    $staleGuests = @($guests | Where-Object { $l = _last $_; ($l -and $l -lt $cut) -or (-not $l -and [datetime]$_.createdDateTime -lt $cut) })
    $syncAcct = @($u | Where-Object { $_.userPrincipalName -like 'Sync_*' -or $_.displayName -like 'On-Premises Directory Synchronization*' })
    $syncServer = @($syncAcct | ForEach-Object { if ($_.userPrincipalName -match '^Sync_([^_]+)_') { $Matches[1] } }) | Select-Object -Unique
    Save-CERRaw -Name 'users.summary' -Object ([ordered]@{ Total = $u.Count; Members = $members.Count; Enabled = $enabled.Count; Licensed = $licensed.Count; Guests = $guests.Count; Stale = @($stale | ForEach-Object { $_.userPrincipalName }); StaleLicensed = @($staleLicensed | ForEach-Object { $_.userPrincipalName }); StaleGuests = @($staleGuests | ForEach-Object { $_.userPrincipalName }); SyncAccounts = @($syncAcct | ForEach-Object { $_.userPrincipalName }) })
    Save-CERRaw -Name 'users' -Object @($u | Select-Object id, userPrincipalName, displayName, accountEnabled, userType, onPremisesSyncEnabled, mail, @{ n = 'licenses'; e = { @($_.assignedLicenses).Count } })
    $flag = if ($enabled.Count -and ($stale.Count / $enabled.Count) -gt 0.02) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-09' -Flag $flag -Action 'Disable the enabled member accounts with no sign-in in the period, then delete after a documented retention window. Agree a joiner-mover-leaver process with the client so the same list is not here at the next review - dormant enabled accounts are credentials nobody is monitoring.' -Evidence ("Entra users: {0} members ({1} enabled, {2} licensed), {3} guests. Enabled members with no sign-in for {4}+ days: {5} ({6}), of which {7} still licensed ({8})." -f $members.Count, $enabled.Count, $licensed.Count, $guests.Count, $StaleDays, $stale.Count, (ConvertTo-CERPct $stale.Count $enabled.Count), $staleLicensed.Count, (Join-CERList ($staleLicensed | ForEach-Object { $_.userPrincipalName }) 5))
    Add-CEREvidence -Control 'IAM-08' -Flag $(if ($guests.Count -and ($staleGuests.Count / $guests.Count) -gt 0.2) { 'Attention' } else { 'OK' }) -Action 'Remove the inactive guest accounts and turn on access reviews for guests where P2 is licensed. Every guest is a standing external identity with access to something; if nobody can say what a guest is for, that is the answer.' -Evidence ("Guests: {0}; inactive {1}+ days: {2} ({3})." -f $guests.Count, $StaleDays, $staleGuests.Count, (ConvertTo-CERPct $staleGuests.Count $guests.Count))
    if ($staleLicensed.Count) { Add-CEREvidence -Control 'M365-10' -Flag Attention -Action 'Reclaim the licences from accounts with no sign-in - this is both a cost saving and a leaver-detection signal. A licensed account nobody uses is usually either a departure that was never processed or a service account that should not hold a user licence.' -Evidence ("{0} licensed accounts with no sign-in for {1}+ days (licence waste / leaver risk)." -f $staleLicensed.Count, $StaleDays) }
    if ($syncServer.Count) { Add-CEREvidence -Control 'IAM-01' -Flag Info -Action 'Record this sync server in STACK.md, confirm the Entra Connect build is still supported, and check whether a staging-mode server exists. With no staging server, losing this host stops directory sync and password hash sync until it is rebuilt.' -Evidence ("Entra Connect sync account(s) point at server: {0}" -f ($syncServer -join ', ')) }
}

# ---------------- Roles / privileged
$adminIds = @()
Invoke-CERSection -Collector $C -Section 'PrivilegedRoles' -Script {
    $defs = @(Get-CERGraph 'roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn' -All)
    $defMap = @{}; foreach ($d in $defs) { $defMap[$d.id] = $d.displayName }
    $assign = @(Get-CERGraph 'roleManagement/directory/roleAssignments?$expand=principal' -All)
    $rows = @($assign | ForEach-Object { $p = $_.principal; [pscustomobject]@{ Role = $defMap[$_.roleDefinitionId]; PrincipalType = ("$($p.'@odata.type')" -replace '#microsoft.graph.', ''); Name = (Get-CERProp $p 'displayName'); UPN = (Get-CERProp $p 'userPrincipalName'); Id = $p.id; Scope = $_.directoryScopeId } })
    $userLookup = @{}; foreach ($x in $script:users) { $userLookup[$x.id] = $x }
    $ga = @($rows | Where-Object { $_.Role -eq 'Global Administrator' })
    $privRoles = 'Global Administrator', 'Privileged Role Administrator', 'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'User Administrator', 'Conditional Access Administrator', 'Application Administrator', 'Cloud Application Administrator', 'Intune Administrator', 'Authentication Administrator', 'Privileged Authentication Administrator', 'Hybrid Identity Administrator', 'Global Reader', 'Helpdesk Administrator', 'Password Administrator', 'Domain Name Administrator', 'Partner Tier2 Support', 'Directory Synchronization Accounts'
    $privUsers = @($rows | Where-Object { $_.PrincipalType -eq 'user' -and $privRoles -contains $_.Role } | Select-Object -ExpandProperty Id -Unique | ForEach-Object { $userLookup[$_] } | Where-Object { $_ })
    $script:adminIds = @($privUsers | ForEach-Object { $_.id })
    $gaUsers = @($ga | Where-Object { $_.PrincipalType -eq 'user' } | ForEach-Object { $userLookup[$_.Id] } | Where-Object { $_ })
    $licensedAdmins = @($privUsers | Where-Object { @($_.assignedLicenses).Count -gt 0 -or $_.mail })
    $syncedAdmins = @($privUsers | Where-Object { $_.onPremisesSyncEnabled -eq $true })
    $guestAdmins = @($privUsers | Where-Object { $_.userType -eq 'Guest' })
    $spAdmins = @($rows | Where-Object { $_.PrincipalType -eq 'servicePrincipal' -and $privRoles -contains $_.Role })
    $pim = $null; try { $pim = @(Get-CERGraph 'roleManagement/directory/roleEligibilityScheduleInstances?$select=id,roleDefinitionId,principalId' -All) } catch { $pim = $null }
    Save-CERRaw -Name 'roles' -Object ([ordered]@{ Assignments = $rows; GlobalAdmins = @($ga | ForEach-Object { $_.UPN }); PIMEligible = $(if ($null -ne $pim) { $pim.Count } else { 'n/a' }) })
    $flag = if ($gaUsers.Count -gt 4 -or $gaUsers.Count -lt 2 -or $licensedAdmins.Count -gt 0 -or $syncedAdmins.Count -gt 0) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-05' -Flag $flag -Action 'Reduce standing Global Administrators to between two and four, all cloud-only, and move everyone else to the least-privileged role that covers their job. Where P2 is licensed, put the remaining roles behind Privileged Identity Management so they are activated on request rather than held permanently.' -Evidence ("Global Administrators: {0} ({1}); total privileged-role users: {2}; admins with a licence or mailbox (likely daily-driver accounts): {3} ({4}); admins synced from on-prem AD: {5} ({6}); guest admins: {7}; service principals in privileged roles: {8}. PIM eligible assignments: {9} (P2 {10})." -f $gaUsers.Count, (Join-CERList ($gaUsers | ForEach-Object { $_.userPrincipalName }) 6), $privUsers.Count, $licensedAdmins.Count, (Join-CERList ($licensedAdmins | ForEach-Object { $_.userPrincipalName }) 6), $syncedAdmins.Count, (Join-CERList ($syncedAdmins | ForEach-Object { $_.userPrincipalName }) 4), $guestAdmins.Count, $spAdmins.Count, $(if ($null -ne $pim) { $pim.Count } else { 'not readable' }), $script:tier.P2)
    Add-CEREvidence -Control 'SEC-08' -Flag $flag -Action 'Give administrators dedicated, cloud-only admin accounts with no mailbox and no licence, and leave email and browsing on their standard user account. An admin account that reads mail is one phishing click from tenant compromise, and it is the single most common way tenants are taken.' -Evidence ("Privileged Entra accounts: {0}; with mailbox/licence (not isolated from email/web): {1}; role breakdown: {2}." -f $privUsers.Count, $licensedAdmins.Count, (Join-CERList ($rows | Where-Object { $privRoles -contains $_.Role } | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 8))
    Add-CEREvidence -Control 'IAM-07' -Flag Info -Action 'Confirm partner access is GDAP with least-privilege roles and a defined expiry, and that no legacy DAP relationship survives. Check the Directory Synchronization Accounts entries match sync servers that still exist - an orphaned one is a standing privileged identity.' -Evidence ("Partner-style principals in roles: 'Partner Tier2 Support' = {0}, 'Directory Synchronization Accounts' = {1}. GDAP relationship status must be read from M365 Lighthouse / Partner Center (bA tenant), not from the customer tenant." -f @($rows | Where-Object { $_.Role -eq 'Partner Tier2 Support' }).Count, @($rows | Where-Object { $_.Role -eq 'Directory Synchronization Accounts' }).Count)
}

# ---------------- Conditional Access + security defaults
$caPolicies = @()
Invoke-CERSection -Collector $C -Section 'ConditionalAccess' -Script {
    $script:caPolicies = @(Get-CERGraph 'identity/conditionalAccess/policies' -All)
    $named = @(Get-CERGraph 'identity/conditionalAccess/namedLocations' -All)
    $sd = Get-CERGraph 'policies/identitySecurityDefaultsEnforcementPolicy'
    $on = @($script:caPolicies | Where-Object { $_.state -eq 'enabled' }); $ro = @($script:caPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }); $off = @($script:caPolicies | Where-Object { $_.state -eq 'disabled' })
    function _ctl { param($p) @((Get-CERProp (Get-CERProp $p 'grantControls') 'builtInControls')) }
    function _allUsers { param($p) $u = $p.conditions.users; (@($u.includeUsers) -contains 'All') }
    function _allApps { param($p) (@($p.conditions.applications.includeApplications) -contains 'All') }
    $mfaAll = @($on | Where-Object { (_allUsers $_) -and ((_ctl $_) -contains 'mfa' -or (Get-CERProp (Get-CERProp $_ 'grantControls') 'authenticationStrength')) -and (_allApps $_) })
    $mfaAny = @($on | Where-Object { ((_ctl $_) -contains 'mfa') -or (Get-CERProp (Get-CERProp $_ 'grantControls') 'authenticationStrength') })
    $legacy = @($on | Where-Object { $c = @($_.conditions.clientAppTypes); ($c -contains 'exchangeActiveSync' -or $c -contains 'other') -and ((_ctl $_) -contains 'block') })
    $compliant = @($on | Where-Object { $c = _ctl $_; ($c -contains 'compliantDevice' -or $c -contains 'domainJoinedDevice') })
    $appProt = @($on | Where-Object { $c = _ctl $_; ($c -contains 'approvedApplication' -or $c -contains 'compliantApplication') })
    $strengthAdmins = @($on | Where-Object { (Get-CERProp (Get-CERProp $_ 'grantControls') 'authenticationStrength') -and @($_.conditions.users.includeRoles).Count -gt 0 })
    $adminMfa = @($on | Where-Object { @($_.conditions.users.includeRoles).Count -gt 0 -and ((_ctl $_) -contains 'mfa' -or (Get-CERProp (Get-CERProp $_ 'grantControls') 'authenticationStrength')) })
    $risk = @($on | Where-Object { @($_.conditions.signInRiskLevels).Count -gt 0 -or @($_.conditions.userRiskLevels).Count -gt 0 })
    $platformBlock = @($on | Where-Object { $_.conditions.platforms -and (@($_.conditions.platforms.includePlatforms) -contains 'all') -and ((_ctl $_) -contains 'block') })
    $session = @($on | Where-Object { $s = $_.sessionControls; $s -and ((Get-CERProp $s 'signInFrequency') -or (Get-CERProp $s 'persistentBrowser') -or (Get-CERProp $s 'applicationEnforcedRestrictions')) })
    $blockCountries = @($on | Where-Object { @($_.conditions.locations.includeLocations).Count -gt 0 -and ((_ctl $_) -contains 'block') })
    # break-glass candidates: users excluded from every enabled policy that targets All users
    $allUserPolicies = @($on | Where-Object { _allUsers $_ })
    $bg = @()
    if ($allUserPolicies.Count -gt 0) {
        $sets = @($allUserPolicies | ForEach-Object { , @($_.conditions.users.excludeUsers) })
        $common = $sets[0]; foreach ($s in $sets) { $common = @($common | Where-Object { $s -contains $_ }) }
        $bg = @($common | ForEach-Object { $id = $_; $x = $script:users | Where-Object { $_.id -eq $id } | Select-Object -First 1; if ($x) { $x.userPrincipalName } else { $id } })
    }
    Save-CERRaw -Name 'conditionalaccess' -Object ([ordered]@{ Policies = @($script:caPolicies | Select-Object id, displayName, state, createdDateTime, modifiedDateTime, conditions, grantControls, sessionControls); NamedLocations = @($named | Select-Object id, displayName, '@odata.type', isTrusted, countriesAndRegions); SecurityDefaults = $sd.isEnabled; BreakGlassCandidates = $bg })
    $flag = if ($mfaAll.Count -eq 0 -and -not $sd.isEnabled) { 'Attention' } elseif ($mfaAll.Count -eq 0 -and $sd.isEnabled) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-02' -Flag $flag -Action 'Review the Conditional Access policy set as a whole rather than policy by policy: confirm every user and every app is covered by at least one enforcing policy, and move anything still in report-only to enforcement with a date. Report-only looks like coverage in a policy list and enforces nothing.' -Evidence ("Conditional Access: {0} policies ({1} enabled, {2} report-only, {3} disabled). Security Defaults: {4}. Enabled policies requiring MFA for ALL users on ALL apps: {5} ({6}); any MFA policy: {7}. Report-only policies left in place: {8}." -f $script:caPolicies.Count, $on.Count, $ro.Count, $off.Count, $sd.isEnabled, $mfaAll.Count, (Join-CERList ($mfaAll | ForEach-Object { $_.displayName }) 3), $mfaAny.Count, (Join-CERList ($ro | ForEach-Object { $_.displayName }) 4))
    Add-CEREvidence -Control 'IAM-04' -Flag $(if ($legacy.Count) { 'OK' } elseif ($sd.isEnabled) { 'OK' } else { 'Attention' }) -Action 'Create and enable a Conditional Access policy blocking legacy authentication for all users. Legacy protocols cannot present a second factor, so while they are reachable MFA is optional in practice - this is the highest-value single CA policy in the tenant.' -Evidence ("Legacy authentication block via CA: {0} enabled policy(ies) ({1}); Security Defaults (also blocks legacy auth): {2}." -f $legacy.Count, (Join-CERList ($legacy | ForEach-Object { $_.displayName }) 3), $sd.isEnabled)
    Add-CEREvidence -Control 'IAM-03' -Flag $(if ($strengthAdmins.Count) { 'OK' } elseif ($adminMfa.Count) { 'Attention' } else { 'Attention' }) -Action 'Require a phishing-resistant authentication strength (FIDO2 or Windows Hello for Business) for the admin roles, not just any MFA. Push and SMS both fall to real-world phishing and MFA-fatigue attacks; for privileged roles that difference is the whole control.' -Evidence ("Admin-role CA policies: {0} require MFA, {1} require a phishing-resistant authentication strength ({2})." -f $adminMfa.Count, $strengthAdmins.Count, (Join-CERList ($strengthAdmins | ForEach-Object { "{0} -> {1}" -f $_.displayName, $_.grantControls.authenticationStrength.displayName }) 3))
    Add-CEREvidence -Control 'IAM-12' -Flag $(if ($compliant.Count -and $platformBlock.Count -and $session.Count) { 'OK' } else { 'Attention' }) -Action 'Add a Conditional Access policy requiring a compliant or hybrid-joined device for corporate applications, and block the platforms the client does not support. Without a device condition, a valid password and MFA code work from any machine anywhere, including an attacker''s.' -Evidence ("CA baseline: require compliant/hybrid-joined device = {0} ({1}); block unsupported platforms = {2}; session controls (sign-in frequency / no persistent browser / app-enforced) = {3}; location block policies = {4}; named locations = {5} ({6} trusted)." -f $compliant.Count, (Join-CERList ($compliant | ForEach-Object { $_.displayName }) 3), $platformBlock.Count, $session.Count, $blockCountries.Count, $named.Count, @($named | Where-Object isTrusted).Count)
    Add-CEREvidence -Control 'IAM-13' -Flag $(if (-not $script:tier.P2) { 'Info' } elseif ($risk.Count -ge 1) { 'OK' } else { 'Attention' }) -Action 'Where P2 is licensed, enable the sign-in risk and user risk Conditional Access policies - they are the only automated response to a credential that is already known to be compromised. Where P2 is not licensed, record that as the reason and price it, rather than leaving the gap unexplained.' -Evidence ("Risk-based CA policies (Identity Protection, P2={0}): {1} enabled ({2})." -f $script:tier.P2, $risk.Count, (Join-CERList ($risk | ForEach-Object { $_.displayName }) 3))
    Add-CEREvidence -Control 'IAM-06' -Flag $(if ($bg.Count -ge 1 -and $bg.Count -le 3) { 'OK' } elseif ($bg.Count -eq 0) { 'Attention' } else { 'Attention' }) -Action 'Verify the break-glass accounts properly: two of them, cloud-only, excluded from every CA policy, passwords in the client CyberArk safe, phishing-resistant MFA registered, and a sign-in alert configured so their use is noticed. Then test one. An untested break-glass account is a theory.' -Evidence ("Accounts excluded from every all-user CA policy (break-glass candidates): {0} - {1}. Verify: cloud-only, strong secret vaulted, sign-in alert configured, tested." -f $bg.Count, (Join-CERList $bg 5))
    Add-CEREvidence -Control 'END-12' -Flag $(if ($compliant.Count) { 'OK' } else { 'Attention' }) -Action 'Add the Intune compliance requirement to Conditional Access - enrolling devices in Intune achieves nothing for access control until a CA policy actually requires compliance. Confirm the compliance policy itself checks something meaningful (encryption, AV, OS minimum), not just enrolment.' -Evidence ("CA policies enforcing Intune compliance: {0}." -f $compliant.Count)
    Add-CEREvidence -Control 'END-14' -Flag $(if ($appProt.Count) { 'OK' } else { 'Attention' }) -Action 'Require app protection policies or approved client apps for mobile access to corporate data. Without it, mail and files can be pulled onto an unmanaged personal phone with no ability to wipe corporate data selectively when the person leaves.' -Evidence ("CA policies requiring app protection / approved client app for mobile: {0} ({1})." -f $appProt.Count, (Join-CERList ($appProt | ForEach-Object { $_.displayName }) 3))
}

# ---------------- Authentication methods
Invoke-CERSection -Collector $C -Section 'AuthenticationMethods' -Script {
    $reg = @(Get-CERGraph 'reports/authenticationMethods/userRegistrationDetails?$top=999' -All -MaxPages 100)
    $pol = Get-CERGraph 'policies/authenticationMethodsPolicy'
    $members = @($reg | Where-Object { $_.userType -ne 'guest' })
    $mfaReg = @($members | Where-Object isMfaRegistered); $mfaCap = @($members | Where-Object isMfaCapable); $pwdless = @($members | Where-Object isPasswordlessCapable)
    $adminsReg = @($members | Where-Object { $_.isAdmin -and $_.isMfaRegistered }); $admins = @($members | Where-Object isAdmin)
    $sms = @($members | Where-Object { @($_.methodsRegistered) -contains 'mobilePhone' -and @($_.methodsRegistered | Where-Object { $_ -in 'microsoftAuthenticatorPush', 'softwareOneTimePasscode', 'fido2SecurityKey', 'windowsHelloForBusiness', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'hardwareOneTimePasscode' }).Count -eq 0 })
    $methodState = @{}
    foreach ($m in @($pol.authenticationMethodConfigurations)) { $methodState[($m.id)] = $m.state }
    $authApp = @($pol.authenticationMethodConfigurations | Where-Object { $_.id -eq 'MicrosoftAuthenticator' })[0]
    $numMatch = $null; if ($authApp) { $numMatch = Get-CERProp (Get-CERProp $authApp 'featureSettings') 'numberMatchingRequiredState' }
    $defaultMethods = @($members | ForEach-Object { $_.defaultMfaMethod } | Group-Object | Sort-Object Count -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    Save-CERRaw -Name 'authmethods' -Object ([ordered]@{ Registration = @($reg | Select-Object userPrincipalName, userType, isAdmin, isMfaRegistered, isMfaCapable, isPasswordlessCapable, isSsprRegistered, methodsRegistered, defaultMfaMethod); Policy = $pol; MethodStates = $methodState })
    $flag = if ($members.Count -and ($mfaReg.Count / $members.Count) -ge 0.98 -and $admins.Count -eq $adminsReg.Count) { 'OK' } else { 'Attention' }
    Add-CEREvidence -Control 'IAM-02' -Flag $flag -Action 'Close the MFA registration gap - unregistered users are the accounts an attacker registers MFA on first, which then locks the legitimate user out and looks like a support call rather than a breach. Registration and enforcement are separate things: check both.' -Evidence ("MFA registration (members): {0}/{1} registered ({2}), {3} MFA-capable, {4} passwordless-capable; admins registered {5}/{6}. Default MFA methods: {7}." -f $mfaReg.Count, $members.Count, (ConvertTo-CERPct $mfaReg.Count $members.Count), $mfaCap.Count, $pwdless.Count, $adminsReg.Count, $admins.Count, (Join-CERList $defaultMethods 5))
    $weakOn = @('Sms', 'Voice') | Where-Object { $methodState[$_] -eq 'enabled' }
    Add-CEREvidence -Control 'IAM-03' -Flag $(if ($weakOn.Count -eq 0) { 'OK' } else { 'Attention' }) -Action 'Disable SMS and voice as authentication methods and move users to Authenticator with number matching, or FIDO2 where the role warrants it. SMS is defeated by SIM swap and interception; leaving it enabled means the weakest method is the one that gets used.' -Evidence ("Authentication methods policy: SMS={0}, Voice={1}, Authenticator={2} (number matching: {3}), FIDO2={4}, Temporary Access Pass={5}, Email OTP={6}; users whose only strong-ish method is a phone number: {7}. Admins passwordless-capable: {8}/{9}." -f $methodState['Sms'], $methodState['Voice'], $methodState['MicrosoftAuthenticator'], $numMatch, $methodState['Fido2'], $methodState['TemporaryAccessPass'], $methodState['Email'], $sms.Count, @($admins | Where-Object isPasswordlessCapable).Count, $admins.Count)
}

# ---------------- Password protection, consent, external collaboration, apps
Invoke-CERSection -Collector $C -Section 'PasswordProtectionConsent' -Script {
    $gs = @(Get-CERGraph 'groupSettings' -All)
    $pw = $gs | Where-Object { $_.displayName -eq 'Password Rule Settings' } | Select-Object -First 1
    $pwv = @{}; if ($pw) { foreach ($v in $pw.values) { $pwv[$v.name] = $v.value } }
    $authz = Get-CERGraph 'policies/authorizationPolicy'
    $consentPolicies = @($authz.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
    $consent = if ($consentPolicies.Count -eq 0) { 'Users cannot consent (admin consent only)' } elseif ($consentPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-low') { 'Users may consent to verified publishers / low-impact permissions' } elseif ($consentPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy') { 'Users can consent to ANY app (legacy default)' } else { $consentPolicies -join ',' }
    $acr = Get-CERGraph 'policies/adminConsentRequestPolicy'
    $grants = @(Get-CERGraph 'oauth2PermissionGrants?$top=999' -All)
    $userGrants = @($grants | Where-Object { $_.consentType -eq 'Principal' })
    $apps = @(Get-CERGraph 'applications?$select=id,displayName,createdDateTime,passwordCredentials,keyCredentials,signInAudience&$top=999' -All)
    $secretRows = @(); foreach ($a in $apps) { foreach ($cred in @($a.passwordCredentials) + @($a.keyCredentials)) { if ($cred.endDateTime) { $days = [int]([datetime]$cred.endDateTime - $now).TotalDays; $secretRows += [pscustomobject]@{ App = $a.displayName; Type = $(if ($cred.secretText -ne $null -or $cred.hint) { 'secret' } else { 'credential' }); DaysToExpiry = $days; Expired = ($days -lt 0); LongLived = ($days -gt 730) } } } }
    $xt = $null; try { $xt = Get-CERGraph 'policies/crossTenantAccessPolicy/default' } catch { }
    Save-CERRaw -Name 'consentapps' -Object ([ordered]@{ PasswordProtection = $pwv; AuthorizationPolicy = $authz; AdminConsentRequest = $acr; UserGrants = @($userGrants | Select-Object clientId, principalId, scope); Apps = @($apps | Select-Object id, displayName, createdDateTime, signInAudience); Credentials = $secretRows; CrossTenantDefault = $xt })
    $flag = if (-not $pw -or $pwv['EnableBannedPasswordCheck'] -eq 'False') { 'Attention' } else { 'OK' }
    $onprem = if ($script:org.onPremisesSyncEnabled) { (" On-prem agent: EnableBannedPasswordCheckOnPremises={0}, mode={1}." -f $pwv['EnableBannedPasswordCheckOnPremises'], $pwv['BannedPasswordCheckOnPremisesMode']) } else { '' }
    Add-CEREvidence -Control 'IAM-11' -Flag $flag -Action 'Enable Entra Password Protection with a custom banned-password list containing the client''s name, local place names and their variants, and deploy the on-premises agent to the DCs so the same list applies to on-prem password changes. Complexity rules alone still allow the passwords people actually pick.' -Evidence ("Entra Password Protection: settings object {0}; banned password check={1}; custom banned list entries={2}; smart lockout threshold={3}, duration={4}s.{5}" -f $(if ($pw) { 'present' } else { 'DEFAULTS (never customised)' }), $pwv['EnableBannedPasswordCheck'], @(($pwv['BannedPasswordList'] -split "`t") | Where-Object { $_ }).Count, $pwv['LockoutThreshold'], $pwv['LockoutDurationInSeconds'], $onprem)
    $flagC = if ($consent -like 'Users can consent to ANY*') { 'Attention' } elseif (-not $acr.isEnabled -and $consentPolicies.Count -eq 0) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'IAM-14' -Flag $flagC -Action 'Block user consent to unverified applications and enable the admin consent request workflow with named reviewers. Illicit consent is how an attacker keeps mailbox access after a password reset - the token survives the reset, which is why it gets missed.' -Evidence ("App consent: {0}; admin consent request workflow enabled={1} (reviewers {2}); user-consented OAuth grants on record: {3} across {4} apps; users can register apps={5}; guest invite setting={6}; guest role={7}." -f $consent, $acr.isEnabled, @($acr.reviewers).Count, $userGrants.Count, @($userGrants | Select-Object -ExpandProperty clientId -Unique).Count, $authz.defaultUserRolePermissions.allowedToCreateApps, $authz.allowInvitesFrom, $(switch ("$($authz.guestUserRoleId)") { '10dae51f-b6af-4016-8d66-8c2a99b929b3' { 'Guest (default limited)' } '2af84b1e-32c8-42b7-82bc-daa82404023b' { 'Restricted guest' } 'a0b1b346-4d3e-4e8b-98f8-753987be4970' { 'Same as member (!)' } default { "$($authz.guestUserRoleId)" } }))
    Add-CEREvidence -Control 'IAM-08' -Flag $(if ($authz.allowInvitesFrom -in 'adminsAndGuestInviters', 'adminsGuestInvitersAndAllMembers', 'none') { 'OK' } else { 'Attention' }) -Action 'Restrict who can invite guests to specific roles rather than all users, and set the cross-tenant access defaults deliberately. If any user can invite, the external collaboration surface grows without anyone deciding it should.' -Evidence ("External collaboration: who can invite guests = {0}; cross-tenant default inbound B2B collaboration: {1}." -f $authz.allowInvitesFrom, $(if ($xt) { "$($xt.b2bCollaborationInbound.usersAndGroups.accessType)" } else { 'n/a' }))
    $expiring = @($secretRows | Where-Object { $_.DaysToExpiry -ge 0 -and $_.DaysToExpiry -le 90 }); $expired = @($secretRows | Where-Object Expired); $long = @($secretRows | Where-Object LongLived)
    Add-CEREvidence -Control 'AZ-02' -Flag $(if ($expiring.Count -or $long.Count) { 'Attention' } else { 'OK' }) -Action 'Track the application credentials expiring within 90 days and give each application an owner - an expired secret is an outage nobody predicted. Then look at the expired-but-present credentials and the long-lived ones: a client secret with a multi-year lifetime is a password that never rotates.' -Evidence ("App registrations: {0}; credentials expiring within 90 days: {1} ({2}); expired but still present: {3}; credentials valid > 2 years: {4} ({5})." -f $apps.Count, $expiring.Count, (Join-CERList ($expiring | ForEach-Object { "{0} ({1}d)" -f $_.App, $_.DaysToExpiry }) 5), $expired.Count, $long.Count, (Join-CERList ($long | ForEach-Object { $_.App }) 5))
}

# ---------------- Identity Protection (P2)
Invoke-CERSection -Collector $C -Section 'IdentityProtection' -Script {
    if (-not $script:tier.P2) { Set-CERSectionResult -Status NotLicensed -Note 'Entra ID P2 not detected - Identity Protection not available'; Add-CEREvidence -Control 'IAM-13' -Flag Info -Action 'Entra ID P2 is not licensed, so Identity Protection risk detection and risk-based Conditional Access are unavailable. Record this as a licensing gap with its consequence rather than a control failure, and price P2 for the privileged users at minimum - risk detection on admin accounts is where it pays for itself.' -Evidence 'Entra ID P2 not licensed: Identity Protection risk policies not available (mark N/A or note as a licensing gap in M365-10).'; return }
    $risky = @(Get-CERGraph "identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'&`$top=500" -All)
    $det = @(Get-CERGraph ("identityProtection/riskDetections?`$filter=detectedDateTime ge {0}&`$top=999" -f $now.AddDays(-30).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -All -MaxPages 10)
    Save-CERRaw -Name 'identityprotection' -Object ([ordered]@{ RiskyUsers = @($risky | Select-Object userPrincipalName, riskLevel, riskState, riskLastUpdatedDateTime); Detections30d = @($det | Select-Object riskEventType, riskLevel, detectedDateTime, userPrincipalName) })
    $old = @($risky | Where-Object { (Get-CERAgeDays $_.riskLastUpdatedDateTime) -gt 7 })
    Add-CEREvidence -Control 'IAM-13' -Flag $(if ($old.Count) { 'Attention' } else { 'OK' }) -Action 'Work the unremediated risky users, starting with the high-risk ones and anything outstanding more than seven days. A risk detection nobody actions is worse than none, because it creates the paperwork of monitoring without the outcome; if these are false positives, dismiss them explicitly so the queue means something.' -Evidence ("Identity Protection: {0} users currently at risk ({1} high), {2} unremediated for > 7 days ({3}); {4} risk detections in the last 30 days ({5})." -f $risky.Count, @($risky | Where-Object { $_.riskLevel -eq 'high' }).Count, $old.Count, (Join-CERList ($old | ForEach-Object { $_.userPrincipalName }) 4), $det.Count, (Join-CERList ($det | Group-Object riskEventType | Sort-Object Count -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 5))
}

# ---------------- Sign-in logs: legacy auth + single-factor successes (P1)
Invoke-CERSection -Collector $C -Section 'SignInLogs' -Script {
    if (-not $script:tier.P1) { Set-CERSectionResult -Status NotLicensed -Note 'Entra P1 required for sign-in logs via Graph'; Add-CEREvidence -Control 'IAM-04' -Flag Info -Action 'Entra ID P1 is not licensed, so sign-in logs are not available through Graph and legacy-authentication use cannot be evidenced. Either price P1, or evidence this control from the Entra portal sign-in logs manually and note the method - it must not be scored as compliant on the basis of no data.' -Evidence 'Sign-in log analysis skipped (Entra P1 not detected). Check legacy auth in Entra portal > Sign-in logs > Client app filter, or EXO auth policy.'; return }
    $since = $now.AddDays(-$SignInDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $pages = [math]::Ceiling($MaxSignIns / 999)
    $si = @(Get-CERGraph ("auditLogs/signIns?`$filter=createdDateTime ge {0}&`$top=999&`$select=createdDateTime,userPrincipalName,appDisplayName,clientAppUsed,status,authenticationRequirement,isInteractive,conditionalAccessStatus,deviceDetail" -f $since) -All -MaxPages $pages)
    $ok = @($si | Where-Object { $_.status.errorCode -eq 0 })
    $modern = 'Browser', 'Mobile Apps and Desktop clients'
    $legacy = @($ok | Where-Object { $_.clientAppUsed -and ($modern -notcontains $_.clientAppUsed) })
    $single = @($ok | Where-Object { $_.authenticationRequirement -eq 'singleFactorAuthentication' -and $_.isInteractive })
    $caNot = @($ok | Where-Object { $_.conditionalAccessStatus -eq 'notApplied' -and $_.isInteractive })
    Save-CERRaw -Name 'signins.summary' -Object ([ordered]@{ Window = $SignInDays; Fetched = $si.Count; Successful = $ok.Count; Legacy = @($legacy | Group-Object clientAppUsed | ForEach-Object { [ordered]@{ Client = $_.Name; Count = $_.Count; Users = @($_.Group | Select-Object -ExpandProperty userPrincipalName -Unique) } }); SingleFactorInteractive = $single.Count; SingleFactorUsers = @($single | Select-Object -ExpandProperty userPrincipalName -Unique); CANotApplied = $caNot.Count })
    $capped = ($si.Count -ge $MaxSignIns)
    Add-CEREvidence -Control 'IAM-04' -Flag $(if ($legacy.Count) { 'Attention' } else { 'OK' }) -Action 'Trace every successful legacy-protocol sign-in to its account and application, migrate each to modern authentication, then block legacy authentication in Conditional Access. These are the sign-ins that bypassed MFA entirely, so each one is a live gap rather than a statistic.' -Evidence ("Sign-ins last {0} days ({1} fetched{2}): successful legacy-protocol sign-ins = {3} by {4} users ({5})." -f $SignInDays, $si.Count, $(if ($capped) { ', capped' } else { '' }), $legacy.Count, @($legacy | Select-Object -ExpandProperty userPrincipalName -Unique).Count, (Join-CERList ($legacy | Group-Object clientAppUsed | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 5))
    Add-CEREvidence -Control 'IAM-02' -Flag $(if ($ok.Count -and ($single.Count / [math]::Max(1, @($ok | Where-Object isInteractive).Count)) -gt 0.05) { 'Attention' } else { 'OK' }) -Action 'Investigate the successful single-factor interactive sign-ins - each represents an account and application combination where MFA did not apply. The usual causes are a CA exclusion nobody revisited, a legacy protocol, or a trusted-location bypass that has outlived its reason.' -Evidence ("Interactive successful sign-ins that were single-factor: {0} of {1} ({2}), by {3} users ({4}); interactive sign-ins with no CA policy applied: {5}." -f $single.Count, @($ok | Where-Object isInteractive).Count, (ConvertTo-CERPct $single.Count @($ok | Where-Object isInteractive).Count), @($single | Select-Object -ExpandProperty userPrincipalName -Unique).Count, (Join-CERList ($single | Select-Object -ExpandProperty userPrincipalName -Unique) 5), $caNot.Count)
    if ($capped) { Set-CERSectionResult -Status Partial -Note ("Capped at {0} sign-ins; raise -MaxSignIns or shorten -SignInDays" -f $MaxSignIns) }
}

# ---------------- Secure Score
Invoke-CERSection -Collector $C -Section 'SecureScore' -Script {
    $scores = @(Get-CERGraph 'security/secureScores?$top=90')
    if ($scores.Count -eq 0) { Set-CERSectionResult -Status Skipped -Note 'No Secure Score data returned'; return }
    $cur = $scores[0]; $old = $scores | Select-Object -Last 1
    $profiles = @(Get-CERGraph 'security/secureScoreControlProfiles?$top=400' -All)
    $pmap = @{}; foreach ($p in $profiles) { $pmap[$p.id] = $p }
    $gaps = @($cur.controlScores | ForEach-Object { $p = $pmap[$_.controlName]; $max = if ($p) { [double]$p.maxScore } else { 0 }; [pscustomobject]@{ Control = $_.controlName; Title = $(if ($p) { $p.title } else { $_.controlName }); Category = $_.controlCategory; Score = [double]$_.score; Max = $max; Gap = ($max - [double]$_.score); State = $_.implementationStatus; Rank = $(if ($p) { $p.rank } else { 999 }) } } | Where-Object { $_.Gap -gt 0 } | Sort-Object Gap -Descending)
    Save-CERRaw -Name 'securescore' -Object ([ordered]@{ Current = ($cur | Select-Object createdDateTime, currentScore, maxScore, licensedUserCount, activeUserCount); Oldest = ($old | Select-Object createdDateTime, currentScore, maxScore); TopGaps = @($gaps | Select-Object -First 25) })
    $pct = 100 * $cur.currentScore / [math]::Max(1, $cur.maxScore); $pctOld = 100 * $old.currentScore / [math]::Max(1, $old.maxScore)
    Add-CEREvidence -Control 'M365-01' -Flag $(if ($pct -ge 65) { 'OK' } else { 'Attention' }) -Action 'Work the Secure Score improvement actions by realised points rather than count, and formally risk-accept the ones the client will not do, with a date. Track the score trend at each monthly review - the direction of travel is the number worth reporting, not the absolute figure.' -Evidence ("Microsoft Secure Score: {0:n1}/{1:n0} = {2:n0}% on {3:yyyy-MM-dd}; {4} days earlier: {5:n0}% ({6}). Largest gaps: {7}." -f $cur.currentScore, $cur.maxScore, $pct, [datetime]$cur.createdDateTime, ($scores.Count - 1), $pctOld, $(if ($pct -ge $pctOld) { 'improving/flat' } else { 'declining' }), (Join-CERList ($gaps | Select-Object -First 8 | ForEach-Object { "{0} (+{1:n0})" -f $_.Title, $_.Gap }) 8))
    Add-CEREvidence -Control 'SEC-11' -Flag Info -Action 'Pick the highest-value unrealised Secure Score actions and put them into the roadmap with owners. Many are configuration changes with no licence cost, which makes them the easiest wins to take to the client.' -Evidence ("Secure Score improvement actions with unrealised points: {0} (total {1:n0} points available). Top by value: {2}." -f $gaps.Count, ($gaps | Measure-Object Gap -Sum).Sum, (Join-CERList ($gaps | Select-Object -First 10 | ForEach-Object { $_.Title }) 10))
    Add-CEREvidence -Control 'SEC-01' -Flag Info -Action 'Use the category breakdown to decide where the review effort goes next - a category well below the others usually means a whole control area nobody owns, rather than a set of individual misconfigurations.' -Evidence ("Secure Score category gaps: {0}." -f (Join-CERList ($gaps | Group-Object Category | ForEach-Object { "{0}: {1:n0} pts" -f $_.Name, ($_.Group | Measure-Object Gap -Sum).Sum }) 5))
}

# ---------------- Devices, LAPS, BitLocker keys
Invoke-CERSection -Collector $C -Section 'Devices' -Script {
    $dev = @(Get-CERGraph 'devices?$select=id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,isManaged,isCompliant,accountEnabled,registrationDateTime,profileType&$top=999' -All -MaxPages 100)
    $en = @($dev | Where-Object accountEnabled)
    $active = @($en | Where-Object { (Get-CERAgeDays $_.approximateLastSignInDateTime) -le 30 })
    $stale = @($en | Where-Object { $a = Get-CERAgeDays $_.approximateLastSignInDateTime; ($null -eq $a) -or ($a -gt 90) })
    $byOs = @($active | Group-Object operatingSystem | Sort-Object Count -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $byTrust = @($active | Group-Object trustType | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $win = @($active | Where-Object { $_.operatingSystem -eq 'Windows' })
    $winManaged = @($win | Where-Object isManaged); $winCompliant = @($win | Where-Object isCompliant)
    $win10 = @($win | Where-Object { $_.operatingSystemVersion -match '^10\.0\.1\d{4}' }); $win11 = @($win | Where-Object { $_.operatingSystemVersion -match '^10\.0\.2\d{4}' })
    $laps = $null; try { $laps = @(Get-CERGraph 'directory/deviceLocalCredentials?$select=id,deviceName,lastBackupDateTime&$top=999' -All -MaxPages 50) } catch { Write-CERLog "deviceLocalCredentials: $($_.Exception.Message)" 'WARN' }
    $bl = $null; try { $bl = @(Get-CERGraph 'informationProtection/bitlocker/recoveryKeys?$select=id,deviceId,createdDateTime&$top=999' -All -MaxPages 100) } catch { Write-CERLog "bitlocker recoveryKeys: $($_.Exception.Message)" 'WARN' }
    Save-CERRaw -Name 'devices' -Object ([ordered]@{ Total = $dev.Count; Enabled = $en.Count; Active30d = $active.Count; Stale90d = $stale.Count; ByOS = $byOs; ByTrust = $byTrust; Windows10 = $win10.Count; Windows11 = $win11.Count; LapsDevices = $(if ($null -ne $laps) { $laps.Count } else { 'n/a' }); BitLockerKeyDevices = $(if ($null -ne $bl) { @($bl | Select-Object -ExpandProperty deviceId -Unique).Count } else { 'n/a' }); Devices = @($dev | Select-Object displayName, operatingSystem, operatingSystemVersion, trustType, approximateLastSignInDateTime, isManaged, isCompliant, accountEnabled) })
    Add-CEREvidence -Control 'END-01' -Flag Info -Action 'Reconcile the Entra device count against Intune, the RMM and the EDR console, and clean up stale device records over 90 days old. Stale objects inflate every coverage percentage the client is shown, which makes the reporting reassuring and wrong.' -Evidence ("Entra devices: {0} enabled, {1} active in 30 days ({2}), {3} stale > 90 days; trust: {4}. Windows active: {5} of which Intune-managed {6} ({7}), compliant {8} ({9})." -f $en.Count, $active.Count, (Join-CERList $byOs 5), $stale.Count, (Join-CERList $byTrust 4), $win.Count, $winManaged.Count, (ConvertTo-CERPct $winManaged.Count $win.Count), $winCompliant.Count, (ConvertTo-CERPct $winCompliant.Count $win.Count))
    Add-CEREvidence -Control 'END-02' -Flag $(if ($win10.Count) { 'Attention' } else { 'OK' }) -Action 'Replace or upgrade the Windows 10 devices - support ended 14 Oct 2025, so they receive no security updates unless the client has bought ESU. Where hardware cannot take Windows 11, that is a capital planning conversation for the SDM and CAM now.' -Evidence ("Entra device records (active 30 d): Windows 10 = {0}, Windows 11 = {1} (Windows 10 out of support 14 Oct 2025)." -f $win10.Count, $win11.Count)
    if ($null -ne $laps) {
        $recent = @($laps | Where-Object { (Get-CERAgeDays $_.lastBackupDateTime) -le 60 })
        $flag = if ($win.Count -and ($laps.Count / $win.Count) -ge 0.9) { 'OK' } else { 'Attention' }
        Add-CEREvidence -Control 'END-08' -Flag $flag -Action 'Extend Windows LAPS to every Windows device and confirm passwords are rotating. Without it the local administrator password is almost certainly identical across the fleet, which is what turns one compromised workstation into all of them.' -Evidence ("Windows LAPS (Entra-backed): {0} devices have a backed-up local admin password ({1} rotated within 60 days) vs {2} active Windows devices ({3})." -f $laps.Count, $recent.Count, $win.Count, (ConvertTo-CERPct $laps.Count $win.Count))
        Add-CEREvidence -Control 'IAM-11' -Flag $flag -Action 'Close the Entra LAPS coverage gap - the policy exists but is not reaching every device. Check the Intune assignment covers all device groups and that the devices have checked in since the policy was applied.' -Evidence ("Entra LAPS coverage: {0} of {1} active Windows devices ({2})." -f $laps.Count, $win.Count, (ConvertTo-CERPct $laps.Count $win.Count))
    } else { Add-CEREvidence -Control 'END-08' -Flag Unknown -Action 'Grant DeviceLocalCredential.ReadBasic.All to the account running this collector (with Global Reader or Security Reader) and re-run, so LAPS coverage can be evidenced. Until then this control is unevidenced rather than compliant.' -Evidence 'Could not read Entra LAPS credentials list (needs DeviceLocalCredential.ReadBasic.All + Global Reader/Security Reader).' }
    if ($null -ne $bl) {
        $blDevices = @($bl | Select-Object -ExpandProperty deviceId -Unique).Count
        Add-CEREvidence -Control 'END-07' -Flag $(if ($win.Count -and ($blDevices / $win.Count) -ge 0.9) { 'OK' } else { 'Attention' }) -Action 'Close the gap between devices with escrowed BitLocker recovery keys and active Windows devices. An encrypted device whose key is not escrowed is unrecoverable after a TPM or firmware change - the encryption works exactly as intended and the data is gone.' -Evidence ("BitLocker recovery keys escrowed to Entra for {0} devices vs {1} active Windows devices ({2}). Encryption state itself comes from Intune (isEncrypted) and the host check." -f $blDevices, $win.Count, (ConvertTo-CERPct $blDevices $win.Count))
    } else { Add-CEREvidence -Control 'END-07' -Flag Unknown -Action 'Grant BitLockerKey.ReadBasic.All to the account running this collector and re-run so key escrow can be evidenced. Encryption without recoverable keys is a data-loss risk rather than a control, so this is worth confirming rather than assuming.' -Evidence 'Could not read BitLocker recovery key list from Entra (BitLockerKey.ReadBasic.All).' }
}

# ---------------- Security alerts
Invoke-CERSection -Collector $C -Section 'SecurityAlerts' -Script {
    $alerts = @(Get-CERGraph "security/alerts_v2?`$filter=status eq 'new'&`$top=200" -All -MaxPages 5)
    $recent = @(Get-CERGraph ("security/alerts_v2?`$filter=createdDateTime ge {0}&`$top=500" -f $now.AddDays(-30).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) -All -MaxPages 5)
    Save-CERRaw -Name 'alerts' -Object ([ordered]@{ New = @($alerts | Select-Object id, title, severity, serviceSource, createdDateTime); Last30d = @($recent | Select-Object id, title, severity, status, serviceSource, createdDateTime) })
    $oldNew = @($alerts | Where-Object { (Get-CERAgeDays $_.createdDateTime) -gt 7 })
    Add-CEREvidence -Control 'SEC-02' -Flag $(if ($oldNew.Count) { 'Attention' } else { 'Info' }) -Action 'Assign an owner to the untriaged Defender XDR alerts, particularly any in the new state for more than seven days. Alerts accumulating unactioned mean either nobody is watching the console or the noise level has made it unusable - both need raising, and the second is the harder conversation.' -Evidence ("Defender XDR alerts: {0} in 'new' state ({1} older than 7 days - nobody triaging?), {2} created in the last 30 days by source: {3}." -f $alerts.Count, $oldNew.Count, $recent.Count, (Join-CERList ($recent | Group-Object serviceSource | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 5))
}

# ---------------- Message centre
Invoke-CERSection -Collector $C -Section 'MessageCenter' -Script {
    $msgs = @(Get-CERGraph "admin/serviceAnnouncement/messages?`$filter=category eq 'planForChange'&`$top=100&`$orderby=lastModifiedDateTime desc")
    $recent = @($msgs | Where-Object { (Get-CERAgeDays $_.lastModifiedDateTime) -le 90 })
    $major = @($recent | Where-Object { $_.isMajorChange })
    Save-CERRaw -Name 'messagecenter' -Object @($recent | Select-Object id, title, isMajorChange, actionRequiredByDateTime, services, lastModifiedDateTime)
    Add-CEREvidence -Control 'M365-11' -Flag Info -Action 'Assign someone to read the Message Centre ''Plan for change'' items monthly and log anything with an action deadline into COMMITMENTS.md. Microsoft-driven changes with a deadline become incidents on the day they land if nobody has read them.' -Evidence ("Message centre 'Plan for change' items in last 90 days: {0} ({1} flagged major change, {2} with an action-required date). Latest: {3}." -f $recent.Count, $major.Count, @($recent | Where-Object actionRequiredByDateTime).Count, (Join-CERList ($recent | Select-Object -First 5 | ForEach-Object { "{0} {1}" -f $_.id, $_.title }) 5))
}

# ---------------- SharePoint tenant settings
Invoke-CERSection -Collector $C -Section 'SharePointSettings' -Script {
    $sp = Get-CERGraph 'admin/sharepoint/settings'
    Save-CERRaw -Name 'sharepoint' -Object $sp
    $cap = "$($sp.sharingCapability)"
    $flag = if ($cap -eq 'externalUserAndGuestSharing' -or $sp.isLegacyAuthProtocolsEnabled) { 'Attention' } else { 'OK' }
    $idle = Get-CERProp $sp 'idleSessionSignOut'
    Add-CEREvidence -Control 'M365-06' -Flag $flag -Action 'Tighten SharePoint and OneDrive external sharing: turn ''Anyone'' links off or give them a short expiry, set the default link type to internal, and require sign-in for external recipients. Anyone-links are unauthenticated URLs that work for whoever holds them, forever, and they are not revoked when someone leaves.' -Evidence ("SharePoint/OneDrive tenant: sharing capability = {0} (externalUserAndGuestSharing allows 'Anyone' links); resharing by external users = {1}; domain restriction mode = {2} ({3} allowed domains); legacy auth protocols enabled = {4}; idle session sign-out = {5}; unmanaged sync clients restricted = {6}. Anyone-link expiry days and default link type need SPO shell (Get-SPOTenant) - manual." -f $cap, $sp.isResharingByExternalUsersEnabled, $sp.sharingDomainRestrictionMode, @($sp.sharingAllowedDomainList).Count, $sp.isLegacyAuthProtocolsEnabled, $(if ($idle) { $idle.isEnabled } else { 'n/a' }), $sp.isUnmanagedSyncAppForTenantRestricted)
}

Complete-CERCollector

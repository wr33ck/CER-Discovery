#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: Azure via Az.Accounts + Az.ResourceGraph (+ Az.Resources for RBAC/locks, REST for budgets, Defender
  plans, diagnostic settings, cost). Works through Azure Lighthouse delegations (connect to the bA tenant) or directly to the
  customer tenant. Feeds AZ-01..07, AZ-05/BDR-01 (backup), SRV-02 (VM OS), NET-04 (exposure), LIC-04.
.EXAMPLE
  .\Get-CERAzure.ps1 -Client C-003 -RunId 20260905-0900 -AzureTenantId <tenant> -SubscriptionId <id1>,<id2>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string]$AzureTenantId,
    [string[]]$SubscriptionId,
    [switch]$UseDeviceCode,
    [switch]$NoConnect,
    [switch]$SkipCost
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Azure' -RunId $RunId
$C = 'Azure'
foreach ($m in 'Az.Accounts', 'Az.ResourceGraph', 'Az.Resources') { if (-not (Test-CERModule -Name $m -Collector $C -Section "Module:$m")) { Complete-CERCollector; return } }
Import-Module Az.Accounts, Az.ResourceGraph, Az.Resources -ErrorAction Stop
$now = Get-Date

Invoke-CERSection -Collector $C -Section 'Connect' -Script {
    $ctx = Get-AzContext
    if (-not ($NoConnect -and $ctx)) {
        $p = @{ ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }; if ($AzureTenantId) { $p['TenantId'] = $AzureTenantId }; if ($UseDeviceCode) { $p['UseDeviceCode'] = $true }
        Connect-AzAccount @p | Out-Null
        $ctx = Get-AzContext
    }
    Write-CERLog ("Azure: {0} in tenant {1}" -f $ctx.Account.Id, $ctx.Tenant.Id)
}
$subs = @()
Invoke-CERSection -Collector $C -Section 'Subscriptions' -Script {
    $all = @(Get-AzSubscription -ErrorAction Stop -WarningAction SilentlyContinue)
    $want = @($SubscriptionId | ForEach-Object { $_ -split '[,;\s]+' } | Where-Object { $_ }); $script:subs = if ($want.Count) { @($all | Where-Object { $want -contains $_.Id -or $want -contains $_.Name }) } else { @($all | Where-Object { $_.State -eq 'Enabled' }) }
    Save-CERRaw -Name 'subscriptions' -Object @($script:subs | Select-Object Name, Id, State, TenantId)
    if ($script:subs.Count -eq 0) { Add-CEREvidence -Control 'AZ-01' -Flag Info -Action 'Confirm whether the client genuinely has no Azure footprint or whether the Lighthouse delegation is missing or expired. An undelegated subscription is invisible to blueAPACHE, which means it is unmonitored, unpatched and unbacked-up as far as the service is concerned - a very different finding from having no Azure at all.' -Evidence 'No enabled Azure subscriptions visible to this account (no Azure footprint, or Lighthouse delegation missing).'; Set-CERSectionResult -Status Skipped -Note 'no subscriptions' }
}
if ($subs.Count -eq 0) { Complete-CERCollector; return }
$subIds = @($subs | ForEach-Object { $_.Id })

function Invoke-CERArg { param([Parameter(Mandatory)][string]$Query)
    $out = New-Object System.Collections.ArrayList; $skip = $null
    do {
        $p = @{ Query = $Query; Subscription = $subIds; First = 1000; ErrorAction = 'Stop' }; if ($skip) { $p['SkipToken'] = $skip }
        $r = Search-AzGraph @p
        foreach ($x in @($r)) { $null = $out.Add($x) }
        $skip = $null; if ($r -and $r.PSObject.Properties['SkipToken']) { $skip = $r.SkipToken }
    } while ($skip)
    return , $out.ToArray()
}

Invoke-CERSection -Collector $C -Section 'Inventory' -Script {
    $res = Invoke-CERArg "resources | summarize count() by type | order by count_ desc"
    $tags = Invoke-CERArg "resources | extend hasOwner = isnotempty(tags['owner']) or isnotempty(tags['Owner']), hasCC = isnotempty(tags['costcentre']) or isnotempty(tags['CostCentre']) or isnotempty(tags['costcenter']) or isnotempty(tags['CostCenter']), hasEnv = isnotempty(tags['environment']) or isnotempty(tags['Environment']) | summarize total=count(), owner=countif(hasOwner), cc=countif(hasCC), env=countif(hasEnv)"
    $locks = @(); foreach ($s in $subIds) { try { $null = Set-AzContext -SubscriptionId $s -ErrorAction Stop -WarningAction SilentlyContinue; $locks += @(Get-AzResourceLock -ErrorAction Stop | Select-Object Name, ResourceType, ResourceName, @{ n = 'Level'; e = { $_.Properties.level } }, @{ n = 'Sub'; e = { $s } }) } catch { } }
    $mg = @(); try { $mg = @(Get-AzManagementGroup -ErrorAction Stop -WarningAction SilentlyContinue | Select-Object Name, DisplayName) } catch { }
    $lighthouse = @(); try { $lighthouse = @(Invoke-CERArg "resources | where type =~ 'microsoft.managedservices/registrationassignments' | project name, subscriptionId") } catch { }
    Save-CERRaw -Name 'inventory' -Object ([ordered]@{ ByType = @($res | Select-Object type, count_); Tags = $tags; Locks = $locks; ManagementGroups = $mg; Lighthouse = $lighthouse })
    $t = $tags | Select-Object -First 1
    $flag = if ($t -and $t.total -gt 0 -and (($t.owner / $t.total) -lt 0.5)) { 'Attention' } else { 'OK' }
    Add-CEREvidence -Control 'AZ-01' -Flag $flag -Action 'Enforce a tagging standard covering owner, cost centre and environment, and apply resource locks to anything whose deletion would be an incident. Untagged resources cannot be attributed, which makes both cost conversations and incident response guesswork.' -Evidence ("Azure: {0} subscriptions ({1}); {2} resources across {3} types; tag coverage owner {4}, cost-centre {5}, environment {6}; resource locks {7}; management groups visible {8}; Lighthouse registration assignments {9}." -f $subs.Count, (Join-CERList ($subs | ForEach-Object { $_.Name }) 4), ($res | Measure-Object count_ -Sum).Sum, $res.Count, (ConvertTo-CERPct $t.owner $t.total), (ConvertTo-CERPct $t.cc $t.total), (ConvertTo-CERPct $t.env $t.total), $locks.Count, $mg.Count, $lighthouse.Count)
}

Invoke-CERSection -Collector $C -Section 'RBAC' -Script {
    $rows = @()
    foreach ($s in $subs) {
        try {
            $null = Set-AzContext -SubscriptionId $s.Id -ErrorAction Stop -WarningAction SilentlyContinue
            $ra = @(Get-AzRoleAssignment -Scope "/subscriptions/$($s.Id)" -IncludeClassicAdministrators -ErrorAction Stop -WarningAction SilentlyContinue)
            foreach ($a in $ra) { if ($a.RoleDefinitionName -in 'Owner', 'Contributor', 'User Access Administrator', 'CoAdministrator', 'ServiceAdministrator', 'AccountAdministrator') { $rows += [pscustomobject]@{ Sub = $s.Name; Role = $a.RoleDefinitionName; Principal = $a.DisplayName; Type = $a.ObjectType; Scope = $a.Scope; SignIn = $a.SignInName } } }
        } catch { Write-CERLog ("RBAC {0}: {1}" -f $s.Name, $_.Exception.Message) 'WARN' }
    }
    Save-CERRaw -Name 'rbac' -Object $rows
    $owners = @($rows | Where-Object { $_.Role -eq 'Owner' }); $users = @($rows | Where-Object { $_.Type -eq 'User' }); $classic = @($rows | Where-Object { $_.Role -in 'CoAdministrator', 'ServiceAdministrator', 'AccountAdministrator' })
    Add-CEREvidence -Control 'AZ-02' -Flag $(if ($owners.Count -gt ($subs.Count * 4) -or $classic.Count) { 'Attention' } else { 'OK' }) -Action 'Reduce standing Owner and Contributor assignments at subscription and management-group scope to named individuals with a business reason, and move the rest behind Privileged Identity Management where P2 is licensed. Subscription Owner is effectively unlimited within that subscription, including the ability to delete the backups.' -Evidence ("Subscription/MG-scope privileged assignments: Owner {0}, Contributor {1}, User Access Admin {2}; direct user assignments (not groups) {3}; classic administrators {4}; service principals {5}. Sample owners: {6}." -f $owners.Count, @($rows | Where-Object { $_.Role -eq 'Contributor' }).Count, @($rows | Where-Object { $_.Role -eq 'User Access Administrator' }).Count, $users.Count, $classic.Count, @($rows | Where-Object { $_.Type -eq 'ServicePrincipal' }).Count, (Join-CERList ($owners | ForEach-Object { "{0} ({1})" -f $_.Principal, $_.Sub }) 5))
}

Invoke-CERSection -Collector $C -Section 'ComputeBackup' -Script {
    $vms = Invoke-CERArg "resources | where type =~ 'microsoft.compute/virtualmachines' | extend os = tostring(properties.storageProfile.osDisk.osType), osName = tostring(properties.extended.instanceView.osName), osVer = tostring(properties.extended.instanceView.osVersion), power = tostring(properties.extended.instanceView.powerState.code), size = tostring(properties.hardwareProfile.vmSize), sku = tostring(properties.storageProfile.imageReference.sku), offer = tostring(properties.storageProfile.imageReference.offer), lic = tostring(properties.licenseType), zones = tostring(zones), avset = tostring(properties.availabilitySet.id) | project name, id, resourceGroup, subscriptionId, location, os, osName, osVer, power, size, sku, offer, lic, zones, avset"
    $prot = Invoke-CERArg "recoveryservicesresources | where type =~ 'microsoft.recoveryservices/vaults/backupfabrics/protectioncontainers/protecteditems' | extend src = tolower(tostring(properties.sourceResourceId)), lastBackup = todatetime(properties.lastBackupTime), status = tostring(properties.lastBackupStatus), health = tostring(properties.protectionStatus) | project src, lastBackup, status, health, vaultName = tostring(split(id,'/')[8])"
    $vaults = Invoke-CERArg "resources | where type =~ 'microsoft.recoveryservices/vaults' | project name, subscriptionId, softDelete = tostring(properties.securitySettings.softDeleteSettings.softDeleteState), immutability = tostring(properties.securitySettings.immutabilitySettings.state), redundancy = tostring(properties.redundancySettings.standardTierStorageRedundancy), crossRegion = tostring(properties.redundancySettings.crossRegionRestore)"
    $asr = Invoke-CERArg "recoveryservicesresources | where type =~ 'microsoft.recoveryservices/vaults/replicationfabrics/replicationprotectioncontainers/replicationprotecteditems' | project name, health = tostring(properties.replicationHealth), state = tostring(properties.protectionState)"
    $protSet = @{}; foreach ($p in $prot) { $protSet[$p.src] = $p }
    $unprotected = @($vms | Where-Object { -not $protSet.ContainsKey($_.id.ToLower()) })
    $failed = @($prot | Where-Object { $_.status -and $_.status -ne 'Completed' -and $_.status -ne 'Healthy' })
    $oldBackup = @($prot | Where-Object { $_.lastBackup -and ((Get-CERAgeDays $_.lastBackup) -gt 2) })
    $stopped = @($vms | Where-Object { $_.power -eq 'PowerState/stopped' })
    $running = @($vms | Where-Object { $_.power -eq 'PowerState/running' })
    $winOs = @($vms | Where-Object { $_.os -eq 'Windows' } | ForEach-Object { $s = Get-CERWindowsSupport -Caption $_.osName -Version $_.osVer -ProductType 3; [pscustomobject]@{ Name = $_.name; Family = $(if ($s.Family) { $s.Family } elseif ($_.sku) { "$($_.offer) $($_.sku)" } else { $_.osName }); Supported = $s.Supported; EoS = $s.EndOfSupport } })
    $unsup = @($winOs | Where-Object { -not $_.Supported }); $unsupBySku = @($vms | Where-Object { $_.os -eq 'Windows' -and ($_.sku -match '2008|2012' -or $_.osName -match '2008|2012') })
    $ahub = @($vms | Where-Object { $_.os -eq 'Windows' -and $_.lic -eq 'Windows_Server' })
    $noZone = @($vms | Where-Object { -not $_.zones -or $_.zones -eq '[]' } | Where-Object { -not $_.avset })
    Save-CERRaw -Name 'compute' -Object ([ordered]@{ VMs = $vms; ProtectedItems = $prot; Vaults = $vaults; ASR = $asr; Unprotected = @($unprotected | ForEach-Object { $_.name }); WindowsSupport = $winOs })
    Add-CEREvidence -Control 'AZ-05' -Flag $(if ($unprotected.Count -or $failed.Count -or @($vaults | Where-Object { $_.softDelete -ne 'Enabled' }).Count) { 'Attention' } else { 'OK' }) -Action 'Deallocate the VMs that are stopped but not deallocated - they are still billing at full rate for compute. Then confirm every VM has an Azure Backup protected item; a VM outside a backup policy is one nobody will be able to restore.' -Evidence ("Azure VMs: {0} ({1} running, {2} stopped-not-deallocated = still billed). Azure Backup: {3} protected items in {4} vaults; VMs with no backup item: {5} ({6}); last backup failed/unhealthy: {7}; last backup > 48 h: {8}. Vault soft delete: {9}; immutability: {10}; ASR replicated items: {11} ({12} unhealthy)." -f $vms.Count, $running.Count, $stopped.Count, $prot.Count, $vaults.Count, $unprotected.Count, (Join-CERList ($unprotected | ForEach-Object { $_.name }) 8), $failed.Count, $oldBackup.Count, (Join-CERList ($vaults | Group-Object softDelete | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 3), (Join-CERList ($vaults | Group-Object immutability | ForEach-Object { "{0}={1}" -f $(if ($_.Name) { $_.Name } else { 'not set' }), $_.Count }) 3), $asr.Count, @($asr | Where-Object { $_.health -ne 'Normal' }).Count)
    Add-CEREvidence -Control 'BDR-01' -Flag $(if ($unprotected.Count) { 'Attention' } else { 'OK' }) -Action 'Add the unprotected Azure VMs to a backup policy, and enable soft delete and immutability on the Recovery Services vault. Without immutability, an attacker with sufficient Azure rights deletes the backups before the VMs, which is the standard order of operations.' -Evidence ("Azure IaaS: {0}/{1} VMs without an Azure Backup protected item: {2}." -f $unprotected.Count, $vms.Count, (Join-CERList ($unprotected | ForEach-Object { $_.name }) 8))
    Add-CEREvidence -Control 'SRV-02' -Flag $(if ($unsup.Count -or $unsupBySku.Count) { 'Attention' } else { 'OK' }) -Action 'Plan the migration for the out-of-support Windows Server VMs in Azure - and note that running an unsupported OS in Azure carries free Extended Security Updates, which is a genuine reason to move a stubborn on-prem legacy workload rather than leave it on-prem unpatched.' -Evidence ("Azure Windows VMs: {0}; OS families: {1}; unsupported (2008/2012): {2} ({3}); Server 2016 (EoS 12 Jan 2027): {4}." -f $winOs.Count, (Join-CERList ($winOs | Group-Object Family | Sort-Object Count -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 5), ([math]::Max($unsup.Count, $unsupBySku.Count)), (Join-CERList (@($unsup | ForEach-Object { $_.Name }) + @($unsupBySku | ForEach-Object { $_.name }) | Select-Object -Unique) 6), @($winOs | Where-Object { $_.Family -eq 'Windows Server 2016' }).Count)
    Add-CEREvidence -Control 'AZ-03' -Flag Info -Action 'Apply Azure Hybrid Benefit to the eligible Windows VMs - it is a licence the client usually already holds and it takes a meaningful percentage off compute cost. Deallocate the stopped-but-not-deallocated VMs while you are there.' -Evidence ("Hybrid Benefit applied on {0}/{1} Windows VMs; VMs stopped but not deallocated: {2} ({3}); VMs without zone/availability set: {4}." -f $ahub.Count, @($vms | Where-Object { $_.os -eq 'Windows' }).Count, $stopped.Count, (Join-CERList ($stopped | ForEach-Object { $_.name }) 5), $noZone.Count)
}

Invoke-CERSection -Collector $C -Section 'SecurityPosture' -Script {
    $score = Invoke-CERArg "securityresources | where type =~ 'microsoft.security/securescores' | project subscriptionId, current = todouble(properties.score.current), max = todouble(properties.score.max), pct = todouble(properties.score.percentage)"
    $recs = Invoke-CERArg "securityresources | where type =~ 'microsoft.security/assessments' | extend status = tostring(properties.status.code), sev = tostring(properties.metadata.severity), disp = tostring(properties.displayName) | where status == 'Unhealthy' | summarize count() by disp, sev | order by count_ desc"
    $nsg = Invoke-CERArg "resources | where type =~ 'microsoft.network/networksecuritygroups' | mv-expand r = properties.securityRules | extend access = tostring(r.properties.access), dir = tostring(r.properties.direction), src = tostring(r.properties.sourceAddressPrefix), srcs = tostring(r.properties.sourceAddressPrefixes), port = tostring(r.properties.destinationPortRange), ports = tostring(r.properties.destinationPortRanges), rname = tostring(r.name) | where access == 'Allow' and dir == 'Inbound' and (src in ('*','Internet','0.0.0.0/0','any') or srcs contains '0.0.0.0/0' or srcs contains 'Internet') | where port in ('*','22','3389','1433','3306','5985','5986','445') or ports contains '3389' or ports contains '22' or port contains '-' | project nsg = name, rname, port, ports, src, subscriptionId"
    $pip = Invoke-CERArg "resources | where type =~ 'microsoft.network/publicipaddresses' | extend ip = tostring(properties.ipAddress), assoc = tostring(properties.ipConfiguration.id) | project name, ip, assoc, subscriptionId"
    $stor = Invoke-CERArg "resources | where type =~ 'microsoft.storage/storageaccounts' | extend pub = tostring(properties.allowBlobPublicAccess), tls = tostring(properties.minimumTlsVersion), https = tostring(properties.supportsHttpsTrafficOnly), netdef = tostring(properties.networkAcls.defaultAction), sharedKey = tostring(properties.allowSharedKeyAccess) | project name, pub, tls, https, netdef, sharedKey, subscriptionId"
    $kv = Invoke-CERArg "resources | where type =~ 'microsoft.keyvault/vaults' | extend purge = tostring(properties.enablePurgeProtection), rbac = tostring(properties.enableRbacAuthorization), netdef = tostring(properties.networkAcls.defaultAction) | project name, purge, rbac, netdef"
    $pricing = @(); $diag = @()
    foreach ($s in $subIds) {
        try { $r = Invoke-AzRestMethod -Path "/subscriptions/$s/providers/Microsoft.Security/pricings?api-version=2024-01-01" -Method GET -ErrorAction Stop; if ($r.StatusCode -eq 200) { $pricing += @((($r.Content | ConvertFrom-Json).value) | ForEach-Object { [pscustomobject]@{ Sub = $s; Plan = $_.name; Tier = $_.properties.pricingTier } }) } } catch { }
        try { $r = Invoke-AzRestMethod -Path "/subscriptions/$s/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview" -Method GET -ErrorAction Stop; if ($r.StatusCode -eq 200) { $diag += @((($r.Content | ConvertFrom-Json).value) | ForEach-Object { [pscustomobject]@{ Sub = $s; Name = $_.name; Workspace = $_.properties.workspaceId; Storage = $_.properties.storageAccountId } }) } } catch { }
    }
    Save-CERRaw -Name 'security' -Object ([ordered]@{ SecureScore = $score; UnhealthyRecommendations = @($recs | Select-Object -First 40); ExposedNsgRules = $nsg; PublicIPs = $pip; StorageAccounts = $stor; KeyVaults = $kv; DefenderPlans = $pricing; ActivityLogDiagnostics = $diag })
    $exposedMgmt = @($nsg | Where-Object { $_.port -in '22', '3389', '*' -or $_.ports -match '3389|"22"' })
    $pubStor = @($stor | Where-Object { $_.pub -eq 'true' -or $_.pub -eq 'True' }); $oldTls = @($stor | Where-Object { $_.tls -and $_.tls -ne 'TLS1_2' -and $_.tls -ne 'TLS1_3' }); $openNet = @($stor | Where-Object { $_.netdef -eq 'Allow' })
    $std = @($pricing | Where-Object { $_.Tier -eq 'Standard' }); $subsNoDiag = @($subIds | Where-Object { $s = $_; -not ($diag | Where-Object { $_.Sub -eq $s }) })
    $pct = if ($score.Count) { ($score | Measure-Object pct -Average).Average * 100 } else { $null }
    Add-CEREvidence -Control 'AZ-04' -Flag $(if ($exposedMgmt.Count -or $pubStor.Count -or $subsNoDiag.Count) { 'Attention' } else { 'OK' }) -Action 'Work the high-severity Defender for Cloud recommendations first and track the secure score trend rather than the absolute number. Confirm the Defender plans are enabled for the resource types that warrant them - servers, SQL and storage - because the recommendations are only as complete as the plans behind them.' -Evidence ("Defender for Cloud secure score: {0}; unhealthy recommendations: {1} high-severity types ({2}). NSG rules allowing inbound from Internet on management/DB ports: {3} ({4}). Public IPs: {5} ({6} unassociated). Storage accounts: {7} - blob public access allowed on {8}, TLS < 1.2 on {9}, network default Allow on {10}. Key Vaults: {11} ({12} without purge protection). Defender plans at Standard: {13} ({14}). Subscriptions without an Activity Log diagnostic setting: {15}." -f $(if ($null -ne $pct) { '{0:n0}%' -f $pct } else { 'n/a' }), @($recs | Where-Object { $_.sev -eq 'High' }).Count, (Join-CERList ($recs | Where-Object { $_.sev -eq 'High' } | Select-Object -First 5 | ForEach-Object { "{0} x{1}" -f $_.disp, $_.count_ }) 5), $exposedMgmt.Count, (Join-CERList ($exposedMgmt | ForEach-Object { "{0}/{1}:{2}{3}" -f $_.nsg, $_.rname, $_.port, $_.ports }) 5), $pip.Count, @($pip | Where-Object { -not $_.assoc }).Count, $stor.Count, $pubStor.Count, $oldTls.Count, $openNet.Count, $kv.Count, @($kv | Where-Object { $_.purge -ne 'true' -and $_.purge -ne 'True' }).Count, $std.Count, (Join-CERList ($std | Select-Object -ExpandProperty Plan -Unique) 6), $subsNoDiag.Count)
    Add-CEREvidence -Control 'NET-04' -Flag $(if ($exposedMgmt.Count) { 'Attention' } else { 'Info' }) -Action 'Close the NSG rules exposing RDP, SSH or any-any from the internet. These are the rules that get found by internet-wide scanning within hours of being created; replace them with Just-In-Time VM access or a bastion host, neither of which needs a standing inbound rule.' -Evidence ("Azure internet exposure: {0} public IPs; NSG rules exposing RDP/SSH/any from Internet: {1}." -f $pip.Count, $exposedMgmt.Count)
    Add-CEREvidence -Control 'AZ-06' -Flag Info -Action 'Inventory the public IPs and confirm each is deliberate and documented. Move storage accounts off network default Allow onto private endpoints or service-firewall rules - a storage account reachable from the internet is only as protected as its key management.' -Evidence ("Public IP inventory: {0} ({1}); storage accounts with network default Allow (no private endpoint/firewall): {2}/{3}; Key Vaults with network default Allow: {4}/{5}." -f $pip.Count, (Join-CERList ($pip | ForEach-Object { "{0}={1}" -f $_.name, $_.ip }) 6), $openNet.Count, $stor.Count, @($kv | Where-Object { $_.netdef -eq 'Allow' }).Count, $kv.Count)
}

Invoke-CERSection -Collector $C -Section 'CostAdvisorOrphans' -Script {
    $adv = Invoke-CERArg "advisorresources | where type =~ 'microsoft.advisor/recommendations' | where properties.category == 'Cost' | extend problem = tostring(properties.shortDescription.problem), savings = todouble(properties.extendedProperties.annualSavingsAmount), currency = tostring(properties.extendedProperties.savingsCurrency), res = tostring(properties.impactedValue) | project problem, savings, currency, res, subscriptionId"
    $disks = Invoke-CERArg "resources | where type =~ 'microsoft.compute/disks' | where tostring(properties.diskState) == 'Unattached' | project name, sizeGb = toint(properties.diskSizeGB), sku = tostring(sku.name), subscriptionId"
    $nics = Invoke-CERArg "resources | where type =~ 'microsoft.network/networkinterfaces' | where isnull(properties.virtualMachine) and isnull(properties.privateEndpoint) | project name, subscriptionId"
    $pips = Invoke-CERArg "resources | where type =~ 'microsoft.network/publicipaddresses' | where isnull(properties.ipConfiguration) and isnull(properties.natGateway) | project name, subscriptionId"
    $budgets = @(); $cost = @()
    foreach ($s in $subIds) {
        try { $r = Invoke-AzRestMethod -Path "/subscriptions/$s/providers/Microsoft.Consumption/budgets?api-version=2023-05-01" -Method GET -ErrorAction Stop; if ($r.StatusCode -eq 200) { $budgets += @((($r.Content | ConvertFrom-Json).value) | ForEach-Object { [pscustomobject]@{ Sub = $s; Name = $_.name; Amount = $_.properties.amount; TimeGrain = $_.properties.timeGrain; Notifications = @($_.properties.notifications.PSObject.Properties).Count } }) } } catch { }
        if (-not $SkipCost) {
            try {
                $from = (Get-Date -Day 1).AddMonths(-5).ToString('yyyy-MM-ddT00:00:00Z'); $to = (Get-Date).ToString('yyyy-MM-ddT00:00:00Z')
                $body = @{ type = 'ActualCost'; timeframe = 'Custom'; timePeriod = @{ from = $from; to = $to }; dataset = @{ granularity = 'Monthly'; aggregation = @{ totalCost = @{ name = 'Cost'; function = 'Sum' } } } } | ConvertTo-Json -Depth 6
                $r = Invoke-AzRestMethod -Path "/subscriptions/$s/providers/Microsoft.CostManagement/query?api-version=2023-11-01" -Method POST -Payload $body -ErrorAction Stop
                if ($r.StatusCode -eq 200) { $j = $r.Content | ConvertFrom-Json; $cols = @($j.properties.columns.name); $ci = [array]::IndexOf($cols, 'Cost'); $di = [array]::IndexOf($cols, 'BillingMonth'); $cur = [array]::IndexOf($cols, 'Currency'); foreach ($row in $j.properties.rows) { $cost += [pscustomobject]@{ Sub = $s; Month = "$($row[$di])".Substring(0, 7); Cost = [math]::Round([double]$row[$ci], 0); Currency = $row[$cur] } } }
            } catch { Write-CERLog ("cost query {0}: {1}" -f $s, $_.Exception.Message) 'WARN' }
        }
    }
    Save-CERRaw -Name 'cost' -Object ([ordered]@{ Advisor = $adv; UnattachedDisks = $disks; OrphanNics = $nics; OrphanPips = $pips; Budgets = $budgets; MonthlyCost = $cost })
    $savings = ($adv | Measure-Object savings -Sum).Sum
    $monthly = @($cost | Group-Object Month | Sort-Object Name | ForEach-Object { "{0}={1:n0}" -f $_.Name, ($_.Group | Measure-Object Cost -Sum).Sum })
    $subsNoBudget = @($subIds | Where-Object { $s = $_; -not ($budgets | Where-Object { $_.Sub -eq $s }) })
    Add-CEREvidence -Control 'AZ-03' -Flag $(if ($subsNoBudget.Count -or $disks.Count -gt 2 -or $savings -gt 1000) { 'Attention' } else { 'OK' }) -Action 'Set a budget with alerts on every subscription that lacks one, and put the Advisor cost recommendations in front of the client with the annual figure attached. Cost findings fund the security work; they are also the ones a client acts on fastest.' -Evidence ("Cost: monthly spend last 6 months ({0}): {1}. Budgets: {2} ({3} subscriptions without one). Advisor cost recommendations: {4} worth ~{5:n0} {6}/year ({7}). Orphaned: {8} unattached disks ({9} GB), {10} NICs, {11} public IPs." -f $(if ($cost.Count) { $cost[0].Currency } else { 'n/a' }), (Join-CERList $monthly 6), $budgets.Count, $subsNoBudget.Count, $adv.Count, $savings, $(if ($adv.Count) { $adv[0].currency } else { '' }), (Join-CERList ($adv | Group-Object problem | Sort-Object Count -Descending | ForEach-Object { "{0} x{1}" -f $_.Name, $_.Count }) 4), $disks.Count, ($disks | Measure-Object sizeGb -Sum).Sum, $nics.Count, $pips.Count)
    Add-CEREvidence -Control 'LIC-04' -Flag Info -Action 'Take the Advisor annual saving figure to the SDM and CAM. Right-sizing and reserved instances are usually the easiest money in the estate, and demonstrating a saving buys credibility for the harder recommendations elsewhere in this review.' -Evidence ("Azure Advisor cost savings available: ~{0:n0}/year across {1} recommendations; see AZ-03 for Hybrid Benefit usage." -f $savings, $adv.Count)
}

Invoke-CERSection -Collector $C -Section 'OperationsPolicyUpdates' -Script {
    $pol = Invoke-CERArg "policyresources | where type =~ 'microsoft.policyinsights/policystates' | summarize count() by tostring(properties.complianceState)"
    $assign = Invoke-CERArg "policyresources | where type =~ 'microsoft.authorization/policyassignments' | project name = tostring(properties.displayName), scope = tostring(properties.scope), enforce = tostring(properties.enforcementMode)"
    $patch = Invoke-CERArg "patchassessmentresources | where type =~ 'microsoft.compute/virtualmachines/patchassessmentresults' or type =~ 'microsoft.hybridcompute/machines/patchassessmentresults' | extend crit = toint(properties.availablePatchCountByClassification.critical), sec = toint(properties.availablePatchCountByClassification.security), other = toint(properties.availablePatchCountByClassification.other), status = tostring(properties.status), reboot = tostring(properties.rebootPending), lastAssessed = todatetime(properties.lastModifiedDateTime) | project machine = tostring(split(id,'/')[8]), crit, sec, other, status, reboot, lastAssessed"
    $arc = Invoke-CERArg "resources | where type =~ 'microsoft.hybridcompute/machines' | extend status = tostring(properties.status), os = tostring(properties.osSku) | project name, status, os"
    $alerts = Invoke-CERArg "resources | where type in~ ('microsoft.insights/metricalerts','microsoft.insights/scheduledqueryrules','microsoft.insights/activitylogalerts') | extend enabled = tostring(properties.enabled) | summarize count() by type, enabled"
    $ag = Invoke-CERArg "resources | where type =~ 'microsoft.insights/actiongroups' | extend emails = array_length(properties.emailReceivers), webhooks = array_length(properties.webhookReceivers), itsm = array_length(properties.itsmReceivers) | project name, emails, webhooks, itsm"
    $agentless = Invoke-CERArg "resources | where type =~ 'microsoft.compute/virtualmachines/extensions' | extend ext = tostring(properties.type) | where ext in ('AzureMonitorWindowsAgent','AzureMonitorLinuxAgent','MicrosoftMonitoringAgent','OmsAgentForLinux') | summarize count() by ext"
    Save-CERRaw -Name 'operations' -Object ([ordered]@{ PolicyCompliance = $pol; PolicyAssignments = $assign; PatchAssessment = $patch; Arc = $arc; Alerts = $alerts; ActionGroups = $ag; MonitorAgents = $agentless })
    $nonc = ($pol | Where-Object { $_.properties_complianceState -eq 'NonCompliant' } | Measure-Object count_ -Sum).Sum
    $comp = ($pol | Where-Object { $_.properties_complianceState -eq 'Compliant' } | Measure-Object count_ -Sum).Sum
    $vmsCrit = @($patch | Where-Object { $_.crit -gt 0 -or $_.sec -gt 0 })
    $noAssess = 'n/a'
    Add-CEREvidence -Control 'AZ-07' -Flag $(if ($ag.Count -eq 0 -or $vmsCrit.Count) { 'Attention' } else { 'OK' }) -Action 'Route the Azure Monitor alerts to LogicMonitor or the NOC so they reach someone, and work the non-compliant policy states. An alert rule with no action group is a rule that fires into nothing - which is worse than no rule, because it looks like monitoring.' -Evidence ("Azure operations: policy states compliant {0} / non-compliant {1} across {2} assignments; alert rules: {3}; action groups: {4} ({5} with email/webhook/ITSM receivers - confirm they reach bA/LogicMonitor). Update Manager assessments: {6} machines assessed, {7} with critical/security patches outstanding ({8}), {9} pending reboot. Azure Arc machines: {10}. Monitor agents installed: {11}." -f $comp, $nonc, $assign.Count, (Join-CERList ($alerts | ForEach-Object { "{0} {1}={2}" -f ($_.type -replace 'microsoft.insights/', ''), $_.enabled, $_.count_ }) 4), $ag.Count, @($ag | Where-Object { $_.emails -gt 0 -or $_.webhooks -gt 0 -or $_.itsm -gt 0 }).Count, $patch.Count, $vmsCrit.Count, (Join-CERList ($vmsCrit | ForEach-Object { "{0} (c{1}/s{2})" -f $_.machine, $_.crit, $_.sec }) 6), @($patch | Where-Object { $_.reboot -eq 'True' -or $_.reboot -eq 'true' }).Count, $arc.Count, (Join-CERList ($agentless | ForEach-Object { "{0}={1}" -f $_.ext, $_.count_ }) 4))
    if ($patch.Count) { Add-CEREvidence -Control 'SRV-03' -Flag $(if ($vmsCrit.Count) { 'Attention' } else { 'OK' }) -Action 'Bring the Azure VMs into Update Manager with a maintenance configuration and a schedule, then work the machines with outstanding critical and security updates. Azure VMs are frequently outside the on-prem patch policy and nobody notices until they are assessed separately, as here.' -Evidence ("Azure Update Manager: {0} machines assessed, {1} with outstanding critical/security updates." -f $patch.Count, $vmsCrit.Count) }
}
Complete-CERCollector

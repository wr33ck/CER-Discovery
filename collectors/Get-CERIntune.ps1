#Requires -Version 5.1
<#
.SYNOPSIS
  CER-Discovery collector: Intune (managed devices, compliance, configuration, update rings, Autopilot, app protection,
  endpoint security policies incl. ASR/LAPS/App Control, ADMX-backed settings, detected apps). Uses the Graph session
  opened by Get-CEREntra.ps1 (or connects itself). Feeds END-01..16, BDR-07, SEC-12.
.NOTES
  Settings-catalog / endpoint-security / Autopilot-profile endpoints are Graph BETA (documented as such by Microsoft).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Client,
    [string]$OutputRoot,
    [string]$RunId,
    [string]$TenantId,
    [switch]$UseDeviceCode,
    [int]$MaxPolicySettingsFetch = 40,
    [int]$MaxDetectedAppPages = 20
)
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'lib/CER.Common.ps1')
$null = Initialize-CERRun -Client $Client -OutputRoot $OutputRoot -Collector 'Intune' -RunId $RunId
$C = 'Intune'
if (-not (Test-CERModule -Name Microsoft.Graph.Authentication -Collector $C)) { Complete-CERCollector; return }
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
$now = Get-Date
$ctx = Get-MgContext
if (-not $ctx -or ($TenantId -and $ctx.TenantId -ne $TenantId)) {
    if (-not $TenantId) { Set-CERCoverage -Collector $C -Section 'Connect' -Status Failed -Note 'No Graph session and no -TenantId given'; Complete-CERCollector; return }
    $p = @{ TenantId = $TenantId; NoWelcome = $true; Scopes = @('DeviceManagementManagedDevices.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementApps.Read.All', 'DeviceManagementServiceConfig.Read.All', 'Directory.Read.All') }
    if ($UseDeviceCode) { $p['UseDeviceCode'] = $true }
    Connect-MgGraph @p
}

# ---------------- Managed devices
$devices = @()
Invoke-CERSection -Collector $C -Section 'ManagedDevices' -Script {
    $script:devices = @(Get-CERGraph 'deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,lastSyncDateTime,managementAgent,managedDeviceOwnerType,model,manufacturer,enrolledDateTime,azureADDeviceId,deviceEnrollmentType,jailBroken,userPrincipalName,serialNumber,skuFamily,joinType,autopilotEnrolled&$top=1000' -All -MaxPages 100)
    $d = $script:devices
    if ($d.Count -eq 0) { Add-CEREvidence -Control 'END-01' -Flag Attention -Action 'Establish which of the three this is: Intune is not licensed, it is licensed but unused, or the collector lacks DeviceManagementManagedDevices.Read.All. If the client owns Intune and is not using it, that is a paid security control sitting idle and the easiest improvement to fund; if it is a permission gap, re-run rather than scoring the endpoint controls as unevidenced.' -Evidence 'Intune returns zero managed devices (not licensed, not used, or no permission).'; return }
    $byOs = @($d | Group-Object operatingSystem | Sort-Object Count -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $win = @($d | Where-Object { $_.operatingSystem -eq 'Windows' })
    $win10 = @($win | Where-Object { $_.osVersion -match '^10\.0\.1\d{4}' }); $win11 = @($win | Where-Object { $_.osVersion -match '^10\.0\.2\d{4}' })
    $builds = @($win | ForEach-Object { if ($_.osVersion -match '^10\.0\.(\d+)') { [int]$Matches[1] } } | Group-Object | Sort-Object Name -Descending | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $stale = @($d | Where-Object { (Get-CERAgeDays $_.lastSyncDateTime) -gt 30 })
    $comp = @($d | Group-Object complianceState | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    $nonComp = @($d | Where-Object { $_.complianceState -in 'noncompliant', 'error', 'conflict' })
    $enc = @($win | Where-Object isEncrypted); $notEnc = @($win | Where-Object { -not $_.isEncrypted })
    $personal = @($d | Where-Object { $_.managedDeviceOwnerType -eq 'personal' })
    $mobile = @($d | Where-Object { $_.operatingSystem -in 'iOS', 'Android', 'iPadOS' })
    $autopilot = @($win | Where-Object autopilotEnrolled)
    $jail = @($d | Where-Object { $_.jailBroken -eq 'True' })
    $mac = @($d | Where-Object { $_.operatingSystem -eq 'macOS' })
    Save-CERRaw -Name 'manageddevices' -Object ([ordered]@{ Total = $d.Count; ByOS = $byOs; WindowsBuilds = $builds; Windows10 = $win10.Count; Windows11 = $win11.Count; Stale30d = @($stale | ForEach-Object { $_.deviceName }); Compliance = $comp; Encrypted = $enc.Count; NotEncrypted = @($notEnc | ForEach-Object { $_.deviceName }); Personal = $personal.Count; Devices = @($d | Select-Object deviceName, operatingSystem, osVersion, complianceState, isEncrypted, lastSyncDateTime, managedDeviceOwnerType, model, manufacturer, enrolledDateTime, joinType, autopilotEnrolled, userPrincipalName) })
    Add-CEREvidence -Control 'END-01' -Flag $(if ($d.Count -and ($stale.Count / $d.Count) -gt 0.05) { 'Attention' } else { 'OK' }) -Action 'Investigate devices that have not synced in 30 days - they are either gone, or still in use and no longer receiving policy or updates. Neither is acceptable: retire the records for devices that no longer exist so coverage percentages mean something, and chase the rest.' -Evidence ("Intune managed devices: {0} ({1}); not synced for > 30 days: {2} ({3}); personal-owned: {4}; join types: {5}. Compare with Entra devices, RMM and EDR counts." -f $d.Count, (Join-CERList $byOs 5), $stale.Count, (ConvertTo-CERPct $stale.Count $d.Count), $personal.Count, (Join-CERList ($win | Group-Object joinType | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 4))
    Add-CEREvidence -Control 'END-02' -Flag $(if ($win10.Count) { 'Attention' } else { 'OK' }) -Action 'Replace or upgrade the Windows 10 devices - support ended 14 Oct 2025 and they receive no security updates without ESU. Track the Windows 11 build spread too: a device several feature updates behind is out of servicing on its own schedule, separately from the OS version.' -Evidence ("Intune Windows devices: {0} - Windows 11: {1}, Windows 10: {2} (out of support 14 Oct 2025); builds: {3}; macOS: {4}." -f $win.Count, $win11.Count, $win10.Count, (Join-CERList $builds 6), $mac.Count)
    Add-CEREvidence -Control 'END-07' -Flag $(if ($win.Count -and ($enc.Count / $win.Count) -ge 0.98) { 'OK' } else { 'Attention' }) -Action 'Encrypt the Windows devices Intune reports as unencrypted, starting with laptops. Enforce it through a disk encryption policy rather than device by device, and confirm recovery keys escrow to Entra - encryption without a recoverable key is a data-loss risk, not a control.' -Evidence ("Intune reports isEncrypted on {0}/{1} Windows devices ({2}); not encrypted: {3}." -f $enc.Count, $win.Count, (ConvertTo-CERPct $enc.Count $win.Count), (Join-CERList ($notEnc | ForEach-Object { $_.deviceName }) 8))
    Add-CEREvidence -Control 'END-12' -Flag $(if ($d.Count -and ($nonComp.Count / $d.Count) -le 0.05) { 'OK' } else { 'Attention' }) -Action 'Work through the non-compliant, error and conflict devices. Conflict usually means two policies targeting the same setting with different values, which leaves the setting effectively unmanaged; error usually means the device cannot apply the policy at all. Both read as coverage in a summary and provide none.' -Evidence ("Compliance state: {0}; non-compliant/error/conflict: {1} ({2})." -f (Join-CERList $comp 5), $nonComp.Count, (ConvertTo-CERPct $nonComp.Count $d.Count))
    Add-CEREvidence -Control 'END-13' -Flag Info -Action 'Register new devices through Autopilot so builds are consistent and provisioning is repeatable. Devices outside Autopilot were built by hand, which means the baseline on them is whatever the technician remembered on the day.' -Evidence ("Windows devices enrolled via Autopilot: {0}/{1} ({2})." -f $autopilot.Count, $win.Count, (ConvertTo-CERPct $autopilot.Count $win.Count))
    Add-CEREvidence -Control 'END-14' -Flag Info -Action 'Confirm every mobile device with corporate mail is under either MDM or app protection policy, and that jailbroken or rooted devices are blocked by a compliance policy backed by Conditional Access. A flagged device that is still allowed to connect is a detection with no consequence.' -Evidence ("Mobile devices under MDM: {0} (iOS/iPadOS {1}, Android {2}); jailbroken/rooted flagged: {3}. MAM-only (app protection without enrolment) users are not in this list." -f $mobile.Count, @($mobile | Where-Object { $_.operatingSystem -like 'i*' }).Count, @($mobile | Where-Object { $_.operatingSystem -eq 'Android' }).Count, $jail.Count)
}

# ---------------- Compliance policies
Invoke-CERSection -Collector $C -Section 'CompliancePolicies' -Script {
    $pol = @(Get-CERGraph 'deviceManagement/deviceCompliancePolicies?$expand=assignments' -All)
    $rows = @($pol | ForEach-Object { $t = ("$($_.'@odata.type')" -replace '#microsoft.graph.', ''); [pscustomobject]@{ Name = $_.displayName; Type = $t; Assigned = (@($_.assignments).Count -gt 0); BitLocker = (Get-CERProp $_ 'bitLockerEnabled'); SecureBoot = (Get-CERProp $_ 'secureBootEnabled'); Antivirus = (Get-CERProp $_ 'antivirusRequired'); Firewall = (Get-CERProp $_ 'activeFirewallRequired'); Defender = (Get-CERProp $_ 'defenderEnabled'); OsMin = (Get-CERProp $_ 'osMinimumVersion'); PasswordRequired = (Get-CERProp $_ 'passwordRequired'); ThreatLevel = (Get-CERProp $_ 'deviceThreatProtectionRequiredSecurityLevel'); TPM = (Get-CERProp $_ 'tpmRequired') } })
    Save-CERRaw -Name 'compliancepolicies' -Object $rows
    $winPol = @($rows | Where-Object { $_.Type -like 'windows10*' -and $_.Assigned })
    $strong = @($winPol | Where-Object { $_.BitLocker -and ($_.Antivirus -or $_.Defender) -and $_.Firewall })
    Add-CEREvidence -Control 'END-12' -Flag $(if ($strong.Count) { 'OK' } elseif ($winPol.Count) { 'Attention' } else { 'Attention' }) -Action 'Make sure every compliance policy is actually assigned - an unassigned policy is inert - and that the Windows policies check something meaningful: encryption, antivirus, firewall, minimum OS build and Defender risk score. Then confirm Conditional Access requires compliance, or none of it affects access.' -Evidence ("Compliance policies: {0} total, {1} assigned ({2}); Windows policies requiring BitLocker + AV + firewall: {3}; OS minimum set on {4}; MDE threat level used on {5}. Platforms: {6}." -f $pol.Count, @($rows | Where-Object Assigned).Count, (Join-CERList ($rows | Where-Object Assigned | ForEach-Object { $_.Name }) 6), $strong.Count, @($winPol | Where-Object OsMin).Count, @($winPol | Where-Object { $_.ThreatLevel -and $_.ThreatLevel -ne 'unavailable' }).Count, (Join-CERList ($rows | Group-Object Type | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 6))
}

# ---------------- Device configuration profiles (v1.0) incl. update rings, endpoint protection
Invoke-CERSection -Collector $C -Section 'ConfigurationProfiles' -Script {
    $cfg = @(Get-CERGraph 'deviceManagement/deviceConfigurations?$expand=assignments' -All)
    $rows = @($cfg | ForEach-Object { [pscustomobject]@{ Name = $_.displayName; Type = ("$($_.'@odata.type')" -replace '#microsoft.graph.', ''); Assigned = (@($_.assignments).Count -gt 0); Raw = $_ } })
    $rings = @($rows | Where-Object { $_.Type -eq 'windowsUpdateForBusinessConfiguration' })
    $ringTxt = @($rings | ForEach-Object { $r = $_.Raw; "{0}: quality defer {1}d, feature defer {2}d, mode {3}, deadline q={4}/f={5}, grace {6}d{7}" -f $_.Name, $r.qualityUpdatesDeferralPeriodInDays, $r.featureUpdatesDeferralPeriodInDays, $r.automaticUpdateMode, (Get-CERProp $r 'deadlineForQualityUpdatesInDays'), (Get-CERProp $r 'deadlineForFeatureUpdatesInDays'), (Get-CERProp $r 'deadlineGracePeriodInDays'), $(if (-not $_.Assigned) { ' [UNASSIGNED]' } else { '' }) })
    $ep = @($rows | Where-Object { $_.Type -eq 'windows10EndpointProtectionConfiguration' -and $_.Assigned })
    $epAsr = @($ep | Where-Object { $r = $_.Raw; ($r.PSObject.Properties | Where-Object { $_.Name -like 'defenderOffice*' -or $_.Name -like 'defender*Process*' -or $_.Name -like 'defenderAdobe*' -or $_.Name -like 'defenderScript*' } | Where-Object { "$($_.Value)" -match 'block|enable' }).Count -gt 0 })
    $epBl = @($ep | Where-Object { (Get-CERProp $_.Raw 'bitLockerEncryptDevice') -eq $true })
    $epFw = @($ep | Where-Object { $r = $_.Raw; (Get-CERProp (Get-CERProp $r 'firewallProfileDomain') 'firewallEnabled') -eq 'allowed' -or (Get-CERProp (Get-CERProp $r 'firewallProfilePublic') 'firewallEnabled') -eq 'allowed' })
    $restr = @($rows | Where-Object { $_.Type -eq 'windows10GeneralConfiguration' -and $_.Assigned })
    $usbBlocked = @($restr | Where-Object { (Get-CERProp $_.Raw 'storageBlockRemovableStorage') -eq $true })
    $lock = @($restr | Where-Object { $v = Get-CERProp $_.Raw 'passwordMinutesOfInactivityBeforeScreenTimeout'; ($v -and $v -le 15) })
    $smart = @($restr | Where-Object { (Get-CERProp $_.Raw 'smartScreenEnableAppInstallControl') -eq $true -or (Get-CERProp $_.Raw 'smartScreenBlockPromptOverride') -eq $true })
    $custom = @($rows | Where-Object { $_.Type -eq 'windows10CustomConfiguration' -and $_.Assigned })
    $edgeCfg = @($rows | Where-Object { $_.Type -like '*edge*' -or $_.Name -match 'Edge|Chrome|Browser' })
    Save-CERRaw -Name 'deviceconfigurations' -Object @($rows | Select-Object Name, Type, Assigned)
    Save-CERRaw -Name 'updaterings' -Object @($rings | ForEach-Object { $_.Raw | Select-Object displayName, qualityUpdatesDeferralPeriodInDays, featureUpdatesDeferralPeriodInDays, automaticUpdateMode, deadlineForQualityUpdatesInDays, deadlineForFeatureUpdatesInDays, deadlineGracePeriodInDays, businessReadyUpdatesOnly, driversExcluded })
    Add-CEREvidence -Control 'END-03' -Flag $(if (@($rings | Where-Object Assigned).Count) { 'OK' } else { 'Attention' }) -Action 'Put every Windows device into an assigned update ring with a defined deferral and deadline, so patching happens on a schedule rather than when the user reboots. Devices in no ring default to whatever Windows Update decides, which is not a patch policy and cannot be reported on.' -Evidence ("Windows Update rings: {0} ({1} assigned) - {2}. Compliance % must come from Intune update reports / RMM; the host check gives last-patch age." -f $rings.Count, @($rings | Where-Object Assigned).Count, (Join-CERList $ringTxt 4))
    Add-CEREvidence -Control 'END-11' -Flag Info -Action 'Migrate the legacy Endpoint Protection profiles to the settings catalog and endpoint security policies - Microsoft is retiring the older profile types, and mixing both is the usual source of conflicting settings that silently leave a control unapplied.' -Evidence ("Legacy Endpoint Protection profiles assigned: {0}; with Defender ASR/exploit-guard settings: {1} ({2}); BitLocker in EP profile: {3}; firewall profiles configured: {4}. Settings-catalog/endpoint-security equivalents are listed separately." -f $ep.Count, $epAsr.Count, (Join-CERList ($epAsr | ForEach-Object { $_.Name }) 3), $epBl.Count, $epFw.Count)
    Add-CEREvidence -Control 'END-15' -Flag Info -Action 'Set the device restriction profile deliberately rather than leaving defaults: removable storage position agreed with the client, screen timeout at 15 minutes or less, and the peripheral controls that match their risk appetite. An unconfigured setting is a decision nobody made.' -Evidence ("Device restriction profiles assigned: {0}; removable storage blocked in {1}; screen timeout <= 15 min in {2}; SmartScreen app-install control in {3}; custom OMA-URI profiles: {4}; browser-related profiles: {5}." -f $restr.Count, $usbBlocked.Count, $lock.Count, $smart.Count, $custom.Count, $edgeCfg.Count)
    Add-CEREvidence -Control 'END-07' -Flag Info -Action 'Enforce BitLocker through a disk encryption policy with recovery keys escrowed to Entra, and check whether encryption is being configured in both the legacy Endpoint Protection profile and the settings catalog - where both target it, the result is unpredictable.' -Evidence ("BitLocker enforced via Endpoint Protection profile(s): {0} ({1}); check settings-catalog Disk Encryption policies below as well." -f $epBl.Count, (Join-CERList ($epBl | ForEach-Object { $_.Name }) 3))
}

# ---------------- Settings catalog + endpoint security (beta)
Invoke-CERSection -Collector $C -Section 'SettingsCatalogEndpointSecurity' -Script {
    $pols = @(Get-CERGraph 'deviceManagement/configurationPolicies?$expand=assignments&$top=100' -Beta -All)
    $rows = @($pols | ForEach-Object { $t = Get-CERProp $_ 'templateReference'; [pscustomobject]@{ Id = $_.id; Name = $_.name; Platform = "$($_.platforms)"; Family = $(if ($t) { "$($t.templateFamily)" } else { 'none' }); Template = $(if ($t) { "$($t.templateDisplayName)" } else { 'settings catalog' }); Assigned = (@($_.assignments).Count -gt 0); Settings = $_.settingCount } })
    Save-CERRaw -Name 'configurationpolicies' -Object $rows
    $fam = @($rows | Where-Object Assigned | Group-Object Family | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count })
    function _family { param($f) @($rows | Where-Object { $_.Assigned -and $_.Family -eq $f }) }
    $asr = _family 'endpointSecurityAttackSurfaceReductionRules'; if ($asr.Count -eq 0) { $asr = @($rows | Where-Object { $_.Assigned -and ($_.Family -like 'endpointSecurityAttackSurfaceReduction*' -or $_.Template -like '*Attack Surface Reduction*') }) }
    $laps = @($rows | Where-Object { $_.Assigned -and ($_.Template -like '*LAPS*' -or $_.Name -match 'LAPS') })
    $appctl = @($rows | Where-Object { $_.Assigned -and ($_.Family -like 'endpointSecurityApplicationControl*' -or $_.Template -like '*App Control*' -or $_.Name -match 'WDAC|AppLocker|App Control') })
    $av = _family 'endpointSecurityAntivirus'; $disk = _family 'endpointSecurityDiskEncryption'; $fw = _family 'endpointSecurityFirewall'; $edr = _family 'endpointSecurityEndpointDetectionAndResponse'; $acct = _family 'endpointSecurityAccountProtection'; $base = _family 'baseline'
    # pull settings for ASR / LAPS / macro-ish policies (capped)
    $fetch = @($asr + $laps + $appctl + @($rows | Where-Object { $_.Assigned -and $_.Name -match 'macro|office|edge|chrome|browser|powershell|logging|usb|removable|print|lock|screen' })) | Select-Object -Unique -Property Id, Name | Select-Object -First $MaxPolicySettingsFetch
    $asrStates = @{}; $keyFinds = @()
    function _walk { param($node, $acc) if ($null -eq $node) { return }; if ($node -is [System.Collections.IEnumerable] -and -not ($node -is [string])) { foreach ($n in $node) { _walk $n $acc }; return }; $def = Get-CERProp $node 'settingDefinitionId'; if ($def) { $val = $null; $c = Get-CERProp $node 'choiceSettingValue'; if ($c) { $val = $c.value } else { $s = Get-CERProp $node 'simpleSettingValue'; if ($s) { $val = $s.value } }; $null = $acc.Add([pscustomobject]@{ Def = $def; Value = "$val" }); foreach ($child in @((Get-CERProp $c 'children'))) { _walk $child $acc } }; foreach ($p in $node.PSObject.Properties) { if ($p.Name -in 'settingInstance', 'groupSettingCollectionValue', 'children', 'settingValue') { _walk $p.Value $acc } } }
    foreach ($f in $fetch) {
        try {
            $set = @(Get-CERGraph ("deviceManagement/configurationPolicies/{0}/settings?`$top=200" -f $f.Id) -Beta -All)
            $acc = New-Object System.Collections.ArrayList
            foreach ($s in $set) { _walk $s.settingInstance $acc }
            foreach ($x in $acc) {
                if ($x.Def -like '*attacksurfacereductionrules_*' -and $x.Def -notlike '*_perruleexclusions*') { $rule = ($x.Def -split 'attacksurfacereductionrules_')[-1]; $mode = ($x.Value -split '_')[-1]; if ($mode -in 'block', 'audit', 'warn', 'off') { $asrStates["$rule"] = $mode } }
                if ($x.Def -match 'macro|vbawarnings|blockcontentexecutionfrominternet|macroruntimescanscope|laps|backupdirectory|scriptblocklogging|modulelogging|removablestorage|pointandprint|inactivitytimeout|smbv1|edge_|chrome') { $keyFinds += [pscustomobject]@{ Policy = $f.Name; Setting = ($x.Def -replace '^device_vendor_msft_policy_config_|^user_vendor_msft_policy_config_', ''); Value = ($x.Value -replace '^.*_', '') } }
            }
        } catch { Write-CERLog ("settings fetch failed for {0}: {1}" -f $f.Name, $_.Exception.Message) 'WARN' }
    }
    Save-CERRaw -Name 'policysettings' -Object ([ordered]@{ ASR = $asrStates; KeySettings = $keyFinds })
    $asrBlock = @($asrStates.Keys | Where-Object { $asrStates[$_] -eq 'block' }); $asrAudit = @($asrStates.Keys | Where-Object { $asrStates[$_] -eq 'audit' })
    Add-CEREvidence -Control 'END-11' -Flag $(if ($asrBlock.Count -ge 6) { 'OK' } elseif ($asr.Count) { 'Attention' } else { 'Attention' }) -Action 'Move the ASR rules from audit to block. Audit mode collects telemetry and prevents nothing; it counts as progress only if there is a date on enforcement. Start with the Office and PDF child-process rules and credential-stealing from LSASS, which have the best protection-to-disruption ratio.' -Evidence ("Endpoint security / settings catalog (assigned): {0}. ASR policies: {1}; rules in block: {2} ({3}); audit: {4}; warn/off: {5}. Antivirus policies {6}, EDR onboarding {7}, firewall {8}, baselines {9}." -f (Join-CERList $fam 8), $asr.Count, $asrBlock.Count, (Join-CERList ($asrBlock | ForEach-Object { $_ -replace 'block', '' }) 8), $asrAudit.Count, ($asrStates.Count - $asrBlock.Count - $asrAudit.Count), $av.Count, $edr.Count, $fw.Count, $base.Count)
    $macroKeys = @($keyFinds | Where-Object { $_.Setting -match 'macro|vbawarnings|blockcontentexecutionfrominternet' })
    Add-CEREvidence -Control 'END-10' -Flag $(if ($macroKeys.Count -or ($asrStates['blockwin32apicallsfromofficemacros'] -eq 'block')) { 'OK' } else { 'Attention' }) -Action 'Deliver the Office macro settings through Intune rather than GPO where devices are cloud-managed, and confirm both blocking macros from the internet and VBAWarnings are set for Word, Excel and PowerPoint. A device covered by neither GPO nor Intune for macros has no macro policy at all.' -Evidence ("Office macro settings delivered by Intune (settings catalog): {0} setting(s) in {1} policies ({2}); ASR 'Block Win32 API calls from Office macros' = {3}. ADMX-backed Office policies are listed under GroupPolicyConfigurations." -f $macroKeys.Count, @($macroKeys | Select-Object -ExpandProperty Policy -Unique).Count, (Join-CERList ($macroKeys | ForEach-Object { "{0}={1}" -f $_.Setting, $_.Value }) 6), $(if ($asrStates.ContainsKey('blockwin32apicallsfromofficemacros')) { $asrStates['blockwin32apicallsfromofficemacros'] } else { 'not configured' }))
    Add-CEREvidence -Control 'END-08' -Flag $(if ($laps.Count) { 'OK' } else { 'Attention' }) -Action 'Deploy a Windows LAPS policy through Intune covering every Windows device, then confirm from the Entra deviceLocalCredentials data that passwords are actually being backed up and rotated. A policy that exists and has not reached devices is a policy in name only.' -Evidence ("Windows LAPS policy in Intune: {0} ({1}); account-protection policies: {2}. Coverage % is in the Entra deviceLocalCredentials evidence." -f $laps.Count, (Join-CERList ($laps | ForEach-Object { $_.Name }) 3), $acct.Count)
    Add-CEREvidence -Control 'END-09' -Flag $(if ($appctl.Count) { 'OK' } else { 'Info' }) -Action 'Start application control in audit mode through Intune (App Control for Business) to build the picture of what runs, then move to enforcement with a date. This is the most effective Essential Eight mitigation and the one most often left at zero because it looks hard - audit mode is not hard.' -Evidence ("Application control policies in Intune (App Control for Business / WDAC / AppLocker custom): {0} ({1}). Airlock is evidenced by its agent on hosts and the Airlock portal." -f $appctl.Count, (Join-CERList ($appctl | ForEach-Object { $_.Name }) 3))
    Add-CEREvidence -Control 'END-07' -Flag $(if ($disk.Count) { 'OK' } else { 'Info' }) -Action 'Assign the disk encryption policy to every Windows device group and confirm recovery keys are escrowing to Entra. Check this against the Entra BitLocker key count rather than the policy assignment - assignment is intent, escrow is evidence.' -Evidence ("Disk encryption (BitLocker) endpoint-security policies assigned: {0} ({1})." -f $disk.Count, (Join-CERList ($disk | ForEach-Object { $_.Name }) 3))
    $other = @($keyFinds | Where-Object { $_.Setting -match 'scriptblocklogging|modulelogging|removablestorage|pointandprint|inactivitytimeout|smbv1' })
    if ($other.Count) { Add-CEREvidence -Control 'END-15' -Flag Info -Action 'Review the settings-catalog host controls against the client''s agreed baseline and record what was deliberately not set. An empty setting is indistinguishable from an unconsidered one once the person who configured it has moved on.' -Evidence ("Settings-catalog host controls found: {0}" -f (Join-CERList ($other | ForEach-Object { "{0}={1}" -f $_.Setting, $_.Value }) 8)) }
}

# ---------------- ADMX-backed (Group Policy) configurations (beta)
Invoke-CERSection -Collector $C -Section 'AdmxPolicies' -Script {
    $gp = @(Get-CERGraph 'deviceManagement/groupPolicyConfigurations?$expand=assignments' -Beta -All)
    $finds = @()
    foreach ($g in $gp) {
        try {
            $dv = @(Get-CERGraph ("deviceManagement/groupPolicyConfigurations/{0}/definitionValues?`$expand=definition" -f $g.id) -Beta -All)
            foreach ($v in $dv) { $finds += [pscustomobject]@{ Profile = $g.displayName; Assigned = (@($g.assignments).Count -gt 0); Setting = $v.definition.displayName; Category = $v.definition.categoryPath; Enabled = $v.enabled } }
        } catch { }
    }
    Save-CERRaw -Name 'admxpolicies' -Object $finds
    $kw = @{ 'END-10' = 'macro|VBA|Trust Center'; 'END-11' = 'Java|Script Block|Module Logging|Transcription|Internet Explorer|Enhanced Security|SmartScreen|Object Linking|OLE|Flash|Protected View|Developer Tools'; 'BDR-07' = 'Known Folder|KFM|OneDrive'; 'END-15' = 'Point and Print|Removable|Screen saver|Lock|Autoplay|AutoRun'; 'END-08' = 'LAPS|Local Administrator'; 'SRV-04' = 'SMB|NTLM|LDAP|Digest' }
    foreach ($k in $kw.Keys) {
        $hit = @($finds | Where-Object { $_.Assigned -and $_.Enabled -and ($_.Setting -match $kw[$k] -or $_.Category -match $kw[$k]) })
        if ($hit.Count) { Add-CEREvidence -Control $k -Flag Info -Action 'Check these ADMX-backed settings against what is also being set by Group Policy on the same devices. Where a hybrid-joined device receives both, the result depends on timing rather than intent - pick one management plane per setting and document which.' -Evidence ("Intune ADMX policies enabled ({0} matching): {1}" -f $hit.Count, (Join-CERList ($hit | ForEach-Object { "{0}" -f $_.Setting } | Select-Object -Unique) 8)) }
    }
    Add-CEREvidence -Control 'END-13' -Flag Info -Action 'Confirm the ADMX profiles are assigned and reaching devices, and record which settings are managed here rather than by GPO. Split-brain management between Intune and Group Policy is one of the harder things for the next engineer to unpick.' -Evidence ("ADMX-backed profiles: {0} ({1} assigned), {2} settings configured." -f $gp.Count, @($gp | Where-Object { @($_.assignments).Count -gt 0 }).Count, $finds.Count)
}

# ---------------- Autopilot, enrollment, ESP
Invoke-CERSection -Collector $C -Section 'AutopilotEnrollment' -Script {
    $profiles = @(Get-CERGraph 'deviceManagement/windowsAutopilotDeploymentProfiles?$expand=assignments' -Beta -All)
    $ids = @(); try { $ids = @(Get-CERGraph 'deviceManagement/windowsAutopilotDeviceIdentities?$top=1000' -All -MaxPages 20) } catch { }
    $enr = @(Get-CERGraph 'deviceManagement/deviceEnrollmentConfigurations' -All)
    $esp = @($enr | Where-Object { "$($_.'@odata.type')" -like '*EnrollmentCompletionPageConfiguration' -and $_.priority -gt 0 })
    $platRestr = @($enr | Where-Object { "$($_.'@odata.type')" -like '*PlatformRestriction*' })
    $personalBlocked = @($platRestr | ForEach-Object { $r = $_; foreach ($n in 'windowsRestriction', 'iosRestriction', 'androidRestriction', 'androidForWorkRestriction', 'macOSRestriction') { $x = Get-CERProp $r $n; if ($x -and $x.personalDeviceEnrollmentBlocked) { $n } } })
    Save-CERRaw -Name 'autopilot' -Object ([ordered]@{ Profiles = @($profiles | Select-Object displayName, '@odata.type', deviceNameTemplate, outOfBoxExperienceSettings, @{ n = 'assigned'; e = { @($_.assignments).Count -gt 0 } }); DeviceIdentities = $ids.Count; ESP = @($esp | Select-Object displayName, priority, showInstallationProgress, blockDeviceSetupRetryByUser, installProgressTimeoutInMinutes); PlatformRestrictions = $personalBlocked })
    Add-CEREvidence -Control 'END-13' -Flag $(if (@($profiles | Where-Object { @($_.assignments).Count -gt 0 }).Count -and $ids.Count) { 'OK' } else { 'Attention' }) -Action 'Assign the Autopilot deployment profiles and use an Enrolment Status Page so a new device is fully configured before the user reaches the desktop. Without ESP the user gets a working desktop and the policies land afterwards, which is exactly when they call the service desk about the machine changing under them.' -Evidence ("Autopilot: {0} deployment profiles ({1} assigned: {2}); {3} registered Autopilot devices; custom ESP profiles: {4}. Naming template(s): {5}." -f $profiles.Count, @($profiles | Where-Object { @($_.assignments).Count -gt 0 }).Count, (Join-CERList ($profiles | ForEach-Object { $_.displayName }) 3), $ids.Count, $esp.Count, (Join-CERList ($profiles | ForEach-Object { $_.deviceNameTemplate } | Where-Object { $_ }) 3))
    Add-CEREvidence -Control 'END-14' -Flag Info -Action 'Set enrolment restrictions to match the client''s BYOD position. If personally-owned devices are not meant to enrol, block them here rather than relying on people not trying - and if they are allowed, confirm app protection policies cover them.' -Evidence ("Enrolment restrictions blocking personally-owned devices: {0}." -f (Join-CERList $personalBlocked 5))
}

# ---------------- App protection (MAM)
Invoke-CERSection -Collector $C -Section 'AppProtection' -Script {
    $mam = @(Get-CERGraph 'deviceAppManagement/managedAppPolicies?$top=200' -All)
    $ios = @($mam | Where-Object { "$($_.'@odata.type')" -like '*iosManagedAppProtection' }); $and = @($mam | Where-Object { "$($_.'@odata.type')" -like '*androidManagedAppProtection' }); $winMam = @($mam | Where-Object { "$($_.'@odata.type')" -like '*windowsManagedAppProtection' -or "$($_.'@odata.type')" -like '*mdmWindowsInformationProtectionPolicy' })
    $pin = @($mam | Where-Object { (Get-CERProp $_ 'pinRequired') -eq $true })
    $saveBlock = @($mam | Where-Object { (Get-CERProp $_ 'saveAsBlocked') -eq $true -or (Get-CERProp $_ 'dataBackupBlocked') -eq $true })
    Save-CERRaw -Name 'appprotection' -Object @($mam | Select-Object displayName, '@odata.type', pinRequired, saveAsBlocked, dataBackupBlocked, allowedOutboundDataTransferDestinations, periodOfflineBeforeWipeIsEnforced, minimumRequiredOsVersion, isAssigned)
    Add-CEREvidence -Control 'END-14' -Flag $(if ($ios.Count -and $and.Count) { 'OK' } else { 'Attention' }) -Action 'Extend app protection policies to every mobile platform in use, requiring a PIN and blocking save-as and backup to personal locations. This is what makes selective wipe possible on a personal phone; without it, the only options when someone leaves are wiping their own device or leaving corporate data on it.' -Evidence ("App protection policies: iOS {0}, Android {1}, Windows {2}; requiring PIN: {3}; blocking save-as/backup to personal locations: {4}. Enforcement depends on the CA 'require app protection' policy (see IAM/END-14 CA evidence)." -f $ios.Count, $and.Count, $winMam.Count, $pin.Count, $saveBlock.Count)
}

# ---------------- Detected apps (watchlist)
Invoke-CERSection -Collector $C -Section 'DetectedApps' -Script {
    $apps = @(); try { $apps = @(Get-CERGraph 'deviceManagement/detectedApps?$top=1000&$orderby=deviceCount desc' -All -MaxPages $MaxDetectedAppPages) } catch { $apps = @(Get-CERGraph 'deviceManagement/detectedApps?$top=1000' -All -MaxPages $MaxDetectedAppPages) }
    $watch = 'Java|Adobe Flash|7-Zip|WinRAR|PuTTY|Adobe Acrobat|Adobe Reader|TeamViewer|AnyDesk|ScreenConnect|Splashtop|LogMeIn|RustDesk|Chrome Remote|UltraVNC|TightVNC|RealVNC|Dropbox|Google Drive|MEGAsync|Silverlight|QuickTime|Zoom|Notepad\+\+|VLC|Wireshark|Microsoft Office (Professional|Standard|Home)'
    $hits = @($apps | Where-Object { $_.displayName -match $watch } | Select-Object displayName, version, deviceCount, publisher)
    Save-CERRaw -Name 'detectedapps' -Object ([ordered]@{ Total = $apps.Count; Watchlist = $hits })
    $remote = @($hits | Where-Object { $_.displayName -match 'TeamViewer|AnyDesk|ScreenConnect|Splashtop|LogMeIn|RustDesk|Chrome Remote|VNC' })
    $java = @($hits | Where-Object { $_.displayName -match 'Java' }); $flash = @($hits | Where-Object { $_.displayName -match 'Flash' })
    $capped = ($apps.Count -ge ($MaxDetectedAppPages * 1000))
    Add-CEREvidence -Control 'END-04' -Flag $(if ($flash.Count) { 'Attention' } else { 'Info' }) -Action 'Remove or update the flagged applications from the Intune inventory - Java and Flash in particular. Third-party software is where most exploited vulnerabilities actually live and it usually sits outside the OS patch policy, so confirm the RMM''s third-party patching covers each title that stays.' -Evidence ("Intune detected apps scanned: {0}{1}. Watchlist: Java entries {2} (max {3} devices), Flash {4}, archive/PDF tools {5}. Versions seen: {6}." -f $apps.Count, $(if ($capped) { ' (capped - raise -MaxDetectedAppPages)' } else { '' }), $java.Count, (($java | Measure-Object deviceCount -Maximum).Maximum), $flash.Count, @($hits | Where-Object { $_.displayName -match '7-Zip|WinRAR|Acrobat|Reader' }).Count, (Join-CERList ($hits | Where-Object { $_.displayName -match '7-Zip|WinRAR|PuTTY|Java' } | Sort-Object deviceCount -Descending | ForEach-Object { "{0} {1} x{2}" -f $_.displayName, $_.version, $_.deviceCount }) 8))
    Add-CEREvidence -Control 'SEC-12' -Flag $(if ($remote.Count) { 'Attention' } else { 'OK' }) -Action 'Account for every remote-access tool in the inventory and confirm each is a sanctioned blueAPACHE or named-vendor path with an owner. Block the rest with application control - unsanctioned remote access is both an unmanaged third-party route in and a common way an attacker retains access.' -Evidence ("Remote-access tools detected by Intune inventory: {0} - {1}." -f $remote.Count, (Join-CERList ($remote | Sort-Object deviceCount -Descending | ForEach-Object { "{0} {1} x{2}" -f $_.displayName, $_.version, $_.deviceCount }) 8))
}

# ---------------- Feature / quality update policies (beta)
Invoke-CERSection -Collector $C -Section 'UpdatePolicies' -Script {
    $fu = @(); $qu = @(); $dp = @()
    try { $fu = @(Get-CERGraph 'deviceManagement/windowsFeatureUpdateProfiles' -Beta -All) } catch { }
    try { $qu = @(Get-CERGraph 'deviceManagement/windowsQualityUpdateProfiles' -Beta -All) } catch { }
    try { $dp = @(Get-CERGraph 'deviceManagement/windowsDriverUpdateProfiles' -Beta -All) } catch { }
    Save-CERRaw -Name 'updatepolicies' -Object ([ordered]@{ Feature = @($fu | Select-Object displayName, featureUpdateVersion, createdDateTime); Quality = @($qu | Select-Object displayName, expeditedUpdateSettings); Driver = @($dp | Select-Object displayName, approvalType) })
    Add-CEREvidence -Control 'END-02' -Flag Info -Action 'Use feature update policies to control which Windows release devices move to and when, rather than letting Windows decide. Without them, feature updates arrive on Microsoft''s schedule and land as an unplanned change on a working day.' -Evidence ("Windows feature update policies: {0} ({1}); expedited quality update policies: {2}; driver update policies: {3}." -f $fu.Count, (Join-CERList ($fu | ForEach-Object { "{0} -> {1}" -f $_.displayName, $_.featureUpdateVersion }) 3), $qu.Count, $dp.Count)
}

Complete-CERCollector

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
    if ($d.Count -eq 0) { Add-CEREvidence -Control 'END-01' -Flag Attention -Evidence 'Intune returns zero managed devices (not licensed, not used, or no permission).'; return }
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
    Add-CEREvidence -Control 'END-01' -Flag $(if ($d.Count -and ($stale.Count / $d.Count) -gt 0.05) { 'Attention' } else { 'OK' }) -Evidence ("Intune managed devices: {0} ({1}); not synced for > 30 days: {2} ({3}); personal-owned: {4}; join types: {5}. Compare with Entra devices, RMM and EDR counts." -f $d.Count, (Join-CERList $byOs 5), $stale.Count, (ConvertTo-CERPct $stale.Count $d.Count), $personal.Count, (Join-CERList ($win | Group-Object joinType | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 4))
    Add-CEREvidence -Control 'END-02' -Flag $(if ($win10.Count) { 'Attention' } else { 'OK' }) -Evidence ("Intune Windows devices: {0} - Windows 11: {1}, Windows 10: {2} (out of support 14 Oct 2025); builds: {3}; macOS: {4}." -f $win.Count, $win11.Count, $win10.Count, (Join-CERList $builds 6), $mac.Count)
    Add-CEREvidence -Control 'END-07' -Flag $(if ($win.Count -and ($enc.Count / $win.Count) -ge 0.98) { 'OK' } else { 'Attention' }) -Evidence ("Intune reports isEncrypted on {0}/{1} Windows devices ({2}); not encrypted: {3}." -f $enc.Count, $win.Count, (ConvertTo-CERPct $enc.Count $win.Count), (Join-CERList ($notEnc | ForEach-Object { $_.deviceName }) 8))
    Add-CEREvidence -Control 'END-12' -Flag $(if ($d.Count -and ($nonComp.Count / $d.Count) -le 0.05) { 'OK' } else { 'Attention' }) -Evidence ("Compliance state: {0}; non-compliant/error/conflict: {1} ({2})." -f (Join-CERList $comp 5), $nonComp.Count, (ConvertTo-CERPct $nonComp.Count $d.Count))
    Add-CEREvidence -Control 'END-13' -Flag Info -Evidence ("Windows devices enrolled via Autopilot: {0}/{1} ({2})." -f $autopilot.Count, $win.Count, (ConvertTo-CERPct $autopilot.Count $win.Count))
    Add-CEREvidence -Control 'END-14' -Flag Info -Evidence ("Mobile devices under MDM: {0} (iOS/iPadOS {1}, Android {2}); jailbroken/rooted flagged: {3}. MAM-only (app protection without enrolment) users are not in this list." -f $mobile.Count, @($mobile | Where-Object { $_.operatingSystem -like 'i*' }).Count, @($mobile | Where-Object { $_.operatingSystem -eq 'Android' }).Count, $jail.Count)
}

# ---------------- Compliance policies
Invoke-CERSection -Collector $C -Section 'CompliancePolicies' -Script {
    $pol = @(Get-CERGraph 'deviceManagement/deviceCompliancePolicies?$expand=assignments' -All)
    $rows = @($pol | ForEach-Object { $t = ("$($_.'@odata.type')" -replace '#microsoft.graph.', ''); [pscustomobject]@{ Name = $_.displayName; Type = $t; Assigned = (@($_.assignments).Count -gt 0); BitLocker = (Get-CERProp $_ 'bitLockerEnabled'); SecureBoot = (Get-CERProp $_ 'secureBootEnabled'); Antivirus = (Get-CERProp $_ 'antivirusRequired'); Firewall = (Get-CERProp $_ 'activeFirewallRequired'); Defender = (Get-CERProp $_ 'defenderEnabled'); OsMin = (Get-CERProp $_ 'osMinimumVersion'); PasswordRequired = (Get-CERProp $_ 'passwordRequired'); ThreatLevel = (Get-CERProp $_ 'deviceThreatProtectionRequiredSecurityLevel'); TPM = (Get-CERProp $_ 'tpmRequired') } })
    Save-CERRaw -Name 'compliancepolicies' -Object $rows
    $winPol = @($rows | Where-Object { $_.Type -like 'windows10*' -and $_.Assigned })
    $strong = @($winPol | Where-Object { $_.BitLocker -and ($_.Antivirus -or $_.Defender) -and $_.Firewall })
    Add-CEREvidence -Control 'END-12' -Flag $(if ($strong.Count) { 'OK' } elseif ($winPol.Count) { 'Attention' } else { 'Attention' }) -Evidence ("Compliance policies: {0} total, {1} assigned ({2}); Windows policies requiring BitLocker + AV + firewall: {3}; OS minimum set on {4}; MDE threat level used on {5}. Platforms: {6}." -f $pol.Count, @($rows | Where-Object Assigned).Count, (Join-CERList ($rows | Where-Object Assigned | ForEach-Object { $_.Name }) 6), $strong.Count, @($winPol | Where-Object OsMin).Count, @($winPol | Where-Object { $_.ThreatLevel -and $_.ThreatLevel -ne 'unavailable' }).Count, (Join-CERList ($rows | Group-Object Type | ForEach-Object { "{0}={1}" -f $_.Name, $_.Count }) 6))
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
    Add-CEREvidence -Control 'END-03' -Flag $(if (@($rings | Where-Object Assigned).Count) { 'OK' } else { 'Attention' }) -Evidence ("Windows Update rings: {0} ({1} assigned) - {2}. Compliance % must come from Intune update reports / RMM; the host check gives last-patch age." -f $rings.Count, @($rings | Where-Object Assigned).Count, (Join-CERList $ringTxt 4))
    Add-CEREvidence -Control 'END-11' -Flag Info -Evidence ("Legacy Endpoint Protection profiles assigned: {0}; with Defender ASR/exploit-guard settings: {1} ({2}); BitLocker in EP profile: {3}; firewall profiles configured: {4}. Settings-catalog/endpoint-security equivalents are listed separately." -f $ep.Count, $epAsr.Count, (Join-CERList ($epAsr | ForEach-Object { $_.Name }) 3), $epBl.Count, $epFw.Count)
    Add-CEREvidence -Control 'END-15' -Flag Info -Evidence ("Device restriction profiles assigned: {0}; removable storage blocked in {1}; screen timeout <= 15 min in {2}; SmartScreen app-install control in {3}; custom OMA-URI profiles: {4}; browser-related profiles: {5}." -f $restr.Count, $usbBlocked.Count, $lock.Count, $smart.Count, $custom.Count, $edgeCfg.Count)
    Add-CEREvidence -Control 'END-07' -Flag Info -Evidence ("BitLocker enforced via Endpoint Protection profile(s): {0} ({1}); check settings-catalog Disk Encryption policies below as well." -f $epBl.Count, (Join-CERList ($epBl | ForEach-Object { $_.Name }) 3))
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
    Add-CEREvidence -Control 'END-11' -Flag $(if ($asrBlock.Count -ge 6) { 'OK' } elseif ($asr.Count) { 'Attention' } else { 'Attention' }) -Evidence ("Endpoint security / settings catalog (assigned): {0}. ASR policies: {1}; rules in block: {2} ({3}); audit: {4}; warn/off: {5}. Antivirus policies {6}, EDR onboarding {7}, firewall {8}, baselines {9}." -f (Join-CERList $fam 8), $asr.Count, $asrBlock.Count, (Join-CERList ($asrBlock | ForEach-Object { $_ -replace 'block', '' }) 8), $asrAudit.Count, ($asrStates.Count - $asrBlock.Count - $asrAudit.Count), $av.Count, $edr.Count, $fw.Count, $base.Count)
    $macroKeys = @($keyFinds | Where-Object { $_.Setting -match 'macro|vbawarnings|blockcontentexecutionfrominternet' })
    Add-CEREvidence -Control 'END-10' -Flag $(if ($macroKeys.Count -or ($asrStates['blockwin32apicallsfromofficemacros'] -eq 'block')) { 'OK' } else { 'Attention' }) -Evidence ("Office macro settings delivered by Intune (settings catalog): {0} setting(s) in {1} policies ({2}); ASR 'Block Win32 API calls from Office macros' = {3}. ADMX-backed Office policies are listed under GroupPolicyConfigurations." -f $macroKeys.Count, @($macroKeys | Select-Object -ExpandProperty Policy -Unique).Count, (Join-CERList ($macroKeys | ForEach-Object { "{0}={1}" -f $_.Setting, $_.Value }) 6), $(if ($asrStates.ContainsKey('blockwin32apicallsfromofficemacros')) { $asrStates['blockwin32apicallsfromofficemacros'] } else { 'not configured' }))
    Add-CEREvidence -Control 'END-08' -Flag $(if ($laps.Count) { 'OK' } else { 'Attention' }) -Evidence ("Windows LAPS policy in Intune: {0} ({1}); account-protection policies: {2}. Coverage % is in the Entra deviceLocalCredentials evidence." -f $laps.Count, (Join-CERList ($laps | ForEach-Object { $_.Name }) 3), $acct.Count)
    Add-CEREvidence -Control 'END-09' -Flag $(if ($appctl.Count) { 'OK' } else { 'Info' }) -Evidence ("Application control policies in Intune (App Control for Business / WDAC / AppLocker custom): {0} ({1}). Airlock is evidenced by its agent on hosts and the Airlock portal." -f $appctl.Count, (Join-CERList ($appctl | ForEach-Object { $_.Name }) 3))
    Add-CEREvidence -Control 'END-07' -Flag $(if ($disk.Count) { 'OK' } else { 'Info' }) -Evidence ("Disk encryption (BitLocker) endpoint-security policies assigned: {0} ({1})." -f $disk.Count, (Join-CERList ($disk | ForEach-Object { $_.Name }) 3))
    $other = @($keyFinds | Where-Object { $_.Setting -match 'scriptblocklogging|modulelogging|removablestorage|pointandprint|inactivitytimeout|smbv1' })
    if ($other.Count) { Add-CEREvidence -Control 'END-15' -Flag Info -Evidence ("Settings-catalog host controls found: {0}" -f (Join-CERList ($other | ForEach-Object { "{0}={1}" -f $_.Setting, $_.Value }) 8)) }
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
        if ($hit.Count) { Add-CEREvidence -Control $k -Flag Info -Evidence ("Intune ADMX policies enabled ({0} matching): {1}" -f $hit.Count, (Join-CERList ($hit | ForEach-Object { "{0}" -f $_.Setting } | Select-Object -Unique) 8)) }
    }
    Add-CEREvidence -Control 'END-13' -Flag Info -Evidence ("ADMX-backed profiles: {0} ({1} assigned), {2} settings configured." -f $gp.Count, @($gp | Where-Object { @($_.assignments).Count -gt 0 }).Count, $finds.Count)
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
    Add-CEREvidence -Control 'END-13' -Flag $(if (@($profiles | Where-Object { @($_.assignments).Count -gt 0 }).Count -and $ids.Count) { 'OK' } else { 'Attention' }) -Evidence ("Autopilot: {0} deployment profiles ({1} assigned: {2}); {3} registered Autopilot devices; custom ESP profiles: {4}. Naming template(s): {5}." -f $profiles.Count, @($profiles | Where-Object { @($_.assignments).Count -gt 0 }).Count, (Join-CERList ($profiles | ForEach-Object { $_.displayName }) 3), $ids.Count, $esp.Count, (Join-CERList ($profiles | ForEach-Object { $_.deviceNameTemplate } | Where-Object { $_ }) 3))
    Add-CEREvidence -Control 'END-14' -Flag Info -Evidence ("Enrolment restrictions blocking personally-owned devices: {0}." -f (Join-CERList $personalBlocked 5))
}

# ---------------- App protection (MAM)
Invoke-CERSection -Collector $C -Section 'AppProtection' -Script {
    $mam = @(Get-CERGraph 'deviceAppManagement/managedAppPolicies?$top=200' -All)
    $ios = @($mam | Where-Object { "$($_.'@odata.type')" -like '*iosManagedAppProtection' }); $and = @($mam | Where-Object { "$($_.'@odata.type')" -like '*androidManagedAppProtection' }); $winMam = @($mam | Where-Object { "$($_.'@odata.type')" -like '*windowsManagedAppProtection' -or "$($_.'@odata.type')" -like '*mdmWindowsInformationProtectionPolicy' })
    $pin = @($mam | Where-Object { (Get-CERProp $_ 'pinRequired') -eq $true })
    $saveBlock = @($mam | Where-Object { (Get-CERProp $_ 'saveAsBlocked') -eq $true -or (Get-CERProp $_ 'dataBackupBlocked') -eq $true })
    Save-CERRaw -Name 'appprotection' -Object @($mam | Select-Object displayName, '@odata.type', pinRequired, saveAsBlocked, dataBackupBlocked, allowedOutboundDataTransferDestinations, periodOfflineBeforeWipeIsEnforced, minimumRequiredOsVersion, isAssigned)
    Add-CEREvidence -Control 'END-14' -Flag $(if ($ios.Count -and $and.Count) { 'OK' } else { 'Attention' }) -Evidence ("App protection policies: iOS {0}, Android {1}, Windows {2}; requiring PIN: {3}; blocking save-as/backup to personal locations: {4}. Enforcement depends on the CA 'require app protection' policy (see IAM/END-14 CA evidence)." -f $ios.Count, $and.Count, $winMam.Count, $pin.Count, $saveBlock.Count)
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
    Add-CEREvidence -Control 'END-04' -Flag $(if ($flash.Count) { 'Attention' } else { 'Info' }) -Evidence ("Intune detected apps scanned: {0}{1}. Watchlist: Java entries {2} (max {3} devices), Flash {4}, archive/PDF tools {5}. Versions seen: {6}." -f $apps.Count, $(if ($capped) { ' (capped - raise -MaxDetectedAppPages)' } else { '' }), $java.Count, (($java | Measure-Object deviceCount -Maximum).Maximum), $flash.Count, @($hits | Where-Object { $_.displayName -match '7-Zip|WinRAR|Acrobat|Reader' }).Count, (Join-CERList ($hits | Where-Object { $_.displayName -match '7-Zip|WinRAR|PuTTY|Java' } | Sort-Object deviceCount -Descending | ForEach-Object { "{0} {1} x{2}" -f $_.displayName, $_.version, $_.deviceCount }) 8))
    Add-CEREvidence -Control 'SEC-12' -Flag $(if ($remote.Count) { 'Attention' } else { 'OK' }) -Evidence ("Remote-access tools detected by Intune inventory: {0} - {1}." -f $remote.Count, (Join-CERList ($remote | Sort-Object deviceCount -Descending | ForEach-Object { "{0} {1} x{2}" -f $_.displayName, $_.version, $_.deviceCount }) 8))
}

# ---------------- Feature / quality update policies (beta)
Invoke-CERSection -Collector $C -Section 'UpdatePolicies' -Script {
    $fu = @(); $qu = @(); $dp = @()
    try { $fu = @(Get-CERGraph 'deviceManagement/windowsFeatureUpdateProfiles' -Beta -All) } catch { }
    try { $qu = @(Get-CERGraph 'deviceManagement/windowsQualityUpdateProfiles' -Beta -All) } catch { }
    try { $dp = @(Get-CERGraph 'deviceManagement/windowsDriverUpdateProfiles' -Beta -All) } catch { }
    Save-CERRaw -Name 'updatepolicies' -Object ([ordered]@{ Feature = @($fu | Select-Object displayName, featureUpdateVersion, createdDateTime); Quality = @($qu | Select-Object displayName, expeditedUpdateSettings); Driver = @($dp | Select-Object displayName, approvalType) })
    Add-CEREvidence -Control 'END-02' -Flag Info -Evidence ("Windows feature update policies: {0} ({1}); expedited quality update policies: {2}; driver update policies: {3}." -f $fu.Count, (Join-CERList ($fu | ForEach-Object { "{0} -> {1}" -f $_.displayName, $_.featureUpdateVersion }) 3), $qu.Count, $dp.Count)
}

Complete-CERCollector
